use aws_config::BehaviorVersion;
use aws_sdk_kms::{Client as KmsClient, primitives::Blob, types::KeyAgreementAlgorithmSpec};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
};
use bitcoin::secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey};
use confidential_script_wire::Settings;
use hkdf::Hkdf;
use p256::{PublicKey as P256PublicKey, pkcs8::EncodePublicKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::AppState;

/// Handler to generate a shared secret and store it as a secp256k1 key pair.
pub async fn setup_handler(
    State(state): State<Arc<AppState>>,
    AxumJson(payload): AxumJson<Settings>,
) -> impl IntoResponse {
    if state.settings.get().is_some() {
        return (StatusCode::CONFLICT, "Settings already set.").into_response();
    }

    // Create KMS client with credentials
    let aws_config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let mut kms_config_builder = aws_sdk_kms::config::Builder::from(&aws_config);
    if let Ok(kms_endpoint) = crate::env::var("AWS_KMS_ENDPOINT") {
        tracing::info!("KMS proxy configured at: {}", kms_endpoint);
        kms_config_builder = kms_config_builder.endpoint_url(kms_endpoint);
    } else {
        tracing::info!("KMS proxy is NOT configured, using default endpoint.");
    }
    let kms_client = KmsClient::from_conf(kms_config_builder.build());

    // Generate the P-256 NUMS key with the provided blockhash
    let p256_nums_key = generate_p256_nums_key(payload.blockhash.as_ref());
    let p256_key_der_bytes = match p256_nums_key.to_public_key_der() {
        Ok(der) => der.as_bytes().to_vec(),
        Err(e) => {
            tracing::error!("Failed to serialize P-256 key to DER: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Key serialization failed.",
            )
                .into_response();
        }
    };

    // Use the P-256 NUMS key to derive a secret from KMS.
    let shared_secret_output = match kms_client
        .derive_shared_secret()
        .key_id(&payload.key_id)
        .key_agreement_algorithm(KeyAgreementAlgorithmSpec::Ecdh)
        .public_key(Blob::new(p256_key_der_bytes))
        .send()
        .await
    {
        Ok(output) => output,
        Err(e) => {
            tracing::error!("Failed to derive shared secret from KMS: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "KMS operation failed.").into_response();
        }
    };

    let shared_secret = match shared_secret_output.shared_secret {
        Some(blob) => blob.into_inner(),
        None => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "KMS returned no secret.").into_response();
        }
    };

    if shared_secret.len() != 32 {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid secret length from KMS.",
        )
            .into_response();
    }

    // Apply HKDF to shared secret to derive secret bytes
    let mut secret_bytes = [0u8; 32];
    let salt = Some(b"confidential-script-salt".as_slice());
    let (_, hkdf) = Hkdf::<Sha256>::extract(salt, &shared_secret);
    hkdf.expand(b"confidential-script-setup", &mut secret_bytes)
        .expect("32-byte shared secret is a valid length for HKDF-SHA256");

    // Now, deterministically convert the 32-byte secret into a valid secp256k1 SecretKey.
    let secp256k1_secret_key = loop {
        if let Ok(key) = SecretKey::from_slice(&secret_bytes) {
            break key;
        }
        increment_be_bytes(&mut secret_bytes);
    };

    let secp = Secp256k1::new();
    let secp256k1_public_key = Secp256k1PublicKey::from_secret_key(&secp, &secp256k1_secret_key);

    // Atomically store the resulting secp256k1 key pair.
    if state
        .master_key_pair
        .set((secp256k1_secret_key, secp256k1_public_key))
        .is_err()
    {
        return (StatusCode::CONFLICT, "Secret has already been generated.").into_response();
    }

    // Atomically store the settings.
    if state.settings.set(payload).is_err() {
        return (StatusCode::CONFLICT, "Settings have already been set.").into_response();
    }

    tracing::info!("Successfully generated and stored ephemeral secp256k1 key pair.");
    (StatusCode::OK, "Secret generated successfully.").into_response()
}

/// Generates a P-256 (NIST) public key where the private key is provably unknown.
/// This key is used for the `DeriveSharedSecret` operation with AWS KMS.
///
/// We include a Bitcoin blockhash in the derivation to ensure that the NUMS key
/// was unknown when the current policy of the KMS key was set. This provides
/// assurance that `DeriveSharedSecret` was not called outside the enclave.
pub fn generate_p256_nums_key(blockhash: &[u8; 32]) -> P256PublicKey {
    let seed = b"This is a P-256 NUMS key for KMS";
    let mut counter: u32 = 0;
    tracing::info!(
        "Generating P-256 NUMS public key based on seed: '{}' and blockhash: {}",
        String::from_utf8_lossy(seed),
        hex::encode(blockhash)
    );

    loop {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(blockhash);
        hasher.update(counter.to_be_bytes());
        let hash_result = hasher.finalize();

        // Attempt to decompress a point from the hash as an x-coordinate
        if let Ok(pub_key) = P256PublicKey::from_sec1_bytes(
            &[0x02]
                .iter()
                .chain(hash_result.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        ) {
            tracing::info!(
                "Successfully generated P-256 NUMS key with counter: {}",
                counter
            );
            return pub_key;
        }
        if let Ok(pub_key) = P256PublicKey::from_sec1_bytes(
            &[0x03]
                .iter()
                .chain(hash_result.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        ) {
            tracing::info!(
                "Successfully generated P-256 NUMS key with counter: {}",
                counter
            );
            return pub_key;
        }

        counter = counter
            .checked_add(1)
            .expect("P-256 NUMS key generation counter overflowed.");
    }
}

/// Increments a 32-byte slice in place, treating it as a big-endian integer.
pub fn increment_be_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut().rev() {
        let (res, overflow) = byte.overflowing_add(1);
        *byte = res;
        if !overflow {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniqueness() {
        let blockhash = [0u8; 32];
        let blockhash2 = [1u8; 32];

        let key = generate_p256_nums_key(&blockhash);
        let key2 = generate_p256_nums_key(&blockhash2);

        assert_ne!(
            key, key2,
            "Different blockhashes should produce different keys"
        );
    }

    #[test]
    fn test_reproducibility() {
        let blockhash = [0u8; 32];

        let key = generate_p256_nums_key(&blockhash);
        let key2 = generate_p256_nums_key(&blockhash);

        assert_eq!(key, key2, "Same blockhash should produce same key");
    }
}
