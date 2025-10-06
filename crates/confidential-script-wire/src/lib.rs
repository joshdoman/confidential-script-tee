// Written in 2025 by Joshua Doman <joshsdoman@gmail.com>
// SPDX-License-Identifier: CC0-1.0

//! # Confidential Script TEE Wire
//!
//! Library for interacting with Confidential Script TEE over REST API

// Coding conventions
#![deny(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

use anyhow::Result;
use bitcoin::{BlockHash, TapNodeHash, Transaction, TxOut, secp256k1::PublicKey};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

/// Header to provide client public key in requests to `/secure/verify-and-sign`
pub const CLIENT_HEADER: &str = "X-Client-Public-Key";

/// Request body to `/setup` and response to `/settings`
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    /// The maximum emulated transaction weight (default: 4M WU)
    pub max_weight: Option<u64>,
    /// The AWS KMS key id (ARN)
    pub key_id: String,
    /// The blockhash used to derive the master secret
    pub blockhash: BlockHash,
}

/// Response to `/public-key`
#[derive(Debug, Serialize, Deserialize)]
pub struct GetPublicKeyResponse {
    /// The master public key
    pub public_key: PublicKey,
}

/// Request payload for `/verify-and-sign`
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyAndSignRequest {
    /// The transaction with emulated witness data
    pub emulated_tx_to: Transaction,
    /// The actual spent outputs
    pub actual_spent_outputs: Vec<TxOut>,
    /// The merkle roots of the (optional) backup spend paths
    pub backup_merkle_roots: HashMap<usize, TapNodeHash>,
}

/// Response to `/verify-and-sign`
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyAndSignResponse {
    /// The signed transaction
    pub signed_tx: Transaction,
}

/// Method to encrypt payload for `/secure/verify-and-sign` using shared secret
pub fn encrypt(data: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key_from_shared_secret(shared_secret);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    // Prepend nonce to ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Method to decrypt response from `/secure/verify-and-sign` using shared secret
pub fn decrypt(encrypted_data: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>> {
    if encrypted_data.len() < 12 {
        return Err(anyhow::anyhow!("Encrypted data missing nonce"));
    }

    let key = derive_key_from_shared_secret(shared_secret);
    let cipher = ChaCha20Poly1305::new(&key);

    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))
}

fn derive_key_from_shared_secret(shared_secret: &[u8]) -> Key {
    let salt = Some(b"confidential-script-salt".as_slice());
    let (_, hkdf) = Hkdf::<Sha256>::extract(salt, shared_secret);

    let mut key = [0u8; 32];
    hkdf.expand(b"Middleware encryption key", &mut key)
        .expect("32-byte output is a valid length for HKDF-SHA256");
    Key::from(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let shared_secret = vec![42u8; 32];
        let original_data = b"This is a secret message that needs to be encrypted.";

        let encrypted_data = encrypt(original_data, &shared_secret).unwrap();
        let decrypted_data = decrypt(&encrypted_data, &shared_secret).unwrap();

        assert_ne!(original_data, encrypted_data.as_slice());
        assert_eq!(original_data, decrypted_data.as_slice());
    }

    #[test]
    fn test_decryption_with_wrong_key_fails() {
        let correct_shared_secret = vec![42u8; 32];
        let wrong_shared_secret = vec![99u8; 32];
        let original_data = b"Another secret message.";

        let encrypted_data = encrypt(original_data, &correct_shared_secret).unwrap();
        let decryption_result = decrypt(&encrypted_data, &wrong_shared_secret);

        assert!(decryption_result.is_err());
    }
}
