use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
};
use bitcoin::{hashes::Hash, Amount, ScriptBuf, TapNodeHash, TxOut, Weight};
use confidential_script_lib::{verify_and_sign, Error, Verifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyAndSignRequest {
    pub input_index: u32,
    pub emulated_tx_to: String,
    pub actual_spent_outputs: Vec<ActualSpentOutput>,
    pub backup_merkle_root: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActualSpentOutput {
    pub value: u64,
    pub script_pubkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyAndSignResponse {
    pub signed_transaction: String,
}

struct KernelVerifier {
    max_weight: u64,
}

impl Verifier for KernelVerifier {
    fn verify(
        &self,
        script_pubkey: &[u8],
        amount: Option<i64>,
        tx_to: &[u8],
        input_index: u32,
        spent_outputs: &[TxOut],
        tx_weight: Weight,
    ) -> Result<(), Error> {
        if tx_weight.to_wu() > self.max_weight {
            return Err(Error::ExceedsMaxWeight);
        }

        let mut outputs = Vec::new();
        for txout in spent_outputs {
            let amount = txout
                .value
                .to_signed()
                .map_err(Error::InvalidAmount)?
                .to_sat();
            let script = bitcoinkernel::ScriptPubkey::try_from(txout.script_pubkey.as_bytes())
                .map_err(|e| Error::VerificationFailed(e.to_string()))?;
            outputs.push(bitcoinkernel::TxOut::new(&script, amount));
        }

        let script_pubkey = &bitcoinkernel::ScriptPubkey::try_from(script_pubkey)
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;

        let tx_to = &bitcoinkernel::Transaction::try_from(tx_to)
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;

        bitcoinkernel::verify(script_pubkey, amount, tx_to, input_index, None, &outputs)
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;

        Ok(())
    }
}

/// Handler to verify an emulated Bitcoin script and sign the corresponding transaction
pub async fn verify_and_sign_handler(
    State(state): State<Arc<AppState>>,
    AxumJson(payload): AxumJson<VerifyAndSignRequest>,
) -> impl IntoResponse {
    // Check if ephemeral key pair exists
    let (secret_key, _) = match state.master_key_pair.get() {
        Some(key_pair) => key_pair.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Secret not found. Please generate it first.",
            )
                .into_response();
        }
    };

    // Decode emulated transaction
    let emulated_tx_bytes = match hex::decode(&payload.emulated_tx_to) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to decode transaction: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid transaction encoding.").into_response();
        }
    };

    let mut aux_rand = [0u8; 32];
    rand::rng().fill_bytes(&mut aux_rand);

    // Decode backup merkle root if provided
    let backup_merkle_root = if let Some(root_hex) = &payload.backup_merkle_root {
        let root_bytes = match hex::decode(root_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Failed to decode backup_merkle_root: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    "Invalid backup merkle root encoding.",
                )
                    .into_response();
            }
        };

        if root_bytes.len() != 32 {
            return (
                StatusCode::BAD_REQUEST,
                "Backup merkle root must be exactly 32 bytes.",
            )
                .into_response();
        }

        let root_array: [u8; 32] = root_bytes.try_into().unwrap();
        Some(TapNodeHash::from_byte_array(root_array))
    } else {
        None
    };

    // Convert ActualSpentOutput to TxOut
    let mut actual_spent_outputs = Vec::new();
    for output in &payload.actual_spent_outputs {
        let script_bytes = match hex::decode(&output.script_pubkey) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Failed to decode script_pubkey: {}", e);
                return (StatusCode::BAD_REQUEST, "Invalid scriptPubKey encoding.").into_response();
            }
        };

        let tx_out = TxOut {
            value: Amount::from_sat(output.value),
            script_pubkey: ScriptBuf::from_bytes(script_bytes),
        };
        actual_spent_outputs.push(tx_out);
    }

    let max_weight = state
        .settings
        .get()
        .and_then(|settings| settings.max_weight)
        .unwrap_or(Weight::MAX_BLOCK.to_wu());

    let verifier = KernelVerifier { max_weight };

    // Call verify_and_sign
    let signed_tx = match verify_and_sign(
        &verifier,
        payload.input_index,
        &emulated_tx_bytes,
        &actual_spent_outputs,
        &aux_rand,
        secret_key,
        backup_merkle_root,
    ) {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Unable to sign transaction: {}", e);
            return (StatusCode::BAD_REQUEST, format!("Unable to sign: {}", e)).into_response();
        }
    };

    // Serialize the signed transaction and return the response
    let signed_tx_bytes = bitcoin::consensus::encode::serialize(&signed_tx);
    let response = VerifyAndSignResponse {
        signed_transaction: hex::encode(signed_tx_bytes),
    };

    tracing::info!("Successfully verified and signed transaction");
    (StatusCode::OK, AxumJson(response)).into_response()
}
