use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
};
use bitcoin::{consensus, ScriptBuf, TapNodeHash, Transaction, TxOut, Weight};
use confidential_script_lib::{verify_and_sign, Error, Verifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyAndSignRequest {
    pub emulated_tx_to: Transaction,
    pub actual_spent_outputs: Vec<TxOut>,
    pub backup_merkle_roots: HashMap<usize, TapNodeHash>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyAndSignResponse {
    pub signed_transaction: String,
}

struct KernelVerifier;

impl Verifier for KernelVerifier {
    fn verify(
        &self,
        script_pubkeys: &HashMap<usize, ScriptBuf>,
        tx_to: &[u8],
        spent_outputs: &[TxOut],
    ) -> Result<(), Error> {
        let mut amounts = Vec::new();
        let mut outputs = Vec::new();
        for txout in spent_outputs {
            let amount = txout
                .value
                .to_signed()
                .map_err(|_| Error::VerificationFailed("invalid amount".to_string()))?
                .to_sat();
            let script = bitcoinkernel::ScriptPubkey::try_from(txout.script_pubkey.as_bytes())
                .map_err(|e| Error::VerificationFailed(e.to_string()))?;

            amounts.push(amount);
            outputs.push(bitcoinkernel::TxOut::new(&script, amount));
        }

        let tx_to = &bitcoinkernel::Transaction::try_from(tx_to)
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;

        for (&i, script_pubkey) in script_pubkeys {
            let amount = amounts.get(i).cloned();
            let script_pubkey = &bitcoinkernel::ScriptPubkey::try_from(script_pubkey.as_bytes())
                .map_err(|e| Error::VerificationFailed(e.to_string()))?;

            bitcoinkernel::verify(script_pubkey, amount, tx_to, i, None, &outputs)
                .map_err(|e| Error::VerificationFailed(e.to_string()))?;
        }

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

    // Check if transaction exceeds max weight
    let max_weight = state
        .settings
        .get()
        .and_then(|settings| settings.max_weight)
        .unwrap_or(Weight::MAX_BLOCK.to_wu());

    if payload.emulated_tx_to.weight().to_wu() > max_weight {
        return (StatusCode::BAD_REQUEST, "Transaction exceeds max weight.").into_response();
    }

    // Generate aux_rand
    let mut aux_rand = [0u8; 32];
    rand::rng().fill_bytes(&mut aux_rand);

    // Call verify_and_sign
    let signed_tx = match verify_and_sign(
        &KernelVerifier,
        &consensus::serialize(&payload.emulated_tx_to),
        &payload.actual_spent_outputs,
        &aux_rand,
        secret_key,
        payload.backup_merkle_roots,
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
