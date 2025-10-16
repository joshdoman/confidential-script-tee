use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
};
use bitcoin::{ScriptBuf, Transaction, TxOut, Weight};
use bitcoinkernel_covenants as bitcoinkernel;
use confidential_script_lib::{Error, Verifier, verify_and_sign};
use confidential_script_wire::{VerifyAndSignRequest, VerifyAndSignResponse};
use rand::RngCore;
use std::collections::HashMap;
use std::num::TryFromIntError;
use std::sync::Arc;

use crate::AppState;

struct KernelVerifier;

impl Verifier for KernelVerifier {
    fn verify(
        &self,
        script_pubkeys: &HashMap<usize, ScriptBuf>,
        tx_to: &Transaction,
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

        let tx_bytes = bitcoin::consensus::serialize(tx_to);
        let tx_to = &bitcoinkernel::Transaction::try_from(tx_bytes.as_slice())
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;

        for (&i, script_pubkey) in script_pubkeys {
            let amount = amounts.get(i).cloned();
            let script_pubkey = &bitcoinkernel::ScriptPubkey::try_from(script_pubkey.as_bytes())
                .map_err(|e| Error::VerificationFailed(e.to_string()))?;
            let index: u32 = i
                .try_into()
                .map_err(|e: TryFromIntError| Error::VerificationFailed(e.to_string()))?;

            bitcoinkernel::verify(script_pubkey, amount, tx_to, index, None, &outputs)
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
        Some(key_pair) => *key_pair,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Secret not found. Make sure to call `/setup` first.",
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
        &payload.emulated_tx_to,
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

    let response = VerifyAndSignResponse { signed_tx };

    tracing::info!("Successfully verified and signed transaction");
    (StatusCode::OK, AxumJson(response)).into_response()
}
