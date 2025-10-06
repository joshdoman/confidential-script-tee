use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
};
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct GetPublicKeyResponse {
    pub public_key: PublicKey,
}

/// Handler to get the public key of the generated secp256k1 key pair.
pub async fn get_public_key_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.master_key_pair.get() {
        Some((_, public_key)) => {
            let response = GetPublicKeyResponse {
                public_key: *public_key,
            };
            (StatusCode::OK, AxumJson(response)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            "Secret not found. Make sure to call `/setup` first.",
        )
            .into_response(),
    }
}
