use anyhow::Result;
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bitcoin::secp256k1::{PublicKey, ecdh};
use confidential_script_wire::{CLIENT_HEADER, decrypt, encrypt};
use serde_json::json;
use std::sync::Arc;

use crate::AppState;

#[derive(Debug)]
pub struct MiddlewareError {
    status: StatusCode,
    message: String,
}

impl MiddlewareError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for MiddlewareError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.message,
            "status": self.status.as_u16()
        }));

        (self.status, body).into_response()
    }
}

pub async fn encryption_middleware(
    State(app_state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, MiddlewareError> {
    let (master_secret_key, _) = app_state.master_key_pair.get().ok_or_else(|| {
        MiddlewareError::new(StatusCode::BAD_REQUEST, "Master key pair not initialized")
    })?;

    let client_public_key_header = request
        .headers()
        .get(CLIENT_HEADER)
        .ok_or_else(|| {
            MiddlewareError::new(
                StatusCode::BAD_REQUEST,
                "Missing X-Client-Public-Key header",
            )
        })?
        .to_str()
        .map_err(|e| {
            MiddlewareError::new(
                StatusCode::BAD_REQUEST,
                format!("Invalid header encoding: {}", e),
            )
        })?;

    let client_public_key_bytes = hex::decode(client_public_key_header).map_err(|e| {
        MiddlewareError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid hex encoding: {}", e),
        )
    })?;

    let client_public_key = PublicKey::from_slice(&client_public_key_bytes).map_err(|e| {
        MiddlewareError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid public key format: {}", e),
        )
    })?;

    // Derive a shared secret from the master secret and the client public key
    let shared_secret = ecdh::shared_secret_point(&client_public_key, master_secret_key);

    // Decrypt the request body
    let body = std::mem::take(request.body_mut());
    let encrypted_body = to_bytes(body, usize::MAX).await.map_err(|e| {
        MiddlewareError::new(
            StatusCode::BAD_REQUEST,
            format!("Failed to read request body: {}", e),
        )
    })?;

    let decrypted_body = decrypt(&encrypted_body, &shared_secret).map_err(|e| {
        MiddlewareError::new(StatusCode::BAD_REQUEST, format!("Decryption failed: {}", e))
    })?;

    // Replace the request body with the decrypted version
    *request.body_mut() = Body::from(decrypted_body);

    // Call the next middleware/handler in the stack
    let mut response = next.run(request).await;

    // Encrypt the response body
    let body = std::mem::take(response.body_mut());
    let response_body = to_bytes(body, usize::MAX).await.map_err(|e| {
        MiddlewareError::new(
            StatusCode::BAD_REQUEST,
            format!("Failed to read response body: {}", e),
        )
    })?;

    let encrypted_response = encrypt(&response_body, &shared_secret).map_err(|e| {
        MiddlewareError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Encryption failed: {}", e),
        )
    })?;

    // Replace the response body with the encrypted version
    *response.body_mut() = Body::from(encrypted_response);

    Ok(response)
}
