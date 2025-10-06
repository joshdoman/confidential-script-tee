use bitcoin::secp256k1::{Secp256k1, SecretKey, ecdh};
use confidential_script_wire::{CLIENT_HEADER, VerifyAndSignResponse, decrypt, encrypt};

mod common;

use common::*;

#[tokio::test]
async fn secure_verify_and_sign() {
    let state = setup_app_state(true);
    let addr = spawn_app(state.clone()).await;

    let (request_payload, spent_output) = create_verify_and_sign_single_input_single_leaf_request();

    // Create client private key
    let secp = Secp256k1::new();
    let client_secret_key = SecretKey::from_slice(&[3u8; 32]).unwrap();
    let client_public_key = client_secret_key.public_key(&secp);

    // Get the server's master key pair
    let (master_secret_key, _) = state.master_key_pair.get().unwrap();

    // Derive shared secret (client perspective)
    let shared_secret =
        ecdh::shared_secret_point(&master_secret_key.public_key(&secp), &client_secret_key);

    // Encrypt payload
    let payload_json = serde_json::to_vec(&request_payload).unwrap();
    let encrypted_payload = encrypt(&payload_json, &shared_secret).unwrap();

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/secure/verify-and-sign", addr))
        .header(CLIENT_HEADER, hex::encode(client_public_key.serialize()))
        .header("content-type", "application/json")
        .body(encrypted_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // Decrypt response
    let encrypted_response = res.bytes().await.unwrap();
    let decrypted_response = decrypt(&encrypted_response, &shared_secret).unwrap();
    let response_body: VerifyAndSignResponse = serde_json::from_slice(&decrypted_response).unwrap();

    validate_single_input_single_leaf_response(response_body, spent_output);
}
