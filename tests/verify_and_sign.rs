mod common;

use bitcoin::{Amount, ScriptBuf, TxOut};
use common::*;
use confidential_script::{api::VerifyAndSignRequest, settings::Settings};
use std::collections::HashMap;

#[tokio::test]
async fn verify_and_sign_single_input_single_leaf_request() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;

    let (request_payload, spent_output) = create_verify_and_sign_single_input_single_leaf_request();

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/verify-and-sign", addr))
        .json(&request_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::OK);

    let response_body = res.json().await.unwrap();
    validate_single_input_single_leaf_response(response_body, spent_output);
}

#[tokio::test]
async fn verify_and_sign_no_secret() {
    let state = setup_app_state(false);
    let addr = spawn_app(state).await;

    let (request_payload, _) = create_verify_and_sign_single_input_single_leaf_request();

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/verify-and-sign", addr))
        .json(&request_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        res.text().await.unwrap(),
        "Secret not found. Please generate it first."
    );
}

#[tokio::test]
async fn verify_and_sign_exceeds_set_max_weight() {
    let settings = Settings {
        max_weight: Some(200),
        key_id: "".to_string(),
        blockhash: "".to_string(),
    };

    let state = setup_app_state_with_settings(true, Some(settings));
    let addr = spawn_app(state).await;

    let (mut emulated_tx, spent_output) = create_emulated_single_input_test_transaction();

    emulated_tx.output = vec![
        TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        };
        100
    ];

    let request = VerifyAndSignRequest {
        emulated_tx_to: emulated_tx,
        actual_spent_outputs: vec![spent_output],
        backup_merkle_roots: HashMap::new(),
    };

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/verify-and-sign", addr))
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(res.text().await.unwrap(), "Transaction exceeds max weight.");
}
