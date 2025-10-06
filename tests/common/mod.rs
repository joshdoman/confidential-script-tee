use axum::{extract::DefaultBodyLimit, middleware, routing::post, Router};
use bitcoin::{
    consensus::{deserialize, encode::serialize},
    key::UntweakedPublicKey,
    opcodes,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    taproot::{LeafVersion, TaprootBuilder},
    Amount, Network, OutPoint, Script, ScriptBuf, Transaction, TxIn, TxOut, Witness,
};
use confidential_script::settings::Settings;
use confidential_script::{
    api::{
        encryption_middleware::encryption_middleware, verify_and_sign_handler,
        VerifyAndSignRequest, VerifyAndSignResponse,
    },
    AppState, MAX_PAYLOAD_SIZE,
};
use std::collections::HashMap;
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::OnceCell};

pub fn create_master_key_pair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = secret_key.public_key(&secp);

    (secret_key, public_key)
}

pub fn setup_app_state(with_key: bool) -> Arc<AppState> {
    setup_app_state_with_settings(with_key, None)
}

pub fn setup_app_state_with_settings(with_key: bool, settings: Option<Settings>) -> Arc<AppState> {
    let master_key_pair = Arc::new(OnceCell::new());

    if with_key {
        let (secret_key, public_key) = create_master_key_pair();
        let serialized_public_key = public_key.serialize_uncompressed().to_vec();
        master_key_pair
            .set((secret_key, serialized_public_key))
            .unwrap();
    }

    let arc_settings = Arc::new(OnceCell::new());

    if let Some(settings) = settings {
        arc_settings.set(settings).unwrap();
    }

    Arc::new(AppState {
        settings: arc_settings,
        master_key_pair,
    })
}

pub async fn spawn_app(app_state: Arc<AppState>) -> SocketAddr {
    let app = Router::new()
        .route(
            "/verify-and-sign",
            post(verify_and_sign_handler).layer(DefaultBodyLimit::max(MAX_PAYLOAD_SIZE)),
        )
        .route(
            "/secure/verify-and-sign",
            post(verify_and_sign_handler)
                .layer(DefaultBodyLimit::max(MAX_PAYLOAD_SIZE))
                .layer(middleware::from_fn_with_state(
                    app_state.clone(),
                    encryption_middleware,
                )),
        )
        .with_state(app_state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

pub fn create_test_transaction_single_input() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new_op_return([]),
        }],
    }
}

pub fn create_emulated_single_input_test_transaction() -> (Transaction, TxOut) {
    let secp = Secp256k1::new();
    let internal_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));
    let op_true_script = Script::builder()
        .push_opcode(opcodes::OP_TRUE)
        .into_script();
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, op_true_script.clone())
        .unwrap();
    let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();
    let emulated_merkle_root = taproot_spend_info.merkle_root().unwrap();

    let (_, parent_public) = create_master_key_pair();
    let actual_address = confidential_script_lib::generate_address(
        parent_public,
        emulated_merkle_root,
        None,
        Network::Bitcoin,
    )
    .unwrap();

    let mut emulated_tx = create_test_transaction_single_input();
    let control_block = taproot_spend_info
        .control_block(&(op_true_script.clone(), LeafVersion::TapScript))
        .unwrap();
    let mut witness = Witness::new();
    witness.push(op_true_script.as_bytes());
    witness.push(control_block.serialize());
    emulated_tx.input[0].witness = witness;

    let value = Amount::from_sat(100_000);
    let spent_output = TxOut {
        value,
        script_pubkey: actual_address.script_pubkey(),
    };

    (emulated_tx, spent_output)
}

pub fn create_verify_and_sign_single_input_single_leaf_request() -> (VerifyAndSignRequest, TxOut) {
    let (emulated_tx, spent_output) = create_emulated_single_input_test_transaction();

    let request = VerifyAndSignRequest {
        emulated_tx_to: emulated_tx,
        actual_spent_outputs: vec![spent_output.clone()],
        backup_merkle_roots: HashMap::new(),
    };

    (request, spent_output)
}

pub fn validate_single_input_single_leaf_response(
    response: VerifyAndSignResponse,
    spent_output: TxOut,
) {
    let signed_tx_bytes = hex::decode(response.signed_transaction).unwrap();
    let actual_tx: Transaction = deserialize(&signed_tx_bytes).unwrap();

    let amount = spent_output.value.to_signed().unwrap().to_sat();
    let script =
        bitcoinkernel::ScriptPubkey::try_from(spent_output.script_pubkey.as_bytes()).unwrap();
    let actual_outputs = [bitcoinkernel::TxOut::new(&script, amount)];

    let verify_result = bitcoinkernel::verify(
        &bitcoinkernel::ScriptPubkey::try_from(spent_output.script_pubkey.as_bytes()).unwrap(),
        Some(amount),
        &bitcoinkernel::Transaction::try_from(serialize(&actual_tx).as_slice()).unwrap(),
        0,
        None,
        &actual_outputs,
    );

    assert!(verify_result.is_ok());
    assert_eq!(actual_tx.input[0].witness.len(), 1);
}
