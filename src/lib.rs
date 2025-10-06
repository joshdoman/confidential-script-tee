use anyhow::Result;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
    Router,
};
use bitcoin::secp256k1::SecretKey;
use std::{env, net::SocketAddr, sync::Arc};
use tokio::sync::OnceCell;

pub mod api;
pub mod settings;

use api::{
    encryption_middleware, get_public_key_handler, get_settings_handler, health_handler,
    setup_handler, verify_and_sign_handler,
};
use settings::Settings;

// The payload size limit (4 MB)
pub const MAX_PAYLOAD_SIZE: usize = 4 * 1024 * 1024;

pub struct AppState {
    pub settings: Arc<OnceCell<Settings>>,
    pub master_key_pair: Arc<OnceCell<(SecretKey, Vec<u8>)>>,
}

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let app_state = Arc::new(AppState {
        settings: Arc::new(OnceCell::new()),
        master_key_pair: Arc::new(OnceCell::new()),
    });

    // Remember to change verify_and_sign to a POST
    let app = Router::new()
        .route("/setup", post(setup_handler))
        .route("/public-key", get(get_public_key_handler))
        .route(
            "/verify-and-sign",
            post(verify_and_sign_handler).layer(DefaultBodyLimit::max(MAX_PAYLOAD_SIZE)),
        )
        .route(
            "/secure/verify-and-sign",
            post(verify_and_sign_handler)
                .layer(DefaultBodyLimit::max(MAX_PAYLOAD_SIZE))
                .route_layer(middleware::from_fn_with_state(
                    app_state.clone(),
                    encryption_middleware,
                )),
        )
        .route("/settings", get(get_settings_handler))
        .route("/health", get(health_handler))
        .with_state(app_state);

    let port = env::var("PORT")
        .unwrap_or_else(|_| "8000".to_string())
        .parse::<u16>()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
