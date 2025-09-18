use axum::{routing::get, Router};
use common::{init_tracing, AppConfig};
use std::{net::SocketAddr, sync::Arc};

#[derive(Clone)]
struct AppState {
    _config: Arc<AppConfig>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();
    let state = AppState { _config: Arc::new(AppConfig::from_env()) };

    let app = Router::new().route("/healthz", get(|| async { "ok" })).with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{}", std::env::var("PORT").unwrap_or_else(|_| "5180".to_string()))
        .parse()
        .unwrap();
    tracing::info!(%addr, "auth_broker listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

