use axum::{extract::Query, routing::get, Router};
use common::{init_tracing, AppConfig};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};

#[derive(Clone)]
struct AppState {
    _config: Arc<AppConfig>,
}

#[derive(Debug, Deserialize)]
struct ValidationQuery {
    validationToken: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();
    let state = AppState { _config: Arc::new(AppConfig::from_env()) };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/graph/webhook", get(graph_validation))
        .with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{}", std::env::var("PORT").unwrap_or_else(|_| "8443".to_string()))
        .parse()
        .unwrap();
    tracing::info!(%addr, "webhook listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn graph_validation(Query(q): Query<ValidationQuery>) -> String {
    // For Graph change notification validation: echo the token
    q.validationToken.unwrap_or_default()
}

