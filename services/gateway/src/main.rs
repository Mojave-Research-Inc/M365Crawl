use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use common::{init_tracing, AppConfig};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Arc::new(AppConfig::from_env());
    let app_state = AppState { config };

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/chat", post(chat_handler))
        .with_state(app_state)
        .layer(cors);

    let addr: SocketAddr = format!(
        "0.0.0.0:{}",
        std::env::var("PORT").unwrap_or_else(|_| "5173".to_string())
    )
    .parse()
    .expect("invalid bind address");

    tracing::info!(%addr, "gateway listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app)
        .await
        .unwrap();

    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Debug, Deserialize)]
struct ChatRequest {
    message: String,
}

#[derive(Debug, Serialize)]
struct ChatResponse {
    reply: String,
}

async fn chat_handler(State(_state): State<AppState>, Json(req): Json<ChatRequest>) -> Response {
    let reply = format!("You said: {} (chat stub)", req.message);
    (StatusCode::OK, Json(ChatResponse { reply })).into_response()
}

