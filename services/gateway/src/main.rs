use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum::routing::get_service;
use common::{init_tracing, AppConfig};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

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

    let static_dir = ServeDir::new("public");
    let index_fallback = ServeFile::new("public/index.html");

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/chat", post(chat_handler))
        // Static assets and SPA fallback
        .nest_service("/", get_service(static_dir).handle_error(|error: std::io::Error| async move {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("static file error: {}", error),
            )
        }))
        .fallback_service(get_service(index_fallback).handle_error(|error: std::io::Error| async move {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("index file error: {}", error),
            )
        }))
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

