use serde::{Deserialize, Serialize};
use std::env;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub app_base_url: String,
    pub database_url: String,
    pub qdrant_url: String,
    pub openai_api_key: Option<String>,
    pub oidc_authority: Option<String>,
    pub oidc_client_id: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            app_base_url: env::var("APP_BASE_URL").unwrap_or_else(|_| "http://localhost:5173".into()),
            database_url: env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://app:app@localhost:5432/app".into()),
            qdrant_url: env::var("QDRANT_URL").unwrap_or_else(|_| "http://localhost:6333".into()),
            openai_api_key: env::var("OPENAI_API_KEY").ok(),
            oidc_authority: env::var("OIDC_AUTHORITY").ok(),
            oidc_client_id: env::var("OIDC_CLIENT_ID").ok(),
        }
    }
}

pub fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = fmt().with_env_filter(env_filter).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

