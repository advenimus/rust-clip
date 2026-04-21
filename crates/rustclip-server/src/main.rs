mod admin;
mod audit;
mod bootstrap;
mod config;
mod db;
mod error;
mod middleware;
mod models;
mod password;
mod state;
mod sweeper;
#[cfg(test)]
mod test_util;
mod tokens;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Router,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tokio::net::TcpListener;
use tower::Layer;
use tower_http::{normalize_path::NormalizePathLayer, trace::TraceLayer};
use tower_sessions::{Expiry, SessionManagerLayer, cookie::SameSite};
use tower_sessions_sqlx_store::SqliteStore;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

use crate::{config::Config, state::AppState};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = Config::from_env().context("loading config from env")?;
    info!(bind = %config.bind_addr, data_dir = %config.data_dir.display(), "starting rustclip-server");

    let pool = db::connect(&config.database_path())
        .await
        .context("opening database")?;
    db::migrate(&pool).await.context("running migrations")?;
    bootstrap::maybe_bootstrap_admin(&pool, &config).await?;

    tokio::fs::create_dir_all(config.blobs_dir())
        .await
        .with_context(|| format!("creating blobs dir {}", config.blobs_dir().display()))?;

    let session_store = SqliteStore::new(pool.clone());
    session_store
        .migrate()
        .await
        .context("migrating session store")?;
    let cookies_secure = config.public_url.starts_with("https://");
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(cookies_secure)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(time::Duration::days(7)));

    sweeper::spawn(pool.clone());

    let state = AppState {
        db: pool,
        config: Arc::new(config.clone()),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/static/app.css", get(serve_app_css))
        .nest("/admin", admin::router())
        .with_state(state)
        .layer(session_layer)
        .layer(TraceLayer::new_for_http());

    // Trim trailing slashes so /admin/ and /admin match the same route.
    let service = NormalizePathLayer::trim_trailing_slash().layer(app);

    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_addr))?;

    info!(addr = %config.bind_addr, "rustclip-server listening");
    axum::serve(listener, tower::make::Shared::new(service))
        .await
        .context("server error")?;
    Ok(())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

const APP_CSS: &str = include_str!("../static/app.css");

async fn serve_app_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("RUSTCLIP_LOG_LEVEL")
        .or_else(|_| EnvFilter::try_new("info"))
        .expect("static filter");
    fmt().with_env_filter(filter).init();
}
