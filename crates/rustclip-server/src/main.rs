mod admin;
mod api;
mod audit;
mod bootstrap;
mod config;
mod db;
mod error;
mod middleware;
mod models;
mod password;
mod rate_limit;
mod settings;
mod state;
mod sweeper;
#[cfg(test)]
mod test_util;
mod tokens;
mod ws;

use std::{env, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Router,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tokio::net::TcpListener;
use tower::Layer;
use tower_http::{
    normalize_path::NormalizePathLayer, set_header::SetResponseHeaderLayer, trace::TraceLayer,
};
use tower_sessions::{Expiry, SessionManagerLayer, cookie::SameSite};
use tower_sessions_sqlx_store::SqliteStore;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use crate::{
    config::Config, rate_limit::RateLimiter, settings::SettingsStore, state::AppState, ws::hub::Hub,
};

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

    let settings = SettingsStore::load(&pool, &config)
        .await
        .context("loading runtime settings")?;

    sweeper::spawn(pool.clone(), settings.clone());

    let auth_limiter = RateLimiter::new();
    auth_limiter
        .clone()
        .spawn_pruner(rate_limit::AUTH_API_LIMIT, std::time::Duration::from_secs(300));

    let state = AppState {
        db: pool,
        config: Arc::new(config.clone()),
        settings,
        hub: Arc::new(Hub::new()),
        auth_limiter,
    };

    let admin_router = admin::router(state.auth_limiter.clone())
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static(
                "default-src 'self'; style-src 'self' 'unsafe-inline'; \
                 script-src 'self'; img-src 'self' data:; \
                 frame-ancestors 'none'; form-action 'self'; base-uri 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("DENY"),
        ));
    let api_router = api::router(state.auth_limiter.clone());

    let pool_for_shutdown = state.db.clone();
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/static/app.css", get(serve_app_css))
        .nest("/admin", admin_router)
        .nest("/api/v1", api_router)
        .nest("/ws", ws::router())
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
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    info!("shutdown: checkpointing WAL and closing pool");
    if let Err(e) = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool_for_shutdown)
        .await
    {
        warn!(error = ?e, "wal checkpoint failed");
    }
    pool_for_shutdown.close().await;
    info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                let _ = s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("shutdown: received ctrl-c"),
        _ = terminate => info!("shutdown: received SIGTERM"),
    }
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
    let format = env::var("RUSTCLIP_LOG_FORMAT")
        .unwrap_or_else(|_| "pretty".into())
        .to_ascii_lowercase();
    let builder = fmt().with_env_filter(filter);
    match format.as_str() {
        "json" => builder.json().with_target(false).init(),
        _ => builder.init(),
    }
}
