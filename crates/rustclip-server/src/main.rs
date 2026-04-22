mod admin;
mod api;
mod audit;
mod bootstrap;
mod config;
mod db;
mod error;
mod metrics;
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
mod update_check;
mod ws;

use std::{env, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tokio::net::TcpListener;
use tower_http::{
    limit::RequestBodyLimitLayer, normalize_path::NormalizePathLayer,
    set_header::SetResponseHeaderLayer, trace::TraceLayer,
};
use tower_sessions::{Expiry, SessionManagerLayer, cookie::SameSite};
use tower_sessions_sqlx_store::SqliteStore;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use crate::{
    config::Config, metrics::MetricsHub, rate_limit::RateLimiter, settings::SettingsStore,
    state::AppState, update_check::UpdateState, ws::hub::Hub,
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

    let update_state = UpdateState::new();
    update_check::spawn(update_state.clone(), settings.clone());

    let auth_limiter = RateLimiter::new();
    auth_limiter.clone().spawn_pruner(
        rate_limit::AUTH_API_LIMIT,
        std::time::Duration::from_secs(300),
    );

    let state = AppState {
        db: pool,
        config: Arc::new(config.clone()),
        settings,
        hub: Arc::new(Hub::new()),
        auth_limiter,
        metrics: Arc::new(MetricsHub::new()),
        update_state,
    };

    let admin_router = admin::router(state.clone())
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
            header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("DENY"),
        ));
    // Per-sub-router body-size wall: blob uploads get 1 GiB (override inside
    // the blob router), every other route gets 1 MiB. Enforced before the
    // body is buffered, so oversized admin-form / auth-API posts are rejected
    // at the network edge, not after the sqlx-layer parses them.
    const SMALL_BODY_LIMIT: usize = 1024 * 1024;
    let api_router = api::router(state.clone()).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT));

    let pool_for_shutdown = state.db.clone();
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics::metrics_handler))
        .route("/static/app.css", get(serve_app_css))
        .route("/static/admin.js", get(serve_admin_js))
        .route("/static/logo.png", get(serve_logo_png))
        .route("/static/logo-light.png", get(serve_logo_light_png))
        .nest(
            "/admin",
            admin_router.layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .nest("/api/v1", api_router)
        .nest("/ws", ws::router())
        .with_state(state)
        .layer(session_layer)
        .layer(TraceLayer::new_for_http())
        // nosniff covers every response, not just admin HTML.
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        // Top-level wall so an attacker cannot POST gigabytes at /healthz or
        // any unrouted path. Blob uploads override this inside the blob router.
        .layer(RequestBodyLimitLayer::new(api::blobs::BLOB_BODY_LIMIT))
        // Trim trailing slashes so /admin/ and /admin match the same route.
        // Outermost layer — runs before routing so the route table gets the
        // trimmed path.
        .layer(NormalizePathLayer::trim_trailing_slash());

    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_addr))?;

    info!(addr = %config.bind_addr, "rustclip-server listening");
    // ConnectInfo<SocketAddr> is made available to handlers + middleware so
    // the rate limiter can key on the real socket peer and only honor
    // X-Forwarded-For when the peer is in `RUSTCLIP_TRUSTED_PROXIES`.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
const ADMIN_JS: &str = include_str!("../static/admin.js");
const LOGO_PNG: &[u8] = include_bytes!("../static/logo.png");
const LOGO_LIGHT_PNG: &[u8] = include_bytes!("../static/logo-light.png");

async fn serve_app_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn serve_admin_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        ADMIN_JS,
    )
}

async fn serve_logo_png() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        LOGO_PNG,
    )
}

async fn serve_logo_light_png() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        LOGO_LIGHT_PNG,
    )
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
