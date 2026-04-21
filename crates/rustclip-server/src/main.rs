use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let addr: SocketAddr = std::env::var("RUSTCLIP_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string())
        .parse()
        .context("invalid RUSTCLIP_BIND_ADDR")?;
    let app = Router::new().route("/healthz", get(healthz));

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    info!(%addr, "rustclip-server listening");
    axum::serve(listener, app).await.context("server error")?;
    Ok(())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("RUSTCLIP_LOG_LEVEL")
        .or_else(|_| EnvFilter::try_new("info"))
        .expect("static filter");
    fmt().with_env_filter(filter).init();
}
