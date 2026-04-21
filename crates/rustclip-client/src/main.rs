use anyhow::Result;
use rustclip_shared::PROTOCOL_VERSION;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!(
        protocol_version = PROTOCOL_VERSION,
        "rustclip-client starting"
    );
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("RUSTCLIP_LOG_LEVEL")
        .or_else(|_| EnvFilter::try_new("info"))
        .expect("static filter");
    fmt().with_env_filter(filter).init();
}
