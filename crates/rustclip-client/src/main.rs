mod clipboard;
mod commands;
mod crypto;
mod http;
mod keychain;
mod sync;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Parser, Debug)]
#[command(name = "rustclip-client", version, about = "RustClip desktop client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enroll this device with an enrollment token from the admin.
    Enroll {
        /// Server base URL, e.g. https://clip.example.com
        #[arg(long)]
        server_url: String,
        /// Friendly name for this device (defaults to hostname)
        #[arg(long)]
        device_name: Option<String>,
    },
    /// Log in an additional device for an already-enrolled user.
    Login {
        #[arg(long)]
        server_url: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        device_name: Option<String>,
    },
    /// Show the current connection and device info.
    Status,
    /// Revoke this device and clear local keychain entries.
    Logout,
    /// Clear local keychain entries without calling the server.
    Reset,
    /// Run the clipboard sync daemon.
    Sync,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Command::Enroll {
            server_url,
            device_name,
        } => commands::enroll(server_url, device_name).await,
        Command::Login {
            server_url,
            username,
            device_name,
        } => commands::login(server_url, username, device_name).await,
        Command::Status => commands::status().await,
        Command::Logout => commands::logout().await,
        Command::Reset => {
            commands::reset()?;
            Ok(())
        }
        Command::Sync => commands::sync_cmd().await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("RUSTCLIP_LOG_LEVEL")
        .or_else(|_| EnvFilter::try_new("warn,rustclip_client=info"))
        .expect("static filter");
    fmt().with_env_filter(filter).init();
}
