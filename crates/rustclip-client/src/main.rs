mod clipboard;
mod clipboard_files;
mod commands;
mod crypto;
mod files;
mod history;
mod http;
mod image_codec;
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
        /// Enrollment token (non-interactive; prompts if omitted)
        #[arg(long)]
        enrollment_token: Option<String>,
        /// Password (non-interactive; prompts if omitted). Use env var
        /// `RUSTCLIP_PASSWORD` in scripts to avoid shell history leakage.
        #[arg(long, env = "RUSTCLIP_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },
    /// Log in an additional device for an already-enrolled user.
    Login {
        #[arg(long)]
        server_url: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        device_name: Option<String>,
        /// Password (non-interactive; prompts if omitted)
        #[arg(long, env = "RUSTCLIP_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },
    /// Show the current connection and device info.
    Status,
    /// Revoke this device and clear local keychain entries.
    Logout,
    /// Clear local keychain entries without calling the server.
    Reset,
    /// Run the clipboard sync daemon.
    Sync,
    /// Send one or more files to all other devices linked to this account.
    SendFiles {
        /// Files to bundle and send.
        #[arg(required = true)]
        paths: Vec<std::path::PathBuf>,
    },
    /// Show the local clipboard history.
    History {
        /// How many recent items to display.
        #[arg(long, default_value_t = 20)]
        limit: i64,
    },
    /// Wipe local clipboard history.
    HistoryClear,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Command::Enroll {
            server_url,
            device_name,
            enrollment_token,
            password,
        } => commands::enroll(server_url, device_name, enrollment_token, password).await,
        Command::Login {
            server_url,
            username,
            device_name,
            password,
        } => commands::login(server_url, username, device_name, password).await,
        Command::Status => commands::status().await,
        Command::Logout => commands::logout().await,
        Command::Reset => {
            commands::reset()?;
            Ok(())
        }
        Command::Sync => commands::sync_cmd().await,
        Command::SendFiles { paths } => commands::send_files(paths).await,
        Command::History { limit } => commands::show_history(limit),
        Command::HistoryClear => commands::clear_history(),
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("RUSTCLIP_LOG_LEVEL")
        .or_else(|_| EnvFilter::try_new("warn,rustclip_client=info"))
        .expect("static filter");
    fmt().with_env_filter(filter).init();
}
