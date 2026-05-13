//! Cross-platform on-disk + stderr tracing setup for the RustClip
//! client. Used by both the CLI bin and the Tauri GUI bin so that any
//! production launch — Finder on macOS, the Start menu on Windows, an
//! AppImage on Linux — writes a daily-rotating log file that a user
//! can later export from the Diagnostics UI without having to
//! relaunch from a terminal.
//!
//! Layout: `$DATA_LOCAL_DIR/rustclip/logs/rustclip.YYYY-MM-DD.log`.
//! Retention is 7 days, matching the local history retention.
//!
//! Two layers are installed:
//! - **stderr** — preserves the existing pretty terminal output for
//!   developers and CI. Default filter is the same as before.
//! - **file** — non-blocking compact (or JSON, if
//!   `RUSTCLIP_LOG_FORMAT=json`) output. Default filter is one step
//!   more verbose than stderr (`debug` for our crates) so a future
//!   "send me the logs" exchange is actually useful.
//!
//! Both layers honor `RUSTCLIP_LOG_LEVEL` when set.

use std::path::PathBuf;

use anyhow::Result;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{Builder, Rotation};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};

const LOG_DIR_SUBPATH: &str = "rustclip/logs";
const FILE_PREFIX: &str = "rustclip";
const FILE_SUFFIX: &str = "log";
const MAX_LOG_FILES: usize = 7;

const STDERR_DEFAULT_FILTER: &str = "warn,rustclip_client=info,rustclip_client_gui=info";
const FILE_DEFAULT_FILTER: &str = "info,rustclip_client=debug,rustclip_client_gui=debug";

/// Resolve the absolute path to the log directory. May or may not
/// exist yet — call [`init_dual`] to ensure creation. Falls back from
/// `data_local_dir` → `data_dir` → `temp_dir` so the resolution
/// always succeeds, matching the pattern in
/// `config.rs`, `image_history.rs`, `files.rs`, and `history.rs`.
pub fn log_dir() -> PathBuf {
    let base = dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(std::env::temp_dir);
    base.join(LOG_DIR_SUBPATH)
}

/// File-name prefix used by the daily rolling appender. Combined with
/// [`log_file_suffix`] and a date, produces names like
/// `rustclip.2026-05-13.log`.
pub fn log_file_prefix() -> &'static str {
    FILE_PREFIX
}

/// File-name suffix used by the daily rolling appender. See
/// [`log_file_prefix`].
pub fn log_file_suffix() -> &'static str {
    FILE_SUFFIX
}

/// Install the dual stderr + file tracing subscriber.
///
/// Returns a `WorkerGuard` that callers MUST hold for the process
/// lifetime — dropping it stops the background flush thread and any
/// further logs go nowhere. On the rare path where the file appender
/// can't be initialized (read-only home, no permissions), falls back
/// to stderr-only and returns `Ok(None)`; a `warn!` describing the
/// failure is emitted via the stderr layer that does install.
///
/// Safe to call from tests: if a global subscriber is already
/// installed, this no-ops rather than panicking.
pub fn init_dual() -> Result<Option<WorkerGuard>> {
    let dir = log_dir();
    let dir_err = std::fs::create_dir_all(&dir).err();

    let (file_writer_guard, file_init_err): (
        Option<(tracing_appender::non_blocking::NonBlocking, WorkerGuard)>,
        Option<String>,
    ) = if dir_err.is_none() {
        match Builder::new()
            .rotation(Rotation::DAILY)
            .filename_prefix(FILE_PREFIX)
            .filename_suffix(FILE_SUFFIX)
            .max_log_files(MAX_LOG_FILES)
            .build(&dir)
        {
            Ok(appender) => {
                let (w, g) = tracing_appender::non_blocking(appender);
                (Some((w, g)), None)
            }
            Err(e) => (None, Some(format!("{e}"))),
        }
    } else {
        (None, None)
    };

    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = Vec::new();
    layers.push(
        fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(build_filter(STDERR_DEFAULT_FILTER))
            .boxed(),
    );

    let guard = if let Some((writer, guard)) = file_writer_guard {
        let format = std::env::var("RUSTCLIP_LOG_FORMAT")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let layer = if format == "json" {
            fmt::layer()
                .json()
                .with_writer(writer)
                .with_filter(build_filter(FILE_DEFAULT_FILTER))
                .boxed()
        } else {
            fmt::layer()
                .compact()
                .with_ansi(false)
                .with_writer(writer)
                .with_filter(build_filter(FILE_DEFAULT_FILTER))
                .boxed()
        };
        layers.push(layer);
        Some(guard)
    } else {
        None
    };

    let _ = Registry::default().with(layers).try_init();

    if let Some(e) = dir_err {
        tracing::warn!(
            log_dir = %dir.display(),
            error = %e,
            "could not create log directory; falling back to stderr-only"
        );
    } else if let Some(e) = file_init_err {
        tracing::warn!(
            log_dir = %dir.display(),
            error = %e,
            "could not initialize file appender; falling back to stderr-only"
        );
    }

    Ok(guard)
}

fn build_filter(default: &str) -> EnvFilter {
    EnvFilter::try_from_env("RUSTCLIP_LOG_LEVEL")
        .or_else(|_| EnvFilter::try_new(default))
        .expect("static filter")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_dir_resolves_under_rustclip_logs() {
        let p = log_dir();
        let s = p.to_string_lossy();
        assert!(
            s.ends_with("rustclip/logs") || s.ends_with("rustclip\\logs"),
            "unexpected log dir: {s}"
        );
    }

    #[test]
    fn init_dual_is_idempotent() {
        // First call installs (or no-ops if another test already did),
        // second call must not panic.
        let _ = init_dual();
        let _ = init_dual();
    }
}
