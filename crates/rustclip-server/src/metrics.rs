//! `/metrics` Prometheus text-format endpoint.
//!
//! We hand-roll the exposition format (it is trivial) instead of pulling
//! in the `prometheus` crate. All values are snapshots read from the DB
//! or from in-process counters maintained by `MetricsHub`. The endpoint
//! is unauthenticated by design — operators are expected to firewall
//! `/metrics` at the reverse proxy and only expose it to their scraper.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
};

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
};

use crate::state::AppState;

/// In-process counters. Everything here is append-only — the scraper
/// computes rates. Gauges (user count, device count, etc.) are looked
/// up from SQLite on each scrape, since the scrape cadence is low
/// (seconds to minutes) and the queries are indexed `COUNT(*)`s.
#[derive(Debug, Default)]
pub struct MetricsHub {
    pub clip_events_accepted: AtomicU64,
    pub clip_events_rejected_rate_limited: AtomicU64,
    pub blob_uploads: AtomicU64,
    pub blob_downloads: AtomicU64,
    pub ws_connections_opened: AtomicU64,
    pub admin_login_success: AtomicU64,
    pub admin_login_failed: AtomicU64,
}

impl MetricsHub {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn incr(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

pub async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let body = render(&state).await.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "metrics render failed");
        format!("# metrics render failed: {e}\n")
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}

async fn render(state: &AppState) -> anyhow::Result<String> {
    let mut out = String::with_capacity(1024);

    // Counters from the hub.
    let m = &state.metrics;
    writeln!(
        out,
        "# HELP rustclip_clip_events_accepted_total ClipEvent messages persisted by the WS hub."
    )
    .unwrap();
    writeln!(out, "# TYPE rustclip_clip_events_accepted_total counter").unwrap();
    writeln!(
        out,
        "rustclip_clip_events_accepted_total {}",
        m.clip_events_accepted.load(Ordering::Relaxed)
    )
    .unwrap();

    writeln!(out, "# HELP rustclip_clip_events_rate_limited_total ClipEvent messages dropped by the per-connection rate cap.").unwrap();
    writeln!(
        out,
        "# TYPE rustclip_clip_events_rate_limited_total counter"
    )
    .unwrap();
    writeln!(
        out,
        "rustclip_clip_events_rate_limited_total {}",
        m.clip_events_rejected_rate_limited.load(Ordering::Relaxed)
    )
    .unwrap();

    writeln!(
        out,
        "# HELP rustclip_blob_uploads_total Blobs successfully uploaded."
    )
    .unwrap();
    writeln!(out, "# TYPE rustclip_blob_uploads_total counter").unwrap();
    writeln!(
        out,
        "rustclip_blob_uploads_total {}",
        m.blob_uploads.load(Ordering::Relaxed)
    )
    .unwrap();

    writeln!(
        out,
        "# HELP rustclip_blob_downloads_total Blobs successfully downloaded."
    )
    .unwrap();
    writeln!(out, "# TYPE rustclip_blob_downloads_total counter").unwrap();
    writeln!(
        out,
        "rustclip_blob_downloads_total {}",
        m.blob_downloads.load(Ordering::Relaxed)
    )
    .unwrap();

    writeln!(
        out,
        "# HELP rustclip_ws_connections_opened_total Successful WebSocket connections."
    )
    .unwrap();
    writeln!(out, "# TYPE rustclip_ws_connections_opened_total counter").unwrap();
    writeln!(
        out,
        "rustclip_ws_connections_opened_total {}",
        m.ws_connections_opened.load(Ordering::Relaxed)
    )
    .unwrap();

    writeln!(
        out,
        "# HELP rustclip_admin_login_success_total Admin portal logins that succeeded."
    )
    .unwrap();
    writeln!(out, "# TYPE rustclip_admin_login_success_total counter").unwrap();
    writeln!(
        out,
        "rustclip_admin_login_success_total {}",
        m.admin_login_success.load(Ordering::Relaxed)
    )
    .unwrap();

    writeln!(
        out,
        "# HELP rustclip_admin_login_failed_total Admin portal logins that failed."
    )
    .unwrap();
    writeln!(out, "# TYPE rustclip_admin_login_failed_total counter").unwrap();
    writeln!(
        out,
        "rustclip_admin_login_failed_total {}",
        m.admin_login_failed.load(Ordering::Relaxed)
    )
    .unwrap();

    // Gauges queried from the database.
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;
    writeln!(out, "# HELP rustclip_users Total users in the system.").unwrap();
    writeln!(out, "# TYPE rustclip_users gauge").unwrap();
    writeln!(out, "rustclip_users {user_count}").unwrap();

    let active_device_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL")
            .fetch_one(&state.db)
            .await?;
    writeln!(
        out,
        "# HELP rustclip_devices_active Active (non-revoked) device registrations."
    )
    .unwrap();
    writeln!(out, "# TYPE rustclip_devices_active gauge").unwrap();
    writeln!(out, "rustclip_devices_active {active_device_count}").unwrap();

    let queued_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM clip_events")
        .fetch_one(&state.db)
        .await?;
    writeln!(
        out,
        "# HELP rustclip_clip_events_buffered Clip events still held in the offline buffer."
    )
    .unwrap();
    writeln!(out, "# TYPE rustclip_clip_events_buffered gauge").unwrap();
    writeln!(out, "rustclip_clip_events_buffered {queued_events}").unwrap();

    let blob_bytes: Option<i64> = sqlx::query_scalar("SELECT SUM(byte_length) FROM blobs")
        .fetch_one(&state.db)
        .await?;
    writeln!(out, "# HELP rustclip_blob_storage_bytes Total bytes of ciphertext currently held in the blob store.").unwrap();
    writeln!(out, "# TYPE rustclip_blob_storage_bytes gauge").unwrap();
    writeln!(
        out,
        "rustclip_blob_storage_bytes {}",
        blob_bytes.unwrap_or(0)
    )
    .unwrap();

    Ok(out)
}
