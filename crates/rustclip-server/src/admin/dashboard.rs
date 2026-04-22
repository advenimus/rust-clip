use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
};
use sqlx::FromRow;
use time::OffsetDateTime;

use crate::{
    db::now_millis, error::AppResult, middleware::AdminUser, state::AppState, update_check,
};

const UPGRADE_COMMAND: &str = "docker compose pull && docker compose up -d";

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const WEEK_MS: i64 = 7 * DAY_MS;

#[derive(FromRow)]
struct RecentEventRow {
    event_type: String,
    created_at: i64,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate<'a> {
    admin_display_name: &'a str,
    csrf_token: String,
    user_count: i64,
    active_device_count: i64,
    clip_events_24h: i64,
    clip_events_7d: i64,
    blob_storage_mb: String,
    recent_events: Vec<RecentEvent>,
    update_banner: Option<UpdateBanner>,
}

pub struct RecentEvent {
    pub event_type: String,
    pub when: String,
}

pub struct UpdateBanner {
    pub current_version: &'static str,
    pub latest_version: String,
    pub release_url: String,
    pub upgrade_command: &'static str,
}

pub async fn show(State(state): State<AppState>, admin: AdminUser) -> AppResult<Response> {
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;
    let active_device_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL")
            .fetch_one(&state.db)
            .await?;

    let now = now_millis();
    let clip_events_24h: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM clip_events WHERE created_at >= ?")
            .bind(now - DAY_MS)
            .fetch_one(&state.db)
            .await?;
    let clip_events_7d: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM clip_events WHERE created_at >= ?")
            .bind(now - WEEK_MS)
            .fetch_one(&state.db)
            .await?;

    let blob_bytes: Option<i64> = sqlx::query_scalar("SELECT SUM(byte_length) FROM blobs")
        .fetch_one(&state.db)
        .await?;
    let blob_storage_mb = format_mb(blob_bytes.unwrap_or(0));

    let recent = sqlx::query_as::<_, RecentEventRow>(
        "SELECT event_type, created_at FROM audit_log ORDER BY created_at DESC LIMIT 10",
    )
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .map(|r| RecentEvent {
        event_type: r.event_type,
        when: format_millis(r.created_at),
    })
    .collect();

    let update_banner = build_update_banner(&state).await;

    let tmpl = DashboardTemplate {
        admin_display_name: &admin.display_name,
        csrf_token: admin.csrf_token.clone(),
        user_count,
        active_device_count,
        clip_events_24h,
        clip_events_7d,
        blob_storage_mb,
        recent_events: recent,
        update_banner,
    };
    Ok(Html(tmpl.render()?).into_response())
}

async fn build_update_banner(state: &AppState) -> Option<UpdateBanner> {
    let settings = state.settings.snapshot().await;
    if !settings.update_check_enabled {
        return None;
    }
    let latest = state.update_state.snapshot().await?;
    let current = env!("CARGO_PKG_VERSION");
    if !update_check::is_newer(current, &latest.tag_name) {
        return None;
    }
    Some(UpdateBanner {
        current_version: current,
        latest_version: latest.tag_name,
        release_url: latest.html_url,
        upgrade_command: UPGRADE_COMMAND,
    })
}

fn format_mb(bytes: i64) -> String {
    if bytes <= 0 {
        return "0".into();
    }
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{bytes} B")
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{:.1} MB", b / MB)
    }
}

pub fn format_millis(ms: i64) -> String {
    let secs = ms / 1000;
    let nanos = ((ms % 1000).max(0) * 1_000_000) as u32;
    match OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => dt
            .replace_nanosecond(nanos)
            .unwrap_or(dt)
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "-".into()),
        Err(_) => "-".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_mb_handles_zero() {
        assert_eq!(format_mb(0), "0");
        assert_eq!(format_mb(-5), "0");
    }

    #[test]
    fn format_mb_bytes_for_small() {
        assert_eq!(format_mb(500), "500 B");
    }

    #[test]
    fn format_mb_kb_for_sub_mb() {
        assert_eq!(format_mb(5120), "5.0 KB");
    }

    #[test]
    fn format_mb_mb_for_large() {
        assert_eq!(format_mb(10 * 1024 * 1024), "10.0 MB");
    }
}
