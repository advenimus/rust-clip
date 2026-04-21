use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
};
use sqlx::FromRow;
use time::OffsetDateTime;

use crate::{error::AppResult, middleware::AdminUser, state::AppState};

#[derive(FromRow)]
struct RecentEventRow {
    event_type: String,
    created_at: i64,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate<'a> {
    admin_display_name: &'a str,
    user_count: i64,
    active_device_count: i64,
    recent_events: Vec<RecentEvent>,
}

pub struct RecentEvent {
    pub event_type: String,
    pub when: String,
}

pub async fn show(State(state): State<AppState>, admin: AdminUser) -> AppResult<Response> {
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;
    let active_device_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL")
            .fetch_one(&state.db)
            .await?;

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

    let tmpl = DashboardTemplate {
        admin_display_name: &admin.display_name,
        user_count,
        active_device_count,
        recent_events: recent,
    };
    Ok(Html(tmpl.render()?).into_response())
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
