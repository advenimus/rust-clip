use askama::Template;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::FromRow;

use crate::{
    admin::dashboard::format_millis, error::AppResult, middleware::AdminUser, state::AppState,
};

const PAGE_SIZE: i64 = 50;

#[derive(FromRow)]
struct AuditRow {
    id: i64,
    event_type: String,
    details_json: String,
    ip_addr: Option<String>,
    created_at: i64,
}

pub struct AuditRowView {
    pub event_type: String,
    pub details: String,
    pub ip_addr: Option<String>,
    pub when: String,
}

#[derive(Template)]
#[template(path = "audit_log.html")]
struct AuditLogTemplate<'a> {
    admin_display_name: &'a str,
    rows: Vec<AuditRowView>,
    has_next: bool,
    next_cursor: Option<i64>,
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub before: Option<i64>,
}

pub async fn list(
    State(state): State<AppState>,
    admin: AdminUser,
    Query(q): Query<ListQuery>,
) -> AppResult<Response> {
    let before = q.before.unwrap_or(i64::MAX);
    let rows = sqlx::query_as::<_, AuditRow>(
        "SELECT id, event_type, details_json, ip_addr, created_at \
         FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?",
    )
    .bind(before)
    .bind(PAGE_SIZE + 1)
    .fetch_all(&state.db)
    .await?;

    let has_next = rows.len() as i64 > PAGE_SIZE;
    let truncated: Vec<AuditRow> = rows.into_iter().take(PAGE_SIZE as usize).collect();
    let next_cursor = if has_next {
        truncated.last().map(|r| r.id)
    } else {
        None
    };

    let views = truncated
        .into_iter()
        .map(|r| AuditRowView {
            event_type: r.event_type,
            details: r.details_json,
            ip_addr: r.ip_addr,
            when: format_millis(r.created_at),
        })
        .collect();

    let tmpl = AuditLogTemplate {
        admin_display_name: &admin.display_name,
        rows: views,
        has_next,
        next_cursor,
    };
    Ok(Html(tmpl.render()?).into_response())
}
