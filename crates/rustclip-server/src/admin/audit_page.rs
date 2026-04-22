use askama::Template;
use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::FromRow;
use time::{
    Date, OffsetDateTime, Time, format_description::well_known::Rfc3339, macros::format_description,
};

use crate::{
    admin::dashboard::format_millis, error::AppResult, middleware::AdminUser, state::AppState,
};

const PAGE_SIZE: i64 = 50;
const CSV_MAX_ROWS: i64 = 10_000;

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
    csrf_token: String,
    rows: Vec<AuditRowView>,
    has_next: bool,
    next_cursor: Option<i64>,
    event_types: Vec<String>,
    filter: FilterView,
    query_string: String,
    csv_query_string: String,
}

pub struct FilterView {
    pub event_type: String,
    pub start_date: String,
    pub end_date: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ListQuery {
    pub before: Option<i64>,
    pub event_type: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
}

struct ParsedFilters {
    event_type: Option<String>,
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    raw_start: String,
    raw_end: String,
    raw_event_type: String,
}

fn parse_filters(q: &ListQuery) -> ParsedFilters {
    let event_type = q
        .event_type
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let start_raw = q.start_date.clone().unwrap_or_default();
    let end_raw = q.end_date.clone().unwrap_or_default();
    let start_ms = parse_date_start_ms(start_raw.trim());
    let end_ms = parse_date_end_ms(end_raw.trim());

    ParsedFilters {
        event_type: event_type.clone(),
        start_ms,
        end_ms,
        raw_start: start_raw,
        raw_end: end_raw,
        raw_event_type: q.event_type.clone().unwrap_or_default(),
    }
}

fn parse_date_start_ms(s: &str) -> Option<i64> {
    parse_date(s).map(|d| d.with_time(Time::MIDNIGHT).assume_utc().unix_timestamp() * 1000)
}

fn parse_date_end_ms(s: &str) -> Option<i64> {
    parse_date(s).map(|d| {
        d.with_time(Time::MIDNIGHT).assume_utc().unix_timestamp() * 1000 + 24 * 60 * 60 * 1000 - 1
    })
}

fn parse_date(s: &str) -> Option<Date> {
    if s.is_empty() {
        return None;
    }
    let fmt = format_description!("[year]-[month]-[day]");
    Date::parse(s, fmt).ok()
}

async fn load_event_types(state: &AppState) -> AppResult<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT event_type FROM audit_log ORDER BY event_type")
            .fetch_all(&state.db)
            .await?;
    Ok(rows.into_iter().map(|(s,)| s).collect())
}

async fn query_rows(
    state: &AppState,
    filters: &ParsedFilters,
    before: i64,
    limit: i64,
) -> AppResult<Vec<AuditRow>> {
    let mut sql = String::from(
        "SELECT id, event_type, details_json, ip_addr, created_at \
         FROM audit_log WHERE id < ?",
    );
    if filters.event_type.is_some() {
        sql.push_str(" AND event_type = ?");
    }
    if filters.start_ms.is_some() {
        sql.push_str(" AND created_at >= ?");
    }
    if filters.end_ms.is_some() {
        sql.push_str(" AND created_at <= ?");
    }
    sql.push_str(" ORDER BY id DESC LIMIT ?");

    let mut query = sqlx::query_as::<_, AuditRow>(&sql).bind(before);
    if let Some(ref ev) = filters.event_type {
        query = query.bind(ev);
    }
    if let Some(ms) = filters.start_ms {
        query = query.bind(ms);
    }
    if let Some(ms) = filters.end_ms {
        query = query.bind(ms);
    }
    query = query.bind(limit);

    Ok(query.fetch_all(&state.db).await?)
}

fn filter_query_string(filters: &ParsedFilters) -> String {
    let mut parts = Vec::new();
    if let Some(ref ev) = filters.event_type {
        parts.push(format!("event_type={}", urlencode(ev)));
    }
    if !filters.raw_start.trim().is_empty() {
        parts.push(format!(
            "start_date={}",
            urlencode(filters.raw_start.trim())
        ));
    }
    if !filters.raw_end.trim().is_empty() {
        parts.push(format!("end_date={}", urlencode(filters.raw_end.trim())));
    }
    parts.join("&")
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub async fn list(
    State(state): State<AppState>,
    admin: AdminUser,
    Query(q): Query<ListQuery>,
) -> AppResult<Response> {
    let filters = parse_filters(&q);
    let before = q.before.unwrap_or(i64::MAX);

    let rows = query_rows(&state, &filters, before, PAGE_SIZE + 1).await?;

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

    let event_types = load_event_types(&state).await?;
    let filter_qs = filter_query_string(&filters);

    let filter_view = FilterView {
        event_type: filters.raw_event_type.clone(),
        start_date: filters.raw_start.clone(),
        end_date: filters.raw_end.clone(),
    };

    let tmpl = AuditLogTemplate {
        admin_display_name: &admin.display_name,
        csrf_token: admin.csrf_token.clone(),
        rows: views,
        has_next,
        next_cursor,
        event_types,
        filter: filter_view,
        query_string: filter_qs.clone(),
        csv_query_string: filter_qs,
    };
    Ok(Html(tmpl.render()?).into_response())
}

pub async fn export_csv(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<ListQuery>,
) -> AppResult<Response> {
    let filters = parse_filters(&q);
    let rows = query_rows(&state, &filters, i64::MAX, CSV_MAX_ROWS).await?;

    let mut body = String::from("id,created_at,event_type,ip_addr,details\n");
    for r in rows {
        let when = OffsetDateTime::from_unix_timestamp(r.created_at / 1000)
            .ok()
            .and_then(|dt| dt.format(&Rfc3339).ok())
            .unwrap_or_else(|| r.created_at.to_string());
        body.push_str(&format!(
            "{},{},{},{},{}\n",
            r.id,
            csv_escape(&when),
            csv_escape(&r.event_type),
            csv_escape(r.ip_addr.as_deref().unwrap_or("")),
            csv_escape(&r.details_json),
        ));
    }

    let filename = "audit_log.csv";
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/csv; charset=utf-8"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            ),
        ],
        Body::from(body),
    )
        .into_response())
}

fn csv_escape(s: &str) -> String {
    if s.contains('"') || s.contains(',') || s.contains('\n') || s.contains('\r') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escape_roundtrip() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("has,comma"), "\"has,comma\"");
        assert_eq!(csv_escape("has\"quote"), "\"has\"\"quote\"");
        assert_eq!(csv_escape("has\nnewline"), "\"has\nnewline\"");
    }

    #[test]
    fn parse_date_handles_iso_format() {
        let ms = parse_date_start_ms("2026-04-21").unwrap();
        // 2026-04-21 00:00:00 UTC in ms
        let expected = time::macros::datetime!(2026-04-21 00:00 UTC).unix_timestamp() * 1000;
        assert_eq!(ms, expected);
    }

    #[test]
    fn parse_date_end_is_end_of_day() {
        let start = parse_date_start_ms("2026-04-21").unwrap();
        let end = parse_date_end_ms("2026-04-21").unwrap();
        assert_eq!(end - start, 24 * 60 * 60 * 1000 - 1);
    }

    #[test]
    fn parse_date_rejects_garbage() {
        assert!(parse_date("not a date").is_none());
        assert!(parse_date("").is_none());
    }

    #[test]
    fn urlencode_escapes_reserved_chars() {
        assert_eq!(urlencode("admin login"), "admin%20login");
        assert_eq!(urlencode("a&b"), "a%26b");
        assert_eq!(urlencode("alpha-1_2.3~4"), "alpha-1_2.3~4");
    }
}
