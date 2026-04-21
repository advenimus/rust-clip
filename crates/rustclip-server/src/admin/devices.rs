use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    admin::dashboard::format_millis,
    audit,
    db::now_millis,
    error::{AppError, AppResult},
    middleware::{AdminUser, client_meta},
    state::AppState,
};

#[derive(FromRow)]
#[allow(dead_code)]
struct DeviceListRow {
    id: Uuid,
    user_id: Uuid,
    username: String,
    device_name: String,
    platform: String,
    last_seen_at: Option<i64>,
    created_at: i64,
    revoked_at: Option<i64>,
}

pub struct DeviceRowView {
    pub id: Uuid,
    pub username: String,
    pub device_name: String,
    pub platform: String,
    pub last_seen_at: Option<String>,
    pub created_at: String,
    pub is_active: bool,
}

#[derive(Template)]
#[template(path = "devices.html")]
struct DevicesTemplate<'a> {
    admin_display_name: &'a str,
    devices: Vec<DeviceRowView>,
    flash: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    pub revoked: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    admin: AdminUser,
    Query(q): Query<ListQuery>,
) -> AppResult<Response> {
    let rows = sqlx::query_as::<_, DeviceListRow>(
        "SELECT d.id, d.user_id, u.username, d.device_name, d.platform, \
                d.last_seen_at, d.created_at, d.revoked_at \
         FROM devices d JOIN users u ON u.id = d.user_id \
         ORDER BY (d.revoked_at IS NULL) DESC, d.last_seen_at DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let devices = rows
        .into_iter()
        .map(|r| DeviceRowView {
            id: r.id,
            username: r.username,
            device_name: r.device_name,
            platform: r.platform,
            last_seen_at: r.last_seen_at.map(format_millis),
            created_at: format_millis(r.created_at),
            is_active: r.revoked_at.is_none(),
        })
        .collect();

    let flash = q
        .revoked
        .as_ref()
        .map(|name| format!("Device '{name}' was revoked."));

    let tmpl = DevicesTemplate {
        admin_display_name: &admin.display_name,
        devices,
        flash,
    };
    Ok(Html(tmpl.render()?).into_response())
}

pub async fn revoke(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Redirect> {
    let device_name: Option<String> =
        sqlx::query_scalar("SELECT device_name FROM devices WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let Some(device_name) = device_name else {
        return Err(AppError::NotFound);
    };

    let now = now_millis();
    let res = sqlx::query("UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(id)
        .execute(&state.db)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    let (ip, ua) = client_meta(&headers);
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_DEVICE_REVOKED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({ "device_id": id, "device_name": device_name }),
    )
    .await?;

    Ok(Redirect::to(&format!(
        "/admin/devices?revoked={}",
        urlencode(&device_name)
    )))
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
