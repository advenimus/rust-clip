//! Admin settings page: view and update the runtime-tunable knobs.

use askama::Template;
use axum::{
    Form,
    extract::State,
    http::HeaderMap,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;

use crate::{
    audit,
    error::{AppError, AppResult},
    middleware::{AdminUser, client_meta},
    settings::{self, RuntimeSettings},
    state::AppState,
};

pub const EVENT_SETTINGS_UPDATED: &str = "settings_updated";

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTemplate<'a> {
    admin_display_name: &'a str,
    csrf_token: String,
    current: RuntimeSettings,
    error: Option<String>,
    saved: bool,
    min_payload_bytes: u64,
    max_payload_bytes: u64,
    min_offline_ttl_hours: u32,
    max_offline_ttl_hours: u32,
    min_audit_retention_days: u32,
    max_audit_retention_days: u32,
    config_max_payload_bytes: u64,
    config_offline_ttl_hours: u32,
}

fn render(
    admin: &AdminUser,
    state: &AppState,
    current: RuntimeSettings,
    error: Option<String>,
    saved: bool,
) -> AppResult<Response> {
    let tmpl = SettingsTemplate {
        admin_display_name: &admin.display_name,
        csrf_token: admin.csrf_token.clone(),
        current,
        error,
        saved,
        min_payload_bytes: settings::MIN_PAYLOAD_BYTES,
        max_payload_bytes: settings::MAX_PAYLOAD_BYTES,
        min_offline_ttl_hours: settings::MIN_OFFLINE_TTL_HOURS,
        max_offline_ttl_hours: settings::MAX_OFFLINE_TTL_HOURS,
        min_audit_retention_days: settings::MIN_AUDIT_RETENTION_DAYS,
        max_audit_retention_days: settings::MAX_AUDIT_RETENTION_DAYS,
        config_max_payload_bytes: state.config.max_payload_bytes,
        config_offline_ttl_hours: state.config.offline_ttl_hours,
    };
    Ok(Html(tmpl.render()?).into_response())
}

pub async fn show(State(state): State<AppState>, admin: AdminUser) -> AppResult<Response> {
    let current = state.settings.snapshot().await;
    render(&admin, &state, current, None, false)
}

#[derive(Deserialize)]
pub struct UpdateForm {
    pub max_payload_bytes: String,
    pub offline_ttl_hours: String,
    pub audit_retention_days: String,
    #[serde(default)]
    pub update_check_enabled: Option<String>,
}

pub async fn update(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Form(form): Form<UpdateForm>,
) -> AppResult<Response> {
    let current = state.settings.snapshot().await;

    let parsed = parse_form(&form);
    let new = match parsed {
        Ok(n) => n,
        Err(msg) => return render(&admin, &state, current, Some(msg), false),
    };
    if let Err(msg) = settings::validate(&new) {
        return render(&admin, &state, current, Some(msg), false);
    }

    state
        .settings
        .update(&state.db, new)
        .await
        .map_err(AppError::internal)?;

    let (ip, ua) = client_meta(&headers);
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: EVENT_SETTINGS_UPDATED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({
            "max_payload_bytes": new.max_payload_bytes,
            "offline_ttl_hours": new.offline_ttl_hours,
            "audit_retention_days": new.audit_retention_days,
            "update_check_enabled": new.update_check_enabled,
        }),
    )
    .await?;

    render(&admin, &state, new, None, true)
}

fn parse_form(form: &UpdateForm) -> Result<RuntimeSettings, String> {
    let max_payload_bytes = form
        .max_payload_bytes
        .trim()
        .parse::<u64>()
        .map_err(|_| "max payload bytes must be a positive integer".to_string())?;
    let offline_ttl_hours = form
        .offline_ttl_hours
        .trim()
        .parse::<u32>()
        .map_err(|_| "offline TTL hours must be a positive integer".to_string())?;
    let audit_retention_days = form
        .audit_retention_days
        .trim()
        .parse::<u32>()
        .map_err(|_| "audit retention days must be a positive integer".to_string())?;
    // HTML checkboxes are only sent in the form body when checked. Any present
    // value counts as "on"; absence means the box was unchecked.
    let update_check_enabled = form.update_check_enabled.is_some();
    Ok(RuntimeSettings {
        max_payload_bytes,
        offline_ttl_hours,
        audit_retention_days,
        update_check_enabled,
    })
}
