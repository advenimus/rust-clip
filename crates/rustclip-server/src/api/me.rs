use axum::Json;
use rustclip_shared::rest::{DeviceInfo, MeResponse};

use crate::api::{ApiError, device_auth::DeviceAuth};

pub async fn show(auth: DeviceAuth) -> Result<Json<MeResponse>, ApiError> {
    Ok(Json(MeResponse {
        user_id: auth.user_id,
        username: auth.username,
        display_name: auth.display_name,
        device: DeviceInfo {
            device_id: auth.device_id,
            device_name: auth.device_name,
            platform: auth.platform,
            created_at: auth.created_at,
            last_seen_at: auth.last_seen_at,
        },
    }))
}
