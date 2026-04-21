//! REST request and response envelopes shared between server and client.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub enrollment_token: String,
    pub password: String,
    /// Base64-encoded 32-byte content salt generated client-side.
    pub content_salt_b64: String,
    pub device_name: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub device_token: String,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub device_name: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub device_token: String,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub username: String,
    pub display_name: String,
    /// Content salt so the client can derive the content key.
    pub content_salt_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: Uuid,
    pub device_name: String,
    pub platform: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeResponse {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub device: DeviceInfo,
}

/// Response from `POST /api/v1/blobs`. The server has persisted the
/// ciphertext to durable storage and returns its id and content hash. The
/// client then announces the blob via a WS `clip_event`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobUploadResponse {
    pub blob_id: Uuid,
    pub sha256_hex: String,
    pub byte_length: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}
