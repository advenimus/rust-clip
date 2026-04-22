//! Blob storage endpoints.
//!
//! Large encrypted clipboard payloads (images, files) go through these
//! endpoints instead of riding inline inside a WS `clip_event`. The server
//! stores the ciphertext on disk under `data_dir/blobs/<uuid>` and records
//! metadata in the `blobs` table. A background sweeper reaps expired rows
//! and their files.

use std::path::PathBuf;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rustclip_shared::rest::BlobUploadResponse;
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use tokio_util::io::ReaderStream;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{api::ApiError, api::device_auth::DeviceAuth, db::now_millis, state::AppState};

/// Hard upper bound on blob upload body size (also ceils the
/// settings-configurable `max_payload_bytes`). 1 GiB.
pub const BLOB_BODY_LIMIT: usize = 1024 * 1024 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(upload))
        .route("/{blob_id}", get(download).delete(remove))
        // Override the api-level default (1 MiB) — the handler still enforces
        // the runtime `max_payload_bytes` cap on its own. This layer is purely
        // the preflight wall so axum doesn't buffer more than 1 GiB into RAM.
        .layer(DefaultBodyLimit::max(BLOB_BODY_LIMIT))
}

async fn upload(
    State(state): State<AppState>,
    auth: DeviceAuth,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<BlobUploadResponse>, ApiError> {
    let declared_len = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let runtime = state.settings.snapshot().await;
    let max = runtime.max_payload_bytes;
    if let Some(n) = declared_len {
        if n > max {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!("blob exceeds server limit of {max} bytes"),
            ));
        }
    }

    fs::create_dir_all(state.config.blobs_dir())
        .await
        .map_err(|e| {
            warn!(error = ?e, "failed to create blobs dir");
            ApiError::internal("blob storage unavailable")
        })?;

    let blob_id = Uuid::new_v4();
    let storage_path = blob_path(&state, blob_id);

    let mut stream = body.into_data_stream();
    let mut file = File::create(&storage_path).await.map_err(|e| {
        warn!(error = ?e, path = %storage_path.display(), "opening blob file");
        ApiError::internal("blob write failed")
    })?;
    let mut hasher = Sha256::new();
    let mut written: u64 = 0;

    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            warn!(error = ?e, "reading upload chunk");
            ApiError::new(StatusCode::BAD_REQUEST, "bad_upload", "upload stream error")
        })?;
        written = written.saturating_add(chunk.len() as u64);
        if written > max {
            drop(file);
            let _ = fs::remove_file(&storage_path).await;
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!("blob exceeds server limit of {max} bytes"),
            ));
        }
        hasher.update(&chunk);
        if let Err(e) = file.write_all(&chunk).await {
            warn!(error = ?e, "writing blob chunk");
            drop(file);
            let _ = fs::remove_file(&storage_path).await;
            return Err(ApiError::internal("blob write failed"));
        }
    }

    if let Err(e) = file.flush().await {
        warn!(error = ?e, "flushing blob file");
        let _ = fs::remove_file(&storage_path).await;
        return Err(ApiError::internal("blob write failed"));
    }
    drop(file);

    if written == 0 {
        let _ = fs::remove_file(&storage_path).await;
        return Err(ApiError::validation("blob body was empty"));
    }

    let sha_hex = hex::encode(hasher.finalize());
    let ttl_hours = runtime.offline_ttl_hours as i64;
    let expires_at =
        (OffsetDateTime::now_utc() + TimeDuration::hours(ttl_hours)).unix_timestamp() * 1000;
    let created_at = now_millis();
    let storage_path_str = storage_path.to_string_lossy().into_owned();

    let res = sqlx::query(
        "INSERT INTO blobs (id, sha256, byte_length, storage_path, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(blob_id)
    .bind(&sha_hex)
    .bind(written as i64)
    .bind(&storage_path_str)
    .bind(created_at)
    .bind(expires_at)
    .execute(&state.db)
    .await;

    if let Err(e) = res {
        let _ = fs::remove_file(&storage_path).await;
        return Err(ApiError::from(e));
    }

    debug!(
        %blob_id,
        uploader = %auth.device_id,
        bytes = written,
        sha = %sha_hex,
        "blob uploaded"
    );
    state.metrics.incr(&state.metrics.blob_uploads);

    Ok(Json(BlobUploadResponse {
        blob_id,
        sha256_hex: sha_hex,
        byte_length: written as i64,
    }))
}

#[derive(FromRow)]
struct BlobRow {
    sha256: String,
    byte_length: i64,
    storage_path: String,
}

async fn download(
    State(state): State<AppState>,
    _auth: DeviceAuth,
    Path(blob_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let row = sqlx::query_as::<_, BlobRow>(
        "SELECT sha256, byte_length, storage_path FROM blobs WHERE id = ?",
    )
    .bind(blob_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "blob not found"))?;

    let file = File::open(&row.storage_path).await.map_err(|e| {
        warn!(error = ?e, path = %row.storage_path, "opening blob for download");
        ApiError::new(StatusCode::NOT_FOUND, "not_found", "blob missing on disk")
    })?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, row.byte_length.into());
    if let Ok(v) = HeaderValue::from_str(&row.sha256) {
        headers.insert("X-Rustclip-Sha256", v);
    }

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    state.metrics.incr(&state.metrics.blob_downloads);
    Ok((StatusCode::OK, headers, body).into_response())
}

async fn remove(
    State(state): State<AppState>,
    _auth: DeviceAuth,
    Path(blob_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let row = sqlx::query_as::<_, BlobRow>(
        "SELECT sha256, byte_length, storage_path FROM blobs WHERE id = ?",
    )
    .bind(blob_id)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Ok(StatusCode::NO_CONTENT);
    };

    sqlx::query("DELETE FROM blobs WHERE id = ?")
        .bind(blob_id)
        .execute(&state.db)
        .await?;
    if let Err(e) = fs::remove_file(&row.storage_path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(error = ?e, path = %row.storage_path, "removing blob file");
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

fn blob_path(state: &AppState, id: Uuid) -> PathBuf {
    state.config.blobs_dir().join(id.to_string())
}
