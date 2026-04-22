//! Integration tests for the blob REST endpoints. Spins up a real axum
//! server on a random port, enrolls a device, uploads ciphertext, and
//! verifies download returns the same bytes.

use std::{net::SocketAddr, sync::Arc};

use axum::Router;
use rustclip_shared::rest::BlobUploadResponse;
use sqlx::query;
use tempfile::TempDir;
use tokio::net::TcpListener;
use uuid::Uuid;

use crate::{
    config::Config,
    metrics::MetricsHub,
    rate_limit::RateLimiter,
    settings::{RuntimeSettings, SettingsStore},
    state::AppState,
    test_util::test_pool,
    tokens,
    ws::hub::Hub,
};

async fn spawn_app(pool: sqlx::SqlitePool) -> (SocketAddr, TempDir) {
    let tmp = TempDir::new().unwrap();
    let config = Arc::new(Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        data_dir: tmp.path().to_path_buf(),
        public_url: "http://localhost".into(),
        admin_username: None,
        admin_password: None,
        max_payload_bytes: 1024 * 1024,
        offline_ttl_hours: 24,
        trusted_proxies: Vec::new(),
        metrics_token: None,
    });
    tokio::fs::create_dir_all(config.blobs_dir()).await.unwrap();

    let settings = SettingsStore::from_values(RuntimeSettings {
        max_payload_bytes: 1024 * 1024,
        offline_ttl_hours: 24,
        audit_retention_days: 90,
        update_check_enabled: false,
    });
    let state = AppState {
        db: pool,
        config,
        settings,
        hub: Arc::new(Hub::new()),
        auth_limiter: RateLimiter::new(),
        metrics: Arc::new(MetricsHub::new()),
        update_state: crate::update_check::UpdateState::new(),
    };
    let app = Router::new()
        .nest("/api/v1", crate::api::router(state.clone()))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, tmp)
}

async fn seed_device(pool: &sqlx::SqlitePool) -> String {
    let user_id = Uuid::new_v4();
    query(
        "INSERT INTO users (id, username, display_name, password_hash, is_admin, created_at) \
         VALUES (?, 'bob', 'Bob', 'dummy', 0, 0)",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();

    let token = tokens::generate_token().unwrap();
    query(
        "INSERT INTO devices (id, user_id, device_name, platform, device_token_hash, created_at) \
         VALUES (?, ?, 'd', 'macos', ?, 0)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(&token.hash)
    .execute(pool)
    .await
    .unwrap();

    token.plaintext
}

#[tokio::test]
async fn blob_round_trip() {
    let pool = test_pool().await;
    let token = seed_device(&pool).await;
    let (addr, _tmp) = spawn_app(pool).await;

    let payload = vec![7u8; 200 * 1024]; // 200 KiB forces a real write
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/api/v1/blobs"))
        .bearer_auth(&token)
        .header("content-type", "application/octet-stream")
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "upload status: {}",
        resp.status()
    );
    let upload: BlobUploadResponse = resp.json().await.unwrap();
    assert_eq!(upload.byte_length, payload.len() as i64);
    assert_eq!(upload.sha256_hex.len(), 64);

    let got = client
        .get(format!("http://{addr}/api/v1/blobs/{}", upload.blob_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(got.status().is_success());
    let bytes = got.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), payload.as_slice());

    let deleted = client
        .delete(format!("http://{addr}/api/v1/blobs/{}", upload.blob_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 204);

    let after = client
        .get(format!("http://{addr}/api/v1/blobs/{}", upload.blob_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(after.status(), 404);
}

#[tokio::test]
async fn upload_rejects_unauthenticated() {
    let pool = test_pool().await;
    let _token = seed_device(&pool).await;
    let (addr, _tmp) = spawn_app(pool).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/blobs"))
        .header("content-type", "application/octet-stream")
        .body(vec![1u8; 10])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn blob_uploads_not_throttled_by_auth_limiter() {
    // Regression: the per-IP auth limiter must NOT cover /blobs, otherwise
    // heavy users hit 429 on their 11th image of the minute.
    let pool = test_pool().await;
    let token = seed_device(&pool).await;
    let (addr, _tmp) = spawn_app(pool).await;

    let client = reqwest::Client::new();
    for i in 0..15 {
        let resp = client
            .post(format!("http://{addr}/api/v1/blobs"))
            .bearer_auth(&token)
            .header("content-type", "application/octet-stream")
            .body(vec![i as u8; 32])
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "upload {} was throttled: {}",
            i,
            resp.status()
        );
    }
}

#[tokio::test]
async fn upload_rejects_empty_body() {
    let pool = test_pool().await;
    let token = seed_device(&pool).await;
    let (addr, _tmp) = spawn_app(pool).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/blobs"))
        .bearer_auth(&token)
        .header("content-type", "application/octet-stream")
        .header("content-length", "0")
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);
}
