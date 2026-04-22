//! End-to-end test of the Phase 5 bundle path.
//!
//! Device A: POST /api/v1/blobs with arbitrary ciphertext (stand-in for an
//! encrypted tar), then send a WS ClipEvent with content kind "blob" and
//! mime `application/x-rustclip-bundle`. Device B should receive the same
//! event via WS and be able to GET /api/v1/blobs/:id back successfully.
//! This validates that the client's pack -> upload -> announce -> receive
//! -> download loop works against a real server wiring, without requiring
//! two Tauri clients.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::Router;
use futures_util::{SinkExt, StreamExt};
use rustclip_shared::{
    PROTOCOL_VERSION,
    protocol::{ClientMessage, ClipEventMessage, ContentRef, MIME_BUNDLE, ServerMessage},
    rest::BlobUploadResponse,
};
use sqlx::query;
use tempfile::TempDir;
use tokio::{net::TcpListener, time::timeout};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};
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
        .nest("/ws", crate::ws::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, tmp)
}

async fn seed_user_and_devices(pool: &sqlx::SqlitePool) -> (Uuid, Uuid, String, String) {
    let user_id = Uuid::new_v4();
    query(
        "INSERT INTO users (id, username, display_name, password_hash, is_admin, created_at) \
         VALUES (?, 'alice', 'Alice', 'dummy', 0, 0)",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();

    let token_a = tokens::generate_token().unwrap();
    let token_b = tokens::generate_token().unwrap();
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    for (id, hash) in [(device_a, &token_a.hash), (device_b, &token_b.hash)] {
        query(
            "INSERT INTO devices (id, user_id, device_name, platform, device_token_hash, created_at) \
             VALUES (?, ?, 'd', 'macos', ?, 0)",
        )
        .bind(id)
        .bind(user_id)
        .bind(hash)
        .execute(pool)
        .await
        .unwrap();
    }

    (device_a, device_b, token_a.plaintext, token_b.plaintext)
}

async fn connect_ws(
    addr: SocketAddr,
    token: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
    req.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    ws
}

async fn expect<S>(reader: &mut S, label: &str) -> ServerMessage
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let frame = timeout(Duration::from_secs(5), reader.next())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"))
        .expect("stream ended")
        .expect("frame error");
    match frame {
        Message::Text(t) => serde_json::from_str(&t).expect("parse ServerMessage"),
        other => panic!("expected text frame for {label}, got {other:?}"),
    }
}

#[tokio::test]
async fn bundle_flows_blob_upload_then_ws_then_blob_download() {
    let pool = test_pool().await;
    let (device_a, _device_b, token_a, token_b) = seed_user_and_devices(&pool).await;
    let (addr, _tmp) = spawn_app(pool).await;

    let http = reqwest::Client::new();
    let ciphertext_payload = vec![42u8; 128 * 1024]; // 128 KiB stand-in for encrypted tar

    // Device A uploads the blob via REST.
    let resp = http
        .post(format!("http://{addr}/api/v1/blobs"))
        .bearer_auth(&token_a)
        .header("content-type", "application/octet-stream")
        .body(ciphertext_payload.clone())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "blob upload failed");
    let upload: BlobUploadResponse = resp.json().await.unwrap();

    // Both devices connect; drain their empty backlog.
    let ws_a = connect_ws(addr, &token_a).await;
    let (mut write_a, mut read_a) = ws_a.split();
    let ws_b = connect_ws(addr, &token_b).await;
    let (_write_b, mut read_b) = ws_b.split();
    for r in [&mut read_a, &mut read_b] {
        assert!(matches!(
            expect(r, "backlog_start").await,
            ServerMessage::BacklogStart
        ));
        assert!(matches!(
            expect(r, "backlog_end").await,
            ServerMessage::BacklogEnd
        ));
    }

    // Device A announces the bundle via WS.
    let event = ClipEventMessage {
        id: Uuid::new_v4(),
        v: PROTOCOL_VERSION,
        source_device_id: None,
        content: ContentRef::Blob {
            blob_id: upload.blob_id,
            nonce_b64: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0".into(),
            sha256_hex: upload.sha256_hex.clone(),
        },
        mime_hint: MIME_BUNDLE.into(),
        size_bytes: upload.byte_length,
        created_at: 1,
    };
    let msg = ClientMessage::ClipEvent(event.clone());
    write_a
        .send(Message::Text(serde_json::to_string(&msg).unwrap().into()))
        .await
        .unwrap();
    match expect(&mut read_a, "ack").await {
        ServerMessage::Ack { id } => assert_eq!(id, event.id),
        other => panic!("expected ack, got {other:?}"),
    }

    // Device B receives the bundle event.
    let got = expect(&mut read_b, "clip_event at B").await;
    let blob_id = match got {
        ServerMessage::ClipEvent(e) => {
            assert_eq!(e.id, event.id);
            assert_eq!(e.mime_hint, MIME_BUNDLE);
            assert_eq!(e.source_device_id, Some(device_a));
            match e.content {
                ContentRef::Blob { blob_id, .. } => blob_id,
                other => panic!("expected Blob, got {other:?}"),
            }
        }
        other => panic!("expected ClipEvent at B, got {other:?}"),
    };

    // Device B downloads the ciphertext.
    let dl = http
        .get(format!("http://{addr}/api/v1/blobs/{blob_id}"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert!(dl.status().is_success());
    let bytes = dl.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), ciphertext_payload.as_slice());
}
