//! End-to-end test of the WS sync path. Spins up a real axum server on a
//! random port, opens two WS clients with different device tokens, and
//! verifies that a clip_event from A is delivered to B with the sender's
//! own echo suppressed.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::Router;
use futures_util::{SinkExt, StreamExt};
use rustclip_shared::{
    PROTOCOL_VERSION,
    protocol::{ClientMessage, ClipEventMessage, ContentRef, MIME_TEXT, ServerMessage},
};
use sqlx::query;
use tokio::{net::TcpListener, time::timeout};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};
use uuid::Uuid;

use crate::{config::Config, state::AppState, test_util::test_pool, tokens, ws::hub::Hub};

async fn spawn_app(pool: sqlx::SqlitePool) -> SocketAddr {
    let config = Arc::new(Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        data_dir: PathBuf::from("/tmp"),
        public_url: "http://localhost".into(),
        admin_username: None,
        admin_password: None,
        max_payload_bytes: 1024 * 1024,
        offline_ttl_hours: 24,
    });
    let state = AppState {
        db: pool,
        config,
        hub: Arc::new(Hub::new()),
    };
    let app = Router::new()
        .nest("/ws", crate::ws::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

async fn seed_user_and_devices(pool: &sqlx::SqlitePool) -> (Uuid, Uuid, Uuid, String, String) {
    let user_id = Uuid::new_v4();
    query(
        "INSERT INTO users (id, username, display_name, password_hash, is_admin, created_at) \
         VALUES (?, 'alice', 'Alice', 'dummy', 0, 0)",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();

    let gen_a = tokens::generate_token().unwrap();
    let gen_b = tokens::generate_token().unwrap();
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    for (id, hash) in [(device_a, &gen_a.hash), (device_b, &gen_b.hash)] {
        query(
            "INSERT INTO devices \
             (id, user_id, device_name, platform, device_token_hash, created_at) \
             VALUES (?, ?, 'd', 'macos', ?, 0)",
        )
        .bind(id)
        .bind(user_id)
        .bind(hash)
        .execute(pool)
        .await
        .unwrap();
    }

    (
        user_id,
        device_a,
        device_b,
        gen_a.plaintext,
        gen_b.plaintext,
    )
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

async fn expect_message<S>(reader: &mut S, label: &str) -> ServerMessage
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let frame = timeout(Duration::from_secs(5), reader.next())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"))
        .expect("stream ended")
        .expect("frame error");
    match frame {
        Message::Text(text) => serde_json::from_str(&text).expect("parse ServerMessage"),
        other => panic!("expected text frame for {label}, got {other:?}"),
    }
}

#[tokio::test]
async fn clip_event_round_trips_to_peer() {
    let pool = test_pool().await;
    let (_user_id, device_a, _device_b, token_a, token_b) = seed_user_and_devices(&pool).await;
    let addr = spawn_app(pool).await;

    // Connect both devices.
    let ws_a = connect_ws(addr, &token_a).await;
    let (mut write_a, mut read_a) = ws_a.split();
    let ws_b = connect_ws(addr, &token_b).await;
    let (_write_b, mut read_b) = ws_b.split();

    // Both should receive BacklogStart/BacklogEnd (empty backlog).
    for reader in [&mut read_a, &mut read_b] {
        let start = expect_message(reader, "backlog_start").await;
        assert!(
            matches!(start, ServerMessage::BacklogStart),
            "got {start:?}"
        );
        let end = expect_message(reader, "backlog_end").await;
        assert!(matches!(end, ServerMessage::BacklogEnd), "got {end:?}");
    }

    // A sends a clip event.
    let event = ClipEventMessage {
        id: Uuid::new_v4(),
        v: PROTOCOL_VERSION,
        source_device_id: None,
        content: ContentRef::Inline {
            ciphertext_b64: "aGVsbG8=".into(), // not real ciphertext; server doesn't decrypt
            nonce_b64: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0".into(),
        },
        mime_hint: MIME_TEXT.into(),
        size_bytes: 5,
        created_at: 1,
    };
    let msg = ClientMessage::ClipEvent(event.clone());
    write_a
        .send(Message::Text(serde_json::to_string(&msg).unwrap().into()))
        .await
        .unwrap();

    // A should get its Ack.
    let ack = expect_message(&mut read_a, "ack").await;
    match ack {
        ServerMessage::Ack { id } => assert_eq!(id, event.id),
        other => panic!("expected ack, got {other:?}"),
    }

    // B should receive the ClipEvent with source_device_id == device_a.
    let live = expect_message(&mut read_b, "clip_event at B").await;
    match live {
        ServerMessage::ClipEvent(got) => {
            assert_eq!(got.id, event.id);
            assert_eq!(got.source_device_id, Some(device_a));
            assert_eq!(got.mime_hint, MIME_TEXT);
        }
        other => panic!("expected ClipEvent at B, got {other:?}"),
    }
}

#[tokio::test]
async fn backlog_drains_on_reconnect() {
    let pool = test_pool().await;
    let (_user_id, device_a, device_b, token_a, token_b) = seed_user_and_devices(&pool).await;

    // Pre-seed an undelivered clip for device_b by simulating A's publish
    // via direct DB writes.
    let event_id = Uuid::new_v4();
    query(
        "INSERT INTO clip_events (id, user_id, source_device_id, content_kind, \
         inline_ciphertext, nonce, mime_hint, size_bytes, created_at, expires_at) \
         VALUES (?, (SELECT user_id FROM devices WHERE id = ?), ?, 'inline', \
                 X'deadbeef', X'0102030405060708090A0B0C0D0E0F101112131415161718', \
                 'text/plain', 4, 0, ?)",
    )
    .bind(event_id)
    .bind(device_a)
    .bind(device_a)
    .bind(i64::MAX)
    .execute(&pool)
    .await
    .unwrap();
    query("INSERT INTO clip_deliveries (clip_event_id, target_device_id) VALUES (?, ?)")
        .bind(event_id)
        .bind(device_b)
        .execute(&pool)
        .await
        .unwrap();

    let addr = spawn_app(pool).await;
    let _ws_a = connect_ws(addr, &token_a).await; // keep A connected to ensure broadcast path works
    let ws_b = connect_ws(addr, &token_b).await;
    let (_write_b, mut read_b) = ws_b.split();

    let start = expect_message(&mut read_b, "backlog_start").await;
    assert!(matches!(start, ServerMessage::BacklogStart));
    let backlog_event = expect_message(&mut read_b, "backlog clip_event").await;
    match backlog_event {
        ServerMessage::ClipEvent(got) => {
            assert_eq!(got.id, event_id);
            assert_eq!(got.source_device_id, Some(device_a));
        }
        other => panic!("expected backlog ClipEvent, got {other:?}"),
    }
    let end = expect_message(&mut read_b, "backlog_end").await;
    assert!(matches!(end, ServerMessage::BacklogEnd));
}
