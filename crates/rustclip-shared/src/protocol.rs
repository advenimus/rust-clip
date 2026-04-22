//! WebSocket protocol shared between client and server.
//!
//! Every message is a JSON object with a `type` discriminator and a `v`
//! protocol version tag at the top level. Payload content (ciphertext, nonce)
//! is base64-encoded because JSON cannot carry binary natively.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::PROTOCOL_VERSION;

pub const WS_SUBPROTOCOL: &str = "rustclip.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    ClipEvent(ClipEventMessage),
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    ClipEvent(ClipEventMessage),
    Ack { id: Uuid },
    BacklogStart,
    BacklogEnd,
    Error { code: String, message: String },
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipEventMessage {
    /// Client-generated event id. Also serves as dedupe key for the receiving
    /// side.
    pub id: Uuid,
    /// Protocol version this message was produced against.
    #[serde(default = "default_version")]
    pub v: u32,
    /// Source device id. Absent when a client produces the message; the server
    /// fills it in when broadcasting to peers.
    #[serde(default)]
    pub source_device_id: Option<Uuid>,
    pub content: ContentRef,
    /// Plaintext MIME hint (text/plain, image/png, application/octet-stream, ...).
    pub mime_hint: String,
    pub size_bytes: i64,
    /// Client's wall-clock timestamp (unix milliseconds) at copy time.
    pub created_at: i64,
}

fn default_version() -> u32 {
    PROTOCOL_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentRef {
    Inline {
        ciphertext_b64: String,
        nonce_b64: String,
    },
    Blob {
        blob_id: Uuid,
        nonce_b64: String,
        sha256_hex: String,
    },
}

impl ContentRef {
    pub fn is_inline(&self) -> bool {
        matches!(self, Self::Inline { .. })
    }
    pub fn is_blob(&self) -> bool {
        matches!(self, Self::Blob { .. })
    }
}

pub const MIME_TEXT: &str = "text/plain; charset=utf-8";
pub const MIME_PNG: &str = "image/png";
pub const MIME_BUNDLE: &str = "application/x-rustclip-bundle";

/// Build the AAD (additional authenticated data) that the AEAD binds
/// alongside the ciphertext. Senders populate `source_device_id`
/// with their own device id before encrypting so receivers can detect
/// a server that's forging the origin of a replayed ciphertext.
///
/// Layout:
/// - 12 bytes: `b"rustclip.v2\0"` (domain separator + version)
/// - 16 bytes: event id (UUID)
/// - 16 bytes: source device id (UUID), all zeros if absent
/// - 4 bytes: LE `u32` mime_hint length
/// - N bytes: mime_hint UTF-8
/// - 8 bytes: LE `i64` size_bytes
/// - 8 bytes: LE `i64` created_at
/// - 1 byte: content tag (`0x01` inline, `0x02` blob)
/// - 16 bytes: blob_id (blob-only)
///
/// `sha256_hex` for blobs is NOT in AAD — the client verifies it
/// separately against the downloaded bytes (see C3). Including it
/// would force the sender to encrypt-then-hash before knowing what
/// to bind, and the AEAD already authenticates the ciphertext on
/// the receiver side.
pub fn build_aad(event: &ClipEventMessage) -> Vec<u8> {
    let mut aad = Vec::with_capacity(128);
    aad.extend_from_slice(b"rustclip.v2\0");
    aad.extend_from_slice(event.id.as_bytes());
    let source = event
        .source_device_id
        .as_ref()
        .map(|u| *u.as_bytes())
        .unwrap_or([0u8; 16]);
    aad.extend_from_slice(&source);
    let mime = event.mime_hint.as_bytes();
    aad.extend_from_slice(&(mime.len() as u32).to_le_bytes());
    aad.extend_from_slice(mime);
    aad.extend_from_slice(&event.size_bytes.to_le_bytes());
    aad.extend_from_slice(&event.created_at.to_le_bytes());
    match &event.content {
        ContentRef::Inline { .. } => aad.push(0x01),
        ContentRef::Blob { blob_id, .. } => {
            aad.push(0x02);
            aad.extend_from_slice(blob_id.as_bytes());
        }
    }
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_changes_when_any_metadata_field_is_touched() {
        let base = ClipEventMessage {
            id: Uuid::from_bytes([1u8; 16]),
            v: PROTOCOL_VERSION,
            source_device_id: Some(Uuid::from_bytes([2u8; 16])),
            content: ContentRef::Inline {
                ciphertext_b64: "c3dhcAo=".into(),
                nonce_b64: "bm9uY2U=".into(),
            },
            mime_hint: MIME_TEXT.into(),
            size_bytes: 42,
            created_at: 1_700_000_000_000,
        };
        let aad0 = build_aad(&base);

        let mut m = base.clone();
        m.mime_hint = MIME_PNG.into();
        assert_ne!(aad0, build_aad(&m), "mime flips must reflect in AAD");

        let mut m = base.clone();
        m.size_bytes = 43;
        assert_ne!(aad0, build_aad(&m));

        let mut m = base.clone();
        m.created_at += 1;
        assert_ne!(aad0, build_aad(&m));

        let mut m = base.clone();
        m.source_device_id = Some(Uuid::from_bytes([9u8; 16]));
        assert_ne!(aad0, build_aad(&m));

        let mut m = base.clone();
        m.content = ContentRef::Blob {
            blob_id: Uuid::from_bytes([3u8; 16]),
            nonce_b64: "n".into(),
            sha256_hex: "".into(),
        };
        assert_ne!(aad0, build_aad(&m), "inline vs blob tag differs");
    }

    #[test]
    fn clip_event_roundtrip() {
        let msg = ClipEventMessage {
            id: Uuid::nil(),
            v: PROTOCOL_VERSION,
            source_device_id: None,
            content: ContentRef::Inline {
                ciphertext_b64: "aGVsbG8=".into(),
                nonce_b64: "bm9uY2U=".into(),
            },
            mime_hint: MIME_TEXT.into(),
            size_bytes: 5,
            created_at: 0,
        };
        let s = serde_json::to_string(&ClientMessage::ClipEvent(msg.clone())).unwrap();
        let back: ClientMessage = serde_json::from_str(&s).unwrap();
        match back {
            ClientMessage::ClipEvent(roundtripped) => {
                assert_eq!(roundtripped.mime_hint, msg.mime_hint);
                assert!(roundtripped.content.is_inline());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_ack() {
        let s = serde_json::to_string(&ServerMessage::Ack { id: Uuid::nil() }).unwrap();
        assert!(s.contains("\"type\":\"ack\""));
        let back: ServerMessage = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ServerMessage::Ack { .. }));
    }
}
