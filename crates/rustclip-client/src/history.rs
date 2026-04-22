//! Per-device local clipboard history.
//!
//! Lives in a SQLite file under the user's data dir. Uses `rusqlite`
//! synchronously to avoid pulling a second async runtime into the desktop
//! binary. The store holds decrypted previews only — we do NOT persist the
//! original ciphertext or the raw image/file bytes beyond what Phase 5
//! already writes into `rustclip/inbox/`.
//!
//! Retention: capped at 100 items OR 7 days, whichever hits first. Enforced
//! on every insert. The `history clear` CLI wipes everything.

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, OsRng as AeadOsRng},
};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Tag we prefix on encrypted previews so readers can tell them apart
/// from legacy plaintext rows (pre-M6 databases). The body after the
/// colon is base64(nonce || ciphertext).
const ENCRYPTED_PREFIX: &str = "enc1:";

pub const DEFAULT_MAX_ITEMS: i64 = 100;
pub const DEFAULT_MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Longest text preview we store inline. Longer text gets truncated and
/// marked with `…` — full content is on the clipboard already.
pub const PREVIEW_MAX_CHARS: usize = 400;

#[derive(Debug, Clone)]
pub enum HistoryKind {
    Text,
    Image,
    Bundle,
}

impl HistoryKind {
    fn as_str(&self) -> &'static str {
        match self {
            HistoryKind::Text => "text",
            HistoryKind::Image => "image",
            HistoryKind::Bundle => "bundle",
        }
    }

    fn from_db(s: &str) -> Self {
        match s {
            "text" => HistoryKind::Text,
            "image" => HistoryKind::Image,
            _ => HistoryKind::Bundle,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Direction {
    Outgoing,
    Incoming,
}

impl Direction {
    fn as_str(&self) -> &'static str {
        match self {
            Direction::Outgoing => "outgoing",
            Direction::Incoming => "incoming",
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HistoryItem {
    pub id: Uuid,
    pub direction: String,
    pub kind: HistoryKind,
    pub preview: String,
    pub size_bytes: i64,
    pub created_at: i64,
}

pub struct History {
    conn: Connection,
    cipher: Option<XChaCha20Poly1305>,
}

impl History {
    /// Open the default history DB with no encryption. Used by tests
    /// and by code paths that don't have the content key to hand; any
    /// previews written through this path land as plaintext.
    pub fn open_default() -> Result<Self> {
        let path = history_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        Self::open(&path)
    }

    /// Open the default history DB with a preview cipher derived from
    /// the user's content key. On a same-user filesystem snapshot the
    /// SQLite file contains only ciphertext previews; reading them
    /// back requires access to the same keychain-stored content key.
    pub fn open_default_with_key(content_key: &[u8; 32]) -> Result<Self> {
        let path = history_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        Self::open_with_key(&path, content_key)
    }

    pub fn open(path: &Path) -> Result<Self> {
        let conn = open_connection(path)?;
        Ok(Self { conn, cipher: None })
    }

    pub fn open_with_key(path: &Path, content_key: &[u8; 32]) -> Result<Self> {
        let conn = open_connection(path)?;
        let subkey = derive_history_subkey(content_key);
        let cipher = XChaCha20Poly1305::new((&subkey).into());
        Ok(Self {
            conn,
            cipher: Some(cipher),
        })
    }

    pub fn record_text(&mut self, direction: Direction, text: &str, event_id: Uuid) -> Result<()> {
        let preview = truncate_preview(text);
        self.insert(
            event_id,
            direction,
            HistoryKind::Text,
            &preview,
            text.len() as i64,
        )
    }

    pub fn record_image(
        &mut self,
        direction: Direction,
        width: u32,
        height: u32,
        size_bytes: i64,
        event_id: Uuid,
    ) -> Result<()> {
        let preview = format!("image {width}x{height}");
        self.insert(
            event_id,
            direction,
            HistoryKind::Image,
            &preview,
            size_bytes,
        )
    }

    pub fn record_bundle(
        &mut self,
        direction: Direction,
        summary: &str,
        size_bytes: i64,
        event_id: Uuid,
    ) -> Result<()> {
        self.insert(
            event_id,
            direction,
            HistoryKind::Bundle,
            summary,
            size_bytes,
        )
    }

    fn insert(
        &mut self,
        event_id: Uuid,
        direction: Direction,
        kind: HistoryKind,
        preview: &str,
        size_bytes: i64,
    ) -> Result<()> {
        let now = now_millis();
        let stored = self.encode_preview(preview)?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO history_items \
                 (id, direction, kind, preview, size_bytes, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    event_id.as_bytes().as_slice(),
                    direction.as_str(),
                    kind.as_str(),
                    stored,
                    size_bytes,
                    now,
                ],
            )
            .context("inserting history row")?;
        self.enforce_retention(DEFAULT_MAX_ITEMS, DEFAULT_MAX_AGE_MS, now)?;
        Ok(())
    }

    fn encode_preview(&self, preview: &str) -> Result<String> {
        match &self.cipher {
            Some(cipher) => {
                let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
                let ct = cipher
                    .encrypt(&nonce, preview.as_bytes())
                    .map_err(|_| anyhow!("history preview encryption failed"))?;
                let mut combined = nonce.to_vec();
                combined.extend_from_slice(&ct);
                Ok(format!("{ENCRYPTED_PREFIX}{}", BASE64.encode(&combined)))
            }
            None => Ok(preview.to_string()),
        }
    }

    fn decode_preview(&self, stored: &str) -> String {
        if let Some(body) = stored.strip_prefix(ENCRYPTED_PREFIX) {
            match &self.cipher {
                Some(cipher) => match BASE64.decode(body.as_bytes()) {
                    Ok(combined) if combined.len() > 24 => {
                        let (nonce_bytes, ct) = combined.split_at(24);
                        let nonce = XNonce::from_slice(nonce_bytes);
                        match cipher.decrypt(nonce, ct) {
                            Ok(pt) => String::from_utf8_lossy(&pt).into_owned(),
                            Err(_) => "(undecryptable: wrong key?)".into(),
                        }
                    }
                    _ => "(undecryptable: malformed)".into(),
                },
                None => "(encrypted)".into(),
            }
        } else {
            // Legacy plaintext row written before M6.
            stored.to_string()
        }
    }

    pub fn list(&self, limit: i64) -> Result<Vec<HistoryItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, direction, kind, preview, size_bytes, created_at \
             FROM history_items ORDER BY created_at DESC, rowid DESC LIMIT ?",
        )?;
        // Collect raw rows first so the borrow on `stmt` ends before
        // we call `self.decode_preview(...)`.
        let raw: Vec<(Vec<u8>, String, String, String, i64, i64)> = stmt
            .query_map(params![limit], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .collect::<std::result::Result<_, _>>()?;
        let mut out = Vec::with_capacity(raw.len());
        for (id_bytes, direction, kind, stored_preview, size_bytes, created_at) in raw {
            let id = Uuid::from_slice(&id_bytes).unwrap_or_else(|_| Uuid::nil());
            out.push(HistoryItem {
                id,
                direction,
                kind: HistoryKind::from_db(&kind),
                preview: self.decode_preview(&stored_preview),
                size_bytes,
                created_at,
            });
        }
        Ok(out)
    }

    pub fn clear(&mut self) -> Result<()> {
        self.conn
            .execute("DELETE FROM history_items", [])
            .context("clearing history")?;
        Ok(())
    }

    fn enforce_retention(&self, max_items: i64, max_age_ms: i64, now: i64) -> Result<()> {
        let cutoff = now - max_age_ms;
        self.conn
            .execute(
                "DELETE FROM history_items WHERE created_at < ?",
                params![cutoff],
            )
            .context("retention: age")?;
        self.conn
            .execute(
                "DELETE FROM history_items WHERE id IN ( \
                    SELECT id FROM history_items \
                    ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ? \
                 )",
                params![max_items],
            )
            .context("retention: count")?;
        Ok(())
    }
}

fn open_connection(path: &Path) -> Result<Connection> {
    let conn =
        Connection::open(path).with_context(|| format!("opening history db {}", path.display()))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("setting WAL journal mode")?;
    conn.pragma_update(None, "foreign_keys", true)
        .context("enabling foreign keys")?;
    init_schema(&conn)?;
    Ok(conn)
}

/// Derive a domain-separated 32-byte subkey from the user's content
/// key. Pure SHA-256 with a static tag — not HKDF, but the input is
/// already a 256-bit random value so one round of hashing is plenty
/// for separation from the payload cipher.
fn derive_history_subkey(content_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"rustclip.history.v1\0");
    hasher.update(content_key);
    let out = hasher.finalize();
    let mut subkey = [0u8; 32];
    subkey.copy_from_slice(&out);
    subkey
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS history_items ( \
            id          BLOB PRIMARY KEY, \
            direction   TEXT NOT NULL, \
            kind        TEXT NOT NULL, \
            preview     TEXT NOT NULL, \
            size_bytes  INTEGER NOT NULL, \
            created_at  INTEGER NOT NULL \
         ); \
         CREATE INDEX IF NOT EXISTS history_items_time ON history_items(created_at DESC);",
    )
    .context("initializing history schema")
}

pub fn history_path() -> PathBuf {
    let base = dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(std::env::temp_dir);
    base.join("rustclip").join("history.db")
}

fn truncate_preview(text: &str) -> String {
    if text.chars().count() <= PREVIEW_MAX_CHARS {
        return text.to_string();
    }
    let cut: String = text.chars().take(PREVIEW_MAX_CHARS).collect();
    format!("{cut}…")
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_test() -> (TempDir, History) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.db");
        let h = History::open(&path).unwrap();
        (tmp, h)
    }

    fn open_test_encrypted(key: [u8; 32]) -> (TempDir, History) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.db");
        let h = History::open_with_key(&path, &key).unwrap();
        (tmp, h)
    }

    #[test]
    fn encrypted_preview_roundtrips_for_matching_key() {
        let key = [13u8; 32];
        let (tmp, mut h) = open_test_encrypted(key);
        h.record_text(Direction::Outgoing, "secret sauce", Uuid::new_v4())
            .unwrap();
        let items = h.list(10).unwrap();
        assert_eq!(items[0].preview, "secret sauce");

        // Re-open with the same key and the same row still decodes.
        drop(h);
        let h2 = History::open_with_key(&tmp.path().join("history.db"), &key).unwrap();
        assert_eq!(h2.list(10).unwrap()[0].preview, "secret sauce");
    }

    #[test]
    fn encrypted_preview_is_opaque_to_wrong_key() {
        let (tmp, mut h) = open_test_encrypted([1u8; 32]);
        h.record_text(Direction::Incoming, "inner text", Uuid::new_v4())
            .unwrap();
        drop(h);

        // Opening the same DB with a different key still reads rows
        // but the preview comes back as an "undecryptable" stub, not
        // the original plaintext.
        let h2 = History::open_with_key(&tmp.path().join("history.db"), &[2u8; 32]).unwrap();
        let items = h2.list(10).unwrap();
        assert_eq!(items.len(), 1);
        assert_ne!(items[0].preview, "inner text");
        assert!(items[0].preview.contains("undecryptable"));
    }

    #[test]
    fn encrypted_db_opened_without_key_returns_stub() {
        let (tmp, mut h) = open_test_encrypted([5u8; 32]);
        h.record_text(Direction::Outgoing, "hidden", Uuid::new_v4())
            .unwrap();
        drop(h);
        // No cipher on read-side.
        let h2 = History::open(&tmp.path().join("history.db")).unwrap();
        let preview = &h2.list(10).unwrap()[0].preview;
        assert_ne!(preview, "hidden");
        assert!(preview.contains("encrypted"));
    }

    #[test]
    fn plaintext_rows_survive_key_upgrade() {
        // A v0.1.x database predates M6 and has legacy plaintext
        // previews. Opening with a key should still return them
        // unchanged (the "enc1:" prefix is what gates decryption).
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.db");
        {
            let mut h = History::open(&path).unwrap();
            h.record_text(Direction::Outgoing, "legacy row", Uuid::new_v4())
                .unwrap();
        }
        let h = History::open_with_key(&path, &[9u8; 32]).unwrap();
        assert_eq!(h.list(10).unwrap()[0].preview, "legacy row");
    }

    #[test]
    fn insert_and_list() {
        let (_tmp, mut h) = open_test();
        h.record_text(Direction::Outgoing, "hello", Uuid::new_v4())
            .unwrap();
        h.record_image(Direction::Incoming, 10, 20, 400, Uuid::new_v4())
            .unwrap();
        let items = h.list(10).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].direction, "incoming");
        assert_eq!(items[1].preview, "hello");
    }

    #[test]
    fn retention_caps_item_count() {
        let (_tmp, mut h) = open_test();
        h.enforce_retention(2, DEFAULT_MAX_AGE_MS, now_millis())
            .unwrap();
        h.record_text(Direction::Outgoing, "a", Uuid::new_v4())
            .unwrap();
        h.record_text(Direction::Outgoing, "b", Uuid::new_v4())
            .unwrap();
        h.record_text(Direction::Outgoing, "c", Uuid::new_v4())
            .unwrap();
        // Each insert re-applies default retention (100 items); no trimming yet.
        assert_eq!(h.list(10).unwrap().len(), 3);
        // Now trim by count to 2.
        h.enforce_retention(2, DEFAULT_MAX_AGE_MS, now_millis())
            .unwrap();
        let items = h.list(10).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].preview, "c");
        assert_eq!(items[1].preview, "b");
    }

    #[test]
    fn preview_truncation() {
        let long = "x".repeat(PREVIEW_MAX_CHARS + 100);
        let (_tmp, mut h) = open_test();
        h.record_text(Direction::Outgoing, &long, Uuid::new_v4())
            .unwrap();
        let items = h.list(1).unwrap();
        assert!(items[0].preview.ends_with('…'));
        assert!(items[0].preview.chars().count() <= PREVIEW_MAX_CHARS + 1);
    }

    #[test]
    fn clear_wipes_all() {
        let (_tmp, mut h) = open_test();
        h.record_text(Direction::Outgoing, "x", Uuid::new_v4())
            .unwrap();
        h.clear().unwrap();
        assert!(h.list(10).unwrap().is_empty());
    }
}
