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
    /// Optional on-disk image blob store. Present only when the
    /// History was opened with the user's content key — the preview
    /// cipher and the image cipher share one derivation. When absent
    /// (plaintext-mode history, e.g. logged-out GUI fallback), image
    /// recopy simply returns "not available".
    image_store: Option<crate::image_history::ImageHistoryStore>,
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
        let image_store = crate::image_history::ImageHistoryStore::open_default(content_key)?;
        Self::open_with_key_and_image_store(&path, content_key, Some(image_store))
    }

    pub fn open(path: &Path) -> Result<Self> {
        let conn = open_connection(path)?;
        Ok(Self {
            conn,
            cipher: None,
            image_store: None,
        })
    }

    pub fn open_with_key(path: &Path, content_key: &[u8; 32]) -> Result<Self> {
        Self::open_with_key_and_image_store(path, content_key, None)
    }

    /// Test-friendly constructor: caller supplies an explicit
    /// `ImageHistoryStore` (or `None` to disable image retention
    /// hooks). Production code goes through `open_default_with_key`
    /// which opens the store at its default path.
    pub fn open_with_key_and_image_store(
        path: &Path,
        content_key: &[u8; 32],
        image_store: Option<crate::image_history::ImageHistoryStore>,
    ) -> Result<Self> {
        let conn = open_connection(path)?;
        let subkey = derive_history_subkey(content_key);
        let cipher = XChaCha20Poly1305::new((&subkey).into());
        Ok(Self {
            conn,
            cipher: Some(cipher),
            image_store,
        })
    }

    /// Borrow the image store, if one is attached. `cmd_copy_history_item`
    /// goes through this to decrypt a past image PNG on demand.
    pub fn image_store(&self) -> Option<&crate::image_history::ImageHistoryStore> {
        self.image_store.as_ref()
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
        // Snapshot the bundle-row ids before we drop the table — we
        // need them to wipe the matching inbox folders after the DELETE
        // succeeds. Image files are handled by `image_store.clear_all`
        // which scans the directory directly.
        let bundle_ids = self
            .collect_ids_of_kind(HistoryKind::Bundle)
            .unwrap_or_default();
        self.conn
            .execute("DELETE FROM history_items", [])
            .context("clearing history")?;
        if let Some(store) = &self.image_store {
            if let Err(e) = store.clear_all() {
                tracing::warn!(error = %e, "clearing image-history store");
            }
        }
        for id in bundle_ids {
            if let Err(e) = crate::files::remove_inbox_dir(id) {
                tracing::warn!(event_id = %id, error = %e, "removing inbox dir on history clear");
            }
        }
        Ok(())
    }

    fn enforce_retention(&self, max_items: i64, max_age_ms: i64, now: i64) -> Result<()> {
        let cutoff = now - max_age_ms;
        // Select the ids + kinds that will be evicted so we can delete
        // their on-disk companions after the SQL DELETE succeeds. Order
        // matters: SQL delete first, file cleanup second — best-effort.
        // If the process dies between the two, we leak files on disk,
        // which the next `clear_all()` / `clear()` will mop up.
        let age_evict = self
            .select_ids_and_kinds_where("created_at < ?", params![cutoff])
            .unwrap_or_default();
        self.conn
            .execute(
                "DELETE FROM history_items WHERE created_at < ?",
                params![cutoff],
            )
            .context("retention: age")?;

        let count_evict = self
            .select_ids_and_kinds_where(
                "id IN ( \
                    SELECT id FROM history_items \
                    ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ? \
                 )",
                params![max_items],
            )
            .unwrap_or_default();
        self.conn
            .execute(
                "DELETE FROM history_items WHERE id IN ( \
                    SELECT id FROM history_items \
                    ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ? \
                 )",
                params![max_items],
            )
            .context("retention: count")?;

        for (id, kind) in age_evict.into_iter().chain(count_evict) {
            self.cleanup_evicted_payload(id, kind);
        }
        Ok(())
    }

    fn collect_ids_of_kind(&self, want: HistoryKind) -> Result<Vec<Uuid>> {
        let kind_str = want.as_str();
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM history_items WHERE kind = ?")?;
        let rows: Vec<Vec<u8>> = stmt
            .query_map(params![kind_str], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|b| Uuid::from_slice(&b).ok())
            .collect())
    }

    fn select_ids_and_kinds_where(
        &self,
        where_clause: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<(Uuid, HistoryKind)>> {
        let sql = format!("SELECT id, kind FROM history_items WHERE {where_clause}");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: Vec<(Vec<u8>, String)> = stmt
            .query_map(params, |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(bytes, kind)| {
                let id = Uuid::from_slice(&bytes).ok()?;
                Some((id, HistoryKind::from_db(&kind)))
            })
            .collect())
    }

    fn cleanup_evicted_payload(&self, id: Uuid, kind: HistoryKind) {
        match kind {
            HistoryKind::Image => {
                if let Some(store) = &self.image_store {
                    if let Err(e) = store.delete(id) {
                        tracing::warn!(event_id = %id, error = %e, "removing evicted image blob");
                    }
                }
            }
            HistoryKind::Bundle => {
                if let Err(e) = crate::files::remove_inbox_dir(id) {
                    tracing::warn!(event_id = %id, error = %e, "removing evicted inbox dir");
                }
            }
            HistoryKind::Text => {}
        }
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
///
/// `pub(crate)` so `image_history` can reuse the same derivation and
/// keep a single "history subkey" across preview rows and image blobs.
pub(crate) fn derive_history_subkey(content_key: &[u8; 32]) -> [u8; 32] {
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

    /// Helper: opens a `History` with a test-isolated image store
    /// rooted at a sibling tempdir path. Returns both the DB tmpdir
    /// and the image-dir tmpdir so the caller can assert against
    /// on-disk state.
    fn open_test_with_image_store(key: [u8; 32]) -> (TempDir, TempDir, History) {
        let db_tmp = TempDir::new().unwrap();
        let img_tmp = TempDir::new().unwrap();
        let db_path = db_tmp.path().join("history.db");
        let store = crate::image_history::ImageHistoryStore::open_at(img_tmp.path(), &key).unwrap();
        let h = History::open_with_key_and_image_store(&db_path, &key, Some(store)).unwrap();
        (db_tmp, img_tmp, h)
    }

    #[test]
    fn retention_count_deletes_image_blobs_for_evicted_rows() {
        let key = [42u8; 32];
        let (_db_tmp, img_tmp, mut h) = open_test_with_image_store(key);

        // Insert 3 image rows and stash a blob per row through the
        // attached store.
        let store = h.image_store().cloned().unwrap();
        let mut ids = Vec::new();
        for n in 0..3u8 {
            let id = Uuid::new_v4();
            h.record_image(Direction::Incoming, 10, 10, 400, id)
                .unwrap();
            store.put(id, &[n; 32]).unwrap();
            ids.push(id);
        }
        // All 3 blobs on disk.
        for id in &ids {
            assert!(
                img_tmp.path().join(format!("{id}.enc")).exists(),
                "expected blob for {id} before retention",
            );
        }

        // Keep only the newest 1 item; the 2 older ones should lose
        // both their SQL row AND their disk blob.
        h.enforce_retention(1, DEFAULT_MAX_AGE_MS, now_millis())
            .unwrap();
        let remaining = h.list(10).unwrap();
        assert_eq!(remaining.len(), 1);
        let kept_id = remaining[0].id;
        for id in &ids {
            let blob_path = img_tmp.path().join(format!("{id}.enc"));
            if *id == kept_id {
                assert!(
                    blob_path.exists(),
                    "kept row {id} should still have its blob"
                );
            } else {
                assert!(!blob_path.exists(), "evicted row {id} should have no blob");
            }
        }
    }

    #[test]
    fn clear_wipes_image_store() {
        let key = [77u8; 32];
        let (_db_tmp, img_tmp, mut h) = open_test_with_image_store(key);
        let store = h.image_store().cloned().unwrap();
        for _ in 0..4 {
            let id = Uuid::new_v4();
            h.record_image(Direction::Outgoing, 1, 1, 100, id).unwrap();
            store.put(id, b"png-data").unwrap();
        }
        let before: Vec<_> = std::fs::read_dir(img_tmp.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(before.len(), 4);

        h.clear().unwrap();
        let after: Vec<_> = std::fs::read_dir(img_tmp.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert!(
            after.is_empty(),
            "expected image-history dir empty, got {after:?}"
        );
    }
}
