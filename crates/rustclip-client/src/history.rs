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

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use uuid::Uuid;

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
}

impl History {
    pub fn open_default() -> Result<Self> {
        let path = history_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        Self::open(&path)
    }

    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening history db {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("setting WAL journal mode")?;
        conn.pragma_update(None, "foreign_keys", true)
            .context("enabling foreign keys")?;
        init_schema(&conn)?;
        Ok(Self { conn })
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
        self.conn
            .execute(
                "INSERT OR REPLACE INTO history_items \
                 (id, direction, kind, preview, size_bytes, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    event_id.as_bytes().as_slice(),
                    direction.as_str(),
                    kind.as_str(),
                    preview,
                    size_bytes,
                    now,
                ],
            )
            .context("inserting history row")?;
        self.enforce_retention(DEFAULT_MAX_ITEMS, DEFAULT_MAX_AGE_MS, now)?;
        Ok(())
    }

    pub fn list(&self, limit: i64) -> Result<Vec<HistoryItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, direction, kind, preview, size_bytes, created_at \
             FROM history_items ORDER BY created_at DESC, rowid DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let id_bytes: Vec<u8> = row.get(0)?;
            let id = Uuid::from_slice(&id_bytes).unwrap_or_else(|_| Uuid::nil());
            Ok(HistoryItem {
                id,
                direction: row.get(1)?,
                kind: HistoryKind::from_db(&row.get::<_, String>(2)?),
                preview: row.get(3)?,
                size_bytes: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
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
