//! On-disk encrypted store for image payloads, keyed by event id.
//!
//! The preview-row in `history_items` only carries the string
//! `"image WxH"` — enough to render a history entry, not enough to
//! re-copy the picture. To let the user re-copy past images, we stash
//! the PNG bytes as `nonce(24) || ciphertext` under
//! `$DATA_LOCAL_DIR/rustclip/image-history/<event_id>.enc`, sealed
//! under the same history-subkey that encrypts previews. That keeps
//! the ciphertext opaque to a same-user backup / filesystem snapshot
//! while still letting the running client decrypt on demand.
//!
//! Storage is deliberately sibling to `inbox/` (where received bundles
//! are unpacked in the clear for Finder / Explorer paste). Mixing the
//! two would trip `files::all_under_inbox` which treats any file URL
//! pointing into inbox as an echo of our own write.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, OsRng as AeadOsRng},
};
use uuid::Uuid;

use crate::history::derive_history_subkey;

/// Fixed nonce size for XChaCha20-Poly1305. Stored as the first 24
/// bytes of every on-disk blob.
const NONCE_LEN: usize = 24;

#[derive(Clone)]
pub struct ImageHistoryStore {
    root: PathBuf,
    cipher: XChaCha20Poly1305,
}

impl ImageHistoryStore {
    /// Open the store under the user's default data dir.
    pub fn open_default(content_key: &[u8; 32]) -> Result<Self> {
        Self::open_at(&default_image_history_dir(), content_key)
    }

    /// Open the store rooted at an explicit directory. Used by tests
    /// that pass a `TempDir`.
    pub fn open_at(root: &Path, content_key: &[u8; 32]) -> Result<Self> {
        fs::create_dir_all(root)
            .with_context(|| format!("creating image-history dir {}", root.display()))?;
        let subkey = derive_history_subkey(content_key);
        let cipher = XChaCha20Poly1305::new((&subkey).into());
        Ok(Self {
            root: root.to_path_buf(),
            cipher,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Encrypt `png` under a fresh nonce and write `nonce || ciphertext`
    /// atomically (write-temp + rename) so a crash mid-write can't leave
    /// a truncated file that later decryption would blame on a wrong
    /// key.
    pub fn put(&self, event_id: Uuid, png: &[u8]) -> Result<()> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, png)
            .map_err(|_| anyhow!("image-history encryption failed"))?;

        let final_path = self.path_for(event_id);
        let tmp_path = final_path.with_extension("enc.tmp");
        {
            let mut f = fs::File::create(&tmp_path).with_context(|| {
                format!("creating image-history tmp file {}", tmp_path.display())
            })?;
            f.write_all(&nonce)
                .with_context(|| format!("writing nonce to {}", tmp_path.display()))?;
            f.write_all(&ciphertext)
                .with_context(|| format!("writing ciphertext to {}", tmp_path.display()))?;
            f.sync_all().ok();
        }
        fs::rename(&tmp_path, &final_path).with_context(|| {
            format!(
                "renaming {} -> {}",
                tmp_path.display(),
                final_path.display()
            )
        })?;
        Ok(())
    }

    /// Read the on-disk blob and decrypt back to PNG bytes. Returns
    /// `Ok(None)` if the file doesn't exist (pre-v0.2.1 rows, or a blob
    /// that the retention sweep wiped). Returns `Err` on malformed
    /// layout or AEAD failure.
    pub fn get(&self, event_id: Uuid) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(event_id);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("reading image-history blob {}", path.display())));
            }
        };
        if bytes.len() < NONCE_LEN + 16 {
            return Err(anyhow!(
                "image-history blob {} is malformed (length {})",
                path.display(),
                bytes.len()
            ));
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
        let nonce = XNonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("image-history decryption failed (wrong key or tampered?)"))?;
        Ok(Some(plaintext))
    }

    /// Best-effort remove. Missing file is not an error.
    pub fn delete(&self, event_id: Uuid) -> Result<()> {
        let path = self.path_for(event_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow::Error::new(e)
                .context(format!("removing image-history blob {}", path.display()))),
        }
    }

    /// Wipe every `.enc` file in the store root. Invoked by
    /// `History::clear`.
    pub fn clear_all(&self) -> Result<()> {
        let read = match fs::read_dir(&self.root) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!(
                    "scanning image-history dir {}",
                    self.root.display()
                )));
            }
        };
        for entry in read {
            let entry = entry.context("reading image-history dir entry")?;
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("enc") {
                if let Err(e) = fs::remove_file(&p) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(path = %p.display(), error = %e, "removing image-history blob");
                    }
                }
            }
        }
        Ok(())
    }

    fn path_for(&self, event_id: Uuid) -> PathBuf {
        self.root.join(format!("{event_id}.enc"))
    }
}

pub fn default_image_history_dir() -> PathBuf {
    let base = dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(std::env::temp_dir);
    base.join("rustclip").join("image-history")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn key(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = ImageHistoryStore::open_at(dir.path(), &key(0x11)).unwrap();
        let id = Uuid::new_v4();
        let png = b"fake-png-bytes-\x89PNG\r\n\x1a\n...".to_vec();
        store.put(id, &png).unwrap();
        let read = store.get(id).unwrap().unwrap();
        assert_eq!(read, png);
    }

    #[test]
    fn get_missing_returns_none() {
        let dir = TempDir::new().unwrap();
        let store = ImageHistoryStore::open_at(dir.path(), &key(0x22)).unwrap();
        let id = Uuid::new_v4();
        assert!(store.get(id).unwrap().is_none());
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let dir = TempDir::new().unwrap();
        let id = Uuid::new_v4();
        let png = b"pretend png".to_vec();
        {
            let s1 = ImageHistoryStore::open_at(dir.path(), &key(0x33)).unwrap();
            s1.put(id, &png).unwrap();
        }
        let s2 = ImageHistoryStore::open_at(dir.path(), &key(0x99)).unwrap();
        assert!(s2.get(id).is_err());
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let store = ImageHistoryStore::open_at(dir.path(), &key(0x44)).unwrap();
        let id = Uuid::new_v4();
        store.put(id, b"data").unwrap();
        store.delete(id).unwrap();
        store.delete(id).unwrap();
        assert!(store.get(id).unwrap().is_none());
    }

    #[test]
    fn clear_all_wipes_enc_files() {
        let dir = TempDir::new().unwrap();
        let store = ImageHistoryStore::open_at(dir.path(), &key(0x55)).unwrap();
        for _ in 0..3 {
            store.put(Uuid::new_v4(), b"x").unwrap();
        }
        // sibling non-.enc files should survive (nothing else should live
        // here, but prove we're kind-scoped)
        std::fs::write(dir.path().join("keep.txt"), b"y").unwrap();
        store.clear_all().unwrap();
        let remaining: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].ends_with("keep.txt"));
    }
}
