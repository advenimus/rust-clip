//! File send/receive primitives for RustClip.
//!
//! The full platform-native file-clipboard integration (macOS
//! NSFilenamesPboardType, Windows CF_HDROP, Linux text/uri-list) is a
//! rabbit hole that varies per platform and per desktop environment. v1
//! ships a more tractable UX:
//!
//! * Senders invoke `rustclip-client send-files <paths>...` explicitly.
//! * Receivers drop the decrypted payload into a per-session inbox under
//!   the user's data dir, and log the inbox path for the user to pick up.
//!
//! Phase 6+ can layer a tray menu "Send file..." affordance and opt-in
//! clipboard-file detection once each platform's backend is stable.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use tar::{Archive, Builder, Header};

/// A bundle of one or more files packed into a tar archive for transport.
/// Stored in memory during Phase 5 — moves to streaming for bigger payloads
/// in later hardening.
pub struct FileBundle {
    /// Raw tar bytes. These get encrypted + uploaded as a blob.
    pub tar_bytes: Vec<u8>,
    /// Displayable single-line summary ("report.pdf" / "3 files, 12.4 MB").
    pub summary: String,
    pub total_bytes: u64,
}

/// Pack `paths` into an in-memory tar archive. Each entry is stored with a
/// path relative to its parent directory, so the receiver reconstructs the
/// original file name but not the full sender-side path.
pub fn pack(paths: &[PathBuf]) -> Result<FileBundle> {
    if paths.is_empty() {
        return Err(anyhow!("no files to pack"));
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut total_bytes: u64 = 0;
    {
        let mut builder = Builder::new(&mut buf);
        for p in paths {
            let meta = fs::metadata(p).with_context(|| format!("stat {}", p.display()))?;
            if !meta.is_file() {
                return Err(anyhow!(
                    "{} is not a regular file (directories are not yet supported)",
                    p.display()
                ));
            }
            let name = p
                .file_name()
                .ok_or_else(|| anyhow!("no file name in {}", p.display()))?
                .to_string_lossy()
                .into_owned();
            let mut file = fs::File::open(p).with_context(|| format!("opening {}", p.display()))?;
            let mut header = Header::new_gnu();
            header.set_size(meta.len());
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, &name, &mut file)
                .with_context(|| format!("packing {}", p.display()))?;
            total_bytes = total_bytes.saturating_add(meta.len());
        }
        builder.finish().context("finalizing tar")?;
    }

    let summary = if paths.len() == 1 {
        paths[0]
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into())
    } else {
        format!("{} files, {}", paths.len(), human_bytes(total_bytes))
    };

    Ok(FileBundle {
        tar_bytes: buf,
        summary,
        total_bytes,
    })
}

/// Unpack a tar bundle into `dest`, creating the directory if needed. Each
/// entry is written with its declared relative name; any attempt to break
/// out (`..`, absolute paths) is rejected.
pub fn unpack(tar_bytes: &[u8], dest: &Path) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut archive = Archive::new(tar_bytes);
    let mut out = Vec::new();
    for entry in archive.entries().context("reading tar entries")? {
        let mut entry = entry.context("tar entry")?;
        let raw_path = entry.path().context("entry path")?;
        let safe = safe_entry_name(&raw_path)?;
        let dest_path = dest.join(&safe);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dir for {}", dest_path.display()))?;
        }
        let mut file = fs::File::create(&dest_path)
            .with_context(|| format!("creating {}", dest_path.display()))?;
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).context("reading entry body")?;
        file.write_all(&buf).context("writing entry body")?;
        out.push(dest_path);
    }
    Ok(out)
}

fn safe_entry_name(raw: &Path) -> Result<PathBuf> {
    if raw.is_absolute() {
        return Err(anyhow!(
            "refusing absolute path in tar entry: {}",
            raw.display()
        ));
    }
    for component in raw.components() {
        use std::path::Component;
        match component {
            Component::ParentDir => {
                return Err(anyhow!(
                    "refusing parent-dir component in tar entry: {}",
                    raw.display()
                ));
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(anyhow!("refusing root component in tar entry"));
            }
            _ => {}
        }
    }
    Ok(raw.to_path_buf())
}

/// Return a directory the client can use to drop incoming file payloads.
/// Falls back to a temp-dir subpath if platform-specific data dirs are
/// unavailable.
pub fn inbox_dir() -> PathBuf {
    let base = dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(std::env::temp_dir);
    base.join("rustclip").join("inbox")
}

fn human_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if n >= GB {
        format!("{:.2} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.2} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn pack_and_unpack_round_trip() {
        let src = TempDir::new().unwrap();
        let a = src.path().join("a.txt");
        let b = src.path().join("b.bin");
        fs::write(&a, b"hello").unwrap();
        fs::write(&b, vec![9u8; 2048]).unwrap();

        let bundle = pack(&[a.clone(), b.clone()]).unwrap();
        assert!(bundle.total_bytes >= 5 + 2048);
        assert!(bundle.summary.contains("files"));

        let dst = TempDir::new().unwrap();
        let out = unpack(&bundle.tar_bytes, dst.path()).unwrap();
        assert_eq!(out.len(), 2);
        let contents_a = fs::read(dst.path().join("a.txt")).unwrap();
        assert_eq!(contents_a, b"hello");
        let contents_b = fs::read(dst.path().join("b.bin")).unwrap();
        assert_eq!(contents_b.len(), 2048);
    }

    #[test]
    fn pack_rejects_empty() {
        assert!(pack(&[]).is_err());
    }

    #[test]
    fn safe_entry_name_rejects_parent_dir() {
        let err = safe_entry_name(Path::new("../escape.txt")).unwrap_err();
        assert!(err.to_string().contains("parent-dir"));
    }

    #[test]
    fn safe_entry_name_rejects_absolute() {
        let err = safe_entry_name(Path::new("/etc/shadow")).unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn safe_entry_name_accepts_plain() {
        let p = safe_entry_name(Path::new("report.pdf")).unwrap();
        assert_eq!(p, Path::new("report.pdf"));
    }
}
