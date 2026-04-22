//! File send/receive primitives for RustClip.
//!
//! Bundles one or more files (or directories, recursively) into a tar
//! archive. Bundles are sent either via the explicit `send-files` CLI or,
//! once OS-native file-copy detection picks them up, automatically from
//! the clipboard watcher. A per-bundle size cap (configurable client-side
//! via `config::ClientConfig`) protects the auto-sync path from accidental
//! multi-gigabyte folder copies.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256};
use tar::{Archive, Builder, Header};
use walkdir::WalkDir;

/// Default cap on automatically-detected bundle size, in bytes. Large
/// copies (e.g., a 20 GB Downloads folder) fall back to the explicit
/// `send-files` CLI rather than silently streaming across the wire.
pub const DEFAULT_AUTO_BUNDLE_CAP_BYTES: u64 = 500 * 1024 * 1024;

/// A bundle of one or more files packed into a tar archive for transport.
#[derive(Debug)]
pub struct FileBundle {
    /// Raw tar bytes. These get encrypted + uploaded as a blob.
    pub tar_bytes: Vec<u8>,
    /// Displayable single-line summary ("report.pdf" / "3 files, 12.4 MB").
    pub summary: String,
    pub total_bytes: u64,
}

/// Typed errors from `pack_checked`, so callers can distinguish the
/// "bundle too big" case from genuine failures and log / skip accordingly.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("bundle total {total_bytes} bytes exceeds cap of {cap} bytes")]
    TooLarge { total_bytes: u64, cap: u64 },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<std::io::Error> for PackError {
    fn from(e: std::io::Error) -> Self {
        PackError::Other(anyhow::Error::from(e))
    }
}

/// Pack `paths` (files and/or directories) into an in-memory tar archive.
///
/// Equivalent to `pack_checked(paths, None)`; retained as the convenience
/// entry point for the CLI `send-files` subcommand, which is an explicit
/// user action and therefore uncapped.
pub fn pack(paths: &[PathBuf]) -> Result<FileBundle> {
    pack_checked(paths, None).map_err(|e| match e {
        PackError::TooLarge { total_bytes, cap } => {
            anyhow!("bundle total {total_bytes} bytes exceeds cap of {cap} bytes")
        }
        PackError::Other(inner) => inner,
    })
}

/// Pack `paths` into a tar archive, rejecting the job if the total
/// uncompressed size would exceed `max_bytes`. `None` means uncapped.
///
/// Directory entries are walked recursively; symlinks are skipped (not
/// followed, not emitted) to keep the unpack path unable to forge paths
/// outside the destination inbox.
pub fn pack_checked(paths: &[PathBuf], max_bytes: Option<u64>) -> Result<FileBundle, PackError> {
    if paths.is_empty() {
        return Err(PackError::Other(anyhow!("no files to pack")));
    }

    // First pass: enumerate every (source, tar-name, size) triple and
    // accumulate the total. This lets us reject an over-cap bundle before
    // reading any file bytes.
    let plan = build_plan(paths)?;
    let total_bytes: u64 = plan.iter().map(|e| e.size).sum();
    if let Some(cap) = max_bytes
        && total_bytes > cap
    {
        return Err(PackError::TooLarge { total_bytes, cap });
    }

    // Second pass: actually stream bytes into the tar.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut builder = Builder::new(&mut buf);
        for e in &plan {
            let mut file = fs::File::open(&e.source)
                .with_context(|| format!("opening {}", e.source.display()))
                .map_err(PackError::Other)?;
            let mut header = Header::new_gnu();
            header.set_size(e.size);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, &e.tar_name, &mut file)
                .with_context(|| format!("packing {}", e.source.display()))
                .map_err(PackError::Other)?;
        }
        builder
            .finish()
            .context("finalizing tar")
            .map_err(PackError::Other)?;
    }

    let summary = build_summary(paths, plan.len(), total_bytes);

    Ok(FileBundle {
        tar_bytes: buf,
        summary,
        total_bytes,
    })
}

struct PackEntry {
    source: PathBuf,
    tar_name: String,
    size: u64,
}

fn build_plan(paths: &[PathBuf]) -> Result<Vec<PackEntry>, PackError> {
    let mut out = Vec::new();
    for p in paths {
        let meta = fs::symlink_metadata(p)
            .with_context(|| format!("stat {}", p.display()))
            .map_err(PackError::Other)?;
        if meta.file_type().is_symlink() {
            // Top-level symlinks are skipped — we never follow them.
            continue;
        }
        let top_name = p
            .file_name()
            .ok_or_else(|| PackError::Other(anyhow!("no file name in {}", p.display())))?
            .to_string_lossy()
            .into_owned();

        if meta.is_file() {
            out.push(PackEntry {
                source: p.clone(),
                tar_name: top_name,
                size: meta.len(),
            });
        } else if meta.is_dir() {
            walk_dir(p, &top_name, &mut out)?;
        } else {
            return Err(PackError::Other(anyhow!(
                "{} is not a regular file or directory",
                p.display()
            )));
        }
    }
    if out.is_empty() {
        return Err(PackError::Other(anyhow!(
            "nothing to pack (all inputs were symlinks or empty directories)"
        )));
    }
    Ok(out)
}

fn walk_dir(root: &Path, prefix: &str, out: &mut Vec<PackEntry>) -> Result<(), PackError> {
    // follow_links(false): we never traverse a symlinked directory, and the
    // entry-level check below drops symlinked files too. This keeps the
    // unpack side from having to consider absolute-path or escape-style
    // symlink entries.
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry
            .with_context(|| format!("walking {}", root.display()))
            .map_err(|e: anyhow::Error| PackError::Other(e))?;
        let ft = entry.file_type();
        if !ft.is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .with_context(|| format!("rel-path of {}", entry.path().display()))
            .map_err(PackError::Other)?;
        let rel_str = rel.to_string_lossy();
        let tar_name = if rel_str.is_empty() {
            prefix.to_string()
        } else {
            format!("{prefix}/{rel_str}")
        };
        let meta = entry
            .metadata()
            .with_context(|| format!("stat {}", entry.path().display()))
            .map_err(|e: anyhow::Error| PackError::Other(e))?;
        out.push(PackEntry {
            source: entry.path().to_path_buf(),
            tar_name,
            size: meta.len(),
        });
    }
    Ok(())
}

fn build_summary(paths: &[PathBuf], file_count: usize, total_bytes: u64) -> String {
    if paths.len() == 1 {
        let name = paths[0]
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "item".into());
        if file_count > 1 {
            format!("{name} ({file_count} files, {})", human_bytes(total_bytes))
        } else {
            name
        }
    } else {
        format!("{file_count} files, {}", human_bytes(total_bytes))
    }
}

/// Upper bound on any single extracted file (H5). Intentionally
/// generous for photos/PDFs but well under the compressed-bomb
/// expansion factor a same-key attacker could muster inside a 25 MiB
/// encrypted envelope.
pub const UNPACK_MAX_ENTRY_BYTES: u64 = 500 * 1024 * 1024;
/// Total bytes written across all entries in one unpack.
pub const UNPACK_MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
/// Upper bound on entry count to prevent inode-exhaustion / metadata
/// flood attacks.
pub const UNPACK_MAX_ENTRIES: usize = 10_000;

/// Unpack a tar bundle into `dest`, creating the directory if needed. Each
/// entry is written with its declared relative name; any attempt to break
/// out (`..`, absolute paths) is rejected.
///
/// Decompressed size is capped per-entry, in aggregate, and by entry
/// count (see `UNPACK_MAX_*` constants). Crossing any cap aborts the
/// unpack mid-extraction: the caller is responsible for cleaning up
/// `dest` if partial output is undesirable.
pub fn unpack(tar_bytes: &[u8], dest: &Path) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut archive = Archive::new(tar_bytes);
    let mut out = Vec::new();
    let mut total_written: u64 = 0;
    for entry in archive.entries().context("reading tar entries")? {
        if out.len() >= UNPACK_MAX_ENTRIES {
            return Err(anyhow!(
                "tar bundle has more than {UNPACK_MAX_ENTRIES} entries; refusing"
            ));
        }
        let mut entry = entry.context("tar entry")?;
        let raw_path = entry.path().context("entry path")?;
        let safe = safe_entry_name(&raw_path)?;
        let dest_path = dest.join(&safe);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dir for {}", dest_path.display()))?;
        }
        // Reject on the declared header size before we stream a byte
        // — a malicious bundle could claim 0 then stream gigabytes,
        // so we also enforce a hard cap on the actual bytes read.
        let declared = entry.header().size().unwrap_or(0);
        if declared > UNPACK_MAX_ENTRY_BYTES {
            return Err(anyhow!(
                "tar entry {} declares {declared} bytes (> {UNPACK_MAX_ENTRY_BYTES} cap)",
                dest_path.display()
            ));
        }
        if total_written.saturating_add(declared) > UNPACK_MAX_TOTAL_BYTES {
            return Err(anyhow!(
                "tar bundle total exceeds {UNPACK_MAX_TOTAL_BYTES} bytes"
            ));
        }
        let mut file = fs::File::create(&dest_path)
            .with_context(|| format!("creating {}", dest_path.display()))?;
        // Take-bounded copy: even if the tar header lies about the
        // entry size, we cap at the per-entry maximum.
        let remaining_total = UNPACK_MAX_TOTAL_BYTES.saturating_sub(total_written);
        let entry_cap = UNPACK_MAX_ENTRY_BYTES.min(remaining_total);
        let mut limited = (&mut entry).take(entry_cap.saturating_add(1));
        let copied = std::io::copy(&mut limited, &mut file)
            .with_context(|| format!("writing entry body for {}", dest_path.display()))?;
        if copied > entry_cap {
            return Err(anyhow!(
                "tar entry {} exceeded per-entry cap of {} bytes",
                dest_path.display(),
                entry_cap
            ));
        }
        total_written = total_written.saturating_add(copied);
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

/// List the immediate children of `dir` — files and directories at the
/// top level only. Used by the receive path to feed the OS pasteboard
/// with whole-folder entries rather than every leaf file, so that a
/// subsequent Ctrl+V / Cmd+V preserves the packed directory structure
/// instead of flattening it.
pub fn top_level_entries(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("entry in {}", dir.display()))?;
        out.push(entry.path());
    }
    out.sort();
    Ok(out)
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

/// Recursively remove the inbox folder for a single event. Used when
/// history retention evicts a bundle row (or when the whole history is
/// cleared). A missing directory is treated as success — the next
/// retention sweep will still see the same (empty) state.
pub fn remove_inbox_dir(event_id: uuid::Uuid) -> Result<()> {
    remove_inbox_dir_at(&inbox_dir(), event_id)
}

/// Like `remove_inbox_dir`, but takes an explicit root path. Factored
/// out so tests can point it at a tempdir instead of the real
/// user-wide inbox location.
pub fn remove_inbox_dir_at(inbox_root: &Path, event_id: uuid::Uuid) -> Result<()> {
    let dir = inbox_root.join(event_id.to_string());
    match fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => {
            Err(anyhow::Error::new(e).context(format!("removing inbox dir {}", dir.display())))
        }
    }
}

/// True iff every path in `paths` resolves under the inbox directory.
/// Used to short-circuit the send-side detection of our own receive-side
/// pasteboard write without relying on timing.
pub fn all_under_inbox(paths: &[PathBuf]) -> bool {
    if paths.is_empty() {
        return false;
    }
    let inbox = match inbox_dir().canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    paths.iter().all(|p| {
        p.canonicalize()
            .map(|c| c.starts_with(&inbox))
            .unwrap_or(false)
    })
}

/// Deterministic 32-byte hash over a file-list's (path, mtime) pairs.
/// Used for echo-suppression of repeated clipboard polls picking up the
/// same file list.
pub fn hash_path_list(paths: &[PathBuf]) -> [u8; 32] {
    let mut pairs: Vec<(Vec<u8>, i128)> = paths
        .iter()
        .map(|p| {
            let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
            let bytes = canon
                .as_os_str()
                .to_string_lossy()
                .into_owned()
                .into_bytes();
            let mtime = fs::metadata(p)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i128)
                .unwrap_or(0);
            (bytes, mtime)
        })
        .collect();
    pairs.sort();
    let mut hasher = Sha256::new();
    for (b, m) in &pairs {
        hasher.update((b.len() as u64).to_le_bytes());
        hasher.update(b);
        hasher.update(m.to_le_bytes());
    }
    hasher.finalize().into()
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
    fn remove_inbox_dir_at_wipes_matching_folder() {
        let inbox = TempDir::new().unwrap();
        let id = uuid::Uuid::new_v4();
        let event_dir = inbox.path().join(id.to_string());
        fs::create_dir_all(event_dir.join("nested")).unwrap();
        fs::write(event_dir.join("a.txt"), b"x").unwrap();
        fs::write(event_dir.join("nested").join("b.txt"), b"y").unwrap();

        remove_inbox_dir_at(inbox.path(), id).unwrap();
        assert!(!event_dir.exists(), "event dir should be gone");
        // Sibling dirs for other events survive.
        let other = inbox.path().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&other).unwrap();
        remove_inbox_dir_at(inbox.path(), id).unwrap(); // idempotent for missing id
        assert!(other.exists(), "unrelated event dir must not be touched");
    }

    #[test]
    fn remove_inbox_dir_at_is_idempotent_for_missing() {
        let inbox = TempDir::new().unwrap();
        let id = uuid::Uuid::new_v4();
        // No directory created. Should succeed silently.
        remove_inbox_dir_at(inbox.path(), id).unwrap();
    }

    #[test]
    fn pack_walks_directories() {
        let src = TempDir::new().unwrap();
        let dir = src.path().join("docs");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("readme.md"), b"# hi").unwrap();
        fs::write(dir.join("sub").join("nested.txt"), b"nested").unwrap();

        let bundle = pack(&[dir]).unwrap();
        let dst = TempDir::new().unwrap();
        let written = unpack(&bundle.tar_bytes, dst.path()).unwrap();
        assert_eq!(written.len(), 2);
        let top = dst.path().join("docs");
        assert!(top.join("readme.md").exists());
        assert!(top.join("sub").join("nested.txt").exists());
    }

    #[test]
    fn pack_checked_enforces_cap() {
        let src = TempDir::new().unwrap();
        let big = src.path().join("big.bin");
        fs::write(&big, vec![7u8; 4096]).unwrap();
        let err = pack_checked(&[big], Some(1024)).unwrap_err();
        match err {
            PackError::TooLarge { total_bytes, cap } => {
                assert_eq!(cap, 1024);
                assert!(total_bytes >= 4096);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn pack_skips_symlinks() {
        let src = TempDir::new().unwrap();
        let target = src.path().join("target.txt");
        fs::write(&target, b"real").unwrap();

        let dir = src.path().join("d");
        fs::create_dir_all(&dir).unwrap();
        let inner = dir.join("inner.txt");
        fs::write(&inner, b"inner").unwrap();
        // Place a symlink inside the directory pointing outside — walkdir
        // should see it as a symlink and skip.
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, dir.join("escape.txt")).unwrap();

        let bundle = pack(&[dir]).unwrap();
        let dst = TempDir::new().unwrap();
        let written = unpack(&bundle.tar_bytes, dst.path()).unwrap();
        // The symlink is dropped; only `inner.txt` survives the walk.
        assert!(written.iter().any(|p| p.ends_with("d/inner.txt")));
        #[cfg(unix)]
        assert!(!written.iter().any(|p| p.ends_with("d/escape.txt")));
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

    #[test]
    fn hash_path_list_is_order_insensitive() {
        let src = TempDir::new().unwrap();
        let a = src.path().join("a.txt");
        let b = src.path().join("b.txt");
        fs::write(&a, b"x").unwrap();
        fs::write(&b, b"y").unwrap();
        let h1 = hash_path_list(&[a.clone(), b.clone()]);
        let h2 = hash_path_list(&[b, a]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_path_list_differs_for_different_sets() {
        let src = TempDir::new().unwrap();
        let a = src.path().join("a.txt");
        let b = src.path().join("b.txt");
        fs::write(&a, b"x").unwrap();
        fs::write(&b, b"y").unwrap();
        let h1 = hash_path_list(&[a.clone()]);
        let h2 = hash_path_list(&[a, b]);
        assert_ne!(h1, h2);
    }

    fn build_tar_with_lied_header(declared: u64, actual_bytes: usize) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let mut builder = Builder::new(&mut buf);
        let mut header = Header::new_gnu();
        header.set_size(declared);
        header.set_mode(0o644);
        header.set_cksum();
        // Feed `actual_bytes` into append_data; the header lies about
        // the size but the actual stream is what the reader consumes.
        let body = vec![0u8; actual_bytes];
        builder
            .append_data(&mut header, "payload.bin", body.as_slice())
            .unwrap();
        builder.finish().unwrap();
        drop(builder);
        buf
    }

    #[test]
    fn unpack_rejects_entry_larger_than_per_entry_cap_declared() {
        let tar = build_tar_with_lied_header(UNPACK_MAX_ENTRY_BYTES + 1, 1);
        let dst = TempDir::new().unwrap();
        let err = unpack(&tar, dst.path()).unwrap_err();
        assert!(err.to_string().contains("cap"), "got: {err}");
    }

    #[test]
    fn unpack_rejects_too_many_entries() {
        let mut buf: Vec<u8> = Vec::new();
        let mut builder = Builder::new(&mut buf);
        for i in 0..=UNPACK_MAX_ENTRIES {
            let mut header = Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            let body = [0u8; 1];
            builder
                .append_data(&mut header, format!("f{i}.bin"), body.as_slice())
                .unwrap();
        }
        builder.finish().unwrap();
        drop(builder);
        let dst = TempDir::new().unwrap();
        let err = unpack(&buf, dst.path()).unwrap_err();
        assert!(err.to_string().contains("entries"), "got: {err}");
    }
}
