//! Dedicated clipboard thread. arboard instances are not `Send` on all
//! platforms, so we keep one pinned to a single OS thread and drive it via
//! channels from the async runtime.

use std::{
    borrow::Cow,
    collections::VecDeque,
    path::PathBuf,
    sync::mpsc as stdmpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use arboard::{Clipboard, ImageData};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::{
    clipboard_files,
    config::{ClientConfig, GuardMode},
    files,
};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Faster poll while a guard is armed so an external single-direction
/// clipboard channel (Citrix, RDP guest tools) can't reliably win the
/// overwrite race. Reverts to [`POLL_INTERVAL`] once the guard drops.
const GUARDED_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long a hash stays in the recent-inbound ring buffer. Anything
/// older than this can no longer be considered a "stale-direction
/// stomp" — if a hash matches after 30 s it's almost certainly the
/// user genuinely copying the same content back.
const RECENT_INBOUND_TTL: Duration = Duration::from_secs(30);
/// Cap on the recent-inbound ring buffer depth per content type.
/// Eight is plenty: even a chatty user copying a new thing every few
/// seconds for half a minute doesn't fill it. Each entry is a hash
/// plus an `Instant`, so memory is trivial.
const RECENT_INBOUND_CAP: usize = 8;
/// Time window after writing an image during which we ignore image reads.
/// Platforms can roundtrip RGBA with slight differences (premultiplied
/// alpha, row-stride alignment) so content-hash echo suppression alone is
/// unreliable for images. A small quiet window catches the echo reliably.
const IMAGE_WRITE_QUIET: Duration = Duration::from_secs(3);
/// Time window after writing a file list during which we ignore file-list
/// reads. Longer than the image window because the receive path does a
/// tar unpack + NSURL / HDROP allocation before the pasteboard write; a
/// large bundle can burn past 3 s.
const FILES_WRITE_QUIET: Duration = Duration::from_secs(5);

/// Events emitted by the clipboard watcher when the user copies something.
#[derive(Debug)]
pub enum ClipEvent {
    Text(String),
    Image(ImageBytes),
    Files(Vec<PathBuf>),
}

/// Which kind of clipboard write hit the OS error path. Used by the
/// GUI to render a more specific toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteKind {
    Text,
    Image,
    Files,
}

impl WriteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WriteKind::Text => "text",
            WriteKind::Image => "image",
            WriteKind::Files => "files",
        }
    }
}

/// Failure to apply an incoming clip to the OS clipboard. The remote
/// device already has the content; the local user just won't see it on
/// paste. The GUI listens for these and surfaces a toast so the user
/// knows their next paste won't have what they expect.
#[derive(Debug, Clone)]
pub struct WriteFailure {
    pub kind: WriteKind,
    pub error: String,
}

/// Decoded PNG image bytes plus dimensions for a round-trip write.
#[derive(Debug, Clone)]
pub struct ImageBytes {
    pub width: usize,
    pub height: usize,
    /// Raw RGBA pixels from arboard. PNG-encoding happens at send time.
    pub rgba: Vec<u8>,
}

/// Caller-supplied request to "guard" a receive — re-assert the just-
/// written content onto the OS clipboard if a single-direction
/// channel clears or stomps it within `seconds`. Scoped to the
/// receive path; manual recopies (tray menu, hotkey) pass `None`.
#[derive(Debug, Clone, Copy)]
pub struct GuardSpec {
    pub seconds: u32,
    pub max_attempts: u8,
    pub mode: GuardMode,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ClipboardCmd {
    WriteText {
        text: String,
        guard: Option<GuardSpec>,
    },
    WriteImage {
        image: ImageBytes,
        guard: Option<GuardSpec>,
    },
    WriteFileList {
        paths: Vec<PathBuf>,
        guard: Option<GuardSpec>,
    },
    Shutdown,
}

/// Active guard state on the worker thread. One of three content
/// types — only one guard is ever armed at a time, replaced on every
/// new receive.
#[derive(Clone)]
struct GuardEntry {
    content: GuardContent,
    content_hash: [u8; 32],
    expires_at: Instant,
    attempts_left: u8,
    mode: GuardMode,
}

#[derive(Clone)]
enum GuardContent {
    Text(String),
    Image(ImageBytes),
    Files(Vec<PathBuf>),
}

impl GuardContent {
    #[allow(dead_code)]
    fn kind(&self) -> WriteKind {
        match self {
            GuardContent::Text(_) => WriteKind::Text,
            GuardContent::Image(_) => WriteKind::Image,
            GuardContent::Files(_) => WriteKind::Files,
        }
    }
}

/// What the worker should do with the active guard on the current
/// poll tick. Pure decision so it can be unit-tested without touching
/// the real OS clipboard.
#[derive(Debug, PartialEq, Eq)]
enum GuardDecision {
    /// No-op — guard stays armed.
    Keep,
    /// Drop the guard (expired, attempts exhausted, or user copied
    /// something else of a hash we don't recognize).
    Drop,
    /// Re-write `content` to the clipboard and decrement
    /// `attempts_left`. The caller also restamps echo-suppression
    /// hashes and skips the rest of the poll tick.
    Reassert,
}

/// Hash + insert time for the recent-inbound ring buffer. Capped at
/// [`RECENT_INBOUND_CAP`] per content type and TTL'd against
/// [`RECENT_INBOUND_TTL`] — older entries are popped on insert.
#[derive(Debug, Clone, Default)]
struct RecentHashes {
    entries: VecDeque<([u8; 32], Instant)>,
}

impl RecentHashes {
    fn record(&mut self, hash: [u8; 32], now: Instant) {
        // Evict expired entries before pushing; cheap given the cap.
        while let Some((_, when)) = self.entries.front() {
            if now.saturating_duration_since(*when) > RECENT_INBOUND_TTL {
                self.entries.pop_front();
            } else {
                break;
            }
        }
        // Push newest; trim to cap.
        self.entries.push_back((hash, now));
        while self.entries.len() > RECENT_INBOUND_CAP {
            self.entries.pop_front();
        }
    }

    fn contains_within(&self, target: &[u8; 32], now: Instant, ttl: Duration) -> bool {
        self.entries
            .iter()
            .any(|(h, when)| h == target && now.saturating_duration_since(*when) <= ttl)
    }
}

/// Evaluate the active guard against the current state of the OS
/// clipboard for the guard's content type.
///
/// - `current_hash = None` means the clipboard is empty or
///   unavailable for that type. Treated identically to the empty
///   case (re-assert if attempts remain).
/// - `current_hash = Some(h) where h == g.content_hash` — our
///   content is still on the clipboard, keep the guard armed.
/// - `current_hash = Some(h) where h != g.content_hash`:
///   - In `Aggressive` mode, if `h` is in `recent_inbound`, that's
///     a stale-direction stomp from a sync channel (Citrix etc.) —
///     re-assert.
///   - Otherwise treat as a genuine user copy and drop the guard so
///     we never fight a real copy.
fn evaluate_guard(
    g: &GuardEntry,
    current_hash: Option<[u8; 32]>,
    recent_inbound: &RecentHashes,
    now: Instant,
) -> GuardDecision {
    if now >= g.expires_at {
        return GuardDecision::Drop;
    }
    let Some(cb_hash) = current_hash else {
        return if g.attempts_left > 0 {
            GuardDecision::Reassert
        } else {
            GuardDecision::Drop
        };
    };
    if cb_hash == g.content_hash {
        return GuardDecision::Keep;
    }
    if g.mode.is_aggressive() && recent_inbound.contains_within(&cb_hash, now, RECENT_INBOUND_TTL) {
        return if g.attempts_left > 0 {
            GuardDecision::Reassert
        } else {
            GuardDecision::Drop
        };
    }
    GuardDecision::Drop
}

/// Sender half of the clipboard worker channel. Cheap to clone —
/// wraps `std::sync::mpsc::Sender` which is itself `Clone`. Cloning
/// lets multiple call sites (the sync loop, the Tauri history-recopy
/// command, the tray recent-clips menu) all drive the single
/// `arboard::Clipboard` that lives on the worker thread.
#[derive(Clone)]
pub struct ClipboardHandle {
    cmd_tx: stdmpsc::Sender<ClipboardCmd>,
}

impl ClipboardHandle {
    pub fn write_text(&self, text: String) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::WriteText { text, guard: None })
            .context("clipboard worker shut down")
    }

    /// Like `write_text` but arms the guard so the worker re-asserts
    /// the same content for `guard.seconds` if a third party (VDI
    /// clipboard channel etc.) clears or stomps the clipboard before
    /// the user pastes. `guard.mode` selects the trigger semantics:
    /// `EmptyOnly` re-asserts on clear; `Aggressive` also re-asserts
    /// on a hash-match-to-recent-inbound overwrite.
    pub fn write_text_guarded(&self, text: String, guard: GuardSpec) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::WriteText {
                text,
                guard: Some(guard),
            })
            .context("clipboard worker shut down")
    }

    pub fn write_image(&self, image: ImageBytes) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::WriteImage { image, guard: None })
            .context("clipboard worker shut down")
    }

    /// Like `write_image` but arms the guard. See
    /// [`Self::write_text_guarded`] for semantics.
    pub fn write_image_guarded(&self, image: ImageBytes, guard: GuardSpec) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::WriteImage {
                image,
                guard: Some(guard),
            })
            .context("clipboard worker shut down")
    }

    pub fn write_file_list(&self, paths: Vec<PathBuf>) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::WriteFileList { paths, guard: None })
            .context("clipboard worker shut down")
    }

    /// Like `write_file_list` but arms the guard. See
    /// [`Self::write_text_guarded`] for semantics.
    pub fn write_file_list_guarded(&self, paths: Vec<PathBuf>, guard: GuardSpec) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::WriteFileList {
                paths,
                guard: Some(guard),
            })
            .context("clipboard worker shut down")
    }

    #[allow(dead_code)]
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(ClipboardCmd::Shutdown);
    }
}

pub fn spawn_watcher(event_tx: mpsc::Sender<ClipEvent>) -> Result<ClipboardHandle> {
    spawn_watcher_inner(event_tx, None)
}

/// Like [`spawn_watcher`] but also feeds each clipboard write failure
/// onto `failure_tx`. The GUI uses this to surface a toast + tray
/// flicker; the CLI never needs to know (warn! is enough), so it stays
/// on the plain entry point.
pub fn spawn_watcher_with_failures(
    event_tx: mpsc::Sender<ClipEvent>,
    failure_tx: mpsc::Sender<WriteFailure>,
) -> Result<ClipboardHandle> {
    spawn_watcher_inner(event_tx, Some(failure_tx))
}

fn spawn_watcher_inner(
    event_tx: mpsc::Sender<ClipEvent>,
    failure_tx: Option<mpsc::Sender<WriteFailure>>,
) -> Result<ClipboardHandle> {
    let (cmd_tx, cmd_rx) = stdmpsc::channel::<ClipboardCmd>();

    // Probe once up-front on the main thread so we can surface a clean error
    // before we've sunk the clipboard into the worker.
    let _probe = Clipboard::new().context("opening system clipboard")?;

    thread::Builder::new()
        .name("rustclip-clipboard".into())
        .spawn(move || worker_loop(event_tx, cmd_rx, failure_tx))
        .context("spawning clipboard worker thread")?;

    Ok(ClipboardHandle { cmd_tx })
}

fn report_failure(failure_tx: &Option<mpsc::Sender<WriteFailure>>, kind: WriteKind, error: &str) {
    if let Some(tx) = failure_tx {
        // blocking_send is fine — we're on the dedicated clipboard
        // thread (no tokio executor running here). A full channel
        // shouldn't happen in practice; if it does, drop silently
        // rather than block forever.
        let _ = tx.try_send(WriteFailure {
            kind,
            error: error.to_string(),
        });
    }
}

/// Total attempts (1 initial + up to N-1 retries) when the OS-level
/// clipboard write hits a transient error. arboard wraps NSPasteboard
/// / CF_HDROP / X11 / Wayland and all of them have occasional
/// glitches — AV scanners, focus changes, a clipboard manager briefly
/// holding the handle — that resolve on the second or third attempt.
const WRITE_MAX_ATTEMPTS: u32 = 3;
/// Sleep between retries. Short enough that even a worst-case retry
/// budget (~100 ms) stays well inside the 500 ms poll interval.
const WRITE_RETRY_DELAY: Duration = Duration::from_millis(50);

fn set_text_with_retry(cb: &mut Clipboard, text: &str) -> std::result::Result<(), arboard::Error> {
    let mut last_err: Option<arboard::Error> = None;
    for attempt in 1..=WRITE_MAX_ATTEMPTS {
        match cb.set_text(text) {
            Ok(()) => return Ok(()),
            Err(e) => {
                debug!(attempt, max = WRITE_MAX_ATTEMPTS, error = %e, "set_text failed, will retry");
                last_err = Some(e);
                if attempt < WRITE_MAX_ATTEMPTS {
                    thread::sleep(WRITE_RETRY_DELAY);
                }
            }
        }
    }
    Err(last_err.expect("attempted at least once"))
}

fn set_image_with_retry(
    cb: &mut Clipboard,
    image: &ImageBytes,
) -> std::result::Result<(), arboard::Error> {
    let mut last_err: Option<arboard::Error> = None;
    for attempt in 1..=WRITE_MAX_ATTEMPTS {
        let img = ImageData {
            width: image.width,
            height: image.height,
            bytes: Cow::Borrowed(&image.rgba),
        };
        match cb.set_image(img) {
            Ok(()) => return Ok(()),
            Err(e) => {
                debug!(attempt, max = WRITE_MAX_ATTEMPTS, error = %e, "set_image failed, will retry");
                last_err = Some(e);
                if attempt < WRITE_MAX_ATTEMPTS {
                    thread::sleep(WRITE_RETRY_DELAY);
                }
            }
        }
    }
    Err(last_err.expect("attempted at least once"))
}

fn write_file_list_with_retry(paths: &[PathBuf]) -> anyhow::Result<()> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=WRITE_MAX_ATTEMPTS {
        match clipboard_files::write_file_list(paths) {
            Ok(()) => return Ok(()),
            Err(e) => {
                debug!(
                    attempt,
                    max = WRITE_MAX_ATTEMPTS,
                    error = %e,
                    "file-list write failed, will retry"
                );
                last_err = Some(e);
                if attempt < WRITE_MAX_ATTEMPTS {
                    thread::sleep(WRITE_RETRY_DELAY);
                }
            }
        }
    }
    Err(last_err.expect("attempted at least once"))
}

fn worker_loop(
    event_tx: mpsc::Sender<ClipEvent>,
    cmd_rx: stdmpsc::Receiver<ClipboardCmd>,
    failure_tx: Option<mpsc::Sender<WriteFailure>>,
) {
    let mut cb = match Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "clipboard worker cannot open clipboard");
            return;
        }
    };

    let config = ClientConfig::load().unwrap_or_default();

    let mut last_read: Option<[u8; 32]> = None;
    let mut last_set: Option<[u8; 32]> = None;
    let mut last_image_write_at: Option<Instant> = None;
    let mut last_read_files: Option<[u8; 32]> = None;
    let mut last_set_files: Option<[u8; 32]> = None;
    let mut last_files_write_at: Option<Instant> = None;
    // Single active guard at a time — a new receive replaces any
    // prior guard (the user is moving on). Per-type ring buffers
    // track recent inbound hashes so an Aggressive guard can
    // recognize a stale-direction stomp from a sync channel.
    let mut guard: Option<GuardEntry> = None;
    let mut recent_text = RecentHashes::default();
    let mut recent_image = RecentHashes::default();
    let mut recent_files = RecentHashes::default();

    loop {
        // Drain pending commands first.
        loop {
            match cmd_rx.try_recv() {
                Ok(ClipboardCmd::WriteText { text, guard: spec }) => {
                    // Pre-stamp echo-suppression hashes BEFORE the OS
                    // write so a third-party reader/writer racing the
                    // very next poll can't trip a spurious echo. Roll
                    // back atomically if the OS write actually fails —
                    // otherwise stale hashes would suppress legitimate
                    // user copies of the prior clipboard content.
                    let hash = sha256(text.as_bytes());
                    let prev_last_set = last_set;
                    let prev_last_read = last_read;
                    let prev_guard = guard.clone();
                    last_set = Some(hash);
                    last_read = Some(hash);
                    if let Some(spec) = spec {
                        guard = Some(GuardEntry {
                            content: GuardContent::Text(text.clone()),
                            content_hash: hash,
                            expires_at: Instant::now() + Duration::from_secs(spec.seconds as u64),
                            attempts_left: spec.max_attempts,
                            mode: spec.mode,
                        });
                        recent_text.record(hash, Instant::now());
                    } else {
                        // A non-guarded write (manual recopy etc.)
                        // implicitly cancels any prior guard — the
                        // user is moving on.
                        guard = None;
                    }
                    if let Err(e) = set_text_with_retry(&mut cb, &text) {
                        warn!(error = %e, "clipboard write failed after retries");
                        last_set = prev_last_set;
                        last_read = prev_last_read;
                        guard = prev_guard;
                        report_failure(&failure_tx, WriteKind::Text, &e.to_string());
                    }
                }
                Ok(ClipboardCmd::WriteImage { image, guard: spec }) => {
                    let hash = hash_image(&image);
                    let prev_last_set = last_set;
                    let prev_last_read = last_read;
                    let prev_image_write_at = last_image_write_at;
                    let prev_guard = guard.clone();
                    last_set = Some(hash);
                    last_read = Some(hash);
                    last_image_write_at = Some(Instant::now());
                    if let Some(spec) = spec {
                        guard = Some(GuardEntry {
                            content: GuardContent::Image(image.clone()),
                            content_hash: hash,
                            expires_at: Instant::now() + Duration::from_secs(spec.seconds as u64),
                            attempts_left: spec.max_attempts,
                            mode: spec.mode,
                        });
                        recent_image.record(hash, Instant::now());
                    } else {
                        guard = None;
                    }
                    if let Err(e) = set_image_with_retry(&mut cb, &image) {
                        warn!(error = %e, "clipboard image write failed after retries");
                        last_set = prev_last_set;
                        last_read = prev_last_read;
                        last_image_write_at = prev_image_write_at;
                        guard = prev_guard;
                        report_failure(&failure_tx, WriteKind::Image, &e.to_string());
                    }
                }
                Ok(ClipboardCmd::WriteFileList { paths, guard: spec }) => {
                    // Bump the echo-suppression hash BEFORE the actual
                    // pasteboard write so the next poll can't sneak in a
                    // read between the write and the hash update. Roll
                    // back the same trio on failure so a stale file-list
                    // hash doesn't outlive the failed attempt — the
                    // previous fix pre-stamped but never restored.
                    let hash = files::hash_path_list(&paths);
                    let prev_last_set_files = last_set_files;
                    let prev_last_read_files = last_read_files;
                    let prev_files_write_at = last_files_write_at;
                    let prev_guard = guard.clone();
                    last_set_files = Some(hash);
                    last_read_files = Some(hash);
                    last_files_write_at = Some(Instant::now());
                    if let Some(spec) = spec {
                        guard = Some(GuardEntry {
                            content: GuardContent::Files(paths.clone()),
                            content_hash: hash,
                            expires_at: Instant::now() + Duration::from_secs(spec.seconds as u64),
                            attempts_left: spec.max_attempts,
                            mode: spec.mode,
                        });
                        recent_files.record(hash, Instant::now());
                    } else {
                        guard = None;
                    }
                    if let Err(e) = write_file_list_with_retry(&paths) {
                        warn!(error = %e, "clipboard file-list write failed after retries");
                        last_set_files = prev_last_set_files;
                        last_read_files = prev_last_read_files;
                        last_files_write_at = prev_files_write_at;
                        guard = prev_guard;
                        report_failure(&failure_tx, WriteKind::Files, &e.to_string());
                    }
                }
                Ok(ClipboardCmd::Shutdown) | Err(stdmpsc::TryRecvError::Disconnected) => {
                    debug!("clipboard worker exiting");
                    return;
                }
                Err(stdmpsc::TryRecvError::Empty) => break,
            }
        }

        // Active-guard fast-poll drops the cadence from 500 ms → 100 ms
        // so a single-direction channel doesn't have a 500 ms window
        // in which to stomp our write before we re-assert.
        let poll_interval = if guard.is_some() {
            GUARDED_POLL_INTERVAL
        } else {
            POLL_INTERVAL
        };

        // Poll file list FIRST. Finder / Explorer also push the filename
        // onto the pasteboard as a text fallback; if we polled text first
        // we'd spuriously send the filename as a text clip.
        let mut files_on_clipboard = false;
        let mut current_files_hash: Option<[u8; 32]> = None;
        if config.auto_sync_files {
            let in_files_quiet = last_files_write_at
                .map(|t| t.elapsed() < FILES_WRITE_QUIET)
                .unwrap_or(false);
            if !in_files_quiet {
                match clipboard_files::read_file_list() {
                    Ok(Some(paths)) if !paths.is_empty() => {
                        files_on_clipboard = true;
                        let hash = files::hash_path_list(&paths);
                        current_files_hash = Some(hash);
                        if files::all_under_inbox(&paths) {
                            // We just wrote these ourselves (receive-side
                            // unpack). Skip silently; don't even update
                            // last_read_files so the user's own later
                            // manual re-copy still syncs.
                        } else {
                            let already_read = last_read_files == Some(hash);
                            let matches_echo = last_set_files == Some(hash);
                            if !already_read && !matches_echo {
                                last_read_files = Some(hash);
                                if event_tx.blocking_send(ClipEvent::Files(paths)).is_err() {
                                    debug!("event receiver dropped, clipboard worker exiting");
                                    return;
                                }
                                thread::sleep(poll_interval);
                                continue;
                            } else if !already_read {
                                last_read_files = Some(hash);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        debug!(error = %e, "clipboard file-list read error");
                    }
                }
            } else {
                // Inside the quiet window we don't call read_file_list
                // (we just wrote it ourselves on the receive path), but
                // file URLs ARE still sitting on the pasteboard — they
                // stay there until the user copies something else. The
                // auto-derived text/icon representations are therefore
                // also still there, so treat this tick as "files
                // present" to gate the text / image polls.
                files_on_clipboard = true;
            }
        }

        // Files-guard pass. Runs ONLY when we just read a real file
        // list (current_files_hash present) or when we KNOW the
        // clipboard is empty for files (read returned Ok(None) and
        // we're outside the quiet window). Inside the quiet window
        // we trust our own recent write and keep the guard armed.
        if let Some(g) = guard.as_mut() {
            if matches!(g.content, GuardContent::Files(_)) {
                let in_files_quiet = last_files_write_at
                    .map(|t| t.elapsed() < FILES_WRITE_QUIET)
                    .unwrap_or(false);
                let decision = if in_files_quiet {
                    GuardDecision::Keep
                } else {
                    evaluate_guard(g, current_files_hash, &recent_files, Instant::now())
                };
                match decision {
                    GuardDecision::Keep => {}
                    GuardDecision::Drop => {
                        guard = None;
                    }
                    GuardDecision::Reassert => {
                        if let Some(g) = guard.as_mut()
                            && let GuardContent::Files(ref paths) = g.content
                        {
                            g.attempts_left -= 1;
                            let attempts_left = g.attempts_left;
                            let hash = g.content_hash;
                            let paths = paths.clone();
                            match write_file_list_with_retry(&paths) {
                                Ok(()) => {
                                    last_set_files = Some(hash);
                                    last_read_files = Some(hash);
                                    last_files_write_at = Some(Instant::now());
                                    debug!(attempts_left, "clipboard guard re-asserted (files)");
                                }
                                Err(e) => {
                                    warn!(error = %e, "clipboard guard re-assert (files) failed");
                                    guard = None;
                                    report_failure(&failure_tx, WriteKind::Files, &e.to_string());
                                }
                            }
                        }
                        thread::sleep(poll_interval);
                        continue;
                    }
                }
            }
        }

        if files_on_clipboard {
            // Skip the text and image polls entirely: any text/icon the
            // OS derived from the file URLs is a fallback, not a real
            // clip. Note we DON'T stamp last_read for them either, so a
            // genuine text copy later still registers.
            thread::sleep(poll_interval);
            continue;
        }

        // Poll text second. Read once and reuse the result for guard
        // handling so a transient third-party clipboard clear can't
        // race between the guard's empty-check and the normal poll.
        let read_result = cb.get_text();

        // Text-guard pass.
        if let Some(g) = guard.as_mut() {
            if matches!(g.content, GuardContent::Text(_)) {
                let current_hash = match &read_result {
                    Ok(s) if !s.is_empty() => Some(sha256(s.as_bytes())),
                    Ok(_) => None,
                    Err(arboard::Error::ContentNotAvailable) => None,
                    Err(_) => Some(g.content_hash), // transient error — pretend our content is there
                };
                match evaluate_guard(g, current_hash, &recent_text, Instant::now()) {
                    GuardDecision::Keep => {}
                    GuardDecision::Drop => {
                        guard = None;
                    }
                    GuardDecision::Reassert => {
                        if let Some(g) = guard.as_mut()
                            && let GuardContent::Text(ref content) = g.content
                        {
                            g.attempts_left -= 1;
                            let attempts_left = g.attempts_left;
                            let hash = g.content_hash;
                            let content = content.clone();
                            match set_text_with_retry(&mut cb, &content) {
                                Ok(()) => {
                                    last_set = Some(hash);
                                    last_read = Some(hash);
                                    debug!(attempts_left, "clipboard guard re-asserted (text)");
                                }
                                Err(e) => {
                                    warn!(error = %e, "clipboard guard re-assert (text) failed");
                                    guard = None;
                                    report_failure(&failure_tx, WriteKind::Text, &e.to_string());
                                }
                            }
                        }
                        thread::sleep(poll_interval);
                        continue;
                    }
                }
            }
        }

        match read_result {
            Ok(text) if !text.is_empty() => {
                let hash = sha256(text.as_bytes());
                let already_read = last_read == Some(hash);
                let matches_echo = last_set == Some(hash);
                if !already_read && !matches_echo {
                    last_read = Some(hash);
                    if event_tx.blocking_send(ClipEvent::Text(text)).is_err() {
                        debug!("event receiver dropped, clipboard worker exiting");
                        return;
                    }
                } else if !already_read {
                    last_read = Some(hash);
                }
                thread::sleep(poll_interval);
                continue;
            }
            Ok(_) => {}
            Err(arboard::Error::ContentNotAvailable) => {}
            Err(e) => {
                debug!(error = %e, "clipboard read error");
            }
        }

        // Poll image third.
        let in_image_quiet = last_image_write_at
            .map(|t| t.elapsed() < IMAGE_WRITE_QUIET)
            .unwrap_or(false);
        let mut current_image_hash: Option<[u8; 32]> = None;
        if !in_image_quiet {
            match cb.get_image() {
                Ok(img) => {
                    let image = ImageBytes {
                        width: img.width,
                        height: img.height,
                        rgba: img.bytes.into_owned(),
                    };
                    let hash = hash_image(&image);
                    current_image_hash = Some(hash);
                    let already_read = last_read == Some(hash);
                    let matches_echo = last_set == Some(hash);
                    if !already_read && !matches_echo {
                        last_read = Some(hash);
                        if event_tx.blocking_send(ClipEvent::Image(image)).is_err() {
                            debug!("event receiver dropped, clipboard worker exiting");
                            return;
                        }
                    } else if !already_read {
                        last_read = Some(hash);
                    }
                }
                Err(arboard::Error::ContentNotAvailable) => {}
                Err(e) => {
                    debug!(error = %e, "clipboard image read error");
                }
            }
        }

        // Image-guard pass.
        if let Some(g) = guard.as_mut() {
            if matches!(g.content, GuardContent::Image(_)) {
                let decision = if in_image_quiet {
                    GuardDecision::Keep
                } else {
                    evaluate_guard(g, current_image_hash, &recent_image, Instant::now())
                };
                match decision {
                    GuardDecision::Keep => {}
                    GuardDecision::Drop => {
                        guard = None;
                    }
                    GuardDecision::Reassert => {
                        if let Some(g) = guard.as_mut()
                            && let GuardContent::Image(ref image) = g.content
                        {
                            g.attempts_left -= 1;
                            let attempts_left = g.attempts_left;
                            let hash = g.content_hash;
                            let image = image.clone();
                            match set_image_with_retry(&mut cb, &image) {
                                Ok(()) => {
                                    last_set = Some(hash);
                                    last_read = Some(hash);
                                    last_image_write_at = Some(Instant::now());
                                    debug!(attempts_left, "clipboard guard re-asserted (image)");
                                }
                                Err(e) => {
                                    warn!(error = %e, "clipboard guard re-assert (image) failed");
                                    guard = None;
                                    report_failure(&failure_tx, WriteKind::Image, &e.to_string());
                                }
                            }
                        }
                        thread::sleep(poll_interval);
                        continue;
                    }
                }
            }
        }

        thread::sleep(poll_interval);
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_image(image: &ImageBytes) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((image.width as u64).to_le_bytes());
    hasher.update((image.height as u64).to_le_bytes());
    hasher.update(&image.rgba);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard_with(
        content: &str,
        expires_in: Duration,
        attempts_left: u8,
        mode: GuardMode,
    ) -> GuardEntry {
        GuardEntry {
            content: GuardContent::Text(content.to_string()),
            content_hash: sha256(content.as_bytes()),
            expires_at: Instant::now() + expires_in,
            attempts_left,
            mode,
        }
    }

    /// Within the window, attempts left, clipboard reads as empty
    /// (`None` hash): caller should re-assert. Holds for both
    /// `EmptyOnly` and `Aggressive` modes.
    #[test]
    fn guard_re_asserts_when_cleared_to_empty() {
        let recent = RecentHashes::default();
        let now = Instant::now();
        for mode in [GuardMode::EmptyOnly, GuardMode::Aggressive] {
            let g = guard_with("hello", Duration::from_secs(5), 3, mode);
            assert_eq!(
                evaluate_guard(&g, None, &recent, now),
                GuardDecision::Reassert,
                "mode: {mode:?}"
            );
        }
    }

    /// User copies something else within the window AND that content
    /// is NOT a recently-seen inbound clip: drop the guard so we
    /// never fight a real copy. Holds for both modes.
    #[test]
    fn guard_clears_on_unknown_user_overwrite() {
        let recent = RecentHashes::default();
        let now = Instant::now();
        let other = sha256(b"a different copy");
        for mode in [GuardMode::EmptyOnly, GuardMode::Aggressive] {
            let g = guard_with("hello", Duration::from_secs(5), 3, mode);
            assert_eq!(
                evaluate_guard(&g, Some(other), &recent, now),
                GuardDecision::Drop
            );
        }
    }

    /// Our own content still sitting on the clipboard → keep the
    /// guard armed.
    #[test]
    fn guard_keeps_when_our_content_is_still_there() {
        let recent = RecentHashes::default();
        let now = Instant::now();
        let g = guard_with("hello", Duration::from_secs(5), 3, GuardMode::Aggressive);
        assert_eq!(
            evaluate_guard(&g, Some(g.content_hash), &recent, now),
            GuardDecision::Keep
        );
    }

    /// Aggressive mode: clipboard contents change to a hash that
    /// matches a recent inbound clip — that's a stale-direction
    /// stomp. Re-assert.
    #[test]
    fn aggressive_guard_re_asserts_on_stale_inbound_overwrite() {
        let now = Instant::now();
        let stale_hash = sha256(b"previously received content");
        let mut recent = RecentHashes::default();
        recent.record(stale_hash, now);
        let g = guard_with("hello", Duration::from_secs(5), 3, GuardMode::Aggressive);
        assert_eq!(
            evaluate_guard(&g, Some(stale_hash), &recent, now),
            GuardDecision::Reassert
        );
    }

    /// EmptyOnly mode: clipboard contents change to a stale-inbound
    /// hash — still treated as a real copy, drop the guard. Only
    /// Aggressive mode opts into the overwrite-defense behavior.
    #[test]
    fn empty_only_guard_does_not_re_assert_on_overwrite() {
        let now = Instant::now();
        let stale_hash = sha256(b"previously received content");
        let mut recent = RecentHashes::default();
        recent.record(stale_hash, now);
        let g = guard_with("hello", Duration::from_secs(5), 3, GuardMode::EmptyOnly);
        assert_eq!(
            evaluate_guard(&g, Some(stale_hash), &recent, now),
            GuardDecision::Drop
        );
    }

    /// Aggressive mode: hash in the recent buffer past its TTL is
    /// treated as a real user copy (the user genuinely re-copying
    /// the same thing after a while).
    #[test]
    fn aggressive_guard_ignores_expired_recent_hashes() {
        let now = Instant::now();
        let stale_hash = sha256(b"old content");
        let mut recent = RecentHashes::default();
        // Insert with a fake `inserted_at` that's already past the TTL.
        recent.entries.push_back((
            stale_hash,
            now - RECENT_INBOUND_TTL - Duration::from_secs(1),
        ));
        let g = guard_with("hello", Duration::from_secs(5), 3, GuardMode::Aggressive);
        assert_eq!(
            evaluate_guard(&g, Some(stale_hash), &recent, now),
            GuardDecision::Drop
        );
    }

    /// Past the expiry the guard is dropped regardless of clipboard
    /// state — including the empty-with-attempts-left case where it
    /// would otherwise re-assert.
    #[test]
    fn guard_clears_on_window_expiry() {
        let recent = RecentHashes::default();
        let g = guard_with("hello", Duration::from_millis(0), 3, GuardMode::Aggressive);
        let now = Instant::now() + Duration::from_millis(1);
        assert_eq!(evaluate_guard(&g, None, &recent, now), GuardDecision::Drop);
        assert_eq!(
            evaluate_guard(&g, Some(g.content_hash), &recent, now),
            GuardDecision::Drop
        );
    }

    /// With zero attempts remaining, an empty clipboard tick drops
    /// the guard rather than re-asserting indefinitely.
    #[test]
    fn guard_caps_re_assertions() {
        let recent = RecentHashes::default();
        let g = guard_with("hello", Duration::from_secs(5), 0, GuardMode::EmptyOnly);
        assert_eq!(
            evaluate_guard(&g, None, &recent, Instant::now()),
            GuardDecision::Drop
        );
    }

    /// Ring buffer trims to RECENT_INBOUND_CAP entries.
    #[test]
    fn recent_hashes_respects_cap() {
        let mut r = RecentHashes::default();
        let now = Instant::now();
        for i in 0..(RECENT_INBOUND_CAP + 4) {
            r.record(sha256(&[i as u8]), now);
        }
        assert_eq!(r.entries.len(), RECENT_INBOUND_CAP);
        // Oldest entries should be the most recent inserts (0..4 popped).
        assert!(r.contains_within(
            &sha256(&[(RECENT_INBOUND_CAP + 3) as u8]),
            now,
            RECENT_INBOUND_TTL
        ));
        assert!(!r.contains_within(&sha256(&[0u8]), now, RECENT_INBOUND_TTL));
    }
}
