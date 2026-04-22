# RustClip

Self-hosted, end-to-end encrypted universal clipboard sync. Pure Rust from the server to the desktop. One Docker image for the server, one menu-bar app for the desktop. Text, images, and files sync live across macOS / Windows / Linux devices linked to the same account; the server routes encrypted blobs and never sees plaintext.

This file is the orientation document for anyone (human or Claude) landing in the repo cold. It covers the concept, the structure, how to run things, the design decisions that aren't obvious from the code, and where the known deferrals are.

## Concept

- **Problem:** existing clipboard-sync tools split badly. ClipCascade is capable but a heavy Java/Spring stack. ClusterCut is lean Rust but LAN-only P2P with no real internet story. Nothing covers the middle: one tiny Docker container, genuine E2E encryption, works across the public internet behind any reverse proxy, scales from a single user to a team or MSP without rework.
- **Product shape:** self-hosted server + native menu-bar client. Admin provisions users via a web portal, hands each user a single-use enrollment token, the user plugs the token into their client, types a password, and from then on clipboard events sync live over WebSocket.
- **Security posture:** the user's password never leaves the client as an encryption input. A content-encryption key is derived from password + per-user salt via Argon2id. All clipboard payloads are sealed with XChaCha20-Poly1305 before hitting the wire. The server stores ciphertext blobs and routing metadata only.

## Workspace layout

```
rust-clip/
├── crates/
│   ├── rustclip-shared/         protocol types, wire envelopes, shared consts
│   ├── rustclip-server/         axum WS + REST + Askama admin portal
│   ├── rustclip-client/         LIB + CLI — sync daemon, auth, history, crypto
│   └── rustclip-client-gui/     Tauri v2 tray app (menu-bar only on macOS)
├── docker/                      Dockerfile + compose for the server
├── docs/
│   ├── operator-guide.md        env vars, deployment, deferrals
│   └── threat-model.md          what we guarantee, what we don't
├── .github/workflows/
│   ├── ci.yml                   fmt, clippy, tests, cargo-audit (every push/PR)
│   ├── server-image.yml         Docker image → GHCR (+ Docker Hub if secrets set), v* tags only
│   └── client-release.yml       tauri-action bundles .dmg/.msi/.AppImage/.deb, auto-publishes Latest, v* tags only
└── CLAUDE.md                    this file
```

## Build history (phase summary)

All phases are on `main`. Commits intentionally follow `feat: Phase N <topic>` so git log reads as a build log. First shipped release is `v0.1.1` at https://github.com/advenimus/rust-clip/releases/latest.

| Phase | What shipped |
|---|---|
| 0 | Workspace scaffolding, 3 crates, CI, stub Dockerfile + compose, `/healthz`. |
| 1 | Server foundations + admin portal MVP. SQLite + migrations, admin bootstrap from env, sessions, user CRUD, enrollment tokens, Askama pages. |
| 2 | End-user auth + device registration (REST + CLI client). Device tokens hashed server-side, keychain storage. |
| 3 | Core text sync over WebSocket. Per-user broadcast hub, clip-event persistence, offline drain on reconnect, echo suppression. End-to-end tokio-tungstenite integration tests. |
| 4 | Images + blob REST path. `POST/GET/DELETE /api/v1/blobs/:id`, PNG encode/decode on the client, inline vs blob threshold, seen-event LRU to dedupe drain-vs-live. |
| 5 | Files (send-only + macOS pasteboard-write). `send-files` CLI packs tar → encrypts → blob-uploads → announces via WS with bare `application/x-rustclip-bundle` mime (no filename leak). Receivers decrypt into `$DATA_LOCAL_DIR/rustclip/inbox/<event_id>/` and on macOS push `NSURL`s via objc2 so Cmd+V in Finder pastes the files. |
| 6 | Local clipboard history. Per-device rusqlite DB at `$DATA_LOCAL_DIR/rustclip/history.db`. 100-item / 7-day retention. `history` / `history-clear` CLI. |
| 7 | Admin portal breadth. Runtime settings store backed by the `settings` table with env fallbacks, live-editable via `/admin/settings`. Audit log gets event-type + date-range filters and CSV export at `/admin/audit-log.csv`. Sweeper prunes audit rows per retention. Dashboard adds clip-event counts (24h/7d) and blob-storage total. Device revoke flows through a named-flash banner. |
| 8 | Hardening. In-process token-bucket rate limiter scoped to `/admin/login` and `/api/v1/auth/*` (the regression test `blob_uploads_not_throttled_by_auth_limiter` pins the scope). Per-WS-connection event bucket (30/10s). `RUSTCLIP_LOG_FORMAT=json` toggle. SIGTERM/Ctrl-C graceful shutdown with `PRAGMA wal_checkpoint(TRUNCATE)`. CSP + Referrer-Policy + X-Frame-Options + X-Content-Type-Options on admin HTML. Client reconnect backoff with ±25% jitter. Threat model doc. |
| 9 | Distribution CI. Scaffolded `server-image.yml` + `client-release.yml`. Both were substantially reworked during release hardening (see Phase 11). `cargo audit` job added to CI. |
| 10 | Tauri v2 desktop UI. `rustclip-client` split into lib + CLI bin. New `rustclip-client-gui` crate with a tray icon, Account window (enroll/login/logout), History window (list/recopy/clear), embedded sync daemon via `SyncRunner`, autostart plugin, menu-bar-only on macOS (`ActivationPolicy::Accessory`). |
| 10.5 | Server observability + GUI polish (commit `77f8ab1`). Auto-start sync after in-app enroll/login. New `history_watcher` module polls the local history DB every 2s, emits `history-updated` Tauri events + `tauri-plugin-notification` toasts on incoming clips. Hand-rolled `/metrics` Prometheus endpoint on the server (`MetricsHub` with atomic counters + DB-queried gauges). |
| 11 | Release shipping. Switched `client-release.yml` to `tauri-apps/tauri-action` so it produces proper installers (`.dmg`, `.msi`, NSIS `.exe`, `.AppImage`, `.deb`, `.rpm`) plus CLI archives — no more raw binaries. Matrix is macOS aarch64 + Linux x86_64 + Windows x86_64 (no Intel Mac — see memory). Both release workflows are **v\* tags only** now (not every push to main). Release is auto-published + marked Latest via `make_latest: "true"`. Docker Hub publishing is optional — gated on `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` secrets, falls back to GHCR-only if unset. `cargo audit` ignores `RUSTSEC-2023-0071` (rsa via `sqlx-macros-core` at compile time, SQLite-only build so not reachable). First shipped tag is `v0.1.1` (v0.1.0 had the wrong app icon — blank placeholder — fixed by regenerating all variants from `icons/logo-color.png`). |

## Architecture deep-dives

### Crypto

- **Content key:** `Argon2id(password, content_salt, t=3, m=65536, p=4) → 32 bytes`. Derived on the client, never sent. On password change the salt rotates and old buffered events become undecryptable (documented trade-off).
- **Payload encryption:** `XChaCha20-Poly1305` with a fresh random 192-bit nonce per message. AAD binds `source_device_id`, `created_at`, `mime_hint` into the tag so the server can't re-label events.
- **Auth hashing (separate):** `Argon2id` PHC strings for passwords, `SHA-256` for device-token comparisons (subtle-time-safe).
- **Keychain:** all seven credential fields (server URL, device token, user/device IDs, username, content salt, derived content key) are packed into a single JSON blob stored as one `keyring` entry. An in-process `OnceLock` cache memoizes the blob so repeated reads inside one session don't touch the Security framework again. This solves the macOS "10 password prompts at launch" problem.

### Sync protocol

- **Envelope:** every WS message carries `"v": 1`. Versioning plan is documented in `docs/threat-model.md`.
- **Types:** `clip_event`, `ack`, `backlog_start`/`backlog_end`, `ping`/`pong`, `error`. Client → server and server → client use the same `ClipEventMessage` shape; the server stamps `source_device_id` on fan-out.
- **Inline vs blob:** `MAX_INLINE_CIPHERTEXT_BYTES = 64 KiB` is shared between server and client. Bigger payloads go through REST `POST /api/v1/blobs` first, and the WS event carries a `ContentRef::Blob { blob_id, nonce_b64, sha256_hex }` instead of inline ciphertext.
- **Backlog drain:** `clip_deliveries(clip_event_id, target_device_id, delivered_at)` tracks per-device delivery. On WS connect, the server streams any undelivered events between `BacklogStart` and `BacklogEnd`, marking them delivered as it goes. A small `SeenEvents` LRU on the client dedupes against the drain-vs-live race window.
- **Echo suppression:** events carry `source_device_id`; receivers discard their own echoes. Text/image watchers also keep a short content-hash LRU + a post-write quiet window (3s for images) to absorb the OS clipboard's own re-fire.

### Server

- **Axum 0.8** on tokio. Three top-level routers under `/admin`, `/api/v1`, `/ws`. Trailing-slash normalized via `NormalizePathLayer`.
- **SQLite (WAL)** via `sqlx` 0.8, compile-time-checked queries, migrations embedded via `sqlx::migrate!`. Schema lives in `crates/rustclip-server/migrations/0001_init.sql`.
- **Sessions:** `tower-sessions` 0.14 + `tower-sessions-sqlx-store` 0.15. Cookies are `HttpOnly`, `SameSite=Strict`, `Secure` whenever `RUSTCLIP_PUBLIC_URL` starts with `https://`.
- **Templates:** Askama 0.12, compile-time-checked. HTMX-light — the admin portal has zero build step; CSS lives at `static/app.css` and is embedded into the binary via `include_str!`.
- **Rate limiting:** scoped by router. `admin::router()` and `api::router()` both take a `RateLimiter` argument and only wrap the auth endpoints with the middleware — blob uploads and regular admin actions are deliberately unthrottled.
- **Shutdown:** `tokio::signal::ctrl_c()` + SIGTERM drain in-flight, `PRAGMA wal_checkpoint(TRUNCATE)`, close pool.

### Desktop client

- `rustclip-client` is both a library (`rustclip_client`) and a CLI binary (`rustclip-client`).
- The library exposes a `gui_api` module with structured return types for everything the GUI needs — `local_account`, `enroll`, `login`, `logout`, `load_sync_context`, `run_sync`, `list_history`, `clear_history`, `history_item_text`, `send_files`. The CLI's `commands` module mirrors the same operations but prints to stdout.
- `rustclip-client-gui` is a Tauri v2 app that depends on the library. The sync daemon runs in a tokio task supervised by `SyncRunner` (one `JoinHandle` behind a mutex, status emitted via Tauri events). Closing any window hides it; the tray keeps the daemon alive. On macOS, `app.set_activation_policy(ActivationPolicy::Accessory)` in `setup()` hides the app from the dock — it's menu-bar only.
- **Tray menu:** status line (Connected/Offline/Error/Not enrolled) → Recent clips submenu (last 10 text items, click to re-copy) → Account / History window links → Start/Stop sync → Quit.

### Release pipeline

- **Trigger model:** artifact workflows (`server-image.yml`, `client-release.yml`) fire **only on `v*` tags**. CI (`ci.yml`) runs on every push to `main` and every PR — tests, not artifacts. Result: nothing ships until a version tag is pushed.
- **Server image:** `docker/Dockerfile` → pushed to `ghcr.io/advenimus/rustclip-server:{version,major.minor,latest}`. Docker Hub push (`docker.io/<user>/rustclip-server:...`) is conditional on `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN` being set as repo secrets; workflow step `Detect Docker Hub secret` short-circuits cleanly when they're not.
- **Client release:** `tauri-apps/tauri-action@v0` builds + bundles. Matrix:
  - `macos-14` (Apple Silicon) → `.dmg` + `.app.tar.gz`
  - `ubuntu-22.04` → `.AppImage` + `.deb` + `.rpm`
  - `windows-latest` → `.msi` + NSIS `-setup.exe`
  After tauri-action finishes, a second `softprops/action-gh-release@v2` step packages the raw CLI binary into a per-platform `rustclip-cli-*` archive and attaches it to the same release. `draft: false` + `make_latest: "true"` means the release lands live and becomes Latest automatically.
- **Cutting a release:**
  ```bash
  # Bump workspace version in Cargo.toml AND tauri.conf.json, then:
  git tag v0.1.x
  git push origin v0.1.x
  ```
- **Known caveat:** bundles are **unsigned** — Gatekeeper (macOS) and SmartScreen (Windows) will warn. macOS workaround: `xattr -d com.apple.quarantine /Applications/RustClip.app`. Signing/notarization still needs repo secrets (deferrals list below).

## How to run things

### Server

```bash
# Quick dev loop
RUSTCLIP_ADMIN_USERNAME=admin RUSTCLIP_ADMIN_PASSWORD=please-change-me \
  cargo run -p rustclip-server
# => admin portal at http://127.0.0.1:8080/admin

# Docker (production shape, build locally)
docker compose -f docker/docker-compose.yml up -d --build

# Docker (pull the published image instead of building)
docker pull ghcr.io/advenimus/rustclip-server:latest
```

Env vars documented in `docs/operator-guide.md`. Defaults are sane; the ones you'll touch are `RUSTCLIP_ADMIN_USERNAME`, `RUSTCLIP_ADMIN_PASSWORD`, `RUSTCLIP_PUBLIC_URL`, and the `/data` volume mount.

### Client

```bash
# GUI (tray app) — macOS will prompt for keychain access ONCE per launch.
cargo run -p rustclip-client-gui

# CLI
cargo run -p rustclip-client -- enroll --server-url http://127.0.0.1:8080
cargo run -p rustclip-client -- sync
cargo run -p rustclip-client -- history
cargo run -p rustclip-client -- send-files foo.pdf bar.png
cargo run -p rustclip-client -- logout
```

Non-interactive flags for scripting: `--enrollment-token`, `--password` (also reads from `RUSTCLIP_PASSWORD` env).

**Install from a GitHub Release** (end-user path): grab the platform-native installer from https://github.com/advenimus/rust-clip/releases/latest — `.dmg` (macOS), `.msi` or NSIS `-setup.exe` (Windows), `.AppImage` / `.deb` / `.rpm` (Linux). Also attached: `rustclip-cli-*` archives with just the CLI binary.

### Tests and checks

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Current state: 57 tests passing (16 client + 38 server + 3 shared). CI runs the same three commands plus `cargo audit` (ignoring `RUSTSEC-2023-0071` — justified in `.github/workflows/ci.yml`).

## Design decisions that aren't obvious from the code

- **SQLite over Postgres on the server.** The workload is WS-fanout + tiny metadata rows. SQLite in WAL mode is easier to operate (one file, one volume, no extra container). Dropping to Postgres is mechanical if it ever matters.
- **Password over TLS at login.** We accept the server-sees-password-at-login posture for now (standard web posture) in exchange for a much simpler protocol. OPAQUE/SRP is noted as a v2 upgrade path in the threat model. Devices never re-send the password after enrollment — they hold only the device token and the derived content key.
- **Server stores ciphertext only.** Everything in `clip_events.inline_ciphertext` / `blobs/*` is encrypted with the user's content key. A malicious operator with disk access gets ciphertext, no more.
- **Single keychain item.** macOS raises one ACL prompt per keychain item; seven items meant seven prompts per session. We pack into one JSON blob keyed by `service=rustclip, account=credentials` and memoize the decrypted result in-process.
- **Rate limiter scope matters.** During Phase 8 I initially wrapped the whole `/admin` and `/api/v1` trees with the auth limiter; the advisor caught that this would throttle blob uploads and admin actions. The fix scopes the middleware to just `/admin/login` and `/api/v1/auth/*`, and the regression test `blob_uploads_not_throttled_by_auth_limiter` pins it.
- **Menu-bar-only on macOS.** `ActivationPolicy::Accessory` is set in `setup()` — no dock tile, no application menu. Tray keeps the daemon alive.
- **File sync scope for Phase 5.** Receive-and-paste works on macOS. Detecting an OS-native file copy on the sending side (`NSFilenamesPboardType`, `CF_HDROP`, `text/uri-list`) is deferred — for now users either use `send-files` from the CLI or drop files into the tray (future). See `docs/architectural_decisions.md` deviation note if you're reading this from a worktree where that exists; otherwise the memory system has the trail.
- **No Intel Mac in the release matrix.** `macos-13` runners queue 15+ minutes under load and modern Macs are all Apple Silicon. The v0.1.0 tag attempt had all three other platforms finish while Intel Mac sat queued — we cut it from the matrix rather than wait. If Intel Mac is ever requested, cross-compile from `macos-14` via `--target x86_64-apple-darwin` instead of re-adding `macos-13`.
- **Tauri config `version` is manually synced.** `tauri.conf.json` hardcodes `"version"` rather than reading from `Cargo.toml` — simpler and reliable. Bumping a release means editing **both** `Cargo.toml` (workspace) and `crates/rustclip-client-gui/tauri.conf.json`.
- **App icon source is `icons/logo-color.png`, not `icon.png`.** A placeholder `icon.png` shipped with v0.1.0 and gave the DMG a blank orange square. Regenerating must use `cargo tauri icon crates/rustclip-client-gui/icons/logo-color.png` (or first `cp logo-color.png icon.png` then run `cargo tauri icon icons/icon.png`). Always delete the `icons/ios/`, `icons/android/`, and `Square*Logo.png` / `StoreLogo.png` artifacts afterwards — desktop-only project.
- **`cargo audit` ignores `RUSTSEC-2023-0071`.** `rsa 0.9.x` Marvin Attack is pulled by `sqlx-macros-core` at compile time for MySQL type introspection. rustclip-server only speaks SQLite, so `rsa` never ships in the release binary. Ignored in `.github/workflows/ci.yml` with justification; revisit if sqlx publishes a fix.

## Known deferrals (not in any phase)

- OS clipboard-watcher file detection on the sending side (so copying files in Finder/Explorer auto-syncs them without using `send-files`).
- Apple Developer ID signing + notarization in the release workflow. The plumbing is ready in `tauri-action`; needs repo secrets wired (`APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`, `CSC_LINK`, `CSC_KEY_PASSWORD`). Team ID `JBTB5G7DRQ` is reused from the user's other project (Conduit).
- Windows code-signing (needs an EV or standard code-signing cert).
- Docker Hub publishing — workflow is wired, waiting on `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN` repo secrets. Without them, server image only lands on GHCR.
- Intel Mac (x86_64-apple-darwin) builds. Deliberate non-goal — see "Design decisions".
- Linux aarch64 client build. Not in the v1 matrix; needs multi-arch xcb headers in the runner.
- Multi-arch Docker image (`linux/arm64`). Currently `linux/amd64` only; QEMU build would add ~20 min.
- Tray-app preference to require password re-entry on unlock (to purge the content key from memory between sessions).

## Where to look for things

- **Protocol wire types:** `crates/rustclip-shared/src/protocol.rs`, `rest.rs`.
- **Admin portal routes:** `crates/rustclip-server/src/admin/mod.rs`.
- **WS session state machine:** `crates/rustclip-server/src/ws/session.rs`.
- **Client sync loop (reconnect, encrypt, decrypt, apply to clipboard):** `crates/rustclip-client/src/sync.rs`.
- **Tauri commands bridged to the frontend:** `crates/rustclip-client-gui/src/commands.rs`.
- **Tray menu construction:** `crates/rustclip-client-gui/src/tray.rs`.
- **Frontend (vanilla HTML/JS, no build step):** `crates/rustclip-client-gui/dist/`.
