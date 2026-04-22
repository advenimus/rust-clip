# RustClip Operator Guide

## Deploying the server

### Docker Compose (recommended)

```bash
cp .env.example .env   # once you create one; otherwise set inline
docker compose -f docker/docker-compose.yml up -d
```

Environment variables consumed by the server:

| Variable | Default | Purpose |
| --- | --- | --- |
| `RUSTCLIP_BIND_ADDR` | `0.0.0.0:8080` | Listen address. Override with caution; prefer putting a reverse proxy in front. |
| `RUSTCLIP_DATA_DIR` | `/data` | Directory for `rustclip.db` and the `blobs/` subdirectory. Should be an encrypted volume. |
| `RUSTCLIP_PUBLIC_URL` | `http://<bind_addr>` | Canonical URL shown in the admin portal. Set to `https://clip.example.com` when you wire up TLS. |
| `RUSTCLIP_ADMIN_USERNAME` | (none) | Bootstrap admin account. Only used on first boot when the `users` table is empty. |
| `RUSTCLIP_ADMIN_PASSWORD` | (none) | Bootstrap admin password. Rotate immediately via the admin portal after first login. |
| `RUSTCLIP_MAX_PAYLOAD_BYTES` | `26214400` (25 MB) | Max single-blob ciphertext. Can also be tuned live in the admin settings page. |
| `RUSTCLIP_OFFLINE_TTL_HOURS` | `24` | How long encrypted events and blobs live for undelivered devices. Also tunable live. |
| `RUSTCLIP_LOG_LEVEL` | `info` | Standard `tracing` env filter. Examples: `warn,rustclip_server=debug`. |
| `RUSTCLIP_LOG_FORMAT` | `pretty` | Set to `json` for structured logs in production. |

### Required operational footnotes

- **Mount `/data` on an encrypted volume.** SQLite is not encrypted at rest, and the blob directory contains ciphertext blobs.
- **Put a reverse proxy in front.** The server speaks plain HTTP and expects the proxy to terminate TLS. Rate limiting on auth endpoints uses `X-Forwarded-For` to key per-IP buckets; without a proxy, all direct clients share one bucket. This is intentional: the shipped deployment model is proxy-fronted.
- **Signals:** SIGTERM and Ctrl-C trigger a graceful shutdown that drains in-flight HTTP, checkpoints the SQLite WAL, and closes the pool. `docker stop` will use SIGTERM (10 s default grace).

## Releases

The `.github/workflows/server-image.yml` workflow publishes the server to `ghcr.io/<owner>/rustclip-server` on every push to `main` and on any `v*` tag. GHCR login uses the auto-provided `GITHUB_TOKEN`; no extra secrets needed.

The `.github/workflows/client-release.yml` workflow builds `rustclip-client` for macOS (x86_64, aarch64), Linux (x86_64), and Windows (x86_64) on tag push. It attaches the archives to a draft GitHub Release.

Deferred to a future PR (not in Phase 9 scope):

- **macOS Developer ID notarization.** Conduit's setup (team ID `JBTB5G7DRQ`) can be reused, but the release workflow needs `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`, `CSC_LINK`, and `CSC_KEY_PASSWORD` secrets wired up on the repo, plus `xcrun notarytool submit` invocation after the build step. Without these, the macOS binaries work but trigger Gatekeeper warnings.
- **Windows code signing.** Needs an EV or standard code-signing cert and `signtool.exe` in the build step.
- **Linux aarch64.** Cross-compiling `arboard` to aarch64-linux-gnu needs the xcb headers + libs for arm64 via dpkg multiarch. Dropped from the v1 matrix; revisit when there's real demand.
- **Linux packaging (AppImage / deb).** Not scaffolded yet; the release currently ships a plain `.tar.gz` with the binary.

## Admin portal

- Login: `/admin/login` (10 req/min per IP rate limit).
- Settings: `/admin/settings` lets you update `max_payload_bytes`, `offline_ttl_hours`, `audit_retention_days`, and the update check toggle at runtime. Writes are persisted in the `settings` table; env vars remain the defaults the DB values start from.
- Audit log: `/admin/audit-log` supports filtering by event type and date range, and exports up to 10 000 rows as CSV at `/admin/audit-log.csv`.
- Device revocation: the devices page has per-row Revoke buttons with a named confirmation dialog. Revoked devices can re-enroll if the admin reissues an enrollment token.

## Updating the server

The server never updates itself — a container can't safely rewrite its own image without the Docker socket, and mounting that socket into the RustClip container would give it root-equivalent access to the host. Instead, RustClip exposes the upgrade path three ways, all opt-in:

1. **Manual upgrade** — from the Docker host:

   ```bash
   docker compose pull
   docker compose up -d
   ```

   The SQLite data volume persists across container recreations.

2. **Watchtower (opt-in)** — `docker/docker-compose.yml` ships with a [Watchtower](https://containrrr.dev/watchtower/) profile. It's off by default. To enable hands-off auto-update:

   ```bash
   docker compose --profile autoupdate up -d
   ```

   Watchtower polls the registry hourly, pulls a newer image when one appears, and restarts the container. It's scoped to containers with the label `com.centurylinklabs.watchtower.enable=true` (only `rustclip` has that label in the compose file) so it won't interfere with anything else running on the host.

   **Prerequisite**: the compose file as shipped builds from source and tags the image `rustclip/server:dev` — that tag doesn't exist in any registry, so Watchtower has nothing to pull. For auto-update to work, edit `docker/docker-compose.yml` so the `rustclip` service uses the published image instead:

   ```yaml
   rustclip:
     image: ghcr.io/advenimus/rustclip-server:latest
     # remove the "build:" block
   ```

   Then `docker compose pull && docker compose --profile autoupdate up -d` to switch. Manual-upgrade users (option 1) can keep building from source.

3. **Admin portal notification** — the server polls `https://api.github.com/repos/advenimus/rust-clip/releases/latest` every six hours. When a newer release is detected, a banner appears on `/admin/` with the copy-paste upgrade command, and `/admin/about` surfaces the full release notes. Admins who'd rather the server not reach out to GitHub can untick "Check for updates" on `/admin/settings`.

## Releasing the desktop client (Tauri updater one-time setup)

The desktop app uses `tauri-plugin-updater` for in-app updates. Before the first signed release, the maintainer must:

1. Install Tauri CLI: `cargo install tauri-cli --version "^2"`.
2. Generate a signing keypair: `cargo tauri signer generate -w ~/.tauri/rustclip.key` (choose a strong password).
3. Back up the private key *off* GitHub (password manager). Losing it means every user has to reinstall manually before future updates work again — the pubkey is baked into the shipped binaries.
4. Add two GitHub repo secrets:
   - `TAURI_SIGNING_PRIVATE_KEY` — contents of the generated private-key file.
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — the password chosen in step 2.
5. Replace the `REPLACE_ME_WITH_GENERATED_PUBKEY` placeholder in `crates/rustclip-client-gui/tauri.conf.json` (`plugins.updater.pubkey`) with the generated `.pub` file's contents.
6. Commit the updated `tauri.conf.json` and cut a test tag (e.g. `v0.2.0-rc1`) to verify the CI produces a `latest.json` artifact on the GitHub release.

Known platform caveats for auto-update:

- **macOS `.dmg`, Windows NSIS `.exe`, Windows `.msi`, Linux AppImage** → update in-app via the banner's "Install update" button.
- **Linux `.deb` / `.rpm`** → system-managed; the banner falls back to an "Open release page" button and a hint to upgrade via `apt` / `dnf`.
