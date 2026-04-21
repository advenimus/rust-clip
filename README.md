# RustClip

Self-hosted universal clipboard sync. Text, images, and files, end-to-end encrypted, across Windows, macOS, and Linux.

**Status:** Phase 3 text sync landed. Server WS hub + client sync daemon encrypt and exchange text clips across devices, with an offline queue, ack, and reconnect-with-backoff. Images come in Phase 4, files in Phase 5, tray UI + history in Phase 6.

## Architecture at a glance

One Rust binary, one Docker container:

- Admin portal at `/admin`
- Client REST API at `/api/v1/*`
- Client WebSocket at `/ws`

Desktop clients (Tauri) connect to the same container behind a reverse proxy (Caddy, Traefik, or Nginx). Clipboard content is encrypted client-side with a password-derived key. The server routes ciphertext, never plaintext.

## Workspace

- `crates/rustclip-shared`, shared types and primitives (no runtime deps).
- `crates/rustclip-server`, the Axum server (admin + API + WS).
- `crates/rustclip-client`, the desktop client (CLI today, Tauri shell in Phase 6).

## Enrolling a device (Phase 2)

```sh
# On the admin side, create a user in the portal and copy its enrollment token.
# Then on the target device:
rustclip-client enroll --server-url http://localhost:8080
# enter the enrollment token and choose a password when prompted

rustclip-client status   # verifies the stored token against the server
rustclip-client sync     # start the clipboard sync daemon (foreground)
rustclip-client logout   # revokes the device and clears the keychain
```

Credentials are stored in the OS keychain (macOS Keychain, Windows Credential Manager,
or the Linux Secret Service). Never in a dotfile.

## Running Phase 0

Native:

```sh
RUSTCLIP_DATA_DIR=./data \
RUSTCLIP_ADMIN_USERNAME=admin \
RUSTCLIP_ADMIN_PASSWORD=please-change-me \
cargo run -p rustclip-server

curl http://localhost:8080/healthz     # → ok
open http://localhost:8080/admin/login # then sign in as admin
```

Docker:

```sh
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build
curl http://localhost:8080/healthz   # → ok
```

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## License

MIT OR Apache-2.0
