# RustClip

Self-hosted universal clipboard sync. Text, images, and files, end-to-end encrypted, across Windows, macOS, and Linux.

**Status:** Phase 0, scaffold only. No functional sync yet.

## Architecture at a glance

One Rust binary, one Docker container:

- Admin portal at `/admin`
- Client REST API at `/api/v1/*`
- Client WebSocket at `/ws`

Desktop clients (Tauri) connect to the same container behind a reverse proxy (Caddy, Traefik, or Nginx). Clipboard content is encrypted client-side with a password-derived key. The server routes ciphertext, never plaintext.

## Workspace

- `crates/rustclip-shared`, shared types and primitives (no runtime deps).
- `crates/rustclip-server`, the Axum server (admin + API + WS).
- `crates/rustclip-client`, the Tauri desktop client (shell comes in Phase 2).

## Running Phase 0

Native:

```sh
cargo run -p rustclip-server
curl http://localhost:8080/healthz   # → ok
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
