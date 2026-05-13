# RustClip Threat Model

This document captures the security posture of RustClip as of Phase 8 hardening. It is deliberately narrow: operational and networking controls (TLS, reverse-proxy hardening) are the operator's responsibility and are called out where they materially change the risk surface.

## Actors

- **Operator.** Runs the server binary or Docker image, controls admin credentials, holds disk access to the SQLite database and blob directory, and terminates TLS.
- **Admin.** Web-portal user. Can create end-user accounts, issue enrollment tokens, revoke devices, view the audit log, and tune runtime settings.
- **End user.** Holds an account, a password, and one or more enrolled devices. Possesses the content-encryption key derived from the password.
- **Device.** A client process with a long-lived bearer device token and a derived content key held in OS keychain.
- **Network adversary.** Can observe or modify traffic between a device and the server. Assumed unable to break TLS.
- **Malicious operator / server breach.** Has read access to the SQLite DB and the `blobs/` directory.

## Guarantees

1. **Content confidentiality end-to-end.** Clipboard payloads (text, images, files) are encrypted client-side with XChaCha20-Poly1305 using a content key derived via Argon2id(password, per-user salt). The server never sees the password-derived key. A malicious operator or server breach yields ciphertext only.
2. **Device-scoped authorization.** All non-login endpoints require a device bearer token hashed on the server side. Tokens are revocable by the admin, self-revocable via logout, and never re-issued without a fresh password check.
3. **Admin-only account creation.** Users are provisioned exclusively through the admin portal. There is no public sign-up path.
4. **Auditability.** Admin logins, failed logins, user creation, device registration/revocation, enrollment-token issuance, and runtime-settings changes are recorded in the `audit_log` table with actor, IP, and user-agent.
5. **Bounded offline buffering.** Encrypted events and blobs expire per the configured TTL (default 24h) and are swept nightly by the background sweeper. Audit rows follow a separate retention window (default 90 days).

## Non-guarantees (explicit)

- **The server sees the password at login.** The Phase 1 decision accepted password-over-TLS for both enrollment and additional-device login, trading a OPAQUE/SRP style zero-knowledge handshake for a significantly simpler implementation and smaller attack surface elsewhere. A malicious operator can therefore harvest passwords during login calls and decrypt subsequent traffic for that user. Mitigations: password-hashing is Argon2id with current cost parameters; devices cache only the derived content key and the device token — they never re-transmit the password.
- **Integrity of stored ciphertext is trusted.** The AEAD tag protects against decryption of tampered ciphertext, but the server can drop events, reorder them, or return stale content. An active malicious operator can mount a denial-of-service or replay attack. Detection relies on operator transparency (audit log) and user-side monitoring of device activity.
- **SQLite is not encrypted at rest.** Operators running on shared disks should mount the `/data` volume on encrypted storage. The Docker image documents this constraint in the README.
- **Clipboard history on each device is plaintext.** The per-device `history.db` contains decrypted previews so users can see what synced. Devices should rely on OS-level full-disk encryption. History is wipeable via `history-clear`, and retention caps to 100 items / 7 days (whichever first).

## Key attack paths and mitigations

### Credential stuffing / brute force on admin login

- **Mitigation:** Per-IP token bucket limiter (10 attempts / min by default) applied to `POST /admin/login`. Successful logins are audited with IP and user-agent.
- **Residual risk:** Distributed-IP attacks bypass the per-IP cap. Operators should monitor the audit log for `admin_login_failed` spikes.

### Credential stuffing on device enrollment / login

- **Mitigation:** Same per-IP token bucket (10/min) on `POST /api/v1/auth/enroll` and `POST /api/v1/auth/login`. Enrollment tokens are single-use and expire after 30 days.
- **Residual risk:** As above.

### WS flooding / abusive clients

- **Mitigation:** Per-WS-connection token bucket caps client-sent ClipEvent messages at 30 events / 10 seconds (~3 events/sec steady state). Overflow events are rejected with an `Error { code: "rate_limited" }` envelope; the socket stays open. REST blob upload enforces `RUSTCLIP_MAX_PAYLOAD_BYTES` (default 25 MB) and rejects oversize streams partway through.
- **Residual risk:** An attacker with many stolen device tokens could sum buckets across connections. Device-level admin revocation is the escalation path.

### Session hijack on admin portal

- **Mitigation:** `tower-sessions` cookie with `HttpOnly`, `Secure` (when public URL is HTTPS), `SameSite=Strict`. Session-store is in SQLite so tokens rotate naturally. Logout calls `session.flush()`.
- **Admin HTML hardening headers:**
  - `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'`. `'unsafe-inline'` is accepted for styles because the admin portal uses Askama with a small number of inline style attributes in templates; no inline scripts are used.
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
- **Residual risk:** An admin running a compromised browser extension still loses control of the portal. Operators should treat admin workstations as sensitive.

### Information leakage in logs

- **Mitigation reviewed:** No tracing statement in the server binary logs plaintext passwords, plaintext tokens, or enrollment tokens. Token-bearing IDs (`%device_id`, `%user_id`) are logged as opaque UUIDs. Structured JSON logging is available via `RUSTCLIP_LOG_FORMAT=json` for operators running a SIEM.

### Nonce reuse in AEAD

- **Mitigation:** XChaCha20-Poly1305 uses a fresh 192-bit random nonce per message. Collision probability is negligible.

### Supply-chain compromise

- **Mitigation:** Toolchain pinned via `rust-toolchain.toml` (once Phase 9 lands its distribution pipeline). Docker image targets `gcr.io/distroless/cc-debian12:nonroot` — no shell, no package manager, non-root user. `cargo audit` runs in CI.
- **Residual risk:** Dependencies are frequently updated; operators should subscribe to advisories for `argon2`, `chacha20poly1305`, `axum`, `sqlx`, and `arboard`.

### Graceful shutdown data loss

- **Mitigation:** On SIGTERM or Ctrl-C, the server drains in-flight requests, checkpoints the SQLite WAL (`PRAGMA wal_checkpoint(TRUNCATE)`), and closes the pool before exit.

## Clipboard guard — aggressive mode trade-off

The receive-side clipboard guard re-asserts a freshly-received clip onto the OS clipboard when an external single-direction channel (Citrix host→guest, RDP guest tools, some VDI clients) stomps the paste. The user controls the behavior via a tri-state config:

- **Off** — never re-write. Safe default.
- **EmptyOnly** — re-write only if the OS clipboard goes empty within the window. Never fights a real copy because it only fires on empty. Safe in any environment.
- **Aggressive** — also re-write if the clipboard contents change to a hash that matches a recently-received inbound clip (within a 30-second ring buffer of the last 8 inbound hashes per content type). Intended for nested-VDI scenarios where both ends run RustClip and the host→guest channel can't be disabled.

**Residual risk in aggressive mode:** if the user, within 30 s of receiving clip X, deliberately re-copies the same content X on the local machine, the guard MAY interpret the second copy as a stale-direction stomp and overwrite it with X (which is the same content — net no harm). The risk is meaningful only if X and the user's NEW copy share a hash by coincidence: astronomically unlikely for text (256-bit SHA-2 collision), plausible for tiny identical images (e.g., a 32×32 status icon copied from one place and then again from another). The user can always re-copy or fall back to **EmptyOnly** if this becomes a problem. The guard is hard-capped at 3 re-assertions per clip so a runaway match can't burn CPU.

**Why a ring buffer rather than a single "last received" entry:** in a chatty session, several inbound clips arrive within seconds. The single-entry model would only defend the most-recent receive against stomps; an older receive that's still on the clipboard when the channel stomps it would be lost. The 8-entry, 30-second-TTL ring buffer covers the realistic window of "what's recently mine that I might paste."

## Open items tracked for future phases

- OPAQUE / SRP-style zero-knowledge password flow to remove the server-sees-password caveat. Currently on the Phase 9+ research list.
- `/metrics` Prometheus exporter for operator visibility beyond the admin portal. Scaffolded in Phase 8 planning; implementation deferred pending real production usage to drive metric choice.
- Client-side "require password on unlock" toggle to purge the content key from the keychain between sessions. Deferred; needs UX design alongside a future tray UI.
