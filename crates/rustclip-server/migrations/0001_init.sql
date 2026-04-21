-- Initial schema for RustClip.
--
-- BLOBs are used for UUIDs (16 bytes) and for ciphertext/nonce.
-- Integer columns use unix milliseconds for timestamps.

CREATE TABLE users (
    id              BLOB PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    content_salt    BLOB,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    disabled_at     INTEGER
);

CREATE INDEX users_username ON users(username);

CREATE TABLE devices (
    id                  BLOB PRIMARY KEY,
    user_id             BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name         TEXT NOT NULL,
    platform            TEXT NOT NULL,
    device_token_hash   TEXT NOT NULL,
    last_seen_at        INTEGER,
    created_at          INTEGER NOT NULL,
    revoked_at          INTEGER
);

CREATE INDEX devices_user_active ON devices(user_id) WHERE revoked_at IS NULL;

CREATE TABLE enrollment_tokens (
    id              BLOB PRIMARY KEY,
    user_id         BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    consumed_at     INTEGER,
    created_at      INTEGER NOT NULL
);

CREATE INDEX enrollment_tokens_user ON enrollment_tokens(user_id);
CREATE INDEX enrollment_tokens_expiry ON enrollment_tokens(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE blobs (
    id              BLOB PRIMARY KEY,
    sha256          TEXT NOT NULL,
    byte_length     INTEGER NOT NULL,
    storage_path    TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);

CREATE INDEX blobs_expiry ON blobs(expires_at);

CREATE TABLE clip_events (
    id                  BLOB PRIMARY KEY,
    user_id             BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_device_id    BLOB REFERENCES devices(id) ON DELETE SET NULL,
    content_kind        TEXT NOT NULL,
    inline_ciphertext   BLOB,
    blob_id             BLOB REFERENCES blobs(id) ON DELETE SET NULL,
    nonce               BLOB NOT NULL,
    mime_hint           TEXT NOT NULL,
    size_bytes          INTEGER NOT NULL,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL
);

CREATE INDEX clip_events_user_time ON clip_events(user_id, created_at DESC);
CREATE INDEX clip_events_expiry ON clip_events(expires_at);

CREATE TABLE clip_deliveries (
    clip_event_id       BLOB NOT NULL REFERENCES clip_events(id) ON DELETE CASCADE,
    target_device_id    BLOB NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    delivered_at        INTEGER,
    PRIMARY KEY (clip_event_id, target_device_id)
);

CREATE INDEX clip_deliveries_pending ON clip_deliveries(target_device_id) WHERE delivered_at IS NULL;

CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id   BLOB REFERENCES users(id) ON DELETE SET NULL,
    actor_device_id BLOB REFERENCES devices(id) ON DELETE SET NULL,
    event_type      TEXT NOT NULL,
    details_json    TEXT NOT NULL,
    ip_addr         TEXT,
    user_agent      TEXT,
    created_at      INTEGER NOT NULL
);

CREATE INDEX audit_log_time ON audit_log(created_at DESC);

CREATE TABLE settings (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      INTEGER NOT NULL
);
