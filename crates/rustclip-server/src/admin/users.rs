use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use rand::{
    RngCore,
    distributions::{Alphanumeric, Distribution},
    rngs::OsRng,
};
use serde::Deserialize;
use sqlx::FromRow;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    admin::dashboard::format_millis,
    audit,
    db::now_millis,
    error::{AppError, AppResult},
    middleware::{AdminUser, client_meta},
    password::hash_password,
    state::AppState,
    tokens,
};

const ENROLLMENT_TTL_DAYS: i64 = 30;

#[derive(FromRow)]
struct UserListRow {
    id: Uuid,
    username: String,
    display_name: String,
    is_admin: i64,
    created_at: i64,
    disabled_at: Option<i64>,
    device_count: i64,
}

pub struct UserRowView {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub is_admin: bool,
    pub is_active: bool,
    pub created_at: String,
    pub device_count: i64,
}

#[derive(Template)]
#[template(path = "users.html")]
struct UsersTemplate<'a> {
    admin_display_name: &'a str,
    users: Vec<UserRowView>,
}

pub async fn list(State(state): State<AppState>, admin: AdminUser) -> AppResult<Response> {
    let rows = sqlx::query_as::<_, UserListRow>(
        "SELECT u.id, u.username, u.display_name, u.is_admin, u.created_at, u.disabled_at, \
         (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL) AS device_count \
         FROM users u \
         ORDER BY u.created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let users = rows
        .into_iter()
        .map(|r| UserRowView {
            id: r.id,
            username: r.username,
            display_name: r.display_name,
            is_admin: r.is_admin != 0,
            is_active: r.disabled_at.is_none(),
            created_at: format_millis(r.created_at),
            device_count: r.device_count,
        })
        .collect();

    let tmpl = UsersTemplate {
        admin_display_name: &admin.display_name,
        users,
    };
    Ok(Html(tmpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    pub username: String,
    pub display_name: String,
}

#[derive(Template)]
#[template(path = "user_created.html")]
struct UserCreatedTemplate<'a> {
    admin_display_name: &'a str,
    username: &'a str,
    display_name: &'a str,
    enrollment_token: &'a str,
    expires_at: &'a str,
    public_url: &'a str,
}

pub async fn create(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Form(form): Form<CreateUserForm>,
) -> AppResult<Response> {
    let username = form.username.trim();
    let display_name = form.display_name.trim();
    if username.is_empty() {
        return Err(AppError::Validation("username is required".into()));
    }
    if display_name.is_empty() {
        return Err(AppError::Validation("display name is required".into()));
    }

    let mut tx = state.db.begin().await?;

    let user_id = Uuid::new_v4();
    let now = now_millis();
    let res = sqlx::query(
        "INSERT INTO users \
         (id, username, display_name, password_hash, content_salt, is_admin, created_at) \
         VALUES (?, ?, ?, '', NULL, 0, ?)",
    )
    .bind(user_id)
    .bind(username)
    .bind(display_name)
    .bind(now)
    .execute(&mut *tx)
    .await;

    match res {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::Validation(format!(
                "username '{username}' already exists"
            )));
        }
        Err(e) => return Err(e.into()),
    }

    let generated = tokens::generate_token().map_err(AppError::internal)?;
    let enrollment_id = Uuid::new_v4();
    let expires_at =
        (OffsetDateTime::now_utc() + Duration::days(ENROLLMENT_TTL_DAYS)).unix_timestamp() * 1000;

    sqlx::query(
        "INSERT INTO enrollment_tokens \
         (id, user_id, token_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(enrollment_id)
    .bind(user_id)
    .bind(&generated.hash)
    .bind(expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let (ip, ua) = client_meta(&headers);
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_USER_CREATED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({ "user_id": user_id, "username": username }),
    )
    .await?;
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_ENROLLMENT_TOKEN_ISSUED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({ "user_id": user_id, "expires_at": expires_at }),
    )
    .await?;

    let tmpl = UserCreatedTemplate {
        admin_display_name: &admin.display_name,
        username,
        display_name,
        enrollment_token: &generated.plaintext,
        expires_at: &format_millis(expires_at),
        public_url: &state.config.public_url,
    };
    Ok(Html(tmpl.render()?).into_response())
}

pub async fn delete(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Redirect> {
    if id == admin.id {
        return Err(AppError::Validation(
            "you cannot delete the currently logged in admin".into(),
        ));
    }
    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let (ip, ua) = client_meta(&headers);
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_USER_DELETED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({ "user_id": id }),
    )
    .await?;
    Ok(Redirect::to("/admin/users"))
}

pub async fn reset_enrollment(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Response> {
    let user = sqlx::query_as::<_, (String, String)>(
        "SELECT username, display_name FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM enrollment_tokens WHERE user_id = ? AND consumed_at IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    let generated = tokens::generate_token().map_err(AppError::internal)?;
    let enrollment_id = Uuid::new_v4();
    let now = now_millis();
    let expires_at =
        (OffsetDateTime::now_utc() + Duration::days(ENROLLMENT_TTL_DAYS)).unix_timestamp() * 1000;

    sqlx::query(
        "INSERT INTO enrollment_tokens \
         (id, user_id, token_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(enrollment_id)
    .bind(id)
    .bind(&generated.hash)
    .bind(expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let (ip, ua) = client_meta(&headers);
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_ENROLLMENT_TOKEN_ISSUED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({ "user_id": id, "expires_at": expires_at, "reissued": true }),
    )
    .await?;

    let tmpl = UserCreatedTemplate {
        admin_display_name: &admin.display_name,
        username: &user.0,
        display_name: &user.1,
        enrollment_token: &generated.plaintext,
        expires_at: &format_millis(expires_at),
        public_url: &state.config.public_url,
    };
    Ok(Html(tmpl.render()?).into_response())
}

const GENERATED_PASSWORD_LEN: usize = 16;
const MIN_PASSWORD_LEN: usize = 8;

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    /// Admin-chosen password. If empty, the server generates one and
    /// shows it once on the confirmation page.
    #[serde(default)]
    pub new_password: String,
}

#[derive(FromRow)]
struct TargetUserRow {
    username: String,
    display_name: String,
    is_admin: i64,
}

#[derive(Template)]
#[template(path = "user_password_reset.html")]
struct PasswordResetTemplate<'a> {
    admin_display_name: &'a str,
    username: &'a str,
    display_name: &'a str,
    new_password: &'a str,
    devices_revoked: u64,
    events_invalidated: u64,
    target_is_admin: bool,
    auto_generated: bool,
}

/// Resets a user's password.
///
/// For end users this is destructive by design: the content-encryption
/// key is derived from the password + per-user content salt, so a
/// password reset necessarily rotates the salt, which in turn makes
/// every already-stored (encrypted) clip event undecryptable with the
/// new key. We therefore:
///   1. Rotate `content_salt` alongside `password_hash`.
///   2. Revoke every active device token for that user — the devices
///      cached the OLD content key in their local keychain, so they
///      would fail to decrypt new clips and mint confusing errors.
///      Forcing re-login is both honest and cleaner.
///   3. Delete any queued `clip_events` for the user — they're
///      garbage now and would surface as decryption failures on the
///      next device-backlog drain. `clip_deliveries` cascades on the
///      delete.
///
/// Admin users (which have no `content_salt` and no devices) only have
/// their auth password hash rotated.
pub async fn reset_password(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<ResetPasswordForm>,
) -> AppResult<Response> {
    let user = sqlx::query_as::<_, TargetUserRow>(
        "SELECT username, display_name, is_admin FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let trimmed = form.new_password.trim();
    let (plaintext, auto_generated) = if trimmed.is_empty() {
        (generate_password(GENERATED_PASSWORD_LEN), true)
    } else {
        if trimmed.len() < MIN_PASSWORD_LEN {
            return Err(AppError::Validation(format!(
                "password must be at least {MIN_PASSWORD_LEN} characters"
            )));
        }
        (trimmed.to_string(), false)
    };

    let password_hash = hash_password(&plaintext).map_err(AppError::internal)?;
    let now = now_millis();

    let mut tx = state.db.begin().await?;

    let (devices_revoked, events_invalidated) = if user.is_admin != 0 {
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(&password_hash)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        (0u64, 0u64)
    } else {
        let mut new_salt = [0u8; 32];
        OsRng.fill_bytes(&mut new_salt);

        sqlx::query("UPDATE users SET password_hash = ?, content_salt = ? WHERE id = ?")
            .bind(&password_hash)
            .bind(new_salt.as_slice())
            .bind(id)
            .execute(&mut *tx)
            .await?;

        let revoked = sqlx::query(
            "UPDATE devices SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        // Deleting clip_events cascades to clip_deliveries via FK.
        let invalidated = sqlx::query("DELETE FROM clip_events WHERE user_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();

        (revoked, invalidated)
    };

    tx.commit().await?;

    let (ip, ua) = client_meta(&headers);
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_USER_PASSWORD_RESET,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({
            "user_id": id,
            "username": user.username,
            "target_is_admin": user.is_admin != 0,
            "auto_generated": auto_generated,
            "devices_revoked": devices_revoked,
            "events_invalidated": events_invalidated,
        }),
    )
    .await?;

    let tmpl = PasswordResetTemplate {
        admin_display_name: &admin.display_name,
        username: &user.username,
        display_name: &user.display_name,
        new_password: &plaintext,
        devices_revoked,
        events_invalidated,
        target_is_admin: user.is_admin != 0,
        auto_generated,
    };
    Ok(Html(tmpl.render()?).into_response())
}

fn generate_password(len: usize) -> String {
    let mut out = String::with_capacity(len);
    while out.len() < len {
        let ch = char::from(Alphanumeric.sample(&mut OsRng));
        // Drop easily-confused characters so the admin can read the
        // password back to the user over voice without ambiguity.
        if matches!(ch, '0' | 'O' | '1' | 'l' | 'I') {
            continue;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{password::verify_password, test_util::test_pool};

    async fn seed_end_user(pool: &crate::db::DbPool) -> (Uuid, String, Vec<u8>) {
        let user_id = Uuid::new_v4();
        let initial_hash = hash_password("old-password").unwrap();
        let initial_salt: Vec<u8> = vec![7u8; 32];
        sqlx::query(
            "INSERT INTO users \
             (id, username, display_name, password_hash, content_salt, is_admin, created_at) \
             VALUES (?, 'target', 'Target', ?, ?, 0, 0)",
        )
        .bind(user_id)
        .bind(&initial_hash)
        .bind(&initial_salt)
        .execute(pool)
        .await
        .unwrap();
        (user_id, initial_hash, initial_salt)
    }

    async fn seed_admin(pool: &crate::db::DbPool) -> Uuid {
        let admin_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, display_name, password_hash, is_admin, created_at) \
             VALUES (?, 'adm', 'Admin', ?, 1, 0)",
        )
        .bind(admin_id)
        .bind(hash_password("admin-pw").unwrap())
        .execute(pool)
        .await
        .unwrap();
        admin_id
    }

    async fn run_reset(
        pool: &crate::db::DbPool,
        admin_id: Uuid,
        user_id: Uuid,
        new_password: &str,
    ) -> (u64, u64) {
        // Exercise the same transaction body the handler uses, without
        // pulling a full axum test harness in just for this one path.
        let user = sqlx::query_as::<_, TargetUserRow>(
            "SELECT username, display_name, is_admin FROM users WHERE id = ?",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();

        let (plaintext, _auto) = if new_password.is_empty() {
            (generate_password(GENERATED_PASSWORD_LEN), true)
        } else {
            (new_password.to_string(), false)
        };
        let password_hash = hash_password(&plaintext).unwrap();
        let now = now_millis();

        let mut tx = pool.begin().await.unwrap();
        let (revoked, invalidated) = if user.is_admin != 0 {
            sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
                .bind(&password_hash)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            (0, 0)
        } else {
            let mut new_salt = [0u8; 32];
            OsRng.fill_bytes(&mut new_salt);
            sqlx::query("UPDATE users SET password_hash = ?, content_salt = ? WHERE id = ?")
                .bind(&password_hash)
                .bind(new_salt.as_slice())
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            let revoked = sqlx::query(
                "UPDATE devices SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .unwrap()
            .rows_affected();
            let invalidated = sqlx::query("DELETE FROM clip_events WHERE user_id = ?")
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .unwrap()
                .rows_affected();
            (revoked, invalidated)
        };
        tx.commit().await.unwrap();

        let _ = admin_id; // kept to mirror handler signature.
        (revoked, invalidated)
    }

    #[tokio::test]
    async fn reset_rotates_hash_salt_and_forces_relogin() {
        let pool = test_pool().await;
        let admin_id = seed_admin(&pool).await;
        let (user_id, original_hash, original_salt) = seed_end_user(&pool).await;

        // Seed one active device and one queued clip event for the user.
        let device_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO devices \
             (id, user_id, device_name, platform, device_token_hash, created_at) \
             VALUES (?, ?, 'd', 'macos', 'x', 0)",
        )
        .bind(device_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO clip_events \
             (id, user_id, source_device_id, content_kind, inline_ciphertext, \
              nonce, mime_hint, size_bytes, created_at, expires_at) \
             VALUES (?, ?, ?, 'inline', X'00', X'01', 'text/plain', 1, 0, ?)",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(device_id)
        .bind(i64::MAX)
        .execute(&pool)
        .await
        .unwrap();

        let (revoked, invalidated) = run_reset(&pool, admin_id, user_id, "fresh-password").await;
        assert_eq!(revoked, 1);
        assert_eq!(invalidated, 1);

        let (new_hash, new_salt, revoked_at): (String, Vec<u8>, Option<i64>) =
            sqlx::query_as(
                "SELECT u.password_hash, u.content_salt, \
                        (SELECT revoked_at FROM devices WHERE id = ?) \
                 FROM users u WHERE u.id = ?",
            )
            .bind(device_id)
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_ne!(new_hash, original_hash);
        assert_ne!(new_salt, original_salt);
        assert!(revoked_at.is_some(), "device must be revoked");
        assert!(
            verify_password("fresh-password", &new_hash).unwrap(),
            "new password must verify"
        );
        assert!(
            !verify_password("old-password", &new_hash).unwrap(),
            "old password must no longer verify"
        );

        let remaining_events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM clip_events WHERE user_id = ?")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining_events, 0, "queued events must be discarded");
    }

    #[tokio::test]
    async fn admin_reset_only_rotates_password_hash() {
        let pool = test_pool().await;
        let admin_id = seed_admin(&pool).await;
        let (_, original_admin_hash, _) =
            (admin_id, hash_password("admin-pw").unwrap(), Vec::<u8>::new());

        let (revoked, invalidated) = run_reset(&pool, admin_id, admin_id, "new-admin-pw").await;
        assert_eq!(revoked, 0);
        assert_eq!(invalidated, 0);

        let new_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?")
            .bind(admin_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_ne!(new_hash, original_admin_hash);
        assert!(verify_password("new-admin-pw", &new_hash).unwrap());
    }

    #[test]
    fn generate_password_respects_length_and_charset() {
        let pw = generate_password(16);
        assert_eq!(pw.len(), 16);
        for c in pw.chars() {
            assert!(c.is_ascii_alphanumeric());
            assert!(!matches!(c, '0' | 'O' | '1' | 'l' | 'I'));
        }
    }
}
