//! Dashboard sessions. Only the SHA-256 of a session token is stored; expiry
//! (idle and absolute) is enforced by every read.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// A new session to store.
pub struct NewSession<'a> {
    pub session_id: Uuid,
    pub token_digest: &'a [u8; 32],
    pub account_id: Uuid,
    pub max_age: Duration,
    pub user_agent: &'a str,
    pub client_address: &'a str,
}

/// Stores a session.
pub async fn insert(
    connection: &mut PgConnection,
    session: NewSession<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_sessions \
           (session_id, token_digest, account_id, expires_at, user_agent, client_address) \
         VALUES ($1, $2, $3, clock_timestamp() + make_interval(secs => $4), $5, $6)",
    )
    .bind(session.session_id)
    .bind(&session.token_digest[..])
    .bind(session.account_id)
    .bind(session.max_age.as_secs_f64())
    .bind(truncate(session.user_agent, 256))
    .bind(truncate(session.client_address, 64))
    .execute(connection)
    .await?;
    Ok(())
}

fn truncate(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}

/// A live session, found by its token.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LiveSession {
    pub session_id: Uuid,
    pub account_id: Uuid,
    pub last_seen_at: DateTime<Utc>,
}

/// The live session a token names: not revoked, not past its absolute
/// expiry, and seen within `idle`.
pub async fn find(
    executor: impl PgExecutor<'_>,
    token_digest: &[u8; 32],
    idle: Duration,
) -> Result<Option<LiveSession>, sqlx::Error> {
    sqlx::query_as::<_, LiveSession>(
        "SELECT session_id, account_id, last_seen_at FROM grund_sessions \
         WHERE token_digest = $1 AND revoked_at IS NULL AND expires_at > clock_timestamp() \
           AND last_seen_at > clock_timestamp() - make_interval(secs => $2)",
    )
    .bind(&token_digest[..])
    .bind(idle.as_secs_f64())
    .fetch_optional(executor)
    .await
}

/// Records activity, at most once a minute per session.
pub async fn touch(executor: impl PgExecutor<'_>, session_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_sessions SET last_seen_at = clock_timestamp() \
         WHERE session_id = $1 AND last_seen_at < clock_timestamp() - interval '1 minute'",
    )
    .bind(session_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// One of an account's sessions, for the sessions page.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionView {
    pub session_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub user_agent: String,
    pub client_address: String,
}

/// The account's live sessions, newest first.
pub async fn list(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
    idle: Duration,
) -> Result<Vec<SessionView>, sqlx::Error> {
    sqlx::query_as::<_, SessionView>(
        "SELECT session_id, created_at, last_seen_at, user_agent, client_address FROM grund_sessions \
         WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > clock_timestamp() \
           AND last_seen_at > clock_timestamp() - make_interval(secs => $2) \
         ORDER BY created_at DESC LIMIT 100",
    )
    .bind(account_id)
    .bind(idle.as_secs_f64())
    .fetch_all(executor)
    .await
}

/// Revokes one of the account's sessions. `false` when the account has no
/// such live session, which includes another account's session.
pub async fn revoke(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
    session_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_sessions SET revoked_at = clock_timestamp() \
         WHERE account_id = $1 AND session_id = $2 AND revoked_at IS NULL",
    )
    .bind(account_id)
    .bind(session_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Revokes every live session of the account except `keep`.
pub async fn revoke_all_except(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
    keep: Option<Uuid>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_sessions SET revoked_at = clock_timestamp() \
         WHERE account_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR session_id <> $2)",
    )
    .bind(account_id)
    .bind(keep)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Revokes whatever session a token names, whoever owns it.
pub async fn revoke_by_token(
    executor: impl PgExecutor<'_>,
    token_digest: &[u8; 32],
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE grund_sessions SET revoked_at = clock_timestamp() WHERE token_digest = $1 AND revoked_at IS NULL")
        .bind(&token_digest[..])
        .execute(executor)
        .await?;
    Ok(())
}

/// Deletes sessions that ended more than a day ago. Bounded per pass.
pub async fn sweep(executor: impl PgExecutor<'_>) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM grund_sessions WHERE session_id IN ( \
           SELECT session_id FROM grund_sessions \
           WHERE expires_at < clock_timestamp() - interval '1 day' \
              OR revoked_at < clock_timestamp() - interval '1 day' \
              OR last_seen_at < clock_timestamp() - interval '91 days' \
           LIMIT 1000)",
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
