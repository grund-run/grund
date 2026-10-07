//! Device logins (grund-docs design/cli.md §2): how `grund login` becomes
//! a CLI session once a signed-in person approves it in the browser. Only
//! the device code's SHA-256 is stored. Expiry is enforced by every read;
//! the sweeper only reclaims space.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// A new login to store.
pub struct NewLogin<'a> {
    pub login_id: Uuid,
    pub device_code_digest: &'a [u8; 32],
    pub user_code: &'a str,
    pub client: &'a str,
    pub host: &'a str,
    pub client_address: &'a str,
    pub ttl: Duration,
}

/// Stores a login. `false` when its user code is already held by a live
/// login, so the caller draws another.
pub async fn insert(
    executor: impl PgExecutor<'_>,
    login: NewLogin<'_>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO grund_device_logins \
           (login_id, device_code_digest, user_code, client, host, client_address, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp() + make_interval(secs => $7)) \
         ON CONFLICT DO NOTHING",
    )
    .bind(login.login_id)
    .bind(&login.device_code_digest[..])
    .bind(login.user_code)
    .bind(login.client)
    .bind(login.host)
    .bind(login.client_address)
    .bind(login.ttl.as_secs_f64())
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// A login waiting for a person, as the approval page shows it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingLogin {
    pub login_id: Uuid,
    pub user_code: String,
    pub client: String,
    pub host: String,
    pub client_address: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// The live login a user code names that nobody has approved or denied.
pub async fn pending(
    executor: impl PgExecutor<'_>,
    user_code: &str,
) -> Result<Option<PendingLogin>, sqlx::Error> {
    sqlx::query_as::<_, PendingLogin>(
        "SELECT login_id, user_code, client, host, client_address, created_at, expires_at \
         FROM grund_device_logins \
         WHERE user_code = $1 AND approved_at IS NULL AND denied_at IS NULL \
           AND used_at IS NULL AND expires_at > clock_timestamp()",
    )
    .bind(user_code)
    .fetch_optional(executor)
    .await
}

/// Approves a pending login for `account_id`. `false` when it is no longer
/// pending.
pub async fn approve(
    executor: impl PgExecutor<'_>,
    login_id: Uuid,
    account_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_device_logins SET approved_by = $2, approved_at = clock_timestamp() \
         WHERE login_id = $1 AND approved_at IS NULL AND denied_at IS NULL \
           AND used_at IS NULL AND expires_at > clock_timestamp()",
    )
    .bind(login_id)
    .bind(account_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Denies a pending login. `false` when it is no longer pending.
pub async fn deny(executor: impl PgExecutor<'_>, login_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_device_logins SET denied_at = clock_timestamp() \
         WHERE login_id = $1 AND approved_at IS NULL AND denied_at IS NULL \
           AND used_at IS NULL AND expires_at > clock_timestamp()",
    )
    .bind(login_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// A login as its poll finds it, locked until the transaction ends.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PolledLogin {
    pub login_id: Uuid,
    pub client: String,
    pub host: String,
    pub approved_by: Option<Uuid>,
    pub denied: bool,
    pub used: bool,
    pub expired: bool,
    pub polled_within: bool,
}

/// The login a device code names, locked, noting this poll. `polled_within`
/// says whether it was polled less than `interval` ago.
pub async fn poll(
    connection: &mut PgConnection,
    device_code_digest: &[u8; 32],
    interval: Duration,
) -> Result<Option<PolledLogin>, sqlx::Error> {
    sqlx::query_as::<_, PolledLogin>(
        "WITH found AS ( \
           SELECT login_id, last_polled_at FROM grund_device_logins \
           WHERE device_code_digest = $1 FOR UPDATE) \
         UPDATE grund_device_logins d SET last_polled_at = clock_timestamp() FROM found \
         WHERE d.login_id = found.login_id \
         RETURNING d.login_id, d.client, d.host, d.approved_by, \
           d.denied_at IS NOT NULL AS denied, d.used_at IS NOT NULL AS used, \
           d.expires_at <= clock_timestamp() AS expired, \
           COALESCE(found.last_polled_at > clock_timestamp() - make_interval(secs => $2), false) \
             AS polled_within",
    )
    .bind(&device_code_digest[..])
    .bind(interval.as_secs_f64())
    .fetch_optional(connection)
    .await
}

/// Marks an approved login used by the session it became.
pub async fn use_up(
    connection: &mut PgConnection,
    login_id: Uuid,
    session_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_device_logins SET used_at = clock_timestamp(), session_id = $2 \
         WHERE login_id = $1 AND used_at IS NULL",
    )
    .bind(login_id)
    .bind(session_id)
    .execute(connection)
    .await?;
    Ok(())
}

/// Deletes logins that ended more than a day ago. Bounded per pass.
pub async fn sweep(executor: impl PgExecutor<'_>) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM grund_device_logins WHERE login_id IN ( \
           SELECT login_id FROM grund_device_logins \
           WHERE expires_at < clock_timestamp() - interval '1 day' LIMIT 1000)",
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
