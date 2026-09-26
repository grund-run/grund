//! Fixed-window counters for sign-in and mail limits.
//! One statement per check; keys are HMAC digests made by the caller, never
//! the counted value itself.

use std::time::Duration;

use sqlx::PgExecutor;

/// What is being counted. The strings match the table's CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    LoginFailure,
    LoginAddress,
    MailEmail,
    MailAddress,
    EnrollAddress,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::LoginFailure => "login_failure",
            Scope::LoginAddress => "login_address",
            Scope::MailEmail => "mail_email",
            Scope::MailAddress => "mail_address",
            Scope::EnrollAddress => "enroll_address",
        }
    }
}

/// Counts one hit in the current window and returns the window's total,
/// including this one. A new window starts from 1.
pub async fn hit(
    executor: impl PgExecutor<'_>,
    scope: Scope,
    key: &[u8; 32],
    window: Duration,
) -> Result<i32, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO grund_throttle AS t (scope, key_digest, window_start, hits) \
         VALUES ($1, $2, date_bin(make_interval(secs => $3), clock_timestamp(), 'epoch'), 1) \
         ON CONFLICT (scope, key_digest) DO UPDATE SET \
           hits = CASE WHEN t.window_start = EXCLUDED.window_start THEN t.hits + 1 ELSE 1 END, \
           window_start = EXCLUDED.window_start \
         RETURNING hits",
    )
    .bind(scope.as_str())
    .bind(&key[..])
    .bind(window.as_secs_f64())
    .fetch_one(executor)
    .await
}

/// The current window's total, without counting.
pub async fn count(
    executor: impl PgExecutor<'_>,
    scope: Scope,
    key: &[u8; 32],
    window: Duration,
) -> Result<i32, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE((SELECT hits FROM grund_throttle \
            WHERE scope = $1 AND key_digest = $2 \
              AND window_start = date_bin(make_interval(secs => $3), clock_timestamp(), 'epoch')), 0)",
    )
    .bind(scope.as_str())
    .bind(&key[..])
    .bind(window.as_secs_f64())
    .fetch_one(executor)
    .await
}

/// Forgets a counter (a successful sign-in clears its failures).
pub async fn clear(
    executor: impl PgExecutor<'_>,
    scope: Scope,
    key: &[u8; 32],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM grund_throttle WHERE scope = $1 AND key_digest = $2")
        .bind(scope.as_str())
        .bind(&key[..])
        .execute(executor)
        .await?;
    Ok(())
}

/// Deletes counters whose window ended more than a day ago. Bounded per pass.
pub async fn sweep(executor: impl PgExecutor<'_>) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM grund_throttle WHERE (scope, key_digest) IN ( \
           SELECT scope, key_digest FROM grund_throttle \
           WHERE window_start < clock_timestamp() - interval '1 day' LIMIT 1000)",
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
