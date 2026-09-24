//! Single-use links sent by mail: email verification and password reset.
//! Only the SHA-256 of a token is stored, bound to the address it was sent to.

use std::time::Duration;

use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// What a link is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    VerifyEmail,
    ResetPassword,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::VerifyEmail => "verify_email",
            Purpose::ResetPassword => "reset_password",
        }
    }
}

/// Stores a new link for the account, valid for `ttl`, and invalidates the
/// account's earlier unused links for the same purpose.
pub async fn issue(
    connection: &mut PgConnection,
    token_digest: &[u8; 32],
    purpose: Purpose,
    account_id: Uuid,
    email_normalized: &str,
    ttl: Duration,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_email_tokens SET used_at = clock_timestamp() \
         WHERE account_id = $1 AND purpose = $2 AND used_at IS NULL",
    )
    .bind(account_id)
    .bind(purpose.as_str())
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO grund_email_tokens (token_digest, purpose, account_id, email_normalized, expires_at) \
         VALUES ($1, $2, $3, $4, clock_timestamp() + make_interval(secs => $5))",
    )
    .bind(&token_digest[..])
    .bind(purpose.as_str())
    .bind(account_id)
    .bind(email_normalized)
    .bind(ttl.as_secs_f64())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

/// A link that is still good.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Redeemable {
    pub account_id: Uuid,
    pub email_normalized: String,
}

/// Whether a link is still good, without using it (for the page a link opens).
pub async fn peek(
    executor: impl PgExecutor<'_>,
    token_digest: &[u8; 32],
    purpose: Purpose,
) -> Result<Option<Redeemable>, sqlx::Error> {
    sqlx::query_as::<_, Redeemable>(
        "SELECT t.account_id, t.email_normalized FROM grund_email_tokens t \
         JOIN grund_account_emails e ON e.account_id = t.account_id AND e.email_normalized = t.email_normalized \
         WHERE t.token_digest = $1 AND t.purpose = $2 AND t.used_at IS NULL AND t.expires_at > clock_timestamp()",
    )
    .bind(&token_digest[..])
    .bind(purpose.as_str())
    .fetch_optional(executor)
    .await
}

/// Uses a link: marks it used and returns whom it was for, or `None` if it
/// is unknown, used, expired, or for an address the account no longer has.
pub async fn redeem(
    connection: &mut PgConnection,
    token_digest: &[u8; 32],
    purpose: Purpose,
) -> Result<Option<Redeemable>, sqlx::Error> {
    sqlx::query_as::<_, Redeemable>(
        "UPDATE grund_email_tokens t SET used_at = clock_timestamp() \
         FROM grund_account_emails e \
         WHERE t.token_digest = $1 AND t.purpose = $2 AND t.used_at IS NULL \
           AND t.expires_at > clock_timestamp() \
           AND e.account_id = t.account_id AND e.email_normalized = t.email_normalized \
         RETURNING t.account_id, t.email_normalized",
    )
    .bind(&token_digest[..])
    .bind(purpose.as_str())
    .fetch_optional(connection)
    .await
}

/// Deletes links that expired more than a day ago. Bounded per pass.
pub async fn sweep(executor: impl PgExecutor<'_>) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM grund_email_tokens WHERE token_digest IN ( \
           SELECT token_digest FROM grund_email_tokens \
           WHERE expires_at < clock_timestamp() - interval '1 day' LIMIT 1000)",
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
