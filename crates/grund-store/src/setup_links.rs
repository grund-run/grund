//! The first owner's setup link: minted on the instance's machine, valid only
//! before any account exists. On a `multi` instance its redemption also
//! creates the operator organisation. Only a keyed token digest is stored.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor, PgPool};
use uuid::Uuid;

/// How minting a link ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Minted {
    /// Stored; valid until the time given.
    Issued(DateTime<Utc>),
    /// An account exists, so the instance has its owner.
    AccountsExist,
}

/// Stores a new link, valid for `ttl`, and deletes every unused one, unless
/// any account exists. One transaction, serialised against other minting by
/// an advisory lock, so two commands run at once still leave one live link.
pub async fn mint(
    pool: &PgPool,
    token_digest: &[u8; 32],
    ttl: Duration,
) -> Result<Minted, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('grund:setup-link'))")
        .execute(&mut *tx)
        .await?;
    if any_account(&mut *tx).await? {
        return Ok(Minted::AccountsExist);
    }
    sqlx::query("DELETE FROM grund_setup_links WHERE used_at IS NULL")
        .execute(&mut *tx)
        .await?;
    let expires_at = sqlx::query_scalar::<_, DateTime<Utc>>(
        "INSERT INTO grund_setup_links (token_digest, expires_at) \
         VALUES ($1, clock_timestamp() + make_interval(secs => $2)) RETURNING expires_at",
    )
    .bind(&token_digest[..])
    .bind(ttl.as_secs_f64())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Minted::Issued(expires_at))
}

/// Whether a link is still good, without using it (for the page it opens):
/// known, unused, unexpired, and no account exists yet.
pub async fn is_live(
    executor: impl PgExecutor<'_>,
    token_digest: &[u8; 32],
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM grund_setup_links \
         WHERE token_digest = $1 AND used_at IS NULL AND expires_at > clock_timestamp()) \
         AND NOT EXISTS (SELECT 1 FROM grund_accounts)",
    )
    .bind(&token_digest[..])
    .fetch_one(executor)
    .await
}

/// Uses a link for `account_id`, inside the transaction that creates that
/// account. `false` when it is unknown, used or expired, or when an account
/// already exists. A concurrent use of the same link waits on the row and
/// then finds it used.
pub async fn redeem(
    connection: &mut PgConnection,
    token_digest: &[u8; 32],
    account_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('grund:setup-link'))")
        .execute(&mut *connection)
        .await?;
    let used = sqlx::query(
        "UPDATE grund_setup_links SET used_at = clock_timestamp(), account_id = $2 \
         WHERE token_digest = $1 AND used_at IS NULL AND expires_at > clock_timestamp()",
    )
    .bind(&token_digest[..])
    .bind(account_id)
    .execute(&mut *connection)
    .await?
    .rows_affected()
        == 1;
    Ok(used && !any_account(&mut *connection).await?)
}

/// The account and home organisation created by the successfully redeemed setup link.
pub async fn claimed_owner(
    executor: impl PgExecutor<'_>,
) -> Result<Option<(Uuid, Uuid)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.account_id, a.organisation_id FROM grund_setup_links s \
         JOIN grund_accounts a ON a.account_id = s.account_id \
         JOIN grund_organisations o ON o.organisation_id = a.organisation_id \
         WHERE s.used_at IS NOT NULL AND o.deleted_at IS NULL",
    )
    .fetch_optional(executor)
    .await
}

/// Whether any account already exists, including an unverified sign-up.
pub async fn any_account(executor: impl PgExecutor<'_>) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM grund_accounts)")
        .fetch_one(executor)
        .await
}
