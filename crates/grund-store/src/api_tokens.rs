//! Personal access tokens for the Connect API (grund-docs design/auth.md
//! §6). Only the SHA-256 of a token is stored; expiry and revocation are
//! enforced by every read.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// A new token to store.
pub struct NewToken<'a> {
    pub organisation_id: Uuid,
    pub token_id: Uuid,
    pub token_digest: &'a [u8; 32],
    pub account_id: Uuid,
    pub name: &'a str,
    pub lifetime_days: u32,
    /// `deploy` or `full` (design/auth.md §6).
    pub scope: &'a str,
}

/// Stores a token unless the organisation already has `max_live` live ones,
/// counted under a lock on the organisation's row so two creations cannot
/// both take the last place. `None` when it is full. Returns when it
/// expires.
pub async fn insert(
    connection: &mut PgConnection,
    token: NewToken<'_>,
    max_live: i64,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    sqlx::query("SELECT 1 FROM grund_organisations WHERE organisation_id = $1 FOR UPDATE")
        .bind(token.organisation_id)
        .execute(&mut *connection)
        .await?;
    sqlx::query_scalar::<_, DateTime<Utc>>(
        "INSERT INTO grund_api_tokens \
           (organisation_id, token_id, token_digest, account_id, name, expires_at, scope) \
         SELECT $1, $2, $3, $4, $5, clock_timestamp() + make_interval(days => $6), $8 \
         WHERE (SELECT count(*) FROM grund_api_tokens \
                WHERE organisation_id = $1 AND revoked_at IS NULL \
                  AND expires_at > clock_timestamp()) < $7 \
         RETURNING expires_at",
    )
    .bind(token.organisation_id)
    .bind(token.token_id)
    .bind(&token.token_digest[..])
    .bind(token.account_id)
    .bind(token.name)
    .bind(token.lifetime_days as i32)
    .bind(max_live)
    .bind(token.scope)
    .fetch_optional(connection)
    .await
}

/// A live token, found by its digest.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LiveToken {
    pub organisation_id: Uuid,
    pub token_id: Uuid,
    pub account_id: Uuid,
    pub scope: String,
}

/// The live token a digest names: not revoked and not expired. Notes its
/// use, at most once a minute per token, in the same statement.
pub async fn authenticate(
    executor: impl PgExecutor<'_>,
    token_digest: &[u8; 32],
) -> Result<Option<LiveToken>, sqlx::Error> {
    sqlx::query_as::<_, LiveToken>(
        "WITH live AS ( \
           SELECT organisation_id, token_id, account_id, scope, last_used_at FROM grund_api_tokens \
           WHERE token_digest = $1 AND revoked_at IS NULL AND expires_at > clock_timestamp()), \
         touched AS ( \
           UPDATE grund_api_tokens t SET last_used_at = clock_timestamp() FROM live \
           WHERE t.organisation_id = live.organisation_id AND t.token_id = live.token_id \
             AND (live.last_used_at IS NULL \
                  OR live.last_used_at < clock_timestamp() - interval '1 minute')) \
         SELECT organisation_id, token_id, account_id, scope FROM live",
    )
    .bind(&token_digest[..])
    .fetch_optional(executor)
    .await
}

/// One of an organisation's live tokens, for the tokens page.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TokenView {
    pub token_id: Uuid,
    pub name: String,
    pub account_id: Uuid,
    pub username: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub scope: String,
}

/// The organisation's live tokens, newest first; only `account_id`'s when it
/// is given.
pub async fn list(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    account_id: Option<Uuid>,
) -> Result<Vec<TokenView>, sqlx::Error> {
    sqlx::query_as::<_, TokenView>(
        "SELECT t.token_id, t.name, t.account_id, a.username, t.created_at, t.expires_at, \
                t.last_used_at, t.scope \
         FROM grund_api_tokens t LEFT JOIN grund_accounts a ON a.account_id = t.account_id \
         WHERE t.organisation_id = $1 AND t.revoked_at IS NULL \
           AND t.expires_at > clock_timestamp() \
           AND ($2::uuid IS NULL OR t.account_id = $2) \
         ORDER BY t.created_at DESC LIMIT 200",
    )
    .bind(organisation_id)
    .bind(account_id)
    .fetch_all(executor)
    .await
}

/// Revokes one of the organisation's live tokens, only `account_id`'s when
/// it is given. `false` when there is no such token, which includes another
/// organisation's.
pub async fn revoke(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    token_id: Uuid,
    account_id: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_api_tokens SET revoked_at = clock_timestamp() \
         WHERE organisation_id = $1 AND token_id = $2 AND revoked_at IS NULL \
           AND expires_at > clock_timestamp() AND ($3::uuid IS NULL OR account_id = $3)",
    )
    .bind(organisation_id)
    .bind(token_id)
    .bind(account_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// One live token of the organisation, by id.
pub async fn get(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    token_id: Uuid,
) -> Result<Option<TokenView>, sqlx::Error> {
    sqlx::query_as::<_, TokenView>(
        "SELECT t.token_id, t.name, t.account_id, a.username, t.created_at, t.expires_at, \
                t.last_used_at, t.scope \
         FROM grund_api_tokens t LEFT JOIN grund_accounts a ON a.account_id = t.account_id \
         WHERE t.organisation_id = $1 AND t.token_id = $2 AND t.revoked_at IS NULL \
           AND t.expires_at > clock_timestamp()",
    )
    .bind(organisation_id)
    .bind(token_id)
    .fetch_optional(executor)
    .await
}

/// Deletes tokens that ended more than a day ago. Bounded per pass.
pub async fn sweep(executor: impl PgExecutor<'_>) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM grund_api_tokens WHERE (organisation_id, token_id) IN ( \
           SELECT organisation_id, token_id FROM grund_api_tokens \
           WHERE expires_at < clock_timestamp() - interval '1 day' \
              OR revoked_at < clock_timestamp() - interval '1 day' \
           LIMIT 1000)",
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
