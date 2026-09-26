//! Reads of machines, and the one-time enrollment tokens they enroll with
//! (grund/fleet docs/design/enrollment-contract.md). Tokens are kept as their
//! SHA-256 only.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// A machine as its organisation's members see it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MachineRow {
    pub machine_id: Uuid,
    pub organisation_id: Uuid,
    pub name: String,
    pub public_key: String,
    pub minted_by: String,
    pub facts: sqlx::types::Json<serde_json::Value>,
    pub enrolled_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A token about to be minted.
pub struct NewToken<'a> {
    pub token_digest: &'a [u8; 32],
    pub organisation_id: Uuid,
    pub machine_name: Option<&'a str>,
    pub minted_by: &'a str,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A token as enrollment sees it, locked for the call.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TokenRow {
    pub organisation_id: Uuid,
    pub machine_name: Option<String>,
    pub minted_by: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub machine_id: Option<Uuid>,
    pub public_key: Option<String>,
    pub uses: i32,
}

pub async fn insert_token(
    executor: impl PgExecutor<'_>,
    token: &NewToken<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_enrollment_tokens \
           (token_digest, organisation_id, machine_name, minted_by, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&token.token_digest[..])
    .bind(token.organisation_id)
    .bind(token.machine_name)
    .bind(token.minted_by)
    .bind(token.created_at)
    .bind(token.expires_at)
    .execute(executor)
    .await?;
    Ok(())
}

/// Tokens of the organisation that are neither used nor expired at `at`.
pub async fn open_tokens(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    at: DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_enrollment_tokens \
         WHERE organisation_id = $1 AND consumed_at IS NULL AND expires_at > $2",
    )
    .bind(organisation_id)
    .bind(at)
    .fetch_one(executor)
    .await
}

/// Counts one call naming the token, committed on its own so a refused call
/// still counts, and returns the count. `None` when no such token exists.
pub async fn count_use(
    executor: impl PgExecutor<'_>,
    token_digest: &[u8; 32],
) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE grund_enrollment_tokens SET uses = uses + 1 WHERE token_digest = $1 RETURNING uses",
    )
    .bind(&token_digest[..])
    .fetch_optional(executor)
    .await
}

/// The token, locked until the transaction ends, so two calls with one
/// token are decided one after the other.
pub async fn lock_token(
    connection: &mut PgConnection,
    token_digest: &[u8; 32],
) -> Result<Option<TokenRow>, sqlx::Error> {
    sqlx::query_as::<_, TokenRow>(
        "SELECT organisation_id, machine_name, minted_by, expires_at, consumed_at, \
                machine_id, public_key, uses \
         FROM grund_enrollment_tokens WHERE token_digest = $1 FOR UPDATE",
    )
    .bind(&token_digest[..])
    .fetch_optional(connection)
    .await
}

/// Marks the token used by `machine_id` with `public_key`.
pub async fn consume_token(
    connection: &mut PgConnection,
    token_digest: &[u8; 32],
    machine_id: Uuid,
    public_key: &str,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_enrollment_tokens SET consumed_at = $2, machine_id = $3, public_key = $4 \
         WHERE token_digest = $1 AND consumed_at IS NULL",
    )
    .bind(&token_digest[..])
    .bind(at)
    .bind(machine_id)
    .bind(public_key)
    .execute(connection)
    .await?;
    Ok(())
}

/// Whether an organisation still exists (a deleted one keeps its row with
/// `deleted_at` set).
pub async fn organisation_live(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_organisations \
                        WHERE organisation_id = $1 AND deleted_at IS NULL)",
    )
    .bind(organisation_id)
    .fetch_one(executor)
    .await
}

/// Whether a machine of the organisation that is not revoked has `name`.
pub async fn name_taken(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    name: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_machines \
                        WHERE organisation_id = $1 AND name = $2 AND revoked_at IS NULL)",
    )
    .bind(organisation_id)
    .bind(name)
    .fetch_one(executor)
    .await
}

const COLUMNS: &str = "machine_id, organisation_id, name, public_key, minted_by, facts, \
                       enrolled_at, revoked_at";

/// The organisation's machines, enrolled first first.
pub async fn list(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<MachineRow>, sqlx::Error> {
    sqlx::query_as::<_, MachineRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM grund_machines WHERE organisation_id = $1 \
         ORDER BY enrolled_at, machine_id"
    )))
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

/// The machine, if it belongs to the organisation. `None` both when it does
/// not exist and when it is another organisation's.
pub async fn get(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    machine_id: Uuid,
) -> Result<Option<MachineRow>, sqlx::Error> {
    sqlx::query_as::<_, MachineRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM grund_machines WHERE organisation_id = $1 AND machine_id = $2"
    )))
    .bind(organisation_id)
    .bind(machine_id)
    .fetch_optional(executor)
    .await
}

/// Deletes tokens that expired more than a day ago. Bounded per pass.
pub async fn sweep(executor: impl PgExecutor<'_>) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM grund_enrollment_tokens WHERE token_digest IN ( \
           SELECT token_digest FROM grund_enrollment_tokens \
           WHERE expires_at < clock_timestamp() - interval '1 day' LIMIT 1000)",
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
