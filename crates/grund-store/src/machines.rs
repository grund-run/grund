//! Machines, registration tokens and the instance's keys: the rows the
//! machine streams project, and the plain tables that commit beside them.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgConnection, PgExecutor};
use uuid::Uuid;

/// One of the instance's keys: its id, purpose and public half.
#[derive(Debug, Clone, FromRow)]
pub struct KeyRow {
    pub key_id: Uuid,
    pub purpose: String,
    pub organisation_id: Option<Uuid>,
    pub public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// The current key for `purpose` (and organisation, for organisation keys).
pub async fn current_key(
    executor: impl PgExecutor<'_>,
    purpose: &str,
    organisation_id: Option<Uuid>,
) -> Result<Option<KeyRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT key_id, purpose, organisation_id, public_key, created_at FROM grund_keys \
         WHERE purpose = $1 AND organisation_id IS NOT DISTINCT FROM $2 AND retired_at IS NULL",
    )
    .bind(purpose)
    .bind(organisation_id)
    .fetch_optional(executor)
    .await
}

/// Every key not retired, for the check at start.
pub async fn current_keys(executor: impl PgExecutor<'_>) -> Result<Vec<KeyRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT key_id, purpose, organisation_id, public_key, created_at FROM grund_keys \
         WHERE retired_at IS NULL ORDER BY created_at",
    )
    .fetch_all(executor)
    .await
}

/// Records a new current key. Of two racing inserts for one purpose, one
/// fails on `grund_keys_current_idx` or `grund_keys_current_organisation_idx`
/// and the caller reads the winner.
pub async fn insert_key(
    executor: impl PgExecutor<'_>,
    key_id: Uuid,
    purpose: &str,
    organisation_id: Option<Uuid>,
    public_key: &[u8; 32],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_keys (key_id, purpose, organisation_id, public_key) VALUES ($1, $2, $3, $4)",
    )
    .bind(key_id)
    .bind(purpose)
    .bind(organisation_id)
    .bind(&public_key[..])
    .execute(executor)
    .await?;
    Ok(())
}

/// Retires every current key (dev mode, after the throwaway secret changed).
pub async fn retire_all_keys(executor: impl PgExecutor<'_>) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query(
            "UPDATE grund_keys SET retired_at = clock_timestamp() WHERE retired_at IS NULL",
        )
        .execute(executor)
        .await?
        .rows_affected(),
    )
}

/// A token about to be stored.
#[derive(Debug, Clone)]
pub struct NewToken<'a> {
    pub token_id: Uuid,
    pub digest: [u8; 32],
    pub kind: &'a str,
    pub organisation_id: Option<Uuid>,
    pub machine_id: Option<Uuid>,
    pub name: Option<&'a str>,
    pub minted_by: &'a str,
    pub expires_at: DateTime<Utc>,
}

pub async fn insert_token(
    executor: impl PgExecutor<'_>,
    token: &NewToken<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_machine_tokens \
           (token_id, token_digest, kind, organisation_id, machine_id, name, minted_by, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(token.token_id)
    .bind(&token.digest[..])
    .bind(token.kind)
    .bind(token.organisation_id)
    .bind(token.machine_id)
    .bind(token.name)
    .bind(token.minted_by)
    .bind(token.expires_at)
    .execute(executor)
    .await?;
    Ok(())
}

/// How many unused tokens of this pool have not expired at `at`.
pub async fn open_tokens(
    executor: impl PgExecutor<'_>,
    kind: &str,
    organisation_id: Option<Uuid>,
    at: DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_machine_tokens \
         WHERE kind = $1 AND organisation_id IS NOT DISTINCT FROM $2 \
           AND consumed_at IS NULL AND expires_at > $3",
    )
    .bind(kind)
    .bind(organisation_id)
    .bind(at)
    .fetch_one(executor)
    .await
}

/// A stored token.
#[derive(Debug, Clone, FromRow)]
pub struct TokenRow {
    pub token_id: Uuid,
    pub kind: String,
    pub organisation_id: Option<Uuid>,
    pub machine_id: Option<Uuid>,
    pub name: Option<String>,
    pub minted_by: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_key: Option<String>,
    pub consumed_machine_id: Option<Uuid>,
    pub replays: i32,
}

/// The token with this digest, locked until the transaction ends so two
/// registrations with one token queue instead of both consuming it.
pub async fn token_for_update(
    connection: &mut PgConnection,
    digest: &[u8; 32],
) -> Result<Option<TokenRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT token_id, kind, organisation_id, machine_id, name, minted_by, expires_at, \
           consumed_key, consumed_machine_id, replays \
         FROM grund_machine_tokens WHERE token_digest = $1 FOR UPDATE",
    )
    .bind(&digest[..])
    .fetch_optional(connection)
    .await
}

/// Marks the token used by `key` for `machine_id`.
pub async fn consume_token(
    connection: &mut PgConnection,
    token_id: Uuid,
    key_hex: &str,
    machine_id: Uuid,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_machine_tokens SET consumed_at = $2, consumed_key = $3, consumed_machine_id = $4 \
         WHERE token_id = $1 AND consumed_at IS NULL",
    )
    .bind(token_id)
    .bind(at)
    .bind(key_hex)
    .bind(machine_id)
    .execute(connection)
    .await?;
    Ok(())
}

/// Counts one repeated registration with a consumed token.
pub async fn count_replay(
    connection: &mut PgConnection,
    token_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE grund_machine_tokens SET replays = replays + 1 WHERE token_id = $1")
        .bind(token_id)
        .execute(connection)
        .await?;
    Ok(())
}

/// A machine as the read model has it.
#[derive(Debug, Clone, FromRow)]
pub struct MachineRow {
    pub machine_id: Uuid,
    pub pool: String,
    pub home_organisation_id: Option<Uuid>,
    pub name: String,
    pub state: String,
    pub public_key: Option<String>,
    pub lease_id: Option<Uuid>,
    pub lessee_organisation_id: Option<Uuid>,
    pub lessee_slug: Option<String>,
    pub lease_name: Option<String>,
    pub leased_at: Option<DateTime<Utc>>,
    pub pool_organisation_id: Option<Uuid>,
    pub pool_name: Option<String>,
    pub facts: sqlx::types::Json<Value>,
    pub minted_by: String,
    pub registered_at: DateTime<Utc>,
    pub key_registered_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

macro_rules! select_machines {
    ($tail:literal) => {
        concat!(
            "SELECT m.machine_id, m.pool, m.home_organisation_id, m.name, m.state, \
               m.public_key, m.lease_id, m.lessee_organisation_id, o.slug AS lessee_slug, \
               m.lease_name, m.leased_at, m.pool_organisation_id, m.pool_name, m.facts, \
               m.minted_by, m.registered_at, m.key_registered_at, m.revoked_at \
             FROM grund_machines m LEFT JOIN grund_organisations o \
               ON o.organisation_id = m.lessee_organisation_id ",
            $tail
        )
    };
}

pub async fn machine(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
) -> Result<Option<MachineRow>, sqlx::Error> {
    sqlx::query_as(select_machines!("WHERE m.machine_id = $1"))
        .bind(machine_id)
        .fetch_optional(executor)
        .await
}

/// The management pool, newest first, optionally in one state.
pub async fn management_machines(
    executor: impl PgExecutor<'_>,
    state: Option<&str>,
) -> Result<Vec<MachineRow>, sqlx::Error> {
    sqlx::query_as(select_machines!(
        "WHERE m.pool = 'management' AND ($1::text IS NULL OR m.state = $1) \
         ORDER BY m.registered_at DESC, m.machine_id LIMIT 1000"
    ))
    .bind(state)
    .fetch_all(executor)
    .await
}

/// The machines in an organisation's pool now: its own and the ones leased
/// to it, by name.
pub async fn organisation_machines(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<MachineRow>, sqlx::Error> {
    sqlx::query_as(select_machines!(
        "WHERE m.pool_organisation_id = $1 ORDER BY m.pool_name"
    ))
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

/// One machine in an organisation's pool, `None` if it is not in that pool.
pub async fn organisation_machine(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    machine_id: Uuid,
) -> Result<Option<MachineRow>, sqlx::Error> {
    sqlx::query_as(select_machines!(
        "WHERE m.pool_organisation_id = $1 AND m.machine_id = $2"
    ))
    .bind(organisation_id)
    .bind(machine_id)
    .fetch_optional(executor)
    .await
}

/// How many machines are in an organisation's pool now.
pub async fn count_organisation_machines(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM grund_machines WHERE pool_organisation_id = $1")
        .bind(organisation_id)
        .fetch_one(executor)
        .await
}

/// Whether the organisation exists and is not deleted.
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
