//! Private networks and their slots (grund-docs design/network.md §5, §6):
//! one network per organisation, the newest signed membership list as sent,
//! and which machine holds which /64.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgConnection, PgExecutor};
use uuid::Uuid;

/// A network, with its newest signed list.
#[derive(Debug, Clone, FromRow)]
pub struct NetworkRow {
    pub network_id: Uuid,
    pub organisation_id: Uuid,
    pub prefix: String,
    pub key_id: Uuid,
    pub epoch: i64,
    pub body: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub issued_at: Option<DateTime<Utc>>,
}

macro_rules! select_network {
    ($tail:literal) => {
        concat!(
            "SELECT network_id, organisation_id, prefix, key_id, epoch, body, signature, issued_at \
             FROM grund_networks ",
            $tail
        )
    };
}

/// The organisation's network, without a lock.
pub async fn organisation_network(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Option<NetworkRow>, sqlx::Error> {
    sqlx::query_as(select_network!("WHERE organisation_id = $1"))
        .bind(organisation_id)
        .fetch_optional(executor)
        .await
}

/// The organisation's network, locked until the transaction ends, so two
/// changes to one network's membership queue and each gets its own epoch.
pub async fn lock_organisation_network(
    connection: &mut PgConnection,
    organisation_id: Uuid,
) -> Result<Option<NetworkRow>, sqlx::Error> {
    sqlx::query_as(select_network!("WHERE organisation_id = $1 FOR UPDATE"))
        .bind(organisation_id)
        .fetch_optional(connection)
        .await
}

/// Records a new network, unless the organisation has one or the prefix is
/// taken; `false` then, and the caller reads or retries.
pub async fn insert_network(
    executor: impl PgExecutor<'_>,
    network_id: Uuid,
    organisation_id: Uuid,
    prefix: &str,
    key_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let inserted = sqlx::query(
        "INSERT INTO grund_networks (network_id, organisation_id, prefix, key_id) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(network_id)
    .bind(organisation_id)
    .bind(prefix)
    .bind(key_id)
    .execute(executor)
    .await?;
    Ok(inserted.rows_affected() == 1)
}

/// Stores the network's newly signed list.
pub async fn store_list(
    executor: impl PgExecutor<'_>,
    network_id: Uuid,
    epoch: i64,
    body: &[u8],
    signature: &[u8; 64],
    issued_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_networks SET epoch = $2, body = $3, signature = $4, issued_at = $5 \
         WHERE network_id = $1",
    )
    .bind(network_id)
    .bind(epoch)
    .bind(body)
    .bind(&signature[..])
    .bind(issued_at)
    .execute(executor)
    .await?;
    Ok(())
}

/// A slot as stored: held while `freed_at` is empty, and for a while after.
#[derive(Debug, Clone, FromRow)]
pub struct SlotRow {
    pub slot: i32,
    pub machine_id: Uuid,
    pub endpoint_id: String,
    pub freed_at: Option<DateTime<Utc>>,
}

/// Every slot the network has ever given out, one row per slot.
pub async fn slots(
    executor: impl PgExecutor<'_>,
    network_id: Uuid,
) -> Result<Vec<SlotRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT slot, machine_id, endpoint_id, freed_at FROM grund_network_slots \
         WHERE network_id = $1 ORDER BY slot",
    )
    .bind(network_id)
    .fetch_all(executor)
    .await
}

/// Gives `slot` to a machine, taking over the row of whoever held it last.
pub async fn assign_slot(
    executor: impl PgExecutor<'_>,
    network_id: Uuid,
    slot: i32,
    machine_id: Uuid,
    endpoint_id: &str,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_network_slots (network_id, slot, machine_id, endpoint_id, assigned_at) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (network_id, slot) DO UPDATE SET machine_id = EXCLUDED.machine_id, \
           endpoint_id = EXCLUDED.endpoint_id, assigned_at = EXCLUDED.assigned_at, freed_at = NULL",
    )
    .bind(network_id)
    .bind(slot)
    .bind(machine_id)
    .bind(endpoint_id)
    .bind(at)
    .execute(executor)
    .await?;
    Ok(())
}

/// Records that the member in `slot` has a new key.
pub async fn rekey_slot(
    executor: impl PgExecutor<'_>,
    network_id: Uuid,
    slot: i32,
    endpoint_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_network_slots SET endpoint_id = $3 WHERE network_id = $1 AND slot = $2",
    )
    .bind(network_id)
    .bind(slot)
    .bind(endpoint_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Frees `slot`; it stays held until the hold ends.
pub async fn free_slot(
    executor: impl PgExecutor<'_>,
    network_id: Uuid,
    slot: i32,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE grund_network_slots SET freed_at = $3 WHERE network_id = $1 AND slot = $2")
        .bind(network_id)
        .bind(slot)
        .bind(at)
        .execute(executor)
        .await?;
    Ok(())
}

/// A machine that belongs on the organisation's network: in its pool (its
/// own or leased to it), not revoked, with a key.
#[derive(Debug, Clone, FromRow)]
pub struct CandidateRow {
    pub machine_id: Uuid,
    pub public_key: String,
}

pub async fn candidates(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<CandidateRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT machine_id, public_key FROM grund_machines \
         WHERE pool_organisation_id = $1 AND state IN ('active', 'leased') \
           AND public_key IS NOT NULL ORDER BY registered_at, machine_id",
    )
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}
