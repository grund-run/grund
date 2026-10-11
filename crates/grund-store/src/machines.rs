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

/// Whether `public_key` (lowercase hex) is the current key of a registered
/// machine. A revoked machine's key is cleared, so it is not.
pub async fn key_is_current(
    executor: impl PgExecutor<'_>,
    public_key: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM grund_machines WHERE public_key = $1)")
        .bind(public_key)
        .fetch_one(executor)
        .await
}

/// Which of `public_keys` (lowercase hex) are the current key of a
/// registered machine.
pub async fn current_keys_among(
    executor: impl PgExecutor<'_>,
    public_keys: &[String],
) -> Result<std::collections::HashSet<String>, sqlx::Error> {
    let found: Vec<String> =
        sqlx::query_scalar("SELECT public_key FROM grund_machines WHERE public_key = ANY($1)")
            .bind(public_keys)
            .fetch_all(executor)
            .await?;
    Ok(found.into_iter().collect())
}

/// Which of `public_keys` (lowercase hex) a relay of this instance may
/// admit: the current key of a registered machine, the instance's own key
/// while it is not retired, or the key of an active `grund edge`, which
/// reaches machines behind NAT through the relay (traffic.md §6.4).
pub async fn relay_keys_among(
    executor: impl PgExecutor<'_>,
    public_keys: &[String],
) -> Result<std::collections::HashSet<String>, sqlx::Error> {
    let found: Vec<String> = sqlx::query_scalar(
        "SELECT public_key FROM grund_machines WHERE public_key = ANY($1) \
         UNION \
         SELECT encode(public_key, 'hex') FROM grund_keys \
         WHERE purpose = 'instance' AND retired_at IS NULL \
           AND encode(public_key, 'hex') = ANY($1) \
         UNION \
         SELECT encode(public_key, 'hex') FROM grund_relays \
         WHERE role = 'edge' AND state = 'active' AND encode(public_key, 'hex') = ANY($1)",
    )
    .bind(public_keys)
    .fetch_all(executor)
    .await?;
    Ok(found.into_iter().collect())
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

/// Records a new current key, unless one already exists for the purpose (and
/// organisation): of two racing inserts one wins, and the caller reads it.
/// Nothing fails, so this is safe inside a larger transaction.
pub async fn insert_key(
    executor: impl PgExecutor<'_>,
    key_id: Uuid,
    purpose: &str,
    organisation_id: Option<Uuid>,
    public_key: &[u8; 32],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_keys (key_id, purpose, organisation_id, public_key) VALUES ($1, $2, $3, $4) \
         ON CONFLICT DO NOTHING",
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
    pub vm_id: Option<Uuid>,
}

pub async fn insert_token(
    executor: impl PgExecutor<'_>,
    token: &NewToken<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_machine_tokens \
           (token_id, token_digest, kind, organisation_id, machine_id, name, minted_by, expires_at, vm_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(token.token_id)
    .bind(&token.digest[..])
    .bind(token.kind)
    .bind(token.organisation_id)
    .bind(token.machine_id)
    .bind(token.name)
    .bind(token.minted_by)
    .bind(token.expires_at)
    .bind(token.vm_id)
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
    pub provider_machine_id: Option<String>,
    pub vm_id: Option<Uuid>,
    pub hosted_size: Option<String>,
    pub hosted_region: Option<String>,
}

/// The token with this digest, locked until the transaction ends so two
/// registrations with one token queue instead of both consuming it.
pub async fn token_for_update(
    connection: &mut PgConnection,
    digest: &[u8; 32],
) -> Result<Option<TokenRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT token_id, kind, organisation_id, machine_id, name, minted_by, expires_at, \
           consumed_key, consumed_machine_id, replays, provider_machine_id, vm_id, hosted_size, hosted_region \
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

/// The token with this id, locked until the transaction ends: the provider's
/// answer and the machine's registration queue on it, so whichever comes
/// second sees the first.
pub async fn token_by_id_for_update(
    connection: &mut PgConnection,
    token_id: Uuid,
) -> Result<Option<TokenRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT token_id, kind, organisation_id, machine_id, name, minted_by, expires_at, \
           consumed_key, consumed_machine_id, replays, provider_machine_id, vm_id, hosted_size, hosted_region \
         FROM grund_machine_tokens WHERE token_id = $1 FOR UPDATE",
    )
    .bind(token_id)
    .fetch_optional(connection)
    .await
}

/// Records the capacity provider's id for the machine a token was minted to
/// provision, as the provider answered it.
pub async fn set_token_provider(
    executor: impl PgExecutor<'_>,
    token_id: Uuid,
    provider_machine_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE grund_machine_tokens SET provider_machine_id = $2 WHERE token_id = $1")
        .bind(token_id)
        .bind(provider_machine_id)
        .execute(executor)
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
    pub provider_machine_id: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub capabilities: Option<sqlx::types::Json<Value>>,
    pub network_ports: sqlx::types::Json<Vec<grund_domain::machine::NetworkPort>>,
    pub labels: sqlx::types::Json<grund_domain::labels::Labels>,
    pub cordoned_at: Option<DateTime<Utc>>,
    pub hosted_size: Option<String>,
    pub hosted_region: Option<String>,
}

macro_rules! select_machines {
    ($tail:literal) => {
        concat!(
            "SELECT m.machine_id, m.pool, m.home_organisation_id, m.name, m.state, \
               m.public_key, m.lease_id, m.lessee_organisation_id, o.slug AS lessee_slug, \
               m.lease_name, m.leased_at, m.pool_organisation_id, m.pool_name, m.facts, \
               m.minted_by, m.registered_at, m.key_registered_at, m.revoked_at, \
               m.provider_machine_id, p.last_seen_at, p.capabilities, m.network_ports, \
               m.labels, m.cordoned_at, m.hosted_size, m.hosted_region \
             FROM grund_machines m LEFT JOIN grund_organisations o \
               ON o.organisation_id = m.lessee_organisation_id \
             LEFT JOIN grund_machine_presence p ON p.machine_id = m.machine_id ",
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
        "WHERE m.pool_organisation_id = $1 \
         AND (m.machine_id = $2 OR (m.pool = 'management' AND m.lease_id = $2))"
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

/// The organisation with this current slug, if it is not deleted.
pub async fn live_organisation_by_slug(
    executor: impl PgExecutor<'_>,
    slug: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT organisation_id FROM grund_organisations WHERE slug = $1 AND deleted_at IS NULL",
    )
    .bind(slug)
    .fetch_optional(executor)
    .await
}

/// The account's role in the organisation, if it is a member.
pub async fn role_in(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    account_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT role FROM grund_memberships WHERE organisation_id = $1 AND account_id = $2",
    )
    .bind(organisation_id)
    .bind(account_id)
    .fetch_optional(executor)
    .await
}

/// Whether an organisation has an explicit hosted-machine grant.
pub async fn hosted_enabled(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_hosted_entitlements \
         WHERE organisation_id = $1 AND enabled)",
    )
    .bind(organisation_id)
    .fetch_one(executor)
    .await
}

/// Grants or withdraws hosted-machine access for a live organisation.
pub async fn grant_hosted(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    enabled: bool,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query_scalar::<_, bool>(
        "WITH live AS (SELECT organisation_id FROM grund_organisations \
         WHERE organisation_id = $1 AND deleted_at IS NULL FOR UPDATE) \
         INSERT INTO grund_hosted_entitlements (organisation_id, enabled) \
         SELECT organisation_id, $2 FROM live \
         ON CONFLICT (organisation_id) DO UPDATE SET enabled = EXCLUDED.enabled, \
         updated_at = clock_timestamp() RETURNING enabled",
    )
    .bind(organisation_id)
    .bind(enabled)
    .fetch_optional(executor)
    .await?
    .is_some())
}

/// A customer's pending or active hosted machine.
#[derive(Debug, Clone, FromRow)]
pub struct HostedOrder {
    pub organisation_id: Uuid,
    pub order_id: Uuid,
    pub name: String,
    pub size: String,
    pub region: String,
    pub token_id: Option<Uuid>,
    pub machine_id: Option<Uuid>,
    pub status: String,
    pub idempotency_key: Option<String>,
}

/// The hosted machines belonging to exactly this organisation.
pub async fn hosted_orders(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<HostedOrder>, sqlx::Error> {
    sqlx::query_as(
        "SELECT organisation_id, order_id, name, size, region, token_id, machine_id, status, idempotency_key \
         FROM grund_hosted_orders WHERE organisation_id = $1 AND status IN ('joining', 'active', 'failed') \
         ORDER BY created_at, order_id",
    )
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

/// Historical leases used only to hide physical machine IDs on VM responses.
pub async fn hosted_vm_orders(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<(Uuid, Uuid, DateTime<Utc>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT order_id, machine_id, created_at FROM grund_hosted_orders \
         WHERE organisation_id = $1 AND machine_id IS NOT NULL \
         UNION ALL \
         SELECT lease_id, machine_id, leased_at FROM grund_hosted_manual_leases \
         WHERE organisation_id = $1 \
         ORDER BY created_at DESC, order_id DESC",
    )
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

/// Preserves the public ID of an operator-issued management lease after removal.
pub async fn record_hosted_manual_lease(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    machine_id: Uuid,
    lease_id: Uuid,
    leased_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_hosted_manual_leases \
           (organisation_id, machine_id, lease_id, leased_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(organisation_id)
    .bind(machine_id)
    .bind(lease_id)
    .bind(leased_at)
    .execute(executor)
    .await?;
    Ok(())
}

/// Locks a customer's order for removal without exposing another organisation's order.
pub async fn hosted_order_for_update(
    connection: &mut PgConnection,
    organisation_id: Uuid,
    order_id: Uuid,
) -> Result<Option<HostedOrder>, sqlx::Error> {
    sqlx::query_as(
        "SELECT organisation_id, order_id, name, size, region, token_id, machine_id, status, idempotency_key \
         FROM grund_hosted_orders WHERE organisation_id = $1 AND order_id = $2 \
         AND status IN ('joining', 'active', 'failed') FOR UPDATE",
    )
    .bind(organisation_id)
    .bind(order_id)
    .fetch_optional(connection)
    .await
}

/// Records the selected offer on a registration token, for subsequent leasing.
pub async fn set_hosted_token_size(
    executor: impl PgExecutor<'_>,
    token_id: Uuid,
    size: &str,
    region: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_machine_tokens SET hosted_size = $2, hosted_region = $3 WHERE token_id = $1",
    )
    .bind(token_id)
    .bind(size)
    .bind(region)
    .execute(executor)
    .await?;
    Ok(())
}

/// A pending order bound to a token; the caller holds that token's row lock.
pub async fn pending_hosted_token(
    executor: impl PgExecutor<'_>,
    token_id: Uuid,
) -> Result<Option<HostedOrder>, sqlx::Error> {
    sqlx::query_as(
        "SELECT organisation_id, order_id, name, size, region, token_id, machine_id, status, idempotency_key \
         FROM grund_hosted_orders WHERE token_id = $1 AND status = 'joining'",
    )
    .bind(token_id)
    .fetch_optional(executor)
    .await
}

/// Selects a suitable unleased ready machine under a row lock.
pub async fn ready_hosted_machine(
    connection: &mut PgConnection,
    size: &str,
    region: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT machine_id FROM grund_machines \
         WHERE pool = 'management' AND state = 'available' AND public_key IS NOT NULL \
           AND hosted_size = $1 AND hosted_region = $2 \
         ORDER BY registered_at, machine_id FOR UPDATE SKIP LOCKED LIMIT 1",
    )
    .bind(size)
    .bind(region)
    .fetch_optional(connection)
    .await
}

/// A hosted order persisted before provisioning or after claiming a warm machine.
pub struct NewHostedOrder<'a> {
    pub organisation_id: Uuid,
    pub order_id: Uuid,
    pub name: &'a str,
    pub size: &'a str,
    pub region: &'a str,
    pub idempotency_key: &'a str,
    pub token_id: Option<Uuid>,
    pub machine_id: Option<Uuid>,
    pub status: &'a str,
}

/// Creates a durable customer request before a provider is called.
pub async fn insert_hosted_order(
    executor: impl PgExecutor<'_>,
    order: NewHostedOrder<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_hosted_orders \
           (organisation_id, order_id, name, size, region, token_id, machine_id, status, idempotency_key) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(order.organisation_id)
    .bind(order.order_id)
    .bind(order.name)
    .bind(order.size)
    .bind(order.region)
    .bind(order.token_id)
    .bind(order.machine_id)
    .bind(order.status)
    .bind(order.idempotency_key)
    .execute(executor)
    .await?;
    Ok(())
}

/// Moves an order to its committed state.
pub async fn set_hosted_order(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    order_id: Uuid,
    status: &str,
    machine_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_hosted_orders SET status = $3, machine_id = COALESCE($4, machine_id), \
           leased_until = NULL, \
           next_attempt_at = CASE WHEN $3 = 'removed' THEN clock_timestamp() + interval '30 seconds' ELSE next_attempt_at END, \
           cancelled_at = CASE WHEN $3 IN ('removed', 'failed', 'refused') THEN clock_timestamp() ELSE cancelled_at END \
         WHERE organisation_id = $1 AND order_id = $2",
    )
    .bind(organisation_id)
    .bind(order_id)
    .bind(status)
    .bind(machine_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Records sizing when a management machine first registers.
pub async fn set_machine_hosted_size(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
    size: &str,
    region: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_machines SET hosted_size = $2, hosted_region = $3 \
         WHERE machine_id = $1 AND pool = 'management'",
    )
    .bind(machine_id)
    .bind(size)
    .bind(region)
    .execute(executor)
    .await?;
    Ok(())
}

/// Looks up a customer's retry key, including terminal responses.
pub async fn hosted_order_by_key(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    key: &str,
) -> Result<Option<HostedOrder>, sqlx::Error> {
    sqlx::query_as(
        "SELECT organisation_id, order_id, name, size, region, token_id, machine_id, status, idempotency_key \
         FROM grund_hosted_orders WHERE organisation_id = $1 AND idempotency_key = $2",
    )
    .bind(organisation_id)
    .bind(key)
    .fetch_optional(executor)
    .await
}

/// Checks a currently registered machine's customer-visible name.
pub async fn organisation_name_taken(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    name: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_machines \
         WHERE pool_organisation_id = $1 AND pool_name = $2)",
    )
    .bind(organisation_id)
    .bind(name)
    .fetch_one(executor)
    .await
}

/// Invalidates a token that was not accepted by the provider.
pub async fn expire_hosted_token(
    executor: impl PgExecutor<'_>,
    token_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_machine_tokens SET expires_at = clock_timestamp() \
         WHERE token_id = $1 AND consumed_at IS NULL",
    )
    .bind(token_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Reconciles size and region for existing provider machines without guessing from hardware.
pub async fn reconcile_hosted_sizes(
    executor: impl PgExecutor<'_>,
    inventory: &[(String, String, String)],
) -> Result<(), sqlx::Error> {
    if inventory.is_empty() {
        return Ok(());
    }
    let ids: Vec<&str> = inventory.iter().map(|(id, _, _)| id.as_str()).collect();
    let sizes: Vec<&str> = inventory.iter().map(|(_, size, _)| size.as_str()).collect();
    let regions: Vec<&str> = inventory
        .iter()
        .map(|(_, _, region)| region.as_str())
        .collect();
    sqlx::query(
        "UPDATE grund_machines m SET hosted_size = data.size, hosted_region = data.region \
         FROM unnest($1::text[], $2::text[], $3::text[]) AS data(id, size, region) \
         WHERE m.provider_machine_id = data.id AND m.pool = 'management' \
           AND m.hosted_size IS NULL AND m.hosted_region IS NULL",
    )
    .bind(ids)
    .bind(sizes)
    .bind(regions)
    .execute(executor)
    .await?;
    Ok(())
}

/// Whether a registered ready machine fits an exact offer.
pub async fn ready_hosted_count(
    executor: impl PgExecutor<'_>,
    size: &str,
    region: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_machines WHERE pool = 'management' \
         AND state = 'available' AND public_key IS NOT NULL \
         AND hosted_size = $1 AND hosted_region = $2",
    )
    .bind(size)
    .bind(region)
    .fetch_one(executor)
    .await
}

/// Serialises quota decisions for one organisation across concurrent orders.
pub async fn lock_hosted_organisation(
    connection: &mut PgConnection,
    organisation_id: Uuid,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        "SELECT organisation_id FROM grund_organisations \
         WHERE organisation_id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(organisation_id)
    .fetch_optional(connection)
    .await?
    .is_some())
}

/// The registered provider assignment attached to a hosted token, if known.
pub async fn hosted_token_provider(
    executor: impl PgExecutor<'_>,
    token_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT provider_machine_id FROM grund_machine_tokens WHERE token_id = $1")
        .bind(token_id)
        .fetch_optional(executor)
        .await
        .map(Option::flatten)
}

/// An order by token, including one removed while its provider call was running.
pub async fn hosted_order_by_token(
    executor: impl PgExecutor<'_>,
    token_id: Uuid,
) -> Result<Option<HostedOrder>, sqlx::Error> {
    sqlx::query_as(
        "SELECT organisation_id, order_id, name, size, region, token_id, machine_id, status, idempotency_key \
         FROM grund_hosted_orders WHERE token_id = $1",
    )
    .bind(token_id)
    .fetch_optional(executor)
    .await
}

/// Expiry of a hosted registration token for retrying one uncertain call.
pub async fn hosted_token_expiry(
    executor: impl PgExecutor<'_>,
    token_id: Uuid,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    sqlx::query_scalar("SELECT expires_at FROM grund_machine_tokens WHERE token_id = $1")
        .bind(token_id)
        .fetch_optional(executor)
        .await
}

/// Allows a new provider call only while the token and pending order are live.
pub async fn hosted_token_provisionable(
    executor: impl PgExecutor<'_>,
    token_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_hosted_orders o \
         JOIN grund_machine_tokens t ON t.token_id = o.token_id \
         WHERE o.token_id = $1 AND o.status = 'joining' AND t.expires_at > clock_timestamp())",
    )
    .bind(token_id)
    .fetch_one(executor)
    .await
}

/// Claims one due unresolved order, committing the claim before provider I/O.
pub async fn claim_hosted_recovery(
    executor: impl PgExecutor<'_>,
) -> Result<Option<HostedOrder>, sqlx::Error> {
    sqlx::query_as(
        "WITH claim AS (SELECT o.organisation_id, o.order_id FROM grund_hosted_orders o \
         JOIN grund_machine_tokens t ON t.token_id = o.token_id \
         WHERE o.status IN ('joining', 'active') AND o.token_id IS NOT NULL \
           AND (t.provider_machine_id IS NULL OR o.status = 'joining') \
           AND o.next_attempt_at <= clock_timestamp() \
           AND (o.leased_until IS NULL OR o.leased_until < clock_timestamp()) \
         ORDER BY o.next_attempt_at, o.order_id FOR UPDATE OF o SKIP LOCKED LIMIT 1) \
         UPDATE grund_hosted_orders o SET leased_until = clock_timestamp() + interval '30 seconds', \
           attempts = attempts + 1, \
           next_attempt_at = clock_timestamp() + (LEAST(300, (1 << LEAST(attempts, 8))) + floor(random() * 5)) * interval '1 second' \
         FROM claim WHERE o.organisation_id = claim.organisation_id AND o.order_id = claim.order_id \
         RETURNING o.organisation_id, o.order_id, o.name, o.size, o.region, o.token_id, o.machine_id, o.status, o.idempotency_key",
    )
    .fetch_optional(executor)
    .await
}

/// Releases a recovery claim after the provider's outcome remains uncertain.
pub async fn retry_hosted_later(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    order_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_hosted_orders SET leased_until = NULL \
         WHERE organisation_id = $1 AND order_id = $2 AND status IN ('joining', 'active')",
    )
    .bind(organisation_id)
    .bind(order_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Finds cancelled or failed pending assignments not yet released.
pub async fn hosted_unreleased(
    executor: impl PgExecutor<'_>,
) -> Result<Vec<(Uuid, Uuid, String, Uuid)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT o.organisation_id, o.order_id, t.provider_machine_id, o.token_id \
         FROM grund_hosted_orders o JOIN grund_machine_tokens t ON t.token_id = o.token_id \
         WHERE o.status IN ('removed', 'failed') AND o.machine_id IS NULL \
           AND o.released_at IS NULL AND t.provider_machine_id IS NOT NULL \
         ORDER BY o.created_at, o.order_id LIMIT 20",
    )
    .fetch_all(executor)
    .await
}

/// Records a provider's idempotent acknowledgement of cancellation.
pub async fn mark_hosted_released(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    order_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_hosted_orders SET released_at = clock_timestamp() \
         WHERE organisation_id = $1 AND order_id = $2 AND machine_id IS NULL \
           AND status IN ('removed', 'failed') AND released_at IS NULL",
    )
    .bind(organisation_id)
    .bind(order_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Removed orders whose provider call may have succeeded before an ambiguous exit.
pub async fn hosted_unresolved_cancellations(
    executor: impl PgExecutor<'_>,
) -> Result<Vec<(Uuid, Uuid, Uuid)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT o.organisation_id, o.order_id, o.token_id \
         FROM grund_hosted_orders o JOIN grund_machine_tokens t ON t.token_id = o.token_id \
         WHERE o.status IN ('removed', 'failed') AND o.machine_id IS NULL \
           AND o.released_at IS NULL AND t.provider_machine_id IS NULL \
           AND GREATEST(t.expires_at, o.cancelled_at) < clock_timestamp() - interval '30 seconds' \
         ORDER BY o.created_at, o.order_id LIMIT 20",
    )
    .fetch_all(executor)
    .await
}

/// Claims a removed hosted lease whose provider wipe has not been acknowledged.
pub async fn claim_hosted_rebuild(
    executor: impl PgExecutor<'_>,
) -> Result<Option<(Uuid, Uuid, Uuid)>, sqlx::Error> {
    sqlx::query_as(
        "WITH claim AS (SELECT organisation_id, order_id FROM grund_hosted_orders \
         WHERE status = 'removed' AND machine_id IS NOT NULL AND rebuild_requested_at IS NULL \
           AND next_attempt_at <= clock_timestamp() \
           AND (leased_until IS NULL OR leased_until < clock_timestamp()) \
         ORDER BY next_attempt_at, order_id FOR UPDATE SKIP LOCKED LIMIT 1) \
         UPDATE grund_hosted_orders o SET leased_until = clock_timestamp() + interval '30 seconds', \
           next_attempt_at = clock_timestamp() + interval '30 seconds' \
         FROM claim WHERE o.organisation_id = claim.organisation_id AND o.order_id = claim.order_id \
         RETURNING o.organisation_id, o.order_id, o.machine_id",
    )
    .fetch_optional(executor)
    .await
}

/// Records a provider's acknowledgement of the wipe, or schedules another try.
pub async fn finish_hosted_rebuild(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    order_id: Uuid,
    requested: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_hosted_orders SET leased_until = NULL, \
           rebuild_requested_at = CASE WHEN $3 THEN clock_timestamp() ELSE rebuild_requested_at END \
         WHERE organisation_id = $1 AND order_id = $2 AND status = 'removed'",
    )
    .bind(organisation_id)
    .bind(order_id)
    .bind(requested)
    .execute(executor)
    .await?;
    Ok(())
}

/// Fails a still-pending order under its registration token's lock.
pub async fn fail_hosted_token(
    connection: &mut PgConnection,
    token_id: Uuid,
    status: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query("SELECT token_id FROM grund_machine_tokens WHERE token_id = $1 FOR UPDATE")
        .bind(token_id)
        .fetch_one(&mut *connection)
        .await?;
    let changed = sqlx::query(
        "UPDATE grund_hosted_orders SET status = $2, leased_until = NULL, \
           cancelled_at = clock_timestamp() \
         WHERE token_id = $1 AND status = 'joining'",
    )
    .bind(token_id)
    .bind(status)
    .execute(&mut *connection)
    .await?
    .rows_affected()
        > 0;
    if changed {
        expire_hosted_token(connection, token_id).await?;
    }
    Ok(changed)
}
