//! The control link's rows (grund-docs design/machines.md §7b): what each
//! agent last said, the VMs an organisation runs on its own machines, and
//! each machine's newest signed desired state.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgConnection, PgExecutor};
use uuid::Uuid;

/// Records a heartbeat: the machine is alive now, with these capabilities.
pub async fn heartbeat(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
    agent_version: &str,
    capabilities: &Value,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_machine_presence (machine_id, last_seen_at, agent_version, capabilities) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (machine_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at, \
           agent_version = EXCLUDED.agent_version, capabilities = EXCLUDED.capabilities",
    )
    .bind(machine_id)
    .bind(at)
    .bind(agent_version)
    .bind(capabilities)
    .execute(executor)
    .await?;
    Ok(())
}

/// Records what the agent reported applying, and what it refused.
pub async fn report(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
    applied_generation: i64,
    refusals: &Value,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_machine_presence (machine_id, last_seen_at, applied_generation, refusals, reported_at) \
         VALUES ($1, $2, $3, $4, $2) \
         ON CONFLICT (machine_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at, \
           applied_generation = EXCLUDED.applied_generation, refusals = EXCLUDED.refusals, \
           reported_at = EXCLUDED.reported_at",
    )
    .bind(machine_id)
    .bind(at)
    .bind(applied_generation)
    .bind(refusals)
    .execute(executor)
    .await?;
    Ok(())
}

/// A VM to insert.
#[derive(Debug, Clone)]
pub struct NewVm<'a> {
    pub vm_id: Uuid,
    pub organisation_id: Uuid,
    pub host_machine_id: Uuid,
    pub name: &'a str,
    pub vcpus: i32,
    pub memory_mib: i32,
    pub disk_gib: i32,
    pub kernel_url: &'a str,
    pub kernel_sha256: &'a str,
    pub rootfs_url: &'a str,
    pub rootfs_sha256: &'a str,
    pub created_by: Uuid,
}

pub async fn insert_vm(executor: impl PgExecutor<'_>, vm: &NewVm<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_vms (vm_id, organisation_id, host_machine_id, name, vcpus, memory_mib, \
           disk_gib, kernel_url, kernel_sha256, rootfs_url, rootfs_sha256, state, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'running', $12)",
    )
    .bind(vm.vm_id)
    .bind(vm.organisation_id)
    .bind(vm.host_machine_id)
    .bind(vm.name)
    .bind(vm.vcpus)
    .bind(vm.memory_mib)
    .bind(vm.disk_gib)
    .bind(vm.kernel_url)
    .bind(vm.kernel_sha256)
    .bind(vm.rootfs_url)
    .bind(vm.rootfs_sha256)
    .bind(vm.created_by)
    .execute(executor)
    .await?;
    Ok(())
}

/// A VM as stored.
#[derive(Debug, Clone, FromRow)]
pub struct VmRow {
    pub vm_id: Uuid,
    pub organisation_id: Uuid,
    pub host_machine_id: Uuid,
    pub host_name: Option<String>,
    pub name: String,
    pub vcpus: i32,
    pub memory_mib: i32,
    pub disk_gib: i32,
    pub kernel_url: String,
    pub kernel_sha256: String,
    pub rootfs_url: String,
    pub rootfs_sha256: String,
    pub state: String,
    pub observed_state: Option<String>,
    pub observed_reason: Option<String>,
    pub machine_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

macro_rules! select_vms {
    ($tail:literal) => {
        concat!(
            "SELECT v.vm_id, v.organisation_id, v.host_machine_id, h.pool_name AS host_name, v.name, \
               v.vcpus, v.memory_mib, v.disk_gib, v.kernel_url, v.kernel_sha256, v.rootfs_url, \
               v.rootfs_sha256, v.state, v.observed_state, v.observed_reason, v.machine_id, \
               v.created_at \
             FROM grund_vms v LEFT JOIN grund_machines h ON h.machine_id = v.host_machine_id ",
            $tail
        )
    };
}

pub async fn vm(executor: impl PgExecutor<'_>, vm_id: Uuid) -> Result<Option<VmRow>, sqlx::Error> {
    sqlx::query_as(select_vms!("WHERE v.vm_id = $1"))
        .bind(vm_id)
        .fetch_optional(executor)
        .await
}

/// An organisation's VMs, newest first.
pub async fn organisation_vms(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<VmRow>, sqlx::Error> {
    sqlx::query_as(select_vms!(
        "WHERE v.organisation_id = $1 ORDER BY v.created_at DESC LIMIT 1000"
    ))
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

/// The VMs a machine hosts, that it should run or stop.
pub async fn hosted_vms(
    executor: impl PgExecutor<'_>,
    host_machine_id: Uuid,
) -> Result<Vec<VmRow>, sqlx::Error> {
    sqlx::query_as(select_vms!(
        "WHERE v.host_machine_id = $1 ORDER BY v.created_at"
    ))
    .bind(host_machine_id)
    .fetch_all(executor)
    .await
}

/// Asks for a VM to run or stop.
pub async fn set_vm_state(
    executor: impl PgExecutor<'_>,
    vm_id: Uuid,
    state: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE grund_vms SET state = $2, updated_at = clock_timestamp() WHERE vm_id = $1")
        .bind(vm_id)
        .bind(state)
        .execute(executor)
        .await?;
    Ok(())
}

/// Records what the host said about one of its VMs. A VM of another host is
/// left alone.
pub async fn observe_vm(
    executor: impl PgExecutor<'_>,
    host_machine_id: Uuid,
    vm_id: Uuid,
    observed_state: &str,
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_vms SET observed_state = $3, observed_reason = $4, updated_at = clock_timestamp() \
         WHERE vm_id = $2 AND host_machine_id = $1",
    )
    .bind(host_machine_id)
    .bind(vm_id)
    .bind(observed_state)
    .bind(reason)
    .execute(executor)
    .await?;
    Ok(())
}

/// Records the machine a VM registered as.
pub async fn link_vm_machine(
    executor: impl PgExecutor<'_>,
    vm_id: Uuid,
    machine_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_vms SET machine_id = $2, updated_at = clock_timestamp() WHERE vm_id = $1",
    )
    .bind(vm_id)
    .bind(machine_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// A machine's newest desired state, as signed.
#[derive(Debug, Clone, FromRow)]
pub struct DocumentRow {
    pub generation: i64,
    pub key_id: Uuid,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

pub async fn document(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
) -> Result<Option<DocumentRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT generation, key_id, payload, signature FROM grund_machine_documents \
         WHERE machine_id = $1 AND generation > 0",
    )
    .bind(machine_id)
    .fetch_optional(executor)
    .await
}

/// The machine's current generation, locked until the transaction ends, so
/// two changes to one machine's document queue and each gets its own
/// generation.
pub async fn lock_generation(
    connection: &mut PgConnection,
    machine_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_machine_documents (machine_id, generation, key_id, payload, signature, issued_at) \
         VALUES ($1, 0, $1, '', decode(repeat('00', 64), 'hex'), clock_timestamp()) \
         ON CONFLICT (machine_id) DO NOTHING",
    )
    .bind(machine_id)
    .execute(&mut *connection)
    .await?;
    sqlx::query_scalar(
        "SELECT generation FROM grund_machine_documents WHERE machine_id = $1 FOR UPDATE",
    )
    .bind(machine_id)
    .fetch_one(connection)
    .await
}

/// Stores the machine's new document.
pub async fn store_document(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
    generation: i64,
    key_id: Uuid,
    payload: &[u8],
    signature: &[u8; 64],
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_machine_documents SET generation = $2, key_id = $3, payload = $4, signature = $5, \
           issued_at = $6 WHERE machine_id = $1",
    )
    .bind(machine_id)
    .bind(generation)
    .bind(key_id)
    .bind(payload)
    .bind(&signature[..])
    .bind(at)
    .execute(executor)
    .await?;
    Ok(())
}
