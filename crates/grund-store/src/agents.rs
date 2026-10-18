//! The control link's rows (grund-docs design/machines.md §7b): what each
//! agent last said, the VMs an organisation runs on its own machines, and
//! each machine's newest signed desired state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgConnection, PgExecutor, PgPool};
use uuid::Uuid;

/// Host memory charged above each VM's configured guest RAM.
pub const VM_MEMORY_OVERHEAD_MIB: i64 = 128;

/// Records a heartbeat: the machine is alive now, with these capabilities.
pub async fn heartbeat(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
    agent_version: &str,
    capabilities: &Value,
    at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "WITH presence AS ( \
           INSERT INTO grund_machine_presence (machine_id, last_seen_at, agent_version, capabilities) \
           VALUES ($1, $2, $3, $4) \
           ON CONFLICT (machine_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at, \
             agent_version = EXCLUDED.agent_version, \
             capabilities = EXCLUDED.capabilities || jsonb_strip_nulls(jsonb_build_object( \
               '_runtime_heartbeat', grund_machine_presence.capabilities->'_runtime_heartbeat', \
               '_runtime_report', grund_machine_presence.capabilities->'_runtime_report')) \
           RETURNING machine_id), \
         recovery AS (UPDATE grund_machine_migration_pauses pause \
           SET recovery_heartbeat_at = clock_timestamp() FROM presence p \
           WHERE pause.machine_id = p.machine_id AND pause.clear_requested_at IS NOT NULL \
             AND pause.recovery_heartbeat_at IS NULL AND pause.expires_at > clock_timestamp() \
           RETURNING pause.machine_id) \
         SELECT EXISTS(SELECT 1 FROM recovery)",
    )
    .bind(machine_id)
    .bind(at)
    .bind(agent_version)
    .bind(capabilities)
    .fetch_one(executor)
    .await
}

/// Authenticated PID1 context and actual resource enforcement results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestBootObservation {
    pub vm_id: Uuid,
    pub attempt_id: Uuid,
    pub sequence: u64,
    pub launch_nonce: Uuid,
    pub os_boot_id: Uuid,
    pub cpu_probe: bool,
    pub memory_probe: bool,
    pub attachment_probe: bool,
    pub probe_failed: bool,
}

/// Host evidence retains physical process provenance, never desired-image substitutes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostVmObservation {
    pub vm_id: Uuid,
    pub attempt_id: Uuid,
    pub sequence: u64,
    pub phase: String,
    pub kernel_sha256: String,
    pub rootfs_sha256: String,
    pub launch_nonce: Uuid,
    pub reason: String,
    pub previous_process: Option<grund_domain::agent_updates::vm::ProcessIdentity>,
    pub candidate_process: Option<grund_domain::agent_updates::vm::ProcessIdentity>,
    pub old_root_fenced: bool,
}

/// A monotonic heartbeat watermark bound to its authenticated registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeHeartbeat {
    pub registration_key: String,
    pub signed_at: DateTime<Utc>,
    pub runtime_ready: bool,
    pub guest_boot: Option<GuestBootObservation>,
}

/// A current-document status snapshot and its original signed timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeReport {
    pub registration_key: String,
    pub signed_at: DateTime<Utc>,
    pub applied_generation: i64,
    pub reports_replicas: bool,
    pub replicas_running: bool,
    pub refusals: Vec<String>,
    pub vm_updates: Vec<HostVmObservation>,
}

/// Disposable observations, read together with the current registered key and document.
#[derive(Debug, Clone)]
pub struct RuntimeObservation {
    pub machine_id: Uuid,
    pub registration_key: String,
    pub heartbeat: Option<RuntimeHeartbeat>,
    pub report: Option<RuntimeReport>,
    pub current_generation: i64,
}

/// Original signature age, rather than receipt time, bounds runtime authority.
pub fn runtime_fresh(signed_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    signed_at <= now && now - signed_at <= chrono::Duration::seconds(30)
}

/// Reads a batch in the caller's transaction without acquiring the update singleton.
pub async fn runtime_observations(
    executor: impl PgExecutor<'_>,
    machine_ids: &[Uuid],
) -> Result<Vec<RuntimeObservation>, sqlx::Error> {
    #[derive(FromRow)]
    struct Row {
        machine_id: Uuid,
        registration_key: String,
        heartbeat: Option<sqlx::types::Json<RuntimeHeartbeat>>,
        report: Option<sqlx::types::Json<RuntimeReport>>,
        current_generation: i64,
    }
    let rows = sqlx::query_as::<_, Row>(
        "SELECT m.machine_id, m.public_key AS registration_key, \
           p.capabilities->'_runtime_heartbeat' AS heartbeat, \
           p.capabilities->'_runtime_report' AS report, \
           COALESCE(d.generation, 0) AS current_generation \
         FROM grund_machines m LEFT JOIN grund_machine_presence p USING(machine_id) \
         LEFT JOIN grund_machine_documents d USING(machine_id) \
         WHERE m.machine_id = ANY($1) AND m.public_key IS NOT NULL AND m.state <> 'revoked'",
    )
    .bind(machine_ids)
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| RuntimeObservation {
            machine_id: row.machine_id,
            heartbeat: row
                .heartbeat
                .map(|value| value.0)
                .filter(|value| value.registration_key == row.registration_key),
            report: row
                .report
                .map(|value| value.0)
                .filter(|value| value.registration_key == row.registration_key),
            registration_key: row.registration_key,
            current_generation: row.current_generation,
        })
        .collect())
}

/// Reads only this host's active disposable VM instruction under its document lock.
pub async fn active_vm_update(
    executor: impl PgExecutor<'_>,
    host_machine_id: Uuid,
) -> Result<Option<grund_domain::agent_updates::vm::VmAttempt>, sqlx::Error> {
    Ok(
        sqlx::query_scalar::<_, sqlx::types::Json<grund_domain::agent_updates::vm::VmAttempt>>(
            "SELECT active FROM grund_agent_updates WHERE rollout_id=$1 \
         AND active ? 'vm_id' AND active->>'host_machine_id'=$2",
        )
        .bind(grund_domain::agent_updates::rollout_id())
        .bind(host_machine_id.to_string())
        .fetch_optional(executor)
        .await?
        .map(|attempt| attempt.0),
    )
}

/// Updates only a strictly newer heartbeat from the currently registered key.
pub async fn record_runtime_heartbeat(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
    heartbeat: &RuntimeHeartbeat,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_machine_presence p SET capabilities = \
           jsonb_set(p.capabilities, '{_runtime_heartbeat}', $2) \
         WHERE p.machine_id = $1 AND EXISTS (SELECT 1 FROM grund_machines m \
           WHERE m.machine_id = $1 AND m.public_key = $3 AND m.state <> 'revoked') \
           AND ($4::timestamptz <= clock_timestamp() \
             AND $4 >= clock_timestamp() - interval '30 seconds') \
           AND (p.capabilities->'_runtime_heartbeat'->>'registration_key' IS DISTINCT FROM $3 \
             OR (p.capabilities->'_runtime_heartbeat'->>'signed_at')::timestamptz < $4)",
    )
    .bind(machine_id)
    .bind(sqlx::types::Json(heartbeat))
    .bind(&heartbeat.registration_key)
    .bind(heartbeat.signed_at)
    .execute(executor)
    .await?;
    Ok(())
}

/// Records one status snapshot while locking its desired-state generation.
/// VM observations from an older document cannot acknowledge a later stop.
pub async fn report(
    pool: &PgPool,
    machine_id: Uuid,
    applied_generation: i64,
    refusals: &Value,
    observed: &[(Uuid, &'static str, Option<String>)],
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    report_inner(
        pool,
        machine_id,
        applied_generation,
        refusals,
        observed,
        at,
        None,
    )
    .await
}

/// Atomically stores authenticated current-generation runtime and VM evidence.
pub async fn report_authenticated(
    pool: &PgPool,
    machine_id: Uuid,
    refusals: &Value,
    observed: &[(Uuid, &'static str, Option<String>)],
    at: DateTime<Utc>,
    runtime: &RuntimeReport,
) -> Result<(), sqlx::Error> {
    report_inner(
        pool,
        machine_id,
        runtime.applied_generation,
        refusals,
        observed,
        at,
        Some(runtime),
    )
    .await
}

async fn report_inner(
    pool: &PgPool,
    machine_id: Uuid,
    applied_generation: i64,
    refusals: &Value,
    observed: &[(Uuid, &'static str, Option<String>)],
    at: DateTime<Utc>,
    runtime: Option<&RuntimeReport>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let generation = lock_generation(&mut tx, machine_id).await?;
    let mut accepted_runtime = runtime.is_none();
    if let Some(runtime) = runtime
        .filter(|runtime| applied_generation == generation && runtime_fresh(runtime.signed_at, at))
    {
        accepted_runtime = sqlx::query_scalar(
            "WITH accepted AS (INSERT INTO grund_machine_presence \
               (machine_id, last_seen_at, capabilities) \
             SELECT $1, $2, jsonb_build_object('_runtime_report', $3::jsonb) \
             WHERE EXISTS (SELECT 1 FROM grund_machines WHERE machine_id=$1 \
               AND public_key=$4 AND state <> 'revoked') \
               AND $5::timestamptz <= clock_timestamp() \
               AND $5 >= clock_timestamp() - interval '30 seconds' \
             ON CONFLICT (machine_id) DO UPDATE SET capabilities = \
               jsonb_set(grund_machine_presence.capabilities, '{_runtime_report}', $3) \
             WHERE grund_machine_presence.capabilities->'_runtime_report'->>'registration_key' IS DISTINCT FROM $4 \
               OR (grund_machine_presence.capabilities->'_runtime_report'->>'signed_at')::timestamptz < $5 \
               OR ((grund_machine_presence.capabilities->'_runtime_report'->>'signed_at')::timestamptz = $5 \
                 AND (grund_machine_presence.capabilities->'_runtime_report'->>'applied_generation')::bigint < $6) \
             RETURNING machine_id) SELECT EXISTS(SELECT 1 FROM accepted)",
        )
        .bind(machine_id).bind(at).bind(sqlx::types::Json(runtime))
        .bind(&runtime.registration_key).bind(runtime.signed_at)
        .bind(applied_generation)
        .fetch_one(&mut *tx).await?;
    }
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
    .execute(&mut *tx)
    .await?;
    if accepted_runtime && applied_generation >= generation {
        for (vm_id, state, reason) in observed.iter().take(200) {
            observe_vm(&mut *tx, machine_id, *vm_id, state, reason.as_deref()).await?;
        }
    }
    tx.commit().await
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
    pub host_pool: Option<String>,
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
            "SELECT v.vm_id, v.organisation_id, v.host_machine_id, h.pool_name AS host_name, h.pool AS host_pool, v.name, \
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

/// Changes a VM's desired state, invalidating observations of its old state.
/// The caller holds the host's document lock and publishes in the same transaction.
pub async fn set_vm_state(
    executor: impl PgExecutor<'_>,
    vm_id: Uuid,
    state: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_vms SET state = $2, observed_state = NULL, observed_reason = NULL, \
         updated_at = clock_timestamp() WHERE vm_id = $1 AND state <> $2",
    )
    .bind(vm_id)
    .bind(state)
    .execute(executor)
    .await?;
    Ok(())
}

async fn observe_vm(
    executor: impl PgExecutor<'_>,
    host_machine_id: Uuid,
    vm_id: Uuid,
    observed_state: &str,
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_vms SET observed_state = $3, observed_reason = left($4, 500), updated_at = clock_timestamp() \
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    async fn registered(pool: &PgPool, key: &str) -> Uuid {
        let machine_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO grund_machines (machine_id,pool,name,state,public_key,minted_by, \
               registered_at,key_registered_at,stream_version) \
             VALUES ($1,'management',$2,'available',$3,'test',clock_timestamp(),clock_timestamp(),1)",
        )
        .bind(machine_id).bind(machine_id.to_string()).bind(key)
        .execute(pool).await.unwrap();
        machine_id
    }

    #[test]
    fn receipt_time_cannot_refresh_an_expired_or_future_signature() {
        let now = Utc::now();
        assert!(runtime_fresh(now - Duration::seconds(30), now));
        assert!(!runtime_fresh(now - Duration::seconds(31), now));
        assert!(!runtime_fresh(now + Duration::seconds(1), now));
    }

    #[sqlx::test(migrations = false)]
    async fn replayed_heartbeats_cannot_replace_newer_boot_proof_or_cross_registrations(
        pool: PgPool,
    ) {
        crate::migrate(&pool).await.unwrap();
        let key = "a".repeat(64);
        let machine = registered(&pool, &key).await;
        let now = Utc::now() - Duration::seconds(1);
        heartbeat(&pool, machine, "1", &serde_json::json!({"apps":true}), now)
            .await
            .unwrap();
        let proof = GuestBootObservation {
            vm_id: Uuid::now_v7(),
            attempt_id: Uuid::now_v7(),
            sequence: 3,
            launch_nonce: Uuid::now_v7(),
            os_boot_id: Uuid::now_v7(),
            cpu_probe: true,
            memory_probe: true,
            attachment_probe: true,
            probe_failed: false,
        };
        let fresh = RuntimeHeartbeat {
            registration_key: key.clone(),
            signed_at: now,
            runtime_ready: true,
            guest_boot: Some(proof.clone()),
        };
        record_runtime_heartbeat(&pool, machine, &fresh)
            .await
            .unwrap();
        let replay = RuntimeHeartbeat {
            signed_at: now - Duration::seconds(1),
            runtime_ready: false,
            guest_boot: None,
            ..fresh.clone()
        };
        heartbeat(
            &pool,
            machine,
            "2",
            &serde_json::json!({"apps":false}),
            Utc::now(),
        )
        .await
        .unwrap();
        record_runtime_heartbeat(&pool, machine, &replay)
            .await
            .unwrap();
        let rows = runtime_observations(&pool, &[machine]).await.unwrap();
        assert_eq!(rows[0].heartbeat.as_ref(), Some(&fresh));
        let capabilities: Value = sqlx::query_scalar(
            "SELECT capabilities FROM grund_machine_presence WHERE machine_id=$1",
        )
        .bind(machine)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(capabilities["apps"], false);
        let new_key = "b".repeat(64);
        sqlx::query("UPDATE grund_machines SET public_key=$2 WHERE machine_id=$1")
            .bind(machine)
            .bind(&new_key)
            .execute(&pool)
            .await
            .unwrap();
        let rows = runtime_observations(&pool, &[machine]).await.unwrap();
        assert!(rows[0].heartbeat.is_none());
        record_runtime_heartbeat(
            &pool,
            machine,
            &RuntimeHeartbeat {
                signed_at: Utc::now() - Duration::milliseconds(100),
                ..fresh
            },
        )
        .await
        .unwrap();
        assert!(
            runtime_observations(&pool, &[machine]).await.unwrap()[0]
                .heartbeat
                .is_none()
        );
        let registered = RuntimeHeartbeat {
            registration_key: new_key,
            signed_at: now - Duration::seconds(2),
            runtime_ready: false,
            guest_boot: None,
        };
        record_runtime_heartbeat(&pool, machine, &registered)
            .await
            .unwrap();
        assert_eq!(
            runtime_observations(&pool, &[machine]).await.unwrap()[0]
                .heartbeat
                .as_ref(),
            Some(&registered)
        );
    }

    #[sqlx::test(migrations = false)]
    async fn status_generation_signature_and_registration_fence_vm_writes_atomically(pool: PgPool) {
        crate::migrate(&pool).await.unwrap();
        let key = "a".repeat(64);
        let host = registered(&pool, &key).await;
        let vm_id = Uuid::now_v7();
        let digest = "a".repeat(64);
        insert_vm(
            &pool,
            &NewVm {
                vm_id,
                organisation_id: Uuid::now_v7(),
                host_machine_id: host,
                name: "guest",
                vcpus: 1,
                memory_mib: 512,
                disk_gib: 8,
                kernel_url: "https://artifacts.example/kernel",
                kernel_sha256: &digest,
                rootfs_url: "https://artifacts.example/rootfs",
                rootfs_sha256: &digest,
                created_by: Uuid::nil(),
            },
        )
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        lock_generation(&mut tx, host).await.unwrap();
        store_document(&mut *tx, host, 2, Uuid::nil(), b"{}", &[0; 64], Utc::now())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let now = DateTime::from_timestamp(Utc::now().timestamp() - 1, 0).unwrap();
        let witness = HostVmObservation {
            vm_id,
            attempt_id: Uuid::now_v7(),
            sequence: 2,
            phase: "quiesced".into(),
            kernel_sha256: String::new(),
            rootfs_sha256: String::new(),
            launch_nonce: Uuid::now_v7(),
            reason: String::new(),
            previous_process: None,
            candidate_process: None,
            old_root_fenced: true,
        };
        let report = RuntimeReport {
            registration_key: key,
            signed_at: now,
            applied_generation: 2,
            reports_replicas: true,
            replicas_running: false,
            refusals: Vec::new(),
            vm_updates: vec![witness.clone()],
        };
        for rejected in [
            RuntimeReport {
                applied_generation: 1,
                ..report.clone()
            },
            RuntimeReport {
                applied_generation: 3,
                ..report.clone()
            },
            RuntimeReport {
                signed_at: now - Duration::seconds(31),
                ..report.clone()
            },
            RuntimeReport {
                registration_key: "b".repeat(64),
                ..report.clone()
            },
        ] {
            report_authenticated(
                &pool,
                host,
                &serde_json::json!([]),
                &[(vm_id, "stopped", None)],
                Utc::now(),
                &rejected,
            )
            .await
            .unwrap();
            assert!(
                vm(&pool, vm_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .observed_state
                    .is_none()
            );
            assert!(
                runtime_observations(&pool, &[host]).await.unwrap()[0]
                    .report
                    .is_none()
            );
        }
        report_authenticated(
            &pool,
            host,
            &serde_json::json!([]),
            &[(vm_id, "exited", None)],
            Utc::now(),
            &report,
        )
        .await
        .unwrap();
        assert_eq!(
            vm(&pool, vm_id)
                .await
                .unwrap()
                .unwrap()
                .observed_state
                .as_deref(),
            Some("exited")
        );
        let mut replay = report.clone();
        replay.vm_updates.clear();
        replay.replicas_running = true;
        report_authenticated(
            &pool,
            host,
            &serde_json::json!([]),
            &[(vm_id, "running", None)],
            Utc::now(),
            &replay,
        )
        .await
        .unwrap();
        let rows = runtime_observations(&pool, &[host]).await.unwrap();
        assert_eq!(rows[0].current_generation, 2);
        assert_eq!(rows[0].report.as_ref(), Some(&report));
        assert_eq!(rows[0].report.as_ref().unwrap().vm_updates[0], witness);
        assert_eq!(
            vm(&pool, vm_id)
                .await
                .unwrap()
                .unwrap()
                .observed_state
                .as_deref(),
            Some("exited")
        );
        let mut tx = pool.begin().await.unwrap();
        lock_generation(&mut tx, host).await.unwrap();
        store_document(&mut *tx, host, 3, Uuid::nil(), b"{}", &[0; 64], Utc::now())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let next = RuntimeReport {
            applied_generation: 3,
            ..report.clone()
        };
        report_authenticated(
            &pool,
            host,
            &serde_json::json!([]),
            &[(vm_id, "stopped", None)],
            Utc::now(),
            &next,
        )
        .await
        .unwrap();
        let rows = runtime_observations(&pool, &[host]).await.unwrap();
        assert_eq!(rows[0].report.as_ref(), Some(&next));
        assert_eq!(
            vm(&pool, vm_id)
                .await
                .unwrap()
                .unwrap()
                .observed_state
                .as_deref(),
            Some("stopped")
        );
    }
}
