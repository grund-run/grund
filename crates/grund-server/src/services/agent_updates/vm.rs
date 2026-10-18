//! Explicit own-VM replacement through the instance's existing durable update slot.

use buffa::Message;
use chrono::{DateTime, Duration, Utc};
use grund_domain::agent_updates::{
    self, ActiveUpdate, AgentUpdates, CompletedUpdate, vm as domain,
};
use grund_proto::grund::agent::v1 as agent;
use grund_store::{agents, work::Work};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::AgentUpdateService;
use crate::{services::agents::AgentsState, state::State};

const RETAINED_KERNEL: &str = "9204218e8bcca6ac23848d74f45df2eb19d7f31e8277840a7d145a0df8b078d2";
const FRESHNESS: Duration = Duration::seconds(30);

/// Owner approval of one exact configured image at a specific VM version.
#[derive(Debug, Clone)]
pub struct VmUpdateRequest {
    pub expected_version: i64,
    pub rootfs_sha256: String,
    pub idempotency_key: String,
}

/// Current replacement state, including safety refusals and unproven legacy guests.
#[derive(Debug, Clone)]
pub struct VmUpdateView {
    pub vm_id: Uuid,
    pub attempt_id: Option<Uuid>,
    pub phase: &'static str,
    pub paused: bool,
    pub reason: Option<String>,
    pub available_rootfs_sha256: Option<String>,
    pub current_rootfs_sha256: String,
    pub update_version: i64,
    pub legacy_guest: bool,
    pub eligible: bool,
    pub can_cancel: bool,
}

/// Stable owner-visible refusals; foreign VMs are indistinguishable from missing VMs.
#[derive(Debug, thiserror::Error)]
pub enum VmUpdateError {
    #[error("VM not found")]
    NotFound,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("VM changed; refresh before updating")]
    Stale,
    #[error("{0}")]
    Blocked(&'static str),
    #[error("idempotency key already names a different request")]
    AlreadyExists,
}

#[derive(sqlx::FromRow)]
struct VmFacts {
    vm_id: Uuid,
    organisation_id: Uuid,
    host_machine_id: Uuid,
    machine_id: Option<Uuid>,
    state: String,
    kernel_url: String,
    kernel_sha256: String,
    rootfs_sha256: String,
    update_stream_version: i64,
    host_registration: Option<String>,
    guest_registration: Option<String>,
    host_active: bool,
    guest_active: bool,
    in_service: bool,
    host_capabilities: serde_json::Value,
    has_local_volumes: bool,
    has_allocations: bool,
    single_machine: bool,
}

async fn facts(
    connection: &mut sqlx::PgConnection,
    organisation_id: Uuid,
    vm_ids: &[Uuid],
) -> anyhow::Result<Vec<VmFacts>> {
    Ok(sqlx::query_as(
        "SELECT v.vm_id,v.organisation_id,v.host_machine_id,v.machine_id,v.state, \
         v.kernel_url,v.kernel_sha256,v.rootfs_sha256,v.update_stream_version, \
         h.public_key AS host_registration,g.public_key AS guest_registration, \
         COALESCE(h.state='active' AND h.pool_organisation_id=v.organisation_id,false) AS host_active, \
         COALESCE(g.state='active' AND g.pool_organisation_id=v.organisation_id,false) AS guest_active, \
         g.cordoned_at IS NULL AS in_service, COALESCE(p.capabilities,'{}'::jsonb) AS host_capabilities, \
         EXISTS(SELECT 1 FROM grund_volumes x WHERE x.organisation_id=v.organisation_id \
           AND x.machine_id=v.machine_id AND x.size_gib IS NULL \
           AND (x.status <> 'deleted' OR x.source IS NOT NULL)) AS has_local_volumes, \
         EXISTS(SELECT 1 FROM grund_replicas r WHERE r.machine_id=v.machine_id) AS has_allocations, \
         (SELECT count(*)<=1 FROM grund_machines m WHERE m.pool_organisation_id=v.organisation_id \
           AND m.state='active' AND m.cordoned_at IS NULL \
           AND m.machine_id NOT IN (v.host_machine_id)) AS single_machine \
         FROM grund_vms v LEFT JOIN grund_machines h ON h.machine_id=v.host_machine_id \
         LEFT JOIN grund_machines g ON g.machine_id=v.machine_id \
         LEFT JOIN grund_machine_presence p ON p.machine_id=h.machine_id \
         WHERE v.organisation_id=$1 AND v.vm_id=ANY($2) ORDER BY v.vm_id",
    )
    .bind(organisation_id)
    .bind(vm_ids)
    .fetch_all(connection)
    .await?)
}

fn target(state: &State, row: &VmFacts) -> Option<domain::Target> {
    let defaults = &state.config.machine_defaults;
    let rootfs_url = defaults.vm_rootfs_url.as_ref()?;
    let rootfs_sha256 = defaults.vm_rootfs_sha256.as_ref()?;
    let approved_url = |url: &str| {
        url.starts_with("https://")
            && url.len() <= 2048
            && url[8..].contains('/')
            && !url.bytes().any(|byte| {
                byte.is_ascii_whitespace() || byte.is_ascii_control() || b"@?#".contains(&byte)
            })
    };
    if row.kernel_sha256 != RETAINED_KERNEL
        || rootfs_sha256 == &row.rootfs_sha256
        || !approved_url(rootfs_url)
        || !approved_url(&row.kernel_url)
    {
        return None;
    }
    Some(domain::Target {
        kernel_url: row.kernel_url.clone(),
        kernel_sha256: row.kernel_sha256.clone(),
        rootfs_url: rootfs_url.clone(),
        rootfs_sha256: rootfs_sha256.clone(),
    })
}

fn blocked(state: &State, rollout: &AgentUpdates, row: &VmFacts) -> Option<&'static str> {
    if !state.config.vm_updates_enabled {
        Some("VM updates are disabled on this instance")
    } else if state.config.agent_updates_paused || rollout.paused {
        Some("Machine updates are paused")
    } else if rollout.active.is_some() || rollout.pending_provider_release.is_some() {
        Some("Another machine update is still resolving")
    } else if rollout.migration_holds.contains_key(&row.host_machine_id)
        || row
            .machine_id
            .is_some_and(|id| rollout.migration_holds.contains_key(&id))
    {
        Some("A machine migration prevents this update")
    } else if row.state != "running" || !row.host_active || !row.guest_active {
        Some("The VM and its registered host and guest must be active")
    } else if row.host_capabilities.get("arch").and_then(|v| v.as_str()) != Some("x86_64")
        || row
            .host_capabilities
            .get("vm_replacement_version")
            .and_then(|v| v.as_u64())
            != Some(1)
    {
        Some("The host does not support safe VM replacement")
    } else if row.has_local_volumes {
        Some("Retained local app data prevents replacing this VM")
    } else if target(state, row).is_none() {
        Some("No approved root filesystem is available for this VM's retained kernel")
    } else {
        None
    }
}

fn current_attempt<'a>(rollout: &'a AgentUpdates, row: &VmFacts) -> Option<&'a domain::VmAttempt> {
    rollout
        .active
        .as_ref()
        .and_then(ActiveUpdate::vm)
        .filter(|a| a.organisation_id == row.organisation_id && a.vm_id == row.vm_id)
        .or_else(|| {
            rollout
                .last_completed
                .as_ref()
                .and_then(CompletedUpdate::vm)
                .filter(|a| a.organisation_id == row.organisation_id && a.vm_id == row.vm_id)
        })
}

fn fresh(now: DateTime<Utc>, at: DateTime<Utc>) -> bool {
    at <= now && now - at <= FRESHNESS
}

fn legacy(row: &VmFacts, observations: &[agents::RuntimeObservation], now: DateTime<Utc>) -> bool {
    !observations
        .iter()
        .find(|o| Some(o.machine_id) == row.machine_id)
        .and_then(|o| o.heartbeat.as_ref())
        .filter(|h| {
            Some(&h.registration_key) == row.guest_registration.as_ref()
                && fresh(now, h.signed_at)
                && h.runtime_ready
        })
        .and_then(|h| h.guest_boot.as_ref())
        .is_some_and(|boot| {
            boot.vm_id == row.vm_id
                && !boot.os_boot_id.is_nil()
                && boot.cpu_probe
                && boot.memory_probe
                && boot.attachment_probe
                && !boot.probe_failed
        })
}

fn view(
    state: &State,
    rollout: &AgentUpdates,
    row: &VmFacts,
    observations: &[agents::RuntimeObservation],
    receipt: Option<&domain::VmAttempt>,
) -> VmUpdateView {
    let attempt = receipt.or_else(|| current_attempt(rollout, row));
    let active = attempt.as_ref().is_some_and(|a| !a.phase.terminal());
    let refusal = (!active).then(|| blocked(state, rollout, row)).flatten();
    let before_authorization =
        active && attempt.as_ref().is_some_and(|a| a.authorized_at.is_none());
    let migration_hold = rollout.migration_holds.contains_key(&row.host_machine_id)
        || row
            .machine_id
            .is_some_and(|id| rollout.migration_holds.contains_key(&id));
    let paused = rollout.paused
        || state.config.agent_updates_paused
        || !state.config.vm_updates_enabled
        || attempt.as_ref().is_some_and(|a| a.failure.is_some())
        || before_authorization && (migration_hold || row.has_local_volumes);
    let reason = if attempt
        .as_ref()
        .is_some_and(|a| a.phase == domain::Phase::Cancelled)
    {
        Some("The update was cancelled without replacing the running guest".to_owned())
    } else if attempt
        .as_ref()
        .is_some_and(|a| a.phase == domain::Phase::RolledBack)
    {
        Some("The previous VM root was restored; machine updates remain paused".to_owned())
    } else if attempt
        .as_ref()
        .is_some_and(|a| a.phase == domain::Phase::Succeeded && a.failure.is_some())
    {
        Some("The VM update succeeded after recovery; machine updates remain paused".to_owned())
    } else if let Some(failure) = attempt.as_ref().and_then(|a| a.failure) {
        Some(
            match failure {
                domain::Failure::Cancelled => "Cancellation is resolving safely",
                domain::Failure::Timeout => "The update deadline elapsed; recovery is resolving",
                domain::Failure::HostFailed => {
                    "The replacement process is unavailable; recovery is resolving"
                }
                domain::Failure::HealthFailed => "The new guest has not proved it is ready",
                domain::Failure::Uncertain => {
                    "Physical state is uncertain; the machine update slot remains held"
                }
            }
            .to_owned(),
        )
    } else {
        let waiting = if before_authorization && row.has_local_volumes {
            Some("Retained local app data prevents replacing this VM; cancel the update")
        } else if before_authorization && migration_hold {
            Some("A machine migration prevents authorizing this update")
        } else if before_authorization
            && (!state.config.vm_updates_enabled
                || state.config.agent_updates_paused
                || rollout.paused)
        {
            Some("New VM update authorization is paused; cancellation remains available")
        } else if attempt
            .as_ref()
            .is_some_and(|a| a.phase == domain::Phase::Draining)
            && row.has_allocations
        {
            Some("Waiting for apps to move and become ready elsewhere")
        } else {
            None
        };
        waiting.or(refusal).map(str::to_owned).or_else(|| row.single_machine.then(||
            "Updating the only available machine may leave apps unavailable until it is ready".to_owned()))
    };
    VmUpdateView {
        vm_id: row.vm_id,
        attempt_id: attempt.as_ref().map(|a| a.id),
        phase: attempt.as_ref().map_or("idle", |a| a.phase.as_str()),
        paused,
        reason,
        available_rootfs_sha256: target(state, row).map(|t| t.rootfs_sha256),
        current_rootfs_sha256: row.rootfs_sha256.clone(),
        update_version: row.update_stream_version,
        legacy_guest: legacy(row, observations, Utc::now()),
        eligible: !active && refusal.is_none(),
        can_cancel: active && attempt.as_ref().is_some_and(|a| a.can_cancel()),
    }
}

fn identity(method: &str, organisation: Uuid, key: &str) -> anyhow::Result<String> {
    let key = Uuid::parse_str(key)
        .map_err(|_| VmUpdateError::Invalid("idempotency key must be a UUID"))?;
    if key.is_nil() {
        return Err(VmUpdateError::Invalid("idempotency key must be a UUID").into());
    }
    Ok(hex::encode(Sha256::digest(format!(
        "{method}\n{organisation}\n{key}"
    ))))
}

fn fingerprint(vm: Uuid, version: i64, rootfs: &str) -> String {
    hex::encode(Sha256::digest(format!("{vm}\n{version}\n{rootfs}")))
}

async fn apply(work: &mut Work<'_>, command: domain::Command) -> anyhow::Result<()> {
    work.agent_updates(agent_updates::Command::Vm(command))
        .await
        .map_err(|error| match error {
            grund_store::work::WorkError::AgentUpdates(agent_updates::Error::StaleFence) => {
                VmUpdateError::Stale.into()
            }
            grund_store::work::WorkError::AgentUpdates(agent_updates::Error::RequestConflict) => {
                VmUpdateError::AlreadyExists.into()
            }
            grund_store::work::WorkError::AgentUpdates(agent_updates::Error::SlotOccupied) => {
                VmUpdateError::Blocked("Another machine update is still resolving").into()
            }
            grund_store::work::WorkError::AgentUpdates(agent_updates::Error::Paused) => {
                VmUpdateError::Blocked("Machine updates are paused").into()
            }
            grund_store::work::WorkError::AgentUpdates(agent_updates::Error::MigrationConflict) => {
                VmUpdateError::Blocked("A machine migration prevents this update").into()
            }
            other => anyhow::Error::from(other),
        })?;
    Ok(())
}

impl AgentUpdateService {
    /// Reads one owned VM without exposing another organisation's existence.
    pub async fn vm_update(
        &self,
        organisation_id: Uuid,
        vm_id: Uuid,
    ) -> anyhow::Result<VmUpdateView> {
        self.vm_updates(organisation_id, &[vm_id])
            .await?
            .pop()
            .ok_or_else(|| VmUpdateError::NotFound.into())
    }

    /// Looks up the singleton, VM safety facts and authenticated evidence in batches.
    pub async fn vm_updates(
        &self,
        organisation_id: Uuid,
        vm_ids: &[Uuid],
    ) -> anyhow::Result<Vec<VmUpdateView>> {
        let mut connection = self.state.pool.acquire().await?;
        let rows = facts(&mut connection, organisation_id, vm_ids).await?;
        let rollout = grund_store::agent_updates::get(&mut *connection)
            .await?
            .map(|r| r.0)
            .unwrap_or_default();
        let ids: Vec<_> = rows
            .iter()
            .flat_map(|r| [Some(r.host_machine_id), r.machine_id])
            .flatten()
            .collect();
        let observations = agents::runtime_observations(&mut *connection, &ids).await?;
        Ok(rows
            .iter()
            .map(|r| view(&self.state, &rollout, r, &observations, None))
            .collect())
    }

    /// Reserves the shared slot atomically, replaying only the same scoped approved request.
    pub async fn request_vm_update(
        &self,
        organisation_id: Uuid,
        vm_id: Uuid,
        actor: &str,
        request: VmUpdateRequest,
    ) -> anyhow::Result<VmUpdateView> {
        let now = Utc::now();
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), actor).await?;
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM grund_vms WHERE organisation_id=$1 AND vm_id=$2)",
        )
        .bind(organisation_id)
        .bind(vm_id)
        .fetch_one(&mut **work.sql())
        .await?;
        if !owned {
            return Err(VmUpdateError::NotFound.into());
        }
        let hash = identity("UpdateVm", organisation_id, &request.idempotency_key)?;
        let fingerprint = fingerprint(vm_id, request.expected_version, &request.rootfs_sha256);
        let mut rollout = super::sweep(&mut work, now).await?;
        let row = facts(work.sql(), organisation_id, &[vm_id])
            .await?
            .pop()
            .ok_or(VmUpdateError::NotFound)?;
        let receipt = rollout
            .active
            .as_ref()
            .and_then(ActiveUpdate::vm)
            .filter(|a| a.organisation_id == organisation_id && a.request_hash == hash)
            .cloned()
            .or(work
                .completed_vm_update_request(organisation_id, &hash)
                .await?);
        if let Some(receipt) = receipt {
            if receipt.fingerprint != fingerprint || receipt.vm_id != vm_id {
                return Err(VmUpdateError::AlreadyExists.into());
            }
            let observations =
                agents::runtime_observations(&mut **work.sql(), &[receipt.guest_machine_id])
                    .await?;
            let result = view(&self.state, &rollout, &row, &observations, Some(&receipt));
            work.commit().await?;
            return Ok(result);
        }
        if let Some(reason) = blocked(&self.state, &rollout, &row) {
            return Err(VmUpdateError::Blocked(reason).into());
        }
        if row.update_stream_version != request.expected_version {
            return Err(VmUpdateError::Stale.into());
        }
        let target = target(&self.state, &row)
            .ok_or(VmUpdateError::Blocked("No approved VM image is configured"))?;
        if request.rootfs_sha256 != target.rootfs_sha256 {
            return Err(VmUpdateError::Stale.into());
        }
        let guest = row
            .machine_id
            .ok_or(VmUpdateError::Blocked("The guest is not registered"))?;
        let observations =
            agents::runtime_observations(&mut **work.sql(), &[row.host_machine_id, guest]).await?;
        if !observations.iter().any(|o| {
            o.machine_id == row.host_machine_id
                && Some(&o.registration_key) == row.host_registration.as_ref()
                && o.heartbeat
                    .as_ref()
                    .is_some_and(|h| fresh(now, h.signed_at) && h.runtime_ready)
        }) {
            return Err(VmUpdateError::Blocked("The host needs a fresh ready heartbeat").into());
        }
        let old_os_boot_id = observations
            .iter()
            .find(|o| o.machine_id == guest)
            .and_then(|o| o.heartbeat.as_ref())
            .filter(|h| fresh(now, h.signed_at))
            .and_then(|h| h.guest_boot.as_ref())
            .filter(|b| b.vm_id == vm_id)
            .map(|b| b.os_boot_id);
        apply(
            &mut work,
            domain::Command::Request {
                request: domain::Request {
                    id: Uuid::now_v7(),
                    vm_id,
                    organisation_id,
                    host_machine_id: row.host_machine_id,
                    guest_machine_id: guest,
                    host_registration_key: row
                        .host_registration
                        .clone()
                        .ok_or(VmUpdateError::Stale)?,
                    guest_registration_key: row
                        .guest_registration
                        .clone()
                        .ok_or(VmUpdateError::Stale)?,
                    request_hash: hash,
                    fingerprint,
                    source: domain::ImageIdentity {
                        kernel_sha256: row.kernel_sha256.clone(),
                        rootfs_sha256: row.rootfs_sha256.clone(),
                    },
                    target,
                    expected_update_version: request.expected_version,
                    original_in_service: row.in_service,
                    old_os_boot_id,
                    launch_nonce: Uuid::now_v7(),
                    deadline: now + Duration::minutes(15),
                },
                at: now,
            },
        )
        .await?;
        publish(&self.state, &mut work, now).await?;
        rollout = work.load_agent_updates().await?;
        let row = facts(work.sql(), organisation_id, &[vm_id])
            .await?
            .pop()
            .ok_or(VmUpdateError::NotFound)?;
        let result = view(&self.state, &rollout, &row, &observations, None);
        work.commit().await?;
        self.state.wakes.documents_changed();
        Ok(result)
    }

    /// Cancels before irreversible commit, preserving the same cancellation launch on replay.
    pub async fn cancel_vm_update(
        &self,
        organisation_id: Uuid,
        vm_id: Uuid,
        actor: &str,
        attempt_id: Uuid,
        idempotency_key: &str,
    ) -> anyhow::Result<VmUpdateView> {
        let now = Utc::now();
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), actor).await?;
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM grund_vms WHERE organisation_id=$1 AND vm_id=$2)",
        )
        .bind(organisation_id)
        .bind(vm_id)
        .fetch_one(&mut **work.sql())
        .await?;
        if !owned {
            return Err(VmUpdateError::NotFound.into());
        }
        let hash = identity("CancelVmUpdate", organisation_id, idempotency_key)?;
        let bytes = hex::decode(hash)?;
        let mut nonce_bytes: [u8; 16] = bytes[..16].try_into()?;
        nonce_bytes[6] = (nonce_bytes[6] & 0x0f) | 0x50;
        nonce_bytes[8] = (nonce_bytes[8] & 0x3f) | 0x80;
        let nonce = Uuid::from_bytes(nonce_bytes);
        let rollout = super::sweep(&mut work, now).await?;
        let row = facts(work.sql(), organisation_id, &[vm_id])
            .await?
            .pop()
            .ok_or(VmUpdateError::NotFound)?;
        let prior:Option<serde_json::Value>=sqlx::query_scalar(
            "SELECT attempt FROM grund_agent_update_completed_attempts WHERE attempt->>'organisation_id'=$1 \
             AND attempt->'operation'->>'launch_nonce'=$2 LIMIT 1")
            .bind(organisation_id.to_string()).bind(nonce.to_string()).fetch_optional(&mut **work.sql()).await?;
        let prior = prior
            .map(serde_json::from_value::<domain::VmAttempt>)
            .transpose()?;
        let active = rollout.active.as_ref().and_then(ActiveUpdate::vm);
        if let Some(prior) = prior.as_ref().or_else(|| {
            active.filter(|a| {
                a.organisation_id == organisation_id && a.operation.launch_nonce == nonce
            })
        }) {
            if prior.vm_id != vm_id || prior.id != attempt_id {
                return Err(VmUpdateError::AlreadyExists.into());
            }
            let observations =
                agents::runtime_observations(&mut **work.sql(), &[prior.guest_machine_id]).await?;
            let result = view(&self.state, &rollout, &row, &observations, Some(prior));
            work.commit().await?;
            return Ok(result);
        }
        if let Some(receipt) = work
            .completed_vm_update_attempt(organisation_id, attempt_id)
            .await?
        {
            if receipt.vm_id != vm_id {
                return Err(VmUpdateError::NotFound.into());
            }
            return Err(VmUpdateError::Blocked(
                "The update is already terminal; replay its original cancellation key",
            )
            .into());
        }
        let attempt = active
            .filter(|a| {
                a.organisation_id == organisation_id && a.vm_id == vm_id && a.id == attempt_id
            })
            .ok_or(VmUpdateError::NotFound)?;
        if !attempt.can_cancel() {
            return Err(VmUpdateError::Blocked(
                "This update must finish resolving before it can be changed",
            )
            .into());
        }
        apply(
            &mut work,
            domain::Command::Cancel {
                attempt_id,
                launch_nonce: nonce,
                recovery_deadline: now + Duration::minutes(5),
                at: now,
            },
        )
        .await?;
        publish(&self.state, &mut work, now).await?;
        let rollout = work.load_agent_updates().await?;
        let row = facts(work.sql(), organisation_id, &[vm_id])
            .await?
            .pop()
            .ok_or(VmUpdateError::NotFound)?;
        let observations =
            agents::runtime_observations(&mut **work.sql(), &[row.machine_id.unwrap_or_default()])
                .await?;
        let result = view(&self.state, &rollout, &row, &observations, None);
        work.commit().await?;
        self.state.wakes.documents_changed();
        Ok(result)
    }
}

async fn publish(state: &State, work: &mut Work<'_>, now: DateTime<Utc>) -> anyhow::Result<()> {
    let rollout = work.load_agent_updates().await?;
    let Some(attempt) = rollout.active.as_ref().and_then(ActiveUpdate::vm) else {
        return Ok(());
    };
    state
        .agents()
        .publish_in(work.sql(), attempt.host_machine_id)
        .await?;
    synchronize_document(work, attempt, now).await?;
    Ok(())
}

async fn synchronize_document(
    work: &mut Work<'_>,
    attempt: &domain::VmAttempt,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    let Some(document) = agents::document(&mut **work.sql(), attempt.host_machine_id).await? else {
        return Ok(());
    };
    let desired = agent::DesiredState::decode_from_slice(&document.payload)?;
    let mut vm_id_buffer = [0; 36];
    let mut attempt_id_buffer = [0; 36];
    let mut nonce_buffer = [0; 36];
    let vm_id: &str = attempt.vm_id.hyphenated().encode_lower(&mut vm_id_buffer);
    let attempt_id: &str = attempt.id.hyphenated().encode_lower(&mut attempt_id_buffer);
    let nonce: &str = attempt
        .operation
        .launch_nonce
        .hyphenated()
        .encode_lower(&mut nonce_buffer);
    let matching = desired
        .machines
        .iter()
        .find(|vm| vm.vm_id == vm_id)
        .and_then(|vm| vm.update.as_option())
        .is_some_and(|update| {
            update.attempt_id == attempt_id
                && update.sequence == attempt.operation.sequence
                && update.launch_nonce == nonce
        });
    if matching && attempt.operation.document_generation != Some(document.generation) {
        apply(
            work,
            domain::Command::DocumentPublished {
                attempt_id: attempt.id,
                operation_sequence: attempt.operation.sequence,
                generation: document.generation,
                at: now,
            },
        )
        .await?;
    }
    Ok(())
}

fn guest_proof(
    attempt: &domain::VmAttempt,
    observations: &[agents::RuntimeObservation],
    now: DateTime<Utc>,
) -> Option<domain::GuestBootProof> {
    if attempt.committed_at.is_none() && now >= attempt.deadline
        || attempt
            .committed_recovery_deadline
            .is_some_and(|deadline| now >= deadline)
    {
        return None;
    }
    let since = attempt
        .committed_health_required_after
        .unwrap_or(attempt.offered_at)
        .max(attempt.authorized_at.unwrap_or(attempt.offered_at));
    let launch = attempt.candidate_launch.as_ref()?;
    let observed = observations.iter().find(|o| {
        o.machine_id == attempt.guest_machine_id
            && o.registration_key == attempt.guest_registration_key
    })?;
    let heartbeat = observed
        .heartbeat
        .as_ref()
        .filter(|h| fresh(now, h.signed_at) && h.signed_at >= since && h.runtime_ready)?;
    let report = observed.report.as_ref().filter(|r| {
        fresh(now, r.signed_at)
            && r.signed_at >= since
            && r.applied_generation > 0
            && r.applied_generation == observed.current_generation
            && r.refusals.is_empty()
    })?;
    let boot = heartbeat.guest_boot.as_ref().filter(|b| {
        b.vm_id == attempt.vm_id
            && b.attempt_id == attempt.id
            && b.sequence == launch.sequence
            && b.launch_nonce == launch.launch_nonce
            && !b.os_boot_id.is_nil()
            && b.cpu_probe
            && b.memory_probe
            && b.attachment_probe
            && !b.probe_failed
    })?;
    Some(domain::GuestBootProof {
        guest_machine_id: attempt.guest_machine_id,
        guest_registration_key: attempt.guest_registration_key.clone(),
        attempt_id: attempt.id,
        attempt_sequence: attempt.sequence,
        launch_sequence: boot.sequence,
        launch_nonce: boot.launch_nonce,
        document_generation: launch.document_generation?,
        guest_document_generation: report.applied_generation,
        current_guest_document_generation: observed.current_generation,
        os_boot_id: boot.os_boot_id,
        pid1_context: boot.launch_nonce,
        image: attempt.target.identity(),
        runtime_ready: heartbeat.runtime_ready,
        cpu_probe: boot.cpu_probe,
        memory_probe: boot.memory_probe,
        attachment_probe: boot.attachment_probe,
        probe_failed: boot.probe_failed,
        observed_at: heartbeat.signed_at.min(report.signed_at),
    })
}

fn host_evidence(
    attempt: &domain::VmAttempt,
    observed: &agents::HostVmObservation,
) -> Option<domain::HostEvidence> {
    if !observed.reason.is_empty() && !matches!(observed.phase.as_str(), "committed" | "released") {
        return Some(domain::HostEvidence::Uncertain);
    }
    let image = domain::ImageIdentity {
        kernel_sha256: observed.kernel_sha256.clone(),
        rootfs_sha256: observed.rootfs_sha256.clone(),
    };
    match observed.phase.as_str() {
        "prepared" if attempt.operation.action == domain::Action::Prepare => {
            Some(domain::HostEvidence::Prepared {
                image,
                old_process: observed.previous_process.clone()?,
            })
        }
        "quiesced"
            if attempt.operation.action == domain::Action::Quiesce
                && observed.candidate_process.is_none() =>
        {
            Some(domain::HostEvidence::Quiesced {
                old_process: observed.previous_process.clone()?,
                old_process_exited: true,
                root_fenced: observed.old_root_fenced,
            })
        }
        "candidate_running" if attempt.operation.action == domain::Action::StartCandidate => {
            Some(domain::HostEvidence::CandidateRunning {
                process: observed.candidate_process.clone()?,
                image,
                fresh_instance_start: true,
            })
        }
        "committed" if attempt.operation.action == domain::Action::Commit => {
            if observed.candidate_process.is_some() && image != attempt.target.identity() {
                return None;
            }
            Some(domain::HostEvidence::Committed {
                process: observed.candidate_process.clone(),
            })
        }
        "released" if attempt.operation.action == domain::Action::ReleaseOld => {
            if observed.candidate_process.as_ref() != attempt.candidate_process.as_ref()
                || observed.candidate_process.is_none()
                || image != attempt.target.identity()
            {
                return Some(domain::HostEvidence::Uncertain);
            }
            Some(domain::HostEvidence::Released)
        }
        "rolled_back" if attempt.operation.action == domain::Action::Rollback => {
            if attempt.authorized_at.is_none() {
                Some(domain::HostEvidence::StagingCancelled {
                    old_process: observed.previous_process.clone()?,
                })
            } else {
                Some(domain::HostEvidence::RolledBack {
                    process: observed.previous_process.clone()?,
                    image,
                    candidate_exited: true,
                    root_restored: !observed.old_root_fenced,
                })
            }
        }
        "uncertain" | "failed" => Some(domain::HostEvidence::Uncertain),
        _ => None,
    }
}

async fn fail(
    work: &mut Work<'_>,
    attempt: &domain::VmAttempt,
    failure: domain::Failure,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    apply(
        work,
        domain::Command::Fail {
            attempt_id: attempt.id,
            failure,
            launch_nonce: Uuid::now_v7(),
            recovery_deadline: now + Duration::minutes(5),
            at: now,
        },
    )
    .await
}

pub(super) async fn reconcile(
    state: &State,
    work: &mut Work<'_>,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    let rollout = work.load_agent_updates().await?;
    let Some(initial) = rollout.active.as_ref().and_then(ActiveUpdate::vm).cloned() else {
        return Ok(());
    };
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("grund-apps-placement:{}", initial.organisation_id))
        .execute(&mut **work.sql())
        .await?;
    let mut document_ids = [initial.host_machine_id, initial.guest_machine_id];
    document_ids.sort_unstable();
    for id in document_ids {
        agents::lock_generation(work.sql(), id).await?;
    }
    synchronize_document(work, &initial, now).await?;
    let mut changed = false;
    for _ in 0..12 {
        let rollout = work.load_agent_updates().await?;
        let Some(attempt) = rollout.active.as_ref().and_then(ActiveUpdate::vm).cloned() else {
            state
                .agents()
                .publish_in(work.sql(), initial.host_machine_id)
                .await?;
            state
                .agents()
                .publish_in(work.sql(), initial.guest_machine_id)
                .await?;
            return Ok(());
        };
        let Some(row) = facts(work.sql(), attempt.organisation_id, &[attempt.vm_id])
            .await?
            .pop()
        else {
            fail(work, &attempt, domain::Failure::Uncertain, now).await?;
            return Ok(());
        };
        let observations = agents::runtime_observations(
            &mut **work.sql(),
            &[attempt.host_machine_id, attempt.guest_machine_id],
        )
        .await?;
        let registered = row.host_registration.as_deref()
            == Some(attempt.host_registration_key.as_str())
            && row.guest_registration.as_deref() == Some(attempt.guest_registration_key.as_str())
            && row.machine_id == Some(attempt.guest_machine_id);
        if !registered {
            fail(work, &attempt, domain::Failure::Uncertain, now).await?;
            return Ok(());
        }
        let host = observations
            .iter()
            .find(|o| o.machine_id == attempt.host_machine_id);
        let host_report = host.and_then(|o| {
            o.report.as_ref().filter(|r| {
                fresh(now, r.signed_at)
                    && r.signed_at >= attempt.offered_at
                    && r.applied_generation == o.current_generation
                    && Some(r.applied_generation) == attempt.operation.document_generation
            })
        });
        let host_observed = host_report.and_then(|r| {
            r.vm_updates.iter().find(|v| {
                v.vm_id == attempt.vm_id
                    && v.attempt_id == attempt.id
                    && v.sequence == attempt.operation.sequence
                    && v.launch_nonce == attempt.operation.launch_nonce
            })
        });
        let mut next = None;
        let proof = guest_proof(&attempt, &observations, now);
        let current_health = proof.is_some();
        if attempt.guest_boot_proof.is_some() && !current_health {
            next = Some(domain::Command::InvalidateGuest {
                attempt_id: attempt.id,
                at: now,
            });
        } else if matches!(
            attempt.phase,
            domain::Phase::CandidateRunning
                | domain::Phase::Verifying
                | domain::Phase::Committed
                | domain::Phase::Releasing
        ) && let Some(proof) = proof
            && attempt.guest_boot_proof.as_ref() != Some(&proof)
        {
            next = Some(domain::Command::VerifyGuest {
                attempt_id: attempt.id,
                proof,
                at: now,
            });
        }
        if next.is_none()
            && let (Some(observed), Some(fence)) = (host_observed, attempt.fence())
            && let Some(evidence) = host_evidence(&attempt, observed)
            && (now < attempt.operation.deadline
                || matches!(
                    attempt.operation.action,
                    domain::Action::Commit | domain::Action::ReleaseOld | domain::Action::Rollback
                ))
        {
            let relevant = matches!(
                (&attempt.phase, &evidence),
                (
                    domain::Phase::Preparing,
                    domain::HostEvidence::Prepared { .. }
                ) | (
                    domain::Phase::Quiescing,
                    domain::HostEvidence::Quiesced { .. }
                ) | (
                    domain::Phase::Starting,
                    domain::HostEvidence::CandidateRunning { .. }
                ) | (
                    domain::Phase::Committing,
                    domain::HostEvidence::Committed { .. }
                ) | (
                    domain::Phase::RollingBack,
                    domain::HostEvidence::RolledBack { .. }
                ) | (
                    domain::Phase::Cancelling,
                    domain::HostEvidence::StagingCancelled { .. }
                )
            ) || current_health
                && matches!(
                    (&attempt.phase, &evidence),
                    (domain::Phase::Releasing, domain::HostEvidence::Released)
                )
                || matches!(evidence, domain::HostEvidence::Uncertain)
                    && attempt.failure != Some(domain::Failure::Uncertain)
                || matches!(attempt.phase, domain::Phase::Committed)
                    && observed.candidate_process.is_none()
                    && attempt.guest_boot_proof.is_some();
            if relevant {
                next = Some(domain::Command::HostAcknowledged {
                    fence,
                    evidence,
                    at: now,
                });
            }
        }
        let external_evidence = next.is_some();
        if next.is_none() {
            let paused = state.config.agent_updates_paused
                || !state.config.vm_updates_enabled
                || rollout.paused;
            let held = rollout
                .migration_holds
                .contains_key(&attempt.host_machine_id)
                || rollout
                    .migration_holds
                    .contains_key(&attempt.guest_machine_id);
            next = match attempt.phase {
                domain::Phase::Prepared if !paused && !held && now < attempt.operation.deadline => {
                    Some(domain::Command::BeginDrain {
                        attempt_id: attempt.id,
                        at: now,
                    })
                }
                domain::Phase::Draining
                    if !paused
                        && !held
                        && now < attempt.operation.deadline
                        && !row.has_local_volumes
                        && !row.has_allocations =>
                {
                    let guest = observations
                        .iter()
                        .find(|o| o.machine_id == attempt.guest_machine_id);
                    guest
                        .and_then(|g| {
                            g.report.as_ref().filter(|r| {
                                fresh(now, r.signed_at)
                                    && r.signed_at >= attempt.offered_at
                                    && r.reports_replicas
                                    && !r.replicas_running
                                    && r.refusals.is_empty()
                                    && r.applied_generation > 0
                                    && r.applied_generation == g.current_generation
                            })
                        })
                        .map(|report| domain::Command::AuthorizeQuiesce {
                            attempt_id: attempt.id,
                            proof: domain::DrainProof {
                                guest_machine_id: attempt.guest_machine_id,
                                guest_registration_key: attempt.guest_registration_key.clone(),
                                host_registration_key: attempt.host_registration_key.clone(),
                                document_generation: attempt
                                    .operation
                                    .document_generation
                                    .unwrap_or_default(),
                                guest_document_generation: report.applied_generation,
                                current_guest_document_generation: report.applied_generation,
                                drained: true,
                                has_allocations: row.has_allocations,
                                has_local_volumes: row.has_local_volumes,
                                observed_at: report.signed_at,
                            },
                            launch_nonce: Uuid::now_v7(),
                            deadline: now + Duration::minutes(10),
                            at: now,
                        })
                }
                domain::Phase::Quiesced if now < attempt.operation.deadline => {
                    Some(domain::Command::StartCandidate {
                        attempt_id: attempt.id,
                        launch_nonce: Uuid::now_v7(),
                        at: now,
                    })
                }
                domain::Phase::Verifying
                    if current_health
                        && attempt.failure.is_none()
                        && now < attempt.operation.deadline =>
                {
                    Some(domain::Command::Commit {
                        attempt_id: attempt.id,
                        at: now,
                    })
                }
                domain::Phase::Committed
                    if current_health
                        && attempt
                            .guest_boot_proof
                            .as_ref()
                            .is_some_and(|p| fresh(now, p.observed_at))
                        && host_observed.is_some_and(|o| {
                            o.candidate_process.as_ref() == attempt.candidate_process.as_ref()
                                && o.candidate_process.is_some()
                                && o.kernel_sha256 == attempt.target.kernel_sha256
                                && o.rootfs_sha256 == attempt.target.rootfs_sha256
                        }) =>
                {
                    Some(domain::Command::ReleaseOld {
                        attempt_id: attempt.id,
                        at: now,
                    })
                }
                domain::Phase::Committed | domain::Phase::Releasing
                    if attempt.committed_at.is_some()
                        && attempt.committed_restart_at.is_none()
                        && host_observed.is_some_and(|o| o.candidate_process.is_none())
                        && host
                            .and_then(|o| o.heartbeat.as_ref())
                            .is_some_and(|h| fresh(now, h.signed_at) && h.runtime_ready) =>
                {
                    Some(domain::Command::RestartCommitted {
                        attempt_id: attempt.id,
                        launch_nonce: Uuid::now_v7(),
                        deadline: now + Duration::minutes(5),
                        at: now,
                    })
                }
                _ => None,
            };
        }
        if next.is_none()
            && now >= attempt.operation.deadline
            && attempt.failure != Some(domain::Failure::Uncertain)
        {
            next = Some(domain::Command::Fail {
                attempt_id: attempt.id,
                failure: domain::Failure::Timeout,
                launch_nonce: Uuid::now_v7(),
                recovery_deadline: now + Duration::minutes(5),
                at: now,
            });
        }
        let Some(command) = next else {
            break;
        };
        let events = match work
            .agent_updates(agent_updates::Command::Vm(command))
            .await
        {
            Ok(events) => events,
            Err(grund_store::work::WorkError::AgentUpdates(
                agent_updates::Error::UnsafeVm
                | agent_updates::Error::StaleFence
                | agent_updates::Error::InvalidPhase
                | agent_updates::Error::Expired,
            )) if external_evidence => {
                if now >= attempt.operation.deadline
                    && attempt.failure != Some(domain::Failure::Uncertain)
                {
                    fail(work, &attempt, domain::Failure::Timeout, now).await?;
                    publish(state, work, now).await?;
                }
                break;
            }
            Err(error) => return Err(error.into()),
        };
        if events.is_empty() {
            break;
        }
        changed = true;
        let after = work.load_agent_updates().await?;
        if after
            .active
            .as_ref()
            .and_then(ActiveUpdate::vm)
            .is_some_and(|a| a.phase == domain::Phase::Draining)
            && attempt.phase != domain::Phase::Draining
        {
            state
                .agents()
                .publish_in(work.sql(), attempt.guest_machine_id)
                .await?;
        }
        let operation_changed = after
            .active
            .as_ref()
            .and_then(ActiveUpdate::vm)
            .is_some_and(|a| a.operation.sequence != attempt.operation.sequence);
        if operation_changed {
            publish(state, work, now).await?;
            break;
        }
    }
    if changed {
        let active = work.load_agent_updates().await?.active;
        if active.is_none() {
            state
                .agents()
                .publish_in(work.sql(), initial.host_machine_id)
                .await?;
            state
                .agents()
                .publish_in(work.sql(), initial.guest_machine_id)
                .await?;
        }
    }
    Ok(())
}
