//! The control link's server side (grund-docs design/machines.md §7b):
//! authenticating a machine's requests by its key, heartbeats, each machine's
//! signed desired state, the join tokens its VMs boot with, what it reports,
//! and the VMs an organisation runs on its own machines.

use base64::{Engine, engine::general_purpose::STANDARD};
use buffa::Message;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use grund_config::names::MachineName;
use grund_domain::machine::{CLOCK_SKEW, KeyPurpose, MAX_MACHINES_PER_ORGANISATION, prefix};
use grund_proto::grund::agent::v1 as agent;
use grund_store::{
    agents::{self, DocumentRow, NewVm, VmRow},
    entry,
    machines::{self, MachineRow},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    keys::KeysState,
    services::entry::EntryState,
    services::machines::{MachinesState, MintOutcome, Minted},
    services::volumes::VolumesState,
    state::State,
};

/// A machine whose heartbeat is older than this is shown as not connected
/// (apps.md §9.2's unreachable threshold).
pub const CONNECTED_WITHIN: Duration = Duration::seconds(30);

/// How often an agent is asked to send a heartbeat.
pub const HEARTBEAT_INTERVAL_SECONDS: i32 = 5;

/// The longest WatchDesiredState waits for a newer document: below the
/// agent's call deadline, so the instance answers first.
pub const LONG_POLL: std::time::Duration = std::time::Duration::from_secs(10);

/// The purpose prefix of an agent request's signature.
pub const REQUEST_PREFIX: &str = "grund-agent-request-v1\n";

/// Whether a three-part numeric agent version precedes this server's version.
/// Unknown and prerelease versions do not establish update ordering.
pub fn outdated_version(version: &str) -> bool {
    fn parts(version: &str) -> Option<[u64; 3]> {
        let mut parts = version.split('.');
        let parsed = [
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        ];
        parts.next().is_none().then_some(parsed)
    }
    parts(version)
        .zip(parts(crate::health::VERSION))
        .is_some_and(|(version, current)| version < current)
}

/// The public agent revision, including when the hosted server adds its own prefix.
pub fn expected_agent_revision() -> &'static str {
    crate::health::revision()
        .rsplit('+')
        .next()
        .unwrap_or("unknown")
}

/// The machine a control-link request is from, as its signature proved.
#[derive(Debug, Clone)]
pub struct MachineCaller {
    pub machine_id: Uuid,
    /// The organisation whose pool the machine is in now, if any.
    pub organisation_id: Option<Uuid>,
    /// First twelve ASCII hex bytes of the verified iroh endpoint key.
    pub endpoint_key_prefix: [u8; 12],
    /// The complete registration public key that authenticated this request.
    pub registration_key: String,
    /// Original timestamp covered by the verified request signature.
    pub signed_at: DateTime<Utc>,
}

/// VM states and replacement receipts from one applied desired document.
pub struct VmReports<'a> {
    pub states: &'a [(Uuid, &'static str, Option<String>)],
    pub updates: &'a [agents::HostVmObservation],
}

/// The bytes an agent signs for one request.
pub fn request_message(path: &str, signed_at: i64, body: &[u8]) -> Vec<u8> {
    format!(
        "{REQUEST_PREFIX}{path}\n{signed_at}\n{}",
        hex::encode(Sha256::digest(body))
    )
    .into_bytes()
}

/// Whether the machine is connected, from when it was last seen.
pub fn connected(last_seen_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    last_seen_at.is_some_and(|seen| now - seen <= CONNECTED_WITHIN)
}

/// One replica as an agent reports it.
#[derive(Debug, Clone)]
pub struct ReplicaReport {
    pub replica_id: Uuid,
    /// One of grund_replica_status's states.
    pub state: &'static str,
    pub ready: bool,
    pub ready_for_ms: u64,
    pub restarts: u32,
    pub last_exit_code: i32,
    pub reason: String,
    pub idle: bool,
    pub applied_generation: u64,
    pub operation_id: Option<Uuid>,
}

/// A VM to place, as the caller asked for it.
#[derive(Debug, Clone)]
pub struct VmRequest {
    pub host_machine_id: Uuid,
    pub name: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub disk_gib: u32,
    pub kernel_url: String,
    pub kernel_sha256: String,
    pub rootfs_url: String,
    pub rootfs_sha256: String,
}

/// How placing or stopping a VM ended.
#[derive(Debug)]
pub enum VmOutcome {
    Done(Box<VmRow>),
    NotFound,
    /// The host has not reported what running a VM that registers needs.
    CannotHost(String),
    Invalid(String),
    NameTaken,
    PoolFull,
}

/// Control-link flows.
#[derive(Clone)]
pub struct Agents {
    state: State,
}

impl Agents {
    /// The machine that signed this request, or `None` for a missing, stale
    /// or wrong signature, an unknown machine and a revoked one alike.
    pub async fn authenticate(
        &self,
        machine: &str,
        signed_at: &str,
        signature: &str,
        path: &str,
        body: &[u8],
    ) -> anyhow::Result<Option<MachineCaller>> {
        let (Ok(machine_id), Ok(signed_at)) = (Uuid::parse_str(machine), signed_at.parse::<i64>())
        else {
            return Ok(None);
        };
        let Some(at) = DateTime::from_timestamp(signed_at, 0) else {
            return Ok(None);
        };
        if (at - Utc::now()).abs() > CLOCK_SKEW {
            return Ok(None);
        }
        let Some(signature) = STANDARD
            .decode(signature)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
        else {
            return Ok(None);
        };
        let Some(row) = machines::machine(&self.state.pool, machine_id).await? else {
            return Ok(None);
        };
        let Some(key) = row
            .public_key
            .as_deref()
            .and_then(|hex| hex::decode(hex).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        else {
            return Ok(None);
        };
        if row.state == "revoked"
            || key
                .verify_strict(
                    &request_message(path, signed_at, body),
                    &Signature::from_bytes(&signature),
                )
                .is_err()
        {
            return Ok(None);
        }
        let endpoint_key_prefix = row.public_key.as_ref().unwrap().as_bytes()[..12]
            .try_into()
            .expect("verified endpoint key has twelve hex bytes");
        Ok(Some(MachineCaller {
            machine_id,
            organisation_id: row.pool_organisation_id,
            endpoint_key_prefix,
            registration_key: row.public_key.expect("verified registration has a key"),
            signed_at: at,
        }))
    }

    /// Records a heartbeat and answers the machine's current generation.
    pub async fn heartbeat(
        &self,
        caller: &MachineCaller,
        agent_version: &str,
        capabilities: &serde_json::Value,
        runtime_ready: bool,
        guest_boot: Option<agents::GuestBootObservation>,
    ) -> anyhow::Result<i64> {
        let version: String = agent_version.chars().take(64).collect();
        let recovering = agents::heartbeat(
            &self.state.pool,
            caller.machine_id,
            &version,
            capabilities,
            Utc::now(),
        )
        .await?;
        agents::record_runtime_heartbeat(
            &self.state.pool,
            caller.machine_id,
            &agents::RuntimeHeartbeat {
                registration_key: caller.registration_key.clone(),
                signed_at: caller.signed_at,
                runtime_ready,
                guest_boot,
            },
        )
        .await?;
        if recovering {
            self.finish_migration_settling(caller.machine_id).await?;
        }
        Ok(agents::document(&self.state.pool, caller.machine_id)
            .await?
            .map_or(0, |d| d.generation))
    }

    /// The machine's document, if newer than `since` and of the organisation
    /// whose pool the machine is in now: a machine whose lease ended, or that
    /// another organisation leased since, is never handed the old lessee's.
    pub async fn desired_state(
        &self,
        caller: &MachineCaller,
        since: u64,
    ) -> anyhow::Result<Option<DocumentRow>> {
        let Some(organisation_id) = caller.organisation_id else {
            return Ok(None);
        };
        Ok(agents::document(&self.state.pool, caller.machine_id)
            .await?
            .filter(|document| document.generation as u64 > since)
            .filter(|document| {
                agent::DesiredState::decode_from_slice(&document.payload)
                    .is_ok_and(|state| state.organisation_id == organisation_id.to_string())
            }))
    }

    /// The machine's document once it is newer than `since`: at once if it
    /// is, otherwise when a change to it commits, or `None` after
    /// [`LONG_POLL`].
    pub async fn watch_desired_state(
        &self,
        caller: &MachineCaller,
        since: u64,
    ) -> anyhow::Result<Option<DocumentRow>> {
        let deadline = tokio::time::Instant::now() + LONG_POLL;
        let mut wakes = self.state.wakes.subscribe();
        loop {
            if let Some(document) = self.desired_state(caller, since).await? {
                return Ok(Some(document));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(None);
            }
            crate::wakes::Wakes::wait(&mut wakes).await;
        }
    }

    /// The join token for a VM the calling machine hosts and should run, that
    /// has not registered yet.
    pub async fn join_token(
        &self,
        caller: &MachineCaller,
        vm_id: Uuid,
    ) -> anyhow::Result<Option<Minted>> {
        let Some(vm) = agents::vm(&self.state.pool, vm_id).await? else {
            return Ok(None);
        };
        if vm.host_machine_id != caller.machine_id
            || vm.state != "running"
            || vm.machine_id.is_some()
        {
            return Ok(None);
        }
        Ok(
            match self
                .state
                .machines()
                .mint_for_vm(vm.organisation_id, vm.vm_id, &vm.name, caller.machine_id)
                .await?
            {
                MintOutcome::Minted(minted) => Some(minted),
                _ => None,
            },
        )
    }

    /// Records what the machine reports running: its VMs, and its replicas
    /// when it reports them. A change the app reconciler decides on wakes it.
    pub async fn report(
        &self,
        caller: &MachineCaller,
        applied_generation: u64,
        observed: VmReports<'_>,
        refusals: &[String],
        replicas: Option<&[ReplicaReport]>,
        volume_deletions: &[(Uuid, Uuid)],
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        if let Some(replicas) = replicas {
            let reports: Vec<grund_store::apps::Report<'_>> = replicas
                .iter()
                .take(400)
                .map(|r| grund_store::apps::Report {
                    replica_id: r.replica_id,
                    state: r.state,
                    ready: r.ready,
                    ready_since: r.ready.then(|| {
                        now - Duration::milliseconds(
                            i64::try_from(r.ready_for_ms)
                                .unwrap_or(i64::MAX / 2)
                                .min(86_400_000 * 365),
                        )
                    }),
                    restarts: i32::try_from(r.restarts).unwrap_or(i32::MAX),
                    last_exit_code: r.last_exit_code,
                    reason: &r.reason,
                    idle: r.idle,
                })
                .collect();
            let mut connection = self.state.pool.acquire().await?;
            if grund_store::apps::record_reports(&mut connection, caller.machine_id, &reports, now)
                .await?
            {
                self.state.wakes.apps_changed();
            }
            if let Some(org) = caller.organisation_id {
                let mut received = false;
                for report in replicas
                    .iter()
                    .take(400)
                    .filter(|r| matches!(r.state, "exited" | "failed"))
                {
                    let (Some(operation_id), Ok(generation)) = (
                        report.operation_id,
                        i64::try_from(report.applied_generation),
                    ) else {
                        continue;
                    };
                    received |= grund_store::apps::record_stack_receipt(
                        &mut connection,
                        org,
                        caller.machine_id,
                        report.replica_id,
                        generation,
                        operation_id,
                    )
                    .await?;
                }
                if received {
                    self.state.wakes.apps_changed();
                    self.state.wakes.documents_changed();
                }
            }
        }
        let refusals: Vec<String> = refusals
            .iter()
            .take(20)
            .map(|r| r.chars().take(300).collect())
            .collect();
        let applied_generation = i64::try_from(applied_generation)?;
        let runtime = agents::RuntimeReport {
            registration_key: caller.registration_key.clone(),
            signed_at: caller.signed_at,
            applied_generation,
            reports_replicas: replicas.is_some(),
            replicas_running: replicas.is_some_and(|reports| {
                reports
                    .iter()
                    .any(|report| !matches!(report.state, "exited" | "failed" | "refused"))
            }),
            refusals: refusals.clone(),
            vm_updates: observed.updates.iter().take(200).cloned().collect(),
        };
        agents::report_authenticated(
            &self.state.pool,
            caller.machine_id,
            &serde_json::json!(refusals),
            observed.states,
            now,
            &runtime,
        )
        .await?;
        if let Some(org) = caller.organisation_id {
            for (app_id, volume_id) in volume_deletions.iter().take(400) {
                self.state
                    .volumes()
                    .acknowledge(org, caller.machine_id, *app_id, *volume_id)
                    .await?;
            }
        }
        if replicas.is_some() {
            self.finish_migration_settling(caller.machine_id).await?;
        }
        Ok(())
    }

    async fn finish_migration_settling(&self, machine_id: Uuid) -> anyhow::Result<()> {
        if let Some(migration_id) =
            entry::finish_settled_pause(&self.state.pool, machine_id).await?
        {
            tracing::info!(%machine_id, %migration_id, "migration settled after ready agent report");
            self.state.wakes.documents_changed();
        }
        Ok(())
    }

    /// Signs the next document for `host_machine_id` and wakes its long
    /// poll. Nothing for a machine in no organisation's pool.
    pub async fn publish(&self, host_machine_id: Uuid) -> anyhow::Result<()> {
        let mut tx = self.state.pool.begin().await?;
        self.publish_in(&mut tx, host_machine_id).await?;
        tx.commit().await?;
        self.state.wakes.documents_changed();
        Ok(())
    }

    /// Signs the next document for `host_machine_id`, from its VMs and its
    /// replicas, with its organisation's key, inside the caller's
    /// transaction: the document commits with the decision that changed it
    /// (apps.md §6.1). The caller wakes the long polls after its commit.
    pub async fn publish_in(
        &self,
        connection: &mut sqlx::PgConnection,
        host_machine_id: Uuid,
    ) -> anyhow::Result<()> {
        let Some(host) = machines::machine(&mut *connection, host_machine_id).await? else {
            return Ok(());
        };
        let Some(organisation_id) = host.pool_organisation_id else {
            return Ok(());
        };
        let placement: bool = sqlx::query_scalar(
            "SELECT CASE WHEN EXISTS(SELECT 1 FROM grund_stack_members WHERE organisation_id=$2) \
             THEN pg_try_advisory_xact_lock(hashtextextended($1,0)) ELSE true END",
        )
        .bind(format!("grund-apps-placement:{organisation_id}"))
        .bind(organisation_id)
        .fetch_one(&mut *connection)
        .await?;
        anyhow::ensure!(
            placement,
            "app placement changed; retry publishing the document"
        );
        let generation = agents::lock_generation(&mut *connection, host_machine_id).await? + 1;
        let previous = agents::document(&mut *connection, host_machine_id)
            .await?
            .and_then(|document| agent::DesiredState::decode_from_slice(&document.payload).ok());
        let vms = agents::hosted_vms(&mut *connection, host_machine_id).await?;
        let active = agents::active_vm_update(&mut *connection, host_machine_id)
            .await?
            .filter(|attempt| {
                attempt.organisation_id == organisation_id
                    && host.public_key.as_deref() == Some(attempt.host_registration_key.as_str())
            });
        let placed = grund_store::apps::machine_replicas(&mut *connection, host_machine_id).await?;
        let mounts = grund_store::volumes::machine_mounts(
            &mut *connection,
            organisation_id,
            host_machine_id,
        )
        .await?;
        let cleanup = grund_store::volumes::pending_cleanup(
            &mut *connection,
            organisation_id,
            host_machine_id,
        )
        .await?;
        let key = self
            .state
            .keys()
            .ensure(
                &mut *connection,
                KeyPurpose::Organisation,
                Some(organisation_id),
            )
            .await?;
        let now = Utc::now();
        let machines: Vec<agent::Vm> = vms
            .iter()
            .map(|vm| {
                let mut message = vm_message(vm);
                if let Some(attempt) = active.as_ref().filter(|attempt| attempt.vm_id == vm.vm_id) {
                    message.state = agent::VmDesiredState::VM_DESIRED_STATE_RUNNING.into();
                    message.update = vm_update_message(attempt).into();
                }
                message
            })
            .collect();
        let entry = self.state.entry();
        let slug = grund_store::entry::organisation_slug(&mut *connection, organisation_id)
            .await?
            .unwrap_or_default();
        let mut addresses: std::collections::HashMap<Uuid, Option<String>> = Default::default();
        let mut custom: std::collections::HashMap<Uuid, Vec<String>> = Default::default();
        let mut replicas: Vec<agent::Replica> = Vec::with_capacity(placed.len());
        let volume_backend = self.state.volume_backend();
        for row in &placed {
            let mut replica = replica_message(row);
            if let Some(member) =
                grund_store::stacks::member(&mut *connection, organisation_id, row.app_id).await?
            {
                let stack =
                    grund_store::stacks::get(&mut *connection, organisation_id, member.stack_id)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("stack member has no owning stack"))?;
                let settings = stack
                    .state
                    .0
                    .revisions
                    .get(&stack.state.0.desired_revision)
                    .and_then(|revision| revision.services.get(&member.service))
                    .or_else(|| {
                        stack
                            .state
                            .0
                            .revisions
                            .values()
                            .rev()
                            .find_map(|revision| revision.services.get(&member.service))
                    })
                    .map(|service| &service.settings)
                    .ok_or_else(|| anyhow::anyhow!("stack member has no service settings"))?;
                replica.exclusive = member.exclusive;
                replica.stopping = member.stopping || row.state == "draining";
                replica.drain_seconds = Some(settings.rollout.drain_seconds);
                replica.operation_id = member
                    .operation_id
                    .map(|id| id.to_string())
                    .unwrap_or_default();
                replica.stack_search = format!("{}.grund.internal", stack.state.0.name);
                let newly_stopping = replica.stopping
                    && !previous.as_ref().is_some_and(|document| {
                        document.replicas.iter().any(|old| {
                            old.replica_id == replica.replica_id
                                && old.stopping
                                && old.operation_id == replica.operation_id
                        })
                    });
                if newly_stopping {
                    sqlx::query("DELETE FROM grund_replica_status WHERE replica_id=$1")
                        .bind(row.replica_id)
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("DELETE FROM grund_stack_receipts WHERE organisation_id=$1 AND stack_id=$2 AND replica_id=$3")
                        .bind(organisation_id).bind(member.stack_id).bind(row.replica_id)
                        .execute(&mut *connection).await?;
                }
                if replica.stopping && (member.required_generation == 0 || newly_stopping) {
                    sqlx::query(
                        "UPDATE grund_stack_members SET required_generation=$3 \
                        WHERE organisation_id=$1 AND app_id=$2 AND operation_id=$4",
                    )
                    .bind(organisation_id)
                    .bind(row.app_id)
                    .bind(generation)
                    .bind(member.operation_id)
                    .execute(&mut *connection)
                    .await?;
                }
            }
            let mut awaiting_block_receipt = false;
            for spec in &row.spec.0.volumes {
                let Some(mount) = mounts
                    .iter()
                    .find(|v| v.app_id == row.app_id && v.name == spec.name)
                else {
                    if spec.size_gib.is_some() {
                        awaiting_block_receipt = true;
                        break;
                    }
                    anyhow::bail!(
                        "volume {} of app {} is not attached to its placement machine",
                        spec.name,
                        row.app_id
                    );
                };
                if spec.size_gib.is_some() {
                    if mount.status != "attached"
                        || mount.slot.is_none()
                        || mount.size_gib != spec.size_gib.map(|size| size as i64)
                    {
                        awaiting_block_receipt = true;
                        break;
                    }
                    let ready = match &volume_backend {
                        Some(backend) => backend.mount_ready(connection, mount).await?,
                        None => false,
                    };
                    if !ready {
                        awaiting_block_receipt = true;
                        break;
                    }
                }
                anyhow::ensure!(
                    mount.path == spec.path && mount.source == spec.source,
                    "volume {} of app {} does not match release mount",
                    spec.name,
                    row.app_id
                );
                replica.volumes.push(agent::VolumeMount {
                    volume_id: mount.volume_id.to_string(),
                    name: spec.name.clone(),
                    path: spec.path.clone(),
                    source: spec.source.clone().unwrap_or_default(),
                    block_device: spec.size_gib.is_some(),
                    ..Default::default()
                });
            }
            if awaiting_block_receipt {
                continue;
            }
            if crate::services::entry::publishes(&row.spec.0) {
                if let std::collections::hash_map::Entry::Vacant(slot) = addresses.entry(row.app_id)
                {
                    slot.insert(
                        entry
                            .address(&mut *connection, row.app_id, &row.app_name, &slug)
                            .await?,
                    );
                }
                if let std::collections::hash_map::Entry::Vacant(slot) = custom.entry(row.app_id) {
                    slot.insert(
                        if grund_store::entry::public_name(&mut *connection, row.app_id)
                            .await?
                            .is_some()
                        {
                            grund_store::domains::names_of_app(&mut *connection, row.app_id).await?
                        } else {
                            Vec::new()
                        },
                    );
                }
                replica.hostnames = addresses[&row.app_id]
                    .iter()
                    .chain(custom[&row.app_id].iter())
                    .cloned()
                    .collect();
            }
            replicas.push(replica);
        }
        let entry_keys = entry.entry_keys(&mut *connection).await?;
        let mut required_features = Vec::new();
        if !machines.is_empty() {
            required_features.push("machines".to_string());
        }
        if !replicas.is_empty() {
            required_features.push("replicas".to_string());
        }
        if replicas.iter().any(|r| !r.volumes.is_empty()) || !cleanup.is_empty() {
            required_features.push("volumes".to_string());
        }
        if replicas
            .iter()
            .any(|r| r.volumes.iter().any(|v| v.block_device))
        {
            required_features.push("block-volumes".to_string());
        }
        if replicas
            .iter()
            .any(|replica| !replica.stack_search.is_empty())
        {
            required_features.push("stack-services".into());
        }
        let payload = agent::DesiredState {
            machine_id: host_machine_id.to_string(),
            organisation_id: organisation_id.to_string(),
            generation: generation as u64,
            issued_at_unix: now.timestamp(),
            required_features,
            machines,
            replicas,
            entry_keys,
            volume_deletions: cleanup
                .iter()
                .map(|item| agent::VolumeDeletion {
                    volume_id: item.volume_id.to_string(),
                    app_id: item.app_id.to_string(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
        .encode_to_vec();
        anyhow::ensure!(
            payload.len() <= 1024 * 1024,
            "the document for machine {host_machine_id} would be larger than 1 MiB"
        );
        let signature = self
            .state
            .keys()
            .sign(key.key_id, prefix::DESIRED_STATE, &payload);
        agents::store_document(
            &mut *connection,
            host_machine_id,
            generation,
            key.key_id,
            &payload,
            &signature,
            now,
        )
        .await?;
        Ok(())
    }

    /// Places a VM on one of the organisation's machines, and publishes that
    /// machine's next document.
    pub async fn run_vm(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        request: &VmRequest,
    ) -> anyhow::Result<VmOutcome> {
        let mut tx = self.state.pool.begin().await?;
        let live: Option<Uuid> = sqlx::query_scalar(
            "SELECT organisation_id FROM grund_organisations WHERE organisation_id=$1 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(organisation_id)
        .fetch_optional(&mut *tx)
        .await?;
        if live.is_none() {
            return Ok(VmOutcome::NotFound);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("grund-apps-placement:{organisation_id}"))
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT 1 FROM grund_machines WHERE machine_id=$1 AND pool_organisation_id=$2 FOR UPDATE",
        )
        .bind(request.host_machine_id)
        .bind(organisation_id)
        .execute(&mut *tx)
        .await?;
        let Some(host) =
            machines::organisation_machine(&mut *tx, organisation_id, request.host_machine_id)
                .await?
        else {
            return Ok(VmOutcome::NotFound);
        };
        if let Some(refusal) = cannot_host(&host) {
            return Ok(VmOutcome::CannotHost(refusal));
        }
        let name = match MachineName::parse(&request.name) {
            Ok(name) => name,
            Err(error) => return Ok(VmOutcome::Invalid(format!("name: {error}"))),
        };
        if let Some(problem) = invalid(request) {
            return Ok(VmOutcome::Invalid(problem));
        }
        let reservations =
            grund_store::apps::reservations(&mut *tx, organisation_id, Uuid::nil()).await?;
        let capacity = crate::services::apps::machine_view(
            &host,
            reservations
                .iter()
                .find(|reservation| reservation.machine_id == request.host_machine_id),
        );
        let memory_mib = u64::from(request.memory_mib) + agents::VM_MEMORY_OVERHEAD_MIB as u64;
        let cpu_millis = request.vcpus * 1000;
        if memory_mib
            > capacity
                .allocatable_memory_mib()
                .saturating_sub(capacity.reserved_memory_mib)
            || cpu_millis
                > capacity
                    .allocatable_cpu_millis()
                    .saturating_sub(capacity.reserved_cpu_millis)
        {
            return Ok(VmOutcome::CannotHost(
                "That machine has insufficient unreserved CPU or memory for this VM and its overhead.".into(),
            ));
        }
        let pool = machines::organisation_machines(&mut *tx, organisation_id).await?;
        if pool
            .iter()
            .any(|m| m.pool_name.as_deref() == Some(name.as_str()))
        {
            return Ok(VmOutcome::NameTaken);
        }
        let running = agents::organisation_vms(&mut *tx, organisation_id)
            .await?
            .iter()
            .filter(|vm| vm.state == "running" && vm.machine_id.is_none())
            .count() as i64;
        if pool.len() as i64 + running >= MAX_MACHINES_PER_ORGANISATION {
            return Ok(VmOutcome::PoolFull);
        }
        let vm_id = Uuid::now_v7();
        let inserted = agents::insert_vm(
            &mut *tx,
            &NewVm {
                vm_id,
                organisation_id,
                host_machine_id: request.host_machine_id,
                name: name.as_str(),
                vcpus: request.vcpus as i32,
                memory_mib: request.memory_mib as i32,
                disk_gib: request.disk_gib as i32,
                kernel_url: &request.kernel_url,
                kernel_sha256: &request.kernel_sha256,
                rootfs_url: &request.rootfs_url,
                rootfs_sha256: &request.rootfs_sha256,
                created_by: actor,
            },
        )
        .await;
        match inserted {
            Ok(()) => {}
            Err(error)
                if error.as_database_error().and_then(|e| e.constraint())
                    == Some("grund_vms_name_idx") =>
            {
                return Ok(VmOutcome::NameTaken);
            }
            Err(error) => return Err(error.into()),
        }
        self.publish_in(&mut tx, request.host_machine_id).await?;
        tx.commit().await?;
        self.state.wakes.documents_changed();
        Ok(match agents::vm(&self.state.pool, vm_id).await? {
            Some(vm) => VmOutcome::Done(Box::new(vm)),
            None => VmOutcome::NotFound,
        })
    }

    /// Asks the organisation's VM to stop, and publishes its host's next
    /// document. Stopping a stopped VM changes nothing.
    pub async fn stop_vm(&self, organisation_id: Uuid, vm_id: Uuid) -> anyhow::Result<VmOutcome> {
        let Some(vm) = agents::vm(&self.state.pool, vm_id)
            .await?
            .filter(|vm| vm.organisation_id == organisation_id)
        else {
            return Ok(VmOutcome::NotFound);
        };
        let mut work =
            grund_store::work::Work::begin(&self.state.events, Uuid::now_v7(), "agent-vm-stop")
                .await?;
        let updates = work.load_agent_updates().await?;
        if updates
            .active
            .as_ref()
            .and_then(grund_domain::agent_updates::ActiveUpdate::vm)
            .is_some_and(|attempt| {
                attempt.host_machine_id == vm.host_machine_id
                    || vm.machine_id == Some(attempt.guest_machine_id)
            })
        {
            return Ok(VmOutcome::CannotHost("that VM is being updated".into()));
        }
        agents::lock_generation(work.sql(), vm.host_machine_id).await?;
        let Some(vm) = agents::vm(&mut **work.sql(), vm_id)
            .await?
            .filter(|vm| vm.organisation_id == organisation_id)
        else {
            return Ok(VmOutcome::NotFound);
        };
        let changed = vm.state != "stopped";
        if changed {
            agents::set_vm_state(&mut **work.sql(), vm_id, "stopped").await?;
            self.publish_in(work.sql(), vm.host_machine_id).await?;
        }
        work.commit().await?;
        if changed {
            self.state.wakes.documents_changed();
        }
        Ok(match agents::vm(&self.state.pool, vm_id).await? {
            Some(vm) => VmOutcome::Done(Box::new(vm)),
            None => VmOutcome::NotFound,
        })
    }

    /// The organisation's VMs.
    pub async fn vms(&self, organisation_id: Uuid) -> anyhow::Result<Vec<VmRow>> {
        Ok(agents::organisation_vms(&self.state.pool, organisation_id).await?)
    }
}

/// Why `host` cannot run a VM that registers, or `None` when it can.
pub fn cannot_host(host: &MachineRow) -> Option<String> {
    if host.cordoned_at.is_some() {
        return Some("that machine is out of service".into());
    }
    let capabilities = host.capabilities.as_ref().map(|c| &c.0);
    let has = |name: &str| {
        capabilities
            .and_then(|c| c[name].as_bool())
            .unwrap_or(false)
    };
    if host.last_seen_at.is_none() {
        return Some("that machine's agent has not connected yet".into());
    }
    if !has("kvm") {
        return Some("that machine has no usable /dev/kvm".into());
    }
    if !has("egress") {
        return Some("a VM on that machine could not reach grund to register".into());
    }
    None
}

fn invalid(request: &VmRequest) -> Option<String> {
    let hex = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    let url = |value: &str| value.starts_with("https://") || value.starts_with("http://");
    if !(1..=64).contains(&request.vcpus) {
        return Some("vcpus must be between 1 and 64".into());
    }
    if !(128..=262_144).contains(&request.memory_mib) {
        return Some("memory_mib must be between 128 and 262144".into());
    }
    if !(1..=4096).contains(&request.disk_gib) {
        return Some("disk_gib must be between 1 and 4096".into());
    }
    if !url(&request.kernel_url) || !url(&request.rootfs_url) {
        return Some("the image's kernel and rootfs must be http or https URLs".into());
    }
    if !hex(&request.kernel_sha256) || !hex(&request.rootfs_sha256) {
        return Some(
            "the image's kernel and rootfs must be pinned by lowercase hex SHA-256".into(),
        );
    }
    None
}

/// A replica's entry in its machine's document (apps.md §6.2): plain
/// settings, and secrets by name and version only.
pub fn replica_message(placed: &grund_store::apps::PlacedRow) -> agent::Replica {
    use grund_config::app::spec::{CheckKind, Protocol};
    let spec = &placed.spec.0;
    agent::Replica {
        replica_id: placed.replica_id.to_string(),
        app: placed.app_name.clone(),
        app_id: placed.app_id.to_string(),
        release: placed.release as u32,
        slot: placed.slot as u32,
        placement: placed.placement as u64,
        image: buffa::MessageField::from(agent::Image {
            reference: spec.image.clone(),
            digest: placed.image_digest.clone(),
            ..Default::default()
        }),
        command: spec.command.clone(),
        env: spec
            .env
            .iter()
            .map(|e| agent::EnvVar {
                name: e.name.clone(),
                value: e.value.clone(),
                ..Default::default()
            })
            .collect(),
        ports: spec
            .ports
            .iter()
            .map(|p| agent::Port {
                name: p.name.clone(),
                port: u32::from(p.port),
                protocol: match p.protocol {
                    Protocol::Http => "http",
                    Protocol::H2c => "h2c",
                    Protocol::Tcp => "tcp",
                }
                .to_string(),
                public: p.public,
                ..Default::default()
            })
            .collect(),
        memory_mib: spec.memory_mib,
        cpu_millis: spec.cpu_millis,
        state: match placed.state.as_str() {
            "draining" => agent::ReplicaState::REPLICA_STATE_DRAINING,
            _ => agent::ReplicaState::REPLICA_STATE_RUNNING,
        }
        .into(),
        secrets: placed
            .secret_versions
            .0
            .iter()
            .map(|s| agent::SecretRef {
                name: s.name.clone(),
                version: s.version,
                ..Default::default()
            })
            .collect(),
        secret_env: spec
            .secrets
            .iter()
            .map(|s| agent::SecretEnv {
                env: s.env.clone(),
                secret: s.secret.clone(),
                ..Default::default()
            })
            .collect(),
        check: spec
            .check
            .as_ref()
            .map(|c| {
                buffa::MessageField::from(agent::ReplicaCheck {
                    kind: Some(match &c.kind {
                        CheckKind::Http { path } => {
                            agent::replica_check::Kind::HttpPath(path.clone())
                        }
                        CheckKind::Tcp => agent::replica_check::Kind::Tcp(true),
                    }),
                    port: u32::from(c.port),
                    interval_ms: c.interval_ms,
                    timeout_ms: c.timeout_ms,
                    ..Default::default()
                })
            })
            .unwrap_or_default(),
        stop: buffa::MessageField::from(agent::ReplicaStop {
            signal: spec.stop.signal.clone(),
            grace_seconds: spec.stop.grace_seconds,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn vm_message(vm: &VmRow) -> agent::Vm {
    let artifact = |url: &str, sha256: &str| agent::Artifact {
        url: url.to_string(),
        sha256: sha256.to_string(),
        ..Default::default()
    };
    agent::Vm {
        vm_id: vm.vm_id.to_string(),
        name: vm.name.clone(),
        vcpus: vm.vcpus as u32,
        memory_mib: vm.memory_mib as u32,
        disk_gib: vm.disk_gib as u32,
        image: buffa::MessageField::from(agent::VmImage {
            kernel: buffa::MessageField::from(artifact(&vm.kernel_url, &vm.kernel_sha256)),
            rootfs: buffa::MessageField::from(artifact(&vm.rootfs_url, &vm.rootfs_sha256)),
            ..Default::default()
        }),
        state: match vm.state.as_str() {
            "running" => agent::VmDesiredState::VM_DESIRED_STATE_RUNNING,
            _ => agent::VmDesiredState::VM_DESIRED_STATE_STOPPED,
        }
        .into(),
        ..Default::default()
    }
}

fn vm_update_message(attempt: &grund_domain::agent_updates::vm::VmAttempt) -> agent::VmUpdate {
    use grund_domain::agent_updates::vm::Action;
    let target = &attempt.target;
    agent::VmUpdate {
        version: 1,
        attempt_id: attempt.id.to_string(),
        sequence: attempt.operation.sequence,
        action: match attempt.operation.action {
            Action::Prepare => agent::VmUpdateAction::VM_UPDATE_ACTION_PREPARE,
            Action::Quiesce => agent::VmUpdateAction::VM_UPDATE_ACTION_QUIESCE,
            Action::StartCandidate => agent::VmUpdateAction::VM_UPDATE_ACTION_START_CANDIDATE,
            Action::Commit => agent::VmUpdateAction::VM_UPDATE_ACTION_COMMIT,
            Action::Rollback => agent::VmUpdateAction::VM_UPDATE_ACTION_ROLLBACK,
            Action::ReleaseOld => agent::VmUpdateAction::VM_UPDATE_ACTION_RELEASE_OLD,
        }
        .into(),
        image: agent::VmImage {
            kernel: agent::Artifact {
                url: target.kernel_url.clone(),
                sha256: target.kernel_sha256.clone(),
                ..Default::default()
            }
            .into(),
            rootfs: agent::Artifact {
                url: target.rootfs_url.clone(),
                sha256: target.rootfs_sha256.clone(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }
        .into(),
        guest_machine_id: attempt.guest_machine_id.to_string(),
        registration_key: hex::decode(&attempt.guest_registration_key)
            .expect("authorized VM guest registration key is valid hex"),
        launch_nonce: attempt.operation.launch_nonce.to_string(),
        deadline: buffa_types::google::protobuf::Timestamp::from_unix(
            attempt.operation.deadline.timestamp(),
            attempt.operation.deadline.timestamp_subsec_nanos() as i32,
        )
        .into(),
        ..Default::default()
    }
}

/// Access to [`Agents`] from [`State`].
pub trait AgentsState {
    fn agents(&self) -> Agents;
}

impl AgentsState for State {
    fn agents(&self) -> Agents {
        Agents {
            state: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::sync::Arc;

    #[derive(Parser)]
    struct TestConfig {
        #[command(flatten)]
        config: crate::config::ServeConfig,
    }

    async fn state(pool: sqlx::PgPool) -> State {
        grund_store::migrate(&pool).await.unwrap();
        let mut config =
            TestConfig::try_parse_from(["test", "--database-url", "postgres://unused/test"])
                .unwrap()
                .config;
        config.license_key = None;
        config.license_key_file = None;
        let secret = Arc::new(crate::secrets::SecretKey::generate());
        let events = mire::EventStore::new(pool.clone());
        let certificates =
            crate::certificates::Certificates::new(&config, pool.clone(), secret.clone());
        let hearing = Arc::new(crate::hearing::Hearing::new(Utc::now()));
        let health = crate::health::registry(
            pool.clone(),
            hearing.clone(),
            None,
            false,
            &certificates,
            &config,
        );
        let entitlements = Arc::new(crate::entitlements(&config).unwrap());
        State {
            config: Arc::new(config),
            pool,
            events: events.clone(),
            nats: None,
            secret,
            certificates,
            health,
            passwords: crate::services::passwords::Passwords::new().unwrap(),
            entitlements,
            billing: crate::services::billing::Billing::Free,
            capacity: crate::services::capacity::Capacity::None,
            deletions: crate::sagas::Deletions::new(events),
            extensions: Arc::new(Vec::new()),
            started: std::time::Instant::now(),
            wakes: crate::wakes::Wakes::default(),
            hearing,
        }
    }

    #[sqlx::test(migrations = false)]
    async fn republishing_preserves_the_active_operation_and_stopping_cannot_bypass_its_slot(
        pool: sqlx::PgPool,
    ) {
        use grund_domain::agent_updates::{Command, vm};
        let state = state(pool).await;
        let host = Uuid::now_v7();
        let guest = Uuid::now_v7();
        let organisation_id = Uuid::now_v7();
        let vm_id = Uuid::now_v7();
        let host_key = "a".repeat(64);
        let source = "b".repeat(64);
        sqlx::query(
            "INSERT INTO grund_machines (machine_id,pool,name,state,public_key,pool_organisation_id, \
               pool_name,minted_by,registered_at,key_registered_at,stream_version) \
             VALUES ($1,'management','host','available',$2,$3,'host','test', \
               clock_timestamp(),clock_timestamp(),1)",
        ).bind(host).bind(&host_key).bind(organisation_id).execute(&state.pool).await.unwrap();
        agents::insert_vm(
            &state.pool,
            &NewVm {
                vm_id,
                organisation_id,
                host_machine_id: host,
                name: "guest",
                vcpus: 1,
                memory_mib: 512,
                disk_gib: 8,
                kernel_url: "https://artifacts.example/old-kernel",
                kernel_sha256: &source,
                rootfs_url: "https://artifacts.example/old-rootfs",
                rootfs_sha256: &source,
                created_by: Uuid::nil(),
            },
        )
        .await
        .unwrap();
        let now = Utc::now();
        let mut work = grund_store::work::Work::begin(&state.events, Uuid::now_v7(), "test")
            .await
            .unwrap();
        work.agent_updates(Command::Initialize { at: now })
            .await
            .unwrap();
        work.agent_updates(Command::Vm(vm::Command::Request {
            request: vm::Request {
                id: Uuid::now_v7(),
                vm_id,
                organisation_id,
                host_machine_id: host,
                guest_machine_id: guest,
                host_registration_key: host_key,
                guest_registration_key: "c".repeat(64),
                request_hash: "d".repeat(64),
                fingerprint: "e".repeat(64),
                source: vm::ImageIdentity {
                    kernel_sha256: source.clone(),
                    rootfs_sha256: source,
                },
                target: vm::Target {
                    kernel_url: "https://artifacts.example/new-kernel".into(),
                    kernel_sha256: "f".repeat(64),
                    rootfs_url: "https://artifacts.example/new-rootfs".into(),
                    rootfs_sha256: "1".repeat(64),
                },
                expected_update_version: 0,
                original_in_service: true,
                old_os_boot_id: None,
                launch_nonce: Uuid::now_v7(),
                deadline: now + Duration::minutes(5),
            },
            at: now,
        }))
        .await
        .unwrap();
        work.commit().await.unwrap();
        state.agents().publish(host).await.unwrap();
        let first = agents::document(&state.pool, host).await.unwrap().unwrap();
        let original = agent::DesiredState::decode_from_slice(&first.payload).unwrap();
        state.agents().publish(host).await.unwrap();
        let second = agents::document(&state.pool, host).await.unwrap().unwrap();
        let republished = agent::DesiredState::decode_from_slice(&second.payload).unwrap();
        assert!(second.generation > first.generation);
        assert_eq!(original.machines[0].update, republished.machines[0].update);
        assert!(republished.machines[0].update.as_option().is_some());
        assert_eq!(
            republished.machines[0].state.as_known(),
            Some(agent::VmDesiredState::VM_DESIRED_STATE_RUNNING)
        );
        assert!(matches!(
            state.agents().stop_vm(Uuid::now_v7(), vm_id).await.unwrap(),
            VmOutcome::NotFound
        ));
        assert!(matches!(
            state
                .agents()
                .stop_vm(organisation_id, vm_id)
                .await
                .unwrap(),
            VmOutcome::CannotHost(_)
        ));
        assert_eq!(
            agents::vm(&state.pool, vm_id).await.unwrap().unwrap().state,
            "running"
        );
        sqlx::query("UPDATE grund_machines SET public_key=$2 WHERE machine_id=$1")
            .bind(host)
            .bind("2".repeat(64))
            .execute(&state.pool)
            .await
            .unwrap();
        state.agents().publish(host).await.unwrap();
        let document = agents::document(&state.pool, host).await.unwrap().unwrap();
        let desired = agent::DesiredState::decode_from_slice(&document.payload).unwrap();
        assert!(desired.machines[0].update.as_option().is_none());
    }

    #[test]
    fn the_request_message_binds_purpose_path_time_and_body() {
        let message = request_message(
            "/grund.agent.v1.AgentService/Heartbeat",
            1_790_000_000,
            b"{}",
        );
        let text = String::from_utf8(message).unwrap();
        assert!(text.starts_with(
            "grund-agent-request-v1\n/grund.agent.v1.AgentService/Heartbeat\n1790000000\n"
        ));
        assert!(text.ends_with(&hex::encode(Sha256::digest(b"{}"))));
    }

    #[test]
    fn a_machine_is_connected_only_within_thirty_seconds_of_its_heartbeat() {
        let now = Utc::now();
        assert!(connected(Some(now - Duration::seconds(10)), now));
        assert!(!connected(Some(now - Duration::seconds(31)), now));
        assert!(!connected(None, now));
    }
}
