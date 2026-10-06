//! The control link's server side (grund-docs design/machines.md §7b):
//! authenticating a machine's requests by its key, heartbeats, each machine's
//! signed desired state, the join tokens its VMs boot with, what it reports,
//! and the VMs an organisation runs on its own machines.

use base64::{Engine, engine::general_purpose::STANDARD};
use buffa::Message;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use grund_domain::{
    machine::{CLOCK_SKEW, KeyPurpose, MAX_MACHINES_PER_ORGANISATION, prefix},
    names::MachineName,
};
use grund_proto::grund::agent::v1 as agent;
use grund_store::{
    agents::{self, DocumentRow, NewVm, VmRow},
    machines::{self, MachineRow},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    keys::KeysState,
    services::entry::EntryState,
    services::machines::{MachinesState, MintOutcome, Minted},
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

/// The machine a control-link request is from, as its signature proved.
#[derive(Debug, Clone)]
pub struct MachineCaller {
    pub machine_id: Uuid,
    /// The organisation whose pool the machine is in now, if any.
    pub organisation_id: Option<Uuid>,
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
        Ok(Some(MachineCaller {
            machine_id,
            organisation_id: row.pool_organisation_id,
        }))
    }

    /// Records a heartbeat and answers the machine's current generation.
    pub async fn heartbeat(
        &self,
        caller: &MachineCaller,
        agent_version: &str,
        capabilities: &serde_json::Value,
    ) -> anyhow::Result<i64> {
        let version: String = agent_version.chars().take(64).collect();
        agents::heartbeat(
            &self.state.pool,
            caller.machine_id,
            &version,
            capabilities,
            Utc::now(),
        )
        .await?;
        Ok(agents::document(&self.state.pool, caller.machine_id)
            .await?
            .map_or(0, |d| d.generation))
    }

    /// The machine's document, if newer than `since`.
    pub async fn desired_state(
        &self,
        caller: &MachineCaller,
        since: u64,
    ) -> anyhow::Result<Option<DocumentRow>> {
        Ok(agents::document(&self.state.pool, caller.machine_id)
            .await?
            .filter(|document| document.generation as u64 > since))
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
        observed: &[(Uuid, &'static str, Option<String>)],
        refusals: &[String],
        replicas: Option<&[ReplicaReport]>,
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
        }
        let refusals: Vec<String> = refusals
            .iter()
            .take(20)
            .map(|r| r.chars().take(300).collect())
            .collect();
        agents::report(
            &self.state.pool,
            caller.machine_id,
            applied_generation as i64,
            &serde_json::json!(refusals),
            now,
        )
        .await?;
        for (vm_id, state, reason) in observed.iter().take(200) {
            let reason: Option<String> = reason.as_ref().map(|r| r.chars().take(500).collect());
            agents::observe_vm(
                &self.state.pool,
                caller.machine_id,
                *vm_id,
                state,
                reason.as_deref(),
            )
            .await?;
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
        let generation = agents::lock_generation(&mut *connection, host_machine_id).await? + 1;
        let vms = agents::hosted_vms(&mut *connection, host_machine_id).await?;
        let placed = grund_store::apps::machine_replicas(&mut *connection, host_machine_id).await?;
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
        let machines: Vec<agent::Vm> = vms.iter().map(vm_message).collect();
        let entry = self.state.entry();
        let slug = grund_store::entry::organisation_slug(&mut *connection, organisation_id)
            .await?
            .unwrap_or_default();
        let mut addresses: std::collections::HashMap<Uuid, Option<String>> = Default::default();
        let mut custom: std::collections::HashMap<Uuid, Vec<String>> = Default::default();
        let mut replicas: Vec<agent::Replica> = Vec::with_capacity(placed.len());
        for row in &placed {
            let mut replica = replica_message(row);
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
                        grund_store::domains::names_of_app(&mut *connection, row.app_id).await?,
                    );
                }
                replica.hostnames = match &addresses[&row.app_id] {
                    Some(address) => std::iter::once(address)
                        .chain(custom[&row.app_id].iter())
                        .cloned()
                        .collect(),
                    None => Vec::new(),
                };
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
        let payload = agent::DesiredState {
            machine_id: host_machine_id.to_string(),
            organisation_id: organisation_id.to_string(),
            generation: generation as u64,
            issued_at_unix: now.timestamp(),
            required_features,
            machines,
            replicas,
            entry_keys,
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
        let Some(host) = machines::organisation_machine(
            &self.state.pool,
            organisation_id,
            request.host_machine_id,
        )
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
        let pool = machines::organisation_machines(&self.state.pool, organisation_id).await?;
        if pool
            .iter()
            .any(|m| m.pool_name.as_deref() == Some(name.as_str()))
        {
            return Ok(VmOutcome::NameTaken);
        }
        let running = agents::organisation_vms(&self.state.pool, organisation_id)
            .await?
            .iter()
            .filter(|vm| vm.state == "running" && vm.machine_id.is_none())
            .count() as i64;
        if pool.len() as i64 + running >= MAX_MACHINES_PER_ORGANISATION {
            return Ok(VmOutcome::PoolFull);
        }
        let vm_id = Uuid::now_v7();
        let inserted = agents::insert_vm(
            &self.state.pool,
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
        self.publish(request.host_machine_id).await?;
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
        if vm.state != "stopped" {
            agents::set_vm_state(&self.state.pool, vm_id, "stopped").await?;
            self.publish(vm.host_machine_id).await?;
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
    use grund_domain::app::spec::{CheckKind, Protocol};
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
