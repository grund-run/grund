//! `grund.agent.v1.AgentService`: the control link over HTTPS (grund-docs
//! design/machines.md §7b). Every call is from a machine whose key signed
//! the request ([`crate::api::authenticate_machine`]); a handler acts only on
//! that machine.

use buffa::MessageField;
use buffa_types::google::protobuf::Timestamp;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_proto::grund::agent::v1::{
    AgentService, GetBackupWorkRequest, GetBackupWorkResponse, GetDesiredStateRequest,
    GetDesiredStateResponse, GetLeaseRequest, GetLeaseResponse, GetMachineJoinTokenRequest,
    GetMachineJoinTokenResponse, GetMembershipRequest, GetMembershipResponse,
    GetPullCredentialRequest, GetPullCredentialResponse, GetReplicaSecretsRequest,
    GetReplicaSecretsResponse, HeartbeatRequest, HeartbeatResponse, RegistryCredential,
    ReplicaObservedState, ReportBackupResultRequest, ReportBackupResultResponse,
    ReportStatusRequest, ReportStatusResponse, SecretValue, SignedDesiredState, SignedLeaseGrant,
    SignedMembershipList, VmObservedState, WatchDesiredStateRequest, WatchDesiredStateResponse,
};
use uuid::Uuid;

use crate::{
    services::{
        AgentUpdatesState,
        agents::{AgentsState, HEARTBEAT_INTERVAL_SECONDS, MachineCaller, ReplicaReport},
        apps::AppsState,
        backups::BackupsState,
        machines::MachinesState,
        networks::{MembershipOutcome, NetworksState},
        registry_credentials::RegistryCredentialsState,
    },
    state::State,
};

/// The service implementation.
pub struct AgentApi {
    state: State,
}

impl AgentApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

fn machine(ctx: &RequestContext) -> Result<MachineCaller, ConnectError> {
    ctx.extensions()
        .get::<MachineCaller>()
        .cloned()
        .ok_or_else(|| ConnectError::unauthenticated("sign the request with the machine key"))
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "agent API call failed");
    ConnectError::unavailable("grund could not finish that; try again")
}

fn signed(document: grund_store::agents::DocumentRow) -> SignedDesiredState {
    SignedDesiredState {
        key_id: document.key_id.to_string(),
        payload: document.payload,
        signature: document.signature,
        ..Default::default()
    }
}

#[allow(refining_impl_trait)]
impl AgentService for AgentApi {
    async fn heartbeat(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, HeartbeatRequest>,
    ) -> ServiceResult<HeartbeatResponse> {
        let caller = machine(&ctx)?;
        tracing::Span::current().record(
            "machine_key_prefix",
            std::str::from_utf8(&caller.endpoint_key_prefix).expect("verified hex key"),
        );
        let capabilities = request
            .capabilities
            .as_option()
            .map_or(serde_json::json!({}), |c| {
                let mut capabilities = serde_json::json!({
                    "kvm": c.kvm,
                    "root": c.root,
                    "egress": c.egress,
                    "free_vcpus": c.free_vcpus,
                    "free_memory_mib": c.free_memory_mib,
                    "apps": c.apps,
                    "volumes": c.volumes,
                    "stack_services": c.stack_services,
                    "arch": c.arch.chars().take(16).collect::<String>(),
                    "memory_mib": c.memory_mib,
                    "cpu_millis": c.cpu_millis,
                    "resources_allocatable": c.resources_allocatable,
                    "apps_unavailable_reason": c.apps_unavailable_reason.chars().take(200).collect::<String>(),
                    "max_replica_memory_mib": c.max_replica_memory_mib,
                    "max_replica_cpu_millis": c.max_replica_cpu_millis,
                    "disk_gib": c.disk_gib,
                });
                if let Some(usage) = c.usage.as_option() {
                    let mut snapshot = serde_json::Map::new();
                    if let Some(value) = usage.cpu_millis {
                        snapshot.insert("cpu_millis".into(), value.into());
                    }
                    if let Some(value) = usage.memory_used_bytes {
                        snapshot.insert("memory_used_bytes".into(), value.into());
                    }
                    if let Some(value) = usage.disk_used_bytes {
                        snapshot.insert("disk_used_bytes".into(), value.into());
                    }
                    if let Some(value) = usage.disk_total_bytes {
                        snapshot.insert("disk_total_bytes".into(), value.into());
                    }
                    if let Some(value) = usage.uptime_seconds {
                        snapshot.insert("uptime_seconds".into(), value.into());
                    }
                    if let Some(sampled_at) = usage.sampled_at.as_option().and_then(|timestamp| {
                        let nanos = u32::try_from(timestamp.nanos)
                            .ok()
                            .filter(|nanos| *nanos < 1_000_000_000)?;
                        chrono::DateTime::from_timestamp(timestamp.seconds, nanos)
                    }) {
                        snapshot.insert(
                            "sampled_at".into(),
                            sampled_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
                                .into(),
                        );
                    }
                    snapshot.insert(
                        "agent_revision".into(),
                        usage.agent_revision.chars().take(64).collect::<String>().into(),
                    );
                    capabilities["usage"] = serde_json::Value::Object(snapshot);
                }
                capabilities
            });
        let generation = self
            .state
            .agents()
            .heartbeat(&caller, request.agent_version, &capabilities)
            .await
            .map_err(internal)?;
        if !request.boot_id.is_empty() {
            let boot_id = Uuid::parse_str(request.boot_id)
                .ok()
                .filter(|id| !id.is_nil())
                .ok_or_else(|| ConnectError::invalid_argument("invalid update boot id"))?;
            self.state
                .agent_updates()
                .observe(
                    &caller,
                    boot_id,
                    request.public_revision,
                    request.update_ready,
                )
                .await
                .map_err(internal)?;
        }
        Response::ok(HeartbeatResponse {
            generation: generation as u64,
            heartbeat_interval_seconds: HEARTBEAT_INTERVAL_SECONDS,
            ..Default::default()
        })
    }

    async fn get_desired_state(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetDesiredStateRequest>,
    ) -> ServiceResult<GetDesiredStateResponse> {
        let caller = machine(&ctx)?;
        let document = self
            .state
            .agents()
            .desired_state(&caller, request.since_generation)
            .await
            .map_err(internal)?;
        Response::ok(GetDesiredStateResponse {
            document: document
                .map(signed)
                .map(MessageField::from)
                .unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn watch_desired_state(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, WatchDesiredStateRequest>,
    ) -> ServiceResult<WatchDesiredStateResponse> {
        let caller = machine(&ctx)?;
        let document = self
            .state
            .agents()
            .watch_desired_state(&caller, request.since_generation)
            .await
            .map_err(internal)?;
        Response::ok(WatchDesiredStateResponse {
            document: document
                .map(signed)
                .map(MessageField::from)
                .unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn get_replica_secrets(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetReplicaSecretsRequest>,
    ) -> ServiceResult<GetReplicaSecretsResponse> {
        let caller = machine(&ctx)?;
        let not_found = || ConnectError::not_found("no such replica on this machine");
        let replica_id = Uuid::parse_str(request.replica_id).map_err(|_| not_found())?;
        let secrets = self
            .state
            .apps()
            .replica_secrets(&caller, replica_id)
            .await
            .map_err(internal)?
            .ok_or_else(not_found)?;
        Response::ok(GetReplicaSecretsResponse {
            secrets: secrets
                .into_iter()
                .map(|s| SecretValue {
                    name: s.name,
                    version: s.version,
                    value: s.value,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn get_pull_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetPullCredentialRequest>,
    ) -> ServiceResult<GetPullCredentialResponse> {
        let caller = machine(&ctx)?;
        let not_found = || ConnectError::not_found("no such replica on this machine");
        let replica_id = Uuid::parse_str(request.replica_id).map_err(|_| not_found())?;
        let credential = self
            .state
            .registry_credentials()
            .for_replica(&caller, replica_id)
            .await
            .map_err(internal)?
            .ok_or_else(not_found)?;
        Response::ok(GetPullCredentialResponse {
            credential: credential
                .map(|c| {
                    MessageField::from(RegistryCredential {
                        host: c.host,
                        username: c.username,
                        password: c.password,
                        ..Default::default()
                    })
                })
                .unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn get_machine_join_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetMachineJoinTokenRequest>,
    ) -> ServiceResult<GetMachineJoinTokenResponse> {
        let caller = machine(&ctx)?;
        let vm_id =
            Uuid::parse_str(request.vm_id).map_err(|_| ConnectError::not_found("no such VM"))?;
        let minted = self
            .state
            .agents()
            .join_token(&caller, vm_id)
            .await
            .map_err(internal)?
            .ok_or_else(|| ConnectError::not_found("no such VM to start on this machine"))?;
        Response::ok(GetMachineJoinTokenResponse {
            token: minted.token,
            expires_at: Timestamp::from_unix(minted.expires_at.timestamp(), 0).into(),
            ..Default::default()
        })
    }

    async fn get_backup_work(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetBackupWorkRequest>,
    ) -> ServiceResult<GetBackupWorkResponse> {
        let caller = machine(&ctx)?;
        if request.machine_id != caller.machine_id.to_string() {
            return Err(ConnectError::not_found("no backup work on this machine"));
        }
        let work = self
            .state
            .backups()
            .for_machine(caller.machine_id)
            .await
            .map_err(internal)?;
        Response::ok(GetBackupWorkResponse {
            work: work.map(MessageField::from).unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn report_backup_result(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReportBackupResultRequest>,
    ) -> ServiceResult<ReportBackupResultResponse> {
        let caller = machine(&ctx)?;
        if request.machine_id != caller.machine_id.to_string() {
            return Err(ConnectError::not_found("no backup work on this machine"));
        }
        let attempt = Uuid::parse_str(request.attempt_id)
            .map_err(|_| ConnectError::invalid_argument("attempt_id must be a UUID"))?;
        let generation = i64::try_from(request.placement_generation)
            .map_err(|_| ConnectError::invalid_argument("placement generation is out of range"))?;
        let accepted = self
            .state
            .backups()
            .ack(
                caller.machine_id,
                attempt,
                generation,
                request.success,
                request.snapshot_id,
                request.failure_class,
                request.source_path,
            )
            .await
            .map_err(internal)?;
        Response::ok(ReportBackupResultResponse {
            accepted,
            ..Default::default()
        })
    }

    async fn report_status(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReportStatusRequest>,
    ) -> ServiceResult<ReportStatusResponse> {
        let caller = machine(&ctx)?;
        let observed: Vec<(Uuid, &'static str, Option<String>)> = request
            .machines
            .iter()
            .filter_map(|vm| {
                let id = Uuid::parse_str(vm.vm_id).ok()?;
                let state = match vm.state.as_known()? {
                    VmObservedState::VM_OBSERVED_STATE_STARTING => "starting",
                    VmObservedState::VM_OBSERVED_STATE_RUNNING => "running",
                    VmObservedState::VM_OBSERVED_STATE_STOPPED => "stopped",
                    VmObservedState::VM_OBSERVED_STATE_EXITED => "exited",
                    VmObservedState::VM_OBSERVED_STATE_FAILED => "failed",
                    VmObservedState::VM_OBSERVED_STATE_UNSPECIFIED => return None,
                };
                Some((
                    id,
                    state,
                    (!vm.reason.is_empty()).then(|| vm.reason.to_string()),
                ))
            })
            .collect();
        let refusals: Vec<String> = request.refusals.iter().map(|r| r.to_string()).collect();
        let replicas: Vec<ReplicaReport> = request
            .replicas
            .iter()
            .filter_map(|r| {
                Some(ReplicaReport {
                    replica_id: Uuid::parse_str(r.replica_id).ok()?,
                    state: match r.state.as_known()? {
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_PULLING => "pulling",
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_STARTING => "starting",
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_RUNNING => "running",
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_EXITED => "exited",
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_FAILED => "failed",
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_REFUSED => "refused",
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_STOPPING => "stopping",
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_UNSPECIFIED => return None,
                    },
                    ready: r.ready,
                    ready_for_ms: r.ready_for_ms,
                    restarts: r.restarts,
                    last_exit_code: r.last_exit_code,
                    reason: r.reason.chars().take(500).collect(),
                    idle: r.idle,
                    applied_generation: r.applied_generation,
                    operation_id: Uuid::parse_str(r.operation_id).ok(),
                })
            })
            .collect();
        let volume_deletions: Vec<(Uuid, Uuid)> = request
            .volume_deletions
            .iter()
            .filter_map(|item| {
                Some((
                    Uuid::parse_str(item.app_id).ok()?,
                    Uuid::parse_str(item.volume_id).ok()?,
                ))
            })
            .collect();
        self.state
            .agents()
            .report(
                &caller,
                request.applied_generation,
                &observed,
                &refusals,
                request.reports_replicas.then_some(replicas.as_slice()),
                &volume_deletions,
            )
            .await
            .map_err(internal)?;
        Response::ok(ReportStatusResponse::default())
    }

    async fn get_lease(
        &self,
        ctx: RequestContext,
        _: ServiceRequest<'_, GetLeaseRequest>,
    ) -> ServiceResult<GetLeaseResponse> {
        let caller = machine(&ctx)?;
        let machines = self.state.machines();
        let Some(row) = machines
            .pool_machine(caller.machine_id)
            .await
            .map_err(internal)?
        else {
            return Response::ok(GetLeaseResponse::default());
        };
        let grant = machines.lease_grant(&row).await.map_err(internal)?;
        Response::ok(GetLeaseResponse {
            grant: grant
                .map(|grant| SignedLeaseGrant {
                    key_id: grant.key_id.to_string(),
                    payload: grant.payload,
                    signature: grant.signature.to_vec(),
                    ..Default::default()
                })
                .map(MessageField::from)
                .unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn get_membership(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetMembershipRequest>,
    ) -> ServiceResult<GetMembershipResponse> {
        let caller = machine(&ctx)?;
        let not_found = || ConnectError::not_found("no such network for this machine");
        let network_id = match request.network_id {
            "" => None,
            id => Some(Uuid::parse_str(id).map_err(|_| not_found())?),
        };
        let outcome = self
            .state
            .networks()
            .membership(
                &caller,
                network_id,
                request.since_epoch,
                request.home_relay_url,
                &request
                    .direct_addrs
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>(),
            )
            .await
            .map_err(internal)?;
        match outcome {
            MembershipOutcome::Newer(network) => Response::ok(GetMembershipResponse {
                network_id: network.network_id.to_string(),
                epoch: network.epoch,
                list: MessageField::from(SignedMembershipList {
                    key_id: network.key.key_id.to_string(),
                    body: network.body,
                    signature: network.signature,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            MembershipOutcome::Unchanged { network_id, epoch } => {
                Response::ok(GetMembershipResponse {
                    network_id: network_id.to_string(),
                    epoch,
                    ..Default::default()
                })
            }
            MembershipOutcome::NotFound => Err(not_found()),
        }
    }
}
