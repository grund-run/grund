//! `grund.machine.v1`: the management pool, run by the operator
//! organisation, and each organisation's own pool (grund-docs
//! design/machines.md §6.2–6.3). A pool the caller may not see is
//! not_found, as an organisation they are not a member of is.

use buffa::{EnumValue, MessageField};
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_domain::machine::{
    Authority, NetworkPort, PortsError, TokenKind, Transport, declared_ports,
};
use grund_proto::grund::{
    agent::v1 as agent,
    machine::v1::{
        CreateHostedMachineRequest, CreateHostedMachineResponse, CreateJoinTokenRequest,
        CreateJoinTokenResponse, CreateRegistrationTokenRequest, CreateRegistrationTokenResponse,
        CreateReregistrationTokenRequest, CreateReregistrationTokenResponse,
        DeclareMachinePortsRequest, DeclareMachinePortsResponse, EndLeaseRequest, EndLeaseResponse,
        GetMachineRequest, GetMachineResponse, GetOrganisationKeyRequest,
        GetOrganisationKeyResponse, GetPoolMachineRequest, GetPoolMachineResponse, HostedOffer,
        Lease, LeaseMachineRequest, LeaseMachineResponse, ListHostedOffersRequest,
        ListHostedOffersResponse, ListMachinesRequest, ListMachinesResponse,
        ListPoolMachinesRequest, ListPoolMachinesResponse, ListVmsRequest, ListVmsResponse,
        Machine, MachineService, MachineState, ManagementPoolService,
        NetworkPort as NetworkPortProto, NetworkTransport, ProviderStep as ProviderStepProto,
        ProvisionPoolMachineRequest, ProvisionPoolMachineResponse, RebuildPoolMachineRequest,
        RebuildPoolMachineResponse, RemoveHostedMachineRequest, RemoveHostedMachineResponse,
        RevokeMachineRequest, RevokeMachineResponse, RevokePoolMachineRequest,
        RevokePoolMachineResponse, RunVmRequest, RunVmResponse, SetMachineInServiceRequest,
        SetMachineInServiceResponse, SetMachineLabelsRequest, SetMachineLabelsResponse,
        SetMigrationPauseRequest, SetMigrationPauseResponse, StopVmRequest, StopVmResponse, Vm,
    },
};
use grund_store::{
    agents::VmRow,
    machines::{HostedOrder, MachineRow},
    organisations::Membership,
};
use uuid::Uuid;

use crate::{
    api::{Caller, CapacityCaller, Principal, caller, principal},
    services::{
        OrganisationsState,
        agents::{AgentsState, VmOutcome, VmRequest},
        entry::EntryState,
        machines::{
            Access, ChangeOutcome, HostedCreate, HostedRemove, MachinesState, MintOutcome, Minted,
            ProviderStep, ProvisionOutcome, public_key_message,
        },
    },
    state::State,
};

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "machine API call failed");
    ConnectError::internal("grund could not finish that")
}

fn timestamp<P: buffa::ProtoBox<Timestamp>>(at: DateTime<Utc>) -> MessageField<Timestamp, P> {
    Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into()
}

fn uuid(value: &str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| ConnectError::not_found("no such machine"))
}

fn state(text: &str) -> EnumValue<MachineState> {
    match text {
        "available" => MachineState::MACHINE_STATE_AVAILABLE,
        "leased" => MachineState::MACHINE_STATE_LEASED,
        "returning" => MachineState::MACHINE_STATE_RETURNING,
        "active" => MachineState::MACHINE_STATE_ACTIVE,
        "revoked" => MachineState::MACHINE_STATE_REVOKED,
        _ => MachineState::MACHINE_STATE_UNSPECIFIED,
    }
    .into()
}

fn state_name(value: EnumValue<MachineState>) -> Option<&'static str> {
    match value.as_known() {
        Some(MachineState::MACHINE_STATE_AVAILABLE) => Some("available"),
        Some(MachineState::MACHINE_STATE_LEASED) => Some("leased"),
        Some(MachineState::MACHINE_STATE_RETURNING) => Some("returning"),
        Some(MachineState::MACHINE_STATE_ACTIVE) => Some("active"),
        Some(MachineState::MACHINE_STATE_REVOKED) => Some("revoked"),
        _ => None,
    }
}

fn facts(value: &serde_json::Value, hosted_os: Option<&str>) -> agent::MachineFacts {
    let text = |key: &str| value[key].as_str().unwrap_or_default().to_string();
    agent::MachineFacts {
        hostname: if hosted_os.is_some() {
            String::new()
        } else {
            text("hostname")
        },
        arch: text("arch"),
        cpu_model: text("cpu_model"),
        cpus: value["cpus"].as_i64().unwrap_or_default() as i32,
        memory_mib: value["memory_mib"].as_i64().unwrap_or_default(),
        disk_gib: value["disk_gib"].as_i64().unwrap_or_default(),
        os: hosted_os.map(str::to_owned).unwrap_or_else(|| text("os")),
        kernel: text("kernel"),
        agent_version: text("agent_version"),
        fleet_machine_id: if hosted_os.is_some() {
            String::new()
        } else {
            text("fleet_machine_id")
        },
        ..Default::default()
    }
}

fn hosted_facts(value: &serde_json::Value) -> agent::MachineFacts {
    facts(value, Some("Linux"))
}

#[derive(Clone, Copy)]
enum View {
    Management,
    Organisation,
}

fn machine(row: &MachineRow, view: View, own_slug: Option<&str>) -> Machine {
    let hosted = matches!(view, View::Organisation) && row.pool == "management";
    let name = match view {
        View::Organisation => row.pool_name.clone().unwrap_or_else(|| row.name.clone()),
        View::Management => row.name.clone(),
    };
    let organisation = match (row.lessee_slug.as_deref(), own_slug) {
        (Some(lessee), _) => lessee.to_string(),
        (None, Some(own)) if row.pool == "organisation" => own.to_string(),
        _ => String::new(),
    };
    let lease = if hosted {
        None
    } else {
        row.lease_id.map(|lease_id| Lease {
            lease_id: lease_id.to_string(),
            organisation: row.lessee_slug.clone().unwrap_or_default(),
            name: row.lease_name.clone().unwrap_or_default(),
            leased_at: row.leased_at.map(timestamp).unwrap_or_default(),
            ..Default::default()
        })
    };
    Machine {
        machine_id: if hosted {
            row.lease_id.unwrap_or(row.machine_id)
        } else {
            row.machine_id
        }
        .to_string(),
        name,
        state: if hosted {
            MachineState::MACHINE_STATE_ACTIVE.into()
        } else {
            state(&row.state)
        },
        pool: if hosted {
            agent::Pool::POOL_UNSPECIFIED
        } else {
            match row.pool.as_str() {
                "management" => agent::Pool::POOL_MANAGEMENT,
                _ => agent::Pool::POOL_ORGANISATION,
            }
        }
        .into(),
        organisation,
        lease: lease.map(MessageField::from).unwrap_or_default(),
        public_key: row
            .public_key
            .as_deref()
            .and_then(|hex| hex::decode(hex).ok())
            .unwrap_or_default(),
        facts: MessageField::from(if hosted {
            hosted_facts(&row.facts.0)
        } else {
            facts(&row.facts.0, None)
        }),
        registered_at: timestamp(row.registered_at),
        key_registered_at: timestamp(row.key_registered_at),
        minted_by: if hosted {
            String::new()
        } else {
            row.minted_by.clone()
        },
        provider_machine_id: match view {
            View::Management => row.provider_machine_id.clone().unwrap_or_default(),
            View::Organisation => String::new(),
        },
        connected: crate::services::agents::connected(row.last_seen_at, Utc::now()),
        last_seen_at: row.last_seen_at.map(timestamp).unwrap_or_default(),
        capabilities: row
            .capabilities
            .as_ref()
            .map(|c| MessageField::from(capabilities(&c.0)))
            .unwrap_or_default(),
        network_ports: row
            .network_ports
            .0
            .iter()
            .map(|p| NetworkPortProto {
                transport: match p.transport {
                    Transport::Tcp => NetworkTransport::NETWORK_TRANSPORT_TCP,
                    Transport::Udp => NetworkTransport::NETWORK_TRANSPORT_UDP,
                }
                .into(),
                port: u32::from(p.port),
                ..Default::default()
            })
            .collect(),
        labels: row
            .labels
            .0
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        out_of_service_since: row.cordoned_at.map(timestamp).unwrap_or_default(),
        hosted,
        ..Default::default()
    }
}

fn hosted_machine(order: &HostedOrder, row: Option<&MachineRow>) -> Machine {
    let mut shown = row
        .map(|row| machine(row, View::Organisation, None))
        .unwrap_or_default();
    shown.machine_id = order.order_id.to_string();
    shown.name = order.name.clone();
    shown.hosted = true;
    shown.pool = agent::Pool::POOL_UNSPECIFIED.into();
    shown.lease = MessageField::default();
    shown.provider_machine_id.clear();
    shown.minted_by.clear();
    if row.is_none() {
        shown.state = if order.status == "failed" {
            MachineState::MACHINE_STATE_FAILED.into()
        } else {
            MachineState::MACHINE_STATE_JOINING.into()
        };
    }
    shown
}

fn external_machine(
    listing: &crate::extension::ExternalMachine,
    row: Option<&MachineRow>,
    slug: &str,
) -> Machine {
    let mut shown = row
        .map(|row| machine(row, View::Organisation, Some(slug)))
        .unwrap_or_default();
    shown.machine_id = listing.id.to_string();
    shown.name = listing.name.clone();
    shown.hosted = true;
    shown.pool = agent::Pool::POOL_UNSPECIFIED.into();
    shown.lease = MessageField::default();
    shown.provider_machine_id.clear();
    shown.minted_by.clear();
    shown.public_key.clear();
    shown.registered_at = MessageField::default();
    shown.key_registered_at = MessageField::default();
    shown.capabilities = MessageField::default();
    if let Some(row) = row {
        shown.facts = MessageField::from(facts(&row.facts.0, Some(listing.os.unwrap_or_default())));
    }
    if row.is_none() {
        shown.state = if listing.state == "failed" {
            MachineState::MACHINE_STATE_FAILED.into()
        } else {
            MachineState::MACHINE_STATE_JOINING.into()
        };
    }
    shown
}

fn declared(
    ports: impl Iterator<Item = (EnumValue<NetworkTransport>, u32)>,
) -> Result<Vec<NetworkPort>, ConnectError> {
    let ports = ports
        .map(|(transport, port)| {
            let transport = match transport.as_known() {
                Some(NetworkTransport::NETWORK_TRANSPORT_TCP) => Transport::Tcp,
                Some(NetworkTransport::NETWORK_TRANSPORT_UDP) => Transport::Udp,
                _ => {
                    return Err(ConnectError::invalid_argument(
                        "a port's transport is tcp or udp",
                    ));
                }
            };
            let port = u16::try_from(port)
                .map_err(|_| ConnectError::invalid_argument("a port is 1 to 65535"))?;
            Ok(NetworkPort { transport, port })
        })
        .collect::<Result<Vec<_>, _>>()?;
    declared_ports(ports).map_err(|error| match error {
        PortsError::Zero => ConnectError::invalid_argument("a port is 1 to 65535"),
        PortsError::TooMany => ConnectError::invalid_argument("declare at most 64 ports"),
    })
}

fn provider_step(step: ProviderStep) -> (EnumValue<ProviderStepProto>, String) {
    match step {
        ProviderStep::NotNeeded => (
            ProviderStepProto::PROVIDER_STEP_NOT_NEEDED.into(),
            String::new(),
        ),
        ProviderStep::Requested => (
            ProviderStepProto::PROVIDER_STEP_REQUESTED.into(),
            String::new(),
        ),
        ProviderStep::Failed(message) => (ProviderStepProto::PROVIDER_STEP_FAILED.into(), message),
    }
}

fn capabilities(value: &serde_json::Value) -> agent::Capabilities {
    agent::Capabilities {
        kvm: value["kvm"].as_bool().unwrap_or(false),
        root: value["root"].as_bool().unwrap_or(false),
        egress: value["egress"].as_bool().unwrap_or(false),
        free_vcpus: value["free_vcpus"].as_u64().unwrap_or(0) as u32,
        free_memory_mib: value["free_memory_mib"].as_u64().unwrap_or(0) as u32,
        apps: value["apps"].as_bool().unwrap_or(false),
        arch: value["arch"].as_str().unwrap_or_default().to_string(),
        memory_mib: value["memory_mib"].as_u64().unwrap_or(0),
        cpu_millis: value["cpu_millis"].as_u64().unwrap_or(0) as u32,
        apps_unavailable_reason: value["apps_unavailable_reason"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        max_replica_memory_mib: value["max_replica_memory_mib"].as_u64().unwrap_or(0),
        max_replica_cpu_millis: value["max_replica_cpu_millis"].as_u64().unwrap_or(0) as u32,
        disk_gib: value["disk_gib"].as_u64().unwrap_or(0),
        ..Default::default()
    }
}

fn vm(row: &VmRow, orders: &[(Uuid, Uuid, chrono::DateTime<chrono::Utc>)]) -> Vm {
    let artifact = |url: &str, sha256: &str| agent::Artifact {
        url: url.to_string(),
        sha256: sha256.to_string(),
        ..Default::default()
    };
    Vm {
        vm_id: row.vm_id.to_string(),
        name: row.name.clone(),
        host_machine_id: orders
            .iter()
            .find(|(_, machine_id, created_at)| {
                *machine_id == row.host_machine_id && *created_at <= row.created_at
            })
            .map_or_else(
                || {
                    if row.host_pool.as_deref() == Some("management") {
                        String::new()
                    } else {
                        row.host_machine_id.to_string()
                    }
                },
                |(order_id, _, _)| order_id.to_string(),
            ),
        host_name: row.host_name.clone().unwrap_or_default(),
        vcpus: row.vcpus as u32,
        memory_mib: row.memory_mib as u32,
        disk_gib: row.disk_gib as u32,
        image: MessageField::from(agent::VmImage {
            kernel: MessageField::from(artifact(&row.kernel_url, &row.kernel_sha256)),
            rootfs: MessageField::from(artifact(&row.rootfs_url, &row.rootfs_sha256)),
            ..Default::default()
        }),
        state: match row.state.as_str() {
            "running" => agent::VmDesiredState::VM_DESIRED_STATE_RUNNING,
            _ => agent::VmDesiredState::VM_DESIRED_STATE_STOPPED,
        }
        .into(),
        observed_state: match row.observed_state.as_deref() {
            Some("starting") => agent::VmObservedState::VM_OBSERVED_STATE_STARTING,
            Some("running") => agent::VmObservedState::VM_OBSERVED_STATE_RUNNING,
            Some("stopped") => agent::VmObservedState::VM_OBSERVED_STATE_STOPPED,
            Some("exited") => agent::VmObservedState::VM_OBSERVED_STATE_EXITED,
            Some("failed") => agent::VmObservedState::VM_OBSERVED_STATE_FAILED,
            _ => agent::VmObservedState::VM_OBSERVED_STATE_UNSPECIFIED,
        }
        .into(),
        observed_reason: row.observed_reason.clone().unwrap_or_default(),
        machine_id: row
            .machine_id
            .map(|id| {
                orders
                    .iter()
                    .find(|(_, machine_id, created_at)| {
                        *machine_id == id && *created_at <= row.created_at
                    })
                    .map_or(id, |(order_id, _, _)| *order_id)
                    .to_string()
            })
            .unwrap_or_default(),
        created_at: timestamp(row.created_at),
        ..Default::default()
    }
}

fn vm_done(outcome: VmOutcome) -> Result<VmRow, ConnectError> {
    match outcome {
        VmOutcome::Done(row) => Ok(*row),
        VmOutcome::NotFound => Err(ConnectError::not_found("no such machine or VM")),
        VmOutcome::CannotHost(reason) => Err(ConnectError::failed_precondition(reason)),
        VmOutcome::Invalid(message) => Err(ConnectError::invalid_argument(message)),
        VmOutcome::NameTaken => Err(ConnectError::failed_precondition(
            "another machine or VM in this organisation has that name",
        )),
        VmOutcome::PoolFull => Err(ConnectError::failed_precondition(
            "this organisation has all the machines it may have",
        )),
    }
}

fn minted(outcome: MintOutcome) -> Result<Minted, ConnectError> {
    match outcome {
        MintOutcome::Minted(minted) => Ok(minted),
        MintOutcome::Invalid(message) => Err(ConnectError::invalid_argument(message)),
        MintOutcome::TooMany => Err(ConnectError::resource_exhausted(
            "this pool has 20 unused setup codes; wait for some to expire",
        )),
        MintOutcome::NotReturning => Err(ConnectError::failed_precondition(
            "only a machine whose lease ended can register again",
        )),
        MintOutcome::NotFound => Err(ConnectError::not_found("no such machine")),
    }
}

fn changed(outcome: ChangeOutcome) -> Result<MachineRow, ConnectError> {
    match outcome {
        ChangeOutcome::Done(row) | ChangeOutcome::Leased(row, _) => Ok(row),
        ChangeOutcome::NotFound => Err(ConnectError::not_found("no such machine")),
        ChangeOutcome::NoOrganisation => {
            Err(ConnectError::invalid_argument("no such organisation"))
        }
        ChangeOutcome::NotAvailable => Err(ConnectError::failed_precondition(
            "only an available machine can be leased",
        )),
        ChangeOutcome::NotLeased => Err(ConnectError::failed_precondition(
            "the machine is not on lease",
        )),
        ChangeOutcome::NotAllowed => Err(ConnectError::failed_precondition(
            "that machine cannot be revoked here: a leased machine is the operator's",
        )),
        ChangeOutcome::PoolFull => Err(ConnectError::failed_precondition(
            "that organisation has all the machines it may have",
        )),
        ChangeOutcome::NameTaken => Err(ConnectError::failed_precondition(
            "another machine in that organisation has that name",
        )),
        ChangeOutcome::NameInvalid(message) => Err(ConnectError::invalid_argument(message)),
        ChangeOutcome::NotReturning => Err(ConnectError::failed_precondition(
            "only a machine whose lease ended can be rebuilt",
        )),
        ChangeOutcome::NoProvider => Err(ConnectError::failed_precondition(
            "that machine did not come from a capacity provider; wipe it and register it again \
             with CreateReregistrationToken",
        )),
    }
}

/// `grund.machine.v1.ManagementPoolService`.
pub struct ManagementPoolApi {
    state: State,
}

impl ManagementPoolApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn access(&self, caller: &Caller, needed: Access) -> Result<(), ConnectError> {
        match self
            .state
            .machines()
            .operator_access(caller.account_id)
            .await
            .map_err(internal)?
        {
            None => Err(ConnectError::not_found("no such pool")),
            Some(Access::Read) if needed == Access::Manage => Err(ConnectError::permission_denied(
                "only owners and admins of the operator organisation run the management pool",
            )),
            Some(_) => Ok(()),
        }
    }
}

#[allow(refining_impl_trait)]
impl ManagementPoolService for ManagementPoolApi {
    async fn create_registration_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateRegistrationTokenRequest>,
    ) -> ServiceResult<CreateRegistrationTokenResponse> {
        let caller = caller(&ctx)?;
        self.access(&caller, Access::Manage).await?;
        let minted = minted(
            self.state
                .machines()
                .mint(
                    TokenKind::Management,
                    None,
                    None,
                    request.name,
                    request.ttl_seconds,
                    caller.account_id,
                )
                .await
                .map_err(internal)?,
        )?;
        Response::ok(CreateRegistrationTokenResponse {
            token: minted.token,
            expires_at: timestamp(minted.expires_at),
            ..Default::default()
        })
    }

    async fn create_reregistration_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateReregistrationTokenRequest>,
    ) -> ServiceResult<CreateReregistrationTokenResponse> {
        let caller = caller(&ctx)?;
        self.access(&caller, Access::Manage).await?;
        let machine_id = uuid(request.machine_id)?;
        let minted = minted(
            self.state
                .machines()
                .mint(
                    TokenKind::Management,
                    None,
                    Some(machine_id),
                    "",
                    request.ttl_seconds,
                    caller.account_id,
                )
                .await
                .map_err(internal)?,
        )?;
        Response::ok(CreateReregistrationTokenResponse {
            token: minted.token,
            expires_at: timestamp(minted.expires_at),
            ..Default::default()
        })
    }

    async fn list_pool_machines(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListPoolMachinesRequest>,
    ) -> ServiceResult<ListPoolMachinesResponse> {
        let caller = caller(&ctx)?;
        self.access(&caller, Access::Read).await?;
        let rows = self
            .state
            .machines()
            .pool(state_name(request.state))
            .await
            .map_err(internal)?;
        Response::ok(ListPoolMachinesResponse {
            machines: rows
                .iter()
                .map(|r| machine(r, View::Management, None))
                .collect(),
            ..Default::default()
        })
    }

    async fn get_pool_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetPoolMachineRequest>,
    ) -> ServiceResult<GetPoolMachineResponse> {
        let caller = caller(&ctx)?;
        self.access(&caller, Access::Read).await?;
        let row = self
            .state
            .machines()
            .pool_machine(uuid(request.machine_id)?)
            .await
            .map_err(internal)?
            .ok_or_else(|| ConnectError::not_found("no such machine"))?;
        Response::ok(GetPoolMachineResponse {
            machine: MessageField::from(machine(&row, View::Management, None)),
            ..Default::default()
        })
    }

    async fn lease_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, LeaseMachineRequest>,
    ) -> ServiceResult<LeaseMachineResponse> {
        let caller = caller(&ctx)?;
        self.access(&caller, Access::Manage).await?;
        let outcome = self
            .state
            .machines()
            .lease(
                caller.account_id,
                uuid(request.machine_id)?,
                request.organisation,
                request.name,
            )
            .await
            .map_err(internal)?;
        let ChangeOutcome::Leased(row, grant) = outcome else {
            changed(outcome)?;
            return Err(internal("a lease ended without a grant"));
        };
        Response::ok(LeaseMachineResponse {
            machine: MessageField::from(machine(&row, View::Management, None)),
            grant: MessageField::from(agent::SignedLeaseGrant {
                key_id: grant.key_id.to_string(),
                payload: grant.payload,
                signature: grant.signature.to_vec(),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    async fn end_lease(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, EndLeaseRequest>,
    ) -> ServiceResult<EndLeaseResponse> {
        let caller = caller(&ctx)?;
        self.access(&caller, Access::Manage).await?;
        let (outcome, step) = self
            .state
            .machines()
            .end_lease(caller.account_id, uuid(request.machine_id)?)
            .await
            .map_err(internal)?;
        let row = changed(outcome)?;
        let (provider_step, provider_message) = provider_step(step);
        Response::ok(EndLeaseResponse {
            machine: MessageField::from(machine(&row, View::Management, None)),
            provider_step,
            provider_message,
            ..Default::default()
        })
    }

    async fn revoke_pool_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokePoolMachineRequest>,
    ) -> ServiceResult<RevokePoolMachineResponse> {
        let caller = caller(&ctx)?;
        self.access(&caller, Access::Manage).await?;
        let (outcome, step) = self
            .state
            .machines()
            .revoke_pool(caller.account_id, uuid(request.machine_id)?)
            .await
            .map_err(internal)?;
        let row = changed(outcome)?;
        let (provider_step, provider_message) = provider_step(step);
        Response::ok(RevokePoolMachineResponse {
            machine: MessageField::from(machine(&row, View::Management, None)),
            provider_step,
            provider_message,
            ..Default::default()
        })
    }

    async fn provision_pool_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ProvisionPoolMachineRequest>,
    ) -> ServiceResult<ProvisionPoolMachineResponse> {
        let caller = caller(&ctx)?;
        self.access(&caller, Access::Manage).await?;
        match self
            .state
            .machines()
            .provision(caller.account_id, request.name, request.size)
            .await
            .map_err(internal)?
        {
            ProvisionOutcome::Provisioned {
                provider_machine_id,
                token_expires_at,
            } => Response::ok(ProvisionPoolMachineResponse {
                provider_machine_id,
                token_expires_at: timestamp(token_expires_at),
                ..Default::default()
            }),
            ProvisionOutcome::NotConfigured => Err(ConnectError::failed_precondition(
                "this instance has no capacity provider; register machines by hand with a setup code",
            )),
            ProvisionOutcome::Invalid(message) => Err(ConnectError::invalid_argument(message)),
            ProvisionOutcome::TooMany => Err(ConnectError::resource_exhausted(
                "this pool has 20 unused setup codes; wait for some to expire",
            )),
            ProvisionOutcome::Unavailable => Err(ConnectError::unavailable(
                "the capacity provider cannot provision now; try again",
            )),
            ProvisionOutcome::Refused(message) => Err(ConnectError::failed_precondition(format!(
                "the capacity provider refused: {message}"
            ))),
        }
    }

    async fn rebuild_pool_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RebuildPoolMachineRequest>,
    ) -> ServiceResult<RebuildPoolMachineResponse> {
        let caller = caller(&ctx)?;
        self.access(&caller, Access::Manage).await?;
        let (outcome, step) = self
            .state
            .machines()
            .rebuild(caller.account_id, uuid(request.machine_id)?)
            .await
            .map_err(internal)?;
        let row = changed(outcome)?;
        let (provider_step, provider_message) = provider_step(step);
        Response::ok(RebuildPoolMachineResponse {
            machine: MessageField::from(machine(&row, View::Management, None)),
            provider_step,
            provider_message,
            ..Default::default()
        })
    }

    async fn set_migration_pause(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetMigrationPauseRequest>,
    ) -> ServiceResult<SetMigrationPauseResponse> {
        if ctx.extensions().get::<CapacityCaller>().is_none() {
            return Err(ConnectError::unauthenticated(
                "the capacity provider token is required",
            ));
        }
        let provider_machine_id = uuid(request.provider_machine_id)?.to_string();
        let migration_id = Uuid::parse_str(request.migration_id)
            .map_err(|_| ConnectError::invalid_argument("migration_id must be a UUID"))?;
        let found = self
            .state
            .entry()
            .set_migration_pause(&provider_machine_id, migration_id, request.paused)
            .await
            .map_err(internal)?;
        if !found {
            return Err(ConnectError::not_found("no such machine"));
        }
        Response::ok(SetMigrationPauseResponse::default())
    }
}

/// `grund.machine.v1.MachineService`.
pub struct MachineApi {
    state: State,
}

impl MachineApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    fn uses_external_hosted(&self) -> bool {
        self.state
            .extensions
            .iter()
            .any(|extension| extension.replaces_builtin_hosted())
    }

    async fn listings(
        &self,
        membership: &Membership,
    ) -> Result<Vec<crate::extension::ExternalMachine>, ConnectError> {
        let mut listings = Vec::new();
        for extension in self.state.extensions.iter() {
            listings.extend(
                extension
                    .machine_listings(&self.state, membership.organisation_id, &membership.slug)
                    .await
                    .map_err(internal)?,
            );
        }
        Ok(listings)
    }

    async fn member(
        &self,
        caller: &Principal,
        slug: &str,
        needed: Access,
    ) -> Result<Membership, ConnectError> {
        let membership = self
            .state
            .organisations()
            .membership(slug, caller.account_id)
            .await
            .map_err(internal)?
            .filter(|m| caller.reaches(m.organisation_id))
            .ok_or_else(|| ConnectError::not_found("no such organisation"))?;
        if needed == Access::Manage && !matches!(membership.role.as_str(), "owner" | "admin") {
            return Err(ConnectError::permission_denied(
                "only owners and admins manage an organisation's machines",
            ));
        }
        Ok(membership)
    }

    async fn pool_machine(
        &self,
        membership: &Membership,
        machine_id: &str,
    ) -> Result<MachineRow, ConnectError> {
        let id = uuid(machine_id)?;
        if self.uses_external_hosted() {
            let resolved = self
                .state
                .machine_id(membership.organisation_id, id)
                .await
                .map_err(internal)?;
            return self
                .state
                .machines()
                .organisation_machine(membership.organisation_id, resolved)
                .await
                .map_err(internal)?
                .filter(|row| {
                    row.pool != "management" || row.lease_id == Some(id) || resolved != id
                })
                .ok_or_else(|| ConnectError::not_found("no such machine"));
        }
        let machines = self.state.machines();
        if let Some(row) = machines
            .organisation_machine(membership.organisation_id, id)
            .await
            .map_err(internal)?
        {
            return Ok(row);
        }
        if let Some(machine_id) = machines
            .hosted_orders(membership.organisation_id)
            .await
            .map_err(internal)?
            .into_iter()
            .find(|order| order.order_id == id)
            .and_then(|order| order.machine_id)
        {
            return machines
                .organisation_machine(membership.organisation_id, machine_id)
                .await
                .map_err(internal)?
                .ok_or_else(|| ConnectError::not_found("no such machine"));
        }
        Err(ConnectError::not_found("no such machine"))
    }

    async fn visible_machine(
        &self,
        membership: &Membership,
        row: &MachineRow,
    ) -> Result<Machine, ConnectError> {
        if self.uses_external_hosted() {
            let listings = self.listings(membership).await?;
            return Ok(
                match listings
                    .iter()
                    .find(|listing| listing.machine_id == Some(row.machine_id))
                {
                    Some(listing) => external_machine(listing, Some(row), &membership.slug),
                    None => machine(row, View::Organisation, Some(&membership.slug)),
                },
            );
        }
        let orders = self
            .state
            .machines()
            .hosted_orders(membership.organisation_id)
            .await
            .map_err(internal)?;
        Ok(
            match orders
                .iter()
                .find(|order| order.machine_id == Some(row.machine_id))
            {
                Some(order) => hosted_machine(order, Some(row)),
                None => machine(row, View::Organisation, Some(&membership.slug)),
            },
        )
    }
}

#[allow(refining_impl_trait)]
impl MachineService for MachineApi {
    async fn create_join_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateJoinTokenRequest>,
    ) -> ServiceResult<CreateJoinTokenResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let minted = minted(
            self.state
                .machines()
                .mint(
                    TokenKind::Organisation,
                    Some(membership.organisation_id),
                    None,
                    request.name,
                    request.ttl_seconds,
                    caller.account_id,
                )
                .await
                .map_err(internal)?,
        )?;
        Response::ok(CreateJoinTokenResponse {
            install_command: crate::services::machines::install_command(
                &self.state.config,
                &minted.token,
            )
            .unwrap_or_default(),
            token: minted.token,
            expires_at: timestamp(minted.expires_at),
            ..Default::default()
        })
    }

    async fn list_hosted_offers(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListHostedOffersRequest>,
    ) -> ServiceResult<ListHostedOffersResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let offers = self
            .state
            .machines()
            .hosted_offers(membership.organisation_id)
            .await
            .map_err(internal)?
            .ok_or_else(|| {
                ConnectError::permission_denied(
                    "Hosted machines are not enabled for this organisation",
                )
            })?;
        Response::ok(ListHostedOffersResponse {
            offers: offers
                .into_iter()
                .map(|offer| HostedOffer {
                    size: offer.size,
                    region: offer.region,
                    vcpus: offer.vcpus,
                    memory_mib: offer.memory_mib,
                    disk_gib: offer.disk_gib,
                    available: offer.can_place,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn create_hosted_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateHostedMachineRequest>,
    ) -> ServiceResult<CreateHostedMachineResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let result = self
            .state
            .machines()
            .create_hosted(
                caller.account_id,
                membership.organisation_id,
                request.name,
                request.size,
                request.region,
                request.idempotency_key,
            )
            .await
            .map_err(internal)?;
        let order = match result {
            HostedCreate::Created(order) => order,
            HostedCreate::Denied => {
                return Err(ConnectError::permission_denied(
                    "Hosted machines are not enabled for this organisation",
                ));
            }
            HostedCreate::Invalid => {
                return Err(ConnectError::invalid_argument(
                    "Choose a valid machine name, size, region and retry key",
                ));
            }
            HostedCreate::NameTaken => {
                return Err(ConnectError::already_exists(
                    "That machine name is already in use",
                ));
            }
            HostedCreate::PoolFull => {
                return Err(ConnectError::resource_exhausted(
                    "This organisation has reached its machine limit",
                ));
            }
            HostedCreate::NoCapacity => {
                return Err(ConnectError::resource_exhausted("No capacity in this size"));
            }
            HostedCreate::Unavailable => {
                return Err(ConnectError::unavailable(
                    "Hosted machines are temporarily unavailable",
                ));
            }
        };
        let row = match order.machine_id {
            Some(id) => self
                .state
                .machines()
                .organisation_machine(membership.organisation_id, id)
                .await
                .map_err(internal)?,
            None => None,
        };
        Response::ok(CreateHostedMachineResponse {
            machine: MessageField::from(hosted_machine(&order, row.as_ref())),
            ..Default::default()
        })
    }

    async fn remove_hosted_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RemoveHostedMachineRequest>,
    ) -> ServiceResult<RemoveHostedMachineResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        match self
            .state
            .machines()
            .remove_hosted(
                caller.account_id,
                membership.organisation_id,
                uuid(request.machine_id)?,
            )
            .await
            .map_err(internal)?
        {
            HostedRemove::Removed => Response::ok(RemoveHostedMachineResponse {
                removed: true,
                ..Default::default()
            }),
            HostedRemove::NotFound => Err(ConnectError::not_found("no such machine")),
            HostedRemove::Unavailable => Err(ConnectError::unavailable(
                "Machine removal is temporarily unavailable",
            )),
        }
    }

    async fn list_machines(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListMachinesRequest>,
    ) -> ServiceResult<ListMachinesResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let rows = self
            .state
            .machines()
            .organisation_machines(membership.organisation_id)
            .await
            .map_err(internal)?;
        if self.uses_external_hosted() {
            let listings = self.listings(&membership).await?;
            let mut listed: Vec<Machine> = rows
                .iter()
                .filter(|row| {
                    !listings
                        .iter()
                        .any(|listing| listing.machine_id == Some(row.machine_id))
                })
                .map(|row| machine(row, View::Organisation, Some(&membership.slug)))
                .collect();
            listed.extend(listings.iter().map(|listing| {
                external_machine(
                    listing,
                    listing
                        .machine_id
                        .and_then(|id| rows.iter().find(|row| row.machine_id == id)),
                    &membership.slug,
                )
            }));
            return Response::ok(ListMachinesResponse {
                machines: listed,
                ..Default::default()
            });
        }
        let orders = self
            .state
            .machines()
            .hosted_orders(membership.organisation_id)
            .await
            .map_err(internal)?;
        let mut listed: Vec<Machine> = rows
            .iter()
            .filter(|row| {
                !orders
                    .iter()
                    .any(|order| order.machine_id == Some(row.machine_id))
            })
            .map(|row| machine(row, View::Organisation, Some(&membership.slug)))
            .collect();
        listed.extend(orders.iter().map(|order| {
            hosted_machine(
                order,
                order
                    .machine_id
                    .and_then(|id| rows.iter().find(|row| row.machine_id == id)),
            )
        }));
        Response::ok(ListMachinesResponse {
            machines: listed,
            ..Default::default()
        })
    }

    async fn get_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetMachineRequest>,
    ) -> ServiceResult<GetMachineResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let id = uuid(request.machine_id)?;
        if self.uses_external_hosted() {
            let listings = self.listings(&membership).await?;
            if let Some(listing) = listings
                .iter()
                .find(|listing| listing.id == id || listing.machine_id == Some(id))
            {
                let row = match listing.machine_id {
                    Some(machine_id) => self
                        .state
                        .machines()
                        .organisation_machine(membership.organisation_id, machine_id)
                        .await
                        .map_err(internal)?,
                    None => None,
                };
                return Response::ok(GetMachineResponse {
                    machine: MessageField::from(external_machine(
                        listing,
                        row.as_ref(),
                        &membership.slug,
                    )),
                    ..Default::default()
                });
            }
            let row = self.pool_machine(&membership, request.machine_id).await?;
            return Response::ok(GetMachineResponse {
                machine: MessageField::from(machine(
                    &row,
                    View::Organisation,
                    Some(&membership.slug),
                )),
                ..Default::default()
            });
        }
        let order = self
            .state
            .machines()
            .hosted_orders(membership.organisation_id)
            .await
            .map_err(internal)?
            .into_iter()
            .find(|order| order.order_id == id || order.machine_id == Some(id));
        let row = match order.as_ref().and_then(|order| order.machine_id) {
            Some(id) => self
                .state
                .machines()
                .organisation_machine(membership.organisation_id, id)
                .await
                .map_err(internal)?,
            None if order.is_some() => None,
            None => Some(self.pool_machine(&membership, request.machine_id).await?),
        };
        Response::ok(GetMachineResponse {
            machine: MessageField::from(match order {
                Some(order) => hosted_machine(&order, row.as_ref()),
                None => machine(
                    &row.ok_or_else(|| ConnectError::not_found("no such machine"))?,
                    View::Organisation,
                    Some(&membership.slug),
                ),
            }),
            ..Default::default()
        })
    }

    async fn revoke_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeMachineRequest>,
    ) -> ServiceResult<RevokeMachineResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let row = self.pool_machine(&membership, request.machine_id).await?;
        let row = changed(
            self.state
                .machines()
                .revoke(
                    caller.account_id,
                    row.machine_id,
                    Authority::Organisation(membership.organisation_id),
                )
                .await
                .map_err(internal)?,
        )?;
        Response::ok(RevokeMachineResponse {
            machine: MessageField::from(self.visible_machine(&membership, &row).await?),
            ..Default::default()
        })
    }

    async fn declare_machine_ports(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeclareMachinePortsRequest>,
    ) -> ServiceResult<DeclareMachinePortsResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let ports = declared(request.ports.iter().map(|p| (p.transport, p.port)))?;
        let row = self.pool_machine(&membership, request.machine_id).await?;
        let outcome = self
            .state
            .machines()
            .declare_ports(
                caller.account_id,
                row.machine_id,
                membership.organisation_id,
                ports,
            )
            .await
            .map_err(internal)?;
        let row = match outcome {
            ChangeOutcome::NotAllowed => {
                return Err(ConnectError::failed_precondition(
                    "that machine is not in this organisation's pool",
                ));
            }
            outcome => changed(outcome)?,
        };
        Response::ok(DeclareMachinePortsResponse {
            machine: MessageField::from(self.visible_machine(&membership, &row).await?),
            ..Default::default()
        })
    }

    async fn set_machine_labels(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetMachineLabelsRequest>,
    ) -> ServiceResult<SetMachineLabelsResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let labels = grund_domain::labels::labels(request.labels.iter().map(|(k, v)| (*k, *v)))
            .map_err(|e| ConnectError::invalid_argument(e.to_string()))?;
        let row = self.pool_machine(&membership, request.machine_id).await?;
        let outcome = self
            .state
            .machines()
            .set_labels(
                caller.account_id,
                row.machine_id,
                membership.organisation_id,
                labels,
            )
            .await
            .map_err(internal)?;
        let row = match outcome {
            ChangeOutcome::NotAllowed => {
                return Err(ConnectError::failed_precondition(
                    "that machine is not in this organisation's pool",
                ));
            }
            outcome => changed(outcome)?,
        };
        Response::ok(SetMachineLabelsResponse {
            machine: MessageField::from(self.visible_machine(&membership, &row).await?),
            ..Default::default()
        })
    }

    async fn set_machine_in_service(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetMachineInServiceRequest>,
    ) -> ServiceResult<SetMachineInServiceResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let row = self.pool_machine(&membership, request.machine_id).await?;
        let outcome = self
            .state
            .machines()
            .set_in_service(
                caller.account_id,
                row.machine_id,
                membership.organisation_id,
                request.in_service,
            )
            .await
            .map_err(internal)?;
        let row = match outcome {
            ChangeOutcome::NotAllowed => {
                return Err(ConnectError::failed_precondition(
                    "that machine is not in this organisation's pool",
                ));
            }
            outcome => changed(outcome)?,
        };
        Response::ok(SetMachineInServiceResponse {
            machine: MessageField::from(self.visible_machine(&membership, &row).await?),
            ..Default::default()
        })
    }

    async fn get_organisation_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetOrganisationKeyRequest>,
    ) -> ServiceResult<GetOrganisationKeyResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let key = self
            .state
            .machines()
            .organisation_key(membership.organisation_id)
            .await
            .map_err(internal)?;
        Response::ok(GetOrganisationKeyResponse {
            key: MessageField::from(public_key_message(&key)),
            ..Default::default()
        })
    }

    async fn run_vm(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RunVmRequest>,
    ) -> ServiceResult<RunVmResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let host_machine_id = self
            .pool_machine(&membership, request.on_machine_id)
            .await?
            .machine_id;
        let image = request.image.as_option();
        let kernel = image.and_then(|i| i.kernel.as_option());
        let rootfs = image.and_then(|i| i.rootfs.as_option());
        let outcome = self
            .state
            .agents()
            .run_vm(
                caller.account_id,
                membership.organisation_id,
                &VmRequest {
                    host_machine_id,
                    name: request.name.to_string(),
                    vcpus: request.vcpus,
                    memory_mib: request.memory_mib,
                    disk_gib: request.disk_gib,
                    kernel_url: kernel.map(|k| k.url.to_string()).unwrap_or_default(),
                    kernel_sha256: kernel.map(|k| k.sha256.to_string()).unwrap_or_default(),
                    rootfs_url: rootfs.map(|r| r.url.to_string()).unwrap_or_default(),
                    rootfs_sha256: rootfs.map(|r| r.sha256.to_string()).unwrap_or_default(),
                },
            )
            .await
            .map_err(internal)?;
        let row = vm_done(outcome)?;
        let orders = self
            .state
            .vm_aliases(membership.organisation_id)
            .await
            .map_err(internal)?;
        Response::ok(RunVmResponse {
            vm: MessageField::from(vm(&row, &orders)),
            ..Default::default()
        })
    }

    async fn stop_vm(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, StopVmRequest>,
    ) -> ServiceResult<StopVmResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let vm_id =
            Uuid::parse_str(request.vm_id).map_err(|_| ConnectError::not_found("no such VM"))?;
        let row = vm_done(
            self.state
                .agents()
                .stop_vm(membership.organisation_id, vm_id)
                .await
                .map_err(internal)?,
        )?;
        let orders = self
            .state
            .vm_aliases(membership.organisation_id)
            .await
            .map_err(internal)?;
        Response::ok(StopVmResponse {
            vm: MessageField::from(vm(&row, &orders)),
            ..Default::default()
        })
    }

    async fn list_vms(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListVmsRequest>,
    ) -> ServiceResult<ListVmsResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let rows = self
            .state
            .agents()
            .vms(membership.organisation_id)
            .await
            .map_err(internal)?;
        let orders = self
            .state
            .vm_aliases(membership.organisation_id)
            .await
            .map_err(internal)?;
        Response::ok(ListVmsResponse {
            vms: rows.iter().map(|row| vm(row, &orders)).collect(),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hosted_machine_facts_hide_provider_and_host_identity() {
        let details = hosted_facts(&serde_json::json!({
            "hostname": "hosted-a",
            "fleet_machine_id": "fleet-secret-1",
            "os": "fleet-guest 0.1.0",
            "kernel": "6.18",
            "cpus": 1
        }));
        assert_eq!(details.os, "Linux");
        assert!(details.hostname.is_empty());
        assert!(details.fleet_machine_id.is_empty());
        assert_eq!(details.kernel, "6.18");
    }

    #[test]
    fn vm_hosts_never_expose_a_removed_management_machine_id() {
        let host = Uuid::now_v7();
        let public = Uuid::now_v7();
        let created_at = Utc::now();
        let mut row = VmRow {
            vm_id: Uuid::now_v7(),
            organisation_id: Uuid::now_v7(),
            host_machine_id: host,
            host_name: Some("customer-machine".into()),
            host_pool: Some("management".into()),
            name: "child".into(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 2,
            kernel_url: String::new(),
            kernel_sha256: String::new(),
            rootfs_url: String::new(),
            rootfs_sha256: String::new(),
            state: "running".into(),
            observed_state: None,
            observed_reason: None,
            machine_id: None,
            created_at,
        };
        assert_eq!(
            vm(&row, &[(public, host, created_at)]).host_machine_id,
            public.to_string()
        );
        assert!(vm(&row, &[]).host_machine_id.is_empty());
        row.host_pool = Some("organisation".into());
        assert_eq!(vm(&row, &[]).host_machine_id, host.to_string());
    }
}
