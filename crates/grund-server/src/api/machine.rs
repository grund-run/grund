//! `grund.machine.v1`: the management pool, run by the operator
//! organisation, and each organisation's own pool (grund-docs
//! design/machines.md §6.2–6.3). A pool the caller may not see is
//! not_found, as an organisation they are not a member of is.

use buffa::{EnumValue, MessageField};
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_domain::machine::{Authority, TokenKind};
use grund_proto::grund::{
    agent::v1 as agent,
    machine::v1::{
        CreateJoinTokenRequest, CreateJoinTokenResponse, CreateRegistrationTokenRequest,
        CreateRegistrationTokenResponse, CreateReregistrationTokenRequest,
        CreateReregistrationTokenResponse, EndLeaseRequest, EndLeaseResponse, GetMachineRequest,
        GetMachineResponse, GetOrganisationKeyRequest, GetOrganisationKeyResponse,
        GetPoolMachineRequest, GetPoolMachineResponse, Lease, LeaseMachineRequest,
        LeaseMachineResponse, ListMachinesRequest, ListMachinesResponse, ListPoolMachinesRequest,
        ListPoolMachinesResponse, ListVmsRequest, ListVmsResponse, Machine, MachineService,
        MachineState, ManagementPoolService, ProviderStep as ProviderStepProto,
        ProvisionPoolMachineRequest, ProvisionPoolMachineResponse, RebuildPoolMachineRequest,
        RebuildPoolMachineResponse, RevokeMachineRequest, RevokeMachineResponse,
        RevokePoolMachineRequest, RevokePoolMachineResponse, RunVmRequest, RunVmResponse,
        StopVmRequest, StopVmResponse, Vm,
    },
};
use grund_store::{agents::VmRow, machines::MachineRow, organisations::Membership};
use uuid::Uuid;

use crate::{
    api::{Caller, caller},
    services::{
        OrganisationsState,
        agents::{AgentsState, VmOutcome, VmRequest},
        machines::{
            Access, ChangeOutcome, MachinesState, MintOutcome, Minted, ProviderStep,
            ProvisionOutcome, public_key_message,
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

fn facts(value: &serde_json::Value) -> agent::MachineFacts {
    let text = |key: &str| value[key].as_str().unwrap_or_default().to_string();
    agent::MachineFacts {
        hostname: text("hostname"),
        arch: text("arch"),
        cpu_model: text("cpu_model"),
        cpus: value["cpus"].as_i64().unwrap_or_default() as i32,
        memory_mib: value["memory_mib"].as_i64().unwrap_or_default(),
        disk_gib: value["disk_gib"].as_i64().unwrap_or_default(),
        os: text("os"),
        kernel: text("kernel"),
        agent_version: text("agent_version"),
        fleet_machine_id: text("fleet_machine_id"),
        ..Default::default()
    }
}

#[derive(Clone, Copy)]
enum View {
    Management,
    Organisation,
}

fn machine(row: &MachineRow, view: View, own_slug: Option<&str>) -> Machine {
    let name = match view {
        View::Organisation => row.pool_name.clone().unwrap_or_else(|| row.name.clone()),
        View::Management => row.name.clone(),
    };
    let organisation = match (row.lessee_slug.as_deref(), own_slug) {
        (Some(lessee), _) => lessee.to_string(),
        (None, Some(own)) if row.pool == "organisation" => own.to_string(),
        _ => String::new(),
    };
    let lease = row.lease_id.map(|lease_id| Lease {
        lease_id: lease_id.to_string(),
        organisation: row.lessee_slug.clone().unwrap_or_default(),
        name: row.lease_name.clone().unwrap_or_default(),
        leased_at: row.leased_at.map(timestamp).unwrap_or_default(),
        ..Default::default()
    });
    Machine {
        machine_id: row.machine_id.to_string(),
        name,
        state: state(&row.state),
        pool: match row.pool.as_str() {
            "management" => agent::Pool::POOL_MANAGEMENT,
            _ => agent::Pool::POOL_ORGANISATION,
        }
        .into(),
        organisation,
        lease: lease.map(MessageField::from).unwrap_or_default(),
        public_key: row
            .public_key
            .as_deref()
            .and_then(|hex| hex::decode(hex).ok())
            .unwrap_or_default(),
        facts: MessageField::from(facts(&row.facts.0)),
        registered_at: timestamp(row.registered_at),
        key_registered_at: timestamp(row.key_registered_at),
        minted_by: row.minted_by.clone(),
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
        ..Default::default()
    }
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
        ..Default::default()
    }
}

fn vm(row: &VmRow) -> Vm {
    let artifact = |url: &str, sha256: &str| agent::Artifact {
        url: url.to_string(),
        sha256: sha256.to_string(),
        ..Default::default()
    };
    Vm {
        vm_id: row.vm_id.to_string(),
        name: row.name.clone(),
        host_machine_id: row.host_machine_id.to_string(),
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
        machine_id: row.machine_id.map(|id| id.to_string()).unwrap_or_default(),
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
}

/// `grund.machine.v1.MachineService`.
pub struct MachineApi {
    state: State,
}

impl MachineApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn member(
        &self,
        caller: &Caller,
        slug: &str,
        needed: Access,
    ) -> Result<Membership, ConnectError> {
        let membership = self
            .state
            .organisations()
            .membership(slug, caller.account_id)
            .await
            .map_err(internal)?
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
        self.state
            .machines()
            .organisation_machine(membership.organisation_id, uuid(machine_id)?)
            .await
            .map_err(internal)?
            .ok_or_else(|| ConnectError::not_found("no such machine"))
    }
}

#[allow(refining_impl_trait)]
impl MachineService for MachineApi {
    async fn create_join_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateJoinTokenRequest>,
    ) -> ServiceResult<CreateJoinTokenResponse> {
        let caller = caller(&ctx)?;
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
            token: minted.token,
            expires_at: timestamp(minted.expires_at),
            ..Default::default()
        })
    }

    async fn list_machines(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListMachinesRequest>,
    ) -> ServiceResult<ListMachinesResponse> {
        let caller = caller(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let rows = self
            .state
            .machines()
            .organisation_machines(membership.organisation_id)
            .await
            .map_err(internal)?;
        Response::ok(ListMachinesResponse {
            machines: rows
                .iter()
                .map(|r| machine(r, View::Organisation, Some(&membership.slug)))
                .collect(),
            ..Default::default()
        })
    }

    async fn get_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetMachineRequest>,
    ) -> ServiceResult<GetMachineResponse> {
        let caller = caller(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let row = self.pool_machine(&membership, request.machine_id).await?;
        Response::ok(GetMachineResponse {
            machine: MessageField::from(machine(&row, View::Organisation, Some(&membership.slug))),
            ..Default::default()
        })
    }

    async fn revoke_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeMachineRequest>,
    ) -> ServiceResult<RevokeMachineResponse> {
        let caller = caller(&ctx)?;
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
            machine: MessageField::from(machine(&row, View::Organisation, Some(&membership.slug))),
            ..Default::default()
        })
    }

    async fn get_organisation_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetOrganisationKeyRequest>,
    ) -> ServiceResult<GetOrganisationKeyResponse> {
        let caller = caller(&ctx)?;
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
        let caller = caller(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let host_machine_id = uuid(request.on_machine_id)?;
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
        Response::ok(RunVmResponse {
            vm: MessageField::from(vm(&row)),
            ..Default::default()
        })
    }

    async fn stop_vm(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, StopVmRequest>,
    ) -> ServiceResult<StopVmResponse> {
        let caller = caller(&ctx)?;
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
        Response::ok(StopVmResponse {
            vm: MessageField::from(vm(&row)),
            ..Default::default()
        })
    }

    async fn list_vms(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListVmsRequest>,
    ) -> ServiceResult<ListVmsResponse> {
        let caller = caller(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let rows = self
            .state
            .agents()
            .vms(membership.organisation_id)
            .await
            .map_err(internal)?;
        Response::ok(ListVmsResponse {
            vms: rows.iter().map(vm).collect(),
            ..Default::default()
        })
    }
}
