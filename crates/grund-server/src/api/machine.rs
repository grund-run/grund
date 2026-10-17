//! `grund.machine.v1`: an organisation's own machines and its virtual
//! machines. A machine outside the caller's organisation is not found.

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
        CreateJoinTokenRequest, CreateJoinTokenResponse, DeclareMachinePortsRequest,
        DeclareMachinePortsResponse, GetMachineRequest, GetMachineResponse,
        GetOrganisationKeyRequest, GetOrganisationKeyResponse, ListMachinesRequest,
        ListMachinesResponse, ListVmsRequest, ListVmsResponse, Machine, MachineService,
        MachineState, NetworkPort as NetworkPortProto, NetworkTransport, RevokeMachineRequest,
        RevokeMachineResponse, RunVmRequest, RunVmResponse, SetMachineInServiceRequest,
        SetMachineInServiceResponse, SetMachineLabelsRequest, SetMachineLabelsResponse,
        StopVmRequest, StopVmResponse, Vm,
    },
};
use grund_store::{agents::VmRow, machines::MachineRow, organisations::Membership};
use uuid::Uuid;

use crate::{
    api::{Principal, principal},
    services::{
        OrganisationsState,
        agents::{AgentsState, VmOutcome, VmRequest},
        machines::{Access, ChangeOutcome, MachinesState, MintOutcome, Minted, public_key_message},
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

fn facts(value: &serde_json::Value, external_os: Option<&str>) -> agent::MachineFacts {
    let text = |key: &str| value[key].as_str().unwrap_or_default().to_string();
    agent::MachineFacts {
        hostname: if external_os.is_some() {
            String::new()
        } else {
            text("hostname")
        },
        arch: text("arch"),
        cpu_model: text("cpu_model"),
        cpus: value["cpus"].as_i64().unwrap_or_default() as i32,
        memory_mib: value["memory_mib"].as_i64().unwrap_or_default(),
        disk_gib: value["disk_gib"].as_i64().unwrap_or_default(),
        os: external_os.map_or_else(|| text("os"), str::to_owned),
        kernel: text("kernel"),
        agent_version: text("agent_version"),
        fleet_machine_id: if external_os.is_some() {
            String::new()
        } else {
            text("fleet_machine_id")
        },
        ..Default::default()
    }
}

fn machine(row: &MachineRow, own_slug: &str) -> Machine {
    let leased = row.pool == "management";
    let name = if leased {
        row.pool_name.clone().unwrap_or_default()
    } else {
        row.pool_name.clone().unwrap_or_else(|| row.name.clone())
    };
    let organisation = row
        .lessee_slug
        .clone()
        .unwrap_or_else(|| own_slug.to_string());
    Machine {
        machine_id: if leased {
            row.lease_id.map(|id| id.to_string()).unwrap_or_default()
        } else {
            row.machine_id.to_string()
        },
        name,
        state: if leased {
            MachineState::MACHINE_STATE_ACTIVE.into()
        } else {
            state(&row.state)
        },
        pool: if leased {
            agent::Pool::POOL_UNSPECIFIED
        } else {
            agent::Pool::POOL_ORGANISATION
        }
        .into(),
        organisation,
        public_key: if leased {
            Vec::new()
        } else {
            row.public_key
                .as_deref()
                .and_then(|hex| hex::decode(hex).ok())
                .unwrap_or_default()
        },
        facts: if leased {
            MessageField::default()
        } else {
            MessageField::from(facts(&row.facts.0, None))
        },
        registered_at: if leased {
            MessageField::default()
        } else {
            timestamp(row.registered_at)
        },
        key_registered_at: if leased {
            MessageField::default()
        } else {
            timestamp(row.key_registered_at)
        },
        minted_by: if leased {
            String::new()
        } else {
            row.minted_by.clone()
        },
        provider_machine_id: String::new(),
        connected: crate::services::agents::connected(row.last_seen_at, Utc::now()),
        last_seen_at: row.last_seen_at.map(timestamp).unwrap_or_default(),
        capabilities: if leased {
            MessageField::default()
        } else {
            row.capabilities
                .as_ref()
                .map(|c| MessageField::from(capabilities(&c.0)))
                .unwrap_or_default()
        },
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
        hosted: leased,
        ..Default::default()
    }
}

fn external_machine(
    listing: &crate::extension::ExternalMachine,
    row: Option<&MachineRow>,
    slug: &str,
) -> Machine {
    let mut shown = row.map(|row| machine(row, slug)).unwrap_or_default();
    shown.machine_id = listing.id.to_string();
    shown.name = listing.name.clone();
    shown.hosted = true;
    shown.pool = agent::Pool::POOL_UNSPECIFIED.into();
    shown.lease = MessageField::default();
    if let (Some(row), Some(os)) = (row, listing.os) {
        shown.facts = MessageField::from(facts(&row.facts.0, Some(os)));
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
                    .map_or_else(
                        || {
                            if row.host_pool.as_deref() == Some("management") {
                                String::new()
                            } else {
                                id.to_string()
                            }
                        },
                        |(public_id, _, _)| public_id.to_string(),
                    )
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
            "a leased machine cannot be revoked here",
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
        let resolved = self
            .state
            .machine_id(membership.organisation_id, id)
            .await
            .map_err(internal)?;
        self.state
            .machines()
            .organisation_machine(membership.organisation_id, resolved)
            .await
            .map_err(internal)?
            .filter(|row| row.pool != "management" || row.lease_id == Some(id) || resolved != id)
            .ok_or_else(|| ConnectError::not_found("no such machine"))
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

    async fn visible_machine(
        &self,
        membership: &Membership,
        row: &MachineRow,
    ) -> Result<Machine, ConnectError> {
        let listings = self.listings(membership).await?;
        Ok(
            match listings
                .iter()
                .find(|item| item.machine_id == Some(row.machine_id))
            {
                Some(item) => external_machine(item, Some(row), &membership.slug),
                None => machine(row, &membership.slug),
            },
        )
    }

    async fn vm_aliases(
        &self,
        organisation_id: Uuid,
    ) -> Result<Vec<(Uuid, Uuid, DateTime<Utc>)>, ConnectError> {
        let mut aliases = Vec::new();
        for extension in self.state.extensions.iter() {
            aliases.extend(
                extension
                    .vm_aliases(&self.state, organisation_id)
                    .await
                    .map_err(internal)?,
            );
        }
        aliases.extend(
            self.state
                .machines()
                .organisation_machines(organisation_id)
                .await
                .map_err(internal)?
                .into_iter()
                .filter(|row| row.pool == "management")
                .filter_map(|row| Some((row.lease_id?, row.machine_id, row.leased_at?))),
        );
        Ok(aliases)
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
        let external = self.listings(&membership).await?;
        let mut listed: Vec<Machine> = rows
            .iter()
            .filter(|row| row.pool != "management" || row.lease_id.is_some())
            .filter(|row| {
                !external
                    .iter()
                    .any(|item| item.machine_id == Some(row.machine_id))
            })
            .map(|row| machine(row, &membership.slug))
            .collect();
        listed.extend(external.iter().map(|item| {
            external_machine(
                item,
                item.machine_id
                    .and_then(|id| rows.iter().find(|row| row.machine_id == id)),
                &membership.slug,
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
        let external = self.listings(&membership).await?;
        let shown = if let Some(item) = external.iter().find(|item| item.id == id) {
            let row = match item.machine_id {
                Some(machine_id) => self
                    .state
                    .machines()
                    .organisation_machine(membership.organisation_id, machine_id)
                    .await
                    .map_err(internal)?,
                None => None,
            };
            external_machine(item, row.as_ref(), &membership.slug)
        } else {
            let row = self.pool_machine(&membership, request.machine_id).await?;
            machine(&row, &membership.slug)
        };
        Response::ok(GetMachineResponse {
            machine: MessageField::from(shown),
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
        let labels = grund_config::labels::labels(request.labels.iter().map(|(k, v)| (*k, *v)))
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
        let orders = self.vm_aliases(membership.organisation_id).await?;
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
        let orders = self.vm_aliases(membership.organisation_id).await?;
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
        let orders = self.vm_aliases(membership.organisation_id).await?;
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
