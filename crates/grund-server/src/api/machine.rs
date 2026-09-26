//! `grund.machine.v1.MachineService`: an organisation's machines, and the
//! tokens new ones enroll with. An organisation the caller is not a member of
//! is not_found, and so is another organisation's machine.

use buffa::MessageField;
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_domain::machine::MachineFacts as Facts;
use grund_proto::grund::machine::v1::{
    CreateEnrollmentTokenRequest, CreateEnrollmentTokenResponse, ListMachinesRequest,
    ListMachinesResponse, Machine, MachineFacts, MachineService, RevokeMachineRequest,
    RevokeMachineResponse,
};
use grund_store::{machines::MachineRow, organisations::Membership};
use uuid::Uuid;

use crate::{
    api::{Caller, caller},
    services::{
        OrganisationsState,
        accounts::RequestMeta,
        machines::{MachinesState, MintOutcome, RevokeOutcome},
    },
    state::State,
};

/// The service implementation.
pub struct MachineApi {
    state: State,
}

impl MachineApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn member(&self, caller: &Caller, slug: &str) -> Result<Membership, ConnectError> {
        self.state
            .organisations()
            .membership(slug, caller.account_id)
            .await
            .map_err(internal)?
            .ok_or_else(|| ConnectError::not_found("no such organisation"))
    }
}

fn timestamp<P: buffa::ProtoBox<Timestamp>>(at: DateTime<Utc>) -> MessageField<Timestamp, P> {
    Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into()
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "machine API call failed");
    ConnectError::internal("grund could not finish that")
}

/// A machine for the API. Facts that no longer parse are shown empty.
pub fn machine(row: &MachineRow) -> Machine {
    let facts: Facts = serde_json::from_value(row.facts.0.clone()).unwrap_or_default();
    Machine {
        machine_id: row.machine_id.to_string(),
        name: row.name.clone(),
        minted_by: row.minted_by.clone(),
        enrolled_at: timestamp(row.enrolled_at),
        revoked_at: row.revoked_at.map(timestamp).unwrap_or_default(),
        facts: MessageField::from(MachineFacts {
            hostname: facts.hostname,
            arch: facts.arch,
            cpu_model: facts.cpu_model,
            cpus: facts.cpus,
            memory_mib: facts.memory_mib,
            disk_gib: facts.disk_gib,
            os: facts.os,
            kernel: facts.kernel,
            agent_version: facts.agent_version,
            fleet_machine_id: facts.fleet_machine_id,
            ..Default::default()
        }),
        public_key: row.public_key.clone(),
        ..Default::default()
    }
}

#[allow(refining_impl_trait)]
impl MachineService for MachineApi {
    async fn create_enrollment_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateEnrollmentTokenRequest>,
    ) -> ServiceResult<CreateEnrollmentTokenResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        match self
            .state
            .machines()
            .mint(
                caller.account_id,
                &membership,
                request.machine_name,
                request.ttl_seconds,
            )
            .await
            .map_err(internal)?
        {
            MintOutcome::Minted { token, expires_at } => {
                Response::ok(CreateEnrollmentTokenResponse {
                    token,
                    expires_at: timestamp(expires_at),
                    ..Default::default()
                })
            }
            MintOutcome::Invalid(message) => Err(ConnectError::invalid_argument(message)),
            MintOutcome::NotAllowed => Err(ConnectError::permission_denied(
                "only owners and admins add machines",
            )),
            MintOutcome::TooMany => Err(ConnectError::resource_exhausted(
                "this organisation has 20 unused enrollment tokens; let some expire first",
            )),
        }
    }

    async fn list_machines(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListMachinesRequest>,
    ) -> ServiceResult<ListMachinesResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        let machines = self
            .state
            .machines()
            .list(membership.organisation_id)
            .await
            .map_err(internal)?;
        Response::ok(ListMachinesResponse {
            machines: machines.iter().map(machine).collect(),
            ..Default::default()
        })
    }

    async fn revoke_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeMachineRequest>,
    ) -> ServiceResult<RevokeMachineResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        let Ok(machine_id) = Uuid::parse_str(request.machine_id) else {
            return Err(ConnectError::not_found("no such machine"));
        };
        let meta = RequestMeta {
            request_id: Uuid::now_v7(),
            address: String::new(),
        };
        match self
            .state
            .machines()
            .revoke(caller.account_id, &membership, machine_id, &meta)
            .await
            .map_err(internal)?
        {
            RevokeOutcome::Revoked => Response::ok(RevokeMachineResponse::default()),
            RevokeOutcome::NotFound => Err(ConnectError::not_found("no such machine")),
            RevokeOutcome::NotAllowed => Err(ConnectError::permission_denied(
                "only owners and admins revoke machines",
            )),
        }
    }
}
