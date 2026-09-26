//! `grund.agent.v1.AgentService`: the control link over HTTPS (grund-docs
//! design/machines.md §7b). Every call is from a machine whose key signed
//! the request ([`crate::api::authenticate_machine`]); a handler acts only on
//! that machine.

use buffa::MessageField;
use buffa_types::google::protobuf::Timestamp;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_proto::grund::agent::v1::{
    AgentService, GetDesiredStateRequest, GetDesiredStateResponse, GetMachineJoinTokenRequest,
    GetMachineJoinTokenResponse, HeartbeatRequest, HeartbeatResponse, ReportStatusRequest,
    ReportStatusResponse, SignedDesiredState, VmObservedState,
};
use uuid::Uuid;

use crate::{
    services::agents::{AgentsState, HEARTBEAT_INTERVAL_SECONDS, MachineCaller},
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

#[allow(refining_impl_trait)]
impl AgentService for AgentApi {
    async fn heartbeat(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, HeartbeatRequest>,
    ) -> ServiceResult<HeartbeatResponse> {
        let caller = machine(&ctx)?;
        let capabilities = request
            .capabilities
            .as_option()
            .map_or(serde_json::json!({}), |c| {
                serde_json::json!({
                    "kvm": c.kvm,
                    "root": c.root,
                    "egress": c.egress,
                    "free_vcpus": c.free_vcpus,
                    "free_memory_mib": c.free_memory_mib,
                })
            });
        let generation = self
            .state
            .agents()
            .heartbeat(&caller, request.agent_version, &capabilities)
            .await
            .map_err(internal)?;
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
                .map(|d| {
                    MessageField::from(SignedDesiredState {
                        key_id: d.key_id.to_string(),
                        payload: d.payload,
                        signature: d.signature,
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
        self.state
            .agents()
            .report(&caller, request.applied_generation, &observed, &refusals)
            .await
            .map_err(internal)?;
        Response::ok(ReportStatusResponse::default())
    }
}
