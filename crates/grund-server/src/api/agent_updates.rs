use buffa::MessageField;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_domain::agent_updates::Failure;
use grund_proto::grund::agent::v1::{
    BeginUpdateRequest, BeginUpdateResponse, MachineUpdateService, PollUpdateRequest,
    PollUpdateResponse, ReportUpdateRequest, ReportUpdateResponse, SignedMachineUpdate,
};
use uuid::Uuid;

use crate::{
    services::{
        AgentUpdatesState,
        agent_updates::{AgentUpdateService, SignedUpdate},
        agents::MachineCaller,
    },
    state::State,
};

pub struct MachineUpdateApi {
    updates: AgentUpdateService,
}

impl MachineUpdateApi {
    pub fn new(state: State) -> Self {
        Self {
            updates: state.agent_updates(),
        }
    }
}

fn caller(ctx: &RequestContext) -> Result<MachineCaller, ConnectError> {
    ctx.extensions()
        .get::<MachineCaller>()
        .cloned()
        .ok_or_else(|| ConnectError::unauthenticated("sign the request with the machine key"))
}

fn id(value: &str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or_else(|| ConnectError::invalid_argument("a nonzero UUID is required"))
}

fn signed(document: SignedUpdate) -> SignedMachineUpdate {
    SignedMachineUpdate {
        payload: document.payload,
        signature: document.signature,
        key_id: document.key_id.to_string(),
        ..Default::default()
    }
}

fn error(error: anyhow::Error) -> ConnectError {
    if let Some(grund_store::work::WorkError::AgentUpdates(reason)) =
        error.downcast_ref::<grund_store::work::WorkError>()
    {
        return ConnectError::failed_precondition(reason.to_string());
    }
    if let Some(reason) = error.downcast_ref::<grund_domain::agent_updates::Error>() {
        return ConnectError::failed_precondition(reason.to_string());
    }
    tracing::error!(error = %error, "machine update API failed");
    ConnectError::unavailable("machine updates are temporarily unavailable")
}

#[allow(refining_impl_trait)]
impl MachineUpdateService for MachineUpdateApi {
    async fn poll_update(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PollUpdateRequest>,
    ) -> ServiceResult<PollUpdateResponse> {
        let caller = caller(&ctx)?;
        let boot_id = id(request.boot_id)?;
        let offer = self
            .updates
            .poll(
                &caller,
                request.following,
                request.architecture,
                request.revision,
                boot_id,
            )
            .await
            .map_err(error)?;
        Response::ok(PollUpdateResponse {
            offer: offer
                .map(signed)
                .map(MessageField::some)
                .unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn begin_update(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, BeginUpdateRequest>,
    ) -> ServiceResult<BeginUpdateResponse> {
        let caller = caller(&ctx)?;
        let authorized = self
            .updates
            .begin(
                &caller,
                id(request.attempt_id)?,
                request.generation,
                id(request.boot_id)?,
            )
            .await
            .map_err(error)?;
        Response::ok(BeginUpdateResponse {
            authorized,
            ..Default::default()
        })
    }

    async fn report_update(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReportUpdateRequest>,
    ) -> ServiceResult<ReportUpdateResponse> {
        let caller = caller(&ctx)?;
        if !matches!(
            request.phase,
            "candidate_health" | "committed" | "rolled_back" | "failed"
        ) {
            return Err(ConnectError::invalid_argument("unknown update phase"));
        }
        let failure = if request.phase == "failed" {
            Some(
                Failure::parse(request.failure_code)
                    .ok_or_else(|| ConnectError::invalid_argument("unknown update failure code"))?,
            )
        } else {
            None
        };
        let (accepted, permit) = self
            .updates
            .report(
                &caller,
                id(request.attempt_id)?,
                request.generation,
                request.phase,
                id(request.boot_id)?,
                request.revision,
                failure,
            )
            .await
            .map_err(error)?;
        Response::ok(ReportUpdateResponse {
            accepted,
            finalize: permit
                .map(signed)
                .map(MessageField::some)
                .unwrap_or_default(),
            ..Default::default()
        })
    }
}
