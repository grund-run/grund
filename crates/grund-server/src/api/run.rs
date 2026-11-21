//! Session-owner-only run access, separate from ordinary application telemetry grants.

use buffa::MessageField;
use buffa_types::google::protobuf::Timestamp;
use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_domain::run::Status;
use grund_proto::grund::run::v1::*;
use uuid::Uuid;

use crate::{
    api::caller,
    services::runs::{Error, RunsState},
    state::State,
};

pub struct RunApi {
    state: State,
}
impl RunApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
    async fn owner(&self, ctx: &RequestContext, slug: &str) -> Result<(Uuid, Uuid), ConnectError> {
        let actor = caller(ctx)?.account_id;
        let org = self.state.runs().owner(slug, actor).await.map_err(failed)?;
        Ok((actor, org))
    }
}

fn failed(error: Error) -> ConnectError {
    let reason = error.reason();
    let error = match error {
        Error::NotFound => ConnectError::not_found("no such run, stack or service"),
        Error::Owner => ConnectError::permission_denied("only organisation owners may access runs"),
        Error::Invalid => ConnectError::invalid_argument("invalid run input"),
        Error::Idempotency => {
            ConnectError::already_exists("idempotency key was used with different input")
        }
        Error::Precondition(reason) => ConnectError::failed_precondition(reason),
        Error::Conflict => ConnectError::aborted("run changed concurrently; retry the request"),
        Error::Internal(_) => {
            tracing::error!(reason, "run API call failed");
            ConnectError::internal("grund could not finish that")
        }
    };
    error.with_detail(ErrorDetail::from_message(
        "grund.run.v1.ErrorReason",
        &ErrorReason {
            reason: reason.into(),
            ..Default::default()
        },
    ))
}
fn id(value: &str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| failed(Error::Invalid))
}
fn timestamp<P: buffa::ProtoBox<Timestamp>>(
    value: Option<chrono::DateTime<chrono::Utc>>,
) -> MessageField<Timestamp, P> {
    value
        .map(|at| Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into())
        .unwrap_or_default()
}

fn message(row: grund_store::runs::Row, org: &str) -> Result<Run, ConnectError> {
    let state = row.state.0;
    let request = state
        .request
        .ok_or_else(|| failed(Error::Precondition("run_inputs_unavailable")))?;
    Ok(Run {
        id: row.run_id.to_string(),
        organisation: org.into(),
        stack: request.stack_name,
        service: request.service,
        stack_revision: request.stack_revision,
        release: request.release.number,
        image_digest: request.release.image_digest,
        machine_id: request.machine_id.to_string(),
        requester_id: request.requester_id.to_string(),
        state: match state.status {
            Status::NonExistent => RunState::RUN_STATE_UNSPECIFIED,
            Status::Pending => RunState::RUN_STATE_PENDING,
            Status::Running => RunState::RUN_STATE_RUNNING,
            Status::Cancelling => RunState::RUN_STATE_CANCELLING,
            Status::Succeeded => RunState::RUN_STATE_SUCCEEDED,
            Status::Failed => RunState::RUN_STATE_FAILED,
            Status::Cancelled => RunState::RUN_STATE_CANCELLED,
            Status::TimedOut => RunState::RUN_STATE_TIMED_OUT,
            Status::NotStarted => RunState::RUN_STATE_NOT_STARTED,
            Status::Unknown => RunState::RUN_STATE_UNKNOWN,
        }
        .into(),
        exit_code: state.exit_code,
        signal: state.signal,
        reason: state.reason,
        requested_at: timestamp(Some(request.requested_at)),
        started_at: timestamp(state.started_at),
        cancel_requested_at: timestamp(state.cancel_requested_at),
        finished_at: timestamp(state.finished_at),
        deadline: timestamp(Some(request.deadline)),
        stop_confirmed: state.stop_confirmed,
        ..Default::default()
    })
}

#[allow(refining_impl_trait)]
impl RunService for RunApi {
    async fn create_run(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateRunRequest>,
    ) -> ServiceResult<CreateRunResponse> {
        let (actor, org) = self.owner(&ctx, request.organisation).await?;
        let input = request.to_owned_message();
        let run = self
            .state
            .runs()
            .create(actor, org, &input)
            .await
            .map_err(failed)?
            .map(|row| message(row, &input.organisation))
            .transpose()?
            .map(MessageField::from)
            .unwrap_or_default();
        Response::ok(CreateRunResponse {
            run,
            ..Default::default()
        })
    }
    async fn get_run(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetRunRequest>,
    ) -> ServiceResult<GetRunResponse> {
        let (_, org) = self.owner(&ctx, request.organisation).await?;
        let id = id(request.id)?;
        let row = self.state.runs().get(org, id).await.map_err(failed)?;
        let args = grund_store::runs::args(&self.state.pool, org, id)
            .await
            .map_err(|e| failed(Error::from(e)))?;
        let mut run = message(row, request.organisation)?;
        run.args_expired = args.is_none();
        run.args = args.unwrap_or_default();
        Response::ok(GetRunResponse {
            run: run.into(),
            ..Default::default()
        })
    }
    async fn list_runs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListRunsRequest>,
    ) -> ServiceResult<ListRunsResponse> {
        let (_, org) = self.owner(&ctx, request.organisation).await?;
        let input = request.to_owned_message();
        let (rows, next_page_token) = self.state.runs().list(org, &input).await.map_err(failed)?;
        Response::ok(ListRunsResponse {
            runs: rows
                .into_iter()
                .map(|r| message(r, &input.organisation))
                .collect::<Result<Vec<_>, _>>()?,
            next_page_token,
            ..Default::default()
        })
    }
    async fn cancel_run(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CancelRunRequest>,
    ) -> ServiceResult<CancelRunResponse> {
        let (actor, org) = self.owner(&ctx, request.organisation).await?;
        let row = self
            .state
            .runs()
            .cancel(
                actor,
                org,
                id(request.id)?,
                request.idempotency_key,
                request.dry_run,
            )
            .await
            .map_err(failed)?;
        Response::ok(CancelRunResponse {
            run: message(row, request.organisation)?.into(),
            ..Default::default()
        })
    }
    async fn list_run_logs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListRunLogsRequest>,
    ) -> ServiceResult<ListRunLogsResponse> {
        use crate::services::app_telemetry::AppTelemetryState;
        let (_, org) = self.owner(&ctx, request.organisation).await?;
        let id = id(request.id)?;
        self.state.runs().get(org, id).await.map_err(failed)?;
        let response = self
            .state
            .app_telemetry()
            .run_logs(org, id, request.page_size, request.page_token)
            .await
            .map_err(|error| {
                if error
                    .downcast_ref::<crate::services::app_telemetry::Invalid>()
                    .is_some()
                {
                    failed(Error::Invalid)
                } else {
                    failed(Error::Internal(error))
                }
            })?;
        Response::ok(response)
    }
}
