//! `grund.edge.v1` (grund-docs design/traffic.md §6): where a `grund edge`
//! enrolls its key with a one-time token, watches its route table, and
//! reports the entry bytes it carried. Enrollment is behind no credential
//! but its token; the rest behind [`super::authenticate_edge`], so the
//! handlers act for the edge its key proved.

use buffa::MessageField;
use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_proto::grund::edge::v1::{
    EdgeEnrollmentService, EdgeService, EnrollEdgeRequest, EnrollEdgeResponse, ErrorReason,
    ReportUsageRequest, ReportUsageResponse, WatchRoutesRequest, WatchRoutesResponse,
};
use uuid::Uuid;

use crate::{
    api::ClientAddress,
    services::{
        entry::EntryState,
        relays::{EnrollOutcome, EnrollRequest, RelayCaller, RelaysState, Role},
    },
    state::State,
};

/// The most usage rows one report may carry.
pub const MAX_USAGE_ROWS: usize = 1000;

/// The edge a request is from, stamped by [`super::authenticate_edge`].
#[derive(Debug, Clone)]
pub struct EdgeCaller(pub RelayCaller);

/// The enrollment service.
pub struct EdgeEnrollmentApi {
    state: State,
}

impl EdgeEnrollmentApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

/// The edge service.
pub struct EdgeApi {
    state: State,
}

impl EdgeApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

fn refusal(error: ConnectError, reason: &str) -> ConnectError {
    error.with_detail(ErrorDetail::from_message(
        "grund.edge.v1.ErrorReason",
        &ErrorReason {
            reason: reason.to_string(),
            ..Default::default()
        },
    ))
}

fn unavailable(error: anyhow::Error) -> ConnectError {
    tracing::error!(error = format!("{error:#}"), "edge service failed");
    ConnectError::unavailable("grund could not answer; try again")
}

fn edge(ctx: &RequestContext) -> Result<RelayCaller, ConnectError> {
    ctx.extensions()
        .get::<EdgeCaller>()
        .map(|caller| caller.0.clone())
        .ok_or_else(|| ConnectError::unauthenticated("sign the request with the edge's key"))
}

#[allow(refining_impl_trait)]
impl EdgeEnrollmentService for EdgeEnrollmentApi {
    async fn enroll_edge(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, EnrollEdgeRequest>,
    ) -> ServiceResult<EnrollEdgeResponse> {
        let address = ctx
            .extensions()
            .get::<ClientAddress>()
            .map(|a| a.0.clone())
            .unwrap_or_default();
        let outcome = self
            .state
            .relays()
            .enroll_as(
                Role::Edge,
                EnrollRequest {
                    token: request.token.to_string(),
                    public_key: request.edge_public_key.to_vec(),
                    signed_at_unix: request.signed_at_unix,
                    signature: request.signature.to_vec(),
                    address,
                },
            )
            .await
            .map_err(unavailable)?;
        match outcome {
            EnrollOutcome::Enrolled(edge) => Response::ok(EnrollEdgeResponse {
                edge_id: edge.relay_id.to_string(),
                host: edge.host,
                relay_urls: self.state.entry().relay_urls(),
                ..Default::default()
            }),
            EnrollOutcome::TokenInvalid => Err(refusal(
                ConnectError::permission_denied(
                    "this edge token is unknown, used, expired, or for a host not in \
                     GRUND_EDGES; mint a new one with `grund edges token <host>`",
                ),
                "token_invalid",
            )),
            EnrollOutcome::ProofInvalid => Err(refusal(
                ConnectError::invalid_argument(
                    "the edge's key or signature is not valid, or its clock is more than 5 \
                     minutes off",
                ),
                "proof_invalid",
            )),
            EnrollOutcome::KeyReused => Err(refusal(
                ConnectError::failed_precondition(
                    "that key is enrolled already or was before; generate a new one",
                ),
                "key_reused",
            )),
            EnrollOutcome::RateLimited => Err(refusal(
                ConnectError::resource_exhausted("too many attempts; wait a minute"),
                "rate_limited",
            )),
        }
    }
}

#[allow(refining_impl_trait)]
impl EdgeService for EdgeApi {
    async fn watch_routes(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, WatchRoutesRequest>,
    ) -> ServiceResult<WatchRoutesResponse> {
        edge(&ctx)?;
        let since = request.since_version.to_string();
        let table = self
            .state
            .entry()
            .watch_routes(&since)
            .await
            .map_err(unavailable)?;
        Response::ok(WatchRoutesResponse {
            table: table.map(MessageField::some).unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn report_usage(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReportUsageRequest>,
    ) -> ServiceResult<ReportUsageResponse> {
        let caller = edge(&ctx)?;
        let report_id = Uuid::parse_str(request.report_id)
            .map_err(|_| ConnectError::invalid_argument("report_id is a UUID"))?;
        if request.usage.len() > MAX_USAGE_ROWS {
            return Err(ConnectError::invalid_argument(format!(
                "at most {MAX_USAGE_ROWS} usage rows per report"
            )));
        }
        let mut rows = Vec::with_capacity(request.usage.len());
        for usage in request.usage.iter() {
            let path = match usage.path {
                "direct" | "relay" => usage.path.to_string(),
                _ => return Err(ConnectError::invalid_argument("path is direct or relay")),
            };
            if usage.name.is_empty() || usage.name.len() > 253 {
                return Err(ConnectError::invalid_argument(
                    "a usage row names an address",
                ));
            }
            let clamp = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
            rows.push(grund_store::entry::UsageRow {
                name: usage.name.to_ascii_lowercase(),
                path,
                bytes_in: clamp(usage.bytes_in),
                bytes_out: clamp(usage.bytes_out),
                connections: clamp(usage.connections),
            });
        }
        self.state
            .entry()
            .record_usage(caller.relay_id, report_id, rows)
            .await
            .map_err(unavailable)?;
        Response::ok(ReportUsageResponse::default())
    }
}
