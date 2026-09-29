//! `grund.relay.v1.RelayEnrollmentService`: where a `grund relay` on a host
//! of its own enrolls its key with a one-time token (grund-docs
//! design/traffic.md §5.7). Not behind the dashboard's session: the token in
//! the request is the credential, as for machine enrollment.

use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_proto::grund::relay::v1::{
    EnrollRelayRequest, EnrollRelayResponse, ErrorReason, RelayEnrollmentService,
};

use crate::{
    api::ClientAddress,
    services::relays::{EnrollOutcome, EnrollRequest, RelaysState},
    state::State,
};

/// The service implementation.
pub struct RelayEnrollmentApi {
    state: State,
}

impl RelayEnrollmentApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

fn refusal(error: ConnectError, reason: &str) -> ConnectError {
    error.with_detail(ErrorDetail::from_message(
        "grund.relay.v1.ErrorReason",
        &ErrorReason {
            reason: reason.to_string(),
            ..Default::default()
        },
    ))
}

#[allow(refining_impl_trait)]
impl RelayEnrollmentService for RelayEnrollmentApi {
    async fn enroll_relay(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, EnrollRelayRequest>,
    ) -> ServiceResult<EnrollRelayResponse> {
        let address = ctx
            .extensions()
            .get::<ClientAddress>()
            .map(|a| a.0.clone())
            .unwrap_or_default();
        let outcome = self
            .state
            .relays()
            .enroll(EnrollRequest {
                token: request.token.to_string(),
                public_key: request.relay_public_key.to_vec(),
                signed_at_unix: request.signed_at_unix,
                signature: request.signature.to_vec(),
                address,
            })
            .await
            .map_err(|error| {
                tracing::error!(error = format!("{error:#}"), "relay enrollment failed");
                ConnectError::unavailable("grund could not enroll the relay; try again")
            })?;
        match outcome {
            EnrollOutcome::Enrolled(relay) => Response::ok(EnrollRelayResponse {
                relay_id: relay.relay_id.to_string(),
                host: relay.host,
                ..Default::default()
            }),
            EnrollOutcome::TokenInvalid => Err(refusal(
                ConnectError::permission_denied(
                    "this relay token is unknown, used, expired, or for a host not in \
                     GRUND_RELAYS; mint a new one with `grund relays token <host>`",
                ),
                "token_invalid",
            )),
            EnrollOutcome::ProofInvalid => Err(refusal(
                ConnectError::invalid_argument(
                    "the relay's key or signature is not valid, or its clock is more than 5 \
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
