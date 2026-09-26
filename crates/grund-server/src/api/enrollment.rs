//! `grund.agent.v1.MachineEnrollmentService`: a machine joining grund. No
//! session: the one-time token in the request is the credential, and the
//! machine's signature proves it holds the key it enrolls
//! (grund/fleet docs/design/enrollment-contract.md).

use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_domain::machine::MachineFacts;
use grund_proto::grund::agent::v1::{
    EnrollMachineRequest, EnrollMachineResponse, ErrorReason, MachineEnrollmentService,
};
use uuid::Uuid;

use crate::{
    services::{
        accounts::RequestMeta,
        machines::{EnrollOutcome, Enrollment, HEARTBEAT_INTERVAL_SECONDS, MachinesState},
    },
    state::State,
};

/// The client address [`crate::api::stamp_client`] found for the call.
#[derive(Debug, Clone)]
pub struct ClientAddress(pub String);

/// The service implementation.
pub struct EnrollmentApi {
    state: State,
}

impl EnrollmentApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

/// `error` with a `grund.agent.v1.ErrorReason` detail naming `reason`.
pub fn with_reason(error: ConnectError, reason: &str) -> ConnectError {
    let mut detail = ErrorDetail::from_message(
        "grund.agent.v1.ErrorReason",
        &ErrorReason {
            reason: reason.to_string(),
            ..Default::default()
        },
    );
    detail.debug = Some(serde_json::json!({ "reason": reason }));
    error.with_detail(detail)
}

#[allow(refining_impl_trait)]
impl MachineEnrollmentService for EnrollmentApi {
    async fn enroll_machine(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, EnrollMachineRequest>,
    ) -> ServiceResult<EnrollMachineResponse> {
        let address = ctx
            .extensions()
            .get::<ClientAddress>()
            .map(|a| a.0.clone())
            .unwrap_or_default();
        let facts = &request.facts;
        let enrollment = Enrollment {
            token: request.token.to_string(),
            public_key: request.machine_public_key.to_vec(),
            signed_at_unix: request.signed_at_unix,
            signature: request.signature.to_vec(),
            facts: MachineFacts {
                hostname: facts.hostname.to_string(),
                arch: facts.arch.to_string(),
                cpu_model: facts.cpu_model.to_string(),
                cpus: facts.cpus,
                memory_mib: facts.memory_mib,
                disk_gib: facts.disk_gib,
                os: facts.os.to_string(),
                kernel: facts.kernel.to_string(),
                agent_version: facts.agent_version.to_string(),
                fleet_machine_id: facts.fleet_machine_id.to_string(),
            },
            requested_name: request.requested_name.to_string(),
        };
        let meta = RequestMeta {
            request_id: Uuid::now_v7(),
            address: address.clone(),
        };
        let outcome = self
            .state
            .machines()
            .enroll(enrollment, &address, &meta)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "enrollment failed");
                ConnectError::unavailable("grund is temporarily unavailable; retry shortly")
            })?;
        match outcome {
            EnrollOutcome::Enrolled(enrolled) => Response::ok(EnrollMachineResponse {
                machine_id: enrolled.machine_id.to_string(),
                machine_name: enrolled.name,
                organisation_id: enrolled.organisation_id.to_string(),
                control_urls: vec![self.state.config.public_origin().serialized],
                heartbeat_interval_seconds: HEARTBEAT_INTERVAL_SECONDS,
                ..Default::default()
            }),
            EnrollOutcome::TokenInvalid => Err(with_reason(
                ConnectError::permission_denied("this enrollment token does not work"),
                "token_invalid",
            )),
            EnrollOutcome::ProofInvalid => Err(with_reason(
                ConnectError::invalid_argument(
                    "the machine's key, signature or clock does not check out",
                ),
                "proof_invalid",
            )),
            EnrollOutcome::RateLimited => Err(with_reason(
                ConnectError::resource_exhausted("too many enrollment attempts; wait a minute"),
                "rate_limited",
            )),
            EnrollOutcome::NameTaken => Err(with_reason(
                ConnectError::failed_precondition(
                    "a machine of this organisation already has the name this token binds",
                ),
                "machine_name_taken",
            )),
        }
    }
}
