//! `grund.agent.v1.MachineEnrollmentService`: where a machine registers into
//! a pool with a one-time token (grund-docs design/machines.md §6.1). Not
//! behind the dashboard's session: the token in the request is the
//! credential, and the caller is a machine, not a browser.

use buffa::MessageField;
use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_domain::machine::{MachineFacts, Pool};
use grund_proto::grund::agent::v1::{
    self as agent, EnrollMachineRequest, EnrollMachineResponse, ErrorReason,
    MachineEnrollmentService,
};

use crate::{
    api::ClientAddress,
    services::machines::{
        EnrollOutcome, EnrollRequest, HEARTBEAT_INTERVAL_SECONDS, MachinesState, public_key_message,
    },
    state::State,
};

/// The service implementation.
pub struct EnrollmentApi {
    state: State,
}

impl EnrollmentApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

fn refusal(error: ConnectError, reason: &str) -> ConnectError {
    error.with_detail(ErrorDetail::from_message(
        "grund.agent.v1.ErrorReason",
        &ErrorReason {
            reason: reason.to_string(),
            ..Default::default()
        },
    ))
}

fn facts(facts: &agent::MachineFactsView<'_>) -> MachineFacts {
    let text = |value: &str| value.chars().take(256).collect::<String>();
    MachineFacts {
        hostname: text(facts.hostname),
        arch: text(facts.arch),
        cpu_model: text(facts.cpu_model),
        cpus: facts.cpus,
        memory_mib: facts.memory_mib,
        disk_gib: facts.disk_gib,
        os: text(facts.os),
        kernel: text(facts.kernel),
        agent_version: text(facts.agent_version),
        fleet_machine_id: text(facts.fleet_machine_id),
    }
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
        let outcome = self
            .state
            .machines()
            .enroll(EnrollRequest {
                token: request.token.to_string(),
                machine_public_key: request.machine_public_key.to_vec(),
                signed_at_unix: request.signed_at_unix,
                signature: request.signature.to_vec(),
                facts: request.facts.as_option().map(facts).unwrap_or_default(),
                requested_name: request.requested_name.to_string(),
                address,
            })
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "machine enrollment failed");
                ConnectError::unavailable("grund could not register the machine; try again")
            })?;
        let enrollment = match outcome {
            EnrollOutcome::Enrolled(enrollment) => enrollment,
            EnrollOutcome::TokenInvalid => {
                return Err(refusal(
                    ConnectError::permission_denied(
                        "this setup code is unknown, used or expired; make a new one",
                    ),
                    "token_invalid",
                ));
            }
            EnrollOutcome::ProofInvalid => {
                return Err(refusal(
                    ConnectError::invalid_argument(
                        "the machine's key or signature is not valid, or its clock is more than \
                         5 minutes off",
                    ),
                    "proof_invalid",
                ));
            }
            EnrollOutcome::MachineLimit => {
                return Err(refusal(
                    ConnectError::failed_precondition(
                        "this organisation has all the machines it may have",
                    ),
                    "machine_limit",
                ));
            }
            EnrollOutcome::NameTaken => {
                return Err(refusal(
                    ConnectError::failed_precondition("another machine in this pool has that name"),
                    "name_taken",
                ));
            }
            EnrollOutcome::NameInvalid(message) => {
                return Err(refusal(
                    ConnectError::invalid_argument(message),
                    "name_invalid",
                ));
            }
            EnrollOutcome::KeyReused => {
                return Err(refusal(
                    ConnectError::failed_precondition(
                        "that key is in use or was used before; generate a new one",
                    ),
                    "key_reused",
                ));
            }
            EnrollOutcome::RateLimited => {
                return Err(refusal(
                    ConnectError::resource_exhausted("too many attempts; wait a minute"),
                    "rate_limited",
                ));
            }
        };
        let (pool, organisation_id) = match enrollment.pool {
            Pool::Management => (agent::Pool::POOL_MANAGEMENT, String::new()),
            Pool::Organisation { organisation_id } => {
                (agent::Pool::POOL_ORGANISATION, organisation_id.to_string())
            }
        };
        Response::ok(EnrollMachineResponse {
            machine_id: enrollment.machine_id.to_string(),
            machine_name: enrollment.name,
            pool: pool.into(),
            organisation_id,
            instance_key: MessageField::from(public_key_message(&enrollment.instance_key)),
            trust_key: MessageField::from(public_key_message(&enrollment.trust_key)),
            heartbeat_interval_seconds: HEARTBEAT_INTERVAL_SECONDS,
            data_channel_urls: Vec::new(),
            ..Default::default()
        })
    }
}
