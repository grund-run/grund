//! `grund.certificates.v1.CertificateService`: certificates for TLS
//! terminators on other hosts (grund-docs design/traffic.md §5.7). Behind
//! [`super::authenticate_terminator`]: the caller is a relay or a machine,
//! proven by its own key before the body is read, and the handlers act on
//! that caller's certificate only.

use std::{collections::HashSet, time::Duration};

use buffa::{EnumValue, MessageField};
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use grund_proto::grund::certificates::v1::{
    self as proto, AnswerChallengeRequest, AnswerChallengeResponse, CertificateService,
    CertificateState, ChallengeType, GetCertificateRequest, GetCertificateResponse,
    RequestCertificateRequest, RequestCertificateResponse, WatchChallengesRequest,
    WatchChallengesResponse,
};
use grund_store::certificates::RemoteStatus;

use crate::{
    services::terminators::{Pending, RequestOutcome, Terminator, TerminatorsState},
    state::State,
};

/// How long one watch stays open before it ends by itself.
pub const WATCH_SPAN: Duration = Duration::from_secs(25);

/// How often an open watch looks for what is new.
pub const WATCH_POLL: Duration = Duration::from_millis(500);

/// The most names one request may carry.
pub const MAX_NAMES: usize = 100;

/// The service implementation.
pub struct CertificatesApi {
    state: State,
}

impl CertificatesApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

fn terminator(ctx: &RequestContext) -> Result<Terminator, ConnectError> {
    ctx.extensions()
        .get::<Terminator>()
        .cloned()
        .ok_or_else(|| ConnectError::unauthenticated("sign the request with the relay's key"))
}

fn not_found() -> ConnectError {
    ConnectError::not_found("no certificate for this caller and these names")
}

fn unavailable(error: anyhow::Error) -> ConnectError {
    tracing::error!(error = format!("{error:#}"), "certificate service failed");
    ConnectError::unavailable("grund could not answer; try again")
}

fn timestamp<P: buffa::ProtoBox<Timestamp>>(
    at: Option<DateTime<Utc>>,
) -> MessageField<Timestamp, P> {
    at.map(|at| Timestamp::from_unix(at.timestamp(), 0).into())
        .unwrap_or_default()
}

fn certificate(status: RemoteStatus) -> proto::Certificate {
    let state = if status.wants_csr {
        CertificateState::CERTIFICATE_STATE_CSR_WANTED
    } else if status.issued {
        CertificateState::CERTIFICATE_STATE_ISSUED
    } else {
        CertificateState::CERTIFICATE_STATE_ORDERING
    };
    proto::Certificate {
        names: status.names,
        state: EnumValue::from(state),
        chain_pem: status.chain_pem.unwrap_or_default(),
        version: status.version,
        not_before: timestamp(status.not_before),
        not_after: timestamp(status.not_after),
        renew_at: timestamp(status.renew_at.filter(|_| status.version > 0)),
        last_error: status.last_error.unwrap_or_default(),
        ..Default::default()
    }
}

fn event(
    event: impl Into<proto::__buffa::oneof::watch_challenges_response::Event>,
) -> WatchChallengesResponse {
    WatchChallengesResponse {
        event: Some(event.into()),
        ..Default::default()
    }
}

struct Watch {
    state: State,
    caller: Terminator,
    sent: HashSet<String>,
    wanted_sent: HashSet<String>,
    versions: std::collections::HashMap<String, i64>,
    queue: std::collections::VecDeque<WatchChallengesResponse>,
    ends: tokio::time::Instant,
    first: bool,
}

impl Watch {
    fn news(&mut self, pending: Vec<Pending>) {
        for pending in pending {
            for challenge in pending.challenges {
                if challenge.kind != "tls-alpn-01" || !self.sent.insert(challenge.token.clone()) {
                    continue;
                }
                self.queue.push_back(event(proto::Challenge {
                    r#type: EnumValue::from(ChallengeType::CHALLENGE_TYPE_TLS_ALPN_01),
                    name: challenge.name,
                    token: challenge.token,
                    key_authorization: challenge.key_authorization,
                    ..Default::default()
                }));
            }
            if pending.wants_csr && self.wanted_sent.insert(pending.subject.clone()) {
                self.queue.push_back(event(proto::CsrWanted {
                    names: pending.names.clone(),
                    ..Default::default()
                }));
            }
            if !pending.wants_csr {
                self.wanted_sent.remove(&pending.subject);
            }
            match self.versions.get(&pending.subject) {
                Some(known) if pending.version > *known => {
                    self.queue.push_back(event(proto::Issued {
                        version: pending.version,
                        names: pending.names.clone(),
                        ..Default::default()
                    }));
                }
                _ => {}
            }
            self.versions.insert(pending.subject, pending.version);
        }
    }

    async fn next(mut self) -> Option<(Result<WatchChallengesResponse, ConnectError>, Self)> {
        loop {
            if let Some(next) = self.queue.pop_front() {
                return Some((Ok(next), self));
            }
            if tokio::time::Instant::now() >= self.ends {
                return None;
            }
            if !self.first {
                tokio::time::sleep(WATCH_POLL).await;
            }
            self.first = false;
            match self.state.terminators().pending(&self.caller).await {
                Ok(pending) if !pending.is_empty() => self.news(pending),
                Ok(_) => return None,
                Err(error) => {
                    tracing::warn!(
                        error = format!("{error:#}"),
                        "certificate watch: could not look; ending the watch"
                    );
                    return None;
                }
            }
        }
    }
}

#[allow(refining_impl_trait)]
impl CertificateService for CertificatesApi {
    async fn request_certificate(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RequestCertificateRequest>,
    ) -> ServiceResult<RequestCertificateResponse> {
        let caller = terminator(&ctx)?;
        if request.names.len() > MAX_NAMES {
            return Err(ConnectError::invalid_argument(format!(
                "at most {MAX_NAMES} names"
            )));
        }
        match request.challenge.as_known() {
            Some(ChallengeType::CHALLENGE_TYPE_UNSPECIFIED)
            | Some(ChallengeType::CHALLENGE_TYPE_TLS_ALPN_01) => {}
            _ => {
                return Err(ConnectError::invalid_argument(
                    "only TLS-ALPN-01 is offered",
                ));
            }
        }
        let names: Vec<String> = request.names.iter().map(|n| n.to_string()).collect();
        let outcome = self
            .state
            .terminators()
            .request(&caller, &names, request.csr)
            .await
            .map_err(unavailable)?;
        match outcome {
            RequestOutcome::Recorded(status) => Response::ok(RequestCertificateResponse {
                certificate: MessageField::some(certificate(*status)),
                ..Default::default()
            }),
            RequestOutcome::NotFound => Err(not_found()),
            RequestOutcome::Invalid(message) => Err(ConnectError::invalid_argument(message)),
            RequestOutcome::AcmeOff => Err(ConnectError::failed_precondition(
                "this instance orders no certificates (GRUND_ACME_DIRECTORY is unset)",
            )),
        }
    }

    async fn watch_challenges(
        &self,
        ctx: RequestContext,
        _: ServiceRequest<'_, WatchChallengesRequest>,
    ) -> ServiceResult<ServiceStream<WatchChallengesResponse>> {
        let caller = terminator(&ctx)?;
        if self
            .state
            .terminators()
            .pending(&caller)
            .await
            .map_err(unavailable)?
            .is_empty()
        {
            return Err(not_found());
        }
        let watch = Watch {
            state: self.state.clone(),
            caller,
            sent: HashSet::new(),
            wanted_sent: HashSet::new(),
            versions: Default::default(),
            queue: Default::default(),
            ends: tokio::time::Instant::now() + WATCH_SPAN,
            first: true,
        };
        let stream: ServiceStream<WatchChallengesResponse> =
            Box::pin(futures_util::stream::unfold(watch, Watch::next));
        Response::ok(stream)
    }

    async fn answer_challenge(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AnswerChallengeRequest>,
    ) -> ServiceResult<AnswerChallengeResponse> {
        let caller = terminator(&ctx)?;
        let token = request.token;
        if token.is_empty() || token.len() > 128 {
            return Err(not_found());
        }
        if self
            .state
            .terminators()
            .answering(&caller, token)
            .await
            .map_err(unavailable)?
        {
            Response::ok(AnswerChallengeResponse::default())
        } else {
            Err(ConnectError::not_found("no such pending challenge"))
        }
    }

    async fn get_certificate(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetCertificateRequest>,
    ) -> ServiceResult<GetCertificateResponse> {
        let caller = terminator(&ctx)?;
        if request.names.len() > MAX_NAMES {
            return Err(not_found());
        }
        let names: Vec<String> = request.names.iter().map(|n| n.to_string()).collect();
        match self
            .state
            .terminators()
            .status(&caller, &names)
            .await
            .map_err(unavailable)?
        {
            Some(status) => Response::ok(GetCertificateResponse {
                certificate: MessageField::some(certificate(status)),
                ..Default::default()
            }),
            None => Err(not_found()),
        }
    }
}
