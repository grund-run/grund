//! `grund.domain.v1.DomainService`: an organisation's custom domains
//! (grund-docs website/design/app-domains.md §3). Members get and list;
//! owners and admins add, verify, check, bind, unbind and remove. Deploy tokens
//! read only domains bound to their allowed apps; unbound domains stay hidden.
//! An organisation the caller is not a member of, an organisation a token
//! is not for, and a domain that is not the organisation's, are not_found
//! alike.

use buffa::MessageField;
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_proto::grund::domain::v1::{
    self as proto, AddDomainRequest, AddDomainResponse, BindDomainRequest, BindDomainResponse,
    CheckDomainRequest, CheckDomainResponse, ConfigureAppDomainRequest, ConfigureAppDomainResponse,
    DomainService, ErrorReason, GetDomainRequest, GetDomainResponse, ListDomainsRequest,
    ListDomainsResponse, RemoveDomainRequest, RemoveDomainResponse, SetAppSubdomainRequest,
    SetAppSubdomainResponse, UnbindDomainRequest, UnbindDomainResponse, VerifyDomainRequest,
    VerifyDomainResponse,
};
use grund_store::{domain_setup::StepState, organisations::Membership};

use crate::{
    api::principal,
    services::{
        OrganisationsState,
        domain_status::summarize,
        domains::{DomainView, DomainsError, DomainsState, Status},
    },
    state::State,
};

/// The service implementation.
pub struct DomainApi {
    state: State,
}

impl DomainApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn member(
        &self,
        ctx: &RequestContext,
        slug: &str,
    ) -> Result<(uuid::Uuid, Membership), ConnectError> {
        let caller = principal(ctx)?;
        let membership = self
            .state
            .organisations()
            .membership(slug, caller.account_id)
            .await
            .map_err(|e| failed(DomainsError::Internal(e)))?
            .filter(|m| caller.reaches(m.organisation_id))
            .ok_or_else(|| ConnectError::not_found("no such organisation"))?;
        Ok((caller.account_id, membership))
    }
}

fn timestamp<P: buffa::ProtoBox<Timestamp>>(
    at: Option<DateTime<Utc>>,
) -> MessageField<Timestamp, P> {
    at.map(|at| Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into())
        .unwrap_or_default()
}

fn failed(error: DomainsError) -> ConnectError {
    let reason = error.reason();
    let message = error.to_string();
    let base = match &error {
        DomainsError::NotFound | DomainsError::AppNotFound => ConnectError::not_found(message),
        DomainsError::NotAllowed => ConnectError::permission_denied(message),
        DomainsError::Invalid(_) | DomainsError::Reserved(_) | DomainsError::InvalidSubdomain => {
            ConnectError::invalid_argument(message)
        }
        DomainsError::Exists | DomainsError::Taken => ConnectError::already_exists(message),
        DomainsError::Limit | DomainsError::DailyLimit | DomainsError::AppLimit => {
            ConnectError::resource_exhausted(message)
        }
        DomainsError::CoolingDown(_)
        | DomainsError::NotVerified
        | DomainsError::VerificationFailed(_)
        | DomainsError::AppNotPublic
        | DomainsError::LastPublicDomain
        | DomainsError::NamespaceConflict(_)
        | DomainsError::AppDomainRequired => ConnectError::failed_precondition(message),
        DomainsError::Internal(cause) => {
            tracing::error!(error = %format!("{cause:#}"), "domain API call failed");
            ConnectError::internal("grund could not finish that")
        }
    };
    base.with_detail(ErrorDetail::from_message(
        "grund.domain.v1.ErrorReason",
        &ErrorReason {
            reason: reason.to_string(),
            ..Default::default()
        },
    ))
}

fn message(view: &DomainView, edge_target: Option<&str>) -> proto::Domain {
    let summary = summarize(view, edge_target);
    proto::Domain {
        name: view.name.clone(),
        status: match view.status {
            Status::Pending => proto::DomainStatus::DOMAIN_STATUS_PENDING,
            Status::Verified => proto::DomainStatus::DOMAIN_STATUS_VERIFIED,
            Status::Bound => proto::DomainStatus::DOMAIN_STATUS_BOUND,
            Status::Issued => proto::DomainStatus::DOMAIN_STATUS_CERTIFICATE_ISSUED,
            Status::Error => proto::DomainStatus::DOMAIN_STATUS_ERROR,
        }
        .into(),
        verification_record_name: view.txt_name.clone(),
        verification_record_value: view.txt_value.clone(),
        app: view.app_name.clone().unwrap_or_default(),
        added_at: timestamp(Some(view.added_at)),
        verified_at: timestamp(view.verified_at),
        bound_at: timestamp(view.bound_at),
        certificate_expires_at: timestamp(view.certificate_not_after),
        problem: view.problem.clone().unwrap_or_default(),
        setup_steps: view
            .steps
            .iter()
            .map(|step| proto::DomainSetupStep {
                name: step.name.clone(),
                state: match step.state {
                    StepState::Waiting => proto::StepState::STEP_STATE_WAITING,
                    StepState::InProgress => proto::StepState::STEP_STATE_IN_PROGRESS,
                    StepState::Done => proto::StepState::STEP_STATE_DONE,
                    StepState::Failed => proto::StepState::STEP_STATE_FAILED,
                }
                .into(),
                detail: step.detail.clone(),
                checked_at: timestamp(step.checked_at),
                next_retry_at: timestamp(step.next_retry_at),
                ..Default::default()
            })
            .collect(),
        certificate_attempts: view.certificate_attempts,
        certificate_next_attempt_at: timestamp(view.certificate_next_attempt_at),
        is_app_domain: view.is_app_domain,
        parent_domain: view.parent_domain.clone(),
        managed_app_name: view.managed_app_name.clone().unwrap_or_default(),
        setup_summary: summary.sentence.into_owned(),
        required_records: summary
            .records
            .into_iter()
            .map(|(kind, name, value)| proto::DomainRequiredRecord {
                r#type: kind.to_string(),
                name: name.into_owned(),
                value: value.to_string(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

#[allow(refining_impl_trait)]
impl DomainService for DomainApi {
    async fn list_domains(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListDomainsRequest>,
    ) -> ServiceResult<ListDomainsResponse> {
        let caller = principal(&ctx)?;
        let (_, membership) = self.member(&ctx, request.organisation).await?;
        let domains: Vec<_> = self
            .state
            .domains()
            .list(membership.organisation_id)
            .await
            .map_err(failed)?
            .into_iter()
            .filter(|domain| {
                caller.apps.is_none()
                    || domain
                        .app_name
                        .as_deref()
                        .is_some_and(|app| caller.reaches_app(app))
            })
            .collect();
        Response::ok(ListDomainsResponse {
            domains: domains
                .iter()
                .map(|domain| {
                    message(
                        domain,
                        self.state.config.entry.edges.first().map(String::as_str),
                    )
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn get_domain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetDomainRequest>,
    ) -> ServiceResult<GetDomainResponse> {
        let caller = principal(&ctx)?;
        let (_, membership) = self.member(&ctx, request.organisation).await?;
        let domain = self
            .state
            .domains()
            .get(membership.organisation_id, request.name)
            .await
            .map_err(failed)?;
        if caller.apps.is_some()
            && !domain
                .app_name
                .as_deref()
                .is_some_and(|app| caller.reaches_app(app))
        {
            return Err(ConnectError::not_found("no such domain"));
        }
        Response::ok(GetDomainResponse {
            domain: MessageField::some(message(
                &domain,
                self.state.config.entry.edges.first().map(String::as_str),
            )),
            ..Default::default()
        })
    }

    async fn add_domain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AddDomainRequest>,
    ) -> ServiceResult<AddDomainResponse> {
        let (actor, membership) = self.member(&ctx, request.organisation).await?;
        let domain = self
            .state
            .domains()
            .add(actor, &membership, request.name)
            .await
            .map_err(failed)?;
        Response::ok(AddDomainResponse {
            domain: MessageField::some(message(
                &domain,
                self.state.config.entry.edges.first().map(String::as_str),
            )),
            ..Default::default()
        })
    }

    async fn verify_domain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, VerifyDomainRequest>,
    ) -> ServiceResult<VerifyDomainResponse> {
        let (actor, membership) = self.member(&ctx, request.organisation).await?;
        let domain = self
            .state
            .domains()
            .verify(actor, &membership, request.name)
            .await
            .map_err(failed)?;
        Response::ok(VerifyDomainResponse {
            domain: MessageField::some(message(
                &domain,
                self.state.config.entry.edges.first().map(String::as_str),
            )),
            ..Default::default()
        })
    }

    async fn check_domain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CheckDomainRequest>,
    ) -> ServiceResult<CheckDomainResponse> {
        let caller = principal(&ctx)?;
        if caller.apps.is_some() {
            return Err(ConnectError::permission_denied(
                "a person's session or full token is required",
            ));
        }
        let (actor, membership) = self.member(&ctx, request.organisation).await?;
        let domain = self
            .state
            .domains()
            .check_now(actor, &membership, request.name)
            .await
            .map_err(failed)?;
        Response::ok(CheckDomainResponse {
            domain: MessageField::some(message(
                &domain,
                self.state.config.entry.edges.first().map(String::as_str),
            )),
            ..Default::default()
        })
    }

    async fn bind_domain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, BindDomainRequest>,
    ) -> ServiceResult<BindDomainResponse> {
        let (actor, membership) = self.member(&ctx, request.organisation).await?;
        let domain = self
            .state
            .domains()
            .bind(actor, &membership, request.name, request.app)
            .await
            .map_err(failed)?;
        Response::ok(BindDomainResponse {
            domain: MessageField::some(message(
                &domain,
                self.state.config.entry.edges.first().map(String::as_str),
            )),
            ..Default::default()
        })
    }

    async fn unbind_domain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UnbindDomainRequest>,
    ) -> ServiceResult<UnbindDomainResponse> {
        let (actor, membership) = self.member(&ctx, request.organisation).await?;
        let domain = self
            .state
            .domains()
            .unbind(actor, &membership, request.name)
            .await
            .map_err(failed)?;
        Response::ok(UnbindDomainResponse {
            domain: MessageField::some(message(
                &domain,
                self.state.config.entry.edges.first().map(String::as_str),
            )),
            ..Default::default()
        })
    }

    async fn remove_domain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RemoveDomainRequest>,
    ) -> ServiceResult<RemoveDomainResponse> {
        let (actor, membership) = self.member(&ctx, request.organisation).await?;
        self.state
            .domains()
            .remove(actor, &membership, request.name)
            .await
            .map_err(failed)?;
        Response::ok(RemoveDomainResponse::default())
    }

    async fn configure_app_domain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ConfigureAppDomainRequest>,
    ) -> ServiceResult<ConfigureAppDomainResponse> {
        if principal(&ctx)?.apps.is_some() {
            return Err(ConnectError::permission_denied(
                "a person's session or full token is required",
            ));
        }
        let (actor, membership) = self.member(&ctx, request.organisation).await?;
        let domain = self
            .state
            .domains()
            .configure_app_domain(actor, &membership, request.name)
            .await
            .map_err(failed)?;
        Response::ok(ConfigureAppDomainResponse {
            domain: MessageField::some(message(
                &domain,
                self.state.config.entry.edges.first().map(String::as_str),
            )),
            ..Default::default()
        })
    }

    async fn set_app_subdomain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetAppSubdomainRequest>,
    ) -> ServiceResult<SetAppSubdomainResponse> {
        if principal(&ctx)?.apps.is_some() {
            return Err(ConnectError::permission_denied(
                "a person's session or full token is required",
            ));
        }
        let (actor, membership) = self.member(&ctx, request.organisation).await?;
        let domain = self
            .state
            .domains()
            .set_app_subdomain(actor, &membership, request.app, request.subdomain)
            .await
            .map_err(failed)?;
        Response::ok(SetAppSubdomainResponse {
            domain: MessageField::some(message(
                &domain,
                self.state.config.entry.edges.first().map(String::as_str),
            )),
            ..Default::default()
        })
    }
}
