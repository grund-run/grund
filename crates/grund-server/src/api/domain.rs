//! `grund.domain.v1.DomainService`: an organisation's custom domains
//! (grund-docs website/design/app-domains.md §3). Members get and list;
//! owners and admins add, verify, bind, unbind and remove. A person's
//! session, or a token of scope full in its own organisation (auth.md §6).
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
    DomainService, ErrorReason, GetDomainRequest, GetDomainResponse, ListDomainsRequest,
    ListDomainsResponse, RemoveDomainRequest, RemoveDomainResponse, UnbindDomainRequest,
    UnbindDomainResponse, VerifyDomainRequest, VerifyDomainResponse,
};
use grund_store::organisations::Membership;

use crate::{
    api::principal,
    services::{
        OrganisationsState,
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
        DomainsError::Invalid(_) | DomainsError::Reserved(_) => {
            ConnectError::invalid_argument(message)
        }
        DomainsError::Exists | DomainsError::Taken => ConnectError::already_exists(message),
        DomainsError::Limit | DomainsError::DailyLimit | DomainsError::AppLimit => {
            ConnectError::resource_exhausted(message)
        }
        DomainsError::CoolingDown(_)
        | DomainsError::NotVerified
        | DomainsError::VerificationFailed(_)
        | DomainsError::AppNotPublic => ConnectError::failed_precondition(message),
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

fn message(view: &DomainView) -> proto::Domain {
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
        let (_, membership) = self.member(&ctx, request.organisation).await?;
        let domains = self
            .state
            .domains()
            .list(membership.organisation_id)
            .await
            .map_err(failed)?;
        Response::ok(ListDomainsResponse {
            domains: domains.iter().map(message).collect(),
            ..Default::default()
        })
    }

    async fn get_domain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetDomainRequest>,
    ) -> ServiceResult<GetDomainResponse> {
        let (_, membership) = self.member(&ctx, request.organisation).await?;
        let domain = self
            .state
            .domains()
            .get(membership.organisation_id, request.name)
            .await
            .map_err(failed)?;
        Response::ok(GetDomainResponse {
            domain: MessageField::some(message(&domain)),
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
            domain: MessageField::some(message(&domain)),
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
            domain: MessageField::some(message(&domain)),
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
            domain: MessageField::some(message(&domain)),
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
            domain: MessageField::some(message(&domain)),
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
}
