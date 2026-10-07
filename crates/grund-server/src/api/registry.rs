//! `grund.registry.v1.RegistryService`: an organisation's registry logins
//! (grund-docs design/apps.md §6.5), the same as Organisation → Registries.
//! Members list; owners and admins set and remove. A person's session, or
//! a token of scope full in its own organisation (auth.md §6).

use buffa::MessageField;
use buffa_types::google::protobuf::Timestamp;
use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_proto::grund::registry::v1::{
    self as proto, ErrorReason, ListRegistryLoginsRequest, ListRegistryLoginsResponse,
    RegistryService, RemoveRegistryLoginRequest, RemoveRegistryLoginResponse,
    SetRegistryLoginRequest, SetRegistryLoginResponse,
};
use grund_store::{organisations::Membership, registry_credentials::CredentialView};

use crate::{
    api::{Principal, principal},
    services::{
        OrganisationsState,
        registry_credentials::{MAX_PER_ORGANISATION, Refusal, RegistryCredentialsState},
    },
    state::State,
};

/// The service implementation.
pub struct RegistryApi {
    state: State,
}

impl RegistryApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn member(&self, caller: &Principal, slug: &str) -> Result<Membership, ConnectError> {
        self.state
            .organisations()
            .membership(slug, caller.account_id)
            .await
            .map_err(internal)?
            .filter(|m| caller.reaches(m.organisation_id))
            .ok_or_else(|| ConnectError::not_found("no such organisation"))
    }

    async fn login(
        &self,
        organisation_id: uuid::Uuid,
        host: &str,
    ) -> Result<proto::RegistryLogin, ConnectError> {
        self.state
            .registry_credentials()
            .list(organisation_id)
            .await
            .map_err(internal)?
            .into_iter()
            .find(|c| c.host == host)
            .map(login_message)
            .ok_or_else(|| internal("a login just set is not found"))
    }
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "registry API call failed");
    ConnectError::internal("grund could not finish that")
}

fn refusal(error: ConnectError, reason: &str) -> ConnectError {
    error.with_detail(ErrorDetail::from_message(
        "grund.registry.v1.ErrorReason",
        &ErrorReason {
            reason: reason.to_string(),
            ..Default::default()
        },
    ))
}

fn refused(refusal_: Refusal) -> ConnectError {
    match refusal_ {
        Refusal::NotAllowed => ConnectError::permission_denied(
            "only owners and admins change an organisation's registry logins",
        ),
        Refusal::TooMany => refusal(
            ConnectError::failed_precondition(format!(
                "this organisation has {MAX_PER_ORGANISATION} registry logins; remove one first"
            )),
            "registry_limit",
        ),
        Refusal::Invalid { field, problem } => refusal(
            ConnectError::invalid_argument(problem),
            &format!("{field}_invalid"),
        ),
    }
}

fn login_message(view: CredentialView) -> proto::RegistryLogin {
    proto::RegistryLogin {
        host: view.host,
        username: view.username,
        version: view.version.max(0) as u32,
        updated_by: view.updated_by.unwrap_or_default(),
        updated_at: MessageField::from(Timestamp::from_unix(
            view.updated_at.timestamp(),
            view.updated_at.timestamp_subsec_nanos() as i32,
        )),
        ..Default::default()
    }
}

#[allow(refining_impl_trait)]
impl RegistryService for RegistryApi {
    async fn list_registry_logins(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListRegistryLoginsRequest>,
    ) -> ServiceResult<ListRegistryLoginsResponse> {
        let caller = principal(&ctx)?;
        let membership = self.member(&caller, request.organisation).await?;
        let logins = self
            .state
            .registry_credentials()
            .list(membership.organisation_id)
            .await
            .map_err(internal)?;
        Response::ok(ListRegistryLoginsResponse {
            logins: logins.into_iter().map(login_message).collect(),
            ..Default::default()
        })
    }

    async fn set_registry_login(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetRegistryLoginRequest>,
    ) -> ServiceResult<SetRegistryLoginResponse> {
        let caller = principal(&ctx)?;
        let membership = self.member(&caller, request.organisation).await?;
        let host = self
            .state
            .registry_credentials()
            .set(
                caller.account_id,
                &membership,
                request.host,
                request.username,
                request.password,
            )
            .await
            .map_err(internal)?
            .map_err(refused)?;
        let login = self.login(membership.organisation_id, &host).await?;
        Response::ok(SetRegistryLoginResponse {
            login: MessageField::from(login),
            ..Default::default()
        })
    }

    async fn remove_registry_login(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RemoveRegistryLoginRequest>,
    ) -> ServiceResult<RemoveRegistryLoginResponse> {
        let caller = principal(&ctx)?;
        let membership = self.member(&caller, request.organisation).await?;
        let removed = self
            .state
            .registry_credentials()
            .remove(caller.account_id, &membership, request.host)
            .await
            .map_err(internal)?
            .map_err(refused)?;
        if !removed {
            return Err(ConnectError::not_found("no login for that host"));
        }
        Response::ok(RemoveRegistryLoginResponse::default())
    }
}
