//! The Connect API (skills `connect-rpc`, D-18): `grund.account.v1`, served
//! over Connect, gRPC and gRPC-Web from the same routes as the pages.
//!
//! ```text
//!   request ─► authenticate (tower): the dashboard session cookie, before the body is read
//!           ─► ConnectRpcService: limits, deadlines
//!           ─► authorize (interceptor): every procedure needs an entry, or it is denied
//!           └► handler: acts on the caller only
//! ```
//!
//! The caller today is the dashboard, same-origin, with its session cookie.
//! A cookie-authenticated call whose `Origin` or `Sec-Fetch-Site` names another
//! site is refused: a cross-site page cannot make a browser send Connect's
//! content types without a CORS preflight, which grund never grants, and this
//! check does not rely on that alone. Bearer tokens (personal access tokens
//! for the CLI) are designed and not built; a call
//! presenting one is refused as unauthenticated.

pub mod account;
pub mod agent;
pub mod enrollment;
pub mod machine;
pub mod organisation;

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Request, State as AxumState},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use connectrpc::{
    ConnectError, ConnectRpcService, DeadlinePolicy, Limits,
    interceptor::{Interceptor, Next as InterceptNext, UnaryRequest, UnaryResponse},
};
use grund_proto::grund::{
    account::v1::ACCOUNT_SERVICE_SERVICE_NAME,
    agent::v1::{AGENT_SERVICE_SERVICE_NAME, MACHINE_ENROLLMENT_SERVICE_SERVICE_NAME},
    machine::v1::{MACHINE_SERVICE_SERVICE_NAME, MANAGEMENT_POOL_SERVICE_SERVICE_NAME},
    organisation::v1::ORGANISATION_SERVICE_SERVICE_NAME,
};
use uuid::Uuid;

use crate::{
    services::{agents::AgentsState, sessions::SessionsState},
    state::State,
    web::browser::{CookieJar, client_address, cookie, same_origin},
};

/// The largest request the API accepts. Its largest message is a session id.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Who an API call is from, stamped by [`authenticate`]. Handlers act on this
/// account only.
#[derive(Debug, Clone, Copy)]
pub struct Caller {
    pub account_id: Uuid,
    pub session_id: Uuid,
}

/// The client address of a call that is not behind the session (machine
/// enrollment), for its rate limit. Stamped by [`stamp_address`].
#[derive(Debug, Clone)]
pub struct ClientAddress(pub String);

/// What a procedure requires of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Any signed-in person, acting on their own account.
    Session,
    /// No session: a one-time token in the request is the credential, checked
    /// by the handler (machine enrollment). Served on routes without the
    /// session and same-origin checks.
    Token,
    /// A registered machine, proven by its key's signature over the request
    /// ([`authenticate_machine`]): the control link.
    Machine,
}

/// Every procedure and what it requires. A procedure missing here is denied,
/// whatever the router serves (`every_procedure_has_an_authorization_entry`).
pub const AUTHORIZATION: &[(&str, Requirement)] = &[
    (
        "/grund.account.v1.AccountService/GetViewer",
        Requirement::Session,
    ),
    (
        "/grund.account.v1.AccountService/ListSessions",
        Requirement::Session,
    ),
    (
        "/grund.account.v1.AccountService/RevokeSession",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/ListOrganisations",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/GetOrganisation",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/CreateOrganisation",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/RenameOrganisation",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/DeleteOrganisation",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/ListMembers",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/ChangeMemberRole",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/RemoveMember",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/ListInvitations",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/InviteMember",
        Requirement::Session,
    ),
    (
        "/grund.organisation.v1.OrganisationService/RevokeInvitation",
        Requirement::Session,
    ),
    (
        "/grund.agent.v1.MachineEnrollmentService/EnrollMachine",
        Requirement::Token,
    ),
    (
        "/grund.machine.v1.ManagementPoolService/CreateRegistrationToken",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.ManagementPoolService/CreateReregistrationToken",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.ManagementPoolService/ListPoolMachines",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.ManagementPoolService/GetPoolMachine",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.ManagementPoolService/LeaseMachine",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.ManagementPoolService/EndLease",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.ManagementPoolService/RevokePoolMachine",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.ManagementPoolService/ProvisionPoolMachine",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.ManagementPoolService/RebuildPoolMachine",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.MachineService/CreateJoinToken",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.MachineService/ListMachines",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.MachineService/GetMachine",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.MachineService/RevokeMachine",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.MachineService/GetOrganisationKey",
        Requirement::Session,
    ),
    (
        "/grund.agent.v1.AgentService/Heartbeat",
        Requirement::Machine,
    ),
    (
        "/grund.agent.v1.AgentService/GetDesiredState",
        Requirement::Machine,
    ),
    (
        "/grund.agent.v1.AgentService/GetMachineJoinToken",
        Requirement::Machine,
    ),
    (
        "/grund.agent.v1.AgentService/ReportStatus",
        Requirement::Machine,
    ),
    (
        "/grund.machine.v1.MachineService/RunVm",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.MachineService/StopVm",
        Requirement::Session,
    ),
    (
        "/grund.machine.v1.MachineService/ListVms",
        Requirement::Session,
    ),
];

/// The API routes, to merge into the page router.
pub fn router(state: State) -> axum::Router {
    let service = ConnectRpcService::new(connect_router(state.clone()))
        .with_limits(
            Limits::default()
                .with_max_request_body_size(MAX_REQUEST_BYTES)
                .with_max_message_size(MAX_REQUEST_BYTES),
        )
        .with_deadline_policy(
            DeadlinePolicy::new()
                .with_min(Duration::from_millis(5))
                .with_max(Duration::from_secs(30))
                .with_default_timeout(Duration::from_secs(10)),
        )
        .with_interceptor(Authorize);
    axum::Router::new()
        .route_service(
            &format!("/{ACCOUNT_SERVICE_SERVICE_NAME}/{{method}}"),
            service.clone(),
        )
        .route_service(
            &format!("/{ORGANISATION_SERVICE_SERVICE_NAME}/{{method}}"),
            service.clone(),
        )
        .route_service(
            &format!("/{MANAGEMENT_POOL_SERVICE_SERVICE_NAME}/{{method}}"),
            service.clone(),
        )
        .route_service(
            &format!("/{MACHINE_SERVICE_SERVICE_NAME}/{{method}}"),
            service.clone(),
        )
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .merge(
            axum::Router::new()
                .route_service(
                    &format!("/{MACHINE_ENROLLMENT_SERVICE_SERVICE_NAME}/{{method}}"),
                    service.clone(),
                )
                .layer(middleware::from_fn_with_state(state.clone(), stamp_address)),
        )
        .merge(
            axum::Router::new()
                .route_service(
                    &format!("/{AGENT_SERVICE_SERVICE_NAME}/{{method}}"),
                    service,
                )
                .layer(middleware::from_fn_with_state(state, authenticate_machine)),
        )
}

/// The largest control-link request: a status report of every VM a machine
/// hosts.
pub const MAX_AGENT_REQUEST_BYTES: usize = 256 * 1024;

/// Authenticates a control-link request by the machine key's signature over
/// its path, time and body (grund-docs design/machines.md §7b), before any
/// handler runs. A bad or missing signature, an unknown machine and a revoked
/// one are refused alike.
pub async fn authenticate_machine(
    AxumState(state): AxumState<State>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let (machine, signed_at, signature) = (
        header("x-grund-machine"),
        header("x-grund-signed-at"),
        header("x-grund-signature"),
    );
    let Ok(bytes) = axum::body::to_bytes(body, MAX_AGENT_REQUEST_BYTES).await else {
        return refuse(ConnectError::resource_exhausted("the request is too large"));
    };
    let caller = match state
        .agents()
        .authenticate(&machine, &signed_at, &signature, parts.uri.path(), &bytes)
        .await
    {
        Ok(Some(caller)) => caller,
        Ok(None) => {
            return refuse(ConnectError::unauthenticated(
                "sign the request with the machine key",
            ));
        }
        Err(error) => {
            tracing::warn!(error = %error, "machine authentication failed");
            return refuse(ConnectError::unavailable(
                "grund is temporarily unavailable",
            ));
        }
    };
    parts.extensions.insert(caller);
    let mut response = next
        .run(Request::from_parts(parts, axum::body::Body::from(bytes)))
        .await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Stamps the client address on a call that is not behind the session, so
/// its handler can rate-limit by it. Machines are not browsers: no cookie,
/// origin or session is looked at here.
pub async fn stamp_address(
    AxumState(state): AxumState<State>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip().to_string());
    let address = client_address(
        request.headers(),
        peer.as_deref(),
        state.config.trusted_proxy_hops,
    );
    request.extensions_mut().insert(ClientAddress(address));
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The Connect router with every service registered.
pub fn connect_router(state: State) -> connectrpc::Router {
    connectrpc::Router::new()
        .add_service(Arc::new(account::AccountApi::new(state.clone())))
        .add_service(Arc::new(organisation::OrganisationApi::new(state.clone())))
        .add_service(Arc::new(machine::ManagementPoolApi::new(state.clone())))
        .add_service(Arc::new(machine::MachineApi::new(state.clone())))
        .add_service(Arc::new(enrollment::EnrollmentApi::new(state.clone())))
        .add_service(Arc::new(agent::AgentApi::new(state)))
}

fn refuse(error: ConnectError) -> Response {
    let mut response = (error.http_status(), error.to_json()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// Authenticates before the body is read: the session cookie must name a live
/// session, and a cookie-authenticated call must come from this origin.
pub async fn authenticate(
    AxumState(state): AxumState<State>,
    mut request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    if headers.contains_key(header::AUTHORIZATION) {
        return refuse(ConnectError::unauthenticated(
            "API tokens are not available yet; sign in to the dashboard",
        ));
    }
    let origin = state.config.public_origin();
    if !same_origin(headers, &origin) {
        return refuse(ConnectError::permission_denied(
            "cross-origin calls are not allowed",
        ));
    }
    let jar = CookieJar::for_origin(&origin);
    let Some(token) = cookie(headers, jar.session_name()).filter(|t| t.len() == 43) else {
        return refuse(ConnectError::unauthenticated("sign in first"));
    };
    let session = match state.sessions().authenticate(&token).await {
        Ok(Some(session)) => session,
        Ok(None) => return refuse(ConnectError::unauthenticated("sign in first")),
        Err(error) => {
            tracing::warn!(error = %error, "session lookup failed for an API call");
            return refuse(ConnectError::unavailable(
                "grund is temporarily unavailable",
            ));
        }
    };
    request.extensions_mut().insert(Caller {
        account_id: session.account_id,
        session_id: session.session_id,
    });
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if response.status() == StatusCode::NOT_FOUND
        && response.headers().get(header::CONTENT_TYPE).is_none()
    {
        return refuse(ConnectError::unimplemented("no such procedure"));
    }
    response
}

/// Authorizes each call against [`AUTHORIZATION`], denying by default.
pub struct Authorize;

#[connectrpc::async_trait]
impl Interceptor for Authorize {
    async fn intercept_unary(
        &self,
        request: UnaryRequest,
        next: InterceptNext<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        let path = request.ctx.path().unwrap_or_default().to_string();
        let requirement = AUTHORIZATION
            .iter()
            .find(|(procedure, _)| *procedure == path)
            .map(|(_, r)| *r);
        match requirement {
            Some(Requirement::Session) if request.ctx.extensions().get::<Caller>().is_some() => {
                next.run(request).await
            }
            Some(Requirement::Session) => Err(ConnectError::unauthenticated("sign in first")),
            Some(Requirement::Token) => next.run(request).await,
            Some(Requirement::Machine)
                if request
                    .ctx
                    .extensions()
                    .get::<crate::services::agents::MachineCaller>()
                    .is_some() =>
            {
                next.run(request).await
            }
            Some(Requirement::Machine) => Err(ConnectError::unauthenticated(
                "sign the request with the machine key",
            )),
            None => Err(ConnectError::permission_denied(
                "this procedure is not open to callers",
            )),
        }
    }
}

/// The caller [`authenticate`] stamped on the request.
pub fn caller(ctx: &connectrpc::RequestContext) -> Result<Caller, ConnectError> {
    ctx.extensions()
        .get::<Caller>()
        .copied()
        .ok_or_else(|| ConnectError::unauthenticated("sign in first"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
    use grund_proto::grund::account::v1::{
        AccountService, GetViewerRequest, GetViewerResponse, ListSessionsRequest,
        ListSessionsResponse, RevokeSessionRequest, RevokeSessionResponse,
    };

    use grund_proto::grund::{agent::v1 as agent, machine::v1 as machine, organisation::v1 as org};

    use super::*;

    struct Unused;

    #[allow(refining_impl_trait)]
    impl AccountService for Unused {
        async fn get_viewer(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, GetViewerRequest>,
        ) -> ServiceResult<GetViewerResponse> {
            unreachable!()
        }
        async fn list_sessions(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, ListSessionsRequest>,
        ) -> ServiceResult<ListSessionsResponse> {
            unreachable!()
        }
        async fn revoke_session(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, RevokeSessionRequest>,
        ) -> ServiceResult<RevokeSessionResponse> {
            unreachable!()
        }
    }

    struct UnusedOrganisations;

    #[allow(refining_impl_trait)]
    impl org::OrganisationService for UnusedOrganisations {
        async fn list_organisations(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::ListOrganisationsRequest>,
        ) -> ServiceResult<org::ListOrganisationsResponse> {
            unreachable!()
        }
        async fn get_organisation(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::GetOrganisationRequest>,
        ) -> ServiceResult<org::GetOrganisationResponse> {
            unreachable!()
        }
        async fn create_organisation(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::CreateOrganisationRequest>,
        ) -> ServiceResult<org::CreateOrganisationResponse> {
            unreachable!()
        }
        async fn rename_organisation(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::RenameOrganisationRequest>,
        ) -> ServiceResult<org::RenameOrganisationResponse> {
            unreachable!()
        }
        async fn delete_organisation(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::DeleteOrganisationRequest>,
        ) -> ServiceResult<org::DeleteOrganisationResponse> {
            unreachable!()
        }
        async fn list_members(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::ListMembersRequest>,
        ) -> ServiceResult<org::ListMembersResponse> {
            unreachable!()
        }
        async fn change_member_role(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::ChangeMemberRoleRequest>,
        ) -> ServiceResult<org::ChangeMemberRoleResponse> {
            unreachable!()
        }
        async fn remove_member(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::RemoveMemberRequest>,
        ) -> ServiceResult<org::RemoveMemberResponse> {
            unreachable!()
        }
        async fn list_invitations(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::ListInvitationsRequest>,
        ) -> ServiceResult<org::ListInvitationsResponse> {
            unreachable!()
        }
        async fn invite_member(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::InviteMemberRequest>,
        ) -> ServiceResult<org::InviteMemberResponse> {
            unreachable!()
        }
        async fn revoke_invitation(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, org::RevokeInvitationRequest>,
        ) -> ServiceResult<org::RevokeInvitationResponse> {
            unreachable!()
        }
    }

    struct UnusedPool;

    #[allow(refining_impl_trait)]
    impl machine::ManagementPoolService for UnusedPool {
        async fn create_registration_token(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::CreateRegistrationTokenRequest>,
        ) -> ServiceResult<machine::CreateRegistrationTokenResponse> {
            unreachable!()
        }
        async fn create_reregistration_token(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::CreateReregistrationTokenRequest>,
        ) -> ServiceResult<machine::CreateReregistrationTokenResponse> {
            unreachable!()
        }
        async fn list_pool_machines(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::ListPoolMachinesRequest>,
        ) -> ServiceResult<machine::ListPoolMachinesResponse> {
            unreachable!()
        }
        async fn get_pool_machine(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::GetPoolMachineRequest>,
        ) -> ServiceResult<machine::GetPoolMachineResponse> {
            unreachable!()
        }
        async fn lease_machine(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::LeaseMachineRequest>,
        ) -> ServiceResult<machine::LeaseMachineResponse> {
            unreachable!()
        }
        async fn end_lease(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::EndLeaseRequest>,
        ) -> ServiceResult<machine::EndLeaseResponse> {
            unreachable!()
        }
        async fn revoke_pool_machine(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::RevokePoolMachineRequest>,
        ) -> ServiceResult<machine::RevokePoolMachineResponse> {
            unreachable!()
        }
        async fn provision_pool_machine(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::ProvisionPoolMachineRequest>,
        ) -> ServiceResult<machine::ProvisionPoolMachineResponse> {
            unreachable!()
        }
        async fn rebuild_pool_machine(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::RebuildPoolMachineRequest>,
        ) -> ServiceResult<machine::RebuildPoolMachineResponse> {
            unreachable!()
        }
    }

    struct UnusedMachines;

    #[allow(refining_impl_trait)]
    impl machine::MachineService for UnusedMachines {
        async fn create_join_token(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::CreateJoinTokenRequest>,
        ) -> ServiceResult<machine::CreateJoinTokenResponse> {
            unreachable!()
        }
        async fn list_machines(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::ListMachinesRequest>,
        ) -> ServiceResult<machine::ListMachinesResponse> {
            unreachable!()
        }
        async fn get_machine(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::GetMachineRequest>,
        ) -> ServiceResult<machine::GetMachineResponse> {
            unreachable!()
        }
        async fn revoke_machine(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::RevokeMachineRequest>,
        ) -> ServiceResult<machine::RevokeMachineResponse> {
            unreachable!()
        }
        async fn get_organisation_key(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::GetOrganisationKeyRequest>,
        ) -> ServiceResult<machine::GetOrganisationKeyResponse> {
            unreachable!()
        }
        async fn run_vm(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::RunVmRequest>,
        ) -> ServiceResult<machine::RunVmResponse> {
            unreachable!()
        }
        async fn stop_vm(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::StopVmRequest>,
        ) -> ServiceResult<machine::StopVmResponse> {
            unreachable!()
        }
        async fn list_vms(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::ListVmsRequest>,
        ) -> ServiceResult<machine::ListVmsResponse> {
            unreachable!()
        }
    }

    struct UnusedAgent;

    #[allow(refining_impl_trait)]
    impl agent::AgentService for UnusedAgent {
        async fn heartbeat(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, agent::HeartbeatRequest>,
        ) -> ServiceResult<agent::HeartbeatResponse> {
            unreachable!()
        }
        async fn get_desired_state(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, agent::GetDesiredStateRequest>,
        ) -> ServiceResult<agent::GetDesiredStateResponse> {
            unreachable!()
        }
        async fn get_machine_join_token(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, agent::GetMachineJoinTokenRequest>,
        ) -> ServiceResult<agent::GetMachineJoinTokenResponse> {
            unreachable!()
        }
        async fn report_status(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, agent::ReportStatusRequest>,
        ) -> ServiceResult<agent::ReportStatusResponse> {
            unreachable!()
        }
    }

    struct UnusedEnrollment;

    #[allow(refining_impl_trait)]
    impl agent::MachineEnrollmentService for UnusedEnrollment {
        async fn enroll_machine(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, agent::EnrollMachineRequest>,
        ) -> ServiceResult<agent::EnrollMachineResponse> {
            unreachable!()
        }
    }

    #[test]
    fn every_procedure_has_an_authorization_entry() {
        let router = connectrpc::Router::new()
            .add_service(Arc::new(Unused))
            .add_service(Arc::new(UnusedOrganisations))
            .add_service(Arc::new(UnusedPool))
            .add_service(Arc::new(UnusedMachines))
            .add_service(Arc::new(UnusedEnrollment))
            .add_service(Arc::new(UnusedAgent));
        let served: BTreeSet<String> = router
            .methods()
            .map(|m| format!("/{}", m.trim_start_matches('/')))
            .collect();
        let authorized: BTreeSet<String> =
            AUTHORIZATION.iter().map(|(p, _)| p.to_string()).collect();
        assert_eq!(
            served, authorized,
            "every served procedure needs exactly one AUTHORIZATION entry"
        );
    }
}
