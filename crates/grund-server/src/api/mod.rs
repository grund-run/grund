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
//! A caller is the dashboard, same-origin, with its session cookie, or CI
//! and scripts with a personal access token (`Authorization: Bearer
//! grund_pat_…`, grund-docs design/auth.md §6). A cookie-authenticated call
//! whose `Origin` or `Sec-Fetch-Site` names another site is refused: a
//! cross-site page cannot make a browser send Connect's content types without
//! a CORS preflight, which grund never grants, and this check does not rely
//! on that alone. A token-authenticated call carries no cookie, so the origin
//! check does not apply to it; a cross-site page cannot set the header
//! without a preflight either. A call that presents an `Authorization`
//! header is judged by the token alone, never by a cookie beside it.
//!
//! A token may call only the procedures [`AUTHORIZATION`] marks
//! [`Requirement::SessionOrToken`]: the app procedures CI needs, and not
//! DeleteApp. Everything else stays session-only: the account, members and
//! invitations, renaming and deleting organisations, machines and their join
//! tokens, and the management pool. A token acts only on its own
//! organisation; any other is `not_found`, as for a non-member.

pub mod account;
pub mod agent;
pub mod app;
pub mod certificates;
pub mod edge;
pub mod enrollment;
pub mod machine;
pub mod organisation;
pub mod relay_access;
pub mod relay_enrollment;

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
    app::v1::APP_SERVICE_SERVICE_NAME,
    certificates::v1::CERTIFICATE_SERVICE_SERVICE_NAME,
    edge::v1::{EDGE_ENROLLMENT_SERVICE_SERVICE_NAME, EDGE_SERVICE_SERVICE_NAME},
    machine::v1::{MACHINE_SERVICE_SERVICE_NAME, MANAGEMENT_POOL_SERVICE_SERVICE_NAME},
    organisation::v1::ORGANISATION_SERVICE_SERVICE_NAME,
    relay::v1::RELAY_ENROLLMENT_SERVICE_SERVICE_NAME,
};
use uuid::Uuid;

use crate::{
    services::{
        agents::AgentsState,
        sessions::SessionsState,
        tokens::{TokenCaller, TokensState},
    },
    state::State,
    web::browser::{CookieJar, client_address, cookie, same_origin},
};

/// The largest request the API accepts. Its largest message is a session id.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Who a session-authenticated API call is from, stamped by
/// [`authenticate`]. Handlers act on this account only.
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
    /// Any signed-in person, acting on their own account. A token is
    /// refused.
    Session,
    /// A signed-in person, or a personal access token acting as the account
    /// that made it, within the token's organisation only.
    SessionOrToken,
    /// No session: a one-time token in the request is the credential, checked
    /// by the handler (machine enrollment). Served on routes without the
    /// session and same-origin checks.
    Token,
    /// A registered machine, proven by its key's signature over the request
    /// ([`authenticate_machine`]): the control link.
    Machine,
    /// A TLS terminator on another host, an enrolled relay or edge, or a
    /// registered machine, proven by its own key's signature
    /// ([`authenticate_terminator`]): the certificate service.
    Terminator,
    /// An enrolled `grund edge`, proven by its key's signature
    /// ([`authenticate_edge`]): its route table and usage.
    Edge,
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
        "/grund.machine.v1.MachineService/DeclareMachinePorts",
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
        "/grund.agent.v1.AgentService/WatchDesiredState",
        Requirement::Machine,
    ),
    (
        "/grund.agent.v1.AgentService/GetReplicaSecrets",
        Requirement::Machine,
    ),
    (
        "/grund.agent.v1.AgentService/GetPullCredential",
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
        "/grund.agent.v1.AgentService/GetMembership",
        Requirement::Machine,
    ),
    (
        "/grund.relay.v1.RelayEnrollmentService/EnrollRelay",
        Requirement::Token,
    ),
    (
        "/grund.edge.v1.EdgeEnrollmentService/EnrollEdge",
        Requirement::Token,
    ),
    ("/grund.edge.v1.EdgeService/WatchRoutes", Requirement::Edge),
    ("/grund.edge.v1.EdgeService/ReportUsage", Requirement::Edge),
    (
        "/grund.certificates.v1.CertificateService/RequestCertificate",
        Requirement::Terminator,
    ),
    (
        "/grund.certificates.v1.CertificateService/WatchChallenges",
        Requirement::Terminator,
    ),
    (
        "/grund.certificates.v1.CertificateService/AnswerChallenge",
        Requirement::Terminator,
    ),
    (
        "/grund.certificates.v1.CertificateService/GetCertificate",
        Requirement::Terminator,
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
    (
        "/grund.app.v1.AppService/CreateApp",
        Requirement::SessionOrToken,
    ),
    (
        "/grund.app.v1.AppService/GetApp",
        Requirement::SessionOrToken,
    ),
    (
        "/grund.app.v1.AppService/ListApps",
        Requirement::SessionOrToken,
    ),
    (
        "/grund.app.v1.AppService/Deploy",
        Requirement::SessionOrToken,
    ),
    (
        "/grund.app.v1.AppService/ListReleases",
        Requirement::SessionOrToken,
    ),
    (
        "/grund.app.v1.AppService/Rollback",
        Requirement::SessionOrToken,
    ),
    (
        "/grund.app.v1.AppService/Scale",
        Requirement::SessionOrToken,
    ),
    (
        "/grund.app.v1.AppService/ConfigureApp",
        Requirement::SessionOrToken,
    ),
    (
        "/grund.app.v1.AppService/SetSecret",
        Requirement::SessionOrToken,
    ),
    ("/grund.app.v1.AppService/DeleteApp", Requirement::Session),
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
        .route_service(
            &format!("/{APP_SERVICE_SERVICE_NAME}/{{method}}"),
            app_service(state.clone()),
        )
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .merge(
            axum::Router::new()
                .route_service(
                    &format!("/{MACHINE_ENROLLMENT_SERVICE_SERVICE_NAME}/{{method}}"),
                    service.clone(),
                )
                .route_service(
                    &format!("/{RELAY_ENROLLMENT_SERVICE_SERVICE_NAME}/{{method}}"),
                    service.clone(),
                )
                .route_service(
                    &format!("/{EDGE_ENROLLMENT_SERVICE_SERVICE_NAME}/{{method}}"),
                    service.clone(),
                )
                .layer(middleware::from_fn_with_state(state.clone(), stamp_address)),
        )
        .merge(
            axum::Router::new()
                .route_service(
                    &format!("/{CERTIFICATE_SERVICE_SERVICE_NAME}/{{method}}"),
                    certificate_service(state.clone()),
                )
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    authenticate_terminator,
                )),
        )
        .merge(
            axum::Router::new()
                .route_service(
                    &format!("/{EDGE_SERVICE_SERVICE_NAME}/{{method}}"),
                    edge_service(state.clone()),
                )
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    authenticate_edge,
                )),
        )
        .merge(
            axum::Router::new()
                .route_service(
                    &format!("/{AGENT_SERVICE_SERVICE_NAME}/{{method}}"),
                    service,
                )
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    authenticate_machine,
                )),
        )
        .merge(relay_access::router(state))
}

/// The largest app request: a deploy with its env and a grund.toml.
pub const MAX_APP_REQUEST_BYTES: usize = 128 * 1024;

/// The app service, on a Connect service of its own: a deploy carries more
/// than any other session call (a spec's env is up to 32 KiB, a grund.toml
/// up to 64 KiB). A deploy resolves the image at its registry, so it gets
/// up to 30 s.
pub fn app_service(state: State) -> ConnectRpcService {
    ConnectRpcService::new(connectrpc::Router::new().add_service(Arc::new(app::AppApi::new(state))))
        .with_limits(
            Limits::default()
                .with_max_request_body_size(MAX_APP_REQUEST_BYTES)
                .with_max_message_size(MAX_APP_REQUEST_BYTES),
        )
        .with_deadline_policy(
            DeadlinePolicy::new()
                .with_min(Duration::from_millis(5))
                .with_max(Duration::from_secs(30))
                .with_default_timeout(Duration::from_secs(30)),
        )
        .with_interceptor(Authorize)
}

/// The largest control-link request: a status report of every VM a machine
/// hosts.
pub const MAX_AGENT_REQUEST_BYTES: usize = 256 * 1024;

/// The largest certificate-service request: a 4 KiB CSR and its names.
pub const MAX_TERMINATOR_REQUEST_BYTES: usize = 16 * 1024;

/// The certificate service, on a Connect service of its own: its watch is a
/// server stream that ends by itself after 25 s
/// ([`certificates::WATCH_SPAN`]), so it gets a longer deadline than the
/// rest of the API, enforced on streams too.
pub fn certificate_service(state: State) -> ConnectRpcService {
    ConnectRpcService::new(
        connectrpc::Router::new().add_service(Arc::new(certificates::CertificatesApi::new(state))),
    )
    .with_limits(
        Limits::default()
            .with_max_request_body_size(MAX_TERMINATOR_REQUEST_BYTES)
            .with_max_message_size(MAX_TERMINATOR_REQUEST_BYTES),
    )
    .with_deadline_policy(
        DeadlinePolicy::new()
            .with_min(Duration::from_millis(5))
            .with_max(Duration::from_secs(60))
            .with_default_timeout(Duration::from_secs(30))
            .with_enforce_on_streams(true),
    )
    .with_interceptor(Authorize)
}

/// The largest edge request: a usage report of up to 1000 addresses.
pub const MAX_EDGE_REQUEST_BYTES: usize = 256 * 1024;

/// The edge service, on a Connect service of its own: WatchRoutes waits up
/// to 10 s, so it gets up to 30 s.
pub fn edge_service(state: State) -> ConnectRpcService {
    ConnectRpcService::new(
        connectrpc::Router::new().add_service(Arc::new(edge::EdgeApi::new(state))),
    )
    .with_limits(
        Limits::default()
            .with_max_request_body_size(MAX_EDGE_REQUEST_BYTES)
            .with_max_message_size(MAX_EDGE_REQUEST_BYTES),
    )
    .with_deadline_policy(
        DeadlinePolicy::new()
            .with_min(Duration::from_millis(5))
            .with_max(Duration::from_secs(30))
            .with_default_timeout(Duration::from_secs(30)),
    )
    .with_interceptor(Authorize)
}

/// Authenticates an edge-service request by the edge's key
/// (`x-grund-edge`), before any handler runs. A bad or missing signature,
/// an unknown or revoked edge and one whose host left GRUND_EDGES are
/// refused alike.
pub async fn authenticate_edge(
    AxumState(state): AxumState<State>,
    request: Request,
    next: Next,
) -> Response {
    use crate::services::relays::{RelaysState, Role};
    let (mut parts, body) = request.into_parts();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let (edge, signed_at, signature) = (
        header("x-grund-edge"),
        header("x-grund-signed-at"),
        header("x-grund-signature"),
    );
    let Ok(bytes) = axum::body::to_bytes(body, MAX_EDGE_REQUEST_BYTES).await else {
        return refuse(ConnectError::resource_exhausted("the request is too large"));
    };
    let path = parts.uri.path().to_string();
    match state
        .relays()
        .authenticate_as(Role::Edge, &edge, &signed_at, &signature, &path, &bytes)
        .await
    {
        Ok(Some(caller)) => {
            parts.extensions.insert(edge::EdgeCaller(caller));
        }
        Ok(None) => {
            return refuse(ConnectError::unauthenticated(
                "sign the request with the edge's key",
            ));
        }
        Err(error) => {
            tracing::warn!(error = %error, "edge authentication failed");
            return refuse(ConnectError::unavailable(
                "grund is temporarily unavailable",
            ));
        }
    }
    let mut response = next
        .run(Request::from_parts(parts, axum::body::Body::from(bytes)))
        .await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Authenticates a certificate-service request by the terminator's own key
/// before any handler runs: an enrolled relay (`x-grund-relay`), or a
/// registered machine (`x-grund-machine`), each signing the control link's
/// way. A bad or missing signature, an unknown or revoked terminator are
/// refused alike.
pub async fn authenticate_terminator(
    AxumState(state): AxumState<State>,
    request: Request,
    next: Next,
) -> Response {
    use crate::services::{relays::RelaysState, terminators::Terminator};
    let (mut parts, body) = request.into_parts();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let (relay, edge, machine, signed_at, signature) = (
        header("x-grund-relay"),
        header("x-grund-edge"),
        header("x-grund-machine"),
        header("x-grund-signed-at"),
        header("x-grund-signature"),
    );
    let Ok(bytes) = axum::body::to_bytes(body, MAX_TERMINATOR_REQUEST_BYTES).await else {
        return refuse(ConnectError::resource_exhausted("the request is too large"));
    };
    let path = parts.uri.path().to_string();
    let caller = if !relay.is_empty() {
        state
            .relays()
            .authenticate(&relay, &signed_at, &signature, &path, &bytes)
            .await
            .map(|caller| caller.map(Terminator::Relay))
    } else if !edge.is_empty() {
        state
            .relays()
            .authenticate_as(
                crate::services::relays::Role::Edge,
                &edge,
                &signed_at,
                &signature,
                &path,
                &bytes,
            )
            .await
            .map(|caller| caller.map(Terminator::Edge))
    } else {
        state
            .agents()
            .authenticate(&machine, &signed_at, &signature, &path, &bytes)
            .await
            .map(|caller| caller.map(Terminator::Machine))
    };
    let caller = match caller {
        Ok(Some(caller)) => caller,
        Ok(None) => {
            return refuse(ConnectError::unauthenticated(
                "sign the request with the relay's or the machine's key",
            ));
        }
        Err(error) => {
            tracing::warn!(error = %error, "terminator authentication failed");
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
        .add_service(Arc::new(relay_enrollment::RelayEnrollmentApi::new(
            state.clone(),
        )))
        .add_service(Arc::new(edge::EdgeEnrollmentApi::new(state.clone())))
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
    if let Some(authorization) = headers.get(header::AUTHORIZATION) {
        let token = authorization
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default()
            .trim()
            .to_string();
        let caller = match state.tokens().authenticate(&token).await {
            Ok(Some(caller)) => caller,
            Ok(None) => {
                return refuse(ConnectError::unauthenticated(
                    "the token is unknown, revoked or expired",
                ));
            }
            Err(error) => {
                tracing::warn!(error = %error, "token lookup failed for an API call");
                return refuse(ConnectError::unavailable(
                    "grund is temporarily unavailable",
                ));
            }
        };
        request.extensions_mut().insert(caller);
        return finish(next.run(request).await);
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
    finish(next.run(request).await)
}

fn finish(mut response: Response) -> Response {
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

/// Authorizes each call against [`AUTHORIZATION`], denying by default:
/// unary calls and streams alike, since connectrpc's default for a stream
/// is to let it through.
pub struct Authorize;

/// Whether the caller stamped on `ctx` meets what [`AUTHORIZATION`] asks of
/// the procedure it calls. A procedure with no entry is refused.
pub fn authorized(ctx: &connectrpc::RequestContext) -> Result<(), ConnectError> {
    let path = ctx.path().unwrap_or_default();
    let requirement = AUTHORIZATION
        .iter()
        .find(|(procedure, _)| *procedure == path)
        .map(|(_, r)| *r);
    let extensions = ctx.extensions();
    match requirement {
        Some(Requirement::Session) if extensions.get::<Caller>().is_some() => Ok(()),
        Some(Requirement::Session) if extensions.get::<TokenCaller>().is_some() => Err(
            ConnectError::permission_denied("an API token cannot call this; use the dashboard"),
        ),
        Some(Requirement::Session) => Err(ConnectError::unauthenticated("sign in first")),
        Some(Requirement::SessionOrToken)
            if extensions.get::<Caller>().is_some()
                || extensions.get::<TokenCaller>().is_some() =>
        {
            Ok(())
        }
        Some(Requirement::SessionOrToken) => Err(ConnectError::unauthenticated("sign in first")),
        Some(Requirement::Token) => Ok(()),
        Some(Requirement::Machine)
            if extensions
                .get::<crate::services::agents::MachineCaller>()
                .is_some() =>
        {
            Ok(())
        }
        Some(Requirement::Machine) => Err(ConnectError::unauthenticated(
            "sign the request with the machine key",
        )),
        Some(Requirement::Terminator)
            if extensions
                .get::<crate::services::terminators::Terminator>()
                .is_some() =>
        {
            Ok(())
        }
        Some(Requirement::Terminator) => Err(ConnectError::unauthenticated(
            "sign the request with the relay's or the machine's key",
        )),
        Some(Requirement::Edge) if extensions.get::<edge::EdgeCaller>().is_some() => Ok(()),
        Some(Requirement::Edge) => Err(ConnectError::unauthenticated(
            "sign the request with the edge's key",
        )),
        None => Err(ConnectError::permission_denied(
            "this procedure is not open to callers",
        )),
    }
}

#[connectrpc::async_trait]
impl Interceptor for Authorize {
    async fn intercept_unary(
        &self,
        request: UnaryRequest,
        next: InterceptNext<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        authorized(&request.ctx)?;
        next.run(request).await
    }

    async fn intercept_streaming(
        &self,
        request: connectrpc::interceptor::StreamRequest,
        inbound: connectrpc::interceptor::PayloadStream,
        next: connectrpc::interceptor::NextStream<'_>,
    ) -> Result<connectrpc::interceptor::StreamResponse, ConnectError> {
        authorized(&request.ctx)?;
        next.run(request, inbound).await
    }
}

/// The session caller [`authenticate`] stamped on the request.
pub fn caller(ctx: &connectrpc::RequestContext) -> Result<Caller, ConnectError> {
    ctx.extensions()
        .get::<Caller>()
        .copied()
        .ok_or_else(|| ConnectError::unauthenticated("sign in first"))
}

/// Who a call for a [`Requirement::SessionOrToken`] procedure acts as: an
/// account, and for a token the one organisation it may act on.
#[derive(Debug, Clone, Copy)]
pub struct Principal {
    pub account_id: Uuid,
    /// `Some` for a token: every other organisation is `not_found` to it.
    pub organisation_id: Option<Uuid>,
}

impl Principal {
    /// Whether this principal may act on `organisation_id` at all, before
    /// its account's role there is asked.
    pub fn reaches(&self, organisation_id: Uuid) -> bool {
        self.organisation_id
            .is_none_or(|own| own == organisation_id)
    }
}

/// The session or token caller [`authenticate`] stamped on the request.
pub fn principal(ctx: &connectrpc::RequestContext) -> Result<Principal, ConnectError> {
    let extensions = ctx.extensions();
    if let Some(caller) = extensions.get::<Caller>() {
        return Ok(Principal {
            account_id: caller.account_id,
            organisation_id: None,
        });
    }
    extensions
        .get::<TokenCaller>()
        .map(|token| Principal {
            account_id: token.account_id,
            organisation_id: Some(token.organisation_id),
        })
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

    use grund_proto::grund::{
        agent::v1 as agent, app::v1 as app_proto, certificates::v1 as certificates_proto,
        machine::v1 as machine, organisation::v1 as org,
    };

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
        async fn declare_machine_ports(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, machine::DeclareMachinePortsRequest>,
        ) -> ServiceResult<machine::DeclareMachinePortsResponse> {
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
        async fn watch_desired_state(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, agent::WatchDesiredStateRequest>,
        ) -> ServiceResult<agent::WatchDesiredStateResponse> {
            unreachable!()
        }
        async fn get_replica_secrets(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, agent::GetReplicaSecretsRequest>,
        ) -> ServiceResult<agent::GetReplicaSecretsResponse> {
            unreachable!()
        }
        async fn get_pull_credential(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, agent::GetPullCredentialRequest>,
        ) -> ServiceResult<agent::GetPullCredentialResponse> {
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
        async fn get_membership(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, agent::GetMembershipRequest>,
        ) -> ServiceResult<agent::GetMembershipResponse> {
            unreachable!()
        }
    }

    struct UnusedApps;

    #[allow(refining_impl_trait)]
    impl app_proto::AppService for UnusedApps {
        async fn create_app(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, app_proto::CreateAppRequest>,
        ) -> ServiceResult<app_proto::CreateAppResponse> {
            unreachable!()
        }
        async fn get_app(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, app_proto::GetAppRequest>,
        ) -> ServiceResult<app_proto::GetAppResponse> {
            unreachable!()
        }
        async fn list_apps(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, app_proto::ListAppsRequest>,
        ) -> ServiceResult<app_proto::ListAppsResponse> {
            unreachable!()
        }
        async fn deploy(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, app_proto::DeployRequest>,
        ) -> ServiceResult<app_proto::DeployResponse> {
            unreachable!()
        }
        async fn list_releases(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, app_proto::ListReleasesRequest>,
        ) -> ServiceResult<app_proto::ListReleasesResponse> {
            unreachable!()
        }
        async fn rollback(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, app_proto::RollbackRequest>,
        ) -> ServiceResult<app_proto::RollbackResponse> {
            unreachable!()
        }
        async fn scale(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, app_proto::ScaleRequest>,
        ) -> ServiceResult<app_proto::ScaleResponse> {
            unreachable!()
        }
        async fn configure_app(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, app_proto::ConfigureAppRequest>,
        ) -> ServiceResult<app_proto::ConfigureAppResponse> {
            unreachable!()
        }
        async fn set_secret(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, app_proto::SetSecretRequest>,
        ) -> ServiceResult<app_proto::SetSecretResponse> {
            unreachable!()
        }
        async fn delete_app(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, app_proto::DeleteAppRequest>,
        ) -> ServiceResult<app_proto::DeleteAppResponse> {
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

    struct UnusedRelayEnrollment;

    #[allow(refining_impl_trait)]
    impl grund_proto::grund::relay::v1::RelayEnrollmentService for UnusedRelayEnrollment {
        async fn enroll_relay(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, grund_proto::grund::relay::v1::EnrollRelayRequest>,
        ) -> ServiceResult<grund_proto::grund::relay::v1::EnrollRelayResponse> {
            unreachable!()
        }
    }

    struct UnusedEdges;
    struct UnusedEdgeEnrollment;

    #[allow(refining_impl_trait)]
    impl grund_proto::grund::edge::v1::EdgeEnrollmentService for UnusedEdgeEnrollment {
        async fn enroll_edge(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, grund_proto::grund::edge::v1::EnrollEdgeRequest>,
        ) -> ServiceResult<grund_proto::grund::edge::v1::EnrollEdgeResponse> {
            unreachable!()
        }
    }

    #[allow(refining_impl_trait)]
    impl grund_proto::grund::edge::v1::EdgeService for UnusedEdges {
        async fn watch_routes(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, grund_proto::grund::edge::v1::WatchRoutesRequest>,
        ) -> ServiceResult<grund_proto::grund::edge::v1::WatchRoutesResponse> {
            unreachable!()
        }
        async fn report_usage(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, grund_proto::grund::edge::v1::ReportUsageRequest>,
        ) -> ServiceResult<grund_proto::grund::edge::v1::ReportUsageResponse> {
            unreachable!()
        }
    }

    struct UnusedCertificates;

    #[allow(refining_impl_trait)]
    impl certificates_proto::CertificateService for UnusedCertificates {
        async fn request_certificate(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, certificates_proto::RequestCertificateRequest>,
        ) -> ServiceResult<certificates_proto::RequestCertificateResponse> {
            unreachable!()
        }
        async fn watch_challenges(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, certificates_proto::WatchChallengesRequest>,
        ) -> ServiceResult<connectrpc::ServiceStream<certificates_proto::WatchChallengesResponse>>
        {
            unreachable!()
        }
        async fn answer_challenge(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, certificates_proto::AnswerChallengeRequest>,
        ) -> ServiceResult<certificates_proto::AnswerChallengeResponse> {
            unreachable!()
        }
        async fn get_certificate(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, certificates_proto::GetCertificateRequest>,
        ) -> ServiceResult<certificates_proto::GetCertificateResponse> {
            unreachable!()
        }
    }

    fn context(path: &str, callers: &[&str]) -> RequestContext {
        let mut extensions = http::Extensions::new();
        for caller in callers {
            match *caller {
                "session" => {
                    extensions.insert(Caller {
                        account_id: Uuid::now_v7(),
                        session_id: Uuid::now_v7(),
                    });
                }
                "machine" => {
                    extensions.insert(crate::services::agents::MachineCaller {
                        machine_id: Uuid::now_v7(),
                        organisation_id: None,
                    });
                }
                "token" => {
                    extensions.insert(TokenCaller {
                        account_id: Uuid::now_v7(),
                        token_id: Uuid::now_v7(),
                        organisation_id: Uuid::now_v7(),
                    });
                }
                "edge" => {
                    extensions.insert(edge::EdgeCaller(crate::services::relays::RelayCaller {
                        relay_id: Uuid::now_v7(),
                        host: "edge-1.example.com".into(),
                    }));
                }
                _ => {
                    extensions.insert(crate::services::terminators::Terminator::Relay(
                        crate::services::relays::RelayCaller {
                            relay_id: Uuid::now_v7(),
                            host: "relay.example.com".into(),
                        },
                    ));
                }
            }
        }
        RequestContext::new(http::HeaderMap::new())
            .with_path(path)
            .with_extensions(extensions)
    }

    #[test]
    fn a_procedure_missing_from_the_table_is_refused_whoever_calls() {
        let everyone = ["session", "machine", "relay"];
        for path in [
            "/grund.certificates.v1.CertificateService/DeleteCertificate",
            "/grund.relay.v1.RelayService/Anything",
            "",
        ] {
            let error = authorized(&context(path, &everyone)).unwrap_err();
            assert_eq!(
                error.code,
                connectrpc::ErrorCode::PermissionDenied,
                "{path}"
            );
        }
    }

    #[test]
    fn a_token_reaches_the_app_procedures_ci_needs_and_nothing_else() {
        let for_tokens: BTreeSet<&str> = AUTHORIZATION
            .iter()
            .filter(|(_, r)| *r == Requirement::SessionOrToken)
            .map(|(p, _)| *p)
            .collect();
        let expected: BTreeSet<&str> = [
            "CreateApp",
            "GetApp",
            "ListApps",
            "Deploy",
            "ListReleases",
            "Rollback",
            "Scale",
            "ConfigureApp",
            "SetSecret",
        ]
        .into_iter()
        .map(|m| format!("/grund.app.v1.AppService/{m}").leak() as &str)
        .collect();
        assert_eq!(for_tokens, expected);
        for path in &for_tokens {
            authorized(&context(path, &["token"])).unwrap();
            authorized(&context(path, &["session"])).unwrap();
            let error = authorized(&context(path, &[])).unwrap_err();
            assert_eq!(error.code, connectrpc::ErrorCode::Unauthenticated, "{path}");
        }
    }

    #[test]
    fn a_token_is_refused_every_session_only_procedure() {
        let session_only: Vec<&str> = AUTHORIZATION
            .iter()
            .filter(|(_, r)| *r == Requirement::Session)
            .map(|(p, _)| *p)
            .collect();
        for required in [
            "/grund.app.v1.AppService/DeleteApp",
            "/grund.account.v1.AccountService/GetViewer",
            "/grund.organisation.v1.OrganisationService/InviteMember",
            "/grund.organisation.v1.OrganisationService/DeleteOrganisation",
            "/grund.machine.v1.MachineService/CreateJoinToken",
        ] {
            assert!(session_only.contains(&required), "{required}");
        }
        for path in session_only {
            let error = authorized(&context(path, &["token"])).unwrap_err();
            assert_eq!(
                error.code,
                connectrpc::ErrorCode::PermissionDenied,
                "{path}"
            );
            authorized(&context(path, &["session"])).unwrap();
        }
        for (path, requirement) in AUTHORIZATION {
            if matches!(
                requirement,
                Requirement::Machine | Requirement::Terminator | Requirement::Edge
            ) {
                let error = authorized(&context(path, &["token"])).unwrap_err();
                assert_eq!(error.code, connectrpc::ErrorCode::Unauthenticated, "{path}");
            }
        }
    }

    #[test]
    fn a_principal_reaches_only_its_tokens_organisation() {
        let own = Uuid::now_v7();
        let token = Principal {
            account_id: Uuid::now_v7(),
            organisation_id: Some(own),
        };
        assert!(token.reaches(own));
        assert!(!token.reaches(Uuid::now_v7()));
        let session = Principal {
            account_id: Uuid::now_v7(),
            organisation_id: None,
        };
        assert!(session.reaches(Uuid::now_v7()));
    }

    #[test]
    fn the_certificate_service_admits_only_a_terminator() {
        for procedure in [
            "RequestCertificate",
            "WatchChallenges",
            "AnswerChallenge",
            "GetCertificate",
        ] {
            let path = format!("/grund.certificates.v1.CertificateService/{procedure}");
            for callers in [&[][..], &["session"], &["machine"], &["session", "machine"]] {
                let error = authorized(&context(&path, callers)).unwrap_err();
                assert_eq!(
                    error.code,
                    connectrpc::ErrorCode::Unauthenticated,
                    "{path} {callers:?}"
                );
            }
            authorized(&context(&path, &["relay"])).unwrap();
        }
    }

    #[test]
    fn the_edge_service_admits_only_an_edge() {
        for procedure in ["WatchRoutes", "ReportUsage"] {
            let path = format!("/grund.edge.v1.EdgeService/{procedure}");
            for callers in [&[][..], &["session"], &["machine"], &["relay"]] {
                let error = authorized(&context(&path, callers)).unwrap_err();
                assert_eq!(
                    error.code,
                    connectrpc::ErrorCode::Unauthenticated,
                    "{path} {callers:?}"
                );
            }
            authorized(&context(&path, &["edge"])).unwrap();
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
            .add_service(Arc::new(UnusedRelayEnrollment))
            .add_service(Arc::new(UnusedEdges))
            .add_service(Arc::new(UnusedEdgeEnrollment))
            .add_service(Arc::new(UnusedCertificates))
            .add_service(Arc::new(UnusedAgent))
            .add_service(Arc::new(UnusedApps));
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
