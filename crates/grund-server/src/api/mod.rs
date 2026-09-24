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
//! for the CLI) are designed in docs/design/auth.md §6 and not built; a call
//! presenting one is refused as unauthenticated.

pub mod account;

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
use grund_proto::grund::account::v1::ACCOUNT_SERVICE_SERVICE_NAME;
use uuid::Uuid;

use crate::{
    services::sessions::SessionsState,
    state::State,
    web::browser::{CookieJar, cookie, same_origin},
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

/// What a procedure requires of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Any signed-in person, acting on their own account.
    Session,
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
            service,
        )
        .layer(middleware::from_fn_with_state(state, authenticate))
}

/// The Connect router with every service registered.
pub fn connect_router(state: State) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(account::AccountApi::new(state)))
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

    #[test]
    fn every_procedure_has_an_authorization_entry() {
        let router = connectrpc::Router::new().add_service(Arc::new(Unused));
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
