//! `grund.account.v1.AccountService`: the caller's own account and sessions.

use buffa::{EnumValue, MessageField};
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_proto::grund::account::v1::{
    AccountService, GetViewerRequest, GetViewerResponse, ListSessionsRequest, ListSessionsResponse,
    Membership, RevokeSessionRequest, RevokeSessionResponse, Role, Session, Viewer,
};
use uuid::Uuid;

use crate::{
    api::caller,
    services::{accounts::AccountsState, sessions::SessionsState},
    state::State,
};

/// The service implementation.
pub struct AccountApi {
    state: State,
}

impl AccountApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

fn timestamp<P: buffa::ProtoBox<Timestamp>>(at: DateTime<Utc>) -> MessageField<Timestamp, P> {
    Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into()
}

fn role(role: &str) -> EnumValue<Role> {
    match role {
        "owner" => Role::ROLE_OWNER,
        "admin" => Role::ROLE_ADMIN,
        "member" => Role::ROLE_MEMBER,
        _ => Role::ROLE_UNSPECIFIED,
    }
    .into()
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "account API call failed");
    ConnectError::internal("grund could not finish that")
}

#[allow(refining_impl_trait)]
impl AccountService for AccountApi {
    async fn get_viewer(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetViewerRequest>,
    ) -> ServiceResult<GetViewerResponse> {
        let caller = caller(&ctx)?;
        let viewer = self
            .state
            .accounts()
            .viewer(caller.account_id)
            .await
            .map_err(internal)?
            .ok_or_else(|| ConnectError::unauthenticated("sign in first"))?;
        Response::ok(GetViewerResponse {
            viewer: MessageField::from(Viewer {
                account_id: viewer.account_id.to_string(),
                username: viewer.username,
                email: viewer.email,
                registered_at: timestamp(viewer.registered_at),
                memberships: viewer
                    .memberships
                    .into_iter()
                    .map(|m| Membership {
                        organisation_id: m.organisation_id.to_string(),
                        organisation_slug: m.slug,
                        role: role(&m.role),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    async fn list_sessions(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListSessionsRequest>,
    ) -> ServiceResult<ListSessionsResponse> {
        let caller = caller(&ctx)?;
        let sessions = self
            .state
            .sessions()
            .list(caller.account_id)
            .await
            .map_err(internal)?;
        Response::ok(ListSessionsResponse {
            sessions: sessions
                .into_iter()
                .map(|s| Session {
                    current: s.session_id == caller.session_id,
                    session_id: s.session_id.to_string(),
                    created_at: timestamp(s.created_at),
                    last_seen_at: timestamp(s.last_seen_at),
                    user_agent: s.user_agent,
                    client_address: s.client_address,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn revoke_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeSessionRequest>,
    ) -> ServiceResult<RevokeSessionResponse> {
        let caller = caller(&ctx)?;
        let session_id = Uuid::parse_str(request.session_id)
            .map_err(|_| ConnectError::invalid_argument("session_id must be a UUID"))?;
        let revoked = self
            .state
            .sessions()
            .revoke(caller.account_id, session_id)
            .await
            .map_err(internal)?;
        if !revoked {
            return Err(ConnectError::not_found("no such session"));
        }
        Response::ok(RevokeSessionResponse::default())
    }
}
