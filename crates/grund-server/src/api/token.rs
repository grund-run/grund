//! `grund.token.v1.TokenService`: an organisation's personal access tokens
//! (grund-docs design/auth.md §6), the same as Organisation → API tokens.
//! Listing, making and revoking need a person's session; GetCurrentToken
//! is for a token describing itself.

use buffa::MessageField;
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_proto::grund::token::v1::{
    self as proto, CreateTokenRequest, CreateTokenResponse, ErrorReason, GetCurrentTokenRequest,
    GetCurrentTokenResponse, ListTokensRequest, ListTokensResponse, RevokeTokenRequest,
    RevokeTokenResponse, TokenService,
};
use grund_store::{api_tokens::TokenView, organisations::Membership};
use uuid::Uuid;

use crate::{
    api::{Caller, caller},
    services::{
        OrganisationsState,
        tokens::{
            CreateRefusal, LIFETIMES_DAYS, MAX_LIVE_PER_ORGANISATION, TokenCaller, TokenScope,
            TokensState,
        },
    },
    state::State,
};

/// The service implementation.
pub struct TokenApi {
    state: State,
}

impl TokenApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn member(&self, caller: &Caller, slug: &str) -> Result<Membership, ConnectError> {
        self.state
            .organisations()
            .membership(slug, caller.account_id)
            .await
            .map_err(internal)?
            .ok_or_else(|| ConnectError::not_found("no such organisation"))
    }
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "token API call failed");
    ConnectError::internal("grund could not finish that")
}

fn refusal(error: ConnectError, reason: &str) -> ConnectError {
    error.with_detail(ErrorDetail::from_message(
        "grund.token.v1.ErrorReason",
        &ErrorReason {
            reason: reason.to_string(),
            ..Default::default()
        },
    ))
}

fn timestamp<P: buffa::ProtoBox<Timestamp>>(at: DateTime<Utc>) -> MessageField<Timestamp, P> {
    Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into()
}

fn scope_message(scope: TokenScope) -> proto::TokenScope {
    match scope {
        TokenScope::Deploy => proto::TokenScope::TOKEN_SCOPE_DEPLOY,
        TokenScope::Full => proto::TokenScope::TOKEN_SCOPE_FULL,
    }
}

fn token_message(view: TokenView) -> proto::Token {
    proto::Token {
        token_id: view.token_id.to_string(),
        name: view.name,
        scope: scope_message(TokenScope::parse(&view.scope)).into(),
        created_by: view.username.unwrap_or_default(),
        created_at: timestamp(view.created_at),
        expires_at: timestamp(view.expires_at),
        last_used_at: view.last_used_at.map(timestamp).unwrap_or_default(),
        ..Default::default()
    }
}

#[allow(refining_impl_trait)]
impl TokenService for TokenApi {
    async fn list_tokens(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListTokensRequest>,
    ) -> ServiceResult<ListTokensResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.organisation).await?;
        let tokens = self
            .state
            .tokens()
            .list(caller.account_id, &membership)
            .await
            .map_err(internal)?;
        Response::ok(ListTokensResponse {
            tokens: tokens.into_iter().map(token_message).collect(),
            ..Default::default()
        })
    }

    async fn create_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateTokenRequest>,
    ) -> ServiceResult<CreateTokenResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.organisation).await?;
        let days = if request.lifetime_days == 0 {
            LIFETIMES_DAYS[0]
        } else {
            request.lifetime_days
        };
        if !LIFETIMES_DAYS.contains(&days) {
            return Err(refusal(
                ConnectError::invalid_argument("lifetime_days is 7, 30, 90 or 365"),
                "lifetime_invalid",
            ));
        }
        let scope = match request.scope.as_known() {
            Some(proto::TokenScope::TOKEN_SCOPE_FULL) => TokenScope::Full,
            _ => TokenScope::Deploy,
        };
        let minted = match self
            .state
            .tokens()
            .create(caller.account_id, &membership, request.name, days, scope)
            .await
            .map_err(internal)?
        {
            Ok(minted) => minted,
            Err(CreateRefusal::Invalid(problem)) => {
                return Err(refusal(
                    ConnectError::invalid_argument(problem),
                    "name_invalid",
                ));
            }
            Err(CreateRefusal::TooMany) => {
                return Err(refusal(
                    ConnectError::failed_precondition(format!(
                        "this organisation has {MAX_LIVE_PER_ORGANISATION} live tokens; revoke some first"
                    )),
                    "token_limit",
                ));
            }
        };
        let view = self
            .state
            .tokens()
            .get(membership.organisation_id, minted.token_id)
            .await
            .map_err(internal)?
            .ok_or_else(|| internal("a token just made is not found"))?;
        Response::ok(CreateTokenResponse {
            token: MessageField::from(token_message(view)),
            secret: minted.token,
            ..Default::default()
        })
    }

    async fn revoke_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeTokenRequest>,
    ) -> ServiceResult<RevokeTokenResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.organisation).await?;
        let token_id = Uuid::parse_str(request.token_id)
            .map_err(|_| ConnectError::not_found("no such token"))?;
        if !self
            .state
            .tokens()
            .revoke(caller.account_id, &membership, token_id)
            .await
            .map_err(internal)?
        {
            return Err(ConnectError::not_found("no such token"));
        }
        Response::ok(RevokeTokenResponse::default())
    }

    async fn get_current_token(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetCurrentTokenRequest>,
    ) -> ServiceResult<GetCurrentTokenResponse> {
        let Some(token) = ctx.extensions().get::<TokenCaller>().copied() else {
            return Err(refusal(
                ConnectError::failed_precondition("this call presents a session, not a token"),
                "not_a_token",
            ));
        };
        let view = self
            .state
            .tokens()
            .get(token.organisation_id, token.token_id)
            .await
            .map_err(internal)?
            .ok_or_else(|| {
                ConnectError::unauthenticated("the token is unknown, revoked or expired")
            })?;
        let organisation = self
            .state
            .organisations()
            .memberships_of(token.account_id)
            .await
            .map_err(internal)?
            .into_iter()
            .find(|m| m.organisation_id == token.organisation_id)
            .map(|m| m.slug)
            .ok_or_else(|| ConnectError::not_found("the token's maker left its organisation"))?;
        Response::ok(GetCurrentTokenResponse {
            token: MessageField::from(token_message(view)),
            organisation,
            ..Default::default()
        })
    }
}
