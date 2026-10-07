//! `grund.login.v1.DeviceLoginService`: signing the CLI in through the
//! browser (grund-docs design/cli.md §2). Not behind the session: these
//! calls take no credential, and StartDeviceLogin counts against the
//! client address's sign-in attempts.

use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_proto::grund::login::v1::{
    DeviceLoginService, DeviceLoginState, ErrorReason, PollDeviceLoginRequest,
    PollDeviceLoginResponse, StartDeviceLoginRequest, StartDeviceLoginResponse,
};

use crate::{
    api::ClientAddress,
    services::{
        AccountsState, LimitsState,
        device_logins::{DeviceLoginsState, INTERVAL, Polled, TTL},
    },
    state::State,
};

/// The service implementation.
pub struct LoginApi {
    state: State,
}

impl LoginApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

fn refusal(error: ConnectError, reason: &str) -> ConnectError {
    error.with_detail(ErrorDetail::from_message(
        "grund.login.v1.ErrorReason",
        &ErrorReason {
            reason: reason.to_string(),
            ..Default::default()
        },
    ))
}

fn unavailable(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "device login failed");
    ConnectError::unavailable("grund could not answer; try again")
}

fn address(ctx: &RequestContext) -> String {
    ctx.extensions()
        .get::<ClientAddress>()
        .map(|a| a.0.clone())
        .unwrap_or_default()
}

#[allow(refining_impl_trait)]
impl DeviceLoginService for LoginApi {
    async fn start_device_login(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, StartDeviceLoginRequest>,
    ) -> ServiceResult<StartDeviceLoginResponse> {
        let address = address(&ctx);
        if !self
            .state
            .limits()
            .admit_login_address(&address)
            .await
            .map_err(unavailable)?
        {
            return Err(refusal(
                ConnectError::resource_exhausted("too many sign-in attempts; wait 15 minutes"),
                "rate_limited",
            ));
        }
        let started = self
            .state
            .device_logins()
            .start(request.client, request.host, &address)
            .await
            .map_err(unavailable)?;
        let verification_uri = format!("{}/device", self.state.config.public_origin().serialized);
        Response::ok(StartDeviceLoginResponse {
            verification_uri_complete: format!("{verification_uri}?code={}", started.user_code),
            verification_uri,
            device_code: started.device_code,
            user_code: started.user_code,
            expires_in_seconds: TTL.as_secs() as u32,
            interval_seconds: INTERVAL.as_secs() as u32,
            ..Default::default()
        })
    }

    async fn poll_device_login(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PollDeviceLoginRequest>,
    ) -> ServiceResult<PollDeviceLoginResponse> {
        let polled = self
            .state
            .device_logins()
            .poll(request.device_code, &address(&ctx))
            .await
            .map_err(unavailable)?;
        let state = match polled {
            Polled::NotFound => {
                return Err(refusal(
                    ConnectError::not_found("no such login; start again with grund login"),
                    "login_not_found",
                ));
            }
            Polled::SlowDown => {
                return Err(refusal(
                    ConnectError::resource_exhausted(format!(
                        "poll at most every {} seconds",
                        INTERVAL.as_secs()
                    )),
                    "slow_down",
                ));
            }
            Polled::Pending => DeviceLoginState::DEVICE_LOGIN_STATE_PENDING,
            Polled::Denied => DeviceLoginState::DEVICE_LOGIN_STATE_DENIED,
            Polled::Expired => DeviceLoginState::DEVICE_LOGIN_STATE_EXPIRED,
            Polled::Approved { token, account_id } => {
                let username = self
                    .state
                    .accounts()
                    .viewer(account_id)
                    .await
                    .map_err(unavailable)?
                    .map(|viewer| viewer.username)
                    .unwrap_or_default();
                return Response::ok(PollDeviceLoginResponse {
                    state: DeviceLoginState::DEVICE_LOGIN_STATE_APPROVED.into(),
                    session_token: token,
                    username,
                    ..Default::default()
                });
            }
        };
        Response::ok(PollDeviceLoginResponse {
            state: state.into(),
            ..Default::default()
        })
    }
}
