//! `/device`: where a signed-in person approves `grund login` (grund-docs
//! design/cli.md §2). It shows the code, the client and the computer that
//! asked, and approves or denies with the browser session; a token or a
//! CLI session cannot reach it.

use axum::{
    Form,
    extract::{Query, State as AxumState},
    http::{StatusCode, Uri},
};
use minijinja::context;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::{
        device_logins::{DeviceLoginsState, display_user_code, normalize_user_code},
        sessions::Session,
    },
    state::State,
    web::{
        browser::Browser,
        pages::{PageResult, forged, require_session, signed_in},
    },
};

#[derive(Deserialize)]
pub struct DeviceQuery {
    #[serde(default)]
    code: String,
}

#[derive(Default)]
struct DeviceView {
    code: String,
    code_error: String,
    notice: &'static str,
    error: &'static str,
    done: bool,
}

async fn device_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    status: StatusCode,
    view: DeviceView,
) -> PageResult {
    let mut code_error = view.code_error;
    let mut login = None;
    if !view.done && !view.code.trim().is_empty() {
        match state.device_logins().pending(&view.code).await? {
            Some(pending) => {
                login = Some(context! {
                    id => pending.login_id.to_string(),
                    code => display_user_code(&pending.user_code),
                    client => pending.client,
                    host => pending.host,
                    address => pending.client_address,
                    created => pending.created_at.format("%-d %b %Y, %H:%M:%S UTC").to_string(),
                });
            }
            None if normalize_user_code(&view.code).is_none() => {
                code_error = "A code is eight letters, such as BCDF-GHJK.".into();
            }
            None => {
                code_error =
                    "No login is waiting with that code. It may have expired; run grund login again."
                        .into();
            }
        }
    }
    let username = crate::services::AccountsState::accounts(state)
        .viewer(session.account_id)
        .await?
        .map(|v| v.username)
        .unwrap_or_default();
    signed_in(
        state,
        browser,
        session,
        None,
        status,
        "pages/device.html.jinja",
        "settings",
        context! {
            login, username, code_error,
            code => view.code,
            done => view.done,
            notice => view.notice,
            error => view.error,
        },
    )
    .await
}

/// `GET /device`, with `?code=` from the CLI's link or typed in.
pub async fn device_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Query(query): Query<DeviceQuery>,
) -> PageResult {
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(redirect) => return Ok(*redirect),
    };
    device_view(
        &state,
        &browser,
        &session,
        StatusCode::OK,
        DeviceView {
            code: query.code,
            ..Default::default()
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct DecisionForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    login: String,
    #[serde(default)]
    decision: String,
}

/// `POST /device`: approves or denies one pending login.
pub async fn decide(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Form(form): Form<DecisionForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(redirect) => return Ok(*redirect),
    };
    let login_id = Uuid::parse_str(&form.login).ok();
    let logins = state.device_logins();
    let decided = match (login_id, form.decision.as_str()) {
        (Some(id), "approve") => logins.approve(id, session.account_id).await?,
        (Some(id), "deny") => logins.deny(id).await?,
        _ => false,
    };
    let view = match (decided, form.decision.as_str()) {
        (true, "approve") => DeviceView {
            notice: "Approved. Return to your terminal: it signs in within seconds.",
            done: true,
            ..Default::default()
        },
        (true, _) => DeviceView {
            notice: "Denied. The terminal is told so and is not signed in.",
            done: true,
            ..Default::default()
        },
        (false, _) => DeviceView {
            error: "That login is no longer waiting: it was approved, denied or expired.",
            ..Default::default()
        },
    };
    let status = if decided {
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    };
    device_view(&state, &browser, &session, status, view).await
}
