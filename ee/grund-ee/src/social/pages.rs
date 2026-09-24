//! Social sign-in pages. Every one of them asks
//! [`grund_server::services::entitlements::Entitlements`] first, and refuses with a
//! 403 page when the license does not include social sign-in.

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use minijinja::context;
use serde::Deserialize;

use std::sync::Arc;

use axum::Extension;
use grund_server::{
    license::Feature,
    services::{entitlements::EntitlementsState, sessions::SessionsState},
    state::State,
    web::{
        browser::{Browser, CookieJar, cookie},
        pages::{PageError, forged, message, redirect, render},
    },
};

use super::{
    SocialLogin,
    flows::{CallbackOutcome, CompleteOutcome, LinkOutcome, Provider},
};

type PageResult = Result<Response, PageError>;

fn flow_cookie_name(jar: &CookieJar) -> &'static str {
    if jar.session_name().starts_with("__Host-") {
        "__Host-grund_oauth"
    } else {
        "grund_oauth"
    }
}

fn gate(
    ee: &SocialLogin,
    state: &State,
    browser: &Browser,
    provider: Option<&str>,
) -> Result<Option<Provider>, Box<PageResult>> {
    if let Err(refusal) = state.entitlements().allows(Feature::SocialLogin) {
        tracing::debug!(%refusal, "social sign-in refused");
        return Err(Box::new(message(
            state,
            browser,
            StatusCode::FORBIDDEN,
            "Social sign-in needs a grund license",
            "This instance offers sign-in with a password only.",
            Some(("/login", "Sign in with a password")),
        )));
    }
    let Some(id) = provider else {
        return Ok(None);
    };
    match ee.flows(state).provider(id) {
        Some(provider) => Ok(Some(provider)),
        None => Err(Box::new(message(
            state,
            browser,
            StatusCode::NOT_FOUND,
            "Not available",
            "This instance does not offer that way to sign in.",
            Some(("/login", "Sign in")),
        ))),
    }
}

fn flow_cookie(browser: &Browser, parts: &axum::http::HeaderMap) -> Option<String> {
    cookie(parts, flow_cookie_name(browser.jar())).filter(|t| t.len() == 43)
}

pub async fn start(
    Extension(ee): Extension<Arc<SocialLogin>>,
    AxumState(state): AxumState<State>,
    browser: Browser,
    Path(provider): Path<String>,
) -> PageResult {
    let provider = match gate(&ee, &state, &browser, Some(&provider)) {
        Ok(Some(provider)) => provider,
        Ok(None) => unreachable!("a provider id was given"),
        Err(page) => return *page,
    };
    let (token, location) = ee.flows(&state).start(&provider).await?;
    let mut response = redirect(&location);
    let jar = browser.jar();
    response.headers_mut().append(
        header::SET_COOKIE,
        jar.set(flow_cookie_name(jar), &token, 600),
    );
    Ok(response)
}

#[derive(Deserialize, Default)]
pub struct CallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
}

pub async fn callback(
    Extension(ee): Extension<Arc<SocialLogin>>,
    AxumState(state): AxumState<State>,
    browser: Browser,
    headers: axum::http::HeaderMap,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> PageResult {
    let provider = match gate(&ee, &state, &browser, Some(&provider)) {
        Ok(Some(provider)) => provider,
        Ok(None) => unreachable!("a provider id was given"),
        Err(page) => return *page,
    };
    let Some(flow) = flow_cookie(&browser, &headers) else {
        return message(
            &state,
            &browser,
            StatusCode::BAD_REQUEST,
            "This sign-in has expired",
            "Start again from the sign-in page.",
            Some(("/login", "Sign in")),
        );
    };
    match ee
        .flows(&state)
        .callback(&provider, &flow, &query.state, &query.code, &browser.meta())
        .await?
    {
        CallbackOutcome::SignIn(account_id) => signed_in(&state, &browser, account_id).await,
        CallbackOutcome::ChooseUsername => Ok(redirect("/auth/complete")),
        CallbackOutcome::Link { .. } => Ok(redirect("/auth/link")),
        CallbackOutcome::Refused(text) => message(
            &state,
            &browser,
            StatusCode::FORBIDDEN,
            "Sign-in did not complete",
            text,
            Some(("/login", "Back to sign in")),
        ),
    }
}

async fn signed_in(state: &State, browser: &Browser, account_id: uuid::Uuid) -> PageResult {
    let (token, _) = state
        .sessions()
        .start(
            account_id,
            browser.session_token.as_deref(),
            &browser.client(),
        )
        .await?;
    let mut response = redirect("/");
    let jar = browser.jar();
    let headers = response.headers_mut();
    headers.append(
        header::SET_COOKIE,
        jar.set(
            jar.session_name(),
            &token,
            state.sessions().max_age().as_secs(),
        ),
    );
    headers.append(header::SET_COOKIE, jar.set(flow_cookie_name(jar), "", 0));
    headers.append(header::SET_COOKIE, jar.set(jar.csrf_name(), "", 0));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn provider_name(ee: &SocialLogin, state: &State, id: &str) -> String {
    ee.flows(state)
        .provider(id)
        .map(|p| p.name)
        .unwrap_or_else(|| id.to_string())
}

pub async fn complete_form(
    Extension(ee): Extension<Arc<SocialLogin>>,
    AxumState(state): AxumState<State>,
    browser: Browser,
    headers: axum::http::HeaderMap,
) -> PageResult {
    if let Err(page) = gate(&ee, &state, &browser, None) {
        return *page;
    }
    let pending = match flow_cookie(&browser, &headers) {
        Some(flow) => ee.flows(&state).pending(&flow, "choose_username").await?,
        None => None,
    };
    let Some(pending) = pending else {
        return Ok(redirect("/login"));
    };
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/social-username.html.jinja",
        context! {
            csrf => browser.csrf_token(), provider => provider_name(&ee, &state, &pending.provider), email => pending.email,
            username => pending.suggested_name.unwrap_or_default(), error => "",
        },
    )
}

#[derive(Deserialize)]
pub struct CompleteFields {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    username: String,
}

pub async fn complete(
    Extension(ee): Extension<Arc<SocialLogin>>,
    AxumState(state): AxumState<State>,
    browser: Browser,
    headers: axum::http::HeaderMap,
    Form(form): Form<CompleteFields>,
) -> PageResult {
    if let Err(page) = gate(&ee, &state, &browser, None) {
        return *page;
    }
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let Some(flow) = flow_cookie(&browser, &headers) else {
        return Ok(redirect("/login"));
    };
    let pending = ee.flows(&state).pending(&flow, "choose_username").await?;
    match ee
        .flows(&state)
        .complete_signup(&flow, &form.username, &browser.meta())
        .await?
    {
        CompleteOutcome::SignIn(account_id) => signed_in(&state, &browser, account_id).await,
        CompleteOutcome::Invalid(error) => {
            let Some(pending) = pending else {
                return Ok(redirect("/login"));
            };
            render(
                &state,
                &browser,
                StatusCode::UNPROCESSABLE_ENTITY,
                "pages/social-username.html.jinja",
                context! {
                    csrf => browser.csrf_token(), provider => provider_name(&ee, &state, &pending.provider), email => pending.email,
                    username => form.username, error,
                },
            )
        }
        CompleteOutcome::Expired => message(
            &state,
            &browser,
            StatusCode::GONE,
            "This sign-in has expired",
            "Start again from the sign-in page.",
            Some(("/login", "Sign in")),
        ),
    }
}

pub async fn link_form(
    Extension(ee): Extension<Arc<SocialLogin>>,
    AxumState(state): AxumState<State>,
    browser: Browser,
    headers: axum::http::HeaderMap,
) -> PageResult {
    if let Err(page) = gate(&ee, &state, &browser, None) {
        return *page;
    }
    let pending = match flow_cookie(&browser, &headers) {
        Some(flow) => ee.flows(&state).pending(&flow, "link").await?,
        None => None,
    };
    let Some(pending) = pending else {
        return Ok(redirect("/login"));
    };
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/social-link.html.jinja",
        context! {
            csrf => browser.csrf_token(), provider => provider_name(&ee, &state, &pending.provider), email => pending.email, error => "",
        },
    )
}

#[derive(Deserialize)]
pub struct LinkFields {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    password: String,
}

pub async fn link(
    Extension(ee): Extension<Arc<SocialLogin>>,
    AxumState(state): AxumState<State>,
    browser: Browser,
    headers: axum::http::HeaderMap,
    Form(form): Form<LinkFields>,
) -> PageResult {
    if let Err(page) = gate(&ee, &state, &browser, None) {
        return *page;
    }
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let Some(flow) = flow_cookie(&browser, &headers) else {
        return Ok(redirect("/login"));
    };
    let pending = ee.flows(&state).pending(&flow, "link").await?;
    let error = match ee
        .flows(&state)
        .link(&flow, &form.password, &browser.meta())
        .await?
    {
        LinkOutcome::SignIn(account_id) => return signed_in(&state, &browser, account_id).await,
        LinkOutcome::WrongPassword => "That password is not right.",
        LinkOutcome::Locked => "Too many attempts for this account. Try again in 15 minutes.",
        LinkOutcome::Expired => {
            return message(
                &state,
                &browser,
                StatusCode::GONE,
                "This sign-in has expired",
                "Start again from the sign-in page.",
                Some(("/login", "Sign in")),
            );
        }
    };
    let Some(pending) = pending else {
        return Ok(redirect("/login"));
    };
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/social-link.html.jinja",
        context! {
            csrf => browser.csrf_token(), provider => provider_name(&ee, &state, &pending.provider), email => pending.email, error,
        },
    )
}
