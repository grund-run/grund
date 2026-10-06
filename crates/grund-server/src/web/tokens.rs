//! `/{org}/settings/tokens`: an organisation's personal access tokens for
//! the API (grund-docs design/auth.md §6). Any member makes tokens, which
//! act as them in this organisation only; owners and admins see and revoke
//! every token of the organisation, members only their own. A new token is
//! shown once, on the page its form answers with, and never again.

use axum::{
    Form,
    extract::{Path, State as AxumState},
    http::{StatusCode, Uri},
    response::Response,
};
use grund_store::organisations::Membership;
use minijinja::{Value, context};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::{
        sessions::Session,
        tokens::{CreateRefusal, LIFETIMES_DAYS, MAX_LIVE_PER_ORGANISATION, Minted, TokensState},
    },
    state::State,
    web::{
        browser::Browser,
        orgs::member_of,
        pages::{PageError, forged, redirect, render, viewer_context},
    },
};

type PageResult = Result<Response, PageError>;

macro_rules! member_or_return {
    ($state:expr, $browser:expr, $uri:expr, $slug:expr) => {
        match member_of($state, $browser, $uri, $slug).await {
            Ok(found) => found,
            Err(response) => return Ok(*response),
        }
    };
}

#[derive(Default, Deserialize)]
pub struct NoticeQuery {
    #[serde(default)]
    done: String,
    #[serde(default)]
    error: String,
}

/// `GET /{org}/settings/tokens`.
pub async fn tokens_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    axum::extract::Query(query): axum::extract::Query<NoticeQuery>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let notice = match query.done.as_str() {
        "revoked" => "Token revoked. Calls with it are refused from now on.",
        _ => "",
    };
    let error = match query.error.as_str() {
        "gone" => "That token is no longer there.",
        _ => "",
    };
    tokens_view(
        &state,
        &browser,
        &session,
        &membership,
        StatusCode::OK,
        TokensForm {
            notice,
            error,
            ..Default::default()
        },
    )
    .await
}

#[derive(Default)]
struct TokensForm<'a> {
    notice: &'a str,
    error: &'a str,
    create_error: String,
    name: String,
    days: u32,
    minted: Option<Minted>,
}

async fn tokens_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    status: StatusCode,
    form: TokensForm<'_>,
) -> PageResult {
    let tokens: Vec<Value> = state
        .tokens()
        .list(session.account_id, membership)
        .await?
        .into_iter()
        .map(|t| {
            let used = t
                .last_used_at
                .map(|at| format!("last used {}", at.format("%-d %b %Y %H:%M UTC")))
                .unwrap_or_else(|| "never used".into());
            context! {
                id => t.token_id.to_string(),
                name => t.name,
                by => t.username.unwrap_or_default(),
                mine => t.account_id == session.account_id,
                created => t.created_at.format("%-d %b %Y").to_string(),
                expires => t.expires_at.format("%-d %b %Y").to_string(),
                used,
            }
        })
        .collect();
    let lifetimes: Vec<(String, String)> = LIFETIMES_DAYS
        .iter()
        .map(|d| (d.to_string(), format!("{d} days")))
        .collect();
    let days = if form.days == 0 {
        LIFETIMES_DAYS[0]
    } else {
        form.days
    };
    let origin = state.config.public_origin().serialized;
    let minted = form.minted.map(|m| {
        let example = format!(
            "curl -sS -H \"Authorization: Bearer $GRUND_TOKEN\" -H 'Content-Type: application/json' \
             -d '{{\"organisation\":\"{slug}\",\"name\":\"APP\",\"spec\":{{\"image\":\"IMAGE\"}}}}' \
             {origin}/grund.app.v1.AppService/Deploy",
            slug = membership.slug,
        );
        context! {
            token => m.token,
            name => m.name,
            expires => m.expires_at.format("%-d %b %Y").to_string(),
            example,
        }
    });
    let viewer = viewer_context(state, session, Some(membership)).await?;
    render(
        state,
        browser,
        status,
        "pages/tokens.html.jinja",
        context! {
            viewer, tokens, lifetimes, minted,
            days => days.to_string(),
            name => form.name,
            max_live => MAX_LIVE_PER_ORGANISATION,
            notice => form.notice, error => form.error,
            create_error => form.create_error,
            csrf => browser.csrf_token(), section => "org-settings",
        },
    )
}

#[derive(Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    days: String,
}

/// `POST /{org}/settings/tokens`: makes a token and answers with the page
/// that shows it, once.
pub async fn create(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<CreateForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let days = form.days.trim().parse::<u32>().unwrap_or(0);
    let outcome = state
        .tokens()
        .create(session.account_id, &membership, &form.name, days)
        .await?;
    let (status, form) = match outcome {
        Ok(minted) => (
            StatusCode::OK,
            TokensForm {
                notice: "Token created. Copy it now: this is the only time grund shows it.",
                minted: Some(minted),
                ..Default::default()
            },
        ),
        Err(CreateRefusal::Invalid(problem)) => (
            StatusCode::OK,
            TokensForm {
                create_error: problem,
                name: form.name,
                days,
                ..Default::default()
            },
        ),
        Err(CreateRefusal::TooMany) => (
            StatusCode::OK,
            TokensForm {
                create_error: format!(
                    "This organisation has {MAX_LIVE_PER_ORGANISATION} live tokens. Revoke some first."
                ),
                name: form.name,
                days,
                ..Default::default()
            },
        ),
    };
    tokens_view(&state, &browser, &session, &membership, status, form).await
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /{org}/settings/tokens/{token}/revoke`.
pub async fn revoke(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, token_id)): Path<(String, Uuid)>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let revoked = state
        .tokens()
        .revoke(session.account_id, &membership, token_id)
        .await?;
    let query = if revoked {
        "done=revoked"
    } else {
        "error=gone"
    };
    Ok(redirect(&format!("/{slug}/settings/tokens?{query}")))
}
