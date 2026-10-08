//! `/{org}/settings/tokens`: an organisation's personal access tokens for
//! the API (grund-docs design/auth.md §6). Any member makes tokens, which
//! act as them in this organisation only; owners and admins see and revoke
//! every token of the organisation, members only their own. A new token is
//! shown once, on the page its form answers with, and never again.

use axum::{
    Form,
    extract::{Path, State as AxumState},
    http::{StatusCode, Uri},
};
use grund_store::organisations::Membership;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::{
        sessions::Session,
        tokens::{
            CreateRefusal, LIFETIMES_DAYS, MAX_LIVE_PER_ORGANISATION, Minted, TokenScope,
            TokensState,
        },
    },
    state::State,
    web::{
        browser::Browser,
        orgs::Member,
        pages::{Notice, PageResult, forged, redirect},
    },
};

pub struct TokenRow {
    pub id: String,
    pub name: String,
    pub by: String,
    pub mine: bool,
    pub created: String,
    pub expires: String,
    pub scope: &'static str,
    pub used: String,
}

pub struct MintedToken {
    pub token: String,
    pub name: String,
    pub expires: String,
    pub example: String,
}

pub struct TokensPage<'a> {
    pub viewer: &'a super::pages::TypedViewer,
    pub csrf: &'a str,
    pub tokens: Vec<TokenRow>,
    pub lifetimes: Vec<(u32, String)>,
    pub minted: Option<MintedToken>,
    pub scopes: &'static [(&'static str, &'static str)],
    pub days: u32,
    pub scope: &'static str,
    pub name: String,
    pub notice: &'a str,
    pub error: &'a str,
    pub create_error: String,
}

/// `GET /{org}/settings/tokens`.
pub async fn tokens_page(
    AxumState(state): AxumState<State>,
    member: Member,
    axum::extract::Query(query): axum::extract::Query<Notice>,
) -> PageResult {
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
        &member.browser,
        &member.session,
        &member.membership,
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
    scope: String,
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
    let tokens: Vec<TokenRow> = state
        .tokens()
        .list(session.account_id, membership)
        .await?
        .into_iter()
        .map(|t| {
            let used = t
                .last_used_at
                .map(|at| format!("last used {}", at.format("%-d %b %Y %H:%M UTC")))
                .unwrap_or_else(|| "never used".into());
            TokenRow {
                id: t.token_id.to_string(),
                name: t.name,
                by: t.username.unwrap_or_default(),
                mine: t.account_id == session.account_id,
                created: t.created_at.format("%-d %b %Y").to_string(),
                expires: t.expires_at.format("%-d %b %Y").to_string(),
                scope: if TokenScope::parse(&t.scope) == TokenScope::Full {
                    "Full"
                } else {
                    "Deploy"
                },
                used,
            }
        })
        .collect();
    let mut lifetimes: Vec<(u32, String)> = LIFETIMES_DAYS
        .iter()
        .map(|&d| (d, format!("{d} days")))
        .collect();
    lifetimes.sort_unstable_by_key(|(days, _)| *days);
    let days = if form.days == 0 {
        LIFETIMES_DAYS[0]
    } else {
        form.days
    };
    let scopes = &[
        ("deploy", "Deploy: create, deploy and change apps"),
        ("full", "Full: everything your role allows here"),
    ];
    let scope = if form.scope == "full" {
        "full"
    } else {
        "deploy"
    };
    let origin = state.config.public_origin().serialized;
    let minted = form.minted.map(|m| {
        let example = format!(
            "GRUND_INSTANCE={origin} GRUND_TOKEN=<the token> grund apps deploy APP -f grund.yaml --json"
        );
        MintedToken {
            token: m.token,
            name: m.name,
            expires: m.expires_at.format("%-d %b %Y").to_string(),
            example,
        }
    });
    super::pages::signed_in_typed(
        state,
        browser,
        session,
        Some(membership),
        status,
        "API tokens",
        "org-settings",
        None,
        None,
        None,
        |viewer, csrf| {
            crate::templates::compiled::pages::tokens::render(&TokensPage {
                viewer,
                csrf,
                tokens,
                lifetimes,
                minted,
                scopes,
                days,
                scope,
                name: form.name,
                notice: form.notice,
                error: form.error,
                create_error: form.create_error,
            })
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    days: String,
    #[serde(default)]
    scope: String,
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
    let scope = match form.scope.as_str() {
        "full" => TokenScope::Full,
        _ => TokenScope::Deploy,
    };
    let outcome = state
        .tokens()
        .create(session.account_id, &membership, &form.name, days, scope)
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
                scope: form.scope,
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
                scope: form.scope,
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
