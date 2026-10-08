//! `/{org}/settings/registries`: the organisation's registry credentials
//! (grund-docs design/apps.md §6.5), one per registry host, for private
//! images. Every member sees which hosts have one and its username; owners
//! and admins set and remove them. A password is never shown again, on this
//! page or anywhere else.

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{StatusCode, Uri},
};
use grund_store::organisations::Membership;
use serde::Deserialize;

use crate::{
    services::{
        registry_credentials::{MAX_PER_ORGANISATION, Refusal, RegistryCredentialsState},
        sessions::Session,
    },
    state::State,
    web::{
        browser::Browser,
        orgs::Member,
        pages::{Notice, PageResult, forged, redirect},
    },
};

pub struct RegistryRow {
    pub host: String,
    pub username: String,
    pub updated: String,
}

pub struct RegistriesPage<'a> {
    pub viewer: &'a super::pages::TypedViewer,
    pub csrf: &'a str,
    pub credentials: Vec<RegistryRow>,
    pub notice: &'a str,
    pub error: &'a str,
    pub form_error: String,
    pub host_error: String,
    pub username_error: String,
    pub password_error: String,
    pub host: String,
    pub username: String,
}

/// `GET /{org}/settings/registries`.
pub async fn registries_page(
    AxumState(state): AxumState<State>,
    member: Member,
    Query(query): Query<Notice>,
) -> PageResult {
    let notice = match query.done.as_str() {
        "set" => "Login saved. Deploys and pulls from that registry use it.",
        "removed" => "Login removed. Images from that registry are pulled without one.",
        _ => "",
    };
    let error = match query.error.as_str() {
        "gone" => "That registry has no credential here.",
        "not-allowed" => "Your role does not allow that.",
        _ => "",
    };
    registries_view(
        &state,
        &member.browser,
        &member.session,
        &member.membership,
        StatusCode::OK,
        RegistriesForm {
            notice,
            error,
            ..Default::default()
        },
    )
    .await
}

#[derive(Default)]
struct RegistriesForm<'a> {
    notice: &'a str,
    error: &'a str,
    form_error: String,
    host_error: String,
    username_error: String,
    password_error: String,
    host: String,
    username: String,
}

async fn registries_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    status: StatusCode,
    form: RegistriesForm<'_>,
) -> PageResult {
    let credentials: Vec<RegistryRow> = state
        .registry_credentials()
        .list(membership.organisation_id)
        .await?
        .into_iter()
        .map(|c| RegistryRow {
            host: c.host,
            username: c.username,
            updated: format!(
                "set {}{}",
                c.updated_at.format("%-d %b %Y"),
                c.updated_by
                    .map(|by| format!(" by {by}"))
                    .unwrap_or_default()
            ),
        })
        .collect();
    super::pages::signed_in_typed(
        state,
        browser,
        session,
        Some(membership),
        status,
        "Registries",
        "org-settings",
        None,
        None,
        None,
        |viewer, csrf| {
            crate::templates::compiled::pages::registries::render(&RegistriesPage {
                viewer,
                csrf,
                credentials,
                notice: form.notice,
                error: form.error,
                form_error: form.form_error,
                host_error: form.host_error,
                username_error: form.username_error,
                password_error: form.password_error,
                host: form.host,
                username: form.username,
            })
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct SetForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

/// `POST /{org}/settings/registries`: sets the credential for a host,
/// replacing any before it.
pub async fn set(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<SetForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let outcome = state
        .registry_credentials()
        .set(
            session.account_id,
            &membership,
            &form.host,
            &form.username,
            &form.password,
        )
        .await?;
    let mut answer = RegistriesForm {
        host: form.host,
        username: form.username,
        ..Default::default()
    };
    let status = match outcome {
        Ok(_) => return Ok(redirect(&format!("/{slug}/settings/registries?done=set"))),
        Err(Refusal::NotAllowed) => {
            answer.form_error = "Only owners and admins set registry credentials.".into();
            StatusCode::FORBIDDEN
        }
        Err(Refusal::TooMany) => {
            answer.form_error = format!(
                "This organisation has credentials for {MAX_PER_ORGANISATION} registries. Remove one first."
            );
            StatusCode::OK
        }
        Err(Refusal::Invalid { field, problem }) => {
            match field {
                "host" => answer.host_error = problem,
                "username" => answer.username_error = problem,
                _ => answer.password_error = problem,
            }
            StatusCode::OK
        }
    };
    registries_view(&state, &browser, &session, &membership, status, answer).await
}

#[derive(Deserialize)]
pub struct RemoveForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    host: String,
}

/// `POST /{org}/settings/registries/remove`.
pub async fn remove(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<RemoveForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let query = match state
        .registry_credentials()
        .remove(session.account_id, &membership, &form.host)
        .await?
    {
        Ok(true) => "done=removed",
        Ok(false) => "error=gone",
        Err(_) => "error=not-allowed",
    };
    Ok(redirect(&format!("/{slug}/settings/registries?{query}")))
}
