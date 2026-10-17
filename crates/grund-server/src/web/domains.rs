//! `/{org}/domains`: the addresses the organisation's apps hold, and its
//! custom domains (grund-docs website/design/app-domains.md §3): add one,
//! make the TXT record the page shows, check it, bind the domain to an
//! app, unbind and remove it. Every member sees them; owners and admins
//! change them.

use crate::templates::compiled::pages::domains;
use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{StatusCode, Uri},
};
use chrono::{DateTime, Utc};
use grund_store::{domain_setup::Step, organisations::Membership};
use serde::Deserialize;
use std::borrow::Cow;

use crate::{
    services::{
        apps::AppsState,
        domains::{DomainView, DomainsError, DomainsState},
        entry::publishes,
        sessions::Session,
    },
    state::State,
    web::{
        browser::Browser,
        orgs::Member,
        pages::{Notice, PageError, PageResult, forged, redirect, signed_in_typed},
    },
};

pub struct DomainStep<'a> {
    pub name: &'a str,
    pub label: &'a str,
    pub state: &'static str,
    pub state_code: &'static str,
    pub tone: &'static str,
    pub detail: &'a str,
    pub checked_at: Option<DateTime<Utc>>,
    pub next_retry_at: Option<DateTime<Utc>>,
}

impl<'a> From<&'a Step> for DomainStep<'a> {
    fn from(step: &'a Step) -> Self {
        let label = match step.name.as_str() {
            "dns_record" => "DNS record seen",
            "edge_reachable" => "Edge reachable",
            "certificate_requested" => "Certificate requested",
            "challenge_passed" => "Challenge passed",
            "certificate_issued" => "Certificate issued",
            "serving_https" => "Serving HTTPS",
            name => name,
        };
        let (state, tone) = match step.state.as_str() {
            "done" => ("Done", "ok"),
            "in_progress" => ("In progress", "blue"),
            "failed" => ("Failed", "danger"),
            _ => ("Waiting", "muted"),
        };
        Self {
            name: &step.name,
            label,
            state,
            state_code: step.state.as_str(),
            tone,
            detail: &step.detail,
            checked_at: step.checked_at,
            next_retry_at: step.next_retry_at,
        }
    }
}

pub struct DomainItem<'a> {
    pub id: String,
    pub name: &'a str,
    pub state: &'a str,
    pub app: &'a str,
    pub sentence: Cow<'a, str>,
    pub tone: &'static str,
    pub records: Vec<(&'static str, &'a str, &'a str)>,
    pub steps: Vec<DomainStep<'a>>,
    pub refresh: bool,
    pub certificate_attempts: i32,
    pub certificate_next_attempt_at: Option<DateTime<Utc>>,
}

pub struct AppAddress<'a> {
    pub name: &'a str,
    pub address: &'a str,
}

pub struct DomainsPage<'a> {
    pub csrf: &'a str,
    pub slug: &'a str,
    pub manages: bool,
    pub addresses: Vec<AppAddress<'a>>,
    pub bindable_apps: Vec<&'a str>,
    pub custom_only: bool,
    pub domains: Vec<DomainItem<'a>>,
    pub notice: &'static str,
    pub error: &'static str,
    pub form_error: String,
    pub name_error: String,
    pub name: String,
}

#[derive(Default)]
struct AddForm {
    notice: &'static str,
    error: &'static str,
    form_error: String,
    name_error: String,
    name: String,
}

pub(crate) fn domain_context<'a>(
    domain: &'a DomainView,
    address: Option<&'a str>,
    public: bool,
) -> DomainItem<'a> {
    let app = domain.app_name.as_deref().unwrap_or("");
    let serving = domain
        .steps
        .iter()
        .any(|step| step.name == "serving_https" && step.state.as_str() == "done");
    let (sentence, tone) = match domain.state.as_str() {
        "pending" if domain.problem.is_some() => (
            Cow::Borrowed(domain.problem.as_deref().unwrap_or_default()),
            "danger",
        ),
        "pending" => (Cow::Borrowed("Waiting for its TXT record."), "orange"),
        "verified" => (Cow::Borrowed("Domain verified. No app bound."), "blue"),
        _ if !public => (
            Cow::Owned(format!("Bound to {app}. No public HTTP port.")),
            "blue",
        ),
        _ if serving => (
            Cow::Owned(format!("Serving {app} at https://{}.", domain.name)),
            "ok",
        ),
        _ if domain
            .steps
            .iter()
            .any(|step| step.state.as_str() == "failed") =>
        {
            (Cow::Borrowed("Setup check failed."), "danger")
        }
        _ => (Cow::Borrowed("HTTPS setup not complete."), "orange"),
    };
    let pending = domain.state == "pending";
    let mut records = Vec::with_capacity(usize::from(pending) + usize::from(address.is_some()));
    if pending {
        records.push(("TXT", domain.txt_name.as_str(), domain.txt_value.as_str()));
    }
    if let Some(address) = address {
        records.push(("CNAME", domain.name.as_str(), address));
    }
    DomainItem {
        id: format!("domain-{}", domain.name),
        name: &domain.name,
        state: &domain.state,
        app,
        sentence,
        tone,
        records,
        steps: domain.steps.iter().map(DomainStep::from).collect(),
        refresh: domain.state == "bound" && !serving,
        certificate_attempts: domain.certificate_attempts,
        certificate_next_attempt_at: domain.certificate_next_attempt_at,
    }
}

async fn domains_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    status: StatusCode,
    form: AddForm,
) -> PageResult {
    let listings = state
        .apps()
        .listings(membership.organisation_id, &membership.slug)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    let addresses: Vec<AppAddress<'_>> = listings
        .iter()
        .filter_map(|l| {
            l.address.as_deref().map(|address| AppAddress {
                name: &l.view.row.name,
                address,
            })
        })
        .collect();
    let custom_only = state.config.entry.app_domains == crate::config::AppDomains::CustomOnly;
    let bindable_apps: Vec<&str> = listings
        .iter()
        .filter(|listing| custom_only || listing.address.is_some())
        .map(|listing| listing.view.row.name.as_str())
        .collect();
    let address_of = |app: &Option<String>| {
        app.as_ref().and_then(|app| {
            listings
                .iter()
                .find(|l| &l.view.row.name == app)
                .and_then(|l| {
                    l.address
                        .as_deref()
                        .or_else(|| state.config.entry.edges.first().map(String::as_str))
                })
        })
    };
    let domain_rows = state
        .domains()
        .list(membership.organisation_id)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    let domains: Vec<DomainItem<'_>> = domain_rows
        .iter()
        .map(|domain| {
            let public = domain.app_name.as_ref().is_some_and(|name| {
                listings.iter().any(|listing| {
                    &listing.view.row.name == name && listing.spec.as_ref().is_some_and(publishes)
                })
            });
            domain_context(
                domain,
                address_of(&domain.app_name)
                    .or_else(|| state.config.entry.edges.first().map(String::as_str)),
                public,
            )
        })
        .collect();
    signed_in_typed(
        state,
        browser,
        session,
        Some(membership),
        status,
        "Domains",
        "domains",
        None,
        None,
        None,
        |_, csrf| {
            domains::render(&DomainsPage {
                csrf,
                slug: &membership.slug,
                manages: matches!(membership.role.as_str(), "owner" | "admin"),
                addresses,
                bindable_apps,
                custom_only,
                domains,
                notice: form.notice,
                error: form.error,
                form_error: form.form_error,
                name_error: form.name_error,
                name: form.name,
            })
        },
    )
    .await
}

/// `GET /{org}/domains`.
pub async fn domains_page(
    AxumState(state): AxumState<State>,
    member: Member,
    Query(query): Query<Notice>,
) -> PageResult {
    let notice = match query.done.as_str() {
        "added" => "Domain added. Make its TXT record, then check it.",
        "verified" => "Domain verified. Bind it to an app to serve it.",
        "bound" => "Domain bound. grund orders its certificate once it points at grund's edge.",
        "unbound" => "Domain unbound. It stays verified for this organisation.",
        "removed" => "Domain removed.",
        "checking" => "Domain check queued.",
        _ => "",
    };
    let error = match query.error.as_str() {
        "unverified" => "grund did not find the TXT record yet. The domain says what DNS answered.",
        "gone" => "That domain is not this organisation's.",
        "not-allowed" => "Only owners and admins change domains.",
        "taken" => "Another organisation on this grund holds that domain.",
        "cooling" => {
            "That domain was released recently by another organisation and cannot be verified yet."
        }
        "not-verified" => "Verify the domain before binding it.",
        "app" => "That app is gone, or has no public HTTP port to serve a domain on.",
        "last-domain" => {
            "Make the app private or bind another domain before removing its last public domain."
        }
        "app-limit" => "That app has as many custom domains as it can hold.",
        "failed" => "grund could not finish that. Try again.",
        _ => "",
    };
    domains_view(
        &state,
        &member.browser,
        &member.session,
        &member.membership,
        StatusCode::OK,
        AddForm {
            notice,
            error,
            ..Default::default()
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct NameForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    app: String,
}

/// `POST /{org}/domains`: adds a domain.
pub async fn add(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<NameForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let outcome = state
        .domains()
        .add(session.account_id, &membership, &form.name)
        .await;
    let mut answer = AddForm {
        name: form.name,
        ..Default::default()
    };
    let status = match outcome {
        Ok(_) => return Ok(redirect(&format!("/{slug}/domains?done=added#custom"))),
        Err(DomainsError::Internal(error)) => return Err(PageError::from(error)),
        Err(DomainsError::NotAllowed) => {
            answer.form_error = "Only owners and admins add domains.".into();
            StatusCode::FORBIDDEN
        }
        Err(
            error @ (DomainsError::Invalid(_)
            | DomainsError::Reserved(_)
            | DomainsError::Exists
            | DomainsError::Taken
            | DomainsError::CoolingDown(_)),
        ) => {
            answer.name_error = match error {
                DomainsError::Taken => {
                    "Another organisation on this grund holds that domain.".into()
                }
                other => capitalise(&other.to_string()),
            };
            StatusCode::UNPROCESSABLE_ENTITY
        }
        Err(other) => {
            answer.form_error = capitalise(&other.to_string());
            StatusCode::UNPROCESSABLE_ENTITY
        }
    };
    domains_view(&state, &browser, &session, &membership, status, answer).await
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn error_query(error: DomainsError) -> Result<&'static str, PageError> {
    Ok(match error {
        DomainsError::NotFound => "error=gone",
        DomainsError::NotAllowed => "error=not-allowed",
        DomainsError::Taken => "error=taken",
        DomainsError::CoolingDown(_) => "error=cooling",
        DomainsError::NotVerified => "error=not-verified",
        DomainsError::VerificationFailed(_) => "error=unverified",
        DomainsError::AppNotFound | DomainsError::AppNotPublic => "error=app",
        DomainsError::LastPublicDomain => "error=last-domain",
        DomainsError::AppLimit => "error=app-limit",
        DomainsError::Internal(error) => return Err(PageError::from(error)),
        _ => "error=failed",
    })
}

async fn act(
    state: &State,
    browser: &Browser,
    uri: &Uri,
    slug: &str,
    form: NameForm,
    done: &'static str,
    action: Action,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(state, browser);
    }
    let (session, membership) = member_or_return!(state, browser, uri, slug);
    let domains = state.domains();
    let actor = session.account_id;
    let outcome = match action {
        Action::Check => domains
            .check_now(actor, &membership, &form.name)
            .await
            .map(|_| ()),
        Action::Verify => domains
            .verify(actor, &membership, &form.name)
            .await
            .map(|_| ()),
        Action::Bind => domains
            .bind(actor, &membership, &form.name, &form.app)
            .await
            .map(|_| ()),
        Action::Unbind => domains
            .unbind(actor, &membership, &form.name)
            .await
            .map(|_| ()),
        Action::Remove => domains.remove(actor, &membership, &form.name).await,
    };
    let query = match outcome {
        Ok(()) => done,
        Err(error) => error_query(error)?,
    };
    Ok(redirect(&format!("/{slug}/domains?{query}#custom")))
}

enum Action {
    Check,
    Verify,
    Bind,
    Unbind,
    Remove,
}

/// `POST /{org}/domains/check`: queues a setup check now.
pub async fn check(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<NameForm>,
) -> PageResult {
    act(
        &state,
        &browser,
        &uri,
        &slug,
        form,
        "done=checking",
        Action::Check,
    )
    .await
}

/// `POST /{org}/domains/verify`: looks for the TXT record now.
pub async fn verify(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<NameForm>,
) -> PageResult {
    act(
        &state,
        &browser,
        &uri,
        &slug,
        form,
        "done=verified",
        Action::Verify,
    )
    .await
}

/// `POST /{org}/domains/bind`: binds a verified domain to an app.
pub async fn bind(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<NameForm>,
) -> PageResult {
    act(
        &state,
        &browser,
        &uri,
        &slug,
        form,
        "done=bound",
        Action::Bind,
    )
    .await
}

/// `POST /{org}/domains/unbind`.
pub async fn unbind(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<NameForm>,
) -> PageResult {
    act(
        &state,
        &browser,
        &uri,
        &slug,
        form,
        "done=unbound",
        Action::Unbind,
    )
    .await
}

/// `POST /{org}/domains/remove`.
pub async fn remove(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<NameForm>,
) -> PageResult {
    act(
        &state,
        &browser,
        &uri,
        &slug,
        form,
        "done=removed",
        Action::Remove,
    )
    .await
}
