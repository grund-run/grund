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
use grund_store::organisations::Membership;
use serde::Deserialize;
use std::borrow::Cow;

use crate::{
    services::{
        apps::AppsState,
        domains::{DomainView, DomainsError, DomainsState, Status},
        sessions::Session,
    },
    state::State,
    web::{
        browser::Browser,
        orgs::Member,
        pages::{Notice, PageError, PageResult, forged, redirect, signed_in_typed},
    },
};

pub struct DomainRecord<'a> {
    pub kind: &'static str,
    pub name: &'a str,
    pub value: &'a str,
}

pub struct DomainItem<'a> {
    pub id: String,
    pub name: &'a str,
    pub state: &'a str,
    pub app: &'a str,
    pub sentence: Cow<'a, str>,
    pub tone: &'static str,
    pub record: Option<DomainRecord<'a>>,
    pub records_aside: Option<String>,
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

fn domain_context<'a>(
    index: usize,
    domain: &'a DomainView,
    address: Option<&'a str>,
) -> DomainItem<'a> {
    let app = domain.app_name.as_deref().unwrap_or("");
    let (sentence, tone) = match domain.status {
        Status::Pending => (Cow::Borrowed("Waiting for its TXT record."), "orange"),
        Status::Verified => (
            Cow::Borrowed(
                "Verified: it is this organisation's on this grund. Bind it to an app to serve it.",
            ),
            "blue",
        ),
        Status::Bound => (
            Cow::Owned(format!(
                "Bound to {app}. Its certificate is on its way once {} points at the app's address.",
                domain.name
            )),
            "orange",
        ),
        Status::Issued => (
            Cow::Owned(format!(
                "Serving {app} at https://{}, certificate valid until {}.",
                domain.name,
                domain
                    .certificate_not_after
                    .map(|at| at.format("%-d %b %Y").to_string())
                    .unwrap_or_default()
            )),
            "ok",
        ),
        Status::Error => (
            Cow::Borrowed(domain.problem.as_deref().unwrap_or("Something went wrong.")),
            "danger",
        ),
    };
    let record = match (domain.state.as_str(), address) {
        ("pending", _) => Some(DomainRecord {
            kind: "TXT",
            name: &domain.txt_name,
            value: &domain.txt_value,
        }),
        ("bound", Some(address)) => Some(DomainRecord {
            kind: "CNAME",
            name: &domain.name,
            value: address,
        }),
        _ => None,
    };
    DomainItem {
        id: format!("domain-{}", index + 1),
        name: &domain.name,
        state: &domain.state,
        app, sentence, tone, record,
        records_aside: (domain.state == "bound" && address.is_some()).then(|| format!(
            "Point {} at the app with this record. A domain at the top of its zone (example.com itself) cannot have a CNAME: use your provider's ALIAS, ANAME or CNAME flattening to the same address.",
            domain.name
        )),
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
    let address_of = |app: &Option<String>| {
        app.as_ref().and_then(|app| {
            listings
                .iter()
                .find(|l| &l.view.row.name == app)
                .and_then(|l| l.address.as_deref())
        })
    };
    let domain_rows = state
        .domains()
        .list(membership.organisation_id)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    let domains: Vec<DomainItem<'_>> = domain_rows
        .iter()
        .enumerate()
        .map(|(index, domain)| domain_context(index, domain, address_of(&domain.app_name)))
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
        "bound" => "Domain bound. grund orders its certificate once it points at the app.",
        "unbound" => "Domain unbound. It stays verified for this organisation.",
        "removed" => "Domain removed.",
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
    Verify,
    Bind,
    Unbind,
    Remove,
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
