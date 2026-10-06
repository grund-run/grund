//! `/{org}/domains`: the addresses the organisation's apps hold, and its
//! custom domains (grund-docs website/design/app-domains.md §3): add one,
//! make the TXT record the page shows, check it, bind the domain to an
//! app, unbind and remove it. Every member sees them; owners and admins
//! change them.

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{StatusCode, Uri},
    response::Response,
};
use grund_store::organisations::Membership;
use minijinja::{Value, context};
use serde::Deserialize;

use crate::{
    services::{
        apps::AppsState,
        domains::{DomainView, DomainsError, DomainsState, MAX_PER_ORGANISATION, Status},
        sessions::Session,
    },
    state::State,
    web::{
        browser::Browser,
        orgs::Member,
        pages::{Notice, PageError, forged, redirect, signed_in},
    },
};

type PageResult = Result<Response, PageError>;

#[derive(Default)]
struct AddForm {
    notice: &'static str,
    error: &'static str,
    form_error: String,
    name_error: String,
    name: String,
}

fn cooldown_words(seconds: u64) -> String {
    match seconds {
        s if s % 86_400 == 0 && s >= 86_400 => {
            let days = s / 86_400;
            format!("{days} day{}", if days == 1 { "" } else { "s" })
        }
        s if s % 3600 == 0 && s >= 3600 => format!("{} hours", s / 3600),
        s => format!("{s} seconds"),
    }
}

fn domain_context(index: usize, domain: &DomainView, address: Option<&str>) -> Value {
    let app = domain.app_name.clone().unwrap_or_default();
    let (sentence, tone) = match domain.status {
        Status::Pending => ("Waiting for its TXT record.".to_string(), "orange"),
        Status::Verified => (
            "Verified: it is this organisation's on this grund. Bind it to an app to serve it."
                .to_string(),
            "blue",
        ),
        Status::Bound => (
            format!(
                "Bound to {app}. Its certificate is on its way once {} points at the app's address.",
                domain.name
            ),
            "orange",
        ),
        Status::Issued => (
            format!(
                "Serving {app} at https://{}, certificate valid until {}.",
                domain.name,
                domain
                    .certificate_not_after
                    .map(|at| at.format("%-d %b %Y").to_string())
                    .unwrap_or_default()
            ),
            "ok",
        ),
        Status::Error => (
            domain
                .problem
                .clone()
                .unwrap_or_else(|| "Something went wrong.".into()),
            "danger",
        ),
    };
    let records: Vec<Value> = match (domain.state.as_str(), address) {
        ("pending", _) => vec![context! {
            type => "TXT", name => domain.txt_name, value => domain.txt_value,
        }],
        ("bound", Some(address)) => vec![context! {
            type => "CNAME", name => domain.name, value => address,
        }],
        _ => Vec::new(),
    };
    context! {
        id => format!("domain-{}", index + 1),
        name => domain.name,
        state => domain.state,
        app,
        sentence, tone, records,
        records_aside => format!(
            "Point {} at the app with this record. A domain at the top of its zone (example.com itself) cannot have a CNAME: use your provider's ALIAS, ANAME or CNAME flattening to the same address.",
            domain.name
        ),
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
    let addresses: Vec<Value> = listings
        .iter()
        .filter_map(|l| {
            l.address
                .as_ref()
                .map(|address| context! { name => l.view.row.name, address })
        })
        .collect();
    let apps: Vec<(String, String)> = listings
        .iter()
        .filter(|l| l.address.is_some())
        .map(|l| (l.view.row.name.clone(), l.view.row.name.clone()))
        .collect();
    let address_of = |app: &Option<String>| {
        app.as_ref().and_then(|app| {
            listings
                .iter()
                .find(|l| &l.view.row.name == app)
                .and_then(|l| l.address.as_deref())
        })
    };
    let domains: Vec<Value> = state
        .domains()
        .list(membership.organisation_id)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?
        .iter()
        .enumerate()
        .map(|(index, domain)| domain_context(index, domain, address_of(&domain.app_name)))
        .collect();
    signed_in(
        state,
        browser,
        session,
        Some(membership),
        status,
        "pages/domains.html.jinja",
        "domains",
        context! {
            addresses, domains, apps,
            max => MAX_PER_ORGANISATION,
            cooldown => cooldown_words(state.config.entry.domain_cooldown),
            notice => form.notice, error => form.error,
            form_error => form.form_error, name_error => form.name_error, name => form.name,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cool_down_is_said_in_the_largest_whole_unit() {
        assert_eq!(cooldown_words(604_800), "7 days");
        assert_eq!(cooldown_words(86_400), "1 day");
        assert_eq!(cooldown_words(7200), "2 hours");
        assert_eq!(cooldown_words(5), "5 seconds");
    }
}
