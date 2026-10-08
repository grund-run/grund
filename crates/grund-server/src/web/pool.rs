//! `/{org}/pool`: the management pool, for the operator organisation only
//! (grund-docs design/machines.md §3, §6.2, §7a). Its owners and admins add
//! machines from the capacity provider, lease an available one to an
//! organisation, end a lease, rebuild a returning machine and revoke one;
//! its members see the list. Every other organisation gets the 404 page, as
//! a slug it is not a member of does.
//!
//! The handlers call the same services as
//! `grund.machine.v1.ManagementPoolService`, so the page and the API refuse
//! the same things.

use crate::templates::compiled::pages::pool;
use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::Uri,
};
use chrono::Utc;
use grund_store::{machines::MachineRow, organisations::Membership};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::{
        agents::connected,
        capacity::CapacityState,
        machines::{ChangeOutcome, MachinesState, ProviderStep, ProvisionOutcome},
    },
    state::State,
    web::{
        browser::Browser,
        orgs::Member,
        pages::{Notice, PageResult, forged, not_found_page, redirect},
    },
};
pub struct PoolMachine {
    pub id: String,
    pub name: String,
    pub state: String,
    pub status: &'static str,
    pub tone: &'static str,
    pub sub: String,
    pub from_provider: bool,
}

pub struct PoolPage<'a> {
    pub csrf: &'a str,
    pub slug: &'a str,
    pub manages: bool,
    pub machines: Vec<PoolMachine>,
    pub notice: &'static str,
    pub error: &'static str,
    pub provider: bool,
}

async fn is_operator(state: &State, membership: &Membership) -> anyhow::Result<bool> {
    Ok(state.machines().operator().await? == Some(membership.organisation_id))
}

fn manages(membership: &Membership) -> bool {
    matches!(membership.role.as_str(), "owner" | "admin")
}

fn pool_context(row: MachineRow, now: chrono::DateTime<Utc>) -> PoolMachine {
    let (status, tone) = match row.state.as_str() {
        "available" => ("Available", "ok"),
        "leased" => ("Leased", "violet"),
        "returning" => ("Returning", "orange"),
        _ => ("Revoked", "muted"),
    };
    let seen = if connected(row.last_seen_at, now) {
        "Connected".to_string()
    } else {
        row.last_seen_at
            .map_or("Not connected yet".to_string(), |at| {
                format!("Last seen {}", at.format("%-d %b %Y %H:%M UTC"))
            })
    };
    use std::fmt::Write as _;
    let mut sub = seen;
    if let Some(slug) = row.lessee_slug.as_deref() {
        write!(
            sub,
            " · Leased to {slug} as {}",
            row.lease_name.as_deref().unwrap_or(&row.name),
        )
        .expect("writing into a String");
    }
    if let Some(id) = row.provider_machine_id.as_deref() {
        write!(sub, " · Provider id {id}").expect("writing into a String");
    }
    PoolMachine {
        id: row.machine_id.to_string(),
        name: row.name,
        state: row.state,
        status,
        tone,
        sub,
        from_provider: row.provider_machine_id.is_some(),
    }
}

/// `/{org}/pool`.
pub async fn pool_page(
    AxumState(state): AxumState<State>,
    member: Member,
    Query(query): Query<Notice>,
) -> PageResult {
    if !is_operator(&state, &member.membership).await? {
        return not_found_page(&state, &member.browser);
    }
    let notice = match query.done.as_str() {
        "provisioned" => "The provider is starting a machine. It joins the pool once it boots.",
        "leased" => "Machine leased.",
        "ended" => {
            "Lease ended. The provider is wiping the machine; it joins the pool again once it boots."
        }
        "ended-by-hand" => "Lease ended. Wipe the machine and register it again with a new code.",
        "rebuilding" => "The provider is wiping the machine again.",
        "revoked" => "Machine revoked. The provider takes it back.",
        "revoked-by-hand" => "Machine revoked.",
        _ => "",
    };
    let error = match query.error.as_str() {
        "not-allowed" => "Your role does not allow that.",
        "no-provider" => "This instance has no capacity provider.",
        "provider" => {
            "The capacity provider did not take the request. The change stands; try the provider step again."
        }
        "provider-busy" => "The capacity provider cannot start a machine now.",
        "codes" => "The pool has 20 unused codes. Wait for some to expire.",
        "no-organisation" => "There is no organisation by that name.",
        "not-available" => "Only an available machine can be leased.",
        "not-leased" => "That machine is not on lease.",
        "not-returning" => "Only a machine whose lease ended can be rebuilt.",
        "pool-full" => "That organisation has all the machines it may have.",
        "name-taken" => "Another machine in that organisation has that name.",
        "name" => "A machine name is 1 to 32 lowercase letters, digits and hyphens.",
        "gone" => "That machine is no longer there.",
        _ => "",
    };
    let now = Utc::now();
    let machines: Vec<PoolMachine> = state
        .machines()
        .pool(None)
        .await?
        .into_iter()
        .filter(|row| row.state != "revoked")
        .map(|row| pool_context(row, now))
        .collect();
    crate::web::pages::signed_in_typed(
        &state,
        &member.browser,
        &member.session,
        Some(&member.membership),
        axum::http::StatusCode::OK,
        "Management pool",
        "pool",
        None,
        None,
        None,
        |_, csrf| {
            pool::render(&PoolPage {
                csrf,
                slug: &member.membership.slug,
                manages: manages(&member.membership),
                machines,
                notice,
                error,
                provider: state.capacity().enabled(),
            })
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct ProvisionForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
pub struct LeaseForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    organisation: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

macro_rules! operator_or_return {
    ($state:expr, $browser:expr, $uri:expr, $slug:expr) => {{
        let (session, membership) = member_or_return!($state, $browser, $uri, $slug);
        if !is_operator($state, &membership).await? {
            return not_found_page($state, $browser);
        }
        if !manages(&membership) {
            return Ok(redirect(&format!("/{}/pool?error=not-allowed", $slug)));
        }
        session
    }};
}

fn outcome_error(outcome: &ChangeOutcome) -> &'static str {
    match outcome {
        ChangeOutcome::NotFound => "gone",
        ChangeOutcome::NoOrganisation => "no-organisation",
        ChangeOutcome::NotAvailable => "not-available",
        ChangeOutcome::NotLeased => "not-leased",
        ChangeOutcome::NotReturning => "not-returning",
        ChangeOutcome::PoolFull => "pool-full",
        ChangeOutcome::NameTaken => "name-taken",
        ChangeOutcome::NameInvalid(_) => "name",
        ChangeOutcome::NoProvider => "no-provider",
        ChangeOutcome::NotAllowed => "not-allowed",
        ChangeOutcome::Done(_) | ChangeOutcome::Leased(..) => "",
    }
}

fn after_step(
    slug: &str,
    outcome: &ChangeOutcome,
    step: &ProviderStep,
    done: &str,
    by_hand: &str,
) -> axum::response::Response {
    let to = match (outcome, step) {
        (ChangeOutcome::Done(_), ProviderStep::Requested) => format!("done={done}"),
        (ChangeOutcome::Done(_), ProviderStep::NotNeeded) => format!("done={by_hand}"),
        (ChangeOutcome::Done(_), ProviderStep::Failed(_)) => "error=provider".to_string(),
        (other, _) => format!("error={}", outcome_error(other)),
    };
    redirect(&format!("/{slug}/pool?{to}"))
}

/// `POST /{org}/pool/provision`: asks the capacity provider for a machine.
pub async fn provision(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<ProvisionForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let session = operator_or_return!(&state, &browser, &uri, &slug);
    let to = match state
        .machines()
        .provision(session.account_id, form.name.trim(), "")
        .await?
    {
        ProvisionOutcome::Provisioned { .. } => "done=provisioned",
        ProvisionOutcome::NotConfigured => "error=no-provider",
        ProvisionOutcome::Invalid(_) => "error=name",
        ProvisionOutcome::TooMany => "error=codes",
        ProvisionOutcome::Unavailable => "error=provider-busy",
        ProvisionOutcome::Refused(message) => {
            tracing::warn!(%message, "the capacity provider refused a machine");
            "error=provider"
        }
    };
    Ok(redirect(&format!("/{slug}/pool?{to}")))
}

/// `POST /{org}/pool/{machine}/lease`: leases an available machine to the
/// organisation named in the form.
pub async fn lease(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, machine_id)): Path<(String, Uuid)>,
    Form(form): Form<LeaseForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let session = operator_or_return!(&state, &browser, &uri, &slug);
    let outcome = state
        .machines()
        .lease(
            session.account_id,
            machine_id,
            form.organisation.trim(),
            form.name.trim(),
        )
        .await?;
    let to = match &outcome {
        ChangeOutcome::Leased(..) => "done=leased".to_string(),
        other => format!("error={}", outcome_error(other)),
    };
    Ok(redirect(&format!("/{slug}/pool?{to}")))
}

/// `POST /{org}/pool/{machine}/end`: ends a lease; a machine from the
/// provider is wiped and registers again.
pub async fn end_lease(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, machine_id)): Path<(String, Uuid)>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let session = operator_or_return!(&state, &browser, &uri, &slug);
    let (outcome, step) = state
        .machines()
        .end_lease(session.account_id, machine_id)
        .await?;
    Ok(after_step(&slug, &outcome, &step, "ended", "ended-by-hand"))
}

/// `POST /{org}/pool/{machine}/rebuild`: asks the provider again to wipe a
/// returning machine.
pub async fn rebuild(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, machine_id)): Path<(String, Uuid)>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let session = operator_or_return!(&state, &browser, &uri, &slug);
    let (outcome, step) = state
        .machines()
        .rebuild(session.account_id, machine_id)
        .await?;
    Ok(after_step(
        &slug,
        &outcome,
        &step,
        "rebuilding",
        "rebuilding",
    ))
}

/// `POST /{org}/pool/{machine}/revoke`: revokes a pool machine for good; a
/// machine from the provider goes back to it.
pub async fn revoke(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, machine_id)): Path<(String, Uuid)>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let session = operator_or_return!(&state, &browser, &uri, &slug);
    let (outcome, step) = state
        .machines()
        .revoke_pool(session.account_id, machine_id)
        .await?;
    Ok(after_step(
        &slug,
        &outcome,
        &step,
        "revoked",
        "revoked-by-hand",
    ))
}
