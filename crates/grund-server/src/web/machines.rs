//! `/{org}/machines`: the machines an organisation runs things on, whether
//! each is connected, the setup code that adds one, and the VMs it runs on
//! them (grund-docs design/machines.md §7b).
//!
//! Every member sees the page; owners and admins add, remove and run. The
//! handlers call the same services as `grund.machine.v1.MachineService`, so
//! the page and the API refuse the same things.

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{StatusCode, Uri},
    response::Response,
};
use chrono::Utc;
use grund_domain::{machine::Authority, machine::TokenKind, organisation::Role};
use grund_store::{agents::VmRow, machines::MachineRow, organisations::Membership};
use minijinja::{Value, context};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::{
        agents::{AgentsState, VmOutcome, VmRequest, cannot_host, connected},
        machines::{ChangeOutcome, MachinesState, MintOutcome},
        sessions::Session,
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

fn manages(membership: &Membership) -> bool {
    Role::parse(&membership.role).is_some_and(|role| role.manages_members())
}

#[derive(Deserialize, Default)]
pub struct NoticeQuery {
    #[serde(default)]
    done: String,
    #[serde(default)]
    error: String,
}

/// `/{org}/machines`.
pub async fn machines_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Query(query): Query<NoticeQuery>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let notice = match query.done.as_str() {
        "removed" => "Machine removed. Its key no longer works here.",
        "running" => "Virtual machine placed. It joins as a machine once it boots.",
        "stopped" => "Virtual machine stopping.",
        _ => "",
    };
    let error = match query.error.as_str() {
        "not-allowed" => "Your role does not allow that.",
        "leased" => "A grund machine goes back when its lease ends; it cannot be removed here.",
        "gone" => "That machine or VM is no longer there.",
        _ => "",
    };
    machines_view(
        &state,
        &browser,
        &session,
        &membership,
        StatusCode::OK,
        MachinesForm {
            notice,
            error,
            ..Default::default()
        },
    )
    .await
}

#[derive(Default)]
struct MachinesForm<'a> {
    notice: &'a str,
    error: &'a str,
    setup: Option<Value>,
    add_error: String,
    name: String,
    run_error: String,
    run: RunForm,
}

fn machine_context(row: &MachineRow, now: chrono::DateTime<Utc>) -> Value {
    let capabilities = row.capabilities.as_ref().map(|c| &c.0);
    context! {
        id => row.machine_id.to_string(),
        name => row.pool_name.clone().unwrap_or_else(|| row.name.clone()),
        leased => row.pool == "management",
        connected => connected(row.last_seen_at, now),
        last_seen => row.last_seen_at.map(|at| at.format("%-d %b %Y %H:%M UTC").to_string()),
        kvm => capabilities.and_then(|c| c["kvm"].as_bool()).unwrap_or(false),
        hostname => row.facts.0["hostname"].as_str().unwrap_or_default().to_string(),
    }
}

fn vm_context(row: &VmRow) -> Value {
    let observed = row.observed_state.as_deref().unwrap_or("waiting");
    let tone = match observed {
        "running" => "ok",
        "failed" | "exited" => "orange",
        _ => "muted",
    };
    context! {
        id => row.vm_id.to_string(),
        name => row.name,
        host => row.host_name.clone().unwrap_or_else(|| "a removed machine".into()),
        vcpus => row.vcpus,
        memory_mib => row.memory_mib,
        disk_gib => row.disk_gib,
        observed => capitalise(observed),
        tone,
        reason => row.observed_reason,
        running => row.state == "running",
    }
}

fn capitalise(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

async fn machines_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    status: StatusCode,
    form: MachinesForm<'_>,
) -> PageResult {
    let now = Utc::now();
    let rows = state
        .machines()
        .organisation_machines(membership.organisation_id)
        .await?;
    let machines: Vec<Value> = rows.iter().map(|row| machine_context(row, now)).collect();
    let hosts: Vec<Value> = rows
        .iter()
        .filter(|row| cannot_host(row).is_none() && connected(row.last_seen_at, now))
        .map(|row| {
            context! {
                id => row.machine_id.to_string(),
                name => row.pool_name.clone().unwrap_or_else(|| row.name.clone()),
            }
        })
        .collect();
    let vms: Vec<Value> = state
        .agents()
        .vms(membership.organisation_id)
        .await?
        .iter()
        .map(vm_context)
        .collect();
    let viewer = viewer_context(state, session, Some(membership)).await?;
    render(
        state,
        browser,
        status,
        "pages/machines.html.jinja",
        context! {
            viewer, machines, hosts, vms,
            notice => form.notice, error => form.error,
            setup => form.setup, add_error => form.add_error, name => form.name,
            run_error => form.run_error, run => Value::from_serialize(&form.run),
            csrf => browser.csrf_token(), section => "machines",
        },
    )
}

#[derive(Deserialize)]
pub struct AddForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
}

/// `POST /{org}/machines/add`: a one-time setup code, shown on the page it
/// answers with and nowhere else.
pub async fn add(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<AddForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/machines?error=not-allowed")));
    }
    let outcome = state
        .machines()
        .mint(
            TokenKind::Organisation,
            Some(membership.organisation_id),
            None,
            form.name.trim(),
            0,
            session.account_id,
        )
        .await?;
    let mut page = MachinesForm {
        name: form.name.clone(),
        ..Default::default()
    };
    let status = match outcome {
        MintOutcome::Minted(minted) => {
            let origin = state.config.public_origin().serialized;
            let minutes = (minted.expires_at - Utc::now()).num_minutes().max(1);
            page.setup = Some(context! {
                command => format!("grund join --url {origin} {}", minted.token),
                minutes,
            });
            page.name = String::new();
            StatusCode::OK
        }
        MintOutcome::Invalid(message) => {
            page.add_error = message;
            StatusCode::OK
        }
        MintOutcome::TooMany => {
            page.add_error =
                "This organisation has 20 unused setup codes. Wait for some to expire.".into();
            StatusCode::OK
        }
        MintOutcome::NotReturning | MintOutcome::NotFound => {
            page.add_error = "grund could not make a setup code. Try again.".into();
            StatusCode::OK
        }
    };
    let mut response = machines_view(&state, &browser, &session, &membership, status, page).await?;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /{org}/machines/{machine}/remove`: revokes one of the organisation's
/// own machines. A leased machine is the operator's and is refused.
pub async fn remove(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, machine_id)): Path<(String, Uuid)>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/machines?error=not-allowed")));
    }
    let machines = state.machines();
    if machines
        .organisation_machine(membership.organisation_id, machine_id)
        .await?
        .is_none()
    {
        return Ok(redirect(&format!("/{slug}/machines?error=gone")));
    }
    let query = match machines
        .revoke(
            session.account_id,
            machine_id,
            Authority::Organisation(membership.organisation_id),
        )
        .await?
    {
        ChangeOutcome::Done(_) | ChangeOutcome::Leased(..) => "done=removed",
        ChangeOutcome::NotAllowed => "error=leased",
        _ => "error=gone",
    };
    Ok(redirect(&format!("/{slug}/machines?{query}")))
}

#[derive(Deserialize, Default, serde::Serialize)]
pub struct RunForm {
    #[serde(default, skip_serializing)]
    csrf: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    vm_name: String,
    #[serde(default)]
    vcpus: String,
    #[serde(default)]
    memory_mib: String,
    #[serde(default)]
    disk_gib: String,
    #[serde(default)]
    kernel_url: String,
    #[serde(default)]
    kernel_sha256: String,
    #[serde(default)]
    rootfs_url: String,
    #[serde(default)]
    rootfs_sha256: String,
}

/// `POST /{org}/machines/vms`: places a VM on one of the organisation's
/// machines.
pub async fn run_vm(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<RunForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/machines?error=not-allowed")));
    }
    let number = |value: &str| value.trim().parse::<u32>().ok();
    let request = match (
        Uuid::parse_str(&form.host).ok(),
        number(&form.vcpus),
        number(&form.memory_mib),
        number(&form.disk_gib),
    ) {
        (Some(host_machine_id), Some(vcpus), Some(memory_mib), Some(disk_gib)) => VmRequest {
            host_machine_id,
            name: form.vm_name.trim().to_string(),
            vcpus,
            memory_mib,
            disk_gib,
            kernel_url: form.kernel_url.trim().to_string(),
            kernel_sha256: form.kernel_sha256.trim().to_ascii_lowercase(),
            rootfs_url: form.rootfs_url.trim().to_string(),
            rootfs_sha256: form.rootfs_sha256.trim().to_ascii_lowercase(),
        },
        (None, ..) => {
            return run_refused(
                &state,
                &browser,
                &session,
                &membership,
                form,
                "Pick a machine to run it on.",
            )
            .await;
        }
        _ => {
            return run_refused(
                &state,
                &browser,
                &session,
                &membership,
                form,
                "vCPUs, memory and disk are whole numbers.",
            )
            .await;
        }
    };
    let outcome = state
        .agents()
        .run_vm(session.account_id, membership.organisation_id, &request)
        .await?;
    let message = match outcome {
        VmOutcome::Done(_) => return Ok(redirect(&format!("/{slug}/machines?done=running"))),
        VmOutcome::NotFound => "That machine is no longer in this organisation.".to_string(),
        VmOutcome::CannotHost(reason) => capitalise(&format!("{reason}.")),
        VmOutcome::Invalid(message) => capitalise(&format!("{message}.")),
        VmOutcome::NameTaken => {
            "Another machine or VM in this organisation has that name.".to_string()
        }
        VmOutcome::PoolFull => "This organisation has all the machines it may have.".to_string(),
    };
    run_refused(&state, &browser, &session, &membership, form, &message).await
}

async fn run_refused(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    form: RunForm,
    message: &str,
) -> PageResult {
    machines_view(
        state,
        browser,
        session,
        membership,
        StatusCode::OK,
        MachinesForm {
            run_error: message.to_string(),
            run: form,
            ..Default::default()
        },
    )
    .await
}

/// `POST /{org}/machines/vms/{vm}/stop`.
pub async fn stop_vm(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, vm_id)): Path<(String, Uuid)>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (_, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/machines?error=not-allowed")));
    }
    let query = match state
        .agents()
        .stop_vm(membership.organisation_id, vm_id)
        .await?
    {
        VmOutcome::Done(_) => "done=stopped",
        _ => "error=gone",
    };
    Ok(redirect(&format!("/{slug}/machines?{query}")))
}
