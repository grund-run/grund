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
        orgs::Member,
        pages::{Notice, PageResult, forged, redirect, signed_in},
    },
};

fn manages(membership: &Membership) -> bool {
    Role::parse(&membership.role).is_some_and(|role| role.manages_members())
}

/// `/{org}/machines`.
pub async fn machines_page(
    AxumState(state): AxumState<State>,
    member: Member,
    Query(query): Query<Notice>,
) -> PageResult {
    let notice = match query.done.as_str() {
        "removed" => "Machine removed. Its key no longer works here.",
        "running" => "Virtual machine placed. It joins as a machine once it boots.",
        "stopped" => "Virtual machine stopping.",
        "out-of-service" => "Machine out of service. Its copies are moving to other machines.",
        "in-service" => "Machine back in service.",
        "labels" => "Labels saved.",
        _ => "",
    };
    let error = match query.error.as_str() {
        "not-allowed" => "Your role does not allow that.",
        "leased" => "A grund machine goes back when its lease ends; it cannot be removed here.",
        "gone" => "That machine or VM is no longer there.",
        "label-key" => {
            "A label key is 1 to 63 lowercase letters, digits, '.', '-', '_' or '/', starting and ending with a letter or digit."
        }
        "label-value" => "A label value is at most 63 letters, digits, '.', '-' or '_'.",
        "label-many" => "A machine has at most 16 labels.",
        _ => "",
    };
    machines_view(
        &state,
        &member.browser,
        &member.session,
        &member.membership,
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

fn machine_context(row: &MachineRow, copies: i64, now: chrono::DateTime<Utc>) -> Value {
    let capabilities = row.capabilities.as_ref().map(|c| &c.0);
    let labels: Vec<String> = row
        .labels
        .0
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let pairs: Vec<(String, String)> = row
        .labels
        .0
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let copies_words = match copies {
        0 => "no copies".to_string(),
        1 => "1 copy".to_string(),
        n => format!("{n} copies"),
    };
    context! {
        labels, pairs, copies_words,
        out_of_service => row.cordoned_at.is_some(),
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
    let copies = grund_store::apps::copies_per_machine(&state.pool, membership.organisation_id)
        .await
        .map_err(anyhow::Error::from)?;
    let machines: Vec<Value> = rows
        .iter()
        .map(|row| {
            let n = copies
                .iter()
                .find(|(id, _)| *id == row.machine_id)
                .map_or(0, |(_, n)| *n);
            machine_context(row, n, now)
        })
        .collect();
    let hosts: Vec<(String, String)> = rows
        .iter()
        .filter(|row| cannot_host(row).is_none() && connected(row.last_seen_at, now))
        .map(|row| {
            (
                row.machine_id.to_string(),
                row.pool_name.clone().unwrap_or_else(|| row.name.clone()),
            )
        })
        .collect();
    let vms: Vec<Value> = state
        .agents()
        .vms(membership.organisation_id)
        .await?
        .iter()
        .map(vm_context)
        .collect();
    let mut run = form.run;
    if run.is_fresh() {
        let defaults = &state.config.machine_defaults;
        let or_empty = |value: &Option<String>| value.clone().unwrap_or_default();
        run.kernel_url = or_empty(&defaults.vm_kernel_url);
        run.kernel_sha256 = or_empty(&defaults.vm_kernel_sha256);
        run.rootfs_url = or_empty(&defaults.vm_rootfs_url);
        run.rootfs_sha256 = or_empty(&defaults.vm_rootfs_sha256);
    }
    signed_in(
        state,
        browser,
        session,
        Some(membership),
        status,
        "pages/machines.html.jinja",
        "machines",
        context! {
            label_keys => rows.iter().flat_map(|r| r.labels.0.keys().cloned()).collect::<std::collections::BTreeSet<_>>(),
            label_values => rows.iter().flat_map(|r| r.labels.0.values().cloned()).collect::<std::collections::BTreeSet<_>>(),
            machines, hosts, vms,
            operator => state.machines().operator().await? == Some(membership.organisation_id),
            notice => form.notice, error => form.error,
            setup => form.setup, add_error => form.add_error, name => form.name,
            run_error => form.run_error, run => Value::from_serialize(&run),
        },
    )
    .await
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
            let defaults = &state.config.machine_defaults;
            let install = match &defaults.agent_install_url {
                Some(url) => Some(format!(
                    "curl -fsSL {url} | sudo sh -s -- --url {origin} --code {}",
                    minted.token
                )),
                None if defaults.serve_installer => Some(format!(
                    "curl -fsSL {origin}/install | sudo sh -s -- --url {origin} --code {} \
                     --from-instance",
                    minted.token
                )),
                None => None,
            };
            page.setup = Some(context! {
                install,
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

#[derive(Deserialize)]
pub struct ServiceForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    in_service: String,
}

/// `POST /{org}/machines/{machine}/service`: takes a machine out of
/// service (`in_service=no`), so its copies move to other machines
/// (grund-docs design/apps.md §5.7), or puts it back (`yes`).
pub async fn service(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, machine_id)): Path<(String, Uuid)>,
    Form(form): Form<ServiceForm>,
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
    let in_service = form.in_service == "yes";
    let query = match machines
        .set_in_service(
            session.account_id,
            machine_id,
            membership.organisation_id,
            in_service,
        )
        .await?
    {
        ChangeOutcome::Done(_) if in_service => "done=in-service",
        ChangeOutcome::Done(_) => "done=out-of-service",
        _ => "error=gone",
    };
    Ok(redirect(&format!("/{slug}/machines?{query}")))
}

/// `POST /{org}/machines/{machine}/labels`: replaces a machine's labels,
/// posted as rows (`labels_key`/`labels_value`); a row with no key is
/// dropped.
pub async fn labels(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, machine_id)): Path<(String, Uuid)>,
    Form(posted): Form<Vec<(String, String)>>,
) -> PageResult {
    let csrf = posted
        .iter()
        .find(|(k, _)| k == "csrf")
        .map(|(_, v)| v.as_str())
        .unwrap_or_default();
    if !browser.form_is_genuine(csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/machines?error=not-allowed")));
    }
    let keys = posted
        .iter()
        .filter(|(k, _)| k == "labels_key")
        .map(|(_, v)| v);
    let mut values = posted
        .iter()
        .filter(|(k, _)| k == "labels_value")
        .map(|(_, v)| v.as_str());
    let pairs: Vec<(&str, &str)> = keys
        .map(|k| (k.as_str(), values.next().unwrap_or_default()))
        .filter(|(k, _)| !k.trim().is_empty())
        .collect();
    let labels = match grund_domain::labels::labels(pairs) {
        Ok(labels) => labels,
        Err(error) => {
            let code = match error {
                grund_domain::labels::LabelError::Key => "label-key",
                grund_domain::labels::LabelError::Value => "label-value",
                grund_domain::labels::LabelError::TooMany => "label-many",
            };
            return Ok(redirect(&format!("/{slug}/machines?error={code}#labels")));
        }
    };
    let machines = state.machines();
    if machines
        .organisation_machine(membership.organisation_id, machine_id)
        .await?
        .is_none()
    {
        return Ok(redirect(&format!("/{slug}/machines?error=gone")));
    }
    let query = match machines
        .set_labels(
            session.account_id,
            machine_id,
            membership.organisation_id,
            labels,
        )
        .await?
    {
        ChangeOutcome::Done(_) => "done=labels",
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

impl RunForm {
    fn is_fresh(&self) -> bool {
        [
            &self.host,
            &self.vm_name,
            &self.vcpus,
            &self.memory_mib,
            &self.disk_gib,
            &self.kernel_url,
            &self.kernel_sha256,
            &self.rootfs_url,
            &self.rootfs_sha256,
        ]
        .iter()
        .all(|field| field.is_empty())
    }
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
