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
use grund_domain::{
    machine::{Authority, TOKEN_TTL, TokenKind},
    organisation::Role,
};
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
        pages::{PageResult, forged, redirect, signed_in},
    },
};

fn manages(membership: &Membership) -> bool {
    Role::parse(&membership.role).is_some_and(|role| role.manages_members())
}

/// The query of `/{org}/machines`: a notice, the tab (`disconnected`), the
/// search and the machine whose labels are open, so every part works
/// without the script.
#[derive(Deserialize, Default)]
pub struct MachinesQuery {
    #[serde(default)]
    done: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    tab: String,
    #[serde(default)]
    q: String,
    #[serde(default)]
    labels: String,
    #[serde(default)]
    run: String,
}

/// `/{org}/machines`.
pub async fn machines_page(
    AxumState(state): AxumState<State>,
    member: Member,
    Query(query): Query<MachinesQuery>,
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
            tab: if query.tab == DISCONNECTED {
                DISCONNECTED
            } else {
                ""
            },
            q: query.q.trim().to_lowercase(),
            labels: query.labels,
            run: RunForm {
                host: query.run,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
}

const DISCONNECTED: &str = "disconnected";

#[derive(Default)]
struct MachinesForm<'a> {
    notice: &'a str,
    error: &'a str,
    tab: &'a str,
    q: String,
    labels: String,
    run_error: String,
    run: RunForm,
}

fn machine_status(row: &MachineRow, now: chrono::DateTime<Utc>) -> (&'static str, &'static str) {
    if row.cordoned_at.is_some() {
        ("Out of service", "muted")
    } else if connected(row.last_seen_at, now) {
        ("Connected", "ok")
    } else if row.last_seen_at.is_none() {
        ("Joining", "blue")
    } else {
        ("Disconnected", "orange")
    }
}

fn human_size(mib: u64) -> String {
    let one = |value: f64, places: usize| {
        let text = format!("{value:.places$}");
        text.strip_suffix(".0").unwrap_or(&text).to_string()
    };
    let gib = mib as f64 / 1024.0;
    if mib < 1024 {
        format!("{mib} MB")
    } else if gib < 1024.0 {
        format!("{} GB", one(gib, usize::from(gib < 10.0)))
    } else {
        format!("{} TB", one(gib / 1024.0, 1))
    }
}

fn machine_facts(
    capabilities: Option<&serde_json::Value>,
    joined_facts: &serde_json::Value,
) -> [(&'static str, String); 3] {
    let reported = |key: &str| {
        capabilities
            .and_then(|c| c[key].as_u64())
            .filter(|n| *n > 0)
    };
    let joined = |key: &str| joined_facts[key].as_u64().filter(|n| *n > 0);
    let vcpus = reported("cpu_millis")
        .or_else(|| joined("cpus").map(|cpus| cpus * 1000))
        .map(|millis| {
            let text = format!("{:.1}", millis as f64 / 1000.0);
            format!("{} vCPU", text.strip_suffix(".0").unwrap_or(&text))
        });
    let memory = reported("memory_mib")
        .or_else(|| joined("memory_mib"))
        .map(|mib| format!("{} RAM", human_size(mib)));
    let disk = reported("disk_gib")
        .or_else(|| joined("disk_gib"))
        .map(|gib| human_size(gib * 1024));
    [
        ("cpu", vcpus.unwrap_or_default()),
        ("memory", memory.unwrap_or_default()),
        ("disk", disk.unwrap_or_default()),
    ]
}

fn machine_context(
    row: &MachineRow,
    copies: i64,
    now: chrono::DateTime<Utc>,
    form: &MachinesForm<'_>,
) -> Value {
    let capabilities = row.capabilities.as_ref().map(|c| &c.0);
    let labels: Vec<String> = row
        .labels
        .0
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let name = row.pool_name.clone().unwrap_or_else(|| row.name.clone());
    let (status, tone) = machine_status(row, now);
    let tab = if status == "Disconnected" {
        DISCONNECTED
    } else {
        ""
    };
    let search = std::iter::once(name.to_lowercase())
        .chain(labels.iter().map(|label| label.to_lowercase()))
        .collect::<Vec<_>>()
        .join(" ");
    let shown = (form.tab.is_empty() || form.tab == tab) && search.contains(&form.q);
    let detail = match status {
        "Out of service" => match copies {
            0 => "no copies".to_string(),
            1 => "1 copy".to_string(),
            n => format!("{n} copies"),
        },
        "Disconnected" => row
            .last_seen_at
            .map(|at| format!("last seen {}", at.format("%-d %b %Y %H:%M UTC")))
            .unwrap_or_default(),
        _ => String::new(),
    };
    context! {
        labels, status, tone, tab, search, shown, detail, name,
        id => row.machine_id.to_string(),
        out_of_service => row.cordoned_at.is_some(),
        leased => row.pool == "management",
        facts => machine_facts(capabilities, &row.facts.0),
        kvm => capabilities.and_then(|c| c["kvm"].as_bool()).unwrap_or(false),
        hosts_vms => cannot_host(row).is_none() && connected(row.last_seen_at, now),
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
            machine_context(row, n, now, &form)
        })
        .collect();
    let disconnected = rows
        .iter()
        .filter(|row| machine_status(row, now).0 == "Disconnected")
        .count();
    let shown = machines
        .iter()
        .filter(|machine| machine.get_attr("shown").is_ok_and(|shown| shown.is_true()))
        .count();
    let editing = rows
        .iter()
        .find(|row| row.machine_id.to_string() == form.labels)
        .map(|row| {
            let pairs: Vec<(String, String)> = row
                .labels
                .0
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            context! {
                pairs,
                id => row.machine_id.to_string(),
                name => row.pool_name.clone().unwrap_or_else(|| row.name.clone()),
            }
        });
    let base = format!("/{}/machines", membership.slug);
    let href = |tab: &str| {
        let pairs: Vec<(&str, &str)> = [("tab", tab), ("q", form.q.as_str())]
            .into_iter()
            .filter(|(_, value)| !value.is_empty())
            .collect();
        match serde_urlencoded::to_string(pairs).unwrap_or_default() {
            query if query.is_empty() => base.clone(),
            query => format!("{base}?{query}"),
        }
    };
    let operator = state.machines().operator().await? == Some(membership.organisation_id);
    let mut tabs = vec![
        ("", href(""), "All machines"),
        (DISCONNECTED, href(DISCONNECTED), "Disconnected"),
    ];
    if operator {
        tabs.push((
            "pool",
            format!("/{}/pool", membership.slug),
            "Management pool",
        ));
    }
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
    let run_open = !form.run_error.is_empty() || hosts.iter().any(|(id, _)| *id == run.host);
    if run.is_fresh() || (run_open && form.run_error.is_empty()) {
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
            machines, hosts, vms, editing, disconnected, shown, tabs, operator, run_open,
            tab => form.tab, q => form.q,
            notice => form.notice, error => form.error,
            run_error => form.run_error, run => Value::from_serialize(&run),
        },
    )
    .await
}

/// `/{org}/machines/add`: the form that makes a setup code. A role that
/// cannot add machines is sent back to the list, as its POST would be.
pub async fn add_page(AxumState(state): AxumState<State>, member: Member) -> PageResult {
    if !manages(&member.membership) {
        let slug = &member.membership.slug;
        return Ok(redirect(&format!("/{slug}/machines?error=not-allowed")));
    }
    member
        .render(
            &state,
            "pages/machine-add.html.jinja",
            "machine-add",
            context! { setup => None::<Value>, add_error => "", name => "", minutes => TOKEN_TTL.num_minutes() },
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
/// answers with and nowhere else. A refused name answers 422 with the
/// form again.
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
    let mut name = form.name.clone();
    let mut setup = None;
    let add_error = match outcome {
        MintOutcome::Minted(minted) => {
            let origin = state.config.public_origin().serialized;
            let minutes = ((minted.expires_at - Utc::now()).num_seconds() + 59)
                .div_euclid(60)
                .max(1);
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
            setup = Some(context! {
                install,
                command => format!("grund join --url {origin} {}", minted.token),
                minutes,
            });
            name = String::new();
            String::new()
        }
        MintOutcome::Invalid(message) => message,
        MintOutcome::TooMany => {
            "This organisation has 20 unused setup codes. Wait for some to expire.".into()
        }
        MintOutcome::NotReturning | MintOutcome::NotFound => {
            "grund could not make a setup code. Try again.".into()
        }
    };
    let status = if add_error.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let mut response = signed_in(
        &state,
        &browser,
        &session,
        Some(&membership),
        status,
        "pages/machine-add.html.jinja",
        "machine-add",
        context! { setup, add_error, name, minutes => TOKEN_TTL.num_minutes() },
    )
    .await?;
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
            return Ok(redirect(&format!(
                "/{slug}/machines?labels={machine_id}&error={code}#labels"
            )));
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn sizes_read_in_the_largest_unit_with_a_decimal_only_below_ten() {
        assert_eq!(human_size(512), "512 MB");
        assert_eq!(human_size(7_782), "7.6 GB");
        assert_eq!(human_size(65_536), "64 GB");
        assert_eq!(human_size(64_200), "63 GB");
        assert_eq!(human_size(1_258_291), "1.2 TB");
        assert_eq!(human_size(2 * 1024 * 1024), "2 TB");
    }

    #[test]
    fn the_heartbeat_wins_over_the_join_and_a_size_never_reported_is_left_empty() {
        let joined = json!({"cpus": 4, "memory_mib": 8192, "disk_gib": 0});
        assert_eq!(
            machine_facts(None, &joined).map(|(_, text)| text),
            ["4 vCPU", "8 GB RAM", ""]
        );
        let beat = json!({"cpu_millis": 15_500, "memory_mib": 65_536, "disk_gib": 1_200});
        assert_eq!(
            machine_facts(Some(&beat), &joined).map(|(_, text)| text),
            ["15.5 vCPU", "64 GB RAM", "1.2 TB"]
        );
        let old_agent = json!({"cpu_millis": 2_000, "memory_mib": 4096});
        assert_eq!(machine_facts(Some(&old_agent), &json!({}))[2].1, "");
    }
}
