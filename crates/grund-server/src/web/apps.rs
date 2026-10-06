//! `/{org}/apps`: an organisation's apps (searched, sorted, as a list or a
//! grid), `/{org}/deploy` for a new app, and each app's page with its
//! copies, its rollout, its releases and the forms that deploy, scale, roll
//! back and set secrets (grund-docs design/apps.md §8.5, §5.4, §9). Also
//! `/{org}/templates`, the premade apps Deploy app also offers
//! (`grund_domain::app::templates`). Every member sees the pages; owners and
//! admins change. The handlers call the same service as
//! `grund.app.v1.AppService`, so the pages and the API refuse the same
//! things.

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use grund_domain::app::ReleaseSource;
use grund_domain::{
    app::{
        file::{SCHEMA_PATH, render as render_file},
        spec::{
            AppSpec, CheckKind, CheckSpec, EnvVar, MAX_COPIES, PortSpec, Protocol, STOP_SIGNALS,
            SecretEnv, SettingsInput, StopSpec,
        },
        templates,
    },
    organisation::Role,
};
use grund_store::{
    apps::{ReleaseRow, ReplicaRow},
    organisations::Membership,
};
use minijinja::{Value, context};
use serde::Deserialize;

use crate::{
    services::{
        apps::{AppListing, AppView, AppsError, AppsState, Change, DeployInput, Launch},
        domains::DomainsState,
        sessions::Session,
    },
    state::State,
    web::{
        browser::Browser,
        orgs::Member,
        pages::{PageError, PageResult, forged, redirect, signed_in},
    },
};

fn manages(membership: &Membership) -> bool {
    Role::parse(&membership.role).is_some_and(|role| role.manages_members())
}

fn when(at: DateTime<Utc>) -> String {
    at.format("%-d %b %Y %H:%M UTC").to_string()
}

fn connected(seen: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    seen.is_some_and(|seen| now - seen <= chrono::Duration::seconds(30))
}

fn copies(n: usize) -> String {
    if n == 1 {
        "1 copy".into()
    } else {
        format!("{n} copies")
    }
}

fn replica_words(replica: &ReplicaRow, now: DateTime<Utc>) -> (String, &'static str) {
    let machine = replica
        .machine_name
        .clone()
        .unwrap_or_else(|| "its machine".into());
    if !connected(replica.last_seen_at, now) {
        return (format!("{machine} is not responding"), "orange");
    }
    if replica.state == "draining" {
        return ("Finishing its requests".into(), "muted");
    }
    let reason = replica.reason.clone().unwrap_or_default();
    match replica.observed_state.as_deref() {
        None => ("Waiting for its machine".into(), "muted"),
        Some("pulling") if reason.is_empty() => ("Fetching its image".into(), "muted"),
        Some("pulling") => (capitalise(&reason), "orange"),
        Some("starting") => ("Starting".into(), "muted"),
        Some("running") if replica.ready == Some(true) => ("Ready".into(), "ok"),
        Some("running") if reason.is_empty() => ("Running, not ready yet".into(), "muted"),
        Some("running") => (format!("Not ready: {reason}"), "orange"),
        Some("exited") => (
            format!(
                "Keeps stopping (exit code {}, {} restarts). grund restarts it.",
                replica.last_exit_code.unwrap_or(0),
                replica.restarts.unwrap_or(0)
            ),
            "orange",
        ),
        Some("refused") => (format!("{machine} refused it: {reason}"), "orange"),
        Some("failed") => (capitalise(&reason), "orange"),
        Some("stopping") => ("Stopping".into(), "muted"),
        Some(other) => (capitalise(other), "muted"),
    }
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

fn ago(at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let seconds = (now - at).num_seconds().max(0);
    let (n, unit) = match seconds {
        0..60 => return "just now".into(),
        60..3_600 => (seconds / 60, "minute"),
        3_600..86_400 => (seconds / 3_600, "hour"),
        86_400..2_592_000 => (seconds / 86_400, "day"),
        _ => return at.format("%-d %b %Y").to_string(),
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

struct Health {
    word: &'static str,
    tone: &'static str,
}

fn ready_copies(view: &AppView, release: i64, now: DateTime<Utc>) -> usize {
    view.replicas
        .iter()
        .filter(|r| {
            r.release as i64 == release
                && r.state == "running"
                && r.ready == Some(true)
                && connected(r.last_seen_at, now)
        })
        .count()
}

fn health(view: &AppView, now: DateTime<Utc>) -> Health {
    let row = &view.row;
    let wanted = row.settings.0.copies as usize;
    let current = row.current_release.map(i64::from);
    let ready = current.map_or(0, |c| ready_copies(view, c, now));
    let (word, tone) = match row.rollout.as_ref().and_then(|r| r["state"].as_str()) {
        _ if row.halted => ("Failed", "danger"),
        Some("in_progress") => ("Rolling out", "blue"),
        Some("failed") => ("Failed", "danger"),
        _ => match current {
            None => ("Stopped", "muted"),
            Some(_) if ready >= wanted => ("Live", "ok"),
            Some(_) => ("Degraded", "orange"),
        },
    };
    Health { word, tone }
}

/// The icon a page draws for `image`: a well-known image's own, `docker`
/// for any other image on Docker Hub, and `image` for one from elsewhere.
pub fn image_icon(image: &str) -> &'static str {
    const KNOWN: &[(&str, &[&str])] = &[
        ("nginx", &["nginx", "nginx-unprivileged", "openresty"]),
        (
            "postgres",
            &[
                "postgres",
                "postgresql",
                "postgis",
                "timescaledb",
                "timescaledb-ha",
            ],
        ),
        ("redis", &["redis", "redis-stack", "redis-stack-server"]),
        ("nats", &["nats", "nats-streaming", "nats-server"]),
        ("clickhouse", &["clickhouse", "clickhouse-server"]),
        ("mongo", &["mongo", "mongodb", "mongodb-community-server"]),
        ("node", &["node"]),
        ("python", &["python"]),
        ("prometheus", &["prometheus"]),
        ("rabbitmq", &["rabbitmq"]),
    ];
    let reference = image.split('@').next().unwrap_or_default().trim();
    let mut parts: Vec<&str> = reference.split('/').collect();
    let registry = (parts.len() > 1
        && (parts[0].contains('.') || parts[0].contains(':') || parts[0] == "localhost"))
        .then(|| parts.remove(0));
    let hosted = registry.is_some_and(|host| {
        !matches!(
            host,
            "docker.io" | "index.docker.io" | "registry-1.docker.io"
        )
    });
    let name = parts
        .last()
        .and_then(|last| last.split(':').next())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let known = KNOWN
        .iter()
        .find(|(_, names)| names.contains(&name.as_str()));
    match known {
        Some((icon, _)) => icon,
        None if reference.is_empty() || hosted => "image",
        None => "docker",
    }
}

fn internal_address(name: &str, spec: &AppSpec) -> Option<String> {
    spec.ports
        .first()
        .map(|port| format!("{name}.grund.internal:{}", port.port))
}

/// An app as a list row or card shows it.
pub fn listing_context(listing: &AppListing) -> Value {
    let view = &listing.view;
    let Health { tone, .. } = health(view, Utc::now());
    let image = listing
        .spec
        .as_ref()
        .map(|spec| spec.image.clone())
        .unwrap_or_default();
    context! {
        name => view.row.name,
        tone,
        copies => view.row.settings.0.copies,
        icon => image_icon(&image),
        image,
        address => listing.address,
        internal => listing.spec.as_ref().and_then(|spec| internal_address(&view.row.name, spec)),
    }
}

/// The distinct icons of `listings`, for the page's sprite.
pub fn icons_of(listings: &[&AppListing]) -> Vec<&'static str> {
    let mut icons: Vec<&'static str> = listings
        .iter()
        .map(|l| {
            image_icon(
                l.spec
                    .as_ref()
                    .map(|s| s.image.as_str())
                    .unwrap_or_default(),
            )
        })
        .collect();
    icons.sort_unstable();
    icons.dedup();
    icons
}

const SORTS: &[(&str, &str)] = &[
    ("name", "Name"),
    ("deployed", "Last deployed"),
    ("created", "Newest"),
];

fn sort_listings(listings: &mut [&AppListing], sort: &str) {
    match sort {
        "deployed" => listings.sort_by(|a, b| {
            b.deployed_at
                .cmp(&a.deployed_at)
                .then_with(|| a.view.row.name.cmp(&b.view.row.name))
        }),
        "created" => listings.sort_by(|a, b| {
            b.view
                .row
                .created_at
                .cmp(&a.view.row.created_at)
                .then_with(|| a.view.row.name.cmp(&b.view.row.name))
        }),
        _ => listings.sort_by(|a, b| a.view.row.name.cmp(&b.view.row.name)),
    }
}

fn matches(listing: &AppListing, query: &str) -> bool {
    query.is_empty()
        || listing.view.row.name.contains(query)
        || listing
            .spec
            .as_ref()
            .is_some_and(|spec| spec.image.to_ascii_lowercase().contains(query))
}

struct ReleaseWords {
    by: String,
    verb: String,
    source: &'static str,
}

fn release_words(row: &ReleaseRow) -> ReleaseWords {
    ReleaseWords {
        by: row
            .created_by_name
            .clone()
            .unwrap_or_else(|| "someone".into()),
        verb: match row.rollback_of {
            Some(number) if row.source == "rollback" => format!("Rolled back to v{number}"),
            _ => "Deployed".into(),
        },
        source: match row.source.as_str() {
            "dashboard" => "from the dashboard",
            "api" => "from the API",
            "file" => "from grund.yaml",
            _ => "",
        },
    }
}

fn release_context(row: &ReleaseRow, current: Option<i32>, now: DateTime<Utc>) -> Value {
    let (outcome, tone, title, state, result) = match row.outcome.as_deref() {
        Some("rolling_out") => ("Releasing", "blue", "Rolling out", "busy", "Rolling out"),
        Some("live") => (
            "Live",
            "ok",
            "Deployment successful",
            "ok",
            "Deployed successfully",
        ),
        Some("replaced") => (
            "Replaced",
            "muted",
            "Deployment successful",
            "",
            "Deployed successfully",
        ),
        Some("failed") => (
            "Failed",
            "danger",
            "Deployment failed",
            "failed",
            "Failed to start",
        ),
        Some("superseded") => (
            "Superseded",
            "muted",
            "Superseded by a newer release",
            "",
            "Superseded",
        ),
        _ => (
            "Made",
            "muted",
            "Waiting to roll out",
            "",
            "Waiting to roll out",
        ),
    };
    let words = release_words(row);
    let digest = row.image_digest.trim_start_matches("sha256:");
    context! {
        event => match row.rollback_of {
            Some(number) if row.source == "rollback" => format!("v{} · rolled back to v{number}", row.number),
            _ => format!("v{} · deployed", row.number),
        },
        short_digest => digest.chars().take(12).collect::<String>(),
        number => row.number,
        image => row.spec.0.image,
        digest => row.image_digest,
        by => words.by,
        verb => words.verb,
        source => words.source,
        at => when(row.created_at),
        ago => ago(row.created_at, now),
        iso => row.created_at.to_rfc3339(),
        note => row.note,
        outcome, tone, title, state, result,
        reason => row.reason,
        live => row.outcome.as_deref() == Some("live"),
        again => if current.is_some_and(|c| row.number < c) { "Roll back to this" } else { "Run this again" },
    }
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    #[serde(default)]
    done: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    q: String,
    #[serde(default)]
    sort: String,
    #[serde(default)]
    view: String,
}

fn notice_words(done: &str) -> &'static str {
    match done {
        "created" => "App made. Its first release is rolling out.",
        "deployed" => "New release made. It is rolling out.",
        "released-file" => "grund.yaml applied as a new release. It is rolling out.",
        "released" => "Saved as a new release. It is rolling out.",
        "saved" => "Saved.",
        "secret" => "Secret stored. A release that reads it is rolling out.",
        "secret-removed" => "Secret removed. A release without it is rolling out.",
        "rolled-back" => "Rolling back, as a new release.",
        "deleted" => "App deleted. Its copies are stopping.",
        _ => "",
    }
}

fn error_words(error: &str) -> &'static str {
    match error {
        "not-allowed" => "Your role does not allow that.",
        "gone" => "That app is no longer there.",
        "no-release" => "It has no release to change yet.",
        _ => "",
    }
}

/// `/{org}/apps`, searched by `q`, ordered by `sort` and drawn as `view`
/// (`list` or `grid`).
pub async fn apps_page(
    AxumState(state): AxumState<State>,
    Member {
        browser,
        session,
        membership,
    }: Member,
    Query(query): Query<ListQuery>,
) -> PageResult {
    let listings = state
        .apps()
        .listings(membership.organisation_id, &membership.slug)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    let q: String = query
        .q
        .trim()
        .to_ascii_lowercase()
        .chars()
        .take(100)
        .collect();
    let sort = SORTS
        .iter()
        .find(|(value, _)| *value == query.sort)
        .map_or("name", |(value, _)| value);
    let view = if query.view == "grid" { "grid" } else { "list" };
    let mut shown: Vec<&AppListing> = listings.iter().filter(|l| matches(l, &q)).collect();
    sort_listings(&mut shown, sort);
    let href = |q: &str, view: &str| {
        let mut pairs = Vec::new();
        if !q.is_empty() {
            pairs.push(("q", q));
        }
        pairs.extend([("sort", sort), ("view", view)]);
        format!(
            "/{}/apps?{}",
            membership.slug,
            serde_urlencoded::to_string(pairs).unwrap_or_default()
        )
    };
    signed_in(
        &state,
        &browser,
        &session,
        Some(&membership),
        StatusCode::OK,
        "pages/apps.html.jinja",
        "apps",
        context! {
            list_href => href(&q, "list"), grid_href => href(&q, "grid"), all_href => href("", view),
            icons => icons_of(&shown),
            apps => shown.iter().map(|l| listing_context(l)).collect::<Vec<_>>(),
            total => listings.len(),
            list => context! { q, sort, view }, sorts => SORTS,
            notice => notice_words(&query.done), error => error_words(&query.error),
        },
    )
    .await
}

/// Which mode `/{org}/deploy` shows, and the template it starts on.
#[derive(Deserialize, Default)]
pub struct DeployQuery {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    template: String,
}

/// `/{org}/deploy`: Deploy app, as a custom image or a premade app. The
/// mode is a query parameter, so the switch works without the script.
pub async fn deploy_page(
    AxumState(state): AxumState<State>,
    Member {
        browser,
        session,
        membership,
    }: Member,
    Query(query): Query<DeployQuery>,
) -> PageResult {
    let template = templates::find(&query.template).filter(|t| !t.needs_storage);
    let premade = query.mode == "premade" || template.is_some();
    let form = NewForm {
        mode: if premade { "premade" } else { "custom" }.into(),
        template: template.map(|t| t.key.to_string()).unwrap_or_default(),
        name: template.map(|t| t.key.to_string()).unwrap_or_default(),
        ..NewForm::default()
    };
    new_view(
        &state,
        &browser,
        &session,
        &membership,
        form,
        Refusal::default(),
        None,
    )
    .await
}

#[derive(Default)]
struct Refusal {
    banner: String,
    fields: std::collections::BTreeMap<&'static str, String>,
}

impl Refusal {
    fn field(field: &'static str, message: impl Into<String>) -> Self {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(field, message.into());
        Self {
            banner: "Nothing was deployed. Check the field marked below.".into(),
            fields,
        }
    }

    fn banner(message: impl Into<String>) -> Self {
        Self {
            banner: message.into(),
            fields: Default::default(),
        }
    }
}

const FORM_FIELDS: &[&str] = &[
    "template", "name", "image", "exposure", "port", "copies", "env", "secrets", "check", "memory",
    "cpu", "command", "stop",
];

const ADVANCED_FIELDS: &[&str] = &[
    "env", "secrets", "check", "memory", "cpu", "command", "stop",
];

fn form_field(spec_field: &str) -> Option<&'static str> {
    let head = spec_field.split(['.', '[']).next().unwrap_or_default();
    Some(match head {
        "name" => "name",
        "image" => "image",
        "copies" | "rollout" | "reschedule_after_seconds" => "copies",
        "ports" | "port" => "port",
        "env" => "env",
        "secrets" | "secret" | "value" => "secrets",
        "check" => "check",
        "resources" if spec_field.ends_with("memory_mib") => "memory",
        "resources" => "cpu",
        "command" => "command",
        "stop" => "stop",
        "machines" | "placement" => "placement",
        _ => return None,
    })
}

fn line_of(spec_field: &str) -> Option<usize> {
    let index = spec_field.split_once('[')?.1.split_once(']')?.0;
    index.parse::<usize>().ok().map(|i| i + 1)
}

fn refusal(error: &AppsError) -> Refusal {
    match error {
        AppsError::Spec(spec) => {
            let problem = capitalise(&spec.problem);
            let message = match (form_field(&spec.field), line_of(&spec.field)) {
                (Some("env" | "secrets"), Some(line)) => {
                    format!("Row {line}: {}.", spec.problem)
                }
                (Some("command"), Some(line)) => format!("Line {line}: {}.", spec.problem),
                _ => format!("{problem}."),
            };
            match form_field(&spec.field) {
                Some(field) => Refusal::field(field, message),
                None => Refusal::banner(format!("{}: {}.", spec.field, spec.problem)),
            }
        }
        AppsError::NameTaken => Refusal::field(
            "name",
            "An app of that name already exists here. Choose another.",
        ),
        AppsError::ImageUnresolved(message) | AppsError::ImageUnsupported(message) => {
            Refusal::field("image", format!("{message}."))
        }
        other => Refusal::banner(sentence(other)),
    }
}

fn exposures(app_domain: Option<&str>) -> Vec<Value> {
    let public = match app_domain {
        Some(domain) => context! {
            value => "public", title => "Public HTTP", icon => "globe",
            text => format!("Via a {domain} address"),
        },
        None => context! {
            value => "public", title => "Public HTTP", icon => "globe", disabled => true,
            tag => "Not set up", text => "This instance gives apps no address of their own",
        },
    };
    vec![
        context! { value => "private", title => "Private", icon => "lock", text => "Only other apps reach it" },
        public,
    ]
}

/// A premade app's image icon: its image's, or its key's while it has none.
pub fn template_icon(template: &templates::Template) -> &'static str {
    image_icon(if template.image.is_empty() {
        template.key
    } else {
        template.image
    })
}

fn template_icons() -> Vec<&'static str> {
    let mut icons: Vec<&'static str> = templates::CATALOGUE.iter().map(template_icon).collect();
    icons.sort_unstable();
    icons.dedup();
    icons
}

const NEEDS_STORAGE: &str = "Needs storage";

/// A premade app as the Templates page shows it.
pub fn template_context(template: &templates::Template) -> Value {
    context! {
        key => template.key,
        title => template.title,
        summary => template.summary,
        icon => template_icon(template),
        soon => template.needs_storage.then_some(NEEDS_STORAGE),
    }
}

struct Changing {
    name: String,
    secrets: Vec<String>,
}

async fn new_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    new: NewForm,
    refused: Refusal,
    change: Option<Changing>,
) -> PageResult {
    let slug = &membership.slug;
    let choices: Vec<Value> = templates::CATALOGUE
        .iter()
        .map(|t| {
            context! {
                value => t.key, title => t.title, text => t.summary, image => template_icon(t),
                disabled => t.needs_storage, tag => t.needs_storage.then_some(NEEDS_STORAGE),
            }
        })
        .collect();
    let premade = new.mode == "premade";
    let mode_href = |mode: &str| format!("/{slug}/deploy?mode={mode}");
    let advanced = refused
        .fields
        .keys()
        .any(|field| ADVANCED_FIELDS.contains(field));
    let secrets_dropped = !refused.banner.is_empty() && !new.secrets.is_empty();
    let errors: std::collections::BTreeMap<&str, &str> = FORM_FIELDS
        .iter()
        .map(|field| (*field, refused.fields.get(field).map_or("", String::as_str)))
        .collect();
    signed_in(
        state,
        browser,
        session,
        Some(membership),
        if refused.banner.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        },
        "pages/deploy.html.jinja",
        "deploy",
        context! {
            mode => if premade { "premade" } else { "custom" },
            modes => vec![
                context! {
                    key => "premade", href => mode_href("premade"), icon => "grid", title => "Premade",
                    text => "A pinned version of a common app", sub => "NATS, whoami, nginx",
                },
                context! {
                    key => "custom", href => mode_href("custom"), icon => "box", title => "Custom",
                    text => "Any container image", sub => "",
                },
            ],
            new => Value::from_serialize(&new),
            new_error => refused.banner.clone(), errors,
            advanced, secrets_dropped,
            exposures => exposures(state.config.entry.app_domain.as_deref()),
            public_hint => state.config.entry.app_domain.as_deref().map(|domain| format!("Public: https://{}-{slug}.{domain}", change.as_ref().map_or("<name>", |c| c.name.as_str()))).unwrap_or_default(),
            change => change.as_ref().map(|c| context! { name => c.name, base => format!("/{slug}/apps/{}", c.name) }),
            secrets_kept => change.as_ref().map(|c| c.secrets.join(", ")).unwrap_or_default(),
            templates => choices, image_keys => template_icons(),
            signals => STOP_SIGNALS.iter().map(|s| (*s, *s)).collect::<Vec<_>>(),
            checks => [("", "None"), ("http", "HTTP request"), ("tcp", "TCP connection")],
            other_mode => mode_href(if premade { "custom" } else { "premade" }),
            templates_href => format!("/{slug}/templates"),
            action => change.as_ref().map_or(format!("/{slug}/deploy"), |c| format!("/{slug}/apps/{}/deploy", c.name)),
        },
    )
    .await
}

/// `/{org}/templates`: the premade apps, the same list Deploy app offers.
pub async fn templates_page(
    AxumState(state): AxumState<State>,
    Member {
        browser,
        session,
        membership,
    }: Member,
) -> PageResult {
    let shown: Vec<Value> = templates::CATALOGUE.iter().map(template_context).collect();
    signed_in(
        &state,
        &browser,
        &session,
        Some(&membership),
        StatusCode::OK,
        "pages/templates.html.jinja",
        "templates",
        context! {
            templates => shown, image_keys => template_icons(),
        },
    )
    .await
}

/// The Deploy app form, in either mode, and the parts of an app's
/// Settings that make a release. Its environment and secrets post as rows
/// (`env_key`/`env_value`, `secrets_key`/`secrets_value`), so it is read
/// with [`NewForm::from_pairs`]. `secrets` is never written back into the
/// page.
#[derive(Deserialize, Default, serde::Serialize)]
pub struct NewForm {
    #[serde(default, skip_serializing)]
    csrf: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    template: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    exposure: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    copies: String,
    #[serde(skip_deserializing)]
    env: Vec<(String, String)>,
    #[serde(skip)]
    secrets: Vec<(String, String)>,
    #[serde(default)]
    check: String,
    #[serde(default)]
    check_path: String,
    #[serde(default)]
    memory: String,
    #[serde(default)]
    cpu: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    stop_signal: String,
    #[serde(default)]
    stop_grace: String,
    #[serde(default, skip_serializing)]
    part: String,
}

fn nonzero(n: impl Into<u64>) -> String {
    match n.into() {
        0 => String::new(),
        n => n.to_string(),
    }
}

impl NewForm {
    fn from_spec(spec: &AppSpec, copies: u32) -> Self {
        let main = spec.ports.iter().find(|p| p.public).or(spec.ports.first());
        let lines = |items: Vec<String>| items.join("\n");
        let (check, check_path) = match spec.check.as_ref().map(|c| &c.kind) {
            Some(CheckKind::Http { path }) => ("http", path.clone()),
            Some(CheckKind::Tcp) => ("tcp", String::new()),
            None => ("", String::new()),
        };
        Self {
            mode: "custom".into(),
            image: spec.image.clone(),
            exposure: if main.is_some_and(|p| p.public) {
                "public"
            } else {
                "private"
            }
            .into(),
            port: main.map(|p| p.port.to_string()).unwrap_or_default(),
            copies: copies.to_string(),
            env: spec
                .env
                .iter()
                .map(|e| (e.name.clone(), e.value.clone()))
                .collect(),
            check: check.into(),
            check_path,
            memory: nonzero(spec.memory_mib),
            cpu: nonzero(spec.cpu_millis),
            command: lines(spec.command.clone()),
            stop_signal: spec.stop.signal.clone(),
            stop_grace: nonzero(spec.stop.grace_seconds),
            ..Self::default()
        }
    }

    fn from_pairs(posted: Vec<(String, String)>) -> Self {
        let mut single = serde_json::Map::new();
        let mut rows: std::collections::BTreeMap<&str, (Vec<String>, Vec<String>)> =
            Default::default();
        for (key, value) in posted {
            match key.as_str() {
                "env_key" => rows.entry("env").or_default().0.push(value),
                "env_value" => rows.entry("env").or_default().1.push(value),
                "secrets_key" => rows.entry("secrets").or_default().0.push(value),
                "secrets_value" => rows.entry("secrets").or_default().1.push(value),
                _ => {
                    single.insert(key, serde_json::Value::String(value));
                }
            }
        }
        let mut form: NewForm =
            serde_json::from_value(serde_json::Value::Object(single)).unwrap_or_default();
        let mut take = |part: &str| {
            let (keys, values) = rows.remove(part).unwrap_or_default();
            let mut values = values.into_iter();
            keys.into_iter()
                .map(|key| (key, values.next().unwrap_or_default()))
                .filter(|(key, value)| !(key.trim().is_empty() && value.is_empty()))
                .collect::<Vec<_>>()
        };
        form.env = take("env");
        form.secrets = take("secrets");
        form
    }
}

fn number<T: std::str::FromStr>(
    text: &str,
    field: &'static str,
    words: &str,
) -> Result<Option<T>, Refusal> {
    match text.trim() {
        "" => Ok(None),
        text => text
            .parse()
            .map(Some)
            .map_err(|_| Refusal::field(field, words.to_string())),
    }
}

fn named(rows: &[(String, String)]) -> Result<Vec<(String, String)>, String> {
    rows.iter()
        .enumerate()
        .map(|(i, (name, value))| match name.trim() {
            "" => Err(format!("Row {}: give the value a name.", i + 1)),
            name => Ok((name.to_string(), value.clone())),
        })
        .collect()
}

fn copies_of(form: &NewForm) -> Result<Option<u32>, Refusal> {
    number(
        &form.copies,
        "copies",
        &format!("Copies is a whole number from 1 to {MAX_COPIES}."),
    )
}

fn form_spec(
    form: &NewForm,
    base: Option<&AppSpec>,
    public: bool,
) -> Result<(AppSpec, Option<PortSpec>), Refusal> {
    let port: Option<u16> = number(&form.port, "port", "A port is a number from 1 to 65535.")?;
    let mut ports = base.map(|b| b.ports.clone()).unwrap_or_default();
    let main_at = ports.iter().position(|p| p.public).unwrap_or(0);
    let mut main = match ports.get(main_at) {
        Some(main) => main.clone(),
        None => PortSpec {
            name: "http".into(),
            port: 0,
            protocol: Protocol::Http,
            public,
        },
    };
    main.public = public;
    if public {
        for other in &mut ports {
            other.public = false;
        }
    }
    let detect = match port {
        Some(number) => {
            main.port = number;
            match ports.get_mut(main_at) {
                Some(slot) => *slot = main,
                None => ports.push(main),
            }
            None
        }
        None => {
            if main_at < ports.len() {
                ports.remove(main_at);
            }
            Some(main)
        }
    };
    let env = named(&form.env)
        .map_err(|message| Refusal::field("env", message))?
        .into_iter()
        .map(|(name, value)| EnvVar { name, value })
        .collect();
    let kind = match form.check.as_str() {
        "http" => Some(CheckKind::Http {
            path: match form.check_path.trim() {
                "" => "/".to_string(),
                path => path.to_string(),
            },
        }),
        "tcp" => Some(CheckKind::Tcp),
        _ => None,
    };
    let before = base.and_then(|b| b.check.as_ref());
    let check = kind.map(|kind| CheckSpec {
        kind,
        port: before
            .map(|c| c.port)
            .filter(|p| ports.iter().any(|port| port.port == *p))
            .unwrap_or(0),
        interval_ms: before.map_or(0, |c| c.interval_ms),
        timeout_ms: before.map_or(0, |c| c.timeout_ms),
    });
    let memory_mib = number(
        &form.memory,
        "memory",
        "Memory is a whole number of MiB, from 16 to 262144.",
    )?;
    let cpu_millis = number(
        &form.cpu,
        "cpu",
        "CPU is a whole number of thousandths of a CPU, from 10 to 64000.",
    )?;
    let grace_seconds = number(
        &form.stop_grace,
        "stop",
        "The grace period is a whole number of seconds, at most 300.",
    )?;
    Ok((
        AppSpec {
            image: form.image.trim().to_string(),
            command: form
                .command
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
            ports,
            memory_mib: memory_mib.unwrap_or(0),
            cpu_millis: cpu_millis.unwrap_or(0),
            env,
            secrets: base.map(|b| b.secrets.clone()).unwrap_or_default(),
            check,
            stop: StopSpec {
                signal: form.stop_signal.trim().to_string(),
                grace_seconds: grace_seconds.unwrap_or(0),
            },
        },
        detect,
    ))
}

fn custom_launch(form: &NewForm, public: bool) -> Result<Launch, Refusal> {
    let (spec, detect_port) = form_spec(form, None, public)?;
    Ok(Launch {
        name: form.name.clone(),
        settings: SettingsInput {
            copies: copies_of(form)?,
            ..Default::default()
        },
        spec,
        detect_port,
        secrets: named(&form.secrets).map_err(|message| Refusal::field("secrets", message))?,
    })
}

fn premade_launch(form: &NewForm, public: bool) -> Result<Launch, Refusal> {
    let template = templates::find(&form.template)
        .filter(|t| !t.needs_storage)
        .ok_or_else(|| Refusal::field("template", "Choose one of the apps."))?;
    if public && template.publishable.is_none() {
        return Err(Refusal::field(
            "exposure",
            format!(
                "{} has no HTTP port to publish. Choose Private.",
                template.title
            ),
        ));
    }
    let spec = template.spec(public).ok_or_else(|| {
        Refusal::field(
            "template",
            "That app needs storage, which is not built yet.",
        )
    })?;
    Ok(Launch {
        name: match form.name.trim() {
            "" => template.key.to_string(),
            name => name.to_string(),
        },
        settings: SettingsInput {
            copies: copies_of(form)?,
            ..Default::default()
        },
        spec,
        detect_port: None,
        secrets: Vec::new(),
    })
}

fn sentence(error: &AppsError) -> String {
    match error {
        AppsError::Spec(spec) => format!("{}: {}.", spec.field, spec.problem),
        AppsError::NameTaken => "An app of that name already exists.".into(),
        AppsError::AppLimit => "This organisation has all the apps it may have.".into(),
        AppsError::Internal(_) => "grund could not finish that. Try again.".into(),
        other => capitalise(&format!("{other}.")),
    }
}

/// `POST /{org}/deploy`: makes the app and rolls out its first version.
/// Every refusal comes back as the form with a message under the field
/// that caused it, and nothing made.
pub async fn create(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(posted): Form<Vec<(String, String)>>,
) -> PageResult {
    let form = NewForm::from_pairs(posted);
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps?error=not-allowed")));
    }
    let public = form.exposure == "public";
    let launch = if public && state.config.entry.app_domain.is_none() {
        Err(Refusal::field(
            "exposure",
            "This instance gives apps no public address. Choose Private.",
        ))
    } else if form.mode == "premade" {
        premade_launch(&form, public)
    } else {
        custom_launch(&form, public)
    };
    let refused = match launch {
        Ok(launch) => {
            let wanted = launch.name.trim().to_ascii_lowercase();
            let apps = state.apps();
            match apps
                .launch(session.account_id, membership.organisation_id, launch)
                .await
            {
                Ok((name, _)) => {
                    return Ok(redirect(&format!("/{slug}/apps/{name}?done=created")));
                }
                Err(AppsError::Internal(error)) => {
                    tracing::error!(error = %format!("{error:#}"), "the deploy page could not make an app");
                    let error = AppsError::Internal(error);
                    if apps.get(membership.organisation_id, &wanted).await.is_ok() {
                        return Ok(redirect(&format!(
                            "/{slug}/apps/{wanted}?deploy_error={}",
                            urlencode(&sentence(&error))
                        )));
                    }
                    Refusal::banner(sentence(&error))
                }
                Err(error) => refusal(&error),
            }
        }
        Err(refused) => refused,
    };
    new_view(&state, &browser, &session, &membership, form, refused, None).await
}

fn urlencode(text: &str) -> String {
    serde_urlencoded::to_string([("v", text)])
        .map(|s| s.trim_start_matches("v=").to_string())
        .unwrap_or_default()
}

#[derive(Deserialize, Default)]
pub struct AppQuery {
    #[serde(default)]
    done: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    deploy_error: String,
    #[serde(default)]
    edit: String,
}

const APP_TABS: &[(&str, &str, &str, &str)] = &[
    ("overview", "", "Overview", "home"),
    ("deployments", "/deployments", "Deployments", "layers"),
    ("logs", "/logs", "Logs", "file"),
    ("metrics", "/metrics", "Metrics", "bars"),
    ("settings", "/settings", "Settings", "gear"),
];

const SETTINGS_FIELDS: &[&str] = &[
    "copies",
    "exposure",
    "port",
    "check",
    "env",
    "memory",
    "cpu",
    "command",
    "stop",
    "variable",
    "value",
    "file",
    "confirm",
    "placement",
];

const SETTINGS_PARTS: &[&str] = &[
    "copies",
    "exposure",
    "env",
    "secrets",
    "check",
    "resources",
    "command",
    "placement",
    "file",
    "delete",
];

fn part_of(field: &str) -> &'static str {
    match field {
        "exposure" | "port" => "exposure",
        "env" => "env",
        "check" => "check",
        "memory" | "cpu" => "resources",
        "command" | "stop" => "command",
        _ => "",
    }
}

fn mib(n: u64) -> String {
    if n >= 1024 && n.is_multiple_of(1024) {
        format!("{} GiB", n / 1024)
    } else {
        format!("{n} MiB")
    }
}

fn cpus(millis: u32) -> String {
    match millis {
        1000 => "1 CPU".into(),
        m if m.is_multiple_of(1000) => format!("{} CPUs", m / 1000),
        m => format!("{:.2} CPU", f64::from(m) / 1000.0),
    }
}

fn names(items: &[String]) -> String {
    let shown: Vec<&str> = items.iter().take(4).map(String::as_str).collect();
    let more = items.len().saturating_sub(shown.len());
    let list = shown.join(", ");
    match (items.len(), more) {
        (0, _) => String::new(),
        (n, 0) => format!("{n}: {list}"),
        (n, more) => format!("{n}: {list} and {more} more"),
    }
}

fn setting_items(
    spec: &AppSpec,
    settings: &grund_domain::app::AppSettings,
    address: Option<&str>,
    secrets: &[String],
    domains: &[String],
) -> Value {
    let main = spec.ports.iter().find(|p| p.public).or(spec.ports.first());
    let exposure = match (main, address) {
        (Some(port), Some(address)) if port.public => {
            format!("Public HTTP on port {} · https://{address}", port.port)
        }
        (Some(port), _) if port.public => format!("Public HTTP on port {}", port.port),
        (Some(port), _) => format!("Private on port {}", port.port),
        (None, _) => "No port: nothing reaches it".into(),
    };
    let check = match spec.check.as_ref().map(|c| &c.kind) {
        Some(CheckKind::Http { path }) => Some(format!("An HTTP request to {path} must answer")),
        Some(CheckKind::Tcp) => Some("A TCP connection must open".into()),
        None => None,
    };
    let memory = if spec.memory_mib == 0 {
        512
    } else {
        spec.memory_mib
    };
    let cpu = if spec.cpu_millis == 0 {
        1000
    } else {
        spec.cpu_millis
    };
    let signal = if spec.stop.signal.is_empty() {
        "SIGTERM"
    } else {
        spec.stop.signal.as_str()
    };
    let grace = if spec.stop.grace_seconds == 0 {
        30
    } else {
        spec.stop.grace_seconds
    };
    let command = (!spec.command.is_empty() || signal != "SIGTERM" || grace != 30).then(|| {
        let run = if spec.command.is_empty() {
            "The image's own command".to_string()
        } else {
            spec.command.join(" ")
        };
        format!("{run} · stops with {signal}, killed after {grace} s")
    });
    let env: Vec<String> = spec.env.iter().map(|e| e.name.clone()).collect();
    let placed = !settings.machines.is_empty()
        || !settings.placement.is_default()
        || settings.reschedule_after_seconds
            != grund_domain::app::AppSettings::default().reschedule_after_seconds;
    let optional = [
        (
            "placement",
            "Placement",
            "server",
            placed.then(|| placement_words(settings)),
        ),
        ("check", "Health check", "ok", check),
        (
            "env",
            "Environment variables",
            "list",
            (!env.is_empty()).then(|| names(&env)),
        ),
        (
            "secrets",
            "Secrets",
            "key",
            (!secrets.is_empty()).then(|| names(secrets)),
        ),
        (
            "domains",
            "Custom domain",
            "link",
            (!domains.is_empty()).then(|| domains.join(", ")),
        ),
        ("volumes", "Volumes / storage", "box", None),
        ("command", "Command override", "code", command),
    ];
    let item = |key: &str, title: &str, icon: &str, value: Option<String>| {
        context! { key, title, icon, value }
    };
    let mut configured = vec![
        item(
            "exposure",
            "Exposure",
            if main.is_some_and(|p| p.public) {
                "globe"
            } else {
                "lock"
            },
            Some(exposure),
        ),
        item(
            "copies",
            "Copies",
            "copy",
            Some(copies(settings.copies as usize)),
        ),
    ];
    let mut more = Vec::new();
    for (key, title, icon, value) in optional {
        match value {
            Some(value) => configured.push(item(key, title, icon, Some(value))),
            None => more.push(item(key, title, icon, None)),
        }
        if key == "check" {
            configured.push(item(
                "resources",
                "Resources",
                "bars",
                Some(format!("{} and {} per copy", mib(memory), cpus(cpu))),
            ));
        }
    }
    more.push(item("file", FILE_NAME, "file", None));
    context! { configured, more }
}

const SETTING_KEYS: &[&str] = &[
    "exposure",
    "copies",
    "placement",
    "check",
    "resources",
    "env",
    "secrets",
    "domains",
    "volumes",
    "command",
    "file",
    "delete",
];

const FILE_NAME: &str = "grund.yaml";

fn placement_words(settings: &grund_domain::app::AppSettings) -> String {
    let rules = &settings.placement;
    let mut parts = vec![
        grund_domain::app::placement::rules_words(settings)
            .map_or("Any machine".to_string(), |words| capitalise(&words)),
    ];
    if let Some(key) = &rules.spread_by {
        parts.push(format!("spread by {key}"));
    }
    if !rules.near.is_empty() {
        parts.push(format!("near {}", rules.near.join(", ")));
    }
    if !rules.apart.is_empty() {
        parts.push(format!("apart from {}", rules.apart.join(", ")));
    }
    parts.push(format!(
        "replaced after {}",
        grund_domain::app::reconcile::span_words(chrono::Duration::seconds(i64::from(
            settings.reschedule_after_seconds
        )))
    ));
    parts.join(" · ")
}

#[derive(Default)]
struct Refused {
    part: &'static str,
    edit: String,
    refusal: Refusal,
    form: Option<NewForm>,
    variable: String,
    file: Option<String>,
}

macro_rules! app_page {
    ($name:ident, $tab:literal, $doc:literal) => {
        #[doc = $doc]
        pub async fn $name(
            AxumState(state): AxumState<State>,
            Member {
                browser,
                session,
                membership,
            }: Member,
            Path((_, name)): Path<(String, String)>,
            Query(query): Query<AppQuery>,
        ) -> PageResult {
            let error = match error_words(&query.error) {
                "" => query.deploy_error.chars().take(300).collect(),
                words => words.to_string(),
            };
            app_view(
                &state,
                &browser,
                &session,
                &membership,
                &name,
                $tab,
                (notice_words(&query.done).to_string(), error),
                Refused {
                    edit: query.edit,
                    ..Refused::default()
                },
            )
            .await
        }
    };
}

app_page!(
    app_page,
    "overview",
    "`/{org}/apps/{app}`: how it is, where it answers and what happened lately."
);
app_page!(
    deployments_page,
    "deployments",
    "`/{org}/apps/{app}/deployments`: its copies and every release, with rollback."
);
app_page!(
    logs_page,
    "logs",
    "`/{org}/apps/{app}/logs`: not built; the page says so."
);
app_page!(
    metrics_page,
    "metrics",
    "`/{org}/apps/{app}/metrics`: not built; the page says so."
);
app_page!(
    settings_page,
    "settings",
    "`/{org}/apps/{app}/settings`: copies, exposure, port, checks, environment, secrets and delete."
);

#[allow(clippy::too_many_arguments)]
async fn app_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    name: &str,
    tab: &str,
    (notice, error): (String, String),
    refused: Refused,
) -> PageResult {
    let slug = &membership.slug;
    let apps = state.apps();
    let listing = match apps.listing(membership.organisation_id, slug, name).await {
        Ok(listing) => listing,
        Err(AppsError::NotFound) => return Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => return Err(PageError::from(anyhow::anyhow!(error))),
    };
    let releases = apps
        .releases(membership.organisation_id, name)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    let view = &listing.view;
    let base = format!("/{slug}/apps/{}", view.row.name);
    let now = Utc::now();
    let wanted = view.row.settings.0.copies;
    let current = view.row.current_release;
    let health = health(view, now);
    let shown = listing_context(&listing);
    let running = current
        .and_then(|number| releases.iter().find(|r| r.number == number))
        .map(|r| {
            let image = r.spec.0.image.split('@').next().unwrap_or_default();
            context! {
                version => format!("v{}", r.number),
                line => format!("{image} · {}", r.image_digest.trim_start_matches("sha256:").chars().take(12).collect::<String>()),
                reference => format!("{image}@{}", r.image_digest),
            }
        });
    let replicas: Vec<Value> = view
        .replicas
        .iter()
        .map(|replica| {
            let (words, tone) = replica_words(replica, now);
            context! {
                slot => replica.slot + 1,
                of => wanted,
                release => replica.release,
                machine => replica.machine_name.clone().unwrap_or_default(),
                words,
                tone,
                placed => when(replica.placed_at),
            }
        })
        .collect();
    let machines: std::collections::BTreeSet<&str> = view
        .replicas
        .iter()
        .filter(|r| r.state == "running")
        .filter_map(|r| r.machine_name.as_deref())
        .collect();
    let crowded = (wanted >= 2 && machines.len() == 1)
        .then(|| machines.iter().next().map(|m| m.to_string()))
        .flatten();
    let waiting: Vec<String> = view
        .row
        .waiting
        .as_array()
        .map(|w| {
            let mut messages: Vec<String> = w
                .iter()
                .filter_map(|w| w["message"].as_str().map(str::to_string))
                .collect();
            messages.dedup();
            messages
        })
        .unwrap_or_default();
    let waiting: Vec<String> = waiting
        .into_iter()
        .enumerate()
        .map(|(i, message)| match current {
            Some(release) if i == 0 => {
                let ready = ready_copies(view, i64::from(release), now);
                format!(
                    "{ready} of {wanted} {} running. {message}",
                    if wanted == 1 { "copy" } else { "copies" }
                )
            }
            _ => message,
        })
        .collect();
    let busy = view
        .row
        .rollout
        .as_ref()
        .is_some_and(|r| r["state"] == "in_progress")
        || !waiting.is_empty()
        || view
            .replicas
            .iter()
            .any(|r| r.state == "draining" || r.ready != Some(true));
    let history: Vec<Value> = releases
        .iter()
        .map(|r| release_context(r, current, now))
        .collect();
    let newest = releases.first();
    let spec = newest.map(|r| &r.spec.0);
    let form = refused.form.unwrap_or_else(|| match spec {
        Some(spec) => NewForm::from_spec(spec, wanted),
        None => NewForm::default(),
    });
    let read: Vec<&SecretEnv> = spec.map(|s| s.secrets.iter().collect()).unwrap_or_default();
    let secret_names: Vec<String> = read.iter().map(|s| s.env.clone()).collect();
    let mut secrets: Vec<Value> = read
        .iter()
        .map(|secret| {
            let stored = view.secrets.iter().find(|(n, _, _)| *n == secret.secret);
            context! {
                variable => secret.env,
                name => secret.secret,
                sub => match stored {
                    Some((_, version, at)) => format!("secret {} · version {version} · set {}", secret.secret, when(*at)),
                    None => format!("secret {} · not stored", secret.secret),
                },
            }
        })
        .collect();
    secrets.extend(
        view.secrets
            .iter()
            .filter(|(n, _, _)| !read.iter().any(|s| s.secret == *n))
            .map(|(name, version, at)| {
                context! {
                    variable => "", name,
                    sub => format!("not read by the app · version {version} · set {}", when(*at)),
                }
            }),
    );
    let errors: std::collections::BTreeMap<&str, &str> = SETTINGS_FIELDS
        .iter()
        .map(|f| (*f, refused.refusal.fields.get(f).map_or("", String::as_str)))
        .collect();
    let banners: std::collections::BTreeMap<&str, &str> = SETTINGS_PARTS
        .iter()
        .copied()
        .map(|part| {
            (
                part,
                if part == refused.part {
                    refused.refusal.banner.as_str()
                } else {
                    ""
                },
            )
        })
        .collect();
    let file = refused.file.clone().or_else(|| {
        newest.map(|r| {
            render_file(
                &view.row.name,
                &r.spec.0,
                &view.row.settings.0,
                &schema_url(state),
            )
        })
    });
    let soon = match tab {
        "logs" => context! {
            title => "Logs are coming",
            text => "grund does not collect logs yet.",
        },
        _ => context! {
            title => "Metrics are coming",
            text => "grund does not collect metrics yet.",
        },
    };
    let template = match tab {
        "overview" => "pages/app-overview.html.jinja",
        "deployments" => "pages/app-deployments.html.jinja",
        "settings" => "pages/app-settings.html.jinja",
        _ => "pages/app-soon.html.jinja",
    };
    let bound = state
        .domains()
        .of_app(view.row.app_id)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    let domain_names: Vec<String> = bound.iter().map(|d| d.name.clone()).collect();
    let domains: Vec<Value> = bound
        .into_iter()
        .map(|domain| {
            let serving = domain.status == crate::services::domains::Status::Issued;
            context! {
                summary => if serving { domain.name.clone() } else { format!("{} (certificate on its way)", domain.name) },
                state_words => if serving { "Serving with its own certificate" } else { "Bound; its certificate is on its way once its DNS points here" },
                name => domain.name,
                serving,
            }
        })
        .collect();
    signed_in(
        state,
        browser,
        session,
        Some(membership),
        if refused.part.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        },
        template,
        "apps",
        context! {
            tab,
            tabs => APP_TABS.iter().map(|(key, path, label, icon)| (*key, format!("{base}{path}"), *label, *icon)).collect::<Vec<_>>(),
            app => context! {
                name => view.row.name,
                base,
                icon => shown.get_attr("icon").ok(),
                image => spec.map(|s| s.image.clone()),
                address => listing.address,
                domains,
                domains_href => format!("/{slug}/domains#custom"),
                internal => shown.get_attr("internal").ok(),
                word => health.word, tone => health.tone,
            },
            running,
            latest => history.first(),
            activity => history.iter().take(3).collect::<Vec<_>>(),
            releases => history,
            replicas, waiting, crowded,
            refresh => busy && matches!(tab, "overview" | "deployments"),
            soon,
            settings => context! {
                copies => wanted,
                machines => view.row.settings.0.machines.join(", "),
                labels => view.row.settings.0.placement.labels.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>(),
                kind => view.row.settings.0.placement.kind.map_or("", |k| k.as_str()),
                spread_by => view.row.settings.0.placement.spread_by.clone().unwrap_or_default(),
                near => view.row.settings.0.placement.near.join(", "),
                apart => view.row.settings.0.placement.apart.join(", "),
                reschedule_after => view.row.settings.0.reschedule_after_seconds,
                auto_rollback => if view.row.settings.0.auto_rollback { "on" } else { "off" },
                number => newest.map(|r| r.number),
                digest => newest.map(|r| r.image_digest.chars().take(19).collect::<String>()),
            },
            rollback_choices => vec![
                context! { value => "on", title => "Roll back on its own", text => "The release before keeps serving" },
                context! { value => "off", title => "Leave it as it is", text => "To debug a failing release in place" },
            ],
            exposures => exposures(state.config.entry.app_domain.as_deref()),
            public_hint => state.config.entry.app_domain.as_deref().map(|domain| format!("Public: https://{}-{slug}.{domain}", view.row.name)).unwrap_or_default(),
            checks => [("", "None"), ("http", "HTTP request"), ("tcp", "TCP connection")],
            form => Value::from_serialize(&form),
            variable => refused.variable,
            secrets, errors, banners,
            file_rows => file.as_ref().map_or(0, |f| f.lines().count() + 1),
            file,
            file_href => format!("{base}/grund.yaml"),
            signals => STOP_SIGNALS.iter().map(|s| (*s, *s)).collect::<Vec<_>>(),
            items => spec.map(|spec| setting_items(spec, &view.row.settings.0, listing.address.as_deref(), &secret_names, &domain_names)),
            next => newest.map(|r| r.number + 1),
            edit => if refused.part.is_empty() { SETTING_KEYS.iter().find(|k| **k == refused.edit).copied().unwrap_or_default() } else { refused.part },
            file_name => FILE_NAME,
            notice, error,
        },
    )
    .await
}

async fn newest_spec(
    state: &State,
    membership: &Membership,
    name: &str,
) -> Result<Result<(AppSpec, u32), Response>, PageError> {
    let slug = &membership.slug;
    let apps = state.apps();
    let view = match apps.get(membership.organisation_id, name).await {
        Ok(view) => view,
        Err(AppsError::NotFound) => return Ok(Err(redirect(&format!("/{slug}/apps?error=gone")))),
        Err(error) => return Err(PageError::from(anyhow::anyhow!(error))),
    };
    let releases = apps
        .releases(membership.organisation_id, name)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    Ok(match releases.into_iter().next() {
        Some(release) => Ok((release.spec.0, view.row.settings.0.copies)),
        None => Err(redirect(&format!("/{slug}/apps/{name}?error=no-release"))),
    })
}

macro_rules! newest_or_return {
    ($state:expr, $membership:expr, $name:expr) => {
        match newest_spec($state, $membership, $name).await? {
            Ok(found) => found,
            Err(response) => return Ok(response),
        }
    };
}

/// `/{org}/apps/{app}/deploy`: Deploy app's form, filled in with what the
/// app runs now, to make its next release.
pub async fn change_page(
    AxumState(state): AxumState<State>,
    Member {
        browser,
        session,
        membership,
    }: Member,
    Path((slug, name)): Path<(String, String)>,
) -> PageResult {
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let (spec, copies) = newest_or_return!(&state, &membership, &name);
    let changing = Changing {
        name: name.clone(),
        secrets: spec.secrets.iter().map(|s| s.env.clone()).collect(),
    };
    new_view(
        &state,
        &browser,
        &session,
        &membership,
        NewForm::from_spec(&spec, copies),
        Refusal::default(),
        Some(changing),
    )
    .await
}

/// `POST /{org}/apps/{app}/deploy`: the next release, from Deploy change.
/// A refusal comes back as the form with 422, and nothing is made.
pub async fn change(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(posted): Form<Vec<(String, String)>>,
) -> PageResult {
    let form = NewForm::from_pairs(posted);
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let (spec, _) = newest_or_return!(&state, &membership, &name);
    let changing = Changing {
        name: name.clone(),
        secrets: spec.secrets.iter().map(|s| s.env.clone()).collect(),
    };
    let public = form.exposure == "public";
    let made = if public && state.config.entry.app_domain.is_none() {
        Err(Refusal::field(
            "exposure",
            "This instance gives apps no public address. Choose Private.",
        ))
    } else {
        changed(&form, &spec, public)
    };
    let refused = match made {
        Ok(change) => match state
            .apps()
            .change(
                session.account_id,
                membership.organisation_id,
                &name,
                change,
            )
            .await
        {
            Ok(_) => return Ok(redirect(&format!("/{slug}/apps/{name}?done=deployed"))),
            Err(AppsError::NotFound) => return Ok(redirect(&format!("/{slug}/apps?error=gone"))),
            Err(error) => refusal(&error),
        },
        Err(refused) => refused,
    };
    new_view(
        &state,
        &browser,
        &session,
        &membership,
        form,
        refused,
        Some(changing),
    )
    .await
}

fn changed(form: &NewForm, base: &AppSpec, public: bool) -> Result<Change, Refusal> {
    let (spec, detect_port) = form_spec(form, Some(base), public)?;
    Ok(Change {
        copies: copies_of(form)?,
        spec,
        detect_port,
        secrets: named(&form.secrets).map_err(|message| Refusal::field("secrets", message))?,
        same_image: false,
    })
}

#[allow(clippy::too_many_arguments)]
async fn refuse_setting(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    name: &str,
    part: &'static str,
    refusal: Refusal,
    form: Option<NewForm>,
) -> PageResult {
    app_view(
        state,
        browser,
        session,
        membership,
        name,
        "settings",
        (String::new(), String::new()),
        Refused {
            part,
            refusal,
            form,
            variable: String::new(),
            file: None,
            edit: String::new(),
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct CopiesForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    copies: String,
    #[serde(default)]
    auto_rollback: String,
}

/// `POST /{org}/apps/{app}/settings/copies`: how many copies, and whether
/// a failed release rolls back on its own. No new release.
pub async fn configure(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<CopiesForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let apps = state.apps();
    let view = match apps.get(membership.organisation_id, &name).await {
        Ok(view) => view,
        Err(AppsError::NotFound) => return Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => return Err(PageError::from(anyhow::anyhow!(error))),
    };
    let refusal = match form.copies.trim().parse::<u32>() {
        Ok(copies) => match view.row.settings.0.with_copies(copies) {
            Ok(settings) => {
                let mut input = settings.as_input();
                input.auto_rollback = Some(form.auto_rollback == "on");
                match apps
                    .configure(session.account_id, membership.organisation_id, &name, input)
                    .await
                {
                    Ok(_) => {
                        return Ok(redirect(&format!(
                            "/{slug}/apps/{name}/settings?done=saved"
                        )));
                    }
                    Err(AppsError::NotFound) => {
                        return Ok(redirect(&format!("/{slug}/apps?error=gone")));
                    }
                    Err(error) => refusal(&error),
                }
            }
            Err(error) => refusal(&AppsError::Spec(error)),
        },
        _ => Refusal::field(
            "copies",
            format!("Copies is a whole number from 1 to {MAX_COPIES}."),
        ),
    };
    refuse_setting(
        &state,
        &browser,
        &session,
        &membership,
        &name,
        "copies",
        refusal,
        None,
    )
    .await
}

/// `POST /{org}/apps/{app}/settings/placement`: which machines the copies
/// run on and how they spread (grund-docs design/apps.md §5.6). No new
/// release; copies that no longer match move, one at a time.
pub async fn placement_settings(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(posted): Form<Vec<(String, String)>>,
) -> PageResult {
    let one = |key: &str| {
        posted
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    if !browser.form_is_genuine(&one("csrf")) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let apps = state.apps();
    let view = match apps.get(membership.organisation_id, &name).await {
        Ok(view) => view,
        Err(AppsError::NotFound) => return Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => return Err(PageError::from(anyhow::anyhow!(error))),
    };
    let list = |key: &str| -> Vec<String> {
        one(key)
            .split([',', ' ', '\n'])
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_string)
            .collect()
    };
    let keys = posted
        .iter()
        .filter(|(k, _)| k == "labels_key")
        .map(|(_, v)| v);
    let mut values = posted
        .iter()
        .filter(|(k, _)| k == "labels_value")
        .map(|(_, v)| v.clone());
    let mut input = view.row.settings.0.as_input();
    input.machines = list("machines");
    input.labels = keys
        .map(|k| (k.trim().to_string(), values.next().unwrap_or_default()))
        .filter(|(k, _)| !k.is_empty())
        .collect();
    input.kind = one("kind");
    input.spread_by = one("spread_by");
    input.near = list("near");
    input.apart = list("apart");
    let refusal = match one("reschedule_after").parse::<u32>() {
        Ok(seconds) => {
            input.reschedule_after_seconds = Some(seconds);
            match apps
                .configure(session.account_id, membership.organisation_id, &name, input)
                .await
            {
                Ok(_) => {
                    return Ok(redirect(&format!(
                        "/{slug}/apps/{name}/settings?done=saved"
                    )));
                }
                Err(AppsError::NotFound) => {
                    return Ok(redirect(&format!("/{slug}/apps?error=gone")));
                }
                Err(AppsError::Spec(spec)) => Refusal::field(
                    "placement",
                    format!(
                        "{}: {}.",
                        spec.field.trim_start_matches("placement."),
                        spec.problem
                    ),
                ),
                Err(error) => refusal(&error),
            }
        }
        Err(_) => Refusal::field(
            "placement",
            "Replace after is a whole number of seconds from 30 to 3600.",
        ),
    };
    refuse_setting(
        &state,
        &browser,
        &session,
        &membership,
        &name,
        "placement",
        refusal,
        None,
    )
    .await
}

/// `POST /{org}/apps/{app}/settings/release`: exposure, port, ready check
/// and environment, as a new release of the image the newest one runs.
pub async fn release_settings(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(posted): Form<Vec<(String, String)>>,
) -> PageResult {
    let posted = NewForm::from_pairs(posted);
    if !browser.form_is_genuine(&posted.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let (spec, copies) = newest_or_return!(&state, &membership, &name);
    let part = match posted.part.as_str() {
        "exposure" => "exposure",
        "env" => "env",
        "check" => "check",
        "resources" => "resources",
        "command" => "command",
        _ => "exposure",
    };
    let now = NewForm::from_spec(&spec, copies);
    let form = match part {
        "env" => NewForm {
            env: posted.env,
            ..now
        },
        "check" => NewForm {
            check: posted.check,
            check_path: posted.check_path,
            ..now
        },
        "resources" => NewForm {
            memory: posted.memory,
            cpu: posted.cpu,
            ..now
        },
        "command" => NewForm {
            command: posted.command,
            stop_signal: posted.stop_signal,
            stop_grace: posted.stop_grace,
            ..now
        },
        _ => NewForm {
            exposure: posted.exposure,
            port: posted.port,
            ..now
        },
    };
    let public = form.exposure == "public";
    let made = if public && state.config.entry.app_domain.is_none() {
        Err(Refusal::field(
            "exposure",
            "This instance gives apps no public address. Choose Private.",
        ))
    } else {
        form_spec(&form, Some(&spec), public).map(|(spec, _)| Change {
            copies: None,
            spec,
            detect_port: None,
            secrets: Vec::new(),
            same_image: true,
        })
    };
    let refusal = match made {
        Ok(change) => match state
            .apps()
            .change(
                session.account_id,
                membership.organisation_id,
                &name,
                change,
            )
            .await
        {
            Ok(_) => {
                return Ok(redirect(&format!(
                    "/{slug}/apps/{name}/settings?done=released"
                )));
            }
            Err(AppsError::NotFound) => return Ok(redirect(&format!("/{slug}/apps?error=gone"))),
            Err(error) => refusal(&error),
        },
        Err(refusal) => refusal,
    };
    let part = refusal
        .fields
        .keys()
        .map(|field| part_of(field))
        .find(|p| !p.is_empty())
        .unwrap_or(part);
    refuse_setting(
        &state,
        &browser,
        &session,
        &membership,
        &name,
        part,
        Refusal {
            banner: "Nothing was released. Check the field marked below.".into(),
            ..refusal
        },
        Some(form),
    )
    .await
}

#[derive(Deserialize)]
pub struct FileForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    file: String,
}

/// `POST /{org}/apps/{app}/settings/file`: the app's `grund.yaml`, edited
/// on the page, deployed as the API deploys one: the same parsing and
/// checks, the image resolved again, a release from grund.yaml.
pub async fn apply_file(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<FileForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let refusal = match state
        .apps()
        .deploy(
            session.account_id,
            membership.organisation_id,
            &name,
            DeployInput::File(form.file.clone()),
            ReleaseSource::File,
            "",
        )
        .await
    {
        Ok(_) => {
            return Ok(redirect(&format!(
                "/{slug}/apps/{name}/settings?done=released-file"
            )));
        }
        Err(AppsError::NotFound) => return Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(AppsError::Spec(spec)) => {
            Refusal::field("file", format!("{}: {}.", spec.field, spec.problem))
        }
        Err(AppsError::ImageUnresolved(message) | AppsError::ImageUnsupported(message)) => {
            Refusal::field("file", format!("image: {message}."))
        }
        Err(error) => Refusal::banner(sentence(&error)),
    };
    app_view(
        &state,
        &browser,
        &session,
        &membership,
        &name,
        "settings",
        (String::new(), String::new()),
        Refused {
            part: "file",
            refusal: Refusal {
                banner: "Nothing was released. Check the file.".into(),
                ..refusal
            },
            form: None,
            variable: String::new(),
            file: Some(form.file),
            edit: String::new(),
        },
    )
    .await
}

fn schema_url(state: &State) -> String {
    format!("{}{SCHEMA_PATH}", state.config.public_origin().serialized)
}

/// `GET /{org}/apps/{app}/grund.yaml`: the newest release as a file to
/// save, for any member.
pub async fn file(
    AxumState(state): AxumState<State>,
    Member { membership, .. }: Member,
    Path((_, name)): Path<(String, String)>,
) -> Result<Response, PageError> {
    let apps = state.apps();
    let view = match apps.get(membership.organisation_id, &name).await {
        Ok(view) => view,
        Err(AppsError::NotFound) => return Ok(StatusCode::NOT_FOUND.into_response()),
        Err(error) => return Err(PageError::from(anyhow::anyhow!(error))),
    };
    let releases = apps
        .releases(membership.organisation_id, &name)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    let Some(newest) = releases.first() else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    Ok((
        [
            (header::CONTENT_TYPE, "application/yaml; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"grund.yaml\"",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        render_file(
            &view.row.name,
            &newest.spec.0,
            &view.row.settings.0,
            &schema_url(&state),
        ),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct SecretForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    variable: String,
    #[serde(default)]
    value: String,
}

/// `POST /{org}/apps/{app}/secrets`: stores a value for a variable and
/// releases the newest release's image again with it. The page never
/// shows the value again.
pub async fn set_secret(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<SecretForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let (spec, _) = newest_or_return!(&state, &membership, &name);
    let variable = form.variable.trim().to_string();
    let change = Change {
        copies: None,
        spec,
        detect_port: None,
        secrets: vec![(variable.clone(), form.value)],
        same_image: true,
    };
    let refusal = match state
        .apps()
        .change(
            session.account_id,
            membership.organisation_id,
            &name,
            change,
        )
        .await
    {
        Ok(_) => {
            return Ok(redirect(&format!(
                "/{slug}/apps/{name}/settings?done=secret"
            )));
        }
        Err(AppsError::NotFound) => return Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(AppsError::Spec(spec))
            if spec.field.starts_with("secrets")
                || spec.field == "secret"
                || spec.field.starts_with("env") =>
        {
            let field = if spec.field.ends_with(".value") {
                "value"
            } else {
                "variable"
            };
            Refusal::field(field, format!("{}.", capitalise(&spec.problem)))
        }
        Err(error) => Refusal::banner(sentence(&error)),
    };
    app_view(
        &state,
        &browser,
        &session,
        &membership,
        &name,
        "settings",
        (String::new(), String::new()),
        Refused {
            part: "secrets",
            refusal,
            form: None,
            variable,
            file: None,
            edit: String::new(),
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct VariableForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    variable: String,
}

/// `POST /{org}/apps/{app}/secrets/remove`: a new release of the same
/// image that no longer reads a secret through `variable`. The stored
/// values stay, for the releases before.
pub async fn remove_secret(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<VariableForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let (mut spec, _) = newest_or_return!(&state, &membership, &name);
    spec.secrets.retain(|s| s.env != form.variable);
    let change = Change {
        copies: None,
        spec,
        detect_port: None,
        secrets: Vec::new(),
        same_image: true,
    };
    match state
        .apps()
        .change(
            session.account_id,
            membership.organisation_id,
            &name,
            change,
        )
        .await
    {
        Ok(_) => Ok(redirect(&format!(
            "/{slug}/apps/{name}/settings?done=secret-removed"
        ))),
        Err(AppsError::NotFound) => Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => {
            refuse_setting(
                &state,
                &browser,
                &session,
                &membership,
                &name,
                "secrets",
                Refusal::banner(sentence(&error)),
                None,
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /{org}/apps/{app}/releases/{number}/rollback`.
pub async fn rollback(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name, number)): Path<(String, String, u32)>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    match state
        .apps()
        .rollback(
            session.account_id,
            membership.organisation_id,
            &name,
            number,
        )
        .await
    {
        Ok(_) => Ok(redirect(&format!(
            "/{slug}/apps/{name}/deployments?done=rolled-back"
        ))),
        Err(AppsError::NotFound) => Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => Ok(redirect(&format!(
            "/{slug}/apps/{name}/deployments?deploy_error={}",
            urlencode(&sentence(&error))
        ))),
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    confirm: String,
}

/// `POST /{org}/apps/{app}/delete`, once its name is typed to confirm.
pub async fn delete(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<DeleteForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    if form.confirm.trim() != name {
        return refuse_setting(
            &state,
            &browser,
            &session,
            &membership,
            &name,
            "delete",
            Refusal {
                banner: "Nothing was deleted.".into(),
                ..Refusal::field("confirm", format!("Type {name} exactly to delete it."))
            },
            None,
        )
        .await;
    }
    match state
        .apps()
        .delete(session.account_id, membership.organisation_id, &name)
        .await
    {
        Ok(()) => Ok(redirect(&format!("/{slug}/apps?done=deleted"))),
        Err(AppsError::NotFound) => Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => Err(PageError::from(anyhow::anyhow!(error))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_reads_as_how_long_ago_it_was_then_as_a_date() {
        let now = DateTime::parse_from_rfc3339("2026-10-06T12:00:00Z")
            .expect("a time")
            .with_timezone(&Utc);
        for (seconds, words) in [
            (5, "just now"),
            (60, "1 minute ago"),
            (7_200, "2 hours ago"),
            (86_400, "1 day ago"),
            (3 * 86_400, "3 days ago"),
            (40 * 86_400, "27 Aug 2026"),
        ] {
            assert_eq!(ago(now - chrono::Duration::seconds(seconds), now), words);
        }
    }

    #[test]
    fn settings_lists_what_is_set_in_order_and_offers_the_rest() {
        let keys = |items: &Value, list: &str| -> Vec<String> {
            items
                .get_attr(list)
                .expect("a list")
                .try_iter()
                .expect("items")
                .map(|item| item.get_attr("key").expect("a key").to_string())
                .collect()
        };
        let mut spec = AppSpec {
            image: "traefik/whoami:v1.11.0".into(),
            ports: vec![PortSpec {
                name: "http".into(),
                port: 80,
                protocol: Protocol::Http,
                public: true,
            }],
            secrets: Vec::new(),
            command: Vec::new(),
            memory_mib: 64,
            cpu_millis: 200,
            env: Vec::new(),
            check: None,
            stop: StopSpec::default(),
        };
        let settings = grund_domain::app::AppSettings::default();
        let bare = setting_items(&spec, &settings, None, &[], &[]);
        assert_eq!(
            keys(&bare, "configured"),
            ["exposure", "copies", "resources"]
        );
        assert_eq!(
            keys(&bare, "more"),
            [
                "placement",
                "check",
                "env",
                "secrets",
                "domains",
                "volumes",
                "command",
                "file"
            ]
        );

        spec.check = Some(CheckSpec {
            kind: CheckKind::Http { path: "/".into() },
            port: 80,
            interval_ms: 1000,
            timeout_ms: 1000,
        });
        spec.env = vec![EnvVar {
            name: "LOG_LEVEL".into(),
            value: "info".into(),
        }];
        spec.stop.grace_seconds = 10;
        let mut settings = settings;
        settings.placement.spread_by = Some("zone".into());
        let set = setting_items(&spec, &settings, None, &["TOKEN".into()], &[]);
        assert_eq!(
            keys(&set, "configured"),
            [
                "exposure",
                "copies",
                "placement",
                "check",
                "resources",
                "env",
                "secrets",
                "command"
            ]
        );
        assert_eq!(keys(&set, "more"), ["domains", "volumes", "file"]);
    }

    #[test]
    fn a_change_keeps_the_ports_and_secrets_the_form_does_not_show() {
        let port = |name: &str, port, public| PortSpec {
            name: name.into(),
            port,
            protocol: Protocol::Http,
            public,
        };
        let base = AppSpec {
            image: "nats:2.10".into(),
            ports: vec![port("client", 4222, false), port("monitor", 8222, true)],
            secrets: vec![SecretEnv {
                env: "TOKEN".into(),
                secret: "token".into(),
            }],
            command: Vec::new(),
            memory_mib: 0,
            cpu_millis: 0,
            env: Vec::new(),
            check: None,
            stop: StopSpec {
                signal: String::new(),
                grace_seconds: 0,
            },
        };
        assert_eq!(
            NewForm::from_spec(&base, 1).port,
            "8222",
            "the public port is the form's"
        );
        let form = NewForm {
            port: "9222".into(),
            ..NewForm::from_spec(&base, 1)
        };
        let (spec, detect) = form_spec(&form, Some(&base), false).ok().expect("a spec");
        assert!(detect.is_none());
        assert_eq!(
            spec.ports,
            vec![port("client", 4222, false), port("monitor", 9222, false)]
        );
        assert_eq!(spec.secrets, base.secrets);
        let (spec, detect) = form_spec(
            &NewForm {
                port: String::new(),
                ..form
            },
            Some(&base),
            true,
        )
        .ok()
        .expect("a spec");
        assert_eq!(spec.ports, vec![port("client", 4222, false)]);
        assert_eq!(detect, Some(port("monitor", 8222, true)));
    }

    #[test]
    fn posted_rows_pair_up_in_order_and_a_row_left_empty_is_dropped() {
        let posted = [
            ("csrf", "t"),
            ("name", "api"),
            ("env_key", "A"),
            ("env_value", "1"),
            ("env_key", ""),
            ("env_value", ""),
            ("env_key", "B"),
            ("env_value", "x=y"),
            ("secrets_key", "TOKEN"),
            ("secrets_value", "s3cr3t"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let form = NewForm::from_pairs(posted.to_vec());
        assert_eq!(form.name, "api");
        assert_eq!(
            form.env,
            vec![("A".into(), "1".into()), ("B".into(), "x=y".into())]
        );
        assert_eq!(form.secrets, vec![("TOKEN".into(), "s3cr3t".into())]);
        assert_eq!(
            named(&[(String::new(), "orphan".into())]),
            Err("Row 1: give the value a name.".into())
        );
    }

    #[test]
    fn well_known_images_get_their_own_icon_wherever_they_come_from() {
        for (image, icon) in [
            ("nginx", "nginx"),
            ("nginx:1.27-alpine", "nginx"),
            ("nginxinc/nginx-unprivileged:stable", "nginx"),
            ("postgres:16", "postgres"),
            ("bitnami/postgresql:16", "postgres"),
            ("docker.io/library/redis:7", "redis"),
            ("nats:2.10", "nats"),
            ("clickhouse/clickhouse-server:24", "clickhouse"),
            ("mongo@sha256:0123", "mongo"),
            ("ghcr.io/acme/python:3.13-slim", "python"),
            ("quay.io/prometheus/prometheus", "prometheus"),
            ("rabbitmq:4-management", "rabbitmq"),
            ("node:22", "node"),
        ] {
            assert_eq!(image_icon(image), icon, "{image}");
        }
    }

    #[test]
    fn other_images_get_docker_on_docker_hub_and_a_neutral_icon_elsewhere() {
        assert_eq!(image_icon("traefik/whoami:v1.11.0"), "docker");
        assert_eq!(image_icon("myapp/worker:latest"), "docker");
        assert_eq!(image_icon("docker.io/traefik/whoami:v1.11.0"), "docker");
        assert_eq!(image_icon("index.docker.io/library/busybox"), "docker");
        assert_eq!(image_icon("nodered/node-red"), "docker");
        assert_eq!(image_icon("ghcr.io/ours/api:v1.4.0"), "image");
        assert_eq!(image_icon("localhost:5000/shop"), "image");
        assert_eq!(image_icon(""), "image");
    }
}
