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

use serde::Deserialize;

use crate::{
    services::{
        apps::{AppListing, AppView, AppsError, AppsState, Change, DeployInput, Launch},
        domains::DomainsState,
        machines::MachinesState,
        sessions::Session,
    },
    state::State,
    web::{
        browser::Browser,
        orgs::Member,
        pages::{AppSearch, PageError, PageResult, forged, redirect, signed_in_typed},
    },
};

pub(super) fn manages(membership: &Membership) -> bool {
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

pub struct ListingView {
    pub name: String,
    pub tone: &'static str,
    pub copies: u32,
    pub icon: &'static str,
    pub image: String,
    pub address: Option<String>,
    pub internal: Option<String>,
}

/// An app as a list row or card shows it.
pub fn listing_view(listing: &AppListing) -> ListingView {
    let view = &listing.view;
    let Health { tone, .. } = health(view, Utc::now());
    let image = listing
        .spec
        .as_ref()
        .map(|spec| spec.image.clone())
        .unwrap_or_default();
    ListingView {
        name: view.row.name.clone(),
        tone,
        copies: view.row.settings.0.copies,
        icon: image_icon(&image),
        image,
        address: listing.address.clone(),
        internal: listing
            .spec
            .as_ref()
            .and_then(|spec| internal_address(&view.row.name, spec)),
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

pub struct ReleaseView {
    pub event: String,
    pub short_digest: String,
    pub number: i32,
    pub image: String,
    pub digest: String,
    pub by: String,
    pub verb: String,
    pub source: &'static str,
    pub at: String,
    pub ago: String,
    pub iso: String,
    pub note: String,
    pub outcome: &'static str,
    pub tone: &'static str,
    pub state: &'static str,
    pub reason: Option<String>,
    pub live: bool,
    pub again: &'static str,
}

fn release_view(row: &ReleaseRow, current: Option<i32>, now: DateTime<Utc>) -> ReleaseView {
    let (outcome, tone, state) = match row.outcome.as_deref() {
        Some("rolling_out") => ("Releasing", "blue", "busy"),
        Some("live") => ("Live", "ok", "ok"),
        Some("replaced") => ("Replaced", "muted", ""),
        Some("failed") => ("Failed", "danger", "failed"),
        Some("superseded") => ("Superseded", "muted", ""),
        _ => ("Made", "muted", ""),
    };
    let words = release_words(row);
    let digest = row.image_digest.trim_start_matches("sha256:");
    ReleaseView {
        event: match row.rollback_of {
            Some(number) if row.source == "rollback" => {
                format!("v{} · rolled back to v{number}", row.number)
            }
            _ => format!("v{} · deployed", row.number),
        },
        short_digest: digest.chars().take(12).collect(),
        number: row.number,
        image: row.spec.0.image.clone(),
        digest: row.image_digest.clone(),
        by: words.by,
        verb: words.verb,
        source: words.source,
        at: when(row.created_at),
        ago: ago(row.created_at, now),
        iso: row.created_at.to_rfc3339(),
        note: row.note.clone(),
        outcome,
        tone,
        state,
        reason: row.reason.clone(),
        live: row.outcome.as_deref() == Some("live"),
        again: if current.is_some_and(|c| row.number < c) {
            "Roll back to this"
        } else {
            "Run this again"
        },
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
pub struct AppsPage {
    pub slug: String,
    pub list_href: String,
    pub grid_href: String,
    pub all_href: String,
    pub icons: Vec<&'static str>,
    pub apps: Vec<ListingView>,
    pub total: usize,
    pub list: AppSearch,
    pub sorts: &'static [(&'static str, &'static str)],
    pub notice: &'static str,
    pub error: &'static str,
    pub manages: bool,
}

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
    let page = AppsPage {
        slug: membership.slug.clone(),
        list_href: href(&q, "list"),
        grid_href: href(&q, "grid"),
        all_href: href("", view),
        icons: icons_of(&shown),
        apps: shown.iter().map(|l| listing_view(l)).collect(),
        total: listings.len(),
        list: AppSearch {
            q,
            sort: sort.into(),
            view: view.into(),
        },
        sorts: SORTS,
        notice: notice_words(&query.done),
        error: error_words(&query.error),
        manages: manages(&membership),
    };
    signed_in_typed(
        &state,
        &browser,
        &session,
        Some(&membership),
        StatusCode::OK,
        "Apps",
        "apps",
        Some(&page.list),
        None,
        None,
        |_, _| crate::templates::compiled::pages::apps::render(&page),
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
    )
    .await
}

#[derive(Default)]
pub(super) struct Refusal {
    pub(super) banner: String,
    pub(super) fields: std::collections::BTreeMap<&'static str, String>,
}

impl Refusal {
    pub(super) fn add(&mut self, field: &'static str, message: impl Into<String>) {
        self.fields.entry(field).or_insert_with(|| message.into());
    }

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

pub(super) fn refusal(error: &AppsError) -> Refusal {
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

pub struct ExposureChoice {
    pub value: &'static str,
    pub title: &'static str,
    pub icon: &'static str,
    pub text: String,
    pub disabled: bool,
    pub tag: Option<&'static str>,
}

fn exposures(app_domain: Option<&str>) -> Vec<ExposureChoice> {
    vec![
        ExposureChoice {
            value: "private",
            title: "Private",
            icon: "lock",
            text: "Only other apps reach it".into(),
            disabled: false,
            tag: None,
        },
        ExposureChoice {
            value: "public",
            title: "Public HTTP",
            icon: "globe",
            text: app_domain.map_or_else(
                || "This instance gives apps no address of their own".into(),
                |domain| format!("Via a {domain} address"),
            ),
            disabled: app_domain.is_none(),
            tag: app_domain.is_none().then_some("Not set up"),
        },
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

pub struct TemplateView {
    pub key: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    pub icon: &'static str,
    pub soon: Option<&'static str>,
}

pub struct TemplateChoice {
    pub value: &'static str,
    pub title: &'static str,
    pub text: &'static str,
    pub image: &'static str,
    pub disabled: bool,
    pub tag: Option<&'static str>,
}

pub struct DeployMode {
    pub key: &'static str,
    pub href: String,
    pub icon: &'static str,
    pub title: &'static str,
    pub text: &'static str,
    pub sub: &'static str,
}

pub struct DeployPage {
    pub slug: String,
    pub manages: bool,
    pub mode: &'static str,
    pub modes: Vec<DeployMode>,
    pub new: NewForm,
    pub new_error: String,
    pub errors: std::collections::BTreeMap<&'static str, String>,
    pub advanced: bool,
    pub secrets_dropped: bool,
    pub exposures: Vec<ExposureChoice>,
    pub public_hint: String,
    pub templates: Vec<TemplateChoice>,
    pub image_keys: Vec<&'static str>,
    pub signals: Vec<(&'static str, &'static str)>,
    pub memory_steps: &'static [u64],
    pub cpu_steps: Vec<String>,
    pub checks: &'static [(&'static str, &'static str)],
    pub action: String,
    pub csrf: String,
}

pub struct TemplatesPage {
    pub slug: String,
    pub manages: bool,
    pub templates: Vec<TemplateView>,
    pub image_keys: Vec<&'static str>,
}

pub fn template_view(template: &templates::Template) -> TemplateView {
    TemplateView {
        key: template.key,
        title: template.title,
        summary: template.summary,
        icon: template_icon(template),
        soon: template.needs_storage.then_some(NEEDS_STORAGE),
    }
}

async fn new_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    new: NewForm,
    refused: Refusal,
) -> PageResult {
    let slug = &membership.slug;
    let choices: Vec<TemplateChoice> = templates::CATALOGUE
        .iter()
        .map(|t| TemplateChoice {
            value: t.key,
            title: t.title,
            text: t.summary,
            image: template_icon(t),
            disabled: t.needs_storage,
            tag: t.needs_storage.then_some(NEEDS_STORAGE),
        })
        .collect();
    let premade = new.mode == "premade";
    let mode_href = |mode: &str| format!("/{slug}/deploy?mode={mode}");
    let advanced = refused
        .fields
        .keys()
        .any(|field| ADVANCED_FIELDS.contains(field));
    let secrets_dropped = !refused.banner.is_empty() && !new.secrets.is_empty();
    let errors: std::collections::BTreeMap<&'static str, String> = FORM_FIELDS
        .iter()
        .map(|field| {
            (
                *field,
                refused.fields.get(field).cloned().unwrap_or_default(),
            )
        })
        .collect();
    let mut page = DeployPage {
        slug: slug.clone(),
        manages: manages(membership),
        mode: if premade { "premade" } else { "custom" },
        modes: vec![
            DeployMode {
                key: "premade",
                href: mode_href("premade"),
                icon: "grid",
                title: "Premade",
                text: "A pinned version of a common app",
                sub: "NATS, whoami, nginx",
            },
            DeployMode {
                key: "custom",
                href: mode_href("custom"),
                icon: "box",
                title: "Custom",
                text: "Any container image",
                sub: "",
            },
        ],
        new,
        new_error: refused.banner.clone(),
        errors,
        advanced,
        secrets_dropped,
        exposures: exposures(state.config.entry.app_domain.as_deref()),
        public_hint: state
            .config
            .entry
            .app_domain
            .as_deref()
            .map(|domain| format!("Public: https://<name>-{slug}.{domain}"))
            .unwrap_or_default(),
        templates: choices,
        image_keys: template_icons(),
        signals: STOP_SIGNALS.iter().map(|s| (*s, *s)).collect(),
        memory_steps: super::resources::MEMORY_STEPS,
        cpu_steps: super::resources::CPU_STEPS
            .iter()
            .map(|c| super::resources::vcpus(*c))
            .collect(),
        checks: &[
            ("", "None"),
            ("http", "HTTP request"),
            ("tcp", "TCP connection"),
        ],
        action: format!("/{slug}/deploy"),
        csrf: String::new(),
    };
    signed_in_typed(
        state,
        browser,
        session,
        Some(membership),
        if page.new_error.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        },
        "Deploy app",
        "deploy",
        None,
        None,
        None,
        |_, csrf| {
            page.csrf = csrf.to_owned();
            crate::templates::compiled::pages::deploy::render(&page)
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
    let page = TemplatesPage {
        slug: membership.slug.clone(),
        manages: manages(&membership),
        templates: templates::CATALOGUE.iter().map(template_view).collect(),
        image_keys: template_icons(),
    };
    signed_in_typed(
        &state,
        &browser,
        &session,
        Some(&membership),
        StatusCode::OK,
        "Templates",
        "templates",
        None,
        None,
        None,
        |_, _| crate::templates::compiled::pages::templates::render(&page),
    )
    .await
}

/// The Deploy app form, in either mode, and the parts of an app's
/// Settings that make a release. Its environment and secrets post as rows
/// (`env_key`/`env_value`, `secrets_key`/`secrets_value`), so it is read
/// with [`NewForm::from_pairs`]. `secrets` is never written back into the
/// page.
#[derive(Deserialize, Default)]
pub struct NewForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) template: String,
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) image: String,
    #[serde(default)]
    pub(crate) exposure: String,
    #[serde(default)]
    pub(crate) port: String,
    #[serde(default)]
    pub(crate) copies: String,
    #[serde(skip_deserializing)]
    pub(crate) env: Vec<(String, String)>,
    #[serde(skip)]
    secrets: Vec<(String, String)>,
    #[serde(default)]
    pub(crate) check: String,
    #[serde(default)]
    pub(crate) check_path: String,
    #[serde(default)]
    pub(crate) memory: String,
    #[serde(default)]
    pub(crate) cpu: String,
    #[serde(default)]
    pub(crate) preset: String,
    #[serde(default)]
    pub(crate) shown_preset: String,
    #[serde(default)]
    pub(crate) command: String,
    #[serde(default)]
    pub(crate) stop_signal: String,
    #[serde(default)]
    pub(crate) stop_grace: String,
    #[serde(default)]
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
            cpu: match spec.cpu_millis {
                0 => String::new(),
                millis => super::resources::vcpus(millis),
            },
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
    let cpu_millis =
        match form.cpu.trim() {
            "" => None,
            text => Some(super::resources::millis_of(text).ok_or_else(|| {
                Refusal::field("cpu", "CPU is a number of vCPUs, from 0.01 to 64.")
            })?),
        };
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
    new_view(&state, &browser, &session, &membership, form, refused).await
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

pub struct AppTab {
    pub key: &'static str,
    pub href: String,
    pub label: &'static str,
    pub icon: &'static str,
}

const APP_TABS: &[(&str, &str, &str, &str)] = &[
    ("overview", "", "Overview", "home"),
    ("deployments", "/deployments", "Deployments", "layers"),
    ("logs", "/logs", "Logs", "file"),
    ("metrics", "/metrics", "Metrics", "bars"),
    ("settings", "/settings", "Settings", "gear"),
];

fn part_of(field: &str) -> &'static str {
    match field {
        "image" => "image",
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

fn image_line(image: &str, digest: &str) -> String {
    let image = image.split('@').next().unwrap_or_default();
    let short = image
        .trim_start_matches("docker.io/")
        .trim_start_matches("library/");
    let hex: String = digest
        .trim_start_matches("sha256:")
        .chars()
        .take(12)
        .collect();
    format!("{short} · {hex}")
}

fn image_named(now: &str, given: &str) -> String {
    let given = given.trim();
    if given.is_empty() || given.contains(['/', ':', '@']) {
        return given.to_string();
    }
    let name = now.split('@').next().unwrap_or_default();
    let last = name.rfind('/').map_or(0, |i| i + 1);
    let repository = match name[last..].rfind(':') {
        Some(colon) => &name[..last + colon],
        None => name,
    };
    format!("{repository}:{given}")
}

pub struct SettingItem {
    pub key: &'static str,
    pub title: &'static str,
    pub icon: &'static str,
    pub value: Option<String>,
}

pub struct SettingItems {
    pub configured: Vec<SettingItem>,
    pub more: Vec<SettingItem>,
}

fn setting_items(
    spec: &AppSpec,
    image: &str,
    settings: &grund_domain::app::AppSettings,
    address: Option<&str>,
    secrets: &[String],
    domains: &[String],
) -> SettingItems {
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
    let item = |key: &'static str,
                title: &'static str,
                icon: &'static str,
                value: Option<String>| SettingItem {
        key,
        title,
        icon,
        value,
    };
    let mut configured = vec![
        item("image", "Image", "layers", Some(image.to_string())),
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
    SettingItems { configured, more }
}

const FILE_NAME: &str = "grund.yaml";

fn placement_words(settings: &grund_domain::app::AppSettings) -> String {
    let rules = &settings.placement;
    let mut parts = vec![
        grund_domain::app::placement::rules_words(settings)
            .map_or("Anywhere".to_string(), |words| capitalise(&words)),
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
    if settings.reschedule_after_seconds
        != grund_domain::app::AppSettings::default().reschedule_after_seconds
    {
        parts.push(format!(
            "replaced after {}",
            grund_domain::app::reconcile::span_words(chrono::Duration::seconds(i64::from(
                settings.reschedule_after_seconds
            )))
        ));
    }
    parts.join(" · ")
}

async fn resource_ceiling(
    state: &State,
    membership: &Membership,
) -> Result<Option<(u64, u32)>, PageError> {
    let machines: Vec<_> = state
        .machines()
        .organisation_machines(membership.organisation_id)
        .await?
        .iter()
        .map(|row| crate::services::apps::machine_view(row, None))
        .collect();
    Ok(super::resources::ceiling(&machines))
}

#[derive(Default)]
pub(super) struct Refused {
    pub(super) part: &'static str,
    pub(super) edit: String,
    pub(super) refusal: Refusal,
    pub(super) form: Option<NewForm>,
    pub(super) variable: String,
    pub(super) file: Option<String>,
    pub(super) placement: Option<super::placement::PlacementForm>,
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

pub struct AppDomain {
    pub state_words: &'static str,
    pub name: String,
    pub serving: bool,
}

pub struct AppIdentity {
    pub name: String,
    pub base: String,
    pub icon: &'static str,
    pub image: Option<String>,
    pub address: Option<String>,
    pub domains: Vec<AppDomain>,
    pub domains_href: String,
    pub internal: Option<String>,
    pub word: &'static str,
    pub tone: &'static str,
}

pub struct RunningRelease {
    pub version: String,
    pub line: String,
    pub reference: String,
}

pub struct ReplicaView {
    pub slot: i32,
    pub of: u32,
    pub release: i32,
    pub machine: String,
    pub words: String,
    pub tone: &'static str,
    pub placed: String,
}

pub struct SecretView {
    pub variable: String,
    pub name: String,
    pub sub: String,
}

pub struct AppShellPage {
    pub slug: String,
    pub tab: String,
    pub tabs: Vec<AppTab>,
    pub app: AppIdentity,
    pub waiting: Vec<String>,
    pub notice: String,
    pub error: String,
    pub manages: bool,
}

pub struct AppOverviewPage<'a> {
    pub app: &'a AppIdentity,
    pub running: &'a Option<RunningRelease>,
    pub releases: &'a [ReleaseView],
}

pub struct AppDeploymentsPage<'a> {
    pub app: &'a AppIdentity,
    pub replicas: &'a [ReplicaView],
    pub crowded: &'a Option<String>,
    pub releases: &'a [ReleaseView],
    pub manages: bool,
    pub csrf: &'a str,
}

pub struct AppSoonPage {
    pub title: &'static str,
    pub text: &'static str,
}

pub enum SettingsEdit {
    List,
    Image {
        image: String,
    },
    Exposure {
        exposure: String,
        port: String,
        choices: Vec<ExposureChoice>,
        hint: String,
        port_hint: String,
        ports: Vec<String>,
    },
    Copies {
        copies: String,
        auto_rollback: bool,
    },
    Placement(Box<super::placement::PlacementView>),
    Check {
        check: String,
        path: String,
    },
    Resources(super::resources::ResourceView),
    Env {
        pairs: Vec<(String, String)>,
    },
    Secrets {
        rows: Vec<SecretView>,
        variable: String,
    },
    Domains,
    Volumes,
    Command {
        command: String,
        stop_signal: String,
        stop_grace: String,
        signals: Vec<(&'static str, &'static str)>,
    },
    File {
        content: Option<String>,
        rows: usize,
        href: String,
    },
    Delete,
}

pub struct AppSettingsData {
    pub items: Option<SettingItems>,
    pub edit: SettingsEdit,
    pub next: Option<i32>,
    pub errors: std::collections::BTreeMap<&'static str, String>,
    pub banners: std::collections::BTreeMap<&'static str, String>,
}

/// Borrowed options for the form components' slice props. Built once from the
/// selected edit, rather than allocating adapters while rendering markup.
#[derive(Default)]
pub struct SettingsOptions<'a> {
    pub ports: Vec<&'a str>,
    pub machines: Vec<(&'a str, &'a str)>,
    pub chosen_machines: Vec<&'a str>,
    pub labels: Vec<(&'a str, &'a str)>,
    pub chosen_labels: Vec<&'a str>,
    pub apps: Vec<(&'a str, &'a str)>,
    pub near: Vec<&'a str>,
    pub apart: Vec<&'a str>,
    pub typed_labels: Vec<(&'a str, &'a str)>,
    pub label_keys: Vec<&'a str>,
    pub label_values: Vec<&'a str>,
    pub memory_steps: Vec<(&'a str, &'a str)>,
    pub cpu_steps: Vec<(&'a str, &'a str)>,
    pub memory_min: String,
    pub memory_max: String,
    pub env: Vec<(&'a str, &'a str)>,
}

fn setting_options<'a>(edit: &'a SettingsEdit, memory_values: &'a [String]) -> SettingsOptions<'a> {
    let pairs = |rows: &'a [(String, String)]| {
        rows.iter()
            .map(|(value, text)| (value.as_str(), text.as_str()))
            .collect()
    };
    let strings = |values: &'a [String]| values.iter().map(String::as_str).collect();
    match edit {
        SettingsEdit::Exposure { ports, .. } => SettingsOptions {
            ports: strings(ports),
            ..Default::default()
        },
        SettingsEdit::Placement(place) => SettingsOptions {
            machines: pairs(&place.machines),
            chosen_machines: strings(&place.chosen_machines),
            labels: pairs(&place.labels),
            chosen_labels: strings(&place.chosen_labels),
            apps: pairs(&place.apps),
            near: strings(&place.near),
            apart: strings(&place.apart),
            typed_labels: pairs(&place.typed_labels),
            label_keys: strings(&place.label_keys),
            label_values: strings(&place.label_values),
            ..Default::default()
        },
        SettingsEdit::Resources(resources) => SettingsOptions {
            memory_steps: resources
                .memory_steps
                .iter()
                .zip(memory_values.iter())
                .map(|((_, label), value)| (value.as_str(), label.as_str()))
                .collect(),
            cpu_steps: pairs(&resources.cpu_steps),
            memory_min: resources.memory_min.to_string(),
            memory_max: resources.memory_max.to_string(),
            ..Default::default()
        },
        SettingsEdit::Env { pairs: rows } => SettingsOptions {
            env: pairs(rows),
            ..Default::default()
        },
        _ => SettingsOptions::default(),
    }
}

pub struct AppSettingsPage<'a> {
    pub app: &'a AppIdentity,
    pub items: &'a Option<SettingItems>,
    pub edit: &'a SettingsEdit,
    pub next: Option<i32>,
    pub manages: bool,
    pub form: crate::templates::FormState<'a>,
    pub options: SettingsOptions<'a>,
}

pub struct AppDetailPage {
    pub shell: AppShellPage,
    pub running: Option<RunningRelease>,
    pub releases: Vec<ReleaseView>,
    pub replicas: Vec<ReplicaView>,
    pub crowded: Option<String>,
    pub soon: AppSoonPage,
    pub settings: AppSettingsData,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn app_view(
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
    let icon = listing
        .spec
        .as_ref()
        .map_or("image", |spec| image_icon(&spec.image));
    let running = current
        .and_then(|number| releases.iter().find(|r| r.number == number))
        .map(|r| RunningRelease {
            version: format!("v{}", r.number),
            line: image_line(&r.spec.0.image, &r.image_digest),
            reference: format!(
                "{}@{}",
                r.spec.0.image.split('@').next().unwrap_or_default(),
                r.image_digest
            ),
        });
    let replicas: Vec<ReplicaView> = view
        .replicas
        .iter()
        .map(|replica| {
            let (words, tone) = replica_words(replica, now);
            ReplicaView {
                slot: replica.slot + 1,
                of: wanted,
                release: replica.release,
                machine: replica.machine_name.clone().unwrap_or_default(),
                words,
                tone,
                placed: when(replica.placed_at),
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
            Some(release)
                if i == 0 && ready_copies(view, i64::from(release), now) < wanted as usize =>
            {
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
    let history: Vec<ReleaseView> = releases
        .iter()
        .map(|r| release_view(r, current, now))
        .collect();
    let newest = releases.first();
    let spec = newest.map(|r| &r.spec.0);
    let edit = if refused.part.is_empty() {
        refused.edit.as_str()
    } else {
        refused.part
    };
    let form = if tab == "settings"
        && matches!(
            edit,
            "image" | "exposure" | "check" | "resources" | "env" | "command"
        ) {
        refused.form.unwrap_or_else(|| match spec {
            Some(spec) => NewForm::from_spec(spec, wanted),
            None => NewForm::default(),
        })
    } else {
        NewForm::default()
    };
    let read: Vec<&SecretEnv> = if tab == "settings" && edit == "secrets" {
        spec.map(|s| s.secrets.iter().collect()).unwrap_or_default()
    } else {
        Vec::new()
    };
    let secret_names: Vec<String> = if tab == "settings" {
        spec.map(|s| s.secrets.iter().map(|secret| secret.env.clone()).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut secrets: Vec<SecretView> = read
        .iter()
        .map(|secret| {
            let stored = view.secrets.iter().find(|(n, _, _)| *n == secret.secret);
            SecretView {
                variable: secret.env.clone(),
                name: secret.secret.clone(),
                sub: match stored {
                    Some((_, version, at)) => format!(
                        "secret {} · version {version} · set {}",
                        secret.secret,
                        when(*at)
                    ),
                    None => format!("secret {} · not stored", secret.secret),
                },
            }
        })
        .collect();
    if tab == "settings" && edit == "secrets" {
        secrets.extend(
            view.secrets
                .iter()
                .filter(|(n, _, _)| !read.iter().any(|s| s.secret == *n))
                .map(|(name, version, at)| SecretView {
                    variable: String::new(),
                    name: name.clone(),
                    sub: format!(
                        "not read by the app · version {version} · set {}",
                        when(*at)
                    ),
                }),
        );
    }
    let errors: std::collections::BTreeMap<&str, &str> = refused
        .refusal
        .fields
        .iter()
        .map(|(field, text)| (*field, text.as_str()))
        .collect();
    let ports = if tab == "settings" && edit == "exposure" {
        match newest {
            Some(r) => {
                let reference = format!(
                    "{}@{}",
                    r.spec.0.image.split('@').next().unwrap_or_default(),
                    r.image_digest
                );
                match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    apps.inspect(membership.organisation_id, &reference),
                )
                .await
                {
                    Ok(Ok(inspection)) => inspection.exposed_ports,
                    _ => Vec::new(),
                }
            }
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    let placement = if tab == "settings" && edit == "placement" {
        let placement_form = refused
            .placement
            .unwrap_or_else(|| super::placement::PlacementForm::of(&view.row.settings.0));
        Some(
            super::placement::context_for(
                state,
                membership,
                &view.row.name,
                &placement_form,
                &errors,
            )
            .await?,
        )
    } else {
        None
    };
    let banners = if refused.part.is_empty() || refused.refusal.banner.is_empty() {
        std::collections::BTreeMap::new()
    } else {
        std::collections::BTreeMap::from([(refused.part, refused.refusal.banner)])
    };
    let file = if tab == "settings" && edit == "file" {
        refused.file.or_else(|| {
            newest.map(|r| {
                render_file(
                    &view.row.name,
                    &r.spec.0,
                    &view.row.settings.0,
                    &schema_url(state),
                )
            })
        })
    } else {
        None
    };
    let (soon_title, soon_text) = match tab {
        "logs" => ("Logs are coming", "grund does not collect logs yet."),
        _ => ("Metrics are coming", "grund does not collect metrics yet."),
    };
    let bound = state
        .domains()
        .of_app(view.row.app_id)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    let domain_names: Vec<String> = bound.iter().map(|d| d.name.clone()).collect();
    let domains: Vec<AppDomain> = bound
        .into_iter()
        .map(|domain| {
            let serving = domain.status == crate::services::domains::Status::Issued;
            AppDomain {
                state_words: if serving {
                    "Serving with its own certificate"
                } else {
                    "Bound; its certificate is on its way once its DNS points here"
                },
                name: domain.name,
                serving,
            }
        })
        .collect();
    let settings_edit = if tab != "settings" || newest.is_none() {
        SettingsEdit::List
    } else {
        match edit {
            "image" => SettingsEdit::Image { image: form.image },
            "exposure" => {
                let port_words: Vec<String> = ports.iter().map(u16::to_string).collect();
                let port_hint = if port_words.is_empty() {
                    "Empty: no port.".to_string()
                } else {
                    format!(
                        "The image listens on {}. Empty: no port.",
                        port_words.join(", ")
                    )
                };
                SettingsEdit::Exposure {
                    exposure: form.exposure,
                    port: form.port,
                    choices: exposures(state.config.entry.app_domain.as_deref()),
                    hint: state
                        .config
                        .entry
                        .app_domain
                        .as_deref()
                        .map(|domain| format!("Public: https://{}-{slug}.{domain}", view.row.name))
                        .unwrap_or_default(),
                    port_hint,
                    ports: port_words,
                }
            }
            "copies" => SettingsEdit::Copies {
                copies: wanted.to_string(),
                auto_rollback: view.row.settings.0.auto_rollback,
            },
            "placement" => SettingsEdit::Placement(Box::new(placement.expect("placement view"))),
            "check" => SettingsEdit::Check {
                check: form.check,
                path: form.check_path,
            },
            "resources" => SettingsEdit::Resources(super::resources::view(
                &form.memory,
                &form.cpu,
                resource_ceiling(state, membership).await?,
            )),
            "env" => SettingsEdit::Env { pairs: form.env },
            "secrets" => SettingsEdit::Secrets {
                rows: secrets,
                variable: refused.variable,
            },
            "domains" => SettingsEdit::Domains,
            "volumes" => SettingsEdit::Volumes,
            "command" => SettingsEdit::Command {
                command: form.command,
                stop_signal: form.stop_signal,
                stop_grace: form.stop_grace,
                signals: STOP_SIGNALS
                    .iter()
                    .map(|signal| (*signal, *signal))
                    .collect(),
            },
            "file" => SettingsEdit::File {
                rows: file.as_ref().map_or(0, |f| f.lines().count() + 1),
                content: file,
                href: format!("{base}/grund.yaml"),
            },
            "delete" if manages(membership) => SettingsEdit::Delete,
            _ => SettingsEdit::List,
        }
    };
    let page = AppDetailPage {
        shell: AppShellPage {
            slug: slug.clone(),
            tab: tab.to_owned(),
            tabs: APP_TABS
                .iter()
                .map(|(key, path, label, icon)| AppTab {
                    key,
                    href: format!("{base}{path}"),
                    label,
                    icon,
                })
                .collect(),
            app: AppIdentity {
                name: view.row.name.clone(),
                base: base.clone(),
                icon,
                image: spec.map(|s| s.image.clone()),
                address: listing.address.clone(),
                domains,
                domains_href: format!("/{slug}/domains#custom"),
                internal: listing
                    .spec
                    .as_ref()
                    .and_then(|spec| internal_address(&view.row.name, spec)),
                word: health.word,
                tone: health.tone,
            },
            waiting,
            notice,
            error,
            manages: manages(membership),
        },
        running,
        releases: history,
        replicas,
        crowded,
        soon: AppSoonPage {
            title: soon_title,
            text: soon_text,
        },
        settings: AppSettingsData {
            items: if tab == "settings" {
                newest.map(|r| {
                    setting_items(
                        &r.spec.0,
                        &image_line(&r.spec.0.image, &r.image_digest),
                        &view.row.settings.0,
                        listing.address.as_deref(),
                        &secret_names,
                        &domain_names,
                    )
                })
            } else {
                None
            },
            edit: settings_edit,
            next: newest.map(|r| r.number + 1),
            errors: refused.refusal.fields,
            banners,
        },
    };
    let status = if refused.part.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let title = format!("{} · Apps", view.row.name);
    signed_in_typed(
        state,
        browser,
        session,
        Some(membership),
        status,
        &title,
        "apps",
        None,
        (busy && matches!(tab, "overview" | "deployments")).then_some(5),
        None,
        |_, csrf| {
            let mut html = crate::templates::compiled::pages::app::render(&page.shell);
            html.push_str(&match tab {
                "overview" => {
                    crate::templates::compiled::pages::app_overview::render(&AppOverviewPage {
                        app: &page.shell.app,
                        running: &page.running,
                        releases: &page.releases,
                    })
                }
                "deployments" => crate::templates::compiled::pages::app_deployments::render(
                    &AppDeploymentsPage {
                        app: &page.shell.app,
                        replicas: &page.replicas,
                        crowded: &page.crowded,
                        releases: &page.releases,
                        manages: page.shell.manages,
                        csrf,
                    },
                ),
                "settings" => {
                    let memory_values: Vec<String> = match &page.settings.edit {
                        SettingsEdit::Resources(view) => view
                            .memory_steps
                            .iter()
                            .map(|(mib, _)| mib.to_string())
                            .collect(),
                        _ => Vec::new(),
                    };
                    crate::templates::compiled::pages::app_settings::render(&AppSettingsPage {
                        app: &page.shell.app,
                        items: &page.settings.items,
                        edit: &page.settings.edit,
                        next: page.settings.next,
                        manages: page.shell.manages,
                        form: crate::templates::FormState {
                            csrf,
                            errors: &page.settings.errors,
                            banners: &page.settings.banners,
                        },
                        options: setting_options(&page.settings.edit, &memory_values),
                    })
                }
                _ => crate::templates::compiled::pages::app_soon::render(&page.soon),
            });
            html
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
            placement: None,
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

/// `POST /{org}/apps/{app}/settings/release`: one Settings item (`part`)
/// as a new release. Every part but `image` releases the image digest the
/// newest release runs; `image` takes a tag, or a whole reference, and
/// resolves it now.
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
    let typed = posted.image.clone();
    let part = match posted.part.as_str() {
        "image" => "image",
        "exposure" => "exposure",
        "env" => "env",
        "check" => "check",
        "resources" => "resources",
        "command" => "command",
        _ => "exposure",
    };
    let now = NewForm::from_spec(&spec, copies);
    let form = match part {
        "image" => NewForm {
            image: image_named(&spec.image, &posted.image),
            ..now
        },
        "env" => NewForm {
            env: posted.env,
            ..now
        },
        "check" => NewForm {
            check: posted.check,
            check_path: posted.check_path,
            ..now
        },
        "resources" => {
            let (memory, cpu) = super::resources::chosen(
                &posted.preset,
                &posted.shown_preset,
                &posted.memory,
                &posted.cpu,
            );
            NewForm { memory, cpu, ..now }
        }
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
            same_image: part != "image",
        })
    };
    let made = match made {
        Ok(change) if part == "resources" => {
            let memory = match change.spec.memory_mib {
                0 => super::resources::DEFAULT_MEMORY_MIB,
                m => m,
            };
            let cpu = match change.spec.cpu_millis {
                0 => super::resources::DEFAULT_CPU_MILLIS,
                c => c,
            };
            match resource_ceiling(&state, &membership).await? {
                Some((most, _)) if memory > most => Err(Refusal::field(
                    "memory",
                    format!("The largest machine here gives one copy at most {most} MiB."),
                )),
                Some((_, most)) if cpu > most => Err(Refusal::field(
                    "cpu",
                    format!(
                        "The largest machine here gives one copy at most {} vCPU.",
                        super::resources::vcpus(most)
                    ),
                )),
                _ => Ok(change),
            }
        }
        other => other,
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
        Some(match part {
            "image" => NewForm {
                image: typed,
                ..form
            },
            _ => form,
        }),
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
            placement: None,
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
            placement: None,
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
        let keys = |items: &[SettingItem]| items.iter().map(|item| item.key).collect::<Vec<_>>();
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
        let bare = setting_items(
            &spec,
            "whoami:v1.11.0 · 0123456789ab",
            &settings,
            None,
            &[],
            &[],
        );
        assert_eq!(
            keys(&bare.configured),
            ["image", "exposure", "copies", "resources"]
        );
        assert_eq!(
            keys(&bare.more),
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
        let set = setting_items(
            &spec,
            "whoami:v1.11.0 · 0123456789ab",
            &settings,
            None,
            &["TOKEN".into()],
            &[],
        );
        assert_eq!(
            keys(&set.configured),
            [
                "image",
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
        assert_eq!(keys(&set.more), ["domains", "volumes", "file"]);
    }

    #[test]
    fn a_tag_alone_replaces_the_tag_of_the_image_the_app_runs_and_a_whole_reference_is_taken_as_it_is()
     {
        for (now, given, named) in [
            (
                "traefik/whoami:v1.10.3",
                "v1.11.0",
                "traefik/whoami:v1.11.0",
            ),
            ("nginx", "1.27", "nginx:1.27"),
            (
                "localhost:5000/acme/shop:1",
                " 2 ",
                "localhost:5000/acme/shop:2",
            ),
            (
                "ghcr.io/acme/shop:1@sha256:0123",
                "2",
                "ghcr.io/acme/shop:2",
            ),
            ("traefik/whoami:v1.10.3", "nginx:1.27", "nginx:1.27"),
            ("traefik/whoami:v1.10.3", "acme/shop", "acme/shop"),
            (
                "traefik/whoami:v1.10.3",
                "traefik/whoami@sha256:00",
                "traefik/whoami@sha256:00",
            ),
            ("traefik/whoami:v1.10.3", "  ", ""),
        ] {
            assert_eq!(image_named(now, given), named, "{now} + {given}");
        }
    }

    #[test]
    fn an_image_reads_as_its_short_name_and_twelve_hex_of_its_digest() {
        assert_eq!(
            image_line(
                "docker.io/library/nginx:1.27@sha256:aa",
                "sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab"
            ),
            "nginx:1.27 · 200689790a0a"
        );
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
