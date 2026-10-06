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
    http::{StatusCode, Uri},
    response::Response,
};
use chrono::{DateTime, Utc};
use grund_domain::{
    app::{
        spec::{
            AppSpec, CheckKind, CheckSpec, EnvVar, MAX_COPIES, PortSpec, Protocol, STOP_SIGNALS,
            SecretEnv, SettingsInput, StopSpec,
        },
        templates,
        toml::render as render_toml,
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
        apps::{AppListing, AppView, AppsError, AppsState, Change, Launch},
        domains::DomainsState,
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
    line: String,
    ready: usize,
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

fn health(view: &AppView, releases: &[ReleaseRow], now: DateTime<Utc>) -> Health {
    let row = &view.row;
    let wanted = row.settings.0.copies as usize;
    let rollout = row.rollout.as_ref();
    let to = rollout.and_then(|r| r["to"].as_i64()).unwrap_or(0);
    let current = row.current_release.map(i64::from);
    let ready = current.map_or(0, |c| ready_copies(view, c, now));
    let health = |word, tone, line: String| Health {
        word,
        tone,
        line,
        ready,
    };
    if row.halted {
        return health(
            "Failed",
            "danger",
            format!(
                "grund is leaving {} as it is: v{to} failed and automatic rollback is off. Deploy or roll back to go on.",
                row.name
            ),
        );
    }
    match rollout.and_then(|r| r["state"].as_str()) {
        Some("in_progress") => {
            let started = releases
                .iter()
                .find(|r| r.number as i64 == to)
                .map(|r| {
                    let words = release_words(r);
                    format!(" · started by {} {}", words.by, words.source)
                })
                .unwrap_or_default();
            health(
                "Rolling out",
                "blue",
                format!(
                    "Releasing v{to}{} · {} of {wanted} ready",
                    started.trim_end(),
                    ready_copies(view, to, now)
                ),
            )
        }
        Some("failed") => {
            let reason = rollout
                .and_then(|r| r["reason"].as_str())
                .unwrap_or_default();
            match current {
                Some(current) => health(
                    "Failed",
                    "danger",
                    format!("{reason} v{current} is still serving."),
                ),
                None => health("Failed", "danger", format!("{reason} Nothing is running.")),
            }
        }
        _ => match current {
            None => health(
                "Stopped",
                "muted",
                format!("{} has no version yet. Deploy one.", row.name),
            ),
            Some(current) if ready >= wanted => health(
                "Live",
                "ok",
                format!("v{current} is live on {}", copies(ready)),
            ),
            Some(current) if ready == 0 => health(
                "Degraded",
                "orange",
                format!("No copy of v{current} is ready. grund keeps trying."),
            ),
            Some(current) => health(
                "Degraded",
                "orange",
                format!("v{current} is live on {ready} of {wanted} copies"),
            ),
        },
    }
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
    let Health { line, tone, .. } = health(view, &[], Utc::now());
    let image = listing
        .spec
        .as_ref()
        .map(|spec| spec.image.clone())
        .unwrap_or_default();
    context! {
        name => view.row.name,
        line,
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
            "file" => "from grund.toml",
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
    context! {
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
        "created" => "App made. Its first version is rolling out.",
        "deployed" => "New release made. It rolls out behind its ready check.",
        "released" => {
            "Settings saved as a new release of the same image. It rolls out behind its ready check."
        }
        "saved" => "Saved.",
        "secret" => "Secret stored. A release that reads it is rolling out.",
        "secret-removed" => "Secret removed. A release without it is rolling out.",
        "rolled-back" => "Rolling back: an earlier release's image and settings, as a new release.",
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
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Query(query): Query<ListQuery>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
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
    let viewer = viewer_context(&state, &session, Some(&membership)).await?;
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/apps.html.jinja",
        context! {
            viewer,
            list_href => href(&q, "list"), grid_href => href(&q, "grid"), all_href => href("", view),
            icons => icons_of(&shown),
            apps => shown.iter().map(|l| listing_context(l)).collect::<Vec<_>>(),
            total => listings.len(),
            list => context! { q, sort, view }, sorts => SORTS,
            notice => notice_words(&query.done), error => error_words(&query.error),
            csrf => browser.csrf_token(), section => "apps",
        },
    )
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
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Query(query): Query<DeployQuery>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
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
                (Some("env" | "secrets" | "command"), Some(line)) => {
                    format!("Line {line}: {}.", spec.problem)
                }
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
        context! { value => "private", title => "Private", icon => "lock", text => "Only accessible within grund" },
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
    let viewer = viewer_context(state, session, Some(membership)).await?;
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
    let secrets_dropped = !refused.banner.is_empty() && !new.secrets.trim().is_empty();
    let errors: std::collections::BTreeMap<&str, &str> = FORM_FIELDS
        .iter()
        .map(|field| (*field, refused.fields.get(field).map_or("", String::as_str)))
        .collect();
    render(
        state,
        browser,
        if refused.banner.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        },
        "pages/deploy.html.jinja",
        context! {
            viewer,
            mode => if premade { "premade" } else { "custom" },
            modes => vec![
                context! {
                    key => "premade", href => mode_href("premade"), icon => "grid", title => "Premade",
                    text => "Quickly deploy popular apps", sub => "NATS, whoami and nginx; databases with storage",
                },
                context! {
                    key => "custom", href => mode_href("custom"), icon => "box", title => "Custom",
                    text => "Deploy any container image", sub => "Paste an image and deploy with sensible defaults",
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
            csrf => browser.csrf_token(), section => "deploy",
        },
    )
}

/// `/{org}/templates`: the premade apps, the same list Deploy app offers.
pub async fn templates_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let viewer = viewer_context(&state, &session, Some(&membership)).await?;
    let shown: Vec<Value> = templates::CATALOGUE.iter().map(template_context).collect();
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/templates.html.jinja",
        context! {
            viewer, templates => shown, image_keys => template_icons(),
            csrf => browser.csrf_token(), section => "templates",
        },
    )
}

/// The Deploy app form, in either mode. `secrets` is never written back
/// into the page.
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
    #[serde(default)]
    env: String,
    #[serde(default, skip_serializing)]
    secrets: String,
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
            env: lines(
                spec.env
                    .iter()
                    .map(|e| format!("{}={}", e.name, e.value))
                    .collect(),
            ),
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

fn pairs(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match line.split_once('=') {
            Some((name, value)) => pairs.push((name.trim().to_string(), value.to_string())),
            None => {
                return Err(format!(
                    "Line {}: write NAME=value; this line has no '='.",
                    i + 1
                ));
            }
        }
    }
    Ok(pairs)
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
    let env = pairs(&form.env)
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
        secrets: pairs(&form.secrets).map_err(|message| Refusal::field("secrets", message))?,
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
    Form(form): Form<NewForm>,
) -> PageResult {
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
}

const APP_TABS: &[(&str, &str, &str, &str)] = &[
    ("overview", "", "Overview", "home"),
    ("deployments", "/deployments", "Deployments", "layers"),
    ("logs", "/logs", "Logs", "file"),
    ("metrics", "/metrics", "Metrics", "bars"),
    ("settings", "/settings", "Settings", "gear"),
];

const SETTINGS_FIELDS: &[&str] = &[
    "copies", "exposure", "port", "check", "env", "variable", "value", "confirm",
];

#[derive(Default)]
struct Refused {
    part: &'static str,
    refusal: Refusal,
    form: Option<NewForm>,
    variable: String,
}

macro_rules! app_page {
    ($name:ident, $tab:literal, $doc:literal) => {
        #[doc = $doc]
        pub async fn $name(
            AxumState(state): AxumState<State>,
            browser: Browser,
            uri: Uri,
            Path((slug, name)): Path<(String, String)>,
            Query(query): Query<AppQuery>,
        ) -> PageResult {
            let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
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
                Refused::default(),
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
    let health = health(view, &releases, now);
    let shown = listing_context(&listing);
    let lede = match health.word {
        "Live" if listing.address.is_some() => "Your application is running and accessible.",
        "Live" if shown.get_attr("internal").is_ok_and(|i| !i.is_none()) => {
            "Your application is running. Other apps reach it by its internal name."
        }
        "Live" => "Your application is running.",
        "Rolling out" => "A new release is rolling out behind its ready check.",
        "Degraded" => "Not every copy is ready.",
        "Failed" => "The newest release did not start.",
        _ => "Nothing runs yet.",
    };
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
    let banners: std::collections::BTreeMap<&str, &str> =
        ["copies", "release", "secrets", "delete"]
            .into_iter()
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
    let soon = match tab {
        "logs" => context! {
            title => "Logs are coming",
            text => "grund does not collect what an app writes yet. When it does, each copy's output and errors show here, as they happen.",
        },
        _ => context! {
            title => "Metrics are coming",
            text => "grund does not measure apps yet. When it does, each copy's CPU and memory, and the requests that reach the app, show here.",
        },
    };
    let template = match tab {
        "overview" => "pages/app-overview.html.jinja",
        "deployments" => "pages/app-deployments.html.jinja",
        "settings" => "pages/app-settings.html.jinja",
        _ => "pages/app-soon.html.jinja",
    };
    let domains: Vec<Value> = state
        .domains()
        .of_app(view.row.app_id)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?
        .into_iter()
        .map(|domain| {
            let serving = domain.status == crate::services::domains::Status::Issued;
            context! {
                name => domain.name,
                serving,
                line => if serving { String::new() } else { format!("{}: waiting for its certificate", domain.name) },
            }
        })
        .collect();
    let viewer = viewer_context(state, session, Some(membership)).await?;
    render(
        state,
        browser,
        if refused.part.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        },
        template,
        context! {
            viewer,
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
                word => health.word, tone => health.tone, line => health.line, lede,
                ready => health.ready,
                copies_line => if health.ready >= wanted as usize { "Running instances".to_string() } else { format!("Ready, of {wanted} wanted") },
            },
            latest => history.first(),
            activity => history.iter().take(3).collect::<Vec<_>>(),
            releases => history,
            replicas, waiting, crowded,
            refresh => busy && matches!(tab, "overview" | "deployments"),
            soon,
            settings => context! {
                copies => wanted,
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
            file => newest.map(|r| render_toml(&view.row.name, &r.spec.0, &view.row.settings.0)),
            notice, error,
            topbar_action => (format!("/{slug}/apps/{}/deploy", view.row.name), "Deploy change"),
            csrf => browser.csrf_token(), section => "apps",
        },
    )
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
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
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
    Form(form): Form<NewForm>,
) -> PageResult {
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
        secrets: pairs(&form.secrets).map_err(|message| Refusal::field("secrets", message))?,
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
                input.auto_rollback = Some(form.auto_rollback != "off");
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

/// `POST /{org}/apps/{app}/settings/release`: exposure, port, ready check
/// and environment, as a new release of the image the newest one runs.
pub async fn release_settings(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(posted): Form<NewForm>,
) -> PageResult {
    if !browser.form_is_genuine(&posted.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let (spec, copies) = newest_or_return!(&state, &membership, &name);
    let form = NewForm {
        exposure: posted.exposure,
        port: posted.port,
        check: posted.check,
        check_path: posted.check_path,
        env: posted.env,
        ..NewForm::from_spec(&spec, copies)
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
    refuse_setting(
        &state,
        &browser,
        &session,
        &membership,
        &name,
        "release",
        refusal,
        Some(form),
    )
    .await
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
