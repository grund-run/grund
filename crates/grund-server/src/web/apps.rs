//! `/{org}/apps`: an organisation's apps (searched, sorted, as a list or a
//! grid), `/{org}/deploy` for a new app, and each app's page with its
//! copies, its rollout, its releases and the forms that deploy, scale, roll
//! back and set secrets (grund-docs design/apps.md §8.5, §5.4, §9). Also
//! `/{org}/domains`, the apps' addresses, and `/{org}/templates`, which says
//! templates are not built yet. Every member sees the pages; owners and
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
        ReleaseSource,
        spec::{
            AppSpec, CheckKind, CheckSpec, EnvVar, PortSpec, Protocol, SettingsInput, StopSpec,
        },
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
        apps::{AppListing, AppView, AppsError, AppsState, DeployInput},
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

fn status_line(view: &AppView) -> (String, &'static str) {
    let row = &view.row;
    let name = &row.name;
    let ready = |release: i64| {
        view.replicas
            .iter()
            .filter(|r| {
                r.release as i64 == release && r.state == "running" && r.ready == Some(true)
            })
            .count()
    };
    let wanted = row.settings.0.copies as usize;
    let rollout = row.rollout.as_ref();
    let to = rollout.and_then(|r| r["to"].as_i64()).unwrap_or(0);
    let current = row.current_release.map(i64::from);
    match rollout.and_then(|r| r["state"].as_str()) {
        _ if row.halted => (
            format!(
                "grund is leaving {name} as it is: v{to} failed and automatic rollback is off. Deploy or roll back to go on."
            ),
            "orange",
        ),
        Some("in_progress") => (
            format!("Releasing v{to} · {} of {wanted} ready", ready(to)),
            "muted",
        ),
        Some("failed") => {
            let reason = rollout
                .and_then(|r| r["reason"].as_str())
                .unwrap_or_default();
            match current {
                Some(current) => (format!("{reason} v{current} is still serving."), "orange"),
                None => (format!("{reason} Nothing is running."), "orange"),
            }
        }
        _ => match current {
            Some(current) => (
                format!("v{current} is live on {}", copies(ready(current))),
                if ready(current) >= wanted {
                    "ok"
                } else {
                    "orange"
                },
            ),
            None => (format!("{name} has no version yet. Deploy one."), "muted"),
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
    let (line, tone) = status_line(view);
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

fn release_context(row: &ReleaseRow) -> Value {
    let outcome = match row.outcome.as_deref() {
        Some("rolling_out") => ("Releasing", "muted"),
        Some("live") => ("Live", "ok"),
        Some("replaced") => ("Replaced", "muted"),
        Some("failed") => ("Failed", "orange"),
        Some("superseded") => ("Superseded", "muted"),
        _ => ("Made", "muted"),
    };
    let source = match row.source.as_str() {
        "dashboard" => "from the dashboard".to_string(),
        "api" => "from the API".to_string(),
        "file" => "from grund.toml".to_string(),
        "rollback" => format!("rolled back to v{}", row.rollback_of.unwrap_or(0)),
        _ => String::new(),
    };
    context! {
        number => row.number,
        image => row.spec.0.image,
        digest => row.image_digest,
        by => row.created_by_name.clone().unwrap_or_else(|| "someone".into()),
        at => when(row.created_at),
        source,
        note => row.note,
        outcome => outcome.0,
        tone => outcome.1,
        reason => row.reason,
        live => row.outcome.as_deref() == Some("live"),
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
        "deployed" => "New version made. It rolls out behind its ready check.",
        "scaled" => "Copies changed.",
        "secret" => "Secret stored. The next version you deploy uses it.",
        "rolled-back" => "Rolling back: an earlier version's contents, as a new version.",
        "deleted" => "App deleted. Its copies are stopping.",
        _ => "",
    }
}

fn error_words(error: &str) -> &'static str {
    match error {
        "not-allowed" => "Your role does not allow that.",
        "gone" => "That app is no longer there.",
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

/// `/{org}/deploy`: the form that makes an app and deploys its first
/// version.
pub async fn deploy_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    new_view(
        &state,
        &browser,
        &session,
        &membership,
        "",
        NewForm::default(),
    )
    .await
}

async fn new_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    new_error: &str,
    new: NewForm,
) -> PageResult {
    let viewer = viewer_context(state, session, Some(membership)).await?;
    render(
        state,
        browser,
        StatusCode::OK,
        "pages/deploy.html.jinja",
        context! {
            viewer, new_error, new => Value::from_serialize(&new),
            csrf => browser.csrf_token(), section => "deploy",
        },
    )
}

/// `/{org}/domains`: the address each app holds. Custom domains are not
/// built; the page says so.
pub async fn domains_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let addresses: Vec<Value> = state
        .apps()
        .listings(membership.organisation_id, &membership.slug)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?
        .iter()
        .filter_map(|l| {
            l.address
                .as_ref()
                .map(|address| context! { name => l.view.row.name, address })
        })
        .collect();
    let viewer = viewer_context(&state, &session, Some(&membership)).await?;
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/domains.html.jinja",
        context! { viewer, addresses, csrf => browser.csrf_token(), section => "domains" },
    )
}

/// `/{org}/templates`: not built yet, and the page says so.
pub async fn templates_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let viewer = viewer_context(&state, &session, Some(&membership)).await?;
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/templates.html.jinja",
        context! { viewer, csrf => browser.csrf_token(), section => "templates" },
    )
}

#[derive(Deserialize, Default, serde::Serialize)]
pub struct NewForm {
    #[serde(default, skip_serializing)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    check: String,
    #[serde(default)]
    copies: String,
}

fn simple_spec(image: &str, port: &str, check: &str, env: Vec<EnvVar>) -> Result<AppSpec, String> {
    let port = port.trim();
    let ports = if port.is_empty() {
        Vec::new()
    } else {
        let number: u16 = port
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .ok_or("A port is a number from 1 to 65535.")?;
        vec![PortSpec {
            name: "http".into(),
            port: number,
            protocol: Protocol::Http,
            public: false,
        }]
    };
    let check = check.trim();
    let check = if check.is_empty() {
        None
    } else {
        Some(CheckSpec {
            kind: CheckKind::Http {
                path: check.to_string(),
            },
            port: 0,
            interval_ms: 0,
            timeout_ms: 0,
        })
    };
    Ok(AppSpec {
        image: image.trim().to_string(),
        command: Vec::new(),
        ports,
        memory_mib: 0,
        cpu_millis: 0,
        env,
        secrets: Vec::new(),
        check,
        stop: StopSpec {
            signal: String::new(),
            grace_seconds: 0,
        },
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

/// `POST /{org}/apps/new`: makes the app and deploys its first version.
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
    let refuse = |message: String, form: NewForm| {
        let (state, browser, session, membership) = (&state, &browser, &session, &membership);
        async move { new_view(state, browser, session, membership, &message, form).await }
    };
    let copies = match form.copies.trim() {
        "" => None,
        text => match text.parse::<u32>() {
            Ok(n) => Some(n),
            Err(_) => return refuse("Copies is a whole number.".into(), form).await,
        },
    };
    let spec = match simple_spec(&form.image, &form.port, &form.check, Vec::new()) {
        Ok(spec) => spec,
        Err(message) => return refuse(message, form).await,
    };
    let spec = match spec.validate() {
        Ok(spec) => spec,
        Err(error) => return refuse(sentence(&AppsError::Spec(error)), form).await,
    };
    let apps = state.apps();
    if let Err(error) = apps
        .create(
            session.account_id,
            membership.organisation_id,
            &form.name,
            SettingsInput {
                copies,
                ..Default::default()
            },
        )
        .await
    {
        return refuse(sentence(&error), form).await;
    }
    let name = form.name.trim().to_ascii_lowercase();
    match apps
        .deploy(
            session.account_id,
            membership.organisation_id,
            &name,
            DeployInput::Spec(spec),
            ReleaseSource::Dashboard,
            "",
        )
        .await
    {
        Ok(_) => Ok(redirect(&format!("/{slug}/apps/{name}?done=created"))),
        Err(error) => Ok(redirect(&format!(
            "/{slug}/apps/{name}?deploy_error={}",
            urlencode(&sentence(&error))
        ))),
    }
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

/// `/{org}/apps/{app}`.
pub async fn app_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Query(query): Query<AppQuery>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    app_view(
        &state,
        &browser,
        &session,
        &membership,
        &name,
        AppForm {
            notice: notice_words(&query.done).into(),
            error: error_words(&query.error).into(),
            deploy_error: query.deploy_error.chars().take(300).collect(),
            ..Default::default()
        },
    )
    .await
}

#[derive(Default)]
struct AppForm {
    notice: String,
    error: String,
    deploy_error: String,
    deploy: Option<DeployForm>,
    secret_error: String,
    scale_error: String,
}

async fn app_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    name: &str,
    form: AppForm,
) -> PageResult {
    let slug = &membership.slug;
    let apps = state.apps();
    let view = match apps.get(membership.organisation_id, name).await {
        Ok(view) => view,
        Err(AppsError::NotFound) => return Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => return Err(PageError::from(anyhow::anyhow!(error))),
    };
    let releases = apps
        .releases(membership.organisation_id, name)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    let now = Utc::now();
    let copies_wanted = view.row.settings.0.copies;
    let replicas: Vec<Value> = view
        .replicas
        .iter()
        .map(|replica| {
            let (words, tone) = replica_words(replica, now);
            context! {
                slot => replica.slot + 1,
                of => copies_wanted,
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
    let crowded = (copies_wanted >= 2 && machines.len() == 1)
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
    let (line, tone) = status_line(&view);
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
    let latest = releases.first();
    let deploy = form.deploy.unwrap_or_else(|| match latest {
        Some(release) => DeployForm::from_spec(&release.spec.0),
        None => DeployForm::default(),
    });
    let file = latest.map(|r| render_toml(&view.row.name, &r.spec.0, &view.row.settings.0));
    let secrets: Vec<Value> = view
        .secrets
        .iter()
        .map(|(name, version, at)| context! { name, version, at => when(*at) })
        .collect();
    let viewer = viewer_context(state, session, Some(membership)).await?;
    render(
        state,
        browser,
        StatusCode::OK,
        "pages/app.html.jinja",
        context! {
            viewer,
            app => context! {
                name => view.row.name,
                line, tone, busy,
                copies => copies_wanted,
                current => view.row.current_release,
                halted => view.row.halted,
            },
            replicas, waiting, crowded,
            releases => releases.iter().map(release_context).collect::<Vec<_>>(),
            secrets, file,
            deploy => Value::from_serialize(&deploy),
            notice => form.notice, error => form.error,
            deploy_error => form.deploy_error, secret_error => form.secret_error,
            scale_error => form.scale_error,
            csrf => browser.csrf_token(), section => "apps",
        },
    )
}

#[derive(Deserialize, Default, serde::Serialize, Clone)]
pub struct DeployForm {
    #[serde(default, skip_serializing)]
    csrf: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    check: String,
    #[serde(default)]
    env: String,
}

impl DeployForm {
    fn from_spec(spec: &AppSpec) -> Self {
        Self {
            csrf: String::new(),
            image: spec.image.clone(),
            port: spec
                .ports
                .first()
                .map(|p| p.port.to_string())
                .unwrap_or_default(),
            check: match spec.check.as_ref().map(|c| &c.kind) {
                Some(CheckKind::Http { path }) => path.clone(),
                _ => String::new(),
            },
            env: spec
                .env
                .iter()
                .map(|e| format!("{}={}", e.name, e.value))
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

/// `POST /{org}/apps/{app}/deploy`: the next version, from the form. Its
/// secrets, command and stop settings are kept from the latest version.
pub async fn deploy(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<DeployForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let refuse = |message: String, form: DeployForm| {
        let (state, browser, session, membership, name) =
            (&state, &browser, &session, &membership, &name);
        async move {
            app_view(
                state,
                browser,
                session,
                membership,
                name,
                AppForm {
                    deploy_error: message,
                    deploy: Some(form),
                    ..Default::default()
                },
            )
            .await
        }
    };
    let mut env = Vec::new();
    for line in form.env.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match line.split_once('=') {
            Some((key, value)) => env.push(EnvVar {
                name: key.trim().to_string(),
                value: value.to_string(),
            }),
            None => {
                return refuse(
                    format!("Each setting is NAME=value on its own line; \"{line}\" has no '='."),
                    form,
                )
                .await;
            }
        }
    }
    let mut spec = match simple_spec(&form.image, &form.port, &form.check, env) {
        Ok(spec) => spec,
        Err(message) => return refuse(message, form).await,
    };
    let apps = state.apps();
    if let Ok(releases) = apps.releases(membership.organisation_id, &name).await
        && let Some(latest) = releases.first()
    {
        let before = &latest.spec.0;
        spec.secrets = before.secrets.clone();
        spec.command = before.command.clone();
        spec.stop = before.stop.clone();
        spec.memory_mib = before.memory_mib;
        spec.cpu_millis = before.cpu_millis;
        if let (Some(check), Some(old)) = (&mut spec.check, &before.check) {
            check.interval_ms = old.interval_ms;
            check.timeout_ms = old.timeout_ms;
        }
    }
    match apps
        .deploy(
            session.account_id,
            membership.organisation_id,
            &name,
            DeployInput::Spec(spec),
            ReleaseSource::Dashboard,
            "",
        )
        .await
    {
        Ok(_) => Ok(redirect(&format!("/{slug}/apps/{name}?done=deployed"))),
        Err(AppsError::NotFound) => Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => refuse(sentence(&error), form).await,
    }
}

#[derive(Deserialize)]
pub struct ScaleForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    copies: String,
}

/// `POST /{org}/apps/{app}/scale`.
pub async fn scale(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(form): Form<ScaleForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let message = match form.copies.trim().parse::<u32>() {
        Err(_) => "Copies is a whole number.".to_string(),
        Ok(copies) => match state
            .apps()
            .scale(
                session.account_id,
                membership.organisation_id,
                &name,
                copies,
            )
            .await
        {
            Ok(_) => return Ok(redirect(&format!("/{slug}/apps/{name}?done=scaled"))),
            Err(AppsError::NotFound) => return Ok(redirect(&format!("/{slug}/apps?error=gone"))),
            Err(error) => sentence(&error),
        },
    };
    app_view(
        &state,
        &browser,
        &session,
        &membership,
        &name,
        AppForm {
            scale_error: message,
            ..Default::default()
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct SecretForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    value: String,
}

/// `POST /{org}/apps/{app}/secrets`: stores a value; the page never shows
/// it again.
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
    match state
        .apps()
        .set_secret(
            session.account_id,
            membership.organisation_id,
            &name,
            form.secret.trim(),
            form.value.as_bytes(),
        )
        .await
    {
        Ok(_) => Ok(redirect(&format!("/{slug}/apps/{name}?done=secret"))),
        Err(AppsError::NotFound) => Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => {
            app_view(
                &state,
                &browser,
                &session,
                &membership,
                &name,
                AppForm {
                    secret_error: sentence(&error),
                    ..Default::default()
                },
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
        Ok(_) => Ok(redirect(&format!("/{slug}/apps/{name}?done=rolled-back"))),
        Err(AppsError::NotFound) => Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => Ok(redirect(&format!(
            "/{slug}/apps/{name}?deploy_error={}",
            urlencode(&sentence(&error))
        ))),
    }
}

/// `POST /{org}/apps/{app}/delete`.
pub async fn delete(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
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
    use super::image_icon;

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
