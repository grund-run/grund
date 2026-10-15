//! Apps (grund-docs design/apps.md): making them, their releases and
//! secrets, and the reconciler that places their replicas and rolls
//! releases out. Every decision about an app's replicas is
//! `grund_domain::app::reconcile::reconcile`, run under the app's stream
//! lock and the organisation's placement lock, and committed in one
//! transaction with the events' read models and the signed documents of
//! every machine it touched (§6.1, §10.3).

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::{LazyLock, Mutex};

use anyhow::Context;
use chrono::{DateTime, Utc};
use grund_domain::app::{
    App, AppCommand, AppError, AppEvent, AppName, AppSettings, AppSpec, ExternalRelease,
    ReleaseSource, SecretVersion,
    file::parse_app,
    placement::MachineView,
    reconcile::{Observation, Observed, reconcile_with_volumes},
    spec::MachineKind,
    spec::{
        ImageReference, MAX_APPS_PER_ORGANISATION, MAX_SECRET_BYTES, PortSpec, SecretEnv,
        SettingsInput, SpecError, secret_name_ok,
    },
};
use grund_store::{
    apps::{self, AppRow, ReleaseRow, ReplicaRow},
    domains, machines,
    work::{Work, WorkError},
};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    registry::{Inspection, Login, Registry, ResolveError},
    services::{
        agents::{AgentsState, MachineCaller},
        domains::DomainsState,
        entry::{EntryState, publishes},
        registry_credentials::RegistryCredentialsState,
        volumes::{VolumesError, VolumesState},
    },
    state::State,
};

/// How often the reconciler looks at every app when nothing woke it.
pub const RECONCILE_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// The release history the API and dashboard show.
pub const RELEASES_SHOWN: i64 = 100;

/// Why an app call was refused. Each maps to a stable reason.
#[derive(Debug, thiserror::Error)]
pub enum AppsError {
    #[error("no such app")]
    NotFound,
    #[error("an app of that name already exists")]
    NameTaken,
    #[error(
        "{name} was deleted on {deleted_at} and can be restored until {purge_after}.",
        deleted_at = .deleted_at.format("%-d %b %Y %H:%M:%S UTC"),
        purge_after = .purge_after.format("%-d %b %Y %H:%M:%S UTC")
    )]
    NameReserved {
        name: String,
        deleted_at: DateTime<Utc>,
        purge_after: DateTime<Utc>,
    },
    #[error("an organisation has at most {MAX_APPS_PER_ORGANISATION} apps")]
    AppLimit,
    #[error("{0}")]
    Spec(#[from] SpecError),
    #[error("{0}")]
    ImageUnresolved(String),
    #[error("{0}")]
    ImageUnsupported(String),
    #[error(
        "Public HTTP requires a verified custom domain bound to this app; bind one under Domains first"
    )]
    DomainRequired,
    #[error("no such release")]
    ReleaseNotFound,
    #[error("the external release key was already used for a different artifact or spec")]
    ExternalReleaseConflict,
    #[error("the app changed since the approved plan")]
    VersionConflict,
    #[error("this app belongs to another external project")]
    ExternalOwnerConflict,
    #[error(transparent)]
    Volume(#[from] VolumesError),
    #[error("app deletion requires confirming its current {actual} volumes")]
    VolumeConfirmationRequired { actual: usize },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppsError {
    /// The stable machine reason.
    pub fn reason(&self) -> &'static str {
        match self {
            AppsError::NotFound => "not_found",
            AppsError::NameTaken => "name_taken",
            AppsError::NameReserved { .. } => "name_reserved_for_restore",
            AppsError::AppLimit => "app_limit",
            AppsError::Spec(_) => "spec_invalid",
            AppsError::ImageUnresolved(_) => "image_unresolved",
            AppsError::ImageUnsupported(_) => "image_unsupported",
            AppsError::DomainRequired => "domain_required",
            AppsError::ReleaseNotFound => "release_not_found",
            AppsError::ExternalReleaseConflict => "external_release_conflict",
            AppsError::VersionConflict => "version_conflict",
            AppsError::ExternalOwnerConflict => "external_owner_conflict",
            AppsError::Volume(_) => "volume_invalid",
            AppsError::VolumeConfirmationRequired { .. } => "volume_confirmation_required",
            AppsError::Internal(_) => "internal",
        }
    }
}

impl From<WorkError> for AppsError {
    fn from(error: WorkError) -> Self {
        if error.unique_violation().as_deref() == Some("grund_apps_name_idx") {
            return AppsError::NameTaken;
        }
        match error {
            WorkError::App(AppError::NotFound) => AppsError::NotFound,
            WorkError::App(AppError::ReleaseNotFound) => AppsError::ReleaseNotFound,
            WorkError::App(AppError::AlreadyExists) => AppsError::NameTaken,
            WorkError::App(AppError::ExternalOwnerConflict) => AppsError::ExternalOwnerConflict,
            other => AppsError::Internal(other.into()),
        }
    }
}

impl From<sqlx::Error> for AppsError {
    fn from(error: sqlx::Error) -> Self {
        AppsError::Internal(error.into())
    }
}

/// What a deploy carries.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum DeployInput {
    Spec(AppSpec),
    /// A grund.yaml naming the app.
    File(String),
}

/// A new app as the dashboard's Deploy page asks for it, made by
/// [`Apps::launch`].
#[derive(Debug, Clone)]
pub struct Launch {
    pub name: String,
    pub settings: SettingsInput,
    pub spec: AppSpec,
    /// When `spec` has no port: the port to give it, numbered from the
    /// lowest TCP port the image declares. An image that declares none is
    /// refused on field `port`.
    pub detect_port: Option<PortSpec>,
    /// Secrets stored before the first release, `(variable, value)`. Each is
    /// named after its variable (`API_KEY` is the secret `api-key`) and
    /// handed to the app as that variable.
    pub secrets: Vec<(String, String)>,
}

/// The next release of an app as the dashboard's Settings ask for it, made
/// by [`Apps::change`].
#[derive(Debug, Clone)]
pub struct Change {
    /// The copies to run from this release on; `None` keeps them.
    pub copies: Option<u32>,
    pub spec: AppSpec,
    /// As [`Launch::detect_port`].
    pub detect_port: Option<PortSpec>,
    /// Secret values stored before the release, `(variable, value)`. A
    /// variable the spec already reads a secret through gets that secret's
    /// next version; a new one is named as in [`Launch::secrets`].
    pub secrets: Vec<(String, String)>,
    /// Release the newest release's image digest again rather than
    /// resolving `spec.image` now: a change of settings, not of image.
    pub same_image: bool,
}

fn attach_secrets(
    spec: &mut AppSpec,
    secrets: &[(String, String)],
) -> Result<Vec<String>, AppsError> {
    let mut names = Vec::new();
    for (i, (variable, value)) in secrets.iter().enumerate() {
        let refuse = |field: &str, problem: &str| {
            Err(AppsError::Spec(SpecError {
                field: format!("secrets[{i}].{field}"),
                problem: problem.into(),
            }))
        };
        if value.len() > MAX_SECRET_BYTES {
            return refuse("value", "a secret is at most 64 KiB");
        }
        if secrets[..i].iter().any(|(earlier, _)| earlier == variable) {
            return refuse("env", "each variable once");
        }
        let secret = match spec.secrets.iter().find(|s| s.env == *variable) {
            Some(read) => read.secret.clone(),
            None => {
                let secret = secret_name_for(variable);
                if !secret_name_ok(&secret) {
                    return refuse("env", "a secret's variable is letters, digits and '_'");
                }
                if spec.secrets.iter().any(|s| s.secret == secret) {
                    return refuse("env", "each variable once");
                }
                spec.secrets.push(SecretEnv {
                    env: variable.clone(),
                    secret: secret.clone(),
                });
                secret
            }
        };
        names.push(secret);
    }
    Ok(names)
}

fn probe(spec: &AppSpec, detect: Option<&PortSpec>) -> Result<(), AppsError> {
    let mut probe = spec.clone();
    if let Some(port) = detect {
        probe.ports.push(PortSpec {
            port: 1,
            ..port.clone()
        });
    }
    probe.validate()?;
    Ok(())
}

fn detected(port: PortSpec, exposed_ports: &[u16]) -> Result<PortSpec, AppsError> {
    let Some(number) = exposed_ports.first() else {
        return Err(AppsError::Spec(SpecError {
            field: "port".into(),
            problem: "the image declares no port; enter the one it listens on".into(),
        }));
    };
    Ok(PortSpec {
        port: *number,
        ..port
    })
}

/// The secret a variable's value is stored as: `API_KEY` is `api-key`.
pub fn secret_name_for(variable: &str) -> String {
    variable
        .to_ascii_lowercase()
        .replace('_', "-")
        .trim_matches('-')
        .to_string()
}

/// An app as the API and dashboard show it.
#[derive(Debug, Clone)]
pub struct AppView {
    pub row: AppRow,
    pub replicas: Vec<ReplicaRow>,
    pub secrets: Vec<(String, i32, DateTime<Utc>)>,
}

/// An app as its organisation's list shows it.
#[derive(Debug, Clone)]
pub struct AppListing {
    pub view: AppView,
    /// The spec of the release it runs, or of its newest while none is live.
    pub spec: Option<AppSpec>,
    /// When that release was made.
    pub deployed_at: Option<DateTime<Utc>>,
    /// The app's public hostname when its current release publishes: the
    /// shared address, or its first bound domain in custom-only mode.
    pub address: Option<String>,
}

/// One secret value of a replica.
#[derive(Debug, Clone)]
pub struct SecretValue {
    pub name: String,
    pub version: u32,
    pub value: Vec<u8>,
}

/// The checked desired release and the live state observed for an approval.
pub struct DeployPreview {
    pub release: ReleaseRow,
    pub previous: Option<ReleaseRow>,
    pub settings: AppSettings,
    pub old_settings: Option<AppSettings>,
    pub domains: Vec<String>,
    pub expected_version: i64,
    pub creates_app: bool,
}

/// App flows.
#[derive(Clone)]
pub struct Apps {
    state: State,
}

fn merged_file_settings(
    current: &AppSettings,
    file: SettingsInput,
) -> Result<AppSettings, SpecError> {
    let mut input = current.as_input();
    input.copies = file.copies.or(input.copies);
    input.max_surge = file.max_surge.or(input.max_surge);
    input.max_unavailable = file.max_unavailable.or(input.max_unavailable);
    input.min_ready_seconds = file.min_ready_seconds.or(input.min_ready_seconds);
    input.ready_deadline_seconds = file.ready_deadline_seconds.or(input.ready_deadline_seconds);
    input.drain_seconds = file.drain_seconds.or(input.drain_seconds);
    input.reschedule_after_seconds = file
        .reschedule_after_seconds
        .or(input.reschedule_after_seconds);
    input.auto_rollback = file.auto_rollback.or(input.auto_rollback);
    if !file.machines.is_empty() {
        input.machines = file.machines;
    }
    AppSettings::validate(input)
}

fn sealing_key(state: &State) -> LessSafeKey {
    let key = state.secret.derive("app-secrets");
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).expect("a 32-byte AES-256 key"))
}

fn aad(app_id: Uuid, name: &str, version: i32) -> Vec<u8> {
    format!("grund-app-secret-v1\n{app_id}\n{name}\n{version}").into_bytes()
}

/// Seals a secret value: a random 12-byte nonce, then the ciphertext and
/// tag, bound to the app, name and version.
pub fn seal(key: &LessSafeKey, app_id: Uuid, name: &str, version: i32, value: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).expect("the system's random source");
    let mut sealed = value.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad(app_id, name, version)),
        &mut sealed,
    )
    .expect("sealing a value within AES-GCM's limits");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&sealed);
    out
}

/// Opens what [`seal`] made, or `None` if it was made for another app,
/// name or version, or changed.
pub fn open(
    key: &LessSafeKey,
    app_id: Uuid,
    name: &str,
    version: i32,
    sealed: &[u8],
) -> Option<Vec<u8>> {
    if sealed.len() < 12 + 16 {
        return None;
    }
    let (nonce, rest) = sealed.split_at(12);
    let mut buffer = rest.to_vec();
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let plain = key
        .open_in_place(nonce, Aad::from(aad(app_id, name, version)), &mut buffer)
        .ok()?;
    Some(plain.to_vec())
}

fn observed(row: &apps::StatusRow) -> Option<Observation> {
    Some(Observation {
        replica_id: row.replica_id,
        state: Observed::parse(&row.state)?,
        ready: row.ready,
        ready_since: row.ready_since,
        ever_ready: row.ever_ready,
        restarts: row.restarts.max(0) as u32,
        last_exit_code: row.last_exit_code,
        reason: row.reason.clone(),
        idle: row.idle,
    })
}

/// A machine as placement sees it, from what its agent last reported and
/// what its owner set. `others` is what the organisation's other apps hold
/// on it.
pub fn machine_view(row: &machines::MachineRow, others: Option<&apps::Reservation>) -> MachineView {
    let capabilities = row.capabilities.as_ref().map(|c| &c.0);
    let number = |key: &str| capabilities.and_then(|c| c[key].as_u64()).unwrap_or(0);
    MachineView {
        machine_id: row.machine_id,
        name: row.pool_name.clone().unwrap_or_else(|| row.name.clone()),
        last_seen: row.last_seen_at,
        apps: capabilities
            .and_then(|c| c["apps"].as_bool())
            .unwrap_or(false),
        arch: capabilities
            .and_then(|c| c["arch"].as_str())
            .unwrap_or_default()
            .to_string(),
        memory_mib: number("memory_mib"),
        cpu_millis: number("cpu_millis") as u32,
        reserved_memory_mib: others.map_or(0, |o| o.memory_mib.max(0) as u64),
        reserved_cpu_millis: others.map_or(0, |o| o.cpu_millis.max(0) as u32),
        max_replica_memory_mib: number("max_replica_memory_mib"),
        max_replica_cpu_millis: number("max_replica_cpu_millis") as u32,
        labels: row.labels.0.clone(),
        cordoned: row.cordoned_at.is_some(),
        kind: if row.pool == "management" {
            MachineKind::Hosted
        } else {
            MachineKind::Own
        },
        running_apps: others.map(|o| o.apps.clone()).unwrap_or_default(),
    }
}

fn reconcile_machine_view(
    row: &machines::MachineRow,
    others: Option<&apps::Reservation>,
    stateful: bool,
    hosted_storage: bool,
    backend_eligible: bool,
    pinned: Option<Uuid>,
    placed: bool,
) -> Option<MachineView> {
    if !matches!(row.state.as_str(), "active" | "leased") {
        return None;
    }
    let eligible = !stateful
        || ((if hosted_storage {
            row.pool == "management" && row.state == "leased" && backend_eligible
        } else {
            row.pool != "management"
                && row.state == "active"
                && row.minted_by.starts_with("account:")
                && row
                    .capabilities
                    .as_ref()
                    .is_some_and(|c| c.0["volumes"].as_bool() == Some(true))
        }) && pinned.is_none_or(|id| id == row.machine_id));
    if !eligible && !placed {
        return None;
    }
    let mut view = machine_view(row, others);
    view.apps &= eligible;
    Some(view)
}

pub(crate) async fn lock_app_domain_policy(
    connection: &mut PgConnection,
    app_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("grund-app-domain-policy:{app_id}"))
        .execute(connection)
        .await?;
    Ok(())
}

fn allows_public_release(
    mode: crate::config::AppDomains,
    spec: &AppSpec,
    has_bound_domain: bool,
) -> bool {
    mode != crate::config::AppDomains::CustomOnly || !publishes(spec) || has_bound_domain
}

fn deleted_name_conflict(
    name: String,
    deleted_at: DateTime<Utc>,
    purge_after: DateTime<Utc>,
    at: DateTime<Utc>,
) -> AppsError {
    if at < purge_after {
        AppsError::NameReserved {
            name,
            deleted_at,
            purge_after,
        }
    } else {
        AppsError::NameTaken
    }
}

impl Apps {
    async fn require_domain(
        &self,
        connection: &mut PgConnection,
        app_id: Uuid,
        command: &AppCommand,
    ) -> Result<(), AppsError> {
        if let AppCommand::Release { spec, .. } = command {
            let mode = self.state.config.entry.app_domains;
            if mode == crate::config::AppDomains::CustomOnly && publishes(spec) {
                let bound = grund_store::domains::count_bound(&mut *connection, app_id).await? > 0;
                if !allows_public_release(mode, spec, bound) {
                    return Err(AppsError::DomainRequired);
                }
            }
        }
        Ok(())
    }

    async fn registry(
        &self,
        organisation_id: Uuid,
        reference: &ImageReference,
    ) -> Result<Registry, AppsError> {
        let login = self
            .state
            .registry_credentials()
            .for_organisation(organisation_id, &reference.registry)
            .await?
            .map(|c| Login {
                username: c.username,
                password: c.password,
            });
        Ok(Registry::new(self.state.config.insecure_registries.clone())?.with_credential(login))
    }

    async fn live(&self, organisation_id: Uuid, name: &str) -> Result<AppRow, AppsError> {
        apps::app_by_name(&self.state.pool, organisation_id, name)
            .await?
            .ok_or(AppsError::NotFound)
    }

    /// The app with its replicas and secrets' names.
    pub async fn view(&self, row: AppRow) -> Result<AppView, AppsError> {
        Ok(AppView {
            replicas: apps::app_replicas(&self.state.pool, row.app_id).await?,
            secrets: apps::latest_secrets(&self.state.pool, row.app_id).await?,
            row,
        })
    }

    pub async fn get(&self, organisation_id: Uuid, name: &str) -> Result<AppView, AppsError> {
        let row = self.live(organisation_id, name).await?;
        self.view(row).await
    }

    pub async fn list(&self, organisation_id: Uuid) -> Result<Vec<AppView>, AppsError> {
        let mut views = Vec::new();
        for row in apps::organisation_apps(&self.state.pool, organisation_id).await? {
            views.push(self.view(row).await?);
        }
        Ok(views)
    }

    /// The organisation's apps as its list shows them: each with the
    /// release it runs and, when that release publishes a port, the
    /// address it holds.
    pub async fn listings(
        &self,
        organisation_id: Uuid,
        slug: &str,
    ) -> Result<Vec<AppListing>, AppsError> {
        let mut running: std::collections::HashMap<Uuid, apps::RunningRow> =
            apps::running_releases(&self.state.pool, organisation_id)
                .await?
                .into_iter()
                .map(|row| (row.app_id, row))
                .collect();
        let mut connection = self.state.pool.acquire().await?;
        let mut listings = Vec::new();
        for view in self.list(organisation_id).await? {
            let release = running.remove(&view.row.app_id);
            listings.push(self.listed(&mut connection, slug, view, release).await?);
        }
        Ok(listings)
    }

    async fn listed(
        &self,
        connection: &mut PgConnection,
        slug: &str,
        view: AppView,
        release: Option<apps::RunningRow>,
    ) -> Result<AppListing, AppsError> {
        let address = match &release {
            Some(release) if publishes(&release.spec.0) => {
                if self.state.config.entry.app_domains == crate::config::AppDomains::CustomOnly {
                    domains::first_bound_name(&mut *connection, view.row.app_id).await?
                } else {
                    self.state
                        .entry()
                        .address(connection, view.row.app_id, &view.row.name, slug)
                        .await?
                }
            }
            _ => None,
        };
        Ok(AppListing {
            view,
            spec: release.as_ref().map(|r| r.spec.0.clone()),
            deployed_at: release.map(|r| r.created_at),
            address,
        })
    }

    async fn name_conflict(
        &self,
        organisation_id: Uuid,
        name: &str,
    ) -> Result<Option<AppsError>, AppsError> {
        let row =
            apps::app_by_name_including_deleted(&self.state.pool, organisation_id, name).await?;
        Ok(row.map(|row| match (row.deleted_at, row.purge_after) {
            (Some(deleted_at), Some(purge_after)) => {
                deleted_name_conflict(row.name, deleted_at, purge_after, Utc::now())
            }
            _ => AppsError::NameTaken,
        }))
    }

    async fn created_name_conflict(
        &self,
        organisation_id: Uuid,
        name: &str,
        error: AppsError,
    ) -> AppsError {
        if matches!(error, AppsError::NameTaken) {
            match self.name_conflict(organisation_id, name).await {
                Ok(Some(conflict)) => conflict,
                Ok(None) => error,
                Err(error) => error,
            }
        } else {
            error
        }
    }

    pub async fn create(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        settings: SettingsInput,
    ) -> Result<AppView, AppsError> {
        let name = AppName::parse(name)?;
        let settings = AppSettings::validate(settings)?;
        if apps::count_live_apps(&self.state.pool, organisation_id).await?
            >= MAX_APPS_PER_ORGANISATION
        {
            return Err(AppsError::AppLimit);
        }
        if let Some(conflict) = self.name_conflict(organisation_id, name.as_str()).await? {
            return Err(conflict);
        }
        let app_id = Uuid::now_v7();
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string())
            .await
            .map_err(AppsError::from)?;
        let result = work
            .app(
                app_id,
                AppCommand::Create {
                    actor,
                    organisation_id,
                    name: name.clone(),
                    settings,
                    at: Utc::now(),
                },
            )
            .await;
        if let Err(error) = result {
            drop(work);
            return Err(self
                .created_name_conflict(organisation_id, name.as_str(), error.into())
                .await);
        }
        if let Err(error) = work.commit().await {
            return Err(self
                .created_name_conflict(organisation_id, name.as_str(), error.into())
                .await);
        }
        let row = apps::app(&self.state.pool, app_id)
            .await?
            .context("the app just created")?;
        self.view(row).await
    }

    /// What `image` names now, and the ports it declares, asked with the
    /// organisation's registry credential.
    #[tracing::instrument(name = "apps.inspect", skip_all)]
    pub async fn inspect(
        &self,
        organisation_id: Uuid,
        image: &str,
    ) -> Result<Inspection, AppsError> {
        let reference = ImageReference::parse(image)?;
        self.registry(organisation_id, &reference)
            .await?
            .inspect(&reference)
            .await
            .map_err(|e| match e {
                ResolveError::Unsupported(_) => AppsError::ImageUnsupported(e.to_string()),
                other => AppsError::ImageUnresolved(other.to_string()),
            })
    }

    /// Makes an app and rolls out its first release. Everything the API's
    /// CreateApp and Deploy would refuse is refused first, the image
    /// resolved included, so a refusal leaves nothing behind.
    pub async fn launch(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        launch: Launch,
    ) -> Result<(AppName, ReleaseRow), AppsError> {
        let name = AppName::parse(&launch.name)?;
        let settings = AppSettings::validate(launch.settings)?;
        let mut spec = launch.spec;
        let secret_names = attach_secrets(&mut spec, &launch.secrets)?;
        let detect = launch.detect_port.filter(|_| spec.ports.is_empty());
        probe(&spec, detect.as_ref())?;
        if apps::count_live_apps(&self.state.pool, organisation_id).await?
            >= MAX_APPS_PER_ORGANISATION
        {
            return Err(AppsError::AppLimit);
        }
        if let Some(conflict) = self.name_conflict(organisation_id, name.as_str()).await? {
            return Err(conflict);
        }
        let inspection = self.inspect(organisation_id, &spec.image).await?;
        if let Some(port) = detect {
            spec.ports.push(detected(port, &inspection.exposed_ports)?);
        }
        let spec = spec.validate()?;
        if !spec.volumes.is_empty() && settings.copies != 1 {
            return Err(AppsError::Spec(SpecError {
                field: "copies".into(),
                problem: "an app with volumes has exactly one copy".into(),
            }));
        }
        if !allows_public_release(self.state.config.entry.app_domains, &spec, false) {
            return Err(AppsError::DomainRequired);
        }
        let app_id = Uuid::now_v7();
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        let result = work
            .app(
                app_id,
                AppCommand::Create {
                    actor,
                    organisation_id,
                    name: name.clone(),
                    settings,
                    at: Utc::now(),
                },
            )
            .await;
        if let Err(error) = result {
            drop(work);
            return Err(self
                .created_name_conflict(organisation_id, name.as_str(), error.into())
                .await);
        }
        if let Err(error) = work.commit().await {
            return Err(self
                .created_name_conflict(organisation_id, name.as_str(), error.into())
                .await);
        }
        for (secret, (_, value)) in secret_names.iter().zip(&launch.secrets) {
            self.set_secret(
                actor,
                organisation_id,
                name.as_str(),
                secret,
                value.as_bytes(),
            )
            .await?;
        }
        let secret_versions = self.secret_versions(app_id, &spec).await?;
        let release = self
            .record_release(
                actor,
                app_id,
                AppCommand::Release {
                    actor,
                    spec,
                    image_digest: inspection.resolved.digest,
                    platforms: inspection.resolved.platforms,
                    exposed_ports: Some(inspection.exposed_ports),
                    secret_versions,
                    source: ReleaseSource::Dashboard,
                    external_release: None,
                    rollback_of: None,
                    note: String::new(),
                    rollout_id: Uuid::now_v7(),
                    at: Utc::now(),
                },
                None,
            )
            .await?;
        Ok((name, release))
    }

    /// Makes the app's next release from `change` and rolls it out. As
    /// [`Apps::launch`], everything is refused before anything is written:
    /// the spec, the secrets, the copies, and the image (resolved now, or
    /// the newest release's digest for a change of settings).
    pub async fn change(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        change: Change,
    ) -> Result<ReleaseRow, AppsError> {
        let row = self.live(organisation_id, name).await?;
        let mut spec = change.spec;
        let secret_names = attach_secrets(&mut spec, &change.secrets)?;
        let detect = change.detect_port.filter(|_| spec.ports.is_empty());
        probe(&spec, detect.as_ref())?;
        let stored = apps::latest_secrets(&self.state.pool, row.app_id).await?;
        if let Some((i, missing)) = spec.secrets.iter().enumerate().find(|(_, s)| {
            !secret_names.contains(&s.secret) && !stored.iter().any(|(n, _, _)| *n == s.secret)
        }) {
            return Err(AppsError::Spec(SpecError {
                field: format!("secrets[{i}].secret"),
                problem: format!("the app has no secret {}; set it first", missing.secret),
            }));
        }
        let settings = match change.copies {
            Some(copies) if copies != row.settings.0.copies => {
                Some(row.settings.0.with_copies(copies)?)
            }
            _ => None,
        };
        let (digest, platforms, exposed_ports) = if change.same_image {
            let newest = apps::releases(&self.state.pool, row.app_id, 1)
                .await?
                .into_iter()
                .next()
                .ok_or(AppsError::ReleaseNotFound)?;
            if newest.spec.0.image != spec.image {
                return Err(AppsError::Spec(SpecError {
                    field: "image".into(),
                    problem: "a change of settings keeps the image; change it under Image".into(),
                }));
            }
            let exposed_ports = if let Some(port) = detect {
                let ports = match newest.exposed_ports {
                    Some(ports) => ports.0,
                    None => {
                        let reference = format!(
                            "{}@{}",
                            spec.image.split('@').next().unwrap_or_default(),
                            newest.image_digest
                        );
                        self.inspect(organisation_id, &reference)
                            .await?
                            .exposed_ports
                    }
                };
                spec.ports.push(detected(port, &ports)?);
                Some(ports)
            } else {
                newest.exposed_ports.map(|ports| ports.0)
            };
            (newest.image_digest, newest.platforms.0, exposed_ports)
        } else {
            let inspection = self.inspect(organisation_id, &spec.image).await?;
            if let Some(port) = detect {
                spec.ports.push(detected(port, &inspection.exposed_ports)?);
            }
            (
                inspection.resolved.digest,
                inspection.resolved.platforms,
                Some(inspection.exposed_ports),
            )
        };
        let spec = spec.validate()?;
        for (secret, (_, value)) in secret_names.iter().zip(&change.secrets) {
            self.set_secret(actor, organisation_id, name, secret, value.as_bytes())
                .await?;
        }
        let secret_versions = self.secret_versions(row.app_id, &spec).await?;
        self.record_release(
            actor,
            row.app_id,
            AppCommand::Release {
                actor,
                spec,
                image_digest: digest,
                platforms,
                exposed_ports,
                secret_versions,
                source: ReleaseSource::Dashboard,
                external_release: None,
                rollback_of: None,
                note: String::new(),
                rollout_id: Uuid::now_v7(),
                at: Utc::now(),
            },
            settings,
        )
        .await
    }

    /// One app as its organisation's list shows it, with its address.
    pub async fn listing(
        &self,
        organisation_id: Uuid,
        slug: &str,
        name: &str,
    ) -> Result<AppListing, AppsError> {
        let view = self.get(organisation_id, name).await?;
        let release = apps::running_releases(&self.state.pool, organisation_id)
            .await?
            .into_iter()
            .find(|r| r.app_id == view.row.app_id);
        let mut connection = self.state.pool.acquire().await?;
        self.listed(&mut connection, slug, view, release).await
    }

    async fn secret_versions(
        &self,
        app_id: Uuid,
        spec: &AppSpec,
    ) -> Result<Vec<SecretVersion>, AppsError> {
        let latest = apps::latest_secrets(&self.state.pool, app_id).await?;
        let mut versions: Vec<SecretVersion> = Vec::new();
        for (i, secret) in spec.secrets.iter().enumerate() {
            let Some((_, version, _)) = latest.iter().find(|(n, _, _)| *n == secret.secret) else {
                return Err(AppsError::Spec(SpecError {
                    field: format!("secrets[{i}].secret"),
                    problem: format!("the app has no secret {}; set it first", secret.secret),
                }));
            };
            if !versions.iter().any(|v| v.name == secret.secret) {
                versions.push(SecretVersion {
                    name: secret.secret.clone(),
                    version: *version as u32,
                });
            }
        }
        Ok(versions)
    }

    async fn external_receipt_in(
        &self,
        connection: &mut PgConnection,
        organisation_id: Uuid,
        app_name: &str,
        origin: &ExternalRelease,
    ) -> Result<Option<ReleaseRow>, AppsError> {
        let receipt: Option<(Uuid, Uuid, Vec<u8>, i32)> = sqlx::query_as(
            "SELECT app_id, artifact_id, request_digest, release_number FROM grund_app_external_releases \
             WHERE organisation_id = $1 AND forest_organisation = $2 AND destination = $3 \
               AND intent_id = $4 AND app_name = $5",
        )
        .bind(organisation_id)
        .bind(&origin.forest_organisation)
        .bind(&origin.destination)
        .bind(origin.intent_id)
        .bind(app_name)
        .fetch_optional(&mut *connection)
        .await?;
        let Some((app_id, artifact, digest, number)) = receipt else {
            return Ok(None);
        };
        if artifact != origin.artifact_id || digest != origin.request_digest {
            return Err(AppsError::ExternalReleaseConflict);
        }
        let owner: Option<(String, String, String)> = sqlx::query_as(
            "SELECT forest_organisation, destination, project FROM grund_app_external_owners \
             WHERE organisation_id = $1 AND app_id = $2",
        )
        .bind(organisation_id)
        .bind(app_id)
        .fetch_optional(&mut *connection)
        .await?;
        if owner.as_ref().is_none_or(|owner| {
            owner.0 != origin.forest_organisation
                || owner.1 != origin.destination
                || owner.2 != origin.project
        }) {
            return Err(AppsError::ExternalOwnerConflict);
        }
        apps::release(&mut *connection, app_id, number)
            .await?
            .ok_or(AppsError::ReleaseNotFound)
            .map(Some)
    }

    async fn record_release(
        &self,
        actor: Uuid,
        app_id: Uuid,
        release: AppCommand,
        settings: Option<AppSettings>,
    ) -> Result<ReleaseRow, AppsError> {
        self.record_release_guarded(actor, app_id, release, settings, None)
            .await
    }

    async fn record_release_guarded(
        &self,
        actor: Uuid,
        app_id: Uuid,
        release: AppCommand,
        settings: Option<AppSettings>,
        expected_version: Option<i64>,
    ) -> Result<ReleaseRow, AppsError> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        lock_app_domain_policy(work.sql(), app_id).await?;
        let app = work.load_app(app_id).await?;
        let app_name = app.name.as_ref().ok_or(AppsError::NotFound)?;
        if let AppCommand::Release {
            external_release: Some(origin),
            ..
        } = &release
            && let Some(previous) = self
                .external_receipt_in(work.sql(), app.organisation_id, app_name.as_str(), origin)
                .await?
        {
            return Ok(previous);
        }
        if let Some(expected) = expected_version {
            let actual: i64 =
                sqlx::query_scalar("SELECT stream_version FROM grund_apps WHERE app_id = $1")
                    .bind(app_id)
                    .fetch_one(&mut **work.sql())
                    .await?;
            if actual != expected {
                return Err(AppsError::VersionConflict);
            }
        }
        self.require_domain(work.sql(), app_id, &release).await?;
        if let Some(settings) = settings {
            work.app(
                app_id,
                AppCommand::Configure {
                    actor,
                    settings,
                    at: Utc::now(),
                },
            )
            .await?;
        }
        let app = work.load_app(app_id).await?;
        let org = app.organisation_id;
        let specs = match &release {
            AppCommand::Release { spec, .. } => &spec.volumes,
            _ => unreachable!("record_release only makes releases"),
        };
        let current = grund_store::volumes::app_volumes(&mut **work.sql(), org, app_id).await?;
        if (!specs.is_empty() || !current.is_empty()) && app.settings.copies != 1 {
            return Err(AppsError::Spec(SpecError {
                field: "copies".into(),
                problem: "an app with volumes has exactly one copy".into(),
            }));
        }
        self.state
            .volumes()
            .resolve_release_in(&mut work, org, app_id, specs)
            .await?;
        let events = work.app(app_id, release).await?;
        work.commit().await?;
        self.state.wakes.apps_changed();
        let number = events
            .iter()
            .find_map(|e| match e {
                AppEvent::ReleaseCreated { release } => Some(release.number as i32),
                _ => None,
            })
            .context("a release was made")?;
        apps::releases(&self.state.pool, app_id, RELEASES_SHOWN)
            .await?
            .into_iter()
            .find(|r| r.number == number)
            .ok_or(AppsError::ReleaseNotFound)
    }

    async fn preview_release(
        &self,
        actor: Uuid,
        app_id: Uuid,
        release: AppCommand,
        settings: Option<AppSettings>,
    ) -> Result<ReleaseRow, AppsError> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        lock_app_domain_policy(work.sql(), app_id).await?;
        self.require_domain(work.sql(), app_id, &release).await?;
        if let Some(settings) = settings {
            work.app(
                app_id,
                AppCommand::Configure {
                    actor,
                    settings,
                    at: Utc::now(),
                },
            )
            .await?;
        }
        let app = work.load_app(app_id).await?;
        let specs = match &release {
            AppCommand::Release { spec, .. } => &spec.volumes,
            _ => unreachable!("preview_release only makes releases"),
        };
        let current =
            grund_store::volumes::app_volumes(&mut **work.sql(), app.organisation_id, app_id)
                .await?;
        if (!specs.is_empty() || !current.is_empty()) && app.settings.copies != 1 {
            return Err(AppsError::Spec(SpecError {
                field: "copies".into(),
                problem: "an app with volumes has exactly one copy".into(),
            }));
        }
        self.state
            .volumes()
            .resolve_release_in(&mut work, app.organisation_id, app_id, specs)
            .await?;
        let events = work.app(app_id, release).await?;
        drop(work);
        let release = events
            .into_iter()
            .find_map(|e| match e {
                AppEvent::ReleaseCreated { release } => Some(release),
                _ => None,
            })
            .context("a release was made")?;
        Ok(ReleaseRow {
            app_id,
            number: release.number as i32,
            spec: sqlx::types::Json(release.spec),
            image_digest: release.image_digest,
            platforms: sqlx::types::Json(release.platforms),
            exposed_ports: release.exposed_ports.map(sqlx::types::Json),
            secret_versions: sqlx::types::Json(release.secret_versions),
            source: release.source.as_str().to_string(),
            rollback_of: release.rollback_of.map(|n| n as i32),
            note: release.note,
            created_by: release.created_by,
            created_by_name: None,
            created_at: release.created_at,
            outcome: None,
            reason: None,
            ended_at: None,
        })
    }

    /// Validates the desired release and returns the old state without writing.
    pub async fn plan_deploy(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        input: DeployInput,
        create_if_missing: bool,
    ) -> Result<DeployPreview, AppsError> {
        let name = AppName::parse(name)?;
        let existing = apps::app_by_name(&self.state.pool, organisation_id, name.as_str()).await?;
        if let Some(row) = existing {
            let settings = match &input {
                DeployInput::Spec(_) => row.settings.0.clone(),
                DeployInput::File(text) => {
                    merged_file_settings(&row.settings.0, parse_app(text, name.as_str())?.settings)?
                }
            };
            let previous = apps::releases(&self.state.pool, row.app_id, 1)
                .await?
                .into_iter()
                .next();
            let release = self
                .preview_deploy(
                    actor,
                    organisation_id,
                    name.as_str(),
                    input,
                    ReleaseSource::Api,
                    "",
                )
                .await?;
            let domains = domains::bound_to(&self.state.pool, row.app_id)
                .await?
                .into_iter()
                .map(|domain| domain.name)
                .collect();
            let after = self.live(organisation_id, name.as_str()).await?;
            if after.stream_version != row.stream_version {
                return Err(AppsError::VersionConflict);
            }
            return Ok(DeployPreview {
                release,
                previous,
                settings,
                old_settings: Some(row.settings.0),
                domains,
                expected_version: row.stream_version,
                creates_app: false,
            });
        }
        if !create_if_missing {
            return Err(AppsError::NotFound);
        }
        if apps::count_live_apps(&self.state.pool, organisation_id).await?
            >= MAX_APPS_PER_ORGANISATION
        {
            return Err(AppsError::AppLimit);
        }
        let (spec, settings, source) = match input {
            DeployInput::Spec(spec) => {
                (spec.validate()?, AppSettings::default(), ReleaseSource::Api)
            }
            DeployInput::File(text) => {
                let declared = parse_app(&text, name.as_str())?;
                (
                    declared.spec,
                    AppSettings::validate(declared.settings)?,
                    ReleaseSource::File,
                )
            }
        };
        if !spec.secrets.is_empty() {
            return Err(AppsError::Spec(SpecError {
                field: "secrets".into(),
                problem: "create the app and set its named secrets before deploying".into(),
            }));
        }
        let inspection = self.inspect(organisation_id, &spec.image).await?;
        if apps::app_by_name(&self.state.pool, organisation_id, name.as_str())
            .await?
            .is_some()
        {
            return Err(AppsError::VersionConflict);
        }
        Ok(DeployPreview {
            release: ReleaseRow {
                app_id: Uuid::nil(),
                number: 1,
                spec: sqlx::types::Json(spec),
                image_digest: inspection.resolved.digest,
                platforms: sqlx::types::Json(inspection.resolved.platforms),
                exposed_ports: Some(sqlx::types::Json(inspection.exposed_ports)),
                secret_versions: sqlx::types::Json(Vec::new()),
                source: source.as_str().to_string(),
                rollback_of: None,
                note: String::new(),
                created_by: actor,
                created_by_name: None,
                created_at: Utc::now(),
                outcome: None,
                reason: None,
                ended_at: None,
            },
            previous: None,
            settings,
            old_settings: None,
            domains: Vec::new(),
            expected_version: 0,
            creates_app: true,
        })
    }

    /// Makes the next release from `input` and rolls it out.
    pub async fn deploy(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        input: DeployInput,
        source: ReleaseSource,
        note: &str,
    ) -> Result<ReleaseRow, AppsError> {
        self.deploy_or_preview(
            actor,
            organisation_id,
            name,
            input,
            source,
            note,
            false,
            None,
            None,
        )
        .await
    }

    /// Deploys an ordinary request only while the observed app version holds.
    #[allow(clippy::too_many_arguments)]
    pub async fn deploy_expected(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        input: DeployInput,
        source: ReleaseSource,
        note: &str,
        expected_version: i64,
    ) -> Result<ReleaseRow, AppsError> {
        self.deploy_or_preview(
            actor,
            organisation_id,
            name,
            input,
            source,
            note,
            false,
            None,
            Some(expected_version),
        )
        .await
    }

    /// The release [`Apps::deploy`] would make from `input`, after every
    /// check it makes (the image resolved at its registry, the app's own
    /// rules), with nothing written: its unit of work is never committed.
    pub async fn preview_deploy(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        input: DeployInput,
        source: ReleaseSource,
        note: &str,
    ) -> Result<ReleaseRow, AppsError> {
        self.deploy_or_preview(
            actor,
            organisation_id,
            name,
            input,
            source,
            note,
            true,
            None,
            None,
        )
        .await
    }

    /// Deploys with a durable forest key and an app-version precondition.
    #[allow(clippy::too_many_arguments)]
    pub async fn deploy_external(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        input: DeployInput,
        note: &str,
        origin: ExternalRelease,
        expected_version: Option<i64>,
    ) -> Result<ReleaseRow, AppsError> {
        self.deploy_or_preview(
            actor,
            organisation_id,
            name,
            input,
            ReleaseSource::File,
            note,
            false,
            Some(origin),
            expected_version,
        )
        .await
    }

    #[tracing::instrument(name = "apps.deploy_or_preview", skip_all)]
    #[allow(clippy::too_many_arguments)]
    async fn deploy_or_preview(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        input: DeployInput,
        source: ReleaseSource,
        note: &str,
        preview: bool,
        mut external_release: Option<ExternalRelease>,
        expected_version: Option<i64>,
    ) -> Result<ReleaseRow, AppsError> {
        let name = AppName::parse(name)?;
        if let Some(origin) = &mut external_release {
            let digest = match &input {
                DeployInput::Spec(spec) => ring::digest::digest(
                    &ring::digest::SHA256,
                    &serde_json::to_vec(spec).map_err(anyhow::Error::from)?,
                ),
                DeployInput::File(text) => {
                    ring::digest::digest(&ring::digest::SHA256, text.as_bytes())
                }
            };
            origin.request_digest.copy_from_slice(digest.as_ref());
            if let Some(previous) = self
                .external_receipt_in(
                    &mut *self.state.pool.acquire().await?,
                    organisation_id,
                    name.as_str(),
                    origin,
                )
                .await?
            {
                return Ok(previous);
            }
        }
        let row = self.live(organisation_id, name.as_str()).await?;
        let (spec, settings, source) = match input {
            DeployInput::Spec(spec) => (spec.validate()?, None, source),
            DeployInput::File(text) => {
                let declared = parse_app(&text, &row.name)?;
                let settings = merged_file_settings(&row.settings.0, declared.settings)?;
                (declared.spec, Some(settings), ReleaseSource::File)
            }
        };
        let note: String = note.chars().take(200).collect();
        let inspection = self.inspect(organisation_id, &spec.image).await?;
        let secret_versions = self.secret_versions(row.app_id, &spec).await?;
        let command = AppCommand::Release {
            actor,
            spec,
            image_digest: inspection.resolved.digest,
            platforms: inspection.resolved.platforms,
            exposed_ports: Some(inspection.exposed_ports),
            secret_versions,
            source,
            external_release,
            rollback_of: None,
            note,
            rollout_id: Uuid::now_v7(),
            at: Utc::now(),
        };
        if preview {
            return self
                .preview_release(actor, row.app_id, command, settings)
                .await;
        }
        self.record_release_guarded(actor, row.app_id, command, settings, expected_version)
            .await
    }

    /// A new release copying `number`'s contents, with the secrets' newest
    /// versions.
    pub async fn rollback(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        number: u32,
    ) -> Result<ReleaseRow, AppsError> {
        let row = self.live(organisation_id, name).await?;
        let earlier = apps::releases(&self.state.pool, row.app_id, i64::MAX)
            .await?
            .into_iter()
            .find(|r| r.number == number as i32)
            .ok_or(AppsError::ReleaseNotFound)?;
        let spec = earlier.spec.0.clone();
        let secret_versions = self.secret_versions(row.app_id, &spec).await?;
        self.record_release(
            actor,
            row.app_id,
            AppCommand::Release {
                actor,
                spec,
                image_digest: earlier.image_digest.clone(),
                platforms: earlier.platforms.0.clone(),
                exposed_ports: earlier.exposed_ports.map(|ports| ports.0),
                secret_versions,
                source: ReleaseSource::Rollback,
                external_release: None,
                rollback_of: Some(number),
                note: String::new(),
                rollout_id: Uuid::now_v7(),
                at: Utc::now(),
            },
            None,
        )
        .await
    }

    pub async fn releases(
        &self,
        organisation_id: Uuid,
        name: &str,
    ) -> Result<Vec<ReleaseRow>, AppsError> {
        let row = self.live(organisation_id, name).await?;
        self.releases_for(row.app_id).await
    }

    pub(crate) async fn releases_for(&self, app_id: Uuid) -> Result<Vec<ReleaseRow>, AppsError> {
        Ok(apps::releases(&self.state.pool, app_id, RELEASES_SHOWN).await?)
    }

    /// Fills missing port metadata after the page returns, at most once per
    /// release concurrently in this process. A failed lookup can retry on the next visit.
    pub fn cache_legacy_ports(&self, organisation_id: Uuid, release: &ReleaseRow) {
        static IN_FLIGHT: LazyLock<Mutex<HashSet<(Uuid, i32)>>> =
            LazyLock::new(|| Mutex::new(HashSet::new()));
        let key = (release.app_id, release.number);
        if !IN_FLIGHT
            .lock()
            .expect("legacy port lock poisoned")
            .insert(key)
        {
            return;
        }
        let apps = self.clone();
        let digest = release.image_digest.clone();
        let reference = format!(
            "{}@{}",
            release.spec.0.image.split('@').next().unwrap_or_default(),
            digest
        );
        tokio::spawn(async move {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                apps.inspect(organisation_id, &reference),
            )
            .await;
            match result {
                Ok(Ok(inspection)) if inspection.resolved.digest == digest => {
                    if let Err(error) = apps::cache_release_ports(
                        &apps.state.pool,
                        key.0,
                        key.1,
                        &digest,
                        &inspection.exposed_ports,
                    )
                    .await
                    {
                        tracing::warn!(%error, "legacy image ports could not be cached");
                    }
                }
                _ => tracing::warn!("legacy image ports could not be inspected"),
            }
            IN_FLIGHT
                .lock()
                .expect("legacy port lock poisoned")
                .remove(&key);
        });
    }

    async fn set_settings(
        &self,
        actor: Uuid,
        row: &AppRow,
        settings: AppSettings,
    ) -> Result<AppView, AppsError> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        let app = work.load_app(row.app_id).await?;
        if settings.copies != 1
            && !grund_store::volumes::app_volumes(
                &mut **work.sql(),
                app.organisation_id,
                row.app_id,
            )
            .await?
            .is_empty()
        {
            return Err(AppsError::Spec(SpecError {
                field: "copies".into(),
                problem: "an app with volumes has exactly one copy".into(),
            }));
        }
        work.app(
            row.app_id,
            AppCommand::Configure {
                actor,
                settings,
                at: Utc::now(),
            },
        )
        .await?;
        work.commit().await?;
        self.state.wakes.apps_changed();
        let row = apps::app(&self.state.pool, row.app_id)
            .await?
            .ok_or(AppsError::NotFound)?;
        self.view(row).await
    }

    pub async fn scale(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        copies: u32,
    ) -> Result<AppView, AppsError> {
        let row = self.live(organisation_id, name).await?;
        let settings = row.settings.0.with_copies(copies)?;
        self.set_settings(actor, &row, settings).await
    }

    pub async fn configure(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        input: SettingsInput,
    ) -> Result<AppView, AppsError> {
        let row = self.live(organisation_id, name).await?;
        let settings = AppSettings::validate(input)?;
        self.set_settings(actor, &row, settings).await
    }

    /// Stores the next version of a secret. The value is sealed before it
    /// reaches the database and never logged.
    pub async fn set_secret(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        secret: &str,
        value: &[u8],
    ) -> Result<(String, i32, DateTime<Utc>), AppsError> {
        if !secret_name_ok(secret) {
            return Err(AppsError::Spec(SpecError {
                field: "secret".into(),
                problem: "a secret's name is a–z, 0–9 and '-', at most 63".into(),
            }));
        }
        if value.len() > MAX_SECRET_BYTES {
            return Err(AppsError::Spec(SpecError {
                field: "value".into(),
                problem: "a secret is at most 64 KiB".into(),
            }));
        }
        let row = self.live(organisation_id, name).await?;
        let key = sealing_key(&self.state);
        let mut tx = self.state.pool.begin().await?;
        let (version, at) = apps::insert_secret(
            &mut tx,
            row.app_id,
            organisation_id,
            secret,
            |version| seal(&key, row.app_id, secret, version, value),
            actor,
        )
        .await?;
        tx.commit().await?;
        Ok((secret.to_string(), version, at))
    }

    /// All live and pending volumes, including detached volumes absent from
    /// the latest release. The deletion precondition uses this same query.
    pub async fn volumes(
        &self,
        organisation_id: Uuid,
        name: &str,
    ) -> Result<Vec<grund_store::volumes::VolumeRow>, AppsError> {
        let row = self.live(organisation_id, name).await?;
        self.state
            .volumes()
            .list(organisation_id, row.app_id)
            .await
            .map_err(Into::into)
    }

    pub async fn deletion_preview(
        &self,
        organisation_id: Uuid,
        name: &str,
    ) -> Result<Vec<grund_store::volumes::VolumeRow>, AppsError> {
        self.volumes(organisation_id, name).await
    }

    /// Deletes the app immediately from every signed machine document, but
    /// retains its volumes and recovery points until the recorded deadline.
    pub async fn delete(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        confirm_volume_count: Option<u32>,
    ) -> Result<DateTime<Utc>, AppsError> {
        let row = self.live(organisation_id, name).await?;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        let before = apps::app_machines(&mut **work.sql(), row.app_id).await?;
        let app = work.load_app(row.app_id).await?;
        if app.deleted || app.organisation_id != organisation_id {
            return Err(AppsError::NotFound);
        }
        let owned =
            grund_store::volumes::app_volumes(&mut **work.sql(), organisation_id, row.app_id)
                .await?;
        if !owned.is_empty() && confirm_volume_count != u32::try_from(owned.len()).ok() {
            return Err(AppsError::VolumeConfirmationRequired {
                actual: owned.len(),
            });
        }
        let at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **work.sql())
            .await?;
        let purge_after = at
            + chrono::Duration::from_std(self.state.config.volume_delete_window)
                .map_err(anyhow::Error::from)?;
        work.app(
            row.app_id,
            AppCommand::Delete {
                actor,
                at,
                purge_after,
            },
        )
        .await?;
        let volume_machines = self
            .state
            .volumes()
            .delete_app_in(&mut work, organisation_id, row.app_id, purge_after)
            .await?;
        sqlx::query("DELETE FROM grund_volume_backup_attempts WHERE organisation_id = $1 AND app_id = $2 AND status IN ('pending','leased')")
            .bind(organisation_id).bind(row.app_id).execute(&mut **work.sql()).await?;
        self.state
            .domains()
            .unbind_app_in(&mut work, actor, row.app_id)
            .await?;
        let mut touched = before;
        touched.extend(volume_machines);
        self.publish_machines(work.sql(), touched).await?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        Ok(purge_after)
    }

    /// Apps are addressable by name while the name and data are reserved.
    pub async fn restorable(&self, organisation_id: Uuid) -> Result<Vec<AppRow>, AppsError> {
        Ok(apps::restorable_apps(&self.state.pool, organisation_id).await?)
    }

    /// Restoring the app keeps its UUID, releases and backup points. Old
    /// replicas were removed on deletion; reconciliation places fresh ones.
    pub async fn restore(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
    ) -> Result<(), AppsError> {
        let row = apps::app_by_name_including_deleted(&self.state.pool, organisation_id, name)
            .await?
            .ok_or(AppsError::NotFound)?;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        let app = work.load_app(row.app_id).await?;
        let at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **work.sql())
            .await?;
        if app.organisation_id != organisation_id
            || !app.deleted
            || !app.purge_after.is_some_and(|due| at < due)
        {
            return Err(AppsError::NotFound);
        }
        let rows =
            grund_store::volumes::app_volumes(&mut **work.sql(), organisation_id, row.app_id)
                .await?;
        let mut machines = Vec::new();
        for volume in rows {
            if volume.status == "pending_deletion" && volume.purge_after == app.purge_after {
                work.volume(
                    volume.volume_id,
                    grund_domain::volume::VolumeCommand::Restore { at },
                )
                .await?;
                if let Some(machine) = volume.machine_id {
                    machines.push(machine);
                }
            }
        }
        work.app(row.app_id, AppCommand::Restore { actor, at })
            .await?;
        self.publish_machines(work.sql(), machines).await?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        self.state.wakes.apps_changed();
        Ok(())
    }
    /// Records final expiry after every owned volume has left recovery.
    pub async fn purge_due(&self, at: DateTime<Utc>) -> Result<usize, AppsError> {
        let due: Vec<Uuid> = sqlx::query_scalar(
            "SELECT a.app_id FROM grund_apps a WHERE a.deleted_at IS NOT NULL \
             AND a.purge_after <= $1 AND NOT EXISTS (SELECT 1 FROM grund_volumes v \
             WHERE v.app_id = a.app_id AND v.status = 'pending_deletion') \
             ORDER BY a.purge_after, a.app_id LIMIT 100",
        )
        .bind(at)
        .fetch_all(&self.state.pool)
        .await?;
        let mut count = 0;
        for id in due {
            let mut work = Work::begin(&self.state.events, Uuid::now_v7(), "grund/purge").await?;
            let app = work.load_app(id).await?;
            if !app.deleted || !app.purge_after.is_some_and(|due| at >= due) {
                continue;
            }
            let pending: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM grund_volumes WHERE app_id = $1 AND status = 'pending_deletion')"
            ).bind(id).fetch_one(&mut **work.sql()).await?;
            if pending {
                continue;
            }
            work.app(id, AppCommand::Purge { at }).await?;
            work.commit().await?;
            count += 1;
        }
        Ok(count)
    }

    async fn publish_machines(
        &self,
        connection: &mut PgConnection,
        mut machines: Vec<Uuid>,
    ) -> anyhow::Result<()> {
        machines.sort();
        machines.dedup();
        for machine_id in machines {
            self.state
                .agents()
                .publish_in(connection, machine_id)
                .await?;
        }
        Ok(())
    }

    /// The secret values a replica on the calling machine needs, or `None`
    /// for a replica that is not placed there.
    pub async fn replica_secrets(
        &self,
        caller: &MachineCaller,
        replica_id: Uuid,
    ) -> anyhow::Result<Option<Vec<SecretValue>>> {
        let Some(placed) =
            apps::placed_replica(&self.state.pool, caller.machine_id, replica_id).await?
        else {
            return Ok(None);
        };
        let key = sealing_key(&self.state);
        let mut values = Vec::new();
        for secret in &placed.secret_versions.0 {
            let version = secret.version as i32;
            let sealed = apps::secret_value(&self.state.pool, placed.app_id, &secret.name, version)
                .await?
                .context("a release names a secret version that is not stored")?;
            let value = open(&key, placed.app_id, &secret.name, version, &sealed)
                .context("a stored secret does not open with this instance's key")?;
            values.push(SecretValue {
                name: secret.name.clone(),
                version: secret.version,
                value,
            });
        }
        Ok(Some(values))
    }

    /// One reconcile pass for one app, committed with the documents of the
    /// machines it touched. Returns whether it decided anything.
    pub async fn reconcile_app(&self, app_id: Uuid, organisation_id: Uuid) -> anyhow::Result<bool> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), "grund/apps").await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("grund-apps-placement:{organisation_id}"))
            .execute(&mut **work.sql())
            .await?;
        let before = apps::app_machines(&mut **work.sql(), app_id).await?;
        let reserved = apps::reservations(&mut **work.sql(), organisation_id, app_id).await?;
        let owned_volumes =
            grund_store::volumes::app_volumes(&mut **work.sql(), organisation_id, app_id).await?;
        let stateful = !owned_volumes.is_empty();
        let hosted_storage = owned_volumes.iter().any(|v| v.size_gib.is_some());
        let app = work.load_app(app_id).await?;
        let target = app.target().and_then(|number| app.release(number));
        let wanted = |name: &str| {
            target.is_some_and(|release| {
                release
                    .spec
                    .volumes
                    .iter()
                    .any(|volume| volume.name == name)
            })
        };
        let usable_volumes: Vec<_> = owned_volumes
            .iter()
            .filter(|volume| volume.lost_host_id.is_none())
            .cloned()
            .collect();
        let pins_writer = |v: &grund_store::volumes::VolumeRow| {
            v.status == "attached"
                || (v.size_gib.is_some()
                    && v.slot.is_some()
                    && matches!(v.status.as_str(), "awaiting_backend" | "detaching_backend"))
        };
        let pinned = owned_volumes
            .iter()
            .find(|v| pins_writer(v))
            .and_then(|v| v.machine_id)
            .or_else(|| {
                owned_volumes
                    .iter()
                    .find(|v| v.status == "available" && v.size_gib.is_none() && wanted(&v.name))
                    .and_then(|v| v.machine_id)
            });
        anyhow::ensure!(
            owned_volumes
                .iter()
                .filter(|v| pins_writer(v)
                    || (v.status == "available" && v.size_gib.is_none() && wanted(&v.name)))
                .all(|v| v.machine_id.is_none() || v.machine_id == pinned),
            "volumes requested by this release are on different machines; explicit recovery required"
        );
        let lost_in_target = owned_volumes
            .iter()
            .find(|v| v.lost_host_id.is_some() && wanted(&v.name));
        let unfenced_lost_machine: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM grund_volumes v JOIN grund_machines m \
             ON m.machine_id=v.machine_id WHERE v.organisation_id=$1 AND v.app_id=$2 \
             AND v.lost_host_id IS NOT NULL AND m.public_key IS NOT NULL)",
        )
        .bind(organisation_id)
        .bind(app_id)
        .fetch_one(&mut **work.sql())
        .await?;
        let volume_backend = self.state.volume_backend();
        let candidates =
            machines::organisation_machines(&mut **work.sql(), organisation_id).await?;
        let mut machines = Vec::with_capacity(candidates.len());
        for candidate in &candidates {
            let backend_eligible = if hosted_storage && candidate.pool == "management" {
                match &volume_backend {
                    Some(backend) => {
                        backend
                            .eligible(work.sql(), candidate, &usable_volumes)
                            .await?
                    }
                    None => false,
                }
            } else {
                false
            };
            let others = reserved
                .iter()
                .find(|r| r.machine_id == candidate.machine_id);
            if let Some(mut view) = reconcile_machine_view(
                candidate,
                others,
                stateful,
                hosted_storage,
                backend_eligible,
                pinned,
                before.contains(&candidate.machine_id),
            ) {
                view.last_seen = self.state.hearing.seen(view.last_seen);
                machines.push(view);
            }
        }
        if lost_in_target.is_some() || unfenced_lost_machine {
            machines.clear();
        }
        let observations: Vec<Observation> = apps::app_statuses(&mut **work.sql(), app_id)
            .await?
            .iter()
            .filter_map(observed)
            .collect();
        let ended_lease_machines =
            apps::ended_lease_machines(&mut **work.sql(), organisation_id, app_id).await?;
        let now = Utc::now();
        let (events, waiting) = work
            .app_decide(app_id, |app: &App| {
                let decision = reconcile_with_volumes(
                    app,
                    &observations,
                    &machines,
                    &ended_lease_machines,
                    now,
                    stateful,
                    &mut Uuid::now_v7,
                );
                Ok((decision.events, decision.waiting))
            })
            .await?;
        if stateful {
            let app = work.load_app(app_id).await?;
            for event in &events {
                if let AppEvent::ReplicaPlaced {
                    release,
                    machine_id,
                    ..
                } = event
                {
                    let spec = &app
                        .release(*release)
                        .context("a placed release exists")?
                        .spec;
                    self.state
                        .volumes()
                        .place_release_in(
                            &mut work,
                            organisation_id,
                            app_id,
                            *machine_id,
                            &spec.volumes,
                        )
                        .await?;
                }
            }
        }
        apps::set_waiting(
            &mut **work.sql(),
            app_id,
            &if let Some(lost) = lost_in_target {
                serde_json::json!([{
                    "slot": 0,
                    "reason": "volume_lost",
                    "message": format!(
                        "Volume {} lost with host {} on {}; {}",
                        lost.name,
                        lost.lost_host_name.as_deref().unwrap_or("unknown"),
                        lost.lost_at.map(|at| at.to_rfc3339()).unwrap_or_default(),
                        lost.lost_snapshot_id.as_ref().map_or_else(
                            || "no completed snapshot; recovery requires accept_empty and starts with empty data".to_string(),
                            |snapshot| format!("restore from snapshot {snapshot} to a new volume"),
                        ),
                    ),
                }])
            } else {
                serde_json::to_value(&waiting)?
            },
            now,
        )
        .await?;
        if events.is_empty() {
            work.commit().await?;
            return Ok(false);
        }
        let mut touched = before;
        touched.extend(apps::app_machines(&mut **work.sql(), app_id).await?);
        self.publish_machines(work.sql(), touched).await?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        Ok(true)
    }

    /// One pass over every app. A failure of one app is logged and the rest
    /// go on.
    pub async fn reconcile_all(&self) -> anyhow::Result<()> {
        let apps = apps::apps_to_reconcile(&self.state.pool).await;
        self.state.hearing.observe(&apps);
        for (app_id, organisation_id) in apps? {
            if let Err(error) = self.reconcile_app(app_id, organisation_id).await {
                tracing::warn!(%app_id, error = %format!("{error:#}"), "app reconcile failed; trying again");
            }
        }
        Ok(())
    }
}

/// Access to [`Apps`] from [`State`].
pub trait AppsState {
    fn apps(&self) -> Apps;
}

impl AppsState for State {
    fn apps(&self) -> Apps {
        Apps {
            state: self.clone(),
        }
    }
}

/// The app reconciler (apps.md §10.3), a notmad component: a pass over every
/// app on each wake (a deploy, a report that changed something) and every
/// [`RECONCILE_EVERY`]. No leader: two instances serialise on the same
/// locks, and the second finds nothing to do.
pub struct AppReconciler {
    state: State,
}

impl AppReconciler {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

impl notmad::Component for AppReconciler {
    fn info(&self) -> notmad::ComponentInfo {
        "grund/apps".into()
    }

    async fn run(
        &self,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<(), notmad::MadError> {
        let wake: Arc<tokio::sync::Notify> = self.state.wakes.apps();
        loop {
            if let Err(error) = self.state.apps().reconcile_all().await {
                tracing::warn!(error = %format!("{error:#}"), "app reconciler pass failed");
            }
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                _ = wake.notified() => {}
                _ = tokio::time::sleep(RECONCILE_EVERY) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deleted_name_is_restorable_only_before_its_deadline() {
        let deleted_at = Utc::now();
        let deadline = deleted_at + chrono::Duration::days(7);
        let recoverable = deleted_name_conflict(
            "shop".into(),
            deleted_at,
            deadline,
            deadline - chrono::Duration::nanoseconds(1),
        );
        assert_eq!(recoverable.reason(), "name_reserved_for_restore");
        assert_eq!(
            recoverable.to_string(),
            format!(
                "shop was deleted on {} and can be restored until {}.",
                deleted_at.format("%-d %b %Y %H:%M:%S UTC"),
                deadline.format("%-d %b %Y %H:%M:%S UTC")
            )
        );
        assert!(matches!(
            deleted_name_conflict("shop".into(), deleted_at, deadline, deadline),
            AppsError::NameTaken
        ));
    }

    #[test]
    fn first_volume_release_stops_the_old_writer_before_starting_on_a_capable_machine() {
        use chrono::Duration;
        use grund_domain::app::{
            PlaceReason, Release, ReleaseSource, ReplicaState,
            placement::Unplaceable,
            spec::{StopSpec, VolumeSpec},
        };
        use serde_json::json;
        use sqlx::types::Json;

        let now = Utc::now();
        let old_id = Uuid::from_u128(1);
        let own_id = Uuid::from_u128(2);
        let row = |machine_id, pool: &str, minted_by: &str, volumes| machines::MachineRow {
            machine_id,
            pool: pool.into(),
            home_organisation_id: None,
            name: format!("machine-{machine_id}"),
            state: if pool == "management" {
                "leased"
            } else {
                "active"
            }
            .into(),
            public_key: None,
            lease_id: None,
            lessee_organisation_id: None,
            lessee_slug: None,
            lease_name: None,
            leased_at: None,
            pool_organisation_id: None,
            pool_name: None,
            facts: Json(json!({})),
            minted_by: minted_by.into(),
            registered_at: now,
            key_registered_at: now,
            revoked_at: None,
            provider_machine_id: None,
            last_seen_at: Some(now),
            capabilities: Some(Json(json!({
                "apps": true,
                "volumes": volumes,
                "arch": "x86_64",
                "memory_mib": 4096,
                "cpu_millis": 4000
            }))),
            network_ports: Json(Vec::new()),
            labels: Json(Default::default()),
            cordoned_at: None,
            hosted_size: None,
            hosted_region: None,
        };
        let spec = |volumes: bool| AppSpec {
            image: "nginx".into(),
            command: Vec::new(),
            ports: Vec::new(),
            memory_mib: 512,
            cpu_millis: 100,
            env: Vec::new(),
            secrets: Vec::new(),
            check: None,
            stop: StopSpec::default(),
            volumes: if volumes {
                vec![VolumeSpec {
                    name: "data".into(),
                    path: "/data".into(),
                    source: None,
                    backup: false,
                    size_gib: None,
                }]
            } else {
                Vec::new()
            },
        };
        for (pool, minted_by) in [("management", "provider"), ("own", "account:owner")] {
            let old = row(old_id, pool, minted_by, false);
            let mut own = row(own_id, "own", "account:owner", false);
            let views = |own: &machines::MachineRow, app: &App| {
                [&old, own]
                    .into_iter()
                    .filter_map(|machine| {
                        let placed = app
                            .replicas
                            .iter()
                            .any(|r| r.machine_id == machine.machine_id);
                        reconcile_machine_view(machine, None, true, false, false, None, placed)
                    })
                    .collect::<Vec<_>>()
            };
            let mut app = App::default();
            let old_replica = Uuid::from_u128(3);
            let rollout_id = Uuid::from_u128(4);
            for event in [
                AppEvent::Created {
                    organisation_id: Uuid::from_u128(5),
                    name: AppName::parse("db").unwrap(),
                    settings: AppSettings::default(),
                    created_by: Uuid::nil(),
                    created_at: now,
                },
                AppEvent::ReleaseCreated {
                    release: Release {
                        number: 1,
                        spec: spec(false),
                        image_digest: "sha256:old".into(),
                        platforms: Vec::new(),
                        exposed_ports: None,
                        secret_versions: Vec::new(),
                        source: ReleaseSource::Api,
                        external_release: None,
                        rollback_of: None,
                        note: String::new(),
                        created_by: Uuid::nil(),
                        created_at: now,
                    },
                },
                AppEvent::ReplicaPlaced {
                    replica_id: old_replica,
                    slot: 0,
                    release: 1,
                    machine_id: old_id,
                    placement: 1,
                    reason: PlaceReason::Scale,
                    placed_at: now,
                },
                AppEvent::CurrentReleaseSet {
                    release: 1,
                    set_at: now,
                },
                AppEvent::ReleaseCreated {
                    release: Release {
                        number: 2,
                        spec: spec(true),
                        image_digest: "sha256:new".into(),
                        platforms: Vec::new(),
                        exposed_ports: None,
                        secret_versions: Vec::new(),
                        source: ReleaseSource::Api,
                        external_release: None,
                        rollback_of: None,
                        note: String::new(),
                        created_by: Uuid::nil(),
                        created_at: now,
                    },
                },
                AppEvent::RolloutStarted {
                    rollout_id,
                    from: Some(1),
                    to: 2,
                    started_at: now,
                },
            ] {
                mire::Aggregate::apply(&mut app, &event);
            }
            let mut observation = Observation {
                replica_id: old_replica,
                state: Observed::Running,
                ready: true,
                ready_since: Some(now - Duration::seconds(20)),
                ever_ready: true,
                restarts: 0,
                last_exit_code: 0,
                reason: String::new(),
                idle: false,
            };
            let mut new_id = || Uuid::from_u128(6);
            let first = reconcile_with_volumes(
                &app,
                &[observation.clone()],
                &views(&own, &app),
                &[],
                now,
                true,
                &mut new_id,
            );
            assert!(
                matches!(first.events.as_slice(), [AppEvent::ReplicaDraining { replica_id, .. }] if *replica_id == old_replica),
                "the old {pool} writer must be stopped before any replacement: {first:?}"
            );
            mire::Aggregate::apply(&mut app, &first.events[0]);
            own.capabilities.as_mut().unwrap().0["volumes"] = json!(true);
            let still_running = reconcile_with_volumes(
                &app,
                &[observation.clone()],
                &views(&own, &app),
                &[],
                now,
                true,
                &mut new_id,
            );
            assert!(
                still_running.events.is_empty(),
                "even a capable machine cannot receive a second writer before stop acknowledgement"
            );
            own.capabilities.as_mut().unwrap().0["volumes"] = json!(false);
            observation.state = Observed::Exited;
            let stopped = reconcile_with_volumes(
                &app,
                &[observation],
                &views(&own, &app),
                &[],
                now,
                true,
                &mut new_id,
            );
            assert!(
                matches!(stopped.events.as_slice(), [AppEvent::ReplicaRemoved { replica_id, .. }] if *replica_id == old_replica),
                "the old writer is fenced, but an incapable own machine cannot receive its volume: {stopped:?}"
            );
            assert_eq!(stopped.waiting[0].reason, Unplaceable::NoCapability);
            mire::Aggregate::apply(&mut app, &stopped.events[0]);
            let waiting =
                reconcile_with_volumes(&app, &[], &views(&own, &app), &[], now, true, &mut new_id);
            assert!(
                waiting.events.is_empty(),
                "without a capable machine no writer is started"
            );
            assert_eq!(waiting.waiting[0].reason, Unplaceable::NoMachine);
            assert_eq!(
                app.current_release,
                Some(1),
                "the old release remains current until v2 is ready"
            );
            own.capabilities.as_mut().unwrap().0["volumes"] = json!(true);
            let placed =
                reconcile_with_volumes(&app, &[], &views(&own, &app), &[], now, true, &mut new_id);
            assert!(
                matches!(placed.events.as_slice(), [AppEvent::ReplicaPlaced { machine_id, release: 2, .. }] if *machine_id == own_id),
                "the newly capable own machine receives the new writer: {placed:?}"
            );
            mire::Aggregate::apply(&mut app, &placed.events[0]);
            let ready = Observation {
                replica_id: app.replicas[0].replica_id,
                state: Observed::Running,
                ready: true,
                ready_since: Some(now - Duration::seconds(20)),
                ever_ready: true,
                restarts: 0,
                last_exit_code: 0,
                reason: String::new(),
                idle: false,
            };
            let finished = reconcile_with_volumes(
                &app,
                &[ready],
                &views(&own, &app),
                &[],
                now,
                true,
                &mut new_id,
            );
            for event in &finished.events {
                mire::Aggregate::apply(&mut app, event);
            }
            assert_eq!(app.current_release, Some(2), "{finished:?}");
            assert_eq!(app.replicas.len(), 1);
            assert_eq!(app.replicas[0].state, ReplicaState::Running);
            assert_eq!(app.replicas[0].machine_id, own_id);
        }
    }

    #[test]
    fn only_a_verified_bound_domain_allows_custom_only_publication() {
        use grund_domain::app::spec::Protocol;

        let mut spec = AppSpec {
            image: "nginx:1.27".into(),
            command: Vec::new(),
            ports: vec![PortSpec {
                name: "http".into(),
                port: 8080,
                protocol: Protocol::Http,
                public: false,
            }],
            memory_mib: 0,
            cpu_millis: 0,
            env: Vec::new(),
            secrets: Vec::new(),
            check: None,
            stop: Default::default(),
            volumes: Vec::new(),
        };
        assert!(allows_public_release(
            crate::config::AppDomains::CustomOnly,
            &spec,
            false
        ));
        spec.ports[0].public = true;
        assert!(!allows_public_release(
            crate::config::AppDomains::CustomOnly,
            &spec,
            false
        ));
        assert!(allows_public_release(
            crate::config::AppDomains::CustomOnly,
            &spec,
            true
        ));
        assert!(allows_public_release(
            crate::config::AppDomains::Shared,
            &spec,
            false
        ));
        spec.ports[0].protocol = Protocol::Tcp;
        assert!(allows_public_release(
            crate::config::AppDomains::CustomOnly,
            &spec,
            false
        ));
    }

    #[test]
    fn a_secret_is_named_after_its_variable() {
        assert_eq!(secret_name_for("API_KEY"), "api-key");
        assert_eq!(secret_name_for("_TOKEN_"), "token");
        assert_eq!(secret_name_for("Db_Password2"), "db-password2");
    }

    #[test]
    fn a_sealed_secret_opens_only_for_its_app_name_and_version() {
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[7u8; 32]).unwrap());
        let app = Uuid::now_v7();
        let sealed = seal(&key, app, "db-password", 1, b"hunter2");
        assert!(!sealed.windows(7).any(|w| w == b"hunter2"));
        assert_eq!(
            open(&key, app, "db-password", 1, &sealed).as_deref(),
            Some(&b"hunter2"[..])
        );
        assert_eq!(open(&key, app, "db-password", 2, &sealed), None);
        assert_eq!(open(&key, app, "other", 1, &sealed), None);
        assert_eq!(open(&key, Uuid::now_v7(), "db-password", 1, &sealed), None);
        let mut tampered = sealed.clone();
        tampered[20] ^= 1;
        assert_eq!(open(&key, app, "db-password", 1, &tampered), None);
    }
}
