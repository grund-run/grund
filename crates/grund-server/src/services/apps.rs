//! Apps (grund-docs design/apps.md): making them, their releases and
//! secrets, and the reconciler that places their replicas and rolls
//! releases out. Every decision about an app's replicas is
//! `grund_domain::app::reconcile::reconcile`, run under the app's stream
//! lock and the organisation's placement lock, and committed in one
//! transaction with the events' read models and the signed documents of
//! every machine it touched (§6.1, §10.3).

use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use grund_domain::app::{
    App, AppCommand, AppError, AppEvent, AppName, AppSettings, AppSpec, ReleaseSource,
    SecretVersion,
    placement::MachineView,
    reconcile::{Observation, Observed, reconcile},
    spec::{
        ImageReference, MAX_APPS_PER_ORGANISATION, MAX_SECRET_BYTES, SettingsInput, SpecError,
        secret_name_ok,
    },
    toml::parse_app,
};
use grund_store::{
    apps::{self, AppRow, ReleaseRow, ReplicaRow},
    machines,
    work::{Work, WorkError},
};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    registry::{Registry, ResolveError},
    services::agents::{AgentsState, MachineCaller},
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
    #[error("an organisation has at most {MAX_APPS_PER_ORGANISATION} apps")]
    AppLimit,
    #[error("{0}")]
    Spec(#[from] SpecError),
    #[error("{0}")]
    ImageUnresolved(String),
    #[error("{0}")]
    ImageUnsupported(String),
    #[error("no such release")]
    ReleaseNotFound,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppsError {
    /// The stable machine reason.
    pub fn reason(&self) -> &'static str {
        match self {
            AppsError::NotFound => "not_found",
            AppsError::NameTaken => "name_taken",
            AppsError::AppLimit => "app_limit",
            AppsError::Spec(_) => "spec_invalid",
            AppsError::ImageUnresolved(_) => "image_unresolved",
            AppsError::ImageUnsupported(_) => "image_unsupported",
            AppsError::ReleaseNotFound => "release_not_found",
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
pub enum DeployInput {
    Spec(AppSpec),
    /// A grund.toml naming the app.
    File(String),
}

/// An app as the API and dashboard show it.
#[derive(Debug, Clone)]
pub struct AppView {
    pub row: AppRow,
    pub replicas: Vec<ReplicaRow>,
    pub secrets: Vec<(String, i32, DateTime<Utc>)>,
}

/// One secret value of a replica.
#[derive(Debug, Clone)]
pub struct SecretValue {
    pub name: String,
    pub version: u32,
    pub value: Vec<u8>,
}

/// App flows.
#[derive(Clone)]
pub struct Apps {
    state: State,
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
    })
}

/// A machine as placement sees it, from what its agent last reported.
pub fn machine_view(row: &machines::MachineRow, reserved: Option<(i64, i64)>) -> MachineView {
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
        reserved_memory_mib: reserved.map_or(0, |(m, _)| m.max(0) as u64),
        reserved_cpu_millis: reserved.map_or(0, |(_, c)| c.max(0) as u32),
        max_replica_memory_mib: number("max_replica_memory_mib"),
        max_replica_cpu_millis: number("max_replica_cpu_millis") as u32,
    }
}

impl Apps {
    fn registry(&self) -> Result<Registry, AppsError> {
        Ok(Registry::new(
            self.state.config.insecure_registries.clone(),
        )?)
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
        if apps::app_by_name(&self.state.pool, organisation_id, name.as_str())
            .await?
            .is_some()
        {
            return Err(AppsError::NameTaken);
        }
        let app_id = Uuid::now_v7();
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string())
            .await
            .map_err(AppsError::from)?;
        work.app(
            app_id,
            AppCommand::Create {
                actor,
                organisation_id,
                name: name.clone(),
                settings,
                at: Utc::now(),
            },
        )
        .await?;
        work.commit().await?;
        let row = apps::app(&self.state.pool, app_id)
            .await?
            .context("the app just created")?;
        self.view(row).await
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

    async fn record_release(
        &self,
        actor: Uuid,
        app_id: Uuid,
        release: AppCommand,
        settings: Option<AppSettings>,
    ) -> Result<ReleaseRow, AppsError> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
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
        let row = self.live(organisation_id, name).await?;
        let (spec, settings, source) = match input {
            DeployInput::Spec(spec) => (spec.validate()?, None, source),
            DeployInput::File(text) => {
                let declared = parse_app(&text, &row.name)?;
                let mut input = row.settings.0.as_input();
                let file = declared.settings;
                input.copies = file.copies.or(input.copies);
                input.max_surge = file.max_surge.or(input.max_surge);
                input.max_unavailable = file.max_unavailable.or(input.max_unavailable);
                input.min_ready_seconds = file.min_ready_seconds.or(input.min_ready_seconds);
                input.ready_deadline_seconds =
                    file.ready_deadline_seconds.or(input.ready_deadline_seconds);
                input.drain_seconds = file.drain_seconds.or(input.drain_seconds);
                input.reschedule_after_seconds = file
                    .reschedule_after_seconds
                    .or(input.reschedule_after_seconds);
                input.auto_rollback = file.auto_rollback.or(input.auto_rollback);
                if !file.machines.is_empty() {
                    input.machines = file.machines;
                }
                (
                    declared.spec,
                    Some(AppSettings::validate(input)?),
                    ReleaseSource::File,
                )
            }
        };
        let note: String = note.chars().take(200).collect();
        let reference = ImageReference::parse(&spec.image)?;
        let resolved = self
            .registry()?
            .resolve(&reference)
            .await
            .map_err(|e| match e {
                ResolveError::Unsupported(_) => AppsError::ImageUnsupported(e.to_string()),
                other => AppsError::ImageUnresolved(other.to_string()),
            })?;
        let secret_versions = self.secret_versions(row.app_id, &spec).await?;
        self.record_release(
            actor,
            row.app_id,
            AppCommand::Release {
                actor,
                spec,
                image_digest: resolved.digest,
                platforms: resolved.platforms,
                secret_versions,
                source,
                rollback_of: None,
                note,
                rollout_id: Uuid::now_v7(),
                at: Utc::now(),
            },
            settings,
        )
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
                secret_versions,
                source: ReleaseSource::Rollback,
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
        Ok(apps::releases(&self.state.pool, row.app_id, RELEASES_SHOWN).await?)
    }

    async fn set_settings(
        &self,
        actor: Uuid,
        row: &AppRow,
        settings: AppSettings,
    ) -> Result<AppView, AppsError> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
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

    /// Deletes the app: its copies leave every machine's document in the
    /// same transaction.
    pub async fn delete(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
    ) -> Result<(), AppsError> {
        let row = self.live(organisation_id, name).await?;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        let before = apps::app_machines(&mut **work.sql(), row.app_id).await?;
        work.app(
            row.app_id,
            AppCommand::Delete {
                actor,
                at: Utc::now(),
            },
        )
        .await?;
        self.publish_machines(work.sql(), before).await?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        Ok(())
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
        let machines: Vec<MachineView> =
            machines::organisation_machines(&mut **work.sql(), organisation_id)
                .await?
                .iter()
                .filter(|m| matches!(m.state.as_str(), "active" | "leased"))
                .map(|m| {
                    let r = reserved
                        .iter()
                        .find(|(id, _, _)| *id == m.machine_id)
                        .map(|(_, mem, cpu)| (*mem, *cpu));
                    machine_view(m, r)
                })
                .collect();
        let observations: Vec<Observation> = apps::app_statuses(&mut **work.sql(), app_id)
            .await?
            .iter()
            .filter_map(observed)
            .collect();
        let now = Utc::now();
        let (events, waiting) = work
            .app_decide(app_id, |app: &App| {
                let decision = reconcile(app, &observations, &machines, now, &mut Uuid::now_v7);
                Ok((decision.events, decision.waiting))
            })
            .await?;
        apps::set_waiting(
            &mut **work.sql(),
            app_id,
            &serde_json::to_value(&waiting)?,
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
        for (app_id, organisation_id) in apps::apps_to_reconcile(&self.state.pool).await? {
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
