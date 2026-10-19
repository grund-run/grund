//! Whole-bundle admission and durable, ordered app coordination.

mod capacity;
mod mutations;
mod worker;
pub use worker::Worker;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use grund_config::{
    app::spec::{
        AppName, MAX_APPS_PER_ORGANISATION, MAX_SECRET_BYTES, Protocol, SecretEnv, SpecError,
    },
    stack::{self, Definition},
};
use grund_domain::{
    app::{AppCommand, Release, ReleaseSource, SecretVersion},
    stack::{Command, Kind, Operation, Revision, Service, Stack, Status, Step},
};
use grund_store::{
    apps, domains, machines, stacks as store,
    work::{Work, WorkError},
};
use ring::{
    aead::{AES_256_GCM, LessSafeKey, UnboundKey},
    hmac,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, types::Json};
use uuid::Uuid;

use crate::{
    services::{
        agents::AgentsState,
        apps::{AppsState, machine_view, open, seal},
        domains::DomainsState,
        entry::EntryState,
        volumes::VolumesState,
    },
    state::State,
};

/// A stable service response never includes a resolved credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceView {
    pub name: String,
    pub app_id: Uuid,
    pub app_name: String,
    pub image: String,
    pub status: String,
    pub ready: u32,
    pub copies: u32,
    /// The desired child execution release, not proof of a running copy.
    pub release: u32,
    /// Fresh observations include old copies still running during replacement.
    #[serde(default)]
    pub observed_running_releases: Vec<u32>,
    pub exclusive: bool,
    pub template: Option<String>,
    #[serde(default)]
    pub volume_intents: Vec<VolumeIntent>,
}

/// Storage intent contains no fabricated volume identity or observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeIntent {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size_gib: Option<u64>,
    pub backup_requested: bool,
    pub backup_policy: String,
}

/// Organisation-scoped owned data, including volumes of removed services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeView {
    pub service: String,
    pub app_id: Uuid,
    pub app_name: String,
    pub volume_id: Uuid,
    pub storage: VolumeIntent,
    pub status: String,
    pub retained: bool,
    pub purge_after: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct OwnedVolume {
    service: String,
    app_id: Uuid,
    app_name: String,
    volume_id: Uuid,
    name: String,
    path: String,
    size_gib: Option<i64>,
    backup: bool,
    status: String,
    purge_after: Option<DateTime<Utc>>,
}

/// The actual stack operation and service states, not a predicted success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackView {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub version: i64,
    pub revision: u32,
    pub machine_id: Option<Uuid>,
    pub address: Option<String>,
    pub services: Vec<ServiceView>,
    pub operation: Option<String>,
    pub failure: Option<String>,
    pub yaml: String,
    #[serde(default)]
    pub volumes: Vec<VolumeView>,
}

/// Effect-free resolved admission plan; capacity remains subject to commit-time checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preview {
    pub name: String,
    pub expected_version: i64,
    pub services: Vec<ServiceView>,
    pub memory_mib: u64,
    pub cpu_millis: u64,
    pub peak_memory_mib: u64,
    pub peak_cpu_millis: u64,
    pub selected_machine: Option<Uuid>,
    pub waiting: Option<String>,
    pub removed_services: Vec<String>,
}

struct Placement {
    machine: Option<Uuid>,
    memory: u64,
    cpu: u64,
}

/// Initial or explicitly changed values are supplied separately from versioned YAML.
#[derive(Clone, Serialize, Deserialize)]
pub struct InputSecret {
    pub service: String,
    pub name: String,
    pub value: String,
}

/// Failures are bounded safe categories; internal causes stay outside API responses.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no such stack")]
    NotFound,
    #[error("{0}")]
    Invalid(#[from] SpecError),
    #[error("stack or request changed; refresh the plan")]
    Conflict,
    #[error("the request key was already used for a different request")]
    IdempotencyConflict,
    #[error("another stack operation is active")]
    Busy,
    #[error("this app is owned by a stack")]
    Owned,
    #[error("stack operation unavailable")]
    Internal(#[from] anyhow::Error),
}

impl Error {
    /// Stable machine reason, without database or provider text.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Invalid(_) => "spec_invalid",
            Self::Conflict => "version_conflict",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::Busy => "operation_in_progress",
            Self::Owned => "stack_owned",
            Self::Internal(_) => "internal",
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(value: sqlx::Error) -> Self {
        Self::Internal(value.into())
    }
}
impl From<WorkError> for Error {
    fn from(value: WorkError) -> Self {
        match value {
            WorkError::Stack(grund_domain::stack::Error::NotFound) => Self::NotFound,
            WorkError::Stack(grund_domain::stack::Error::Busy) => Self::Busy,
            WorkError::Stack(_) => Self::Conflict,
            WorkError::App(grund_domain::app::AppError::StackOwned { .. }) => Self::Owned,
            other => Self::Internal(other.into()),
        }
    }
}

fn invalid(field: impl Into<String>, problem: impl Into<String>) -> Error {
    Error::Invalid(SpecError {
        field: field.into(),
        problem: problem.into(),
    })
}
fn key(state: &State) -> LessSafeKey {
    LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &state.secret.derive("app-secrets"))
            .expect("a 32-byte app sealing key"),
    )
}
fn app_name(id: Uuid) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut value = id.as_u128();
    let mut bytes = [b'a'; 27];
    bytes[0] = b's';
    for i in (1..27).rev() {
        bytes[i] = ALPHABET[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(bytes.to_vec()).expect("base32 is ASCII")
}
fn operation(
    kind: Kind,
    revision: u32,
    previous: u32,
    order: Vec<String>,
    at: DateTime<Utc>,
) -> Operation {
    Operation {
        id: Uuid::now_v7(),
        kind,
        target_revision: revision,
        previous_revision: previous,
        order,
        cursor: 0,
        step: Step::Pending,
        started_at: at,
        deadline: at + Duration::seconds(1800),
        compensating: false,
        failure: None,
        releases: BTreeMap::new(),
        halting: false,
    }
}
fn order(revision: &Revision) -> Result<Vec<String>, Error> {
    let mut completed = BTreeSet::new();
    let mut result = Vec::with_capacity(revision.services.len());
    while result.len() < revision.services.len() {
        let next = revision
            .services
            .iter()
            .find(|(name, s)| {
                !completed.contains(*name) && s.depends_on.iter().all(|d| completed.contains(d))
            })
            .map(|(n, _)| n.clone())
            .ok_or_else(|| invalid("stack.services", "dependency cycle"))?;
        completed.insert(next.clone());
        result.push(next);
    }
    Ok(result)
}

fn removed_services(previous: &Stack, revision: &Revision) -> Vec<String> {
    previous
        .revisions
        .get(&previous.desired_revision)
        .into_iter()
        .flat_map(|previous| previous.services.keys())
        .filter(|name| !revision.services.contains_key(*name))
        .cloned()
        .collect()
}
fn totals(revision: &Revision) -> (u64, u64) {
    revision
        .services
        .values()
        .fold((0, 0), |(memory, cpu), service| {
            (
                memory + service.release.spec.memory_mib * u64::from(service.settings.copies),
                cpu + u64::from(service.release.spec.cpu_millis)
                    * u64::from(service.settings.copies),
            )
        })
}

/// Service access reuses the instance handles; it creates no parallel runtime.
#[derive(Clone)]
pub struct Stacks {
    state: State,
}

/// Stack service extension shared by API, dashboard and worker.
pub trait StacksState {
    fn stacks(&self) -> Stacks;
}
impl StacksState for State {
    fn stacks(&self) -> Stacks {
        Stacks {
            state: self.clone(),
        }
    }
}

impl Stacks {
    async fn prepare(
        &self,
        org: Uuid,
        yaml: &str,
        selected: Option<&str>,
        refresh: Option<&str>,
        allowed_apps: Option<&[String]>,
    ) -> Result<(Definition, Revision, Vec<String>, Option<store::Row>), Error> {
        let definition = stack::parse(yaml)?;
        let old = store::by_name(&self.state.pool, org, &definition.name).await?;
        if let Some(apps) = allowed_apps {
            let row = old.as_ref().ok_or(Error::NotFound)?;
            self.require_scope(org, row.stack_id, apps).await?;
            if definition.services.keys().any(|name| {
                retained_service(&row.state.0.revisions, name)
                    .is_none_or(|service| !apps.contains(&service.app_name))
            }) {
                return Err(Error::NotFound);
            }
        }
        if old
            .as_ref()
            .is_some_and(|r| r.state.0.status == Status::Deleted)
        {
            return Err(Error::NotFound);
        }
        let previous = old
            .as_ref()
            .and_then(|r| r.state.0.revisions.get(&r.state.0.desired_revision));
        let previous_definition = previous.map(|r| stack::parse(&r.yaml)).transpose()?;
        if let Some(service) = selected {
            if !definition.services.contains_key(service) || previous.is_none() {
                return Err(invalid("service", "select a service of an existing stack"));
            }
            let before = previous_definition
                .as_ref()
                .expect("existing definition parsed");
            if definition.name != before.name
                || definition.machines != before.machines
                || definition.placement != before.placement
                || definition.public != before.public
                || definition.services.len() != before.services.len()
                || definition.services.iter().any(|(name, value)| {
                    name != service && before.services.get(name) != Some(value)
                })
            {
                return Err(invalid(
                    "service",
                    "the file changes another service or stack setting",
                ));
            }
        }
        if let Some(service) = refresh
            && (selected.is_some_and(|s| s != service)
                || !definition
                    .services
                    .get(service)
                    .is_some_and(|s| s.template.is_some()))
        {
            return Err(invalid(
                "refresh_template",
                "select a template service in this deployment",
            ));
        }
        let at = Utc::now();
        let mut revision = Revision {
            number: previous.map_or(1, |r| r.number + 1),
            yaml: yaml.to_string(),
            services: BTreeMap::new(),
            public_service: definition.public.as_ref().map(|p| p.service.clone()),
            public_port: definition.public.as_ref().map(|p| p.port.clone()),
            created_at: at,
            created_by: Uuid::nil(),
            rollback_of: None,
        };
        let mut changed = Vec::new();
        for (name, service) in &definition.services {
            let current = previous.and_then(|r| r.services.get(name));
            let prior = old
                .as_ref()
                .and_then(|row| retained_service(&row.state.0.revisions, name));
            let catalogue = service
                .template
                .as_deref()
                .map(|id| {
                    grund_domain::app::templates::find(id)
                        .filter(|template| template.unavailable.is_none())
                        .ok_or_else(|| {
                            invalid(
                                format!("stack.services.{name}.template"),
                                "template is unavailable",
                            )
                        })
                })
                .transpose()?;
            if prior.is_some_and(|prior| prior.template != service.template) {
                return Err(invalid(
                    format!("stack.services.{name}.template"),
                    "a retained service cannot change between image and template identities",
                ));
            }
            let unchanged_template = service.template.is_some()
                && refresh != Some(name.as_str())
                && previous_definition
                    .as_ref()
                    .and_then(|d| d.services.get(name))
                    == Some(service);
            if let Some(current) = current
                && (selected.is_some_and(|s| s != name) || unchanged_template)
            {
                revision.services.insert(name.clone(), current.clone());
                continue;
            }
            let (mut spec, mut settings, refs) =
                expand_service(&definition, name, catalogue, prior)?;
            if let Some(volume) = self
                .selected_data_volume(
                    &mut *self.state.pool.acquire().await?,
                    org,
                    name,
                    service,
                    prior,
                    old.as_ref().and_then(|row| row.state.0.machine_id),
                )
                .await?
            {
                let selected = spec.volumes.first_mut().expect("a stateful template");
                selected.size_gib = volume.size_gib.map(|size| size as u64);
                selected.backup = service
                    .app
                    .volumes
                    .get("data")
                    .and_then(|overlay| overlay.backup)
                    .map_or(volume.backup, |policy| {
                        matches!(policy, grund_config::app::file::FileBackup::Daily)
                    });
            }
            for reference in &refs {
                let producer = definition
                    .services
                    .get(&reference.service)
                    .ok_or_else(|| invalid("env", "unknown reference producer"))?;
                if matches!(
                    reference.output.as_str(),
                    "access_key_id" | "secret_access_key" | "region"
                ) && producer.template.as_deref() != Some("seaweedfs")
                {
                    return Err(invalid(
                        format!("stack.services.{name}.env.{}", reference.env),
                        "S3 outputs require a SeaweedFS template producer",
                    ));
                }
                if reference.output == "port" && producer.template.is_none() {
                    return Err(invalid(
                        format!("stack.services.{name}.env.{}", reference.env),
                        "image services export host and a single HTTP URL, not port",
                    ));
                }
                if reference.output == "url" && producer.template.is_none() {
                    let (producer_spec, _, _) = definition.service(&reference.service, None)?;
                    if producer_spec
                        .ports
                        .iter()
                        .filter(|p| matches!(p.protocol, Protocol::Http | Protocol::H2c))
                        .count()
                        != 1
                    {
                        return Err(invalid("env", "url requires exactly one HTTP or h2c port"));
                    }
                }
                if reference.output == "url"
                    && let Some(template) = producer
                        .template
                        .as_deref()
                        .and_then(grund_domain::app::templates::find)
                    && !matches!(template.key, "postgres" | "redis")
                    && template
                        .ports
                        .iter()
                        .filter(|(_, _, protocol)| {
                            matches!(protocol, Protocol::Http | Protocol::H2c)
                        })
                        .count()
                        != 1
                {
                    return Err(invalid("env", "producer exports no single typed URL"));
                }
                let secret = format!(
                    "stack-ref-{}",
                    hex::encode(&Sha256::digest(reference.env.as_bytes())[..12])
                );
                spec.secrets.push(SecretEnv {
                    env: reference.env.clone(),
                    secret,
                });
            }
            spec = spec.validate()?;
            settings.auto_rollback = false;
            let retained_exclusive = old.as_ref().is_some_and(|row| {
                row.state.0.revisions.values().any(|revision| {
                    revision.services.get(name).is_some_and(|service| {
                        service.exclusive || !service.release.spec.volumes.is_empty()
                    })
                })
            });
            if retained_exclusive && settings.copies != 1 {
                return Err(invalid(
                    format!("stack.services.{name}.copies"),
                    "a retained exclusive service requires exactly one copy",
                ));
            }
            let id = prior.map_or_else(Uuid::now_v7, |s| s.app_id);
            let release = Release {
                number: prior.map_or(1, |s| s.release.number + 1),
                spec,
                image_digest: String::new(),
                platforms: Vec::new(),
                exposed_ports: None,
                secret_versions: prior.map_or_else(Vec::new, |s| s.release.secret_versions.clone()),
                source: ReleaseSource::File,
                rollback_of: None,
                note: String::new(),
                created_by: Uuid::nil(),
                created_at: at,
                external_release: None,
                request: None,
            };
            let exclusive = matches!(service.restart(&release.spec), stack::Restart::Exclusive)
                || retained_exclusive;
            let candidate = Service {
                app_id: id,
                app_name: prior.map_or_else(|| app_name(id), |s| s.app_name.clone()),
                release,
                settings,
                depends_on: service.depends_on.clone(),
                exclusive,
                template: service.template.clone(),
            };
            changed.push(name.clone());
            revision.services.insert(name.clone(), candidate);
        }
        stack::validate_expanded(&revision.services)?;
        for name in changed.clone() {
            let candidate = revision.services.get_mut(&name).expect("planned service");
            let inspection = self
                .state
                .apps()
                .inspect(org, &candidate.release.spec.image)
                .await
                .map_err(|_| {
                    invalid(
                        format!("stack.services.{name}.image"),
                        "image cannot be resolved for this organisation",
                    )
                })?;
            candidate.release.image_digest = inspection.resolved.digest;
            candidate.release.platforms = inspection.resolved.platforms;
            candidate.release.exposed_ports = Some(inspection.exposed_ports);
            if let Some(prior) = previous.and_then(|revision| revision.services.get(&name))
                && prior.release.spec == candidate.release.spec
                && prior.release.image_digest == candidate.release.image_digest
                && prior.settings == candidate.settings
                && prior.depends_on == candidate.depends_on
                && prior.exclusive == candidate.exclusive
            {
                *candidate = prior.clone();
                changed.retain(|changed| changed != &name);
            }
        }
        if definition
            .placement
            .as_ref()
            .is_none_or(|placement| placement.kind.is_none())
            && revision
                .services
                .values()
                .any(|service| !service.release.spec.volumes.is_empty())
            && old.as_ref().is_none_or(|row| {
                row.state.0.revisions.values().all(|revision| {
                    revision
                        .services
                        .values()
                        .all(|service| service.release.spec.volumes.is_empty())
                })
            })
            && revision.services.iter().all(|(name, service)| {
                service.release.spec.volumes.is_empty()
                    || service.template.is_some()
                        && old.as_ref().is_none_or(|row| {
                            row.state
                                .0
                                .revisions
                                .values()
                                .all(|revision| !revision.services.contains_key(name))
                        })
            })
        {
            let mut connection = self.state.pool.acquire().await?;
            let pinned = old.as_ref().and_then(|row| row.state.0.machine_id);
            let stack_id = old.as_ref().map(|row| row.stack_id);
            if self
                .choose_machine(&mut connection, org, &revision, pinned, stack_id)
                .await?
                .machine
                .is_none()
            {
                let mut hosted = revision.clone();
                for (name, service) in &mut hosted.services {
                    if let Some(template) = service
                        .template
                        .as_deref()
                        .and_then(grund_domain::app::templates::find)
                        && let Some(storage) = template.storage
                    {
                        service.settings.placement.kind =
                            Some(grund_config::app::spec::MachineKind::Hosted);
                        for volume in &mut service.release.spec.volumes {
                            volume.size_gib = Some(storage.size_gib);
                            volume.backup = !matches!(
                                definition.services[name]
                                    .app
                                    .volumes
                                    .get(&volume.name)
                                    .and_then(|volume| volume.backup),
                                Some(grund_config::app::file::FileBackup::Off)
                            );
                        }
                    }
                }
                if self
                    .choose_machine(&mut connection, org, &hosted, pinned, stack_id)
                    .await?
                    .machine
                    .is_some()
                {
                    revision = hosted;
                }
            }
        }
        stack::validate_expanded(&revision.services)?;
        let ordered = order(&revision)?;
        changed.sort_by_key(|n| ordered.iter().position(|o| o == n));
        Ok((definition, revision, changed, old))
    }

    /// Previews the exact selected-service expansion without creating durable resources.
    pub async fn preview(
        &self,
        org: Uuid,
        yaml: &str,
        selected: Option<&str>,
        refresh: Option<&str>,
        allowed_apps: Option<&[String]>,
    ) -> Result<Preview, Error> {
        let (definition, revision, _, old) = self
            .prepare(org, yaml, selected, refresh, allowed_apps)
            .await?;
        let (memory, cpu) = totals(&revision);
        let mut connection = self.state.pool.acquire().await?;
        let placement = self
            .choose_machine(
                &mut connection,
                org,
                &revision,
                old.as_ref().and_then(|r| r.state.0.machine_id),
                old.as_ref().map(|r| r.stack_id),
            )
            .await?;
        Ok(Preview {
            name: definition.name,
            expected_version: old.as_ref().map_or(0, |r| r.stream_version),
            removed_services: old
                .as_ref()
                .map_or_else(Vec::new, |row| removed_services(&row.state.0, &revision)),
            services: revision
                .services
                .iter()
                .map(|(n, s)| service_view(n, s, 0, "planned"))
                .collect(),
            memory_mib: memory,
            cpu_millis: cpu,
            peak_memory_mib: placement.memory,
            peak_cpu_millis: placement.cpu,
            selected_machine: placement.machine,
            waiting: placement
                .machine
                .is_none()
                .then(|| "Waiting for one capable machine with enough capacity".into()),
        })
    }

    /// Reads actual app observations without projecting success from desired intent.
    pub async fn get(
        &self,
        org: Uuid,
        name: &str,
        allowed_apps: Option<&[String]>,
    ) -> Result<StackView, Error> {
        let row = store::by_name(&self.state.pool, org, name)
            .await?
            .ok_or(Error::NotFound)?;
        if let Some(apps) = allowed_apps {
            self.require_scope(org, row.stack_id, apps).await?;
        }
        self.view(row, allowed_apps).await
    }

    /// Lists a keyset page, including a bounded extra row for the next cursor.
    pub async fn list(
        &self,
        org: Uuid,
        limit: u32,
        after: Option<Uuid>,
        allowed_apps: Option<&[String]>,
    ) -> Result<Vec<StackView>, Error> {
        let rows = store::list(
            &self.state.pool,
            org,
            i64::from(limit.clamp(1, 100)) + 1,
            after,
            allowed_apps,
        )
        .await?;
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            result.push(self.view(row, allowed_apps).await?);
        }
        Ok(result)
    }

    async fn require_scope(&self, org: Uuid, stack: Uuid, apps: &[String]) -> Result<(), Error> {
        if !store::allowed(&self.state.pool, org, stack, apps).await? {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    async fn view(
        &self,
        row: store::Row,
        allowed_apps: Option<&[String]>,
    ) -> Result<StackView, Error> {
        let state = &row.state.0;
        let revision = state
            .revisions
            .get(&state.desired_revision)
            .ok_or(Error::NotFound)?;
        let volumes = volume_views(&self.state.pool, state, revision, row.stack_id).await?;
        if allowed_apps.is_some_and(|apps| {
            revision
                .services
                .values()
                .any(|service| !apps.contains(&service.app_name))
                || volumes
                    .iter()
                    .any(|volume| !apps.contains(&volume.app_name))
        }) {
            return Err(Error::NotFound);
        }
        let services = {
            let mut connection = self.state.pool.acquire().await?;
            self.service_views(&mut connection, state, revision).await?
        };
        let address = self.address(state, revision).await?;
        Ok(StackView {
            id: row.stack_id,
            name: state.name.clone(),
            status: state.status.as_str().into(),
            version: row.stream_version,
            revision: state.desired_revision,
            machine_id: state.machine_id,
            address,
            services,
            operation: state.operation.as_ref().map(|o| o.id.to_string()),
            failure: state.failure.clone(),
            yaml: revision.yaml.clone(),
            volumes,
        })
    }

    async fn service_views(
        &self,
        connection: &mut PgConnection,
        state: &Stack,
        revision: &Revision,
    ) -> Result<Vec<ServiceView>, Error> {
        let mut services = Vec::with_capacity(revision.services.len());
        let now = Utc::now();
        for (name, service) in &revision.services {
            let replicas = apps::app_replicas(&mut *connection, service.app_id).await?;
            let target = state
                .operation
                .as_ref()
                .and_then(|operation| operation.releases.get(name))
                .copied()
                .unwrap_or_else(|| {
                    if let Some(operation) = state
                        .operation
                        .as_ref()
                        .filter(|operation| operation.order.contains(name))
                    {
                        if matches!(operation.kind, Kind::Restart | Kind::Restore) {
                            0
                        } else {
                            service.release.number
                        }
                    } else {
                        replicas
                            .iter()
                            .map(|replica| replica.release.max(0) as u32)
                            .max()
                            .unwrap_or(service.release.number)
                    }
                });
            let mut ready = 0;
            let mut observed_running_releases = Vec::new();
            for replica in &replicas {
                if replica.observed_state.as_deref() != Some("running")
                    || !self
                        .state
                        .hearing
                        .seen(replica.last_seen_at)
                        .is_some_and(|seen| {
                            now - seen <= grund_domain::app::placement::UNREACHABLE_AFTER
                        })
                {
                    continue;
                }
                let release = replica.release.max(0) as u32;
                if !observed_running_releases.contains(&release) {
                    observed_running_releases.push(release);
                }
                if release == target && replica.state == "running" && replica.ready == Some(true) {
                    ready += 1;
                }
            }
            observed_running_releases.sort_unstable();
            let status = if state.status == Status::Deleted {
                "deleted"
            } else if ready == service.settings.copies {
                "ready"
            } else if replicas.is_empty() {
                "waiting"
            } else {
                "starting"
            };
            let mut view = service_view(name, service, ready, status);
            view.release = target;
            view.observed_running_releases = observed_running_releases;
            services.push(view);
        }
        Ok(services)
    }

    async fn address(&self, state: &Stack, revision: &Revision) -> Result<Option<String>, Error> {
        if state.status == Status::Deleted
            || state.status == Status::Deleting
            || revision.public_service.is_none()
        {
            return Ok(None);
        }
        let mut connection = self.state.pool.acquire().await?;
        let slug = grund_store::entry::organisation_slug(&mut *connection, state.organisation_id)
            .await?
            .unwrap_or_default();
        let selected = revision
            .public_service
            .as_ref()
            .and_then(|n| revision.services.get(n))
            .ok_or(Error::NotFound)?;
        self.state
            .entry()
            .address(&mut connection, selected.app_id, &selected.app_name, &slug)
            .await
            .map_err(Error::Internal)
    }

    async fn selected_data_volume(
        &self,
        connection: &mut PgConnection,
        org: Uuid,
        service_name: &str,
        definition: &stack::Service,
        prior: Option<&Service>,
        machine: Option<Uuid>,
    ) -> Result<Option<grund_store::volumes::VolumeRow>, Error> {
        let Some(selected) = &definition.data_volume else {
            return Ok(None);
        };
        let field = format!("stack.services.{service_name}.data_volume");
        let storage = definition
            .template
            .as_deref()
            .and_then(grund_domain::app::templates::find)
            .and_then(|template| template.storage)
            .ok_or_else(|| invalid(&field, "only a stateful template can select a data volume"))?;
        let prior =
            prior.ok_or_else(|| invalid(&field, "select a volume only in an existing service"))?;
        let current = prior
            .release
            .spec
            .volumes
            .first()
            .ok_or_else(|| invalid(&field, "the retained service has no data volume"))?;
        let row = grund_store::volumes::by_name(&mut *connection, org, prior.app_id, selected)
            .await?
            .ok_or_else(|| invalid(&field, "the selected data volume is unavailable"))?;
        if !matches!(row.status.as_str(), "available" | "attached")
            || row.detachment_pending
            || row.lost_host_id.is_some()
            || row.source.is_some()
            || row.path != storage.path
            || row.size_gib.map(|size| size as u64) != current.size_gib
            || machine.is_none()
            || row.machine_id != machine
        {
            return Err(invalid(
                &field,
                "the selected data volume is not ready on the stack's machine with its canonical path and capacity",
            ));
        }
        let restore = if row.size_gib.is_some() {
            self.state
                .volume_backend()
                .ok_or_else(|| invalid(&field, "hosted storage is unavailable"))?
                .restore_status(&self.state.pool, org, prior.app_id, row.volume_id)
                .await?
        } else {
            grund_store::volumes::restore_status(&mut *connection, org, prior.app_id, row.volume_id)
                .await?
        };
        if restore.is_some_and(|(status, _)| status != "completed") {
            return Err(invalid(
                &field,
                "the selected data volume's restore has not completed",
            ));
        }
        Ok(Some(row))
    }

    async fn lock(&self, work: &mut Work<'_>, org: Uuid) -> Result<(), Error> {
        domains::lock_hierarchy_policy(&mut **work.sql()).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("grund-apps-placement:{org}"))
            .execute(&mut **work.sql())
            .await?;
        Ok(())
    }

    async fn choose_machine(
        &self,
        connection: &mut PgConnection,
        org: Uuid,
        revision: &Revision,
        pinned: Option<Uuid>,
        stack_id: Option<Uuid>,
    ) -> Result<Placement, Error> {
        let (memory, cpu) = self
            .transition_reservation(connection, org, revision, stack_id)
            .await?;
        let placement = Placement {
            machine: None,
            memory,
            cpu,
        };
        let reservations = apps::reservations_for_stack(&mut *connection, org, stack_id).await?;
        let definition = stack::parse(&revision.yaml)?;
        let app_ids = revision
            .services
            .values()
            .map(|s| s.app_id)
            .collect::<Vec<_>>();
        let volumes:Vec<grund_store::volumes::VolumeRow>=sqlx::query_as("SELECT v.* FROM grund_volumes v WHERE v.organisation_id=$1 AND v.status<>'deleted' AND (v.app_id=ANY($2) OR ($3::uuid IS NOT NULL AND EXISTS(SELECT 1 FROM grund_stack_members sm WHERE sm.organisation_id=v.organisation_id AND sm.app_id=v.app_id AND sm.stack_id=$3)))")
            .bind(org).bind(&app_ids).bind(stack_id).fetch_all(&mut *connection).await?;
        let hosted = volumes.iter().any(|volume| volume.size_gib.is_some())
            || revision.services.values().any(|service| {
                service
                    .release
                    .spec
                    .volumes
                    .iter()
                    .any(|volume| volume.size_gib.is_some())
            });
        let local = volumes.iter().any(|volume| volume.size_gib.is_none())
            || revision.services.values().any(|service| {
                service
                    .release
                    .spec
                    .volumes
                    .iter()
                    .any(|volume| volume.size_gib.is_none())
            });
        if hosted && local {
            return Err(invalid(
                "stack.services",
                "desired and retained volumes cannot mix hosted blocks and own-machine directories",
            ));
        }
        let mut unplaced_count = volumes
            .iter()
            .filter(|volume| volume.size_gib.is_some() && volume.slot.is_none())
            .count();
        let mut unplaced_gib = volumes
            .iter()
            .filter(|volume| volume.size_gib.is_some() && volume.slot.is_none())
            .map(|volume| volume.size_gib.unwrap_or(0).max(0) as u64)
            .sum::<u64>();
        for service in revision.services.values() {
            for volume in &service.release.spec.volumes {
                if let Some(size) = volume.size_gib
                    && !volumes.iter().any(|existing| {
                        existing.app_id == service.app_id && existing.name == volume.name
                    })
                {
                    unplaced_count += 1;
                    unplaced_gib = unplaced_gib.saturating_add(size);
                }
            }
        }
        if volumes.iter().any(|v| v.lost_host_id.is_some()) {
            return Ok(placement);
        }
        let volume_pins = volumes
            .iter()
            .filter_map(|v| v.machine_id)
            .collect::<BTreeSet<_>>();
        if volume_pins.len() > 1 {
            return Ok(placement);
        }
        let mut candidates = machines::organisation_machines(&mut *connection, org).await?;
        candidates.sort_by_key(|m| m.machine_id);
        for row in candidates {
            if pinned.is_some_and(|id| id != row.machine_id)
                || !matches!(row.state.as_str(), "active" | "leased")
            {
                continue;
            }
            if !row
                .capabilities
                .as_ref()
                .is_some_and(|c| c.0["stack_services"].as_bool() == Some(true))
            {
                continue;
            }
            if volume_pins.iter().any(|id| *id != row.machine_id) {
                continue;
            }
            let usage = reservations.iter().find(|r| r.machine_id == row.machine_id);
            let mut view = machine_view(&row, usage);
            view.last_seen = self.state.hearing.seen(view.last_seen);
            if !view.apps || !view.connected(Utc::now()) || view.cordoned {
                continue;
            }
            if !definition.machines.is_empty() && !definition.machines.contains(&view.name) {
                continue;
            }
            if let Some(placement) = &definition.placement {
                if placement
                    .labels
                    .iter()
                    .any(|(k, v)| view.labels.get(k) != Some(v))
                {
                    continue;
                }
                let kind = placement.kind.map(|k| match k {
                    grund_config::app::file::FileMachineKind::Own => {
                        grund_config::app::spec::MachineKind::Own
                    }
                    grund_config::app::file::FileMachineKind::Hosted => {
                        grund_config::app::spec::MachineKind::Hosted
                    }
                });
                if kind.is_some_and(|k| k != view.kind) {
                    continue;
                }
            }
            if revision.services.values().any(|s| {
                s.settings
                    .placement
                    .kind
                    .is_some_and(|kind| kind != view.kind)
                    || !s.release.platforms.is_empty() && !s.release.platforms.contains(&view.arch)
                    || view.max_replica_memory_mib > 0
                        && s.release.spec.memory_mib > view.max_replica_memory_mib
                    || view.max_replica_cpu_millis > 0
                        && s.release.spec.cpu_millis > view.max_replica_cpu_millis
            }) {
                continue;
            }
            let stateful = !volumes.is_empty()
                || revision
                    .services
                    .values()
                    .any(|s| !s.release.spec.volumes.is_empty());
            if stateful {
                if hosted {
                    if row.pool != "management" || row.state != "leased" {
                        continue;
                    }
                    let Some(backend) = self.state.volume_backend() else {
                        continue;
                    };
                    if !volumes.is_empty() && !backend.eligible(connection, &row, &volumes).await? {
                        continue;
                    }
                    let occupied: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM grund_volumes WHERE machine_id=$1 AND slot IS NOT NULL AND status<>'deleted'",
                    )
                    .bind(row.machine_id)
                    .fetch_one(&mut *connection)
                    .await?;
                    if occupied.max(0) as usize + unplaced_count > 4
                        || unplaced_gib > 0
                            && !backend
                                .template_available(connection, &row, unplaced_gib)
                                .await?
                    {
                        continue;
                    }
                } else if row.pool == "management"
                    || !row.minted_by.starts_with("account:")
                    || !row
                        .capabilities
                        .as_ref()
                        .is_some_and(|c| c.0["volumes"].as_bool() == Some(true))
                {
                    continue;
                }
            }
            if memory
                > view
                    .allocatable_memory_mib()
                    .saturating_sub(view.reserved_memory_mib)
                || cpu
                    > u64::from(
                        view.allocatable_cpu_millis()
                            .saturating_sub(view.reserved_cpu_millis),
                    )
            {
                continue;
            }
            return Ok(Placement {
                machine: Some(row.machine_id),
                ..placement
            });
        }
        Ok(placement)
    }
}

fn service_view(name: &str, service: &Service, ready: u32, status: &str) -> ServiceView {
    ServiceView {
        name: name.into(),
        app_id: service.app_id,
        app_name: service.app_name.clone(),
        image: service.release.spec.image.clone(),
        status: status.into(),
        ready,
        copies: service.settings.copies,
        release: service.release.number,
        observed_running_releases: Vec::new(),
        exclusive: service.exclusive,
        template: service.template.clone(),
        volume_intents: service
            .release
            .spec
            .volumes
            .iter()
            .map(|volume| {
                volume_intent(
                    volume.name.clone(),
                    volume.path.clone(),
                    volume.size_gib,
                    volume.backup,
                )
            })
            .collect(),
    }
}

async fn volume_views(
    executor: impl sqlx::PgExecutor<'_>,
    state: &Stack,
    revision: &Revision,
    id: Uuid,
) -> Result<Vec<VolumeView>, Error> {
    let owned: Vec<OwnedVolume> = sqlx::query_as(
        "SELECT sm.service,v.app_id,sm.app_name,v.volume_id,v.name,v.path, \
                v.size_gib,v.backup,v.status,v.purge_after \
         FROM grund_volumes v JOIN grund_stack_members sm \
           ON sm.organisation_id=v.organisation_id AND sm.app_id=v.app_id \
         WHERE v.organisation_id=$1 AND sm.stack_id=$2 AND v.status<>'deleted' \
         ORDER BY sm.service,v.name",
    )
    .bind(state.organisation_id)
    .bind(id)
    .fetch_all(executor)
    .await?;
    Ok(owned
        .into_iter()
        .map(|volume| {
            let retained = state.status == Status::Deleted
                || !revision
                    .services
                    .get(&volume.service)
                    .is_some_and(|service| {
                        service.app_id == volume.app_id
                            && service
                                .release
                                .spec
                                .volumes
                                .iter()
                                .any(|intent| intent.name == volume.name)
                    });
            VolumeView {
                service: volume.service,
                app_id: volume.app_id,
                app_name: volume.app_name,
                volume_id: volume.volume_id,
                storage: volume_intent(
                    volume.name,
                    volume.path,
                    volume.size_gib.map(|size| size.max(0) as u64),
                    volume.backup,
                ),
                status: volume.status,
                retained,
                purge_after: volume.purge_after,
            }
        })
        .collect())
}

fn volume_intent(
    name: String,
    path: String,
    size_gib: Option<u64>,
    backup_requested: bool,
) -> VolumeIntent {
    VolumeIntent {
        name,
        path,
        kind: if size_gib.is_some() {
            "hosted_sized"
        } else {
            "own_local"
        }
        .into(),
        size_gib,
        backup_requested,
        backup_policy: match (size_gib, backup_requested) {
            (None, _) => "not_available",
            (Some(_), true) => "daily_snapshots_requested",
            (Some(_), false) => "off",
        }
        .into(),
    }
}

fn expand_service(
    definition: &Definition,
    name: &str,
    catalogue: Option<&grund_domain::app::templates::Template>,
    prior: Option<&Service>,
) -> Result<
    (
        grund_config::app::spec::AppSpec,
        grund_config::app::spec::AppSettings,
        Vec<stack::ConnectionRef>,
    ),
    Error,
> {
    let template = catalogue.and_then(|template| template.spec(false));
    let (mut spec, settings, refs) = definition.service(name, template)?;
    let Some(template) = catalogue else {
        return Ok((spec, settings, refs));
    };
    for variable in template.secret_variables {
        spec.secrets.push(SecretEnv {
            env: (*variable).into(),
            secret: crate::services::apps::secret_name_for(variable),
        });
    }
    if let Some(storage) = template.storage {
        let retained_volume = prior.and_then(|prior| prior.release.spec.volumes.first());
        let requested = settings.placement.kind;
        let hosted = retained_volume.map_or(
            requested == Some(grund_config::app::spec::MachineKind::Hosted),
            |volume| volume.size_gib.is_some(),
        );
        if requested
            .is_some_and(|kind| (kind == grund_config::app::spec::MachineKind::Hosted) != hosted)
        {
            return Err(invalid(
                format!("stack.services.{name}.volumes"),
                "a retained data volume cannot change storage kind",
            ));
        }
        for volume in &mut spec.volumes {
            volume.size_gib = if hosted {
                Some(
                    retained_volume
                        .and_then(|volume| volume.size_gib)
                        .unwrap_or(storage.size_gib),
                )
            } else {
                None
            };
            if hosted
                && definition.services[name]
                    .app
                    .volumes
                    .get(&volume.name)
                    .is_none_or(|overlay| overlay.backup.is_none())
            {
                volume.backup = true;
            }
        }
    }
    Ok((spec.validate()?, settings, refs))
}

fn retained_service<'a>(revisions: &'a BTreeMap<u32, Revision>, name: &str) -> Option<&'a Service> {
    revisions
        .values()
        .rev()
        .find_map(|revision| revision.services.get(name))
}
