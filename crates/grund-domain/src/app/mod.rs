//! The app aggregate (`grund-app`, grund-docs design/apps.md §10.1): an
//! app, its releases, where its copies run and how a release replaces
//! another. One stream per app, so every decision about its replicas (a
//! rollout step, a scale-down, a replacement) is made under one lock.
//!
//! Observations (a replica became ready, a machine stopped answering) are
//! not events; what grund decides because of them is ([`reconcile`]).

pub mod file;
pub mod placement;
pub mod reconcile;
pub mod spec;
pub mod templates;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use self::spec::{AppName, AppSettings, AppSpec, SpecError};

pub const APP_CATEGORY: &str = "grund-app";

/// Where a release came from, for the release list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseSource {
    Dashboard,
    Api,
    File,
    Rollback,
}

impl ReleaseSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ReleaseSource::Dashboard => "dashboard",
            ReleaseSource::Api => "api",
            ReleaseSource::File => "file",
            ReleaseSource::Rollback => "rollback",
        }
    }
}

/// The version of a secret a release was made with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretVersion {
    pub name: String,
    pub version: u32,
}
/// The durable origin of one externally requested release. The request
/// fingerprint contains no credentials or raw artifact contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRelease {
    pub forest_organisation: String,
    pub destination: String,
    pub project: String,
    pub intent_id: uuid::Uuid,
    pub artifact_id: uuid::Uuid,
    pub request_digest: [u8; 32],
}

/// An immutable, numbered snapshot of what every copy runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub number: u32,
    pub spec: AppSpec,
    /// `sha256:…`: what runs.
    pub image_digest: String,
    /// The architectures the image has a variant for; empty when the
    /// registry did not say (a single-platform manifest), in which case any
    /// machine may try.
    pub platforms: Vec<String>,
    /// Ports declared by the image's chosen runnable variant; absent on older releases.
    #[serde(default)]
    pub exposed_ports: Option<Vec<u16>>,
    pub secret_versions: Vec<SecretVersion>,
    pub source: ReleaseSource,
    pub rollback_of: Option<u32>,
    pub note: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_release: Option<ExternalRelease>,
}

/// Why a replica was placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaceReason {
    /// The app has fewer copies than it should, outside a rollout.
    Scale,
    /// A rollout's new copy for a slot.
    Rollout,
    /// The replica it replaces was lost with its machine.
    ReplaceLost,
    /// The app's copies were crowded on one machine while another was free.
    Spread,
    /// Its predecessor's machine was taken out of service, or no longer
    /// matches the app's placement (apps.md §5.7).
    Move,
}

/// Why a replica leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainReason {
    /// A newer copy in its slot is ready.
    Replaced,
    /// No room beside it for its successor, so it goes first.
    NoRoom,
    ScaledDown,
    /// The app has no release to run (its first release failed).
    NoRelease,
    /// Its management machine's lease ended; a hosted writer needs a detach receipt.
    LeaseEnded,
    Deleted,
}

/// Whether a placed replica should run or is leaving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaState {
    Running,
    Draining,
}

impl ReplicaState {
    pub fn as_str(self) -> &'static str {
        match self {
            ReplicaState::Running => "running",
            ReplicaState::Draining => "draining",
        }
    }
}

/// A replica grund placed and has not removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replica {
    pub replica_id: Uuid,
    pub slot: u32,
    pub release: u32,
    pub machine_id: Uuid,
    /// Numbered per app, never reused.
    pub placement: u64,
    pub state: ReplicaState,
    pub placed_at: DateTime<Utc>,
    pub draining_since: Option<DateTime<Utc>>,
}

/// A rollout in progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rollout {
    pub rollout_id: Uuid,
    pub from: Option<u32>,
    pub to: u32,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, mire::EventData)]
#[serde(tag = "type", rename_all = "snake_case")]
#[mire(entity = "grund-app")]
#[allow(clippy::large_enum_variant)]
pub enum AppEvent {
    Created {
        organisation_id: Uuid,
        name: AppName,
        settings: AppSettings,
        created_by: Uuid,
        created_at: DateTime<Utc>,
    },
    /// The settings in force, all of them.
    Configured {
        settings: AppSettings,
        configured_by: Uuid,
        configured_at: DateTime<Utc>,
    },
    ReleaseCreated {
        release: Release,
    },
    RolloutStarted {
        rollout_id: Uuid,
        from: Option<u32>,
        to: u32,
        started_at: DateTime<Utc>,
    },
    ReplicaPlaced {
        replica_id: Uuid,
        slot: u32,
        release: u32,
        machine_id: Uuid,
        placement: u64,
        reason: PlaceReason,
        placed_at: DateTime<Utc>,
    },
    ReplicaDraining {
        replica_id: Uuid,
        reason: DrainReason,
        draining_at: DateTime<Utc>,
    },
    ReplicaRemoved {
        replica_id: Uuid,
        removed_at: DateTime<Utc>,
    },
    /// Its machine was unreachable past the app's `reschedule_after`, or
    /// left the organisation; it is gone, and its slot is placed again.
    ReplicaLost {
        replica_id: Uuid,
        machine_id: Uuid,
        lost_at: DateTime<Utc>,
    },
    RolloutSucceeded {
        rollout_id: Uuid,
        succeeded_at: DateTime<Utc>,
    },
    /// `reason` is in words for the customer. `rolled_back`: the app goes
    /// back to its current release; otherwise it is halted as it is.
    RolloutFailed {
        rollout_id: Uuid,
        reason: String,
        rolled_back: bool,
        failed_at: DateTime<Utc>,
    },
    RolloutSuperseded {
        rollout_id: Uuid,
        by: u32,
        superseded_at: DateTime<Utc>,
    },
    CurrentReleaseSet {
        release: u32,
        set_at: DateTime<Utc>,
    },
    Deleted {
        deleted_by: Uuid,
        deleted_at: DateTime<Utc>,
        #[serde(default)]
        purge_after: Option<DateTime<Utc>>,
    },
    Restored {
        restored_by: Uuid,
        restored_at: DateTime<Utc>,
    },
    Purged {
        purged_at: DateTime<Utc>,
    },
    HostedVolumeLost {
        volume_id: Uuid,
        name: String,
        host_name: String,
        lost_at: DateTime<Utc>,
        snapshot_id: Option<String>,
    },
    HostedVolumeEmptyAccepted {
        volume_id: Uuid,
        actor: Uuid,
        accepted_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostedVolumeLoss {
    pub volume_id: Uuid,
    pub name: String,
    pub host_name: String,
    pub lost_at: DateTime<Utc>,
    pub snapshot_id: Option<String>,
    #[serde(default)]
    pub empty_replacement_accepted: bool,
}

/// What `apply` builds; also the snapshot.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct App {
    pub exists: bool,
    pub deleted: bool,
    pub purge_after: Option<DateTime<Utc>>,
    pub organisation_id: Uuid,
    pub name: Option<AppName>,
    #[serde(default)]
    pub external_owner: Option<(String, String, String)>,
    pub settings: AppSettings,
    pub releases: Vec<Release>,
    pub current_release: Option<u32>,
    pub rollout: Option<Rollout>,
    /// A release failed with automatic rollback off: nothing changes until
    /// the next release.
    pub halted: bool,
    pub replicas: Vec<Replica>,
    pub next_placement: u64,
    pub last_spread_move: Option<DateTime<Utc>>,
    #[serde(default)]
    pub lost_volumes: Vec<HostedVolumeLoss>,
}

impl App {
    /// The release every copy should run: the one rolling out, else the
    /// current one. `None` before any release went live and while none
    /// rolls out, and while halted.
    pub fn target(&self) -> Option<u32> {
        if self.halted || self.deleted {
            return None;
        }
        self.rollout.as_ref().map(|r| r.to).or(self.current_release)
    }

    pub fn release(&self, number: u32) -> Option<&Release> {
        self.releases.iter().find(|r| r.number == number)
    }

    pub fn latest_release(&self) -> Option<&Release> {
        self.releases.last()
    }

    pub fn replica(&self, replica_id: Uuid) -> Option<&Replica> {
        self.replicas.iter().find(|r| r.replica_id == replica_id)
    }
}

impl mire::Aggregate for App {
    type Event = AppEvent;

    fn stream_category() -> &'static str {
        APP_CATEGORY
    }

    fn apply(&mut self, event: &AppEvent) {
        match event {
            AppEvent::Created {
                organisation_id,
                name,
                settings,
                ..
            } => {
                self.exists = true;
                self.organisation_id = *organisation_id;
                self.name = Some(name.clone());
                self.settings = settings.clone();
            }
            AppEvent::Configured { settings, .. } => self.settings = settings.clone(),
            AppEvent::ReleaseCreated { release } => {
                if let Some(origin) = &release.external_release {
                    self.external_owner.get_or_insert_with(|| {
                        (
                            origin.forest_organisation.clone(),
                            origin.destination.clone(),
                            origin.project.clone(),
                        )
                    });
                }
                self.releases.push(release.clone());
                self.halted = false;
            }
            AppEvent::RolloutStarted {
                rollout_id,
                from,
                to,
                started_at,
            } => {
                self.rollout = Some(Rollout {
                    rollout_id: *rollout_id,
                    from: *from,
                    to: *to,
                    started_at: *started_at,
                });
            }
            AppEvent::ReplicaPlaced {
                replica_id,
                slot,
                release,
                machine_id,
                placement,
                reason,
                placed_at,
            } => {
                self.replicas.push(Replica {
                    replica_id: *replica_id,
                    slot: *slot,
                    release: *release,
                    machine_id: *machine_id,
                    placement: *placement,
                    state: ReplicaState::Running,
                    placed_at: *placed_at,
                    draining_since: None,
                });
                self.next_placement = self.next_placement.max(placement + 1);
                if *reason == PlaceReason::Spread {
                    self.last_spread_move = Some(*placed_at);
                }
            }
            AppEvent::ReplicaDraining {
                replica_id,
                draining_at,
                ..
            } => {
                if let Some(replica) = self
                    .replicas
                    .iter_mut()
                    .find(|r| r.replica_id == *replica_id)
                {
                    replica.state = ReplicaState::Draining;
                    replica.draining_since = Some(*draining_at);
                }
            }
            AppEvent::ReplicaRemoved { replica_id, .. }
            | AppEvent::ReplicaLost { replica_id, .. } => {
                self.replicas.retain(|r| r.replica_id != *replica_id);
            }
            AppEvent::RolloutSucceeded { .. } | AppEvent::RolloutSuperseded { .. } => {
                self.rollout = None;
            }
            AppEvent::RolloutFailed { rolled_back, .. } => {
                self.rollout = None;
                self.halted = !rolled_back;
            }
            AppEvent::CurrentReleaseSet { release, .. } => self.current_release = Some(*release),
            AppEvent::Deleted { purge_after, .. } => {
                self.deleted = true;
                self.purge_after = *purge_after;
                self.rollout = None;
            }
            AppEvent::Restored { .. } => {
                self.deleted = false;
                self.purge_after = None;
                self.halted = false;
            }
            AppEvent::HostedVolumeLost {
                volume_id,
                name,
                host_name,
                lost_at,
                snapshot_id,
            } => {
                if !self
                    .lost_volumes
                    .iter()
                    .any(|loss| loss.volume_id == *volume_id)
                {
                    self.lost_volumes.push(HostedVolumeLoss {
                        volume_id: *volume_id,
                        name: name.clone(),
                        host_name: host_name.clone(),
                        lost_at: *lost_at,
                        snapshot_id: snapshot_id.clone(),
                        empty_replacement_accepted: false,
                    });
                }
            }
            AppEvent::HostedVolumeEmptyAccepted { volume_id, .. } => {
                if let Some(loss) = self
                    .lost_volumes
                    .iter_mut()
                    .find(|loss| loss.volume_id == *volume_id)
                {
                    loss.empty_replacement_accepted = true;
                }
            }
            AppEvent::Purged { .. } => self.purge_after = None,
        }
    }
}

impl mire::Snapshot for App {
    const SNAPSHOT_VERSION: i32 = 5;
    const SNAPSHOT_FREQUENCY: i64 = 100;
}

/// What can be asked of an app. Authorization is the service's, before.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum AppCommand {
    Create {
        actor: Uuid,
        organisation_id: Uuid,
        name: AppName,
        settings: AppSettings,
        at: DateTime<Utc>,
    },
    /// Replaces the settings; the same settings again change nothing.
    Configure {
        actor: Uuid,
        settings: AppSettings,
        at: DateTime<Utc>,
    },
    /// Makes the next release, numbered by the aggregate, and rolls it out,
    /// superseding a rollout in progress.
    Release {
        actor: Uuid,
        spec: AppSpec,
        image_digest: String,
        platforms: Vec<String>,
        exposed_ports: Option<Vec<u16>>,
        secret_versions: Vec<SecretVersion>,
        source: ReleaseSource,
        external_release: Option<ExternalRelease>,
        rollback_of: Option<u32>,
        note: String,
        rollout_id: Uuid,
        at: DateTime<Utc>,
    },
    Delete {
        actor: Uuid,
        at: DateTime<Utc>,
        purge_after: DateTime<Utc>,
    },
    Restore {
        actor: Uuid,
        at: DateTime<Utc>,
    },
    Purge {
        at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppError {
    #[error("the app already exists")]
    AlreadyExists,
    #[error("no such app")]
    NotFound,
    #[error("no such release")]
    ReleaseNotFound,
    #[error("an app has at most 100000 releases")]
    TooManyReleases,
    #[error("this app belongs to another external project")]
    ExternalOwnerConflict,
}

impl mire::Command for AppCommand {
    type Aggregate = App;
    type Error = AppError;
    type Events = Vec<AppEvent>;

    fn handle(self, app: &App) -> Result<Vec<AppEvent>, AppError> {
        if let AppCommand::Create {
            actor,
            organisation_id,
            name,
            settings,
            at,
        } = self
        {
            if app.exists {
                return Err(AppError::AlreadyExists);
            }
            return Ok(vec![AppEvent::Created {
                organisation_id,
                name,
                settings,
                created_by: actor,
                created_at: at,
            }]);
        }
        if !app.exists {
            return Err(AppError::NotFound);
        }
        if app.deleted {
            return match self {
                AppCommand::Restore { actor, at }
                    if app.purge_after.is_some_and(|due| at < due) =>
                {
                    Ok(vec![AppEvent::Restored {
                        restored_by: actor,
                        restored_at: at,
                    }])
                }
                AppCommand::Purge { at } if app.purge_after.is_some_and(|due| at >= due) => {
                    Ok(vec![AppEvent::Purged { purged_at: at }])
                }
                _ => Err(AppError::NotFound),
            };
        }
        match self {
            AppCommand::Create { .. } => unreachable!("handled above"),
            AppCommand::Configure {
                actor,
                settings,
                at,
            } => {
                if app.settings == settings {
                    return Ok(Vec::new());
                }
                Ok(vec![AppEvent::Configured {
                    settings,
                    configured_by: actor,
                    configured_at: at,
                }])
            }
            AppCommand::Release {
                actor,
                spec,
                image_digest,
                platforms,
                exposed_ports,
                secret_versions,
                source,
                external_release,
                rollback_of,
                note,
                rollout_id,
                at,
            } => {
                if let Some(origin) = &external_release
                    && app.external_owner.as_ref().is_some_and(|owner| {
                        owner.0 != origin.forest_organisation
                            || owner.1 != origin.destination
                            || owner.2 != origin.project
                    })
                {
                    return Err(AppError::ExternalOwnerConflict);
                }
                if rollback_of.is_some_and(|n| app.release(n).is_none()) {
                    return Err(AppError::ReleaseNotFound);
                }
                let number = app.releases.last().map_or(1, |r| r.number + 1);
                if number > 100_000 {
                    return Err(AppError::TooManyReleases);
                }
                let mut events = vec![AppEvent::ReleaseCreated {
                    release: Release {
                        number,
                        spec,
                        image_digest,
                        platforms,
                        exposed_ports,
                        secret_versions,
                        source,
                        rollback_of,
                        note,
                        created_by: actor,
                        external_release,
                        created_at: at,
                    },
                }];
                if let Some(rollout) = &app.rollout {
                    events.push(AppEvent::RolloutSuperseded {
                        rollout_id: rollout.rollout_id,
                        by: number,
                        superseded_at: at,
                    });
                }
                events.push(AppEvent::RolloutStarted {
                    rollout_id,
                    from: app.current_release,
                    to: number,
                    started_at: at,
                });
                Ok(events)
            }
            AppCommand::Delete {
                actor,
                at,
                purge_after,
            } => {
                let mut events = vec![AppEvent::Deleted {
                    deleted_by: actor,
                    deleted_at: at,
                    purge_after: Some(purge_after),
                }];
                for replica in &app.replicas {
                    events.push(AppEvent::ReplicaRemoved {
                        replica_id: replica.replica_id,
                        removed_at: at,
                    });
                }
                Ok(events)
            }
            AppCommand::Restore { .. } | AppCommand::Purge { .. } => Err(AppError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use mire::{Aggregate, Command};

    use super::*;
    use crate::app::spec::{PortSpec, Protocol, StopSpec};

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).unwrap()
    }

    fn spec() -> AppSpec {
        AppSpec {
            image: "nginx".into(),
            command: Vec::new(),
            ports: vec![PortSpec {
                name: "http".into(),
                port: 80,
                protocol: Protocol::Http,
                public: false,
            }],
            memory_mib: 64,
            cpu_millis: 100,
            env: Vec::new(),
            volumes: Vec::new(),
            secrets: Vec::new(),
            check: None,
            stop: StopSpec::default(),
        }
    }

    fn fold(events: &[AppEvent]) -> App {
        let mut app = App::default();
        for event in events {
            app.apply(event);
        }
        app
    }

    fn created() -> App {
        let events = AppCommand::Create {
            actor: Uuid::nil(),
            organisation_id: Uuid::from_u128(1),
            name: AppName::parse("shop").unwrap(),
            settings: AppSettings::default(),
            at: at(),
        }
        .handle(&App::default())
        .unwrap();
        fold(&events)
    }

    fn release(app: &App) -> Vec<AppEvent> {
        AppCommand::Release {
            actor: Uuid::nil(),
            spec: spec(),
            image_digest: format!("sha256:{}", "b".repeat(64)),
            platforms: vec!["x86_64".into()],
            secret_versions: Vec::new(),
            exposed_ports: Some(vec![80]),
            source: ReleaseSource::Api,
            external_release: None,
            rollback_of: None,
            note: String::new(),
            rollout_id: Uuid::from_u128(9),
            at: at(),
        }
        .handle(app)
        .unwrap()
    }

    #[test]
    fn releases_are_numbered_from_one_and_each_starts_a_rollout() {
        let mut app = created();
        let events = release(&app);
        assert!(matches!(&events[0], AppEvent::ReleaseCreated { release } if release.number == 1));
        assert!(matches!(
            &events[1],
            AppEvent::RolloutStarted {
                from: None,
                to: 1,
                ..
            }
        ));
        for event in &events {
            app.apply(event);
        }
        assert_eq!(app.target(), Some(1));
        let second = release(&app);
        assert!(matches!(&second[0], AppEvent::ReleaseCreated { release } if release.number == 2));
        assert!(matches!(
            &second[1],
            AppEvent::RolloutSuperseded { by: 2, .. }
        ));
        assert!(matches!(&second[2], AppEvent::RolloutStarted { to: 2, .. }));
    }

    #[test]
    fn a_failed_release_without_rollback_halts_the_app_until_the_next() {
        let mut app = created();
        for event in release(&app) {
            app.apply(&event);
        }
        app.apply(&AppEvent::RolloutFailed {
            rollout_id: Uuid::from_u128(9),
            reason: "no".into(),
            rolled_back: false,
            failed_at: at(),
        });
        assert!(app.halted);
        assert_eq!(app.target(), None);
        for event in release(&app) {
            app.apply(&event);
        }
        assert!(!app.halted);
        assert_eq!(app.target(), Some(2));
    }

    #[test]
    fn a_rollback_of_a_release_that_never_existed_is_refused() {
        let app = created();
        let refused = AppCommand::Release {
            actor: Uuid::nil(),
            spec: spec(),
            image_digest: String::new(),
            platforms: Vec::new(),
            exposed_ports: None,
            secret_versions: Vec::new(),
            source: ReleaseSource::Rollback,
            external_release: None,
            rollback_of: Some(4),
            note: String::new(),
            rollout_id: Uuid::nil(),
            at: at(),
        }
        .handle(&app);
        assert_eq!(refused, Err(AppError::ReleaseNotFound));
    }

    #[test]
    fn a_deleted_app_removes_its_replicas_and_refuses_everything_after() {
        let mut app = created();
        app.apply(&AppEvent::ReplicaPlaced {
            replica_id: Uuid::from_u128(5),
            slot: 0,
            release: 1,
            machine_id: Uuid::from_u128(7),
            placement: 0,
            reason: PlaceReason::Scale,
            placed_at: at(),
        });
        let events = AppCommand::Delete {
            actor: Uuid::nil(),
            at: at(),
            purge_after: at() + chrono::Duration::days(7),
        }
        .handle(&app)
        .unwrap();
        assert_eq!(events.len(), 2);
        for event in &events {
            app.apply(event);
        }
        assert!(app.replicas.is_empty());
        assert_eq!(
            AppCommand::Delete {
                actor: Uuid::nil(),
                at: at(),
                purge_after: at() + chrono::Duration::days(7),
            }
            .handle(&app),
            Err(AppError::NotFound)
        );
    }

    #[test]
    fn a_deleted_app_can_be_restored_only_before_its_deadline() {
        let mut app = created();
        let deadline = at() + chrono::Duration::days(7);
        for event in (AppCommand::Delete {
            actor: Uuid::nil(),
            at: at(),
            purge_after: deadline,
        })
        .handle(&app)
        .unwrap()
        {
            app.apply(&event);
        }
        assert_eq!(
            AppCommand::Restore {
                actor: Uuid::nil(),
                at: deadline
            }
            .handle(&app),
            Err(AppError::NotFound)
        );
        let restored = AppCommand::Restore {
            actor: Uuid::nil(),
            at: deadline - chrono::Duration::seconds(1),
        }
        .handle(&app)
        .unwrap();
        for event in &restored {
            app.apply(event);
        }
        assert!(!app.deleted);
        assert_eq!(app.purge_after, None);
        assert_eq!(
            AppCommand::Purge { at: deadline }.handle(&app),
            Err(AppError::NotFound)
        );
    }

    #[test]
    fn a_purged_app_cannot_be_restored() {
        let mut app = created();
        let deadline = at() + chrono::Duration::days(7);
        for event in (AppCommand::Delete {
            actor: Uuid::nil(),
            at: at(),
            purge_after: deadline,
        })
        .handle(&app)
        .unwrap()
        {
            app.apply(&event);
        }
        for event in (AppCommand::Purge { at: deadline }).handle(&app).unwrap() {
            app.apply(&event);
        }
        assert!(app.deleted);
        assert_eq!(app.purge_after, None);
        assert_eq!(
            AppCommand::Restore {
                actor: Uuid::nil(),
                at: deadline
            }
            .handle(&app),
            Err(AppError::NotFound)
        );
    }

    #[test]
    fn configuring_the_same_settings_changes_nothing() {
        let app = created();
        let events = AppCommand::Configure {
            actor: Uuid::nil(),
            settings: AppSettings::default(),
            at: at(),
        }
        .handle(&app)
        .unwrap();
        assert!(events.is_empty());
    }
}
