//! The instance-wide, single-slot machine update rollout.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// The event category of the instance-wide rollout.
pub const CATEGORY: &str = "grund-agent-updates";

/// The fixed identity shared by every writer of this instance's rollout.
pub fn rollout_id() -> Uuid {
    Uuid::from_u128(0x6772756e_642d_6167_656e_742d75706461)
}

/// A public forge package, independent of machine architecture and checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BuildFields")]
pub struct PublicBuild {
    pub revision: String,
    pub package: String,
}

#[derive(Deserialize)]
struct BuildFields {
    revision: String,
    package: String,
}

impl TryFrom<BuildFields> for PublicBuild {
    type Error = Error;

    fn try_from(fields: BuildFields) -> Result<Self, Self::Error> {
        Self::new(fields.revision, fields.package)
    }
}

impl PublicBuild {
    /// Accepts an exact lowercase public revision and its immutable package.
    pub fn new(revision: impl Into<String>, package: impl Into<String>) -> Result<Self, Error> {
        let build = Self {
            revision: revision.into(),
            package: package.into(),
        };
        build.validate()?;
        Ok(build)
    }

    /// Selects the public half of a hosted `private+public` revision.
    pub fn from_revision(build_revision: &str, package: impl Into<String>) -> Result<Self, Error> {
        Self::new(public_revision(build_revision)?, package)
    }

    /// Selects the exact public main package, including for hosted builds.
    pub fn main(build_revision: &str) -> Result<Self, Error> {
        let revision = public_revision(build_revision)?;
        Self::new(revision, format!("main-{revision}"))
    }

    /// Rejects malformed revisions and packages, including arbitrary URLs.
    pub fn validate(&self) -> Result<(), Error> {
        if !valid_revision(&self.revision) {
            return Err(Error::InvalidBuild);
        }
        if self.package.strip_prefix("main-") == Some(self.revision.as_str())
            || valid_tag(&self.package)
        {
            Ok(())
        } else {
            Err(Error::InvalidBuild)
        }
    }
}

/// Extracts only the published public revision from a public or hosted build.
pub fn public_revision(revision: &str) -> Result<&str, Error> {
    let public = match revision.split_once('+') {
        Some((private, public)) if valid_revision(private) => public,
        Some(_) => return Err(Error::InvalidBuild),
        None => revision,
    };
    valid_revision(public)
        .then_some(public)
        .ok_or(Error::InvalidBuild)
}

fn valid_revision(revision: &str) -> bool {
    revision.len() == 40
        && revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_number(number: &str) -> bool {
    !number.is_empty()
        && (number.len() == 1 || !number.starts_with('0'))
        && number.bytes().all(|b| b.is_ascii_digit())
        && number.parse::<u64>().is_ok()
}

fn valid_tag(package: &str) -> bool {
    let Some(tag) = package.strip_prefix('v') else {
        return false;
    };
    let base = match tag.split_once("-alpha.") {
        Some((base, alpha)) if valid_number(alpha) && alpha != "0" => base,
        Some(_) => return false,
        None => tag,
    };
    let mut parts = base.split('.');
    (0..3).all(|_| parts.next().is_some_and(valid_number)) && parts.next().is_none()
}

/// Durable phases; failure retains ownership until safe completion or rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Offered,
    Authorized,
    HealthVerified,
    Succeeded,
    RolledBack,
    Failed,
}

/// Secret-free failure categories, never provider or command output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Download,
    Verification,
    Restart,
    Health,
    Timeout,
    Offline,
    LocalState,
    RegistrationChanged,
}

impl Failure {
    /// The stable bounded wire code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Verification => "verification",
            Self::Restart => "restart",
            Self::Health => "health",
            Self::Timeout => "timeout",
            Self::Offline => "offline",
            Self::LocalState => "local_state",
            Self::RegistrationChanged => "registration_changed",
        }
    }

    /// Parses only known, secret-free failure codes.
    pub fn parse(code: &str) -> Option<Self> {
        match code {
            "download" => Some(Self::Download),
            "verification" => Some(Self::Verification),
            "restart" => Some(Self::Restart),
            "health" => Some(Self::Health),
            "timeout" => Some(Self::Timeout),
            "offline" => Some(Self::Offline),
            "local_state" => Some(Self::LocalState),
            "registration_changed" => Some(Self::RegistrationChanged),
            _ => None,
        }
    }
}

/// Every report is bound to the same machine registration and selected target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fence {
    pub attempt_id: Uuid,
    pub machine_id: Uuid,
    pub registration_key: String,
    pub generation: u64,
}

/// A provider reservation whose release watermark permanently closes delayed acquisition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderUpdateFence {
    pub provider_machine_id: String,
    pub controller_id: Uuid,
    pub attempt_id: Uuid,
    pub sequence: u64,
}
/// The sole machine that may replace its executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub id: Uuid,
    pub machine_id: Uuid,
    #[serde(default)]
    pub sequence: u64,
    #[serde(default)]
    pub provider_fence: Option<ProviderUpdateFence>,
    pub registration_key: String,
    pub generation: u64,
    pub previous_revision: String,
    pub target: PublicBuild,
    pub phase: Phase,
    pub offered_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub authorized_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub authorized_boot_id: Option<Uuid>,
    pub boot_id: Option<Uuid>,
    pub failure: Option<Failure>,
}

impl Attempt {
    /// The immutable identity required for all subsequent transitions.
    pub fn fence(&self) -> Fence {
        Fence {
            attempt_id: self.id,
            machine_id: self.machine_id,
            registration_key: self.registration_key.clone(),
            generation: self.generation,
        }
    }

    fn matches(&self, fence: &Fence) -> bool {
        self.id == fence.attempt_id
            && self.machine_id == fence.machine_id
            && self.registration_key == fence.registration_key
            && self.generation == fence.generation
    }
}

/// The terminal identity needed for command replay; full receipts remain in the attempt projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedAttempt {
    pub id: Uuid,
    pub machine_id: Uuid,
    pub registration_key: String,
    pub generation: u64,
    pub phase: Phase,
    pub boot_id: Option<Uuid>,
}

impl From<&Attempt> for CompletedAttempt {
    fn from(attempt: &Attempt) -> Self {
        Self {
            id: attempt.id,
            machine_id: attempt.machine_id,
            registration_key: attempt.registration_key.clone(),
            generation: attempt.generation,
            phase: attempt.phase,
            boot_id: attempt.boot_id,
        }
    }
}

impl CompletedAttempt {
    fn matches(&self, fence: &Fence) -> bool {
        self.id == fence.attempt_id
            && self.machine_id == fence.machine_id
            && self.registration_key == fence.registration_key
            && self.generation == fence.generation
    }
}

/// The long-lived singleton; snapshots bound replay without becoming truth.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentUpdates {
    pub initialized: bool,
    pub generation: u64,
    pub target: Option<PublicBuild>,
    pub paused: bool,
    pub active: Option<Attempt>,
    pub last_completed: Option<CompletedAttempt>,
    #[serde(default)]
    pub attempt_sequence: u64,
    #[serde(default)]
    pub migration_holds: BTreeMap<Uuid, Uuid>,
    #[serde(default)]
    pub closed_migrations: BTreeMap<Uuid, Uuid>,
    #[serde(default)]
    pub pending_provider_release: Option<ProviderUpdateFence>,
}

/// Absolute transitions projected transactionally with their stream version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, mire::EventData)]
#[serde(tag = "type", rename_all = "snake_case")]
#[mire(entity = "grund-agent-updates")]
pub enum Event {
    Initialized {
        at: DateTime<Utc>,
    },
    TargetSelected {
        generation: u64,
        target: PublicBuild,
        at: DateTime<Utc>,
    },
    RolloutPaused {
        at: DateTime<Utc>,
    },
    RolloutResumed {
        at: DateTime<Utc>,
    },
    AttemptOffered {
        attempt: Attempt,
        at: DateTime<Utc>,
    },
    AttemptAuthorized {
        attempt: Attempt,
        at: DateTime<Utc>,
    },
    CandidateHealthVerified {
        attempt: Attempt,
        at: DateTime<Utc>,
    },
    AttemptSucceeded {
        attempt: Attempt,
        at: DateTime<Utc>,
    },
    AttemptRolledBack {
        attempt: Attempt,
        at: DateTime<Utc>,
    },
    AttemptFailed {
        attempt: Attempt,
        at: DateTime<Utc>,
    },
    OfferCancelled {
        attempt: Attempt,
        at: DateTime<Utc>,
    },
    MigrationHeld {
        machine_id: Uuid,
        migration_id: Uuid,
        at: DateTime<Utc>,
    },
    MigrationCleared {
        machine_id: Uuid,
        migration_id: Uuid,
        at: DateTime<Utc>,
    },
    ProviderReservationRequested {
        attempt: Attempt,
        at: DateTime<Utc>,
    },
    ProviderReleaseAcknowledged {
        reservation: ProviderUpdateFence,
        at: DateTime<Utc>,
    },
}

impl mire::Aggregate for AgentUpdates {
    type Event = Event;

    fn stream_category() -> &'static str {
        CATEGORY
    }

    fn apply(&mut self, event: &Event) {
        match event {
            Event::Initialized { .. } => self.initialized = true,
            Event::TargetSelected {
                generation, target, ..
            } => {
                self.generation = *generation;
                self.target = Some(target.clone());
            }
            Event::RolloutPaused { .. } => self.paused = true,
            Event::RolloutResumed { .. } => self.paused = false,
            Event::MigrationHeld {
                machine_id,
                migration_id,
                ..
            } => {
                self.migration_holds.insert(*machine_id, *migration_id);
            }
            Event::MigrationCleared {
                machine_id,
                migration_id,
                ..
            } => {
                if self.migration_holds.get(machine_id) == Some(migration_id) {
                    self.migration_holds.remove(machine_id);
                }
                self.closed_migrations
                    .entry(*machine_id)
                    .and_modify(|closed| *closed = (*closed).max(*migration_id))
                    .or_insert(*migration_id);
            }
            Event::ProviderReleaseAcknowledged { reservation, .. } => {
                if self.pending_provider_release.as_ref() == Some(reservation) {
                    self.pending_provider_release = None;
                }
            }
            Event::AttemptOffered { attempt, .. } => {
                self.attempt_sequence = self.attempt_sequence.max(attempt.sequence);
                self.active = Some(attempt.clone());
            }
            Event::ProviderReservationRequested { attempt, .. }
            | Event::AttemptAuthorized { attempt, .. }
            | Event::CandidateHealthVerified { attempt, .. } => self.active = Some(attempt.clone()),
            Event::AttemptFailed { attempt, .. } => {
                self.active = Some(attempt.clone());
                self.paused = true;
            }
            Event::AttemptSucceeded { attempt, .. } => {
                self.active = None;
                self.last_completed = Some(CompletedAttempt::from(attempt));
                self.pending_provider_release = attempt.provider_fence.clone();
            }
            Event::AttemptRolledBack { attempt, .. } => {
                self.active = None;
                self.last_completed = Some(CompletedAttempt::from(attempt));
                self.paused = true;
                self.pending_provider_release = attempt.provider_fence.clone();
            }
            Event::OfferCancelled { attempt, .. } => {
                self.active = None;
                self.pending_provider_release = attempt.provider_fence.clone();
            }
        }
    }
}

impl mire::Snapshot for AgentUpdates {
    const SNAPSHOT_VERSION: i32 = 4;
    const SNAPSHOT_FREQUENCY: i64 = 100;
}

/// Pure decisions; clocks and observed boot identities come from the caller.
#[derive(Debug, Clone)]
pub enum Command {
    Initialize {
        at: DateTime<Utc>,
    },
    Select {
        target: PublicBuild,
        at: DateTime<Utc>,
    },
    Pause {
        at: DateTime<Utc>,
    },
    Resume {
        at: DateTime<Utc>,
    },
    Offer {
        attempt_id: Uuid,
        machine_id: Uuid,
        registration_key: String,
        generation: u64,
        previous_revision: String,
        at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
    Begin {
        fence: Fence,
        boot_id: Uuid,
        provider_permit: Option<ProviderUpdateFence>,
        at: DateTime<Utc>,
    },
    HoldMigration {
        machine_id: Uuid,
        migration_id: Uuid,
        at: DateTime<Utc>,
    },
    ClearMigration {
        machine_id: Uuid,
        migration_id: Uuid,
        at: DateTime<Utc>,
    },
    ReserveProvider {
        fence: Fence,
        provider_machine_id: String,
        controller_id: Uuid,
        at: DateTime<Utc>,
    },
    AcknowledgeProviderRelease {
        reservation: ProviderUpdateFence,
        at: DateTime<Utc>,
    },
    Health {
        fence: Fence,
        boot_id: Uuid,
        at: DateTime<Utc>,
    },
    Commit {
        fence: Fence,
        boot_id: Uuid,
        at: DateTime<Utc>,
    },
    Rollback {
        fence: Fence,
        boot_id: Uuid,
        at: DateTime<Utc>,
    },
    Fail {
        fence: Fence,
        failure: Failure,
        at: DateTime<Utc>,
    },
    Cancel {
        fence: Fence,
        at: DateTime<Utc>,
    },
}

/// A refused transition records no events and leaves the slot untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("machine updates are not initialized")]
    NotInitialized,
    #[error("invalid public build identity")]
    InvalidBuild,
    #[error("machine rollout is paused")]
    Paused,
    #[error("the machine update slot is occupied")]
    SlotOccupied,
    #[error("no public target has been selected")]
    NoTarget,
    #[error("the attempt identity or generation has changed")]
    StaleFence,
    #[error("invalid attempt phase")]
    InvalidPhase,
    #[error("the offer has expired")]
    Expired,
    #[error("invalid attempt identity or clock")]
    InvalidAttempt,
    #[error("the candidate requires a new boot")]
    SameBoot,
    #[error("target generation is exhausted")]
    GenerationExhausted,
    #[error("machine lifecycle changes are blocked by an authorized update")]
    LifecycleBlocked,
    #[error("provider authorization is required")]
    ProviderPermitRequired,
}

impl AgentUpdates {
    fn attempt(&self, fence: &Fence) -> Result<&Attempt, Error> {
        self.active
            .as_ref()
            .filter(|a| a.matches(fence))
            .ok_or(Error::StaleFence)
    }

    fn completed(&self, fence: &Fence, phase: Phase, boot_id: Uuid) -> bool {
        self.last_completed
            .as_ref()
            .is_some_and(|a| a.matches(fence) && a.phase == phase && a.boot_id == Some(boot_id))
    }
}

impl mire::Command for Command {
    type Aggregate = AgentUpdates;
    type Error = Error;
    type Events = Vec<Event>;

    fn handle(self, state: &AgentUpdates) -> Result<Vec<Event>, Error> {
        if let Self::Initialize { at } = self {
            return Ok(if state.initialized {
                vec![]
            } else {
                vec![Event::Initialized { at }]
            });
        }
        if !state.initialized {
            return Err(Error::NotInitialized);
        }
        let event = match self {
            Self::Initialize { .. } => return Ok(vec![]),
            Self::HoldMigration {
                machine_id,
                migration_id,
                at,
            } => {
                if machine_id.is_nil() || migration_id.get_version_num() != 7 {
                    return Err(Error::InvalidAttempt);
                }
                if state
                    .closed_migrations
                    .get(&machine_id)
                    .is_some_and(|closed| migration_id <= *closed)
                {
                    return Err(Error::LifecycleBlocked);
                }
                if let Some(current) = state.migration_holds.get(&machine_id) {
                    return if *current == migration_id {
                        Ok(vec![])
                    } else {
                        Err(Error::LifecycleBlocked)
                    };
                }
                if state
                    .active
                    .as_ref()
                    .is_some_and(|a| a.machine_id == machine_id && a.authorized_at.is_some())
                {
                    return Err(Error::LifecycleBlocked);
                }
                Event::MigrationHeld {
                    machine_id,
                    migration_id,
                    at,
                }
            }
            Self::ClearMigration {
                machine_id,
                migration_id,
                at,
            } => {
                if machine_id.is_nil() || migration_id.get_version_num() != 7 {
                    return Err(Error::InvalidAttempt);
                }
                if state.migration_holds.get(&machine_id) != Some(&migration_id)
                    && state
                        .closed_migrations
                        .get(&machine_id)
                        .is_some_and(|closed| migration_id <= *closed)
                {
                    return Ok(vec![]);
                }
                Event::MigrationCleared {
                    machine_id,
                    migration_id,
                    at,
                }
            }
            Self::ReserveProvider {
                fence,
                provider_machine_id,
                controller_id,
                at,
            } => {
                let active = state.attempt(&fence)?;
                if active.phase != Phase::Offered
                    || state.paused
                    || state.migration_holds.contains_key(&active.machine_id)
                {
                    return Err(Error::LifecycleBlocked);
                }
                if at >= active.expires_at {
                    return Err(Error::Expired);
                }
                if provider_machine_id.is_empty() || controller_id.is_nil() || active.sequence == 0
                {
                    return Err(Error::InvalidAttempt);
                }
                let reservation = ProviderUpdateFence {
                    provider_machine_id,
                    controller_id,
                    attempt_id: active.id,
                    sequence: active.sequence,
                };
                if let Some(current) = &active.provider_fence {
                    return if *current == reservation {
                        Ok(vec![])
                    } else {
                        Err(Error::StaleFence)
                    };
                }
                let mut attempt = active.clone();
                attempt.provider_fence = Some(reservation);
                Event::ProviderReservationRequested { attempt, at }
            }
            Self::AcknowledgeProviderRelease { reservation, at } => {
                if state.pending_provider_release.as_ref() != Some(&reservation) {
                    return Ok(vec![]);
                }
                Event::ProviderReleaseAcknowledged { reservation, at }
            }
            Self::Select { target, at } => {
                target.validate()?;
                if state.target.as_ref() == Some(&target) {
                    return Ok(vec![]);
                }
                if state.active.is_some() {
                    return Err(Error::SlotOccupied);
                }
                let generation = state
                    .generation
                    .checked_add(1)
                    .filter(|generation| *generation <= i64::MAX as u64)
                    .ok_or(Error::GenerationExhausted)?;
                Event::TargetSelected {
                    generation,
                    target,
                    at,
                }
            }
            Self::Pause { at } => {
                if state.paused {
                    return Ok(vec![]);
                }
                Event::RolloutPaused { at }
            }
            Self::Resume { at } => {
                if !state.paused {
                    return Ok(vec![]);
                }
                if state
                    .active
                    .as_ref()
                    .is_some_and(|a| a.phase == Phase::Failed)
                {
                    return Err(Error::InvalidPhase);
                }
                Event::RolloutResumed { at }
            }
            Self::Offer {
                attempt_id,
                machine_id,
                registration_key,
                generation,
                previous_revision,
                at,
                expires_at,
            } => {
                if generation != state.generation {
                    return Err(Error::StaleFence);
                }
                if let Some(active) = &state.active {
                    if active.id == attempt_id
                        && active.machine_id == machine_id
                        && active.registration_key == registration_key
                        && active.generation == generation
                        && active.previous_revision == previous_revision
                        && active.expires_at == expires_at
                    {
                        return Ok(vec![]);
                    }
                    return Err(Error::SlotOccupied);
                }
                if state.paused {
                    return Err(Error::Paused);
                }
                if state.pending_provider_release.is_some()
                    || state.migration_holds.contains_key(&machine_id)
                {
                    return Err(Error::LifecycleBlocked);
                }
                let sequence = state
                    .attempt_sequence
                    .checked_add(1)
                    .filter(|sequence| *sequence <= i64::MAX as u64)
                    .ok_or(Error::GenerationExhausted)?;
                let target = state.target.as_ref().ok_or(Error::NoTarget)?;
                if attempt_id.is_nil()
                    || machine_id.is_nil()
                    || registration_key.len() != 64
                    || !registration_key
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !valid_revision(&previous_revision)
                    || previous_revision == target.revision
                    || expires_at <= at
                    || state
                        .last_completed
                        .as_ref()
                        .is_some_and(|a| a.id == attempt_id)
                {
                    return Err(Error::InvalidAttempt);
                }
                let attempt = Attempt {
                    id: attempt_id,
                    machine_id,
                    registration_key,
                    generation,
                    previous_revision,
                    sequence,
                    provider_fence: None,
                    target: target.clone(),
                    phase: Phase::Offered,
                    offered_at: at,
                    expires_at,
                    authorized_at: None,
                    authorized_boot_id: None,
                    boot_id: None,
                    failure: None,
                };
                Event::AttemptOffered { attempt, at }
            }
            Self::Begin {
                fence,
                boot_id,
                provider_permit,
                at,
            } => {
                let active = state.attempt(&fence)?;
                if active.authorized_at.is_some() && active.authorized_boot_id == Some(boot_id) {
                    return Ok(vec![]);
                }
                if state.paused {
                    return Err(Error::Paused);
                }
                if state.migration_holds.contains_key(&active.machine_id) {
                    return Err(Error::LifecycleBlocked);
                }
                if active.provider_fence != provider_permit {
                    return Err(Error::ProviderPermitRequired);
                }
                if fence.generation != state.generation {
                    return Err(Error::StaleFence);
                }
                if active.phase != Phase::Offered {
                    return Err(Error::InvalidPhase);
                }
                if at >= active.expires_at {
                    return Err(Error::Expired);
                }
                if at < active.offered_at || boot_id.is_nil() {
                    return Err(Error::InvalidAttempt);
                }
                let mut attempt = active.clone();
                attempt.phase = Phase::Authorized;
                attempt.authorized_at = Some(at);
                attempt.authorized_boot_id = Some(boot_id);
                attempt.boot_id = Some(boot_id);
                Event::AttemptAuthorized { attempt, at }
            }
            Self::Health { fence, boot_id, at } => {
                let active = state.attempt(&fence)?;
                if active.phase == Phase::HealthVerified && active.boot_id == Some(boot_id) {
                    return Ok(vec![]);
                }
                if !matches!(active.phase, Phase::Authorized | Phase::Failed)
                    || active.authorized_at.is_none()
                {
                    return Err(Error::InvalidPhase);
                }
                if boot_id.is_nil()
                    || active
                        .authorized_at
                        .is_some_and(|authorized| at < authorized)
                {
                    return Err(Error::InvalidAttempt);
                }
                if active.authorized_boot_id == Some(boot_id) {
                    return Err(Error::SameBoot);
                }
                let mut attempt = active.clone();
                attempt.phase = Phase::HealthVerified;
                attempt.boot_id = Some(boot_id);
                Event::CandidateHealthVerified { attempt, at }
            }
            Self::Commit { fence, boot_id, at } => {
                if state.completed(&fence, Phase::Succeeded, boot_id) {
                    return Ok(vec![]);
                }
                let active = state.attempt(&fence)?;
                if active.phase != Phase::HealthVerified || active.boot_id != Some(boot_id) {
                    return Err(Error::InvalidPhase);
                }
                if active
                    .authorized_at
                    .is_some_and(|authorized| at < authorized)
                {
                    return Err(Error::InvalidAttempt);
                }
                let mut attempt = active.clone();
                attempt.phase = Phase::Succeeded;
                Event::AttemptSucceeded { attempt, at }
            }
            Self::Rollback { fence, boot_id, at } => {
                if state.completed(&fence, Phase::RolledBack, boot_id) {
                    return Ok(vec![]);
                }
                let active = state.attempt(&fence)?;
                if active.authorized_at.is_none()
                    || !matches!(
                        active.phase,
                        Phase::Authorized | Phase::HealthVerified | Phase::Failed
                    )
                {
                    return Err(Error::InvalidPhase);
                }
                if boot_id.is_nil()
                    || active
                        .authorized_at
                        .is_some_and(|authorized| at < authorized)
                {
                    return Err(Error::InvalidAttempt);
                }
                if active.boot_id == Some(boot_id) || active.authorized_boot_id == Some(boot_id) {
                    return Err(Error::SameBoot);
                }
                let mut attempt = active.clone();
                attempt.phase = Phase::RolledBack;
                attempt.boot_id = Some(boot_id);
                Event::AttemptRolledBack { attempt, at }
            }
            Self::Fail { fence, failure, at } => {
                let active = state.attempt(&fence)?;
                if active.phase == Phase::Failed && active.failure == Some(failure) {
                    return Ok(vec![]);
                }
                if at < active.offered_at {
                    return Err(Error::InvalidAttempt);
                }
                let mut attempt = active.clone();
                attempt.phase = Phase::Failed;
                attempt.failure = Some(failure);
                Event::AttemptFailed { attempt, at }
            }
            Self::Cancel { fence, at } => {
                let active = state.attempt(&fence)?;
                if active.authorized_at.is_some() {
                    return Err(Error::InvalidPhase);
                }
                if at < active.offered_at {
                    return Err(Error::InvalidAttempt);
                }
                Event::OfferCancelled {
                    attempt: active.clone(),
                    at,
                }
            }
        };
        Ok(vec![event])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mire::{Aggregate, Command as _};

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    fn decide(state: &mut AgentUpdates, command: Command) -> Result<Vec<Event>, Error> {
        let events = command.handle(state)?;
        for event in &events {
            state.apply(event);
        }
        Ok(events)
    }

    fn selected() -> AgentUpdates {
        let mut state = AgentUpdates::default();
        decide(&mut state, Command::Initialize { at: at() }).unwrap();
        decide(
            &mut state,
            Command::Select {
                target: PublicBuild::main(&"b".repeat(40)).unwrap(),
                at: at(),
            },
        )
        .unwrap();
        state
    }

    fn offer(state: &AgentUpdates, id: u128) -> Command {
        Command::Offer {
            attempt_id: Uuid::from_u128(id),
            machine_id: Uuid::from_u128(id + 10),
            registration_key: "a".repeat(64),
            generation: state.generation,
            previous_revision: "a".repeat(40),
            at: at(),
            expires_at: at() + chrono::Duration::minutes(10),
        }
    }

    fn offered() -> (AgentUpdates, Fence) {
        let mut state = selected();
        let command = offer(&state, 1);
        decide(&mut state, command).unwrap();
        let fence = state.active.as_ref().unwrap().fence();
        (state, fence)
    }

    fn authorized() -> (AgentUpdates, Fence) {
        let (mut state, fence) = offered();
        decide(
            &mut state,
            Command::Begin {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(20),
                provider_permit: None,
                at: at(),
            },
        )
        .unwrap();
        (state, fence)
    }

    #[test]
    fn one_slot_remains_occupied_through_health_until_the_commit_acknowledgment() {
        let (mut state, fence) = authorized();
        assert_eq!(offer(&state, 2).handle(&state), Err(Error::SlotOccupied));
        decide(
            &mut state,
            Command::Health {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(21),
                at: at(),
            },
        )
        .unwrap();
        assert_eq!(state.active.as_ref().unwrap().phase, Phase::HealthVerified);
        assert_eq!(offer(&state, 2).handle(&state), Err(Error::SlotOccupied));
        let commit = Command::Commit {
            fence,
            boot_id: Uuid::from_u128(21),
            at: at(),
        };
        decide(&mut state, commit.clone()).unwrap();
        assert!(state.active.is_none());
        assert_eq!(
            state.last_completed.as_ref().unwrap().phase,
            Phase::Succeeded
        );
        assert!(decide(&mut state, commit).unwrap().is_empty());
        let next = offer(&state, 2);
        decide(&mut state, next).unwrap();
        assert_eq!(state.active.as_ref().unwrap().id, Uuid::from_u128(2));
    }

    #[test]
    fn pausing_before_begin_refuses_authorization_but_pausing_after_begin_allows_safe_completion() {
        let (mut state, fence) = offered();
        decide(&mut state, Command::Pause { at: at() }).unwrap();
        let begin = Command::Begin {
            fence: fence.clone(),
            boot_id: Uuid::from_u128(20),
            provider_permit: None,
            at: at(),
        };
        assert_eq!(begin.clone().handle(&state), Err(Error::Paused));
        decide(&mut state, Command::Resume { at: at() }).unwrap();
        decide(&mut state, begin).unwrap();
        decide(&mut state, Command::Pause { at: at() }).unwrap();
        decide(
            &mut state,
            Command::Health {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(21),
                at: at(),
            },
        )
        .unwrap();
        decide(
            &mut state,
            Command::Commit {
                fence,
                boot_id: Uuid::from_u128(21),
                at: at(),
            },
        )
        .unwrap();
        assert!(state.paused);
        assert!(state.active.is_none());
    }

    #[test]
    fn old_generations_and_changed_registrations_cannot_begin_or_report() {
        let (mut state, fence) = offered();
        let mut wrong = fence.clone();
        wrong.registration_key = "b".repeat(64);
        assert_eq!(
            Command::Begin {
                fence: wrong,
                boot_id: Uuid::from_u128(20),
                provider_permit: None,
                at: at()
            }
            .handle(&state),
            Err(Error::StaleFence)
        );
        decide(
            &mut state,
            Command::Cancel {
                fence: fence.clone(),
                at: at(),
            },
        )
        .unwrap();
        decide(
            &mut state,
            Command::Select {
                target: PublicBuild::main(&"c".repeat(40)).unwrap(),
                at: at(),
            },
        )
        .unwrap();
        assert_eq!(
            Command::Begin {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(20),
                provider_permit: None,
                at: at()
            }
            .handle(&state),
            Err(Error::StaleFence)
        );
        let stale_offer = Command::Offer {
            attempt_id: Uuid::from_u128(2),
            machine_id: fence.machine_id,
            registration_key: fence.registration_key,
            generation: fence.generation,
            previous_revision: "a".repeat(40),
            at: at(),
            expires_at: at() + chrono::Duration::minutes(10),
        };
        assert_eq!(stale_offer.handle(&state), Err(Error::StaleFence));
        let (state, mut fence) = authorized();
        fence.registration_key = "b".repeat(64);
        assert_eq!(
            Command::Health {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(21),
                at: at()
            }
            .handle(&state),
            Err(Error::StaleFence)
        );
        assert_eq!(
            Command::Rollback {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(22),
                at: at()
            }
            .handle(&state),
            Err(Error::StaleFence)
        );
        assert_eq!(
            Command::Fail {
                fence,
                failure: Failure::Offline,
                at: at()
            }
            .handle(&state),
            Err(Error::StaleFence)
        );
    }

    #[test]
    fn failure_pauses_and_retains_the_slot_but_verified_health_can_still_commit() {
        let (mut state, fence) = authorized();
        decide(
            &mut state,
            Command::Fail {
                fence: fence.clone(),
                failure: Failure::Offline,
                at: at(),
            },
        )
        .unwrap();
        assert!(state.paused);
        assert_eq!(state.active.as_ref().unwrap().phase, Phase::Failed);
        assert_eq!(
            Command::Cancel {
                fence: fence.clone(),
                at: at()
            }
            .handle(&state),
            Err(Error::InvalidPhase)
        );
        assert_eq!(
            Command::Health {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(20),
                at: at()
            }
            .handle(&state),
            Err(Error::SameBoot)
        );
        decide(
            &mut state,
            Command::Health {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(21),
                at: at(),
            },
        )
        .unwrap();
        decide(
            &mut state,
            Command::Fail {
                fence: fence.clone(),
                failure: Failure::Timeout,
                at: at(),
            },
        )
        .unwrap();
        decide(
            &mut state,
            Command::Health {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(21),
                at: at(),
            },
        )
        .unwrap();
        decide(
            &mut state,
            Command::Commit {
                fence,
                boot_id: Uuid::from_u128(21),
                at: at(),
            },
        )
        .unwrap();
        assert!(state.active.is_none());
        assert!(state.paused);
    }

    #[test]
    fn rollback_frees_the_slot_pauses_and_replays_a_lost_acknowledgment() {
        let (mut state, fence) = authorized();
        decide(
            &mut state,
            Command::Fail {
                fence: fence.clone(),
                failure: Failure::Health,
                at: at(),
            },
        )
        .unwrap();
        let rollback = Command::Rollback {
            fence,
            boot_id: Uuid::from_u128(22),
            at: at(),
        };
        decide(&mut state, rollback.clone()).unwrap();
        assert!(state.active.is_none());
        assert!(state.paused);
        assert_eq!(
            state.last_completed.as_ref().unwrap().phase,
            Phase::RolledBack
        );
        assert!(decide(&mut state, rollback).unwrap().is_empty());
        assert_eq!(offer(&state, 2).handle(&state), Err(Error::Paused));
    }

    #[test]
    fn only_never_authorized_offers_can_be_cancelled_or_expire() {
        let (mut state, fence) = offered();
        assert_eq!(
            Command::Begin {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(20),
                provider_permit: None,
                at: at() + chrono::Duration::minutes(10)
            }
            .handle(&state),
            Err(Error::Expired)
        );
        decide(
            &mut state,
            Command::Cancel {
                fence,
                at: at() + chrono::Duration::minutes(10),
            },
        )
        .unwrap();
        assert!(state.active.is_none());
        let (state, fence) = authorized();
        assert_eq!(
            Command::Cancel {
                fence,
                at: at() + chrono::Duration::days(1)
            }
            .handle(&state),
            Err(Error::InvalidPhase)
        );
        assert!(state.active.is_some());
    }

    #[test]
    fn snapshots_roundtrip_all_slot_and_failure_fences() {
        let (mut state, fence) = authorized();
        decide(
            &mut state,
            Command::Fail {
                fence,
                failure: Failure::Timeout,
                at: at(),
            },
        )
        .unwrap();
        let encoded = serde_json::to_vec(&state).unwrap();
        assert_eq!(
            serde_json::from_slice::<AgentUpdates>(&encoded).unwrap(),
            state
        );
    }

    #[test]
    fn public_build_selection_never_uses_a_private_revision_or_an_arbitrary_package() {
        let public = "a".repeat(40);
        let private = "b".repeat(40);
        assert_eq!(
            PublicBuild::main(&format!("{private}+{public}"))
                .unwrap()
                .revision,
            public
        );
        for tag in ["v1.2.3", "v0.0.0-alpha.12"] {
            assert!(PublicBuild::new(&public, tag).is_ok());
        }
        for package in [
            "v01.2.3",
            "v1.2.3-alpha.0",
            "v1.2.3-alpha.01",
            "v1.2.3-beta.1",
            "v1.2.3+other",
            "https://example.com/executable",
            "main-other",
        ] {
            assert_eq!(PublicBuild::new(&public, package), Err(Error::InvalidBuild));
        }
        assert_eq!(PublicBuild::main(&"A".repeat(40)), Err(Error::InvalidBuild));
        assert!(
            serde_json::from_str::<PublicBuild>(r#"{"revision":"bad","package":"v1.2.3"}"#)
                .is_err()
        );
    }
    fn migration(id: u128) -> Uuid {
        Uuid::from_u128(0x019a0000_0000_7000_8000_000000000000 + id)
    }

    #[test]
    fn clear_before_prepare_closes_delayed_callbacks_without_unlocking_a_different_migration() {
        let mut state = selected();
        let machine_id = Uuid::from_u128(70);
        decide(
            &mut state,
            Command::ClearMigration {
                machine_id,
                migration_id: migration(1),
                at: at(),
            },
        )
        .unwrap();
        assert_eq!(
            Command::HoldMigration {
                machine_id,
                migration_id: migration(1),
                at: at()
            }
            .handle(&state),
            Err(Error::LifecycleBlocked)
        );
        assert_eq!(
            Command::HoldMigration {
                machine_id,
                migration_id: Uuid::from_u128(1),
                at: at()
            }
            .handle(&state),
            Err(Error::InvalidAttempt)
        );
        decide(
            &mut state,
            Command::HoldMigration {
                machine_id,
                migration_id: migration(2),
                at: at(),
            },
        )
        .unwrap();
        decide(
            &mut state,
            Command::ClearMigration {
                machine_id,
                migration_id: migration(3),
                at: at(),
            },
        )
        .unwrap();
        state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(state.migration_holds.get(&machine_id), Some(&migration(2)));
        decide(
            &mut state,
            Command::ClearMigration {
                machine_id,
                migration_id: migration(2),
                at: at(),
            },
        )
        .unwrap();
        assert!(state.migration_holds.is_empty());
        assert_eq!(
            Command::HoldMigration {
                machine_id,
                migration_id: migration(3),
                at: at()
            }
            .handle(&state),
            Err(Error::LifecycleBlocked)
        );
        decide(
            &mut state,
            Command::HoldMigration {
                machine_id,
                migration_id: migration(4),
                at: at(),
            },
        )
        .unwrap();
    }
    #[test]
    fn migration_holds_outlive_drain_deadlines_and_only_the_matching_clear_unlocks_begin() {
        let (mut state, fence) = offered();
        let migration_id = migration(50);
        decide(
            &mut state,
            Command::HoldMigration {
                machine_id: fence.machine_id,
                migration_id,
                at: at(),
            },
        )
        .unwrap();
        let later = at() + chrono::Duration::seconds(121);
        let begin = Command::Begin {
            fence: fence.clone(),
            boot_id: Uuid::from_u128(20),
            provider_permit: None,
            at: later,
        };
        assert_eq!(begin.clone().handle(&state), Err(Error::LifecycleBlocked));
        decide(
            &mut state,
            Command::ClearMigration {
                machine_id: fence.machine_id,
                migration_id: migration(51),
                at: later,
            },
        )
        .unwrap();
        assert_eq!(begin.clone().handle(&state), Err(Error::LifecycleBlocked));
        decide(
            &mut state,
            Command::ClearMigration {
                machine_id: fence.machine_id,
                migration_id,
                at: later,
            },
        )
        .unwrap();
        decide(&mut state, begin).unwrap();
        assert_eq!(
            Command::HoldMigration {
                machine_id: fence.machine_id,
                migration_id,
                at: later
            }
            .handle(&state),
            Err(Error::LifecycleBlocked)
        );
    }

    fn reserve(state: &mut AgentUpdates, fence: &Fence) -> ProviderUpdateFence {
        decide(
            state,
            Command::ReserveProvider {
                fence: fence.clone(),
                provider_machine_id: "provider-machine".into(),
                controller_id: Uuid::from_u128(60),
                at: at(),
            },
        )
        .unwrap();
        state
            .active
            .as_ref()
            .unwrap()
            .provider_fence
            .clone()
            .unwrap()
    }

    #[test]
    fn cancelled_acquisition_is_durable_and_old_release_acknowledgments_cannot_clear_newer_work() {
        let (mut state, fence) = offered();
        let reservation = reserve(&mut state, &fence);
        assert_eq!(
            Command::Begin {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(20),
                provider_permit: None,
                at: at()
            }
            .handle(&state),
            Err(Error::ProviderPermitRequired)
        );
        decide(
            &mut state,
            Command::Cancel {
                fence: fence.clone(),
                at: at(),
            },
        )
        .unwrap();
        state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(state.pending_provider_release.as_ref(), Some(&reservation));
        assert_eq!(
            offer(&state, 2).handle(&state),
            Err(Error::LifecycleBlocked)
        );
        assert_eq!(
            Command::Begin {
                fence,
                boot_id: Uuid::from_u128(20),
                provider_permit: Some(reservation.clone()),
                at: at()
            }
            .handle(&state),
            Err(Error::StaleFence)
        );
        decide(
            &mut state,
            Command::AcknowledgeProviderRelease {
                reservation: reservation.clone(),
                at: at(),
            },
        )
        .unwrap();
        decide(
            &mut state,
            Command::Select {
                target: PublicBuild::main(&"c".repeat(40)).unwrap(),
                at: at(),
            },
        )
        .unwrap();
        let next = offer(&state, 2);
        decide(&mut state, next).unwrap();
        let fence = state.active.as_ref().unwrap().fence();
        let newer = reserve(&mut state, &fence);
        assert!(newer.sequence > reservation.sequence);
        decide(&mut state, Command::Cancel { fence, at: at() }).unwrap();
        assert!(
            decide(
                &mut state,
                Command::AcknowledgeProviderRelease {
                    reservation,
                    at: at()
                }
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(state.pending_provider_release, Some(newer));
    }

    #[test]
    fn uncertain_authorization_keeps_its_provider_fence_until_verified_terminal_completion() {
        for rollback in [false, true] {
            let (mut state, fence) = offered();
            let reservation = reserve(&mut state, &fence);
            decide(
                &mut state,
                Command::Begin {
                    fence: fence.clone(),
                    boot_id: Uuid::from_u128(20),
                    provider_permit: Some(reservation.clone()),
                    at: at(),
                },
            )
            .unwrap();
            decide(
                &mut state,
                Command::Fail {
                    fence: fence.clone(),
                    failure: Failure::Offline,
                    at: at() + chrono::Duration::days(1),
                },
            )
            .unwrap();
            assert!(state.pending_provider_release.is_none());
            assert_eq!(
                state.active.as_ref().unwrap().provider_fence.as_ref(),
                Some(&reservation)
            );
            assert_eq!(
                Command::Cancel {
                    fence: fence.clone(),
                    at: at()
                }
                .handle(&state),
                Err(Error::InvalidPhase)
            );
            if rollback {
                decide(
                    &mut state,
                    Command::Rollback {
                        fence,
                        boot_id: Uuid::from_u128(22),
                        at: at() + chrono::Duration::days(1),
                    },
                )
                .unwrap();
            } else {
                decide(
                    &mut state,
                    Command::Health {
                        fence: fence.clone(),
                        boot_id: Uuid::from_u128(21),
                        at: at() + chrono::Duration::days(1),
                    },
                )
                .unwrap();
                decide(
                    &mut state,
                    Command::Commit {
                        fence,
                        boot_id: Uuid::from_u128(21),
                        at: at() + chrono::Duration::days(1),
                    },
                )
                .unwrap();
            }
            state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
            assert!(state.active.is_none());
            assert_eq!(state.pending_provider_release, Some(reservation));
        }
    }
}
