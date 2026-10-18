//! Secret-free own-VM replacement decisions in the shared instance update slot.
use super::{ActiveUpdate, AgentUpdates, Error, Event};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageIdentity {
    pub kernel_sha256: String,
    pub rootfs_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub kernel_url: String,
    pub kernel_sha256: String,
    pub rootfs_url: String,
    pub rootfs_sha256: String,
}
impl Target {
    pub fn identity(&self) -> ImageIdentity {
        ImageIdentity {
            kernel_sha256: self.kernel_sha256.clone(),
            rootfs_sha256: self.rootfs_sha256.clone(),
        }
    }
    fn matches(&self, image: &ImageIdentity) -> bool {
        self.kernel_sha256 == image.kernel_sha256 && self.rootfs_sha256 == image.rootfs_sha256
    }
    fn valid(&self) -> bool {
        digest(&self.kernel_sha256)
            && digest(&self.rootfs_sha256)
            && [&self.kernel_url, &self.rootfs_url].iter().all(|url| {
                url.starts_with("https://")
                    && url.len() <= 2048
                    && !url.bytes().any(|b| {
                        b.is_ascii_whitespace() || b.is_ascii_control() || b"@?#".contains(&b)
                    })
                    && url[8..].contains('/')
            })
    }
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preparing,
    Prepared,
    Draining,
    Quiescing,
    Quiesced,
    Starting,
    CandidateRunning,
    Verifying,
    Committing,
    Committed,
    Releasing,
    Succeeded,
    RollingBack,
    RolledBack,
    Cancelling,
    Cancelled,
    Failed,
}
impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Prepared => "prepared",
            Self::Draining => "draining",
            Self::Quiescing => "quiescing",
            Self::Quiesced => "quiesced",
            Self::Starting => "starting",
            Self::CandidateRunning => "candidate_running",
            Self::Verifying => "verifying",
            Self::Committing => "committing",
            Self::Committed => "committed",
            Self::Releasing => "releasing",
            Self::Succeeded => "succeeded",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::Cancelling => "cancelling",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
    pub fn terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::RolledBack | Self::Cancelled)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Prepare,
    Quiesce,
    StartCandidate,
    Commit,
    Rollback,
    ReleaseOld,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Cancelled,
    Timeout,
    HostFailed,
    HealthFailed,
    Uncertain,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub sequence: u64,
    pub action: Action,
    pub launch_nonce: Uuid,
    pub deadline: DateTime<Utc>,
    pub document_generation: Option<i64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fence {
    pub attempt_id: Uuid,
    pub attempt_sequence: u64,
    pub vm_id: Uuid,
    pub host_machine_id: Uuid,
    pub host_registration_key: String,
    pub operation_sequence: u64,
    pub action: Action,
    pub launch_nonce: Uuid,
    pub document_generation: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub process_id: u32,
    pub start_time_ticks: u64,
    pub host_boot_id: Uuid,
}
impl ProcessIdentity {
    fn valid(&self) -> bool {
        self.process_id > 0 && self.start_time_ticks > 0 && !self.host_boot_id.is_nil()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestBootProof {
    pub guest_machine_id: Uuid,
    pub guest_registration_key: String,
    pub attempt_id: Uuid,
    pub attempt_sequence: u64,
    pub launch_sequence: u64,
    pub launch_nonce: Uuid,
    pub document_generation: i64,
    pub guest_document_generation: i64,
    pub current_guest_document_generation: i64,
    pub os_boot_id: Uuid,
    pub pid1_context: Uuid,
    pub image: ImageIdentity,
    pub runtime_ready: bool,
    pub cpu_probe: bool,
    pub memory_probe: bool,
    pub attachment_probe: bool,
    pub probe_failed: bool,
    pub observed_at: DateTime<Utc>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainProof {
    pub guest_machine_id: Uuid,
    pub guest_registration_key: String,
    pub host_registration_key: String,
    pub document_generation: i64,
    pub guest_document_generation: i64,
    pub current_guest_document_generation: i64,
    pub drained: bool,
    pub has_allocations: bool,
    pub has_local_volumes: bool,
    pub observed_at: DateTime<Utc>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: Uuid,
    pub vm_id: Uuid,
    pub organisation_id: Uuid,
    pub host_machine_id: Uuid,
    pub guest_machine_id: Uuid,
    pub host_registration_key: String,
    pub guest_registration_key: String,
    pub request_hash: String,
    pub fingerprint: String,
    pub source: ImageIdentity,
    pub target: Target,
    pub expected_update_version: i64,
    pub original_in_service: bool,
    pub old_os_boot_id: Option<Uuid>,
    pub launch_nonce: Uuid,
    pub deadline: DateTime<Utc>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmAttempt {
    pub id: Uuid,
    pub vm_id: Uuid,
    pub organisation_id: Uuid,
    pub host_machine_id: Uuid,
    pub guest_machine_id: Uuid,
    pub host_registration_key: String,
    pub guest_registration_key: String,
    pub sequence: u64,
    pub request_hash: String,
    pub fingerprint: String,
    pub source: ImageIdentity,
    pub target: Target,
    pub expected_update_version: i64,
    pub original_in_service: bool,
    pub phase: Phase,
    pub offered_at: DateTime<Utc>,
    pub authorized_at: Option<DateTime<Utc>>,
    pub deadline: DateTime<Utc>,
    pub operation: Operation,
    pub last_document_generation: i64,
    pub used_launch_nonces: [Option<Uuid>; 4],
    pub old_process: Option<ProcessIdentity>,
    pub candidate_process: Option<ProcessIdentity>,
    pub rollback_process: Option<ProcessIdentity>,
    pub old_os_boot_id: Option<Uuid>,
    pub root_fenced: bool,
    pub old_process_exited: bool,
    pub candidate_launch: Option<Operation>,
    pub guest_boot_proof: Option<GuestBootProof>,
    pub failure: Option<Failure>,
    pub committed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub committed_restart_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub committed_recovery_deadline: Option<DateTime<Utc>>,
    #[serde(default)]
    pub committed_previous_process: Option<ProcessIdentity>,
    #[serde(default)]
    pub committed_previous_boot: Option<GuestBootProof>,
    #[serde(default)]
    pub committed_health_required_after: Option<DateTime<Utc>>,
    #[serde(default)]
    pub candidate_boot_identity: Option<(Uuid, Uuid)>,
    #[serde(default)]
    pub last_guest_document_generation: i64,
    pub completed_at: Option<DateTime<Utc>>,
}
impl VmAttempt {
    pub fn fence(&self) -> Option<Fence> {
        Some(Fence {
            attempt_id: self.id,
            attempt_sequence: self.sequence,
            vm_id: self.vm_id,
            host_machine_id: self.host_machine_id,
            host_registration_key: self.host_registration_key.clone(),
            operation_sequence: self.operation.sequence,
            action: self.operation.action,
            launch_nonce: self.operation.launch_nonce,
            document_generation: self.operation.document_generation?,
        })
    }
    fn matches(&self, fence: &Fence) -> bool {
        self.id == fence.attempt_id
            && self.sequence == fence.attempt_sequence
            && self.vm_id == fence.vm_id
            && self.host_machine_id == fence.host_machine_id
            && self.host_registration_key == fence.host_registration_key
            && self.operation.sequence == fence.operation_sequence
            && self.operation.action == fence.action
            && self.operation.launch_nonce == fence.launch_nonce
            && self.operation.document_generation == Some(fence.document_generation)
    }
    pub fn can_cancel(&self) -> bool {
        self.committed_at.is_none()
            && !matches!(
                self.phase,
                Phase::Committing | Phase::RollingBack | Phase::Cancelling | Phase::Failed
            )
            && !self.phase.terminal()
    }
    fn health_since(&self) -> DateTime<Utc> {
        self.committed_health_required_after
            .unwrap_or(self.offered_at)
            .max(self.authorized_at.unwrap_or(self.offered_at))
    }
    fn healthy(&self, at: DateTime<Utc>) -> bool {
        self.candidate_process.is_some()
            && self
                .committed_recovery_deadline
                .is_none_or(|deadline| at < deadline)
            && self
                .guest_boot_proof
                .as_ref()
                .is_some_and(|proof| fresh(at, proof.observed_at, self.health_since()))
    }
    fn unavailable(&mut self, at: DateTime<Utc>, failure: Failure) {
        if let Some(proof) = self.guest_boot_proof.take()
            && (self.committed_restart_at.is_none() || self.committed_previous_boot.is_none())
        {
            self.committed_previous_boot = Some(proof);
        }
        self.committed_health_required_after =
            Some(self.committed_health_required_after.unwrap_or(at).max(at));
        self.failure = Some(failure);
    }
    fn next(&mut self, action: Action, nonce: Uuid, deadline: DateTime<Utc>) -> Result<(), Error> {
        if nonce.is_nil() || self.used_launch_nonces.contains(&Some(nonce)) {
            return Err(Error::StaleFence);
        }
        let slot = self
            .used_launch_nonces
            .iter()
            .position(Option::is_none)
            .ok_or(Error::GenerationExhausted)?;
        self.operation = Operation {
            sequence: self
                .operation
                .sequence
                .checked_add(1)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(Error::GenerationExhausted)?,
            action,
            launch_nonce: nonce,
            deadline,
            document_generation: None,
        };
        self.used_launch_nonces[slot] = Some(nonce);
        Ok(())
    }
    fn instruction(&mut self, action: Action) -> Result<(), Error> {
        self.operation.sequence = self
            .operation
            .sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::GenerationExhausted)?;
        self.operation.action = action;
        self.operation.document_generation = None;
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEvidence {
    Prepared {
        image: ImageIdentity,
        old_process: ProcessIdentity,
    },
    Quiesced {
        old_process: ProcessIdentity,
        old_process_exited: bool,
        root_fenced: bool,
    },
    CandidateRunning {
        process: ProcessIdentity,
        image: ImageIdentity,
        fresh_instance_start: bool,
    },
    Committed {
        process: Option<ProcessIdentity>,
    },
    Released,
    RolledBack {
        process: ProcessIdentity,
        image: ImageIdentity,
        candidate_exited: bool,
        root_restored: bool,
    },
    StagingCancelled {
        old_process: ProcessIdentity,
    },
    Uncertain,
}
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    Request {
        request: Request,
        at: DateTime<Utc>,
    },
    DocumentPublished {
        attempt_id: Uuid,
        operation_sequence: u64,
        generation: i64,
        at: DateTime<Utc>,
    },
    BeginDrain {
        attempt_id: Uuid,
        at: DateTime<Utc>,
    },
    AuthorizeQuiesce {
        attempt_id: Uuid,
        proof: DrainProof,
        launch_nonce: Uuid,
        deadline: DateTime<Utc>,
        at: DateTime<Utc>,
    },
    StartCandidate {
        attempt_id: Uuid,
        launch_nonce: Uuid,
        at: DateTime<Utc>,
    },
    RestartCommitted {
        attempt_id: Uuid,
        launch_nonce: Uuid,
        deadline: DateTime<Utc>,
        at: DateTime<Utc>,
    },
    HostAcknowledged {
        fence: Fence,
        evidence: HostEvidence,
        at: DateTime<Utc>,
    },
    VerifyGuest {
        attempt_id: Uuid,
        proof: GuestBootProof,
        at: DateTime<Utc>,
    },
    InvalidateGuest {
        attempt_id: Uuid,
        at: DateTime<Utc>,
    },
    Commit {
        attempt_id: Uuid,
        at: DateTime<Utc>,
    },
    ReleaseOld {
        attempt_id: Uuid,
        at: DateTime<Utc>,
    },
    Cancel {
        attempt_id: Uuid,
        launch_nonce: Uuid,
        recovery_deadline: DateTime<Utc>,
        at: DateTime<Utc>,
    },
    Fail {
        attempt_id: Uuid,
        failure: Failure,
        launch_nonce: Uuid,
        recovery_deadline: DateTime<Utc>,
        at: DateTime<Utc>,
    },
}
fn active(state: &AgentUpdates, id: Uuid, at: DateTime<Utc>) -> Result<&VmAttempt, Error> {
    let attempt = state
        .active
        .as_ref()
        .and_then(ActiveUpdate::vm)
        .filter(|a| a.id == id)
        .ok_or(Error::StaleFence)?;
    if at < attempt.offered_at {
        return Err(Error::InvalidAttempt);
    }
    Ok(attempt)
}
fn bounded(at: DateTime<Utc>, deadline: DateTime<Utc>, minutes: i64) -> bool {
    deadline > at && deadline <= at + Duration::minutes(minutes)
}
fn fresh(at: DateTime<Utc>, observed: DateTime<Utc>, since: DateTime<Utc>) -> bool {
    observed >= since && observed <= at && at - observed <= Duration::seconds(30)
}
impl mire::Command for Command {
    type Aggregate = AgentUpdates;
    type Error = Error;
    type Events = Vec<Event>;
    fn handle(self, state: &AgentUpdates) -> Result<Vec<Event>, Error> {
        if !state.initialized {
            return Err(Error::NotInitialized);
        }
        let at = match &self {
            Self::Request { at, .. }
            | Self::DocumentPublished { at, .. }
            | Self::BeginDrain { at, .. }
            | Self::AuthorizeQuiesce { at, .. }
            | Self::StartCandidate { at, .. }
            | Self::RestartCommitted { at, .. }
            | Self::HostAcknowledged { at, .. }
            | Self::VerifyGuest { at, .. }
            | Self::InvalidateGuest { at, .. }
            | Self::Commit { at, .. }
            | Self::ReleaseOld { at, .. }
            | Self::Cancel { at, .. }
            | Self::Fail { at, .. } => *at,
        };
        let mut attempt = match self {
            Self::Request { request: r, .. } => {
                if let Some(a) = state
                    .active
                    .as_ref()
                    .and_then(ActiveUpdate::vm)
                    .filter(|a| a.request_hash == r.request_hash)
                {
                    return if a.fingerprint == r.fingerprint
                        && a.organisation_id == r.organisation_id
                        && a.vm_id == r.vm_id
                    {
                        Ok(vec![])
                    } else {
                        Err(Error::RequestConflict)
                    };
                }
                if let Some(super::CompletedUpdate::Vm(a)) = &state.last_completed
                    && a.request_hash == r.request_hash
                {
                    return if a.fingerprint == r.fingerprint
                        && a.organisation_id == r.organisation_id
                        && a.vm_id == r.vm_id
                    {
                        Ok(vec![])
                    } else {
                        Err(Error::RequestConflict)
                    };
                }
                if state.active.is_some() || state.pending_provider_release.is_some() {
                    return Err(Error::SlotOccupied);
                }
                if state.paused {
                    return Err(Error::Paused);
                }
                if state.migration_holds.contains_key(&r.host_machine_id)
                    || state.migration_holds.contains_key(&r.guest_machine_id)
                {
                    return Err(Error::MigrationConflict);
                }
                if r.id.get_version_num() != 7
                    || [
                        r.vm_id,
                        r.organisation_id,
                        r.host_machine_id,
                        r.guest_machine_id,
                        r.launch_nonce,
                    ]
                    .iter()
                    .any(Uuid::is_nil)
                    || r.host_machine_id == r.guest_machine_id
                    || !digest(&r.host_registration_key)
                    || !digest(&r.guest_registration_key)
                    || !digest(&r.request_hash)
                    || !digest(&r.fingerprint)
                    || !digest(&r.source.kernel_sha256)
                    || !digest(&r.source.rootfs_sha256)
                    || !r.target.valid()
                    || r.target.matches(&r.source)
                    || r.expected_update_version < 0
                    || !bounded(at, r.deadline, 15)
                    || r.old_os_boot_id.is_some_and(|id| id.is_nil())
                {
                    return Err(Error::InvalidAttempt);
                }
                VmAttempt {
                    id: r.id,
                    vm_id: r.vm_id,
                    organisation_id: r.organisation_id,
                    host_machine_id: r.host_machine_id,
                    guest_machine_id: r.guest_machine_id,
                    host_registration_key: r.host_registration_key,
                    guest_registration_key: r.guest_registration_key,
                    sequence: state
                        .attempt_sequence
                        .checked_add(1)
                        .filter(|n| *n <= i64::MAX as u64)
                        .ok_or(Error::GenerationExhausted)?,
                    request_hash: r.request_hash,
                    fingerprint: r.fingerprint,
                    source: r.source,
                    target: r.target,
                    expected_update_version: r.expected_update_version,
                    original_in_service: r.original_in_service,
                    phase: Phase::Preparing,
                    offered_at: at,
                    authorized_at: None,
                    deadline: r.deadline,
                    operation: Operation {
                        sequence: 1,
                        action: Action::Prepare,
                        launch_nonce: r.launch_nonce,
                        deadline: r.deadline,
                        document_generation: None,
                    },
                    last_document_generation: 0,
                    used_launch_nonces: [Some(r.launch_nonce), None, None, None],
                    old_process: None,
                    candidate_process: None,
                    rollback_process: None,
                    old_os_boot_id: r.old_os_boot_id,
                    root_fenced: false,
                    old_process_exited: false,
                    candidate_launch: None,
                    guest_boot_proof: None,
                    failure: None,
                    committed_at: None,
                    completed_at: None,
                    committed_restart_at: None,
                    committed_recovery_deadline: None,
                    committed_previous_process: None,
                    committed_previous_boot: None,
                    committed_health_required_after: None,
                    candidate_boot_identity: None,
                    last_guest_document_generation: 0,
                }
            }
            Self::DocumentPublished {
                attempt_id,
                operation_sequence,
                generation,
                ..
            } => {
                let a = active(state, attempt_id, at)?;
                if a.operation.sequence != operation_sequence {
                    return Err(Error::StaleFence);
                }
                if a.operation.document_generation == Some(generation) {
                    return Ok(vec![]);
                }
                if generation <= a.last_document_generation {
                    return Err(Error::StaleFence);
                }
                let mut a = a.clone();
                a.last_document_generation = generation;
                a.operation.document_generation = Some(generation);
                if a.operation.action == Action::StartCandidate && a.candidate_launch.is_none() {
                    a.candidate_launch = Some(a.operation.clone());
                }
                return Ok(vec![Event::VmDocumentPublished { attempt: a, at }]);
            }
            Self::BeginDrain { attempt_id, .. } => {
                let a = active(state, attempt_id, at)?;
                if a.phase == Phase::Draining {
                    return Ok(vec![]);
                }
                if state.paused {
                    return Err(Error::Paused);
                }
                if a.phase != Phase::Prepared {
                    return Err(Error::InvalidPhase);
                }
                if at >= a.deadline {
                    return Err(Error::Expired);
                }
                let mut a = a.clone();
                a.phase = Phase::Draining;
                a
            }
            Self::AuthorizeQuiesce {
                attempt_id,
                proof,
                launch_nonce,
                deadline,
                ..
            } => {
                let a = active(state, attempt_id, at)?;
                if state.paused {
                    return Err(Error::Paused);
                }
                if state.migration_holds.contains_key(&a.host_machine_id)
                    || state.migration_holds.contains_key(&a.guest_machine_id)
                {
                    return Err(Error::MigrationConflict);
                }
                if a.phase != Phase::Draining {
                    return Err(Error::InvalidPhase);
                }
                if at >= a.deadline || !bounded(at, deadline, 15) {
                    return Err(Error::Expired);
                }
                if !proof.drained
                    || proof.has_allocations
                    || proof.has_local_volumes
                    || proof.guest_machine_id != a.guest_machine_id
                    || proof.guest_registration_key != a.guest_registration_key
                    || proof.host_registration_key != a.host_registration_key
                    || proof.guest_document_generation <= 0
                    || proof.guest_document_generation != proof.current_guest_document_generation
                    || Some(proof.document_generation) != a.operation.document_generation
                    || !fresh(at, proof.observed_at, a.offered_at)
                {
                    return Err(Error::UnsafeVm);
                }
                let mut a = a.clone();
                a.last_guest_document_generation = proof.guest_document_generation;
                a.authorized_at = Some(at);
                a.deadline = deadline;
                a.next(Action::Quiesce, launch_nonce, deadline)?;
                a.phase = Phase::Quiescing;
                a
            }
            Self::StartCandidate {
                attempt_id,
                launch_nonce,
                ..
            } => {
                let a = active(state, attempt_id, at)?;
                if a.phase != Phase::Quiesced || !a.root_fenced || !a.old_process_exited {
                    return Err(Error::InvalidPhase);
                }
                if at >= a.deadline {
                    return Err(Error::Expired);
                }
                let mut a = a.clone();
                a.next(Action::StartCandidate, launch_nonce, a.deadline)?;
                a.phase = Phase::Starting;
                a
            }
            Self::RestartCommitted {
                attempt_id,
                launch_nonce,
                deadline,
                ..
            } => {
                let a = active(state, attempt_id, at)?;
                if a.committed_at.is_none() {
                    return Err(Error::InvalidPhase);
                }
                if a.committed_restart_at.is_some() {
                    return if a.operation.launch_nonce == launch_nonce
                        && a.committed_recovery_deadline == Some(deadline)
                    {
                        Ok(vec![])
                    } else {
                        Err(Error::InvalidPhase)
                    };
                }
                if !matches!(a.phase, Phase::Committed | Phase::Releasing)
                    || !bounded(at, deadline, 5)
                {
                    return Err(Error::InvalidPhase);
                }
                if launch_nonce.is_nil() || a.used_launch_nonces.contains(&Some(launch_nonce)) {
                    return Err(Error::StaleFence);
                }
                let mut a = a.clone();
                a.committed_previous_process = a.candidate_process.take();
                a.unavailable(at, Failure::HostFailed);
                a.next(Action::StartCandidate, launch_nonce, deadline)?;
                a.committed_restart_at = Some(at);
                a.committed_recovery_deadline = Some(deadline);
                a.candidate_launch = None;
                a.candidate_boot_identity = None;
                a.phase = Phase::Starting;
                return Ok(vec![Event::VmRecoveryRequested { attempt: a, at }]);
            }
            Self::HostAcknowledged {
                fence, evidence, ..
            } => {
                if let Some(super::CompletedUpdate::Vm(a)) = &state.last_completed
                    && a.matches(&fence)
                {
                    let replay = match &evidence {
                        HostEvidence::Released => a.phase == Phase::Succeeded,
                        HostEvidence::StagingCancelled { old_process } => {
                            a.phase == Phase::Cancelled
                                && a.old_process.as_ref() == Some(old_process)
                        }
                        HostEvidence::RolledBack {
                            process,
                            image,
                            candidate_exited,
                            root_restored,
                        } => {
                            a.phase == Phase::RolledBack
                                && a.rollback_process.as_ref() == Some(process)
                                && *image == a.source
                                && *candidate_exited
                                && *root_restored
                        }
                        _ => false,
                    };
                    if replay {
                        return Ok(vec![]);
                    }
                }
                let a = active(state, fence.attempt_id, at)?;
                if !a.matches(&fence) {
                    return Err(Error::StaleFence);
                }
                if at >= a.operation.deadline
                    && !matches!(
                        a.operation.action,
                        Action::Commit | Action::ReleaseOld | Action::Rollback
                    )
                    && !matches!(evidence, HostEvidence::Uncertain)
                {
                    return Err(Error::Expired);
                }
                match evidence {
                    HostEvidence::Prepared { image, old_process } => {
                        if a.phase == Phase::Prepared
                            && a.old_process.as_ref() == Some(&old_process)
                            && a.target.matches(&image)
                        {
                            return Ok(vec![]);
                        }
                        if a.phase != Phase::Preparing
                            || !a.target.matches(&image)
                            || !old_process.valid()
                        {
                            return Err(Error::UnsafeVm);
                        }
                        let mut a = a.clone();
                        a.old_process = Some(old_process);
                        a.phase = Phase::Prepared;
                        a
                    }
                    HostEvidence::Quiesced {
                        old_process,
                        old_process_exited,
                        root_fenced,
                    } => {
                        if a.phase == Phase::Quiesced
                            && a.old_process.as_ref() == Some(&old_process)
                            && old_process_exited
                            && root_fenced
                        {
                            return Ok(vec![]);
                        }
                        if a.phase != Phase::Quiescing
                            || a.old_process.as_ref() != Some(&old_process)
                            || !old_process_exited
                            || !root_fenced
                        {
                            return Err(Error::UnsafeVm);
                        }
                        let mut a = a.clone();
                        a.old_process_exited = true;
                        a.root_fenced = true;
                        a.phase = Phase::Quiesced;
                        a
                    }
                    HostEvidence::CandidateRunning {
                        process,
                        image,
                        fresh_instance_start,
                    } => {
                        if a.phase == Phase::CandidateRunning
                            && a.candidate_process.as_ref() == Some(&process)
                            && a.target.matches(&image)
                            && fresh_instance_start
                        {
                            return Ok(vec![]);
                        }
                        if a.phase != Phase::Starting
                            || !process.valid()
                            || a.old_process.as_ref() == Some(&process)
                            || a.committed_previous_process.as_ref() == Some(&process)
                            || !a.target.matches(&image)
                            || !fresh_instance_start
                            || !a.root_fenced
                            || !a.old_process_exited
                        {
                            return Err(Error::UnsafeVm);
                        }
                        let mut a = a.clone();
                        a.candidate_process = Some(process);
                        a.phase = Phase::CandidateRunning;
                        a
                    }
                    HostEvidence::Committed { process } => {
                        if a.operation.action != Action::Commit {
                            return Err(Error::InvalidPhase);
                        }
                        if a.committed_at.is_some() && a.phase == Phase::Committed {
                            if process.is_none() {
                                if a.failure.is_some() && a.guest_boot_proof.is_none() {
                                    return Ok(vec![]);
                                }
                                let mut a = a.clone();
                                a.unavailable(at, Failure::HostFailed);
                                return Ok(vec![Event::VmUncertain { attempt: a, at }]);
                            }
                            return if process
                                .as_ref()
                                .is_some_and(|p| a.candidate_process.as_ref() == Some(p))
                            {
                                Ok(vec![])
                            } else {
                                Err(Error::UnsafeVm)
                            };
                        }
                        if a.phase != Phase::Committing
                            || process
                                .as_ref()
                                .is_some_and(|p| a.candidate_process.as_ref() != Some(p))
                        {
                            return Err(Error::UnsafeVm);
                        }
                        let mut a = a.clone();
                        a.committed_at = Some(at);
                        a.phase = Phase::Committed;
                        if process.is_none() {
                            a.unavailable(at, Failure::HostFailed);
                        }
                        return Ok(vec![Event::VmCommitConfirmed { attempt: a, at }]);
                    }
                    HostEvidence::Released => {
                        if a.phase != Phase::Releasing || a.committed_at.is_none() {
                            return Err(Error::InvalidPhase);
                        }
                        if !a.healthy(at) {
                            if a.failure == Some(Failure::Uncertain) && a.guest_boot_proof.is_none()
                            {
                                return Ok(vec![]);
                            }
                            let mut a = a.clone();
                            a.unavailable(at, Failure::Uncertain);
                            return Ok(vec![Event::VmUncertain { attempt: a, at }]);
                        }
                        let mut a = a.clone();
                        a.phase = Phase::Succeeded;
                        a.completed_at = Some(at);
                        return Ok(vec![Event::VmCompleted { attempt: a, at }]);
                    }
                    HostEvidence::RolledBack {
                        process,
                        image,
                        candidate_exited,
                        root_restored,
                    } => {
                        if a.phase != Phase::RollingBack
                            || a.committed_at.is_some()
                            || !process.valid()
                            || a.old_process.as_ref() == Some(&process)
                            || a.candidate_process.as_ref() == Some(&process)
                            || image != a.source
                            || !candidate_exited
                            || !root_restored
                        {
                            return Err(Error::UnsafeVm);
                        }
                        let mut a = a.clone();
                        a.rollback_process = Some(process);
                        a.phase = Phase::RolledBack;
                        a.completed_at = Some(at);
                        return Ok(vec![Event::VmCompleted { attempt: a, at }]);
                    }
                    HostEvidence::StagingCancelled { old_process } => {
                        if a.phase != Phase::Cancelling
                            || a.authorized_at.is_some()
                            || a.old_process
                                .as_ref()
                                .is_some_and(|old| *old != old_process)
                            || !old_process.valid()
                        {
                            return Err(Error::UnsafeVm);
                        }
                        let mut a = a.clone();
                        a.old_process = Some(old_process);
                        a.phase = Phase::Cancelled;
                        a.completed_at = Some(at);
                        return Ok(vec![Event::VmCompleted { attempt: a, at }]);
                    }
                    HostEvidence::Uncertain => {
                        if a.failure == Some(Failure::Uncertain)
                            && (a.committed_at.is_none() || a.guest_boot_proof.is_none())
                        {
                            return Ok(vec![]);
                        }
                        let mut a = a.clone();
                        if a.committed_at.is_some() {
                            a.unavailable(at, Failure::Uncertain);
                        } else {
                            a.failure = Some(Failure::Uncertain);
                        }
                        return Ok(vec![Event::VmUncertain { attempt: a, at }]);
                    }
                }
            }
            Self::InvalidateGuest { attempt_id, .. } => {
                let a = active(state, attempt_id, at)?;
                if a.guest_boot_proof.is_none() {
                    return Ok(vec![]);
                }
                let mut a = a.clone();
                a.guest_boot_proof = None;
                a
            }
            Self::VerifyGuest {
                attempt_id, proof, ..
            } => {
                let a = active(state, attempt_id, at)?;
                if a.guest_boot_proof.as_ref() == Some(&proof) {
                    return Ok(vec![]);
                }
                let committed_observation = a.committed_at.is_some()
                    && matches!(a.phase, Phase::Committed | Phase::Releasing);
                let deadline = if a.committed_at.is_some() {
                    a.committed_recovery_deadline
                } else {
                    Some(a.deadline)
                };
                if (!matches!(a.phase, Phase::CandidateRunning | Phase::Verifying)
                    && !committed_observation)
                    || deadline.is_some_and(|deadline| at >= deadline)
                {
                    return Err(Error::InvalidPhase);
                }
                let launch = a.candidate_launch.as_ref().ok_or(Error::StaleFence)?;
                if proof.guest_machine_id != a.guest_machine_id
                    || proof.guest_registration_key != a.guest_registration_key
                    || proof.attempt_id != a.id
                    || proof.attempt_sequence != a.sequence
                    || proof.launch_sequence != launch.sequence
                    || proof.launch_nonce != launch.launch_nonce
                    || Some(proof.document_generation) != launch.document_generation
                    || proof.guest_document_generation <= 0
                    || proof.guest_document_generation != proof.current_guest_document_generation
                    || proof.guest_document_generation < a.last_guest_document_generation
                    || a.candidate_boot_identity
                        .is_some_and(|identity| identity != (proof.os_boot_id, proof.pid1_context))
                    || a.guest_boot_proof.as_ref().is_some_and(|old| {
                        proof.observed_at < old.observed_at
                            || proof.guest_document_generation < old.guest_document_generation
                            || proof.os_boot_id != old.os_boot_id
                            || proof.pid1_context != old.pid1_context
                    })
                    || (a.committed_restart_at.is_some()
                        && a.committed_previous_boot.as_ref().is_some_and(|old| {
                            proof.os_boot_id == old.os_boot_id
                                || proof.pid1_context == old.pid1_context
                        }))
                    || proof.os_boot_id.is_nil()
                    || proof.pid1_context.is_nil()
                    || a.old_os_boot_id == Some(proof.os_boot_id)
                    || !a.target.matches(&proof.image)
                    || !proof.runtime_ready
                    || !proof.cpu_probe
                    || !proof.memory_probe
                    || !proof.attachment_probe
                    || proof.probe_failed
                    || !fresh(at, proof.observed_at, a.health_since())
                    || !a.old_process_exited
                    || a.candidate_process.is_none()
                {
                    return Err(Error::UnsafeVm);
                }
                let mut a = a.clone();
                a.candidate_boot_identity = Some((proof.os_boot_id, proof.pid1_context));
                a.last_guest_document_generation = proof.guest_document_generation;
                a.guest_boot_proof = Some(proof);
                a.phase = if a.committed_at.is_some() {
                    if a.phase == Phase::Releasing {
                        Phase::Releasing
                    } else {
                        Phase::Committed
                    }
                } else {
                    Phase::Verifying
                };
                a
            }
            Self::Commit { attempt_id, .. } => {
                let a = active(state, attempt_id, at)?;
                if a.committed_at.is_some() {
                    return Err(Error::Irreversible);
                }
                if a.phase == Phase::Committing {
                    return Ok(vec![]);
                }
                if a.phase != Phase::Verifying || a.guest_boot_proof.is_none() || at >= a.deadline {
                    return Err(Error::InvalidPhase);
                }
                if !a.guest_boot_proof.as_ref().is_some_and(|proof| {
                    fresh(
                        at,
                        proof.observed_at,
                        a.authorized_at.unwrap_or(a.offered_at),
                    )
                }) {
                    return Err(Error::UnsafeVm);
                }
                let mut a = a.clone();
                a.instruction(Action::Commit)?;
                a.phase = Phase::Committing;
                a
            }
            Self::ReleaseOld { attempt_id, .. } => {
                let a = active(state, attempt_id, at)?;
                if a.phase == Phase::Releasing {
                    return Ok(vec![]);
                }
                if a.phase != Phase::Committed || a.committed_at.is_none() {
                    return Err(Error::InvalidPhase);
                }
                if !a.healthy(at) {
                    return Err(Error::UnsafeVm);
                }
                let mut a = a.clone();
                a.instruction(Action::ReleaseOld)?;
                a.phase = Phase::Releasing;
                a
            }
            Self::Cancel {
                attempt_id,
                launch_nonce,
                recovery_deadline,
                ..
            }
            | Self::Fail {
                attempt_id,
                launch_nonce,
                recovery_deadline,
                failure: Failure::Cancelled,
                ..
            } => {
                let a = active(state, attempt_id, at)?;
                return rollback(a, Failure::Cancelled, launch_nonce, recovery_deadline, at);
            }
            Self::Fail {
                attempt_id,
                failure,
                launch_nonce,
                recovery_deadline,
                ..
            } => {
                let a = active(state, attempt_id, at)?;
                if failure == Failure::Timeout && at < a.operation.deadline {
                    return Err(Error::InvalidAttempt);
                }
                if a.committed_at.is_some()
                    || failure == Failure::Uncertain
                    || matches!(a.operation.action, Action::Commit | Action::ReleaseOld)
                    || (failure == Failure::Timeout
                        && matches!(a.phase, Phase::RollingBack | Phase::Cancelling))
                {
                    if a.failure == Some(Failure::Uncertain)
                        && (a.committed_at.is_none() || a.guest_boot_proof.is_none())
                    {
                        return Ok(vec![]);
                    }
                    let mut a = a.clone();
                    if a.committed_at.is_some() {
                        a.unavailable(at, Failure::Uncertain);
                    } else {
                        a.failure = Some(Failure::Uncertain);
                    }
                    return Ok(vec![Event::VmUncertain { attempt: a, at }]);
                }
                return rollback(a, failure, launch_nonce, recovery_deadline, at);
            }
        };
        attempt.completed_at = None;
        Ok(vec![Event::VmTransitioned { attempt, at }])
    }
}
fn rollback(
    a: &VmAttempt,
    failure: Failure,
    nonce: Uuid,
    deadline: DateTime<Utc>,
    at: DateTime<Utc>,
) -> Result<Vec<Event>, Error> {
    if a.committed_at.is_some() || matches!(a.operation.action, Action::Commit | Action::ReleaseOld)
    {
        return Err(Error::Irreversible);
    }
    if matches!(a.phase, Phase::RollingBack | Phase::Cancelling) {
        return if a.operation.launch_nonce == nonce && a.operation.deadline == deadline {
            Ok(vec![])
        } else {
            Err(Error::StaleFence)
        };
    }
    if !bounded(at, deadline, 5) {
        return Err(Error::InvalidAttempt);
    }
    if nonce.is_nil() || a.used_launch_nonces.contains(&Some(nonce)) {
        return Err(Error::StaleFence);
    }
    let mut a = a.clone();
    a.next(Action::Rollback, nonce, deadline)?;
    a.failure = Some(failure);
    a.phase = if a.authorized_at.is_some() {
        Phase::RollingBack
    } else {
        Phase::Cancelling
    };
    Ok(vec![Event::VmRecoveryRequested { attempt: a, at }])
}

#[cfg(test)]
mod tests {
    use super::*;
    use mire::{Aggregate as _, Command as _};

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }
    fn id(n: u128) -> Uuid {
        Uuid::from_u128(0x00000000_0000_7000_8000_000000000000 + n)
    }
    fn request() -> Request {
        Request {
            id: id(1),
            vm_id: id(2),
            organisation_id: id(3),
            host_machine_id: id(4),
            guest_machine_id: id(5),
            host_registration_key: "a".repeat(64),
            guest_registration_key: "b".repeat(64),
            request_hash: "c".repeat(64),
            fingerprint: "d".repeat(64),
            source: ImageIdentity {
                kernel_sha256: "e".repeat(64),
                rootfs_sha256: "f".repeat(64),
            },
            target: Target {
                kernel_url: "https://artifacts.example/kernel".into(),
                kernel_sha256: "1".repeat(64),
                rootfs_url: "https://artifacts.example/root".into(),
                rootfs_sha256: "2".repeat(64),
            },
            expected_update_version: 0,
            original_in_service: true,
            old_os_boot_id: Some(id(6)),
            launch_nonce: id(7),
            deadline: at() + Duration::minutes(10),
        }
    }
    fn apply(state: &mut AgentUpdates, command: Command) -> Vec<Event> {
        let events = command.handle(state).unwrap();
        for event in &events {
            state.apply(event);
        }
        events
    }
    fn vm(state: &AgentUpdates) -> &VmAttempt {
        state.active.as_ref().and_then(ActiveUpdate::vm).unwrap()
    }
    fn process(n: u32) -> ProcessIdentity {
        ProcessIdentity {
            process_id: n,
            start_time_ticks: u64::from(n) * 100,
            host_boot_id: id(8),
        }
    }
    fn publish(state: &mut AgentUpdates) {
        let a = vm(state);
        let command = Command::DocumentPublished {
            attempt_id: a.id,
            operation_sequence: a.operation.sequence,
            generation: a.last_document_generation + 1,
            at: at(),
        };
        apply(state, command);
    }
    fn ack(state: &mut AgentUpdates, evidence: HostEvidence) -> Vec<Event> {
        let command = Command::HostAcknowledged {
            fence: vm(state).fence().unwrap(),
            evidence,
            at: at(),
        };
        apply(state, command)
    }
    fn prepared() -> AgentUpdates {
        let mut state = AgentUpdates {
            initialized: true,
            ..Default::default()
        };
        apply(
            &mut state,
            Command::Request {
                request: request(),
                at: at(),
            },
        );
        publish(&mut state);
        ack(
            &mut state,
            HostEvidence::Prepared {
                image: request().target.identity(),
                old_process: process(10),
            },
        );
        state
    }
    fn drain() -> DrainProof {
        DrainProof {
            guest_machine_id: id(5),
            guest_registration_key: "b".repeat(64),
            host_registration_key: "a".repeat(64),
            document_generation: 1,
            guest_document_generation: 1,
            current_guest_document_generation: 1,
            drained: true,
            has_allocations: false,
            has_local_volumes: false,
            observed_at: at(),
        }
    }
    fn quiesce() -> Command {
        Command::AuthorizeQuiesce {
            attempt_id: id(1),
            proof: drain(),
            launch_nonce: id(9),
            deadline: at() + Duration::minutes(5),
            at: at(),
        }
    }
    fn authorized() -> AgentUpdates {
        let mut state = prepared();
        apply(
            &mut state,
            Command::BeginDrain {
                attempt_id: id(1),
                at: at(),
            },
        );
        apply(&mut state, quiesce());
        publish(&mut state);
        state
    }
    fn candidate() -> AgentUpdates {
        let mut state = authorized();
        ack(
            &mut state,
            HostEvidence::Quiesced {
                old_process: process(10),
                old_process_exited: true,
                root_fenced: true,
            },
        );
        apply(
            &mut state,
            Command::StartCandidate {
                attempt_id: id(1),
                launch_nonce: id(11),
                at: at(),
            },
        );
        publish(&mut state);
        ack(
            &mut state,
            HostEvidence::CandidateRunning {
                process: process(11),
                image: request().target.identity(),
                fresh_instance_start: true,
            },
        );
        state
    }
    fn boot() -> GuestBootProof {
        GuestBootProof {
            guest_machine_id: id(5),
            guest_registration_key: "b".repeat(64),
            attempt_id: id(1),
            attempt_sequence: 1,
            launch_sequence: 3,
            launch_nonce: id(11),
            document_generation: 3,
            os_boot_id: id(12),
            pid1_context: id(13),
            guest_document_generation: 1,
            current_guest_document_generation: 1,
            image: request().target.identity(),
            runtime_ready: true,
            cpu_probe: true,
            memory_probe: true,
            attachment_probe: true,
            probe_failed: false,
            observed_at: at(),
        }
    }
    fn verified() -> AgentUpdates {
        let mut state = candidate();
        apply(
            &mut state,
            Command::VerifyGuest {
                attempt_id: id(1),
                proof: boot(),
                at: at(),
            },
        );
        state
    }
    fn cancel(at: DateTime<Utc>) -> Command {
        Command::Cancel {
            attempt_id: id(1),
            launch_nonce: id(20),
            recovery_deadline: at + Duration::minutes(2),
            at,
        }
    }

    #[test]
    fn executable_vm_and_pending_provider_release_share_one_slot() {
        let state = prepared();
        let mut other = request();
        other.id = id(100);
        other.request_hash = "3".repeat(64);
        assert_eq!(
            Command::Request {
                request: other.clone(),
                at: at()
            }
            .handle(&state),
            Err(Error::SlotOccupied)
        );
        assert_eq!(
            super::super::Command::Offer {
                attempt_id: id(100),
                machine_id: id(101),
                registration_key: "a".repeat(64),
                generation: 0,
                previous_revision: "a".repeat(40),
                at: at(),
                expires_at: at() + Duration::minutes(1)
            }
            .handle(&state),
            Err(Error::SlotOccupied)
        );
        let mut state = AgentUpdates {
            initialized: true,
            ..Default::default()
        };
        state.pending_provider_release = Some(super::super::ProviderUpdateFence {
            provider_machine_id: "provider".into(),
            controller_id: id(30),
            attempt_id: id(31),
            sequence: 1,
        });
        assert_eq!(
            Command::Request {
                request: other,
                at: at()
            }
            .handle(&state),
            Err(Error::SlotOccupied)
        );
    }

    #[test]
    fn no_stale_registration_nonce_sequence_or_document_can_quiesce_the_vm() {
        let state = authorized();
        let original = vm(&state).fence().unwrap();
        let mut stale = Vec::new();
        let mut f = original.clone();
        f.host_registration_key = "9".repeat(64);
        stale.push(f);
        let mut f = original.clone();
        f.launch_nonce = id(100);
        stale.push(f);
        let mut f = original.clone();
        f.operation_sequence -= 1;
        stale.push(f);
        let mut f = original.clone();
        f.document_generation -= 1;
        stale.push(f);
        let mut f = original.clone();
        f.attempt_sequence += 1;
        stale.push(f);
        for fence in stale {
            assert_eq!(
                Command::HostAcknowledged {
                    fence,
                    evidence: HostEvidence::Quiesced {
                        old_process: process(10),
                        old_process_exited: true,
                        root_fenced: true
                    },
                    at: at()
                }
                .handle(&state),
                Err(Error::StaleFence)
            );
        }
        assert_eq!(vm(&state).phase, Phase::Quiescing);
    }

    #[test]
    fn pause_migration_hold_and_retained_data_cannot_authorize_quiesce() {
        let mut state = prepared();
        apply(
            &mut state,
            Command::BeginDrain {
                attempt_id: id(1),
                at: at(),
            },
        );
        state.paused = true;
        assert_eq!(quiesce().handle(&state), Err(Error::Paused));
        state.paused = false;
        state.migration_holds.insert(id(4), id(100));
        assert_eq!(quiesce().handle(&state), Err(Error::MigrationConflict));
        state.migration_holds.clear();
        for (local, allocated, drained) in [
            (true, false, true),
            (false, true, true),
            (false, false, false),
        ] {
            let mut proof = drain();
            proof.has_local_volumes = local;
            proof.has_allocations = allocated;
            proof.drained = drained;
            assert_eq!(
                Command::AuthorizeQuiesce {
                    attempt_id: id(1),
                    proof,
                    launch_nonce: id(9),
                    deadline: at() + Duration::minutes(5),
                    at: at()
                }
                .handle(&state),
                Err(Error::UnsafeVm)
            );
        }
        assert!(vm(&state).authorized_at.is_none());
    }

    #[test]
    fn image_echo_and_partial_or_stale_guest_health_are_not_boot_proof() {
        let mut state = authorized();
        ack(
            &mut state,
            HostEvidence::Quiesced {
                old_process: process(10),
                old_process_exited: true,
                root_fenced: true,
            },
        );
        apply(
            &mut state,
            Command::StartCandidate {
                attempt_id: id(1),
                launch_nonce: id(11),
                at: at(),
            },
        );
        publish(&mut state);
        for (process, fresh) in [(process(10), true), (process(11), false)] {
            assert_eq!(
                Command::HostAcknowledged {
                    fence: vm(&state).fence().unwrap(),
                    evidence: HostEvidence::CandidateRunning {
                        process,
                        image: request().target.identity(),
                        fresh_instance_start: fresh
                    },
                    at: at()
                }
                .handle(&state),
                Err(Error::UnsafeVm)
            );
        }
        ack(
            &mut state,
            HostEvidence::CandidateRunning {
                process: process(11),
                image: request().target.identity(),
                fresh_instance_start: true,
            },
        );
        let mut bad = Vec::new();
        let mut p = boot();
        p.memory_probe = false;
        bad.push(p);
        let mut p = boot();
        p.probe_failed = true;
        bad.push(p);
        let mut p = boot();
        p.os_boot_id = id(6);
        bad.push(p);
        let mut p = boot();
        p.pid1_context = Uuid::nil();
        bad.push(p);
        let mut p = boot();
        p.guest_registration_key = "9".repeat(64);
        bad.push(p);
        let mut p = boot();
        p.launch_nonce = id(100);
        bad.push(p);
        let mut p = boot();
        p.document_generation -= 1;
        bad.push(p);
        for proof in bad {
            assert_eq!(
                Command::VerifyGuest {
                    attempt_id: id(1),
                    proof,
                    at: at()
                }
                .handle(&state),
                Err(Error::UnsafeVm)
            );
        }
        assert!(vm(&state).guest_boot_proof.is_none());
    }

    #[test]
    fn timeout_requires_a_fresh_rollback_launch_and_positive_baseline_without_invented_health() {
        let mut state = candidate();
        let late = at() + Duration::minutes(5);
        let mut invalid = cancel(late);
        if let Command::Cancel { launch_nonce, .. } = &mut invalid {
            *launch_nonce = id(11);
        }
        assert_eq!(invalid.handle(&state), Err(Error::StaleFence));
        apply(
            &mut state,
            Command::Fail {
                attempt_id: id(1),
                failure: Failure::Timeout,
                launch_nonce: id(20),
                recovery_deadline: late + Duration::minutes(2),
                at: late,
            },
        );
        assert!(state.paused);
        assert_eq!(vm(&state).phase, Phase::RollingBack);
        let before = state.clone();
        let events = Command::DocumentPublished {
            attempt_id: id(1),
            operation_sequence: 4,
            generation: 4,
            at: late,
        }
        .handle(&state)
        .unwrap();
        for event in &events {
            state.apply(event);
        }
        let mut snapshot: AgentUpdates =
            serde_json::from_slice(&serde_json::to_vec(&before).unwrap()).unwrap();
        for event in &events {
            snapshot.apply(event);
        }
        assert_eq!(snapshot, state);
        let fence = vm(&state).fence().unwrap();
        let command = Command::HostAcknowledged {
            fence,
            evidence: HostEvidence::RolledBack {
                process: process(20),
                image: request().source,
                candidate_exited: true,
                root_restored: true,
            },
            at: late,
        };
        apply(&mut state, command.clone());
        assert!(state.active.is_none());
        assert!(state.paused);
        let Some(super::super::CompletedUpdate::Vm(receipt)) = &state.last_completed else {
            panic!()
        };
        assert_eq!(receipt.rollback_process, Some(process(20)));
        assert!(receipt.guest_boot_proof.is_none());
        assert!(command.handle(&state).unwrap().is_empty());
    }

    #[test]
    fn commit_is_irreversible_and_only_matching_release_acknowledgment_frees_the_slot() {
        let mut state = verified();
        apply(
            &mut state,
            Command::Commit {
                attempt_id: id(1),
                at: at(),
            },
        );
        assert_eq!(cancel(at()).handle(&state), Err(Error::Irreversible));
        publish(&mut state);
        ack(&mut state, HostEvidence::Uncertain);
        assert!(state.paused);
        assert_eq!(cancel(at()).handle(&state), Err(Error::Irreversible));
        let confirmed = ack(
            &mut state,
            HostEvidence::Committed {
                process: Some(process(11)),
            },
        );
        assert!(matches!(&confirmed[..], [Event::VmCommitConfirmed { .. }]));
        assert!(state.active.is_some());
        assert_eq!(cancel(at()).handle(&state), Err(Error::Irreversible));
        apply(
            &mut state,
            Command::ReleaseOld {
                attempt_id: id(1),
                at: at(),
            },
        );
        assert!(state.active.is_some());
        let launch = vm(&state).candidate_launch.as_ref().unwrap();
        assert_eq!(launch.sequence, 3);
        assert_eq!(launch.launch_nonce, id(11));
        publish(&mut state);
        let release = Command::HostAcknowledged {
            fence: vm(&state).fence().unwrap(),
            evidence: HostEvidence::Released,
            at: at(),
        };
        apply(&mut state, release.clone());
        assert!(state.active.is_none());
        assert!(release.handle(&state).unwrap().is_empty());
    }

    #[test]
    fn scoped_requests_replay_the_original_attempt_and_conflict_on_changed_input() {
        let mut state = prepared();
        let mut replay = request();
        replay.id = id(100);
        assert!(
            Command::Request {
                request: replay.clone(),
                at: at()
            }
            .handle(&state)
            .unwrap()
            .is_empty()
        );
        replay.fingerprint = "9".repeat(64);
        assert_eq!(
            Command::Request {
                request: replay.clone(),
                at: at()
            }
            .handle(&state),
            Err(Error::RequestConflict)
        );
        replay = request();
        replay.organisation_id = id(100);
        assert_eq!(
            Command::Request {
                request: replay.clone(),
                at: at()
            }
            .handle(&state),
            Err(Error::RequestConflict)
        );
        replay.request_hash = "8".repeat(64);
        assert_eq!(
            Command::Request {
                request: replay,
                at: at()
            }
            .handle(&state),
            Err(Error::SlotOccupied)
        );
        apply(&mut state, cancel(at()));
        publish(&mut state);
        ack(
            &mut state,
            HostEvidence::StagingCancelled {
                old_process: process(10),
            },
        );
        assert!(
            Command::Request {
                request: request(),
                at: at()
            }
            .handle(&state)
            .unwrap()
            .is_empty()
        );
        assert!(state.active.is_none());
    }

    #[test]
    fn republishing_does_not_extend_deadlines_or_accept_an_older_document() {
        let mut state = authorized();
        let deadline = vm(&state).deadline;
        publish(&mut state);
        assert_eq!(vm(&state).deadline, deadline);
        assert_eq!(vm(&state).operation.deadline, deadline);
        assert_eq!(
            Command::DocumentPublished {
                attempt_id: id(1),
                operation_sequence: 2,
                generation: 2,
                at: at()
            }
            .handle(&state),
            Err(Error::StaleFence)
        );
        assert_eq!(
            Command::DocumentPublished {
                attempt_id: id(1),
                operation_sequence: 1,
                generation: 100,
                at: at()
            }
            .handle(&state),
            Err(Error::StaleFence)
        );
    }

    #[test]
    fn executable_history_stays_readable_and_also_excludes_vm_requests() {
        use super::super::{Command as BinaryCommand, PublicBuild};
        let mut state = AgentUpdates {
            initialized: true,
            ..Default::default()
        };
        for command in [
            BinaryCommand::Select {
                target: PublicBuild::main(&"a".repeat(40)).unwrap(),
                at: at(),
            },
            BinaryCommand::Offer {
                attempt_id: id(100),
                machine_id: id(101),
                registration_key: "a".repeat(64),
                generation: 1,
                previous_revision: "b".repeat(40),
                at: at(),
                expires_at: at() + Duration::minutes(2),
            },
        ] {
            for event in command.handle(&state).unwrap() {
                state.apply(&event);
            }
        }
        let attempt = state
            .active
            .as_ref()
            .and_then(ActiveUpdate::executable)
            .unwrap();
        let historical = serde_json::to_value(attempt).unwrap();
        assert_eq!(
            serde_json::to_value(state.active.as_ref().unwrap()).unwrap(),
            historical
        );
        let decoded: ActiveUpdate = serde_json::from_value(historical).unwrap();
        assert_eq!(decoded.executable(), Some(attempt));
        assert_eq!(
            Command::Request {
                request: request(),
                at: at()
            }
            .handle(&state),
            Err(Error::SlotOccupied)
        );
    }

    #[test]
    fn migration_preparation_conflict_is_not_an_authorized_update_veto() {
        let state = prepared();
        for machine_id in [id(4), id(5)] {
            let hold = super::super::Command::HoldMigration {
                machine_id,
                migration_id: id(100),
                at: at(),
            };
            assert_eq!(hold.clone().handle(&state), Err(Error::VmUpdateConflict));
            assert_eq!(hold.handle(&authorized()), Err(Error::LifecycleBlocked));
        }
    }

    #[test]
    fn a_guest_drain_report_from_an_older_desired_generation_is_not_authorization() {
        let mut state = prepared();
        apply(
            &mut state,
            Command::BeginDrain {
                attempt_id: id(1),
                at: at(),
            },
        );
        let mut proof = drain();
        proof.current_guest_document_generation = 2;
        assert_eq!(
            Command::AuthorizeQuiesce {
                attempt_id: id(1),
                proof,
                launch_nonce: id(9),
                deadline: at() + Duration::minutes(5),
                at: at()
            }
            .handle(&state),
            Err(Error::UnsafeVm)
        );
        assert_eq!(vm(&state).phase, Phase::Draining);
    }

    #[test]
    fn a_recovery_timeout_holds_the_slot_until_positive_physical_restoration() {
        let mut state = candidate();
        apply(&mut state, cancel(at()));
        let old_nonce = vm(&state).operation.launch_nonce;
        let late = at() + Duration::minutes(2);
        apply(
            &mut state,
            Command::Fail {
                attempt_id: id(1),
                failure: Failure::Timeout,
                launch_nonce: id(100),
                recovery_deadline: late + Duration::minutes(2),
                at: late,
            },
        );
        assert_eq!(vm(&state).operation.launch_nonce, old_nonce);
        assert_eq!(vm(&state).failure, Some(Failure::Uncertain));
        assert!(state.paused);
        assert!(vm(&state).completed_at.is_none());
        apply(
            &mut state,
            Command::DocumentPublished {
                attempt_id: id(1),
                operation_sequence: 4,
                generation: 4,
                at: late,
            },
        );
        let fence = vm(&state).fence().unwrap();
        apply(
            &mut state,
            Command::HostAcknowledged {
                fence,
                evidence: HostEvidence::RolledBack {
                    process: process(20),
                    image: request().source,
                    candidate_exited: true,
                    root_restored: true,
                },
                at: late + Duration::seconds(1),
            },
        );
        assert!(state.active.is_none());
        assert!(state.paused);
    }

    #[test]
    fn republishing_preserves_physical_launch_context_but_guest_health_stays_current() {
        let mut state = candidate();
        publish(&mut state);
        assert_eq!(vm(&state).operation.document_generation, Some(4));
        assert_eq!(
            vm(&state)
                .candidate_launch
                .as_ref()
                .unwrap()
                .document_generation,
            Some(3)
        );
        let mut proof = boot();
        proof.current_guest_document_generation = 2;
        assert_eq!(
            Command::VerifyGuest {
                attempt_id: id(1),
                proof: proof.clone(),
                at: at()
            }
            .handle(&state),
            Err(Error::UnsafeVm)
        );
        proof.guest_document_generation = 2;
        apply(
            &mut state,
            Command::VerifyGuest {
                attempt_id: id(1),
                proof,
                at: at(),
            },
        );
        let later = at() + Duration::seconds(31);
        assert_eq!(
            Command::Commit {
                attempt_id: id(1),
                at: later
            }
            .handle(&state),
            Err(Error::UnsafeVm)
        );
        let mut fresh = boot();
        fresh.observed_at = later;
        fresh.guest_document_generation = 2;
        fresh.current_guest_document_generation = 2;
        apply(
            &mut state,
            Command::VerifyGuest {
                attempt_id: id(1),
                proof: fresh,
                at: later,
            },
        );
        apply(
            &mut state,
            Command::Commit {
                attempt_id: id(1),
                at: later,
            },
        );
        assert_eq!(vm(&state).phase, Phase::Committing);
    }

    fn committed(process_present: bool) -> AgentUpdates {
        let mut state = verified();
        apply(
            &mut state,
            Command::Commit {
                attempt_id: id(1),
                at: at(),
            },
        );
        publish(&mut state);
        ack(
            &mut state,
            HostEvidence::Committed {
                process: process_present.then(|| process(11)),
            },
        );
        state
    }
    fn restart(state: &mut AgentUpdates, at: DateTime<Utc>) -> Command {
        let command = Command::RestartCommitted {
            attempt_id: id(1),
            launch_nonce: id(20),
            deadline: at + Duration::minutes(2),
            at,
        };
        apply(state, command.clone());
        command
    }
    fn restarted_boot(state: &AgentUpdates, at: DateTime<Utc>) -> GuestBootProof {
        let launch = vm(state).candidate_launch.as_ref().unwrap();
        let mut proof = boot();
        proof.launch_sequence = launch.sequence;
        proof.launch_nonce = launch.launch_nonce;
        proof.document_generation = launch.document_generation.unwrap();
        proof.os_boot_id = id(21);
        proof.pid1_context = id(22);
        proof.observed_at = at;
        proof.guest_document_generation = 2;
        proof.current_guest_document_generation = 2;
        proof
    }

    #[test]
    fn a_dead_committed_candidate_can_restart_the_pinned_root_once_without_rollback_or_recommit() {
        let mut state = committed(false);
        assert!(state.paused);
        assert!(vm(&state).guest_boot_proof.is_none());
        assert_eq!(
            Command::ReleaseOld {
                attempt_id: id(1),
                at: at()
            }
            .handle(&state),
            Err(Error::UnsafeVm)
        );
        let marker = vm(&state).committed_at;
        let target = vm(&state).target.clone();
        let command = restart(&mut state, at());
        assert!(command.handle(&state).unwrap().is_empty());
        assert_eq!(vm(&state).committed_at, marker);
        assert_eq!(vm(&state).target, target);
        assert_eq!(vm(&state).phase, Phase::Starting);
        assert_eq!(vm(&state).operation.sequence, 5);
        assert_eq!(cancel(at()).handle(&state), Err(Error::Irreversible));
        assert_eq!(
            Command::RestartCommitted {
                attempt_id: id(1),
                launch_nonce: id(100),
                deadline: at() + Duration::minutes(2),
                at: at()
            }
            .handle(&state),
            Err(Error::InvalidPhase)
        );
        publish(&mut state);
        assert_eq!(
            Command::HostAcknowledged {
                fence: vm(&state).fence().unwrap(),
                evidence: HostEvidence::CandidateRunning {
                    process: process(11),
                    image: target.identity(),
                    fresh_instance_start: true
                },
                at: at()
            }
            .handle(&state),
            Err(Error::UnsafeVm)
        );
        ack(
            &mut state,
            HostEvidence::CandidateRunning {
                process: process(20),
                image: target.identity(),
                fresh_instance_start: true,
            },
        );
        let mut proof = restarted_boot(&state, at());
        proof.os_boot_id = id(12);
        assert_eq!(
            Command::VerifyGuest {
                attempt_id: id(1),
                proof,
                at: at()
            }
            .handle(&state),
            Err(Error::UnsafeVm)
        );
        let proof = restarted_boot(&state, at());
        apply(
            &mut state,
            Command::VerifyGuest {
                attempt_id: id(1),
                proof,
                at: at(),
            },
        );
        assert_eq!(vm(&state).phase, Phase::Committed);
        assert_eq!(
            Command::Commit {
                attempt_id: id(1),
                at: at()
            }
            .handle(&state),
            Err(Error::Irreversible)
        );
        apply(
            &mut state,
            Command::ReleaseOld {
                attempt_id: id(1),
                at: at(),
            },
        );
        publish(&mut state);
        ack(&mut state, HostEvidence::Released);
        assert!(state.active.is_none());
        assert!(state.paused);
    }

    #[test]
    fn a_prior_release_receipt_cannot_free_a_slot_after_committed_guest_health_was_lost() {
        let mut state = committed(true);
        apply(
            &mut state,
            Command::ReleaseOld {
                attempt_id: id(1),
                at: at(),
            },
        );
        publish(&mut state);
        let old_release = Command::HostAcknowledged {
            fence: vm(&state).fence().unwrap(),
            evidence: HostEvidence::Released,
            at: at(),
        };
        ack(&mut state, HostEvidence::Uncertain);
        assert!(old_release.clone().handle(&state).unwrap().is_empty());
        assert!(state.active.is_some());
        assert!(state.paused);
        restart(&mut state, at());
        publish(&mut state);
        assert_eq!(old_release.handle(&state), Err(Error::StaleFence));
        ack(
            &mut state,
            HostEvidence::CandidateRunning {
                process: process(20),
                image: request().target.identity(),
                fresh_instance_start: true,
            },
        );
        let proof = restarted_boot(&state, at());
        apply(
            &mut state,
            Command::VerifyGuest {
                attempt_id: id(1),
                proof,
                at: at(),
            },
        );
        apply(
            &mut state,
            Command::ReleaseOld {
                attempt_id: id(1),
                at: at(),
            },
        );
        publish(&mut state);
        ack(&mut state, HostEvidence::Released);
        assert!(state.active.is_none());
    }

    #[test]
    fn committed_recovery_timeout_remains_irreversible_paused_and_bounded() {
        let mut state = committed(false);
        restart(&mut state, at());
        publish(&mut state);
        let deadline = vm(&state).committed_recovery_deadline;
        publish(&mut state);
        assert_eq!(vm(&state).committed_recovery_deadline, deadline);
        assert_eq!(vm(&state).deadline, at() + Duration::minutes(5));
        let late = at() + Duration::minutes(2);
        apply(
            &mut state,
            Command::Fail {
                attempt_id: id(1),
                failure: Failure::Timeout,
                launch_nonce: id(100),
                recovery_deadline: late + Duration::minutes(2),
                at: late,
            },
        );
        assert_eq!(vm(&state).operation.action, Action::StartCandidate);
        assert!(state.paused);
        assert!(vm(&state).committed_at.is_some());
        assert_eq!(cancel(late).handle(&state), Err(Error::Irreversible));
        assert_eq!(
            Command::RestartCommitted {
                attempt_id: id(1),
                launch_nonce: id(101),
                deadline: late + Duration::minutes(2),
                at: late
            }
            .handle(&state),
            Err(Error::InvalidPhase)
        );
        let proof = restarted_boot(&state, late);
        assert_eq!(
            Command::VerifyGuest {
                attempt_id: id(1),
                proof,
                at: late
            }
            .handle(&state),
            Err(Error::InvalidPhase)
        );
    }

    #[test]
    fn invalidating_committed_health_cannot_forget_boot_or_guest_generation_fences() {
        let mut state = committed(true);
        let mut proof = boot();
        proof.guest_document_generation = 2;
        proof.current_guest_document_generation = 2;
        apply(
            &mut state,
            Command::VerifyGuest {
                attempt_id: id(1),
                proof,
                at: at(),
            },
        );
        ack(&mut state, HostEvidence::Uncertain);
        assert!(vm(&state).guest_boot_proof.is_none());
        let mut stale = boot();
        assert_eq!(
            Command::VerifyGuest {
                attempt_id: id(1),
                proof: stale.clone(),
                at: at()
            }
            .handle(&state),
            Err(Error::UnsafeVm)
        );
        stale.guest_document_generation = 2;
        stale.current_guest_document_generation = 2;
        stale.os_boot_id = id(100);
        assert_eq!(
            Command::VerifyGuest {
                attempt_id: id(1),
                proof: stale,
                at: at()
            }
            .handle(&state),
            Err(Error::UnsafeVm)
        );
        assert!(state.active.is_some());
        assert!(state.paused);
    }

    #[test]
    fn snapshot_tail_replay_retains_committed_restart_and_release_fences() {
        let mut state = committed(false);
        restart(&mut state, at());
        let mut snapshot: AgentUpdates =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        let a = vm(&state);
        let command = Command::DocumentPublished {
            attempt_id: a.id,
            operation_sequence: a.operation.sequence,
            generation: a.last_document_generation + 1,
            at: at(),
        };
        let events = command.handle(&state).unwrap();
        for event in events {
            state.apply(&event);
            snapshot.apply(&event);
        }
        assert_eq!(snapshot, state);
        assert!(vm(&snapshot).committed_at.is_some());
        assert_eq!(vm(&snapshot).committed_restart_at, Some(at()));
        assert_eq!(
            vm(&snapshot).committed_recovery_deadline,
            Some(at() + Duration::minutes(2))
        );
        assert_eq!(cancel(at()).handle(&snapshot), Err(Error::Irreversible));
        let mut stale = vm(&snapshot).fence().unwrap();
        stale.operation_sequence -= 1;
        stale.action = Action::ReleaseOld;
        assert_eq!(
            Command::HostAcknowledged {
                fence: stale,
                evidence: HostEvidence::Released,
                at: at()
            }
            .handle(&snapshot),
            Err(Error::StaleFence)
        );
    }
    #[test]
    fn superseded_guest_health_cannot_authorize_commit_or_finish_cleanup() {
        let mut before_commit = verified();
        apply(
            &mut before_commit,
            Command::InvalidateGuest {
                attempt_id: id(1),
                at: at(),
            },
        );
        assert_eq!(
            Command::Commit {
                attempt_id: id(1),
                at: at()
            }
            .handle(&before_commit),
            Err(Error::InvalidPhase)
        );
        assert!(before_commit.active.is_some());

        let mut after_commit = committed(true);
        apply(
            &mut after_commit,
            Command::ReleaseOld {
                attempt_id: id(1),
                at: at(),
            },
        );
        publish(&mut after_commit);
        apply(
            &mut after_commit,
            Command::InvalidateGuest {
                attempt_id: id(1),
                at: at(),
            },
        );
        ack(&mut after_commit, HostEvidence::Released);
        assert!(after_commit.active.is_some());
        assert!(after_commit.paused);
        assert_eq!(cancel(at()).handle(&after_commit), Err(Error::Irreversible));
    }
}
