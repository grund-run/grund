//! Instance-wide serial machine updates and independently observed boot health.

use chrono::{DateTime, Duration, Utc};
use grund_domain::{
    agent_updates::{AgentUpdates, Attempt, Command, Failure, Fence, Phase, PublicBuild},
    machine::KeyPurpose,
};
use grund_store::{
    machines::{self, MachineRow},
    work::Work,
};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    config::DatabaseArgs,
    keys::KeysState,
    services::{agents::MachineCaller, capacity::CapacityState},
    state::State,
};

/// Domain separation for offers and finalize permits signed by the pinned trust key.
pub const SIGNATURE_PREFIX: &[u8] = b"grund-machine-update-v1\n";

const OFFER_TTL: Duration = Duration::minutes(10);
const ATTEMPT_TIMEOUT: Duration = Duration::minutes(15);
const OBSERVATION_FRESHNESS: Duration = Duration::seconds(30);
const OFFLINE_AFTER: Duration = Duration::seconds(90);

/// A narrow signed JSON document; it contains package identities, never URLs.
pub struct SignedUpdate {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub key_id: Uuid,
}

#[derive(Serialize)]
struct Payload<'a> {
    kind: &'static str,
    attempt_id: Uuid,
    machine_id: Uuid,
    registration_key: &'a str,
    generation: u64,
    previous_revision: &'a str,
    target: &'a PublicBuild,
    expires_at_unix: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permit: Option<bool>,
}

/// Machine update operations sharing the durable singleton lock with lifecycle changes.
pub struct AgentUpdateService {
    state: State,
}

impl AgentUpdateService {
    /// Constructs a service using the existing instance state and trust keys.
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn work(&self, caller: &MachineCaller) -> anyhow::Result<Work<'_>> {
        Ok(Work::begin(
            &self.state.events,
            Uuid::now_v7(),
            &format!("machine:{}", caller.machine_id),
        )
        .await?)
    }

    /// Offers one exact public package only when local policy and lifecycle permit it.
    pub async fn poll(
        &self,
        caller: &MachineCaller,
        following: bool,
        architecture: &str,
        revision: &str,
        boot_id: Uuid,
    ) -> anyhow::Result<Option<SignedUpdate>> {
        let now = Utc::now();
        let mut work = self.work(caller).await?;
        let mut rollout = sweep(&mut work, now).await?;
        let row = current_machine(&mut work, caller).await?;
        let eligible = following
            && matches!(architecture, "x86_64" | "aarch64")
            && valid_revision(revision)
            && !self.state.config.agent_updates_paused
            && !rollout.paused
            && !rollout.migration_holds.contains_key(&caller.machine_id)
            && rollout.pending_provider_release.is_none()
            && row.as_ref().is_some_and(|row| safe_machine(row, now));
        if !eligible {
            work.commit().await?;
            return Ok(None);
        }
        if !observed(&mut work, caller, boot_id, revision, now).await? {
            work.commit().await?;
            return Ok(None);
        }
        let row = row.expect("eligibility requires a current machine");
        if rollout.active.is_none() {
            let Some(target) = instance_target() else {
                work.commit().await?;
                return Ok(None);
            };
            if rollout.target.as_ref() != Some(&target) {
                work.agent_updates(Command::Select { target, at: now })
                    .await?;
                rollout = work.load_agent_updates().await?;
            }
            if rollout
                .target
                .as_ref()
                .is_some_and(|target| target.revision != revision)
            {
                work.agent_updates(Command::Offer {
                    attempt_id: Uuid::now_v7(),
                    machine_id: caller.machine_id,
                    registration_key: caller.registration_key.clone(),
                    generation: rollout.generation,
                    previous_revision: revision.to_owned(),
                    at: now,
                    expires_at: now + OFFER_TTL,
                })
                .await?;
                rollout = work.load_agent_updates().await?;
            }
        }
        let offer = match rollout.active.as_ref() {
            Some(attempt)
                if attempt.machine_id == caller.machine_id
                    && attempt.registration_key == caller.registration_key
                    && attempt.authorized_at.is_none()
                    && attempt.previous_revision == revision
                    && attempt.expires_at > now =>
            {
                Some(self.sign(&mut work, &row, attempt, None).await?)
            }
            _ => None,
        };
        work.commit().await?;
        Ok(offer)
    }

    /// Acquires a provider fence outside Work, then revalidates before authorization.
    pub async fn begin(
        &self,
        caller: &MachineCaller,
        attempt_id: Uuid,
        generation: u64,
        boot_id: Uuid,
    ) -> anyhow::Result<bool> {
        let now = Utc::now();
        let mut work = self.work(caller).await?;
        let rollout = work.load_agent_updates().await?;
        let Some(row) = current_machine(&mut work, caller).await? else {
            return Err(grund_domain::agent_updates::Error::StaleFence.into());
        };
        let Some(attempt) = rollout.active.as_ref().filter(|a| a.id == attempt_id) else {
            let completed = work.completed_update_attempt(attempt_id).await?;
            return match completed {
                Some(attempt)
                    if matches_attempt(&attempt, caller, attempt_id, generation)
                        && attempt.authorized_boot_id == Some(boot_id) =>
                {
                    Ok(false)
                }
                Some(_) => Err(grund_domain::agent_updates::Error::StaleFence.into()),
                None => Ok(false),
            };
        };
        if !matches_attempt(attempt, caller, attempt_id, generation) {
            return Err(grund_domain::agent_updates::Error::StaleFence.into());
        }
        if attempt.authorized_at.is_some() {
            return if attempt.authorized_boot_id == Some(boot_id) {
                Ok(true)
            } else {
                Err(grund_domain::agent_updates::Error::StaleFence.into())
            };
        }
        if attempt.expires_at <= now {
            work.agent_updates(Command::Cancel {
                fence: fence(attempt),
                at: now,
            })
            .await?;
            work.commit().await?;
            return Ok(false);
        }
        if !can_begin(
            &self.state,
            &mut work,
            &rollout,
            &row,
            caller,
            attempt,
            boot_id,
            now,
        )
        .await?
        {
            return Ok(false);
        }
        let Some(provider_machine_id) = row.provider_machine_id.as_ref() else {
            work.agent_updates(Command::Begin {
                fence: fence(attempt),
                boot_id,
                provider_permit: None,
                at: now,
            })
            .await?;
            work.commit().await?;
            return Ok(true);
        };
        let controller_id = self
            .state
            .keys()
            .ensure(work.sql(), KeyPurpose::Management, None)
            .await?
            .key_id;
        work.agent_updates(Command::ReserveProvider {
            fence: fence(attempt),
            provider_machine_id: provider_machine_id.clone(),
            controller_id,
            at: now,
        })
        .await?;
        let reservation = work
            .load_agent_updates()
            .await?
            .active
            .and_then(|attempt| attempt.provider_fence)
            .expect("reservation command retains its intent");
        work.commit().await?;

        let allowed = match self
            .state
            .capacity()
            .acquire_machine_update_fence(&reservation)
            .await
        {
            Ok(allowed) => allowed,
            Err(_) => {
                tracing::warn!(
                    "provider update fence unavailable; cancelling the unacknowledged reservation"
                );
                false
            }
        };

        let now = Utc::now();
        let mut work = self.work(caller).await?;
        let rollout = work.load_agent_updates().await?;
        let Some(attempt) = rollout
            .active
            .as_ref()
            .filter(|a| matches_attempt(a, caller, attempt_id, generation))
        else {
            work.commit().await?;
            return Ok(false);
        };
        if attempt.authorized_at.is_some() {
            return Ok(attempt.authorized_boot_id == Some(boot_id));
        }
        let row = current_machine(&mut work, caller).await?;
        let valid = if let Some(row) = row.as_ref() {
            allowed
                && attempt.provider_fence.as_ref() == Some(&reservation)
                && row.provider_machine_id.as_deref()
                    == Some(reservation.provider_machine_id.as_str())
                && can_begin(
                    &self.state,
                    &mut work,
                    &rollout,
                    row,
                    caller,
                    attempt,
                    boot_id,
                    now,
                )
                .await?
        } else {
            false
        };
        if valid {
            work.agent_updates(Command::Begin {
                fence: fence(attempt),
                boot_id,
                provider_permit: Some(reservation),
                at: now,
            })
            .await?;
        } else {
            work.agent_updates(Command::Cancel {
                fence: fence(attempt),
                at: now,
            })
            .await?;
        }
        work.commit().await?;
        Ok(valid)
    }

    /// Records a fenced supervisor report; candidate health alone never frees the slot.
    #[allow(clippy::too_many_arguments)]
    pub async fn report(
        &self,
        caller: &MachineCaller,
        attempt_id: Uuid,
        generation: u64,
        phase: &str,
        boot_id: Uuid,
        revision: &str,
        failure: Option<Failure>,
    ) -> anyhow::Result<(bool, Option<SignedUpdate>)> {
        let now = Utc::now();
        let mut work = self.work(caller).await?;
        let rollout = work.load_agent_updates().await?;
        let Some(row) = current_machine(&mut work, caller).await? else {
            return Ok((false, None));
        };
        let completed = work.completed_update_attempt(attempt_id).await?;
        if let Some(completed) = completed
            .as_ref()
            .filter(|a| matches_attempt(a, caller, attempt_id, generation))
        {
            let accepted = match phase {
                "committed" => {
                    completed.phase == Phase::Succeeded
                        && completed.boot_id == Some(boot_id)
                        && revision == completed.target.revision
                }
                "rolled_back" => {
                    completed.phase == Phase::RolledBack
                        && completed.boot_id == Some(boot_id)
                        && revision == completed.previous_revision
                }
                _ => false,
            };
            return Ok((accepted, None));
        }
        let Some(attempt) = rollout
            .active
            .as_ref()
            .filter(|a| matches_attempt(a, caller, attempt_id, generation))
        else {
            return Ok((false, None));
        };
        let command = match phase {
            "candidate_health" => {
                if attempt.authorized_boot_id == Some(boot_id)
                    || revision != attempt.target.revision
                    || !observed(&mut work, caller, boot_id, revision, now).await?
                {
                    return Ok((false, None));
                }
                Command::Health {
                    fence: fence(attempt),
                    boot_id,
                    at: now,
                }
            }
            "committed" => {
                if !verified_commit(attempt, boot_id, revision) {
                    return Ok((false, None));
                }
                if attempt.phase == Phase::Failed {
                    work.agent_updates(Command::Health {
                        fence: fence(attempt),
                        boot_id,
                        at: now,
                    })
                    .await?;
                }
                Command::Commit {
                    fence: fence(attempt),
                    boot_id,
                    at: now,
                }
            }
            "rolled_back" => {
                if attempt.authorized_boot_id == Some(boot_id)
                    || revision != attempt.previous_revision
                    || !observed(&mut work, caller, boot_id, revision, now).await?
                {
                    return Ok((false, None));
                }
                Command::Rollback {
                    fence: fence(attempt),
                    boot_id,
                    at: now,
                }
            }
            "failed" => Command::Fail {
                fence: fence(attempt),
                failure: failure.ok_or_else(|| anyhow::anyhow!("failure code required"))?,
                at: now,
            },
            _ => return Ok((false, None)),
        };
        work.agent_updates(command).await?;
        let permit = if phase == "candidate_health" {
            let rollout = work.load_agent_updates().await?;
            Some(
                self.sign(
                    &mut work,
                    &row,
                    rollout
                        .active
                        .as_ref()
                        .expect("health retains active attempt"),
                    Some(boot_id),
                )
                .await?,
            )
        } else {
            None
        };
        work.commit().await?;
        Ok((true, permit))
    }

    async fn sign(
        &self,
        work: &mut Work<'_>,
        row: &MachineRow,
        attempt: &Attempt,
        boot_id: Option<Uuid>,
    ) -> anyhow::Result<SignedUpdate> {
        let (purpose, organisation_id) = if row.pool == "management" {
            (KeyPurpose::Management, None)
        } else {
            (KeyPurpose::Organisation, row.home_organisation_id)
        };
        let keys = self.state.keys();
        let key = keys.ensure(work.sql(), purpose, organisation_id).await?;
        let payload = serde_json::to_vec(&Payload {
            kind: if boot_id.is_some() {
                "finalize"
            } else {
                "offer"
            },
            attempt_id: attempt.id,
            machine_id: attempt.machine_id,
            registration_key: &attempt.registration_key,
            generation: attempt.generation,
            previous_revision: &attempt.previous_revision,
            target: &attempt.target,
            expires_at_unix: if boot_id.is_some() {
                (Utc::now() + OFFER_TTL).timestamp()
            } else {
                attempt.expires_at.timestamp()
            },
            boot_id,
            permit: boot_id.map(|_| true),
        })?;
        let signature = keys.sign(key.key_id, SIGNATURE_PREFIX, &payload).to_vec();
        Ok(SignedUpdate {
            payload,
            signature,
            key_id: key.key_id,
        })
    }

    /// Stores a disposable heartbeat observation after rechecking registration.
    pub async fn observe(
        &self,
        caller: &MachineCaller,
        boot_id: Uuid,
        revision: &str,
        ready: bool,
    ) -> anyhow::Result<()> {
        if !valid_revision(revision) {
            return Ok(());
        }
        let mut work = self.work(caller).await?;
        if current_machine(&mut work, caller).await?.is_none() {
            return Ok(());
        }
        work.record_update_observation(
            caller.machine_id,
            &caller.registration_key,
            boot_id,
            revision,
            ready,
            Utc::now(),
        )
        .await?;
        work.commit().await?;
        Ok(())
    }
}

/// Retains and pauses ambiguous authorized attempts even when no machine polls.
pub struct AgentUpdateMonitor {
    state: State,
}

impl AgentUpdateMonitor {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

impl notmad::Component for AgentUpdateMonitor {
    fn info(&self) -> notmad::ComponentInfo {
        "grund/agent-updates".into()
    }

    async fn run(
        &self,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<(), notmad::MadError> {
        let mut tick = tokio::time::interval(self.state.config.work_poll_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                _ = tick.tick() => {
                    if let Err(error) = monitor(&self.state).await {
                        tracing::warn!(error = %error, "machine update monitoring failed; retaining the durable slot");
                    }
                }
            }
        }
    }
}

async fn monitor(state: &State) -> anyhow::Result<()> {
    let mut work = Work::begin(
        &state.events,
        Uuid::now_v7(),
        "instance:agent-update-monitor",
    )
    .await?;
    let rollout = sweep(&mut work, Utc::now()).await?;
    let pending = rollout.pending_provider_release;
    work.commit().await?;
    if let Some(reservation) = pending {
        let closed = state
            .capacity()
            .release_machine_update_fence(&reservation)
            .await?;
        if closed >= reservation.sequence {
            let mut work = Work::begin(
                &state.events,
                Uuid::now_v7(),
                "instance:agent-update-monitor",
            )
            .await?;
            work.agent_updates(Command::AcknowledgeProviderRelease {
                reservation,
                at: Utc::now(),
            })
            .await?;
            work.commit().await?;
        }
    }
    Ok(())
}

async fn sweep(work: &mut Work<'_>, now: DateTime<Utc>) -> anyhow::Result<AgentUpdates> {
    let mut rollout = work.load_agent_updates().await?;
    if !rollout.initialized {
        work.agent_updates(Command::Initialize { at: now }).await?;
        rollout = work.load_agent_updates().await?;
    }
    let Some(attempt) = rollout.active.as_ref() else {
        return Ok(rollout);
    };
    if attempt.authorized_at.is_some() && attempt.phase != Phase::Failed {
        let row = machines::machine(&mut **work.sql(), attempt.machine_id).await?;
        let failure = if row.as_ref().and_then(|m| m.public_key.as_deref())
            != Some(attempt.registration_key.as_str())
        {
            Some(Failure::RegistrationChanged)
        } else if attempt
            .authorized_at
            .is_some_and(|at| now - at > ATTEMPT_TIMEOUT)
        {
            Some(Failure::Timeout)
        } else if row
            .as_ref()
            .and_then(|m| m.last_seen_at)
            .is_none_or(|seen| now - seen > OFFLINE_AFTER)
        {
            Some(Failure::Offline)
        } else {
            None
        };
        if let Some(failure) = failure {
            work.agent_updates(Command::Fail {
                fence: fence(attempt),
                failure,
                at: now,
            })
            .await?;
            return Ok(work.load_agent_updates().await?);
        }
    } else if attempt.authorized_at.is_none() && attempt.expires_at <= now {
        work.agent_updates(Command::Cancel {
            fence: fence(attempt),
            at: now,
        })
        .await?;
        return Ok(work.load_agent_updates().await?);
    }
    Ok(rollout)
}

/// Machine following operations available through the shared instance state.
pub trait AgentUpdatesState {
    fn agent_updates(&self) -> AgentUpdateService;
}

impl AgentUpdatesState for State {
    fn agent_updates(&self) -> AgentUpdateService {
        AgentUpdateService::new(self.clone())
    }
}

fn verified_commit(attempt: &Attempt, boot_id: Uuid, revision: &str) -> bool {
    matches!(attempt.phase, Phase::HealthVerified | Phase::Failed)
        && attempt.authorized_at.is_some()
        && attempt
            .authorized_boot_id
            .is_some_and(|previous| previous != boot_id)
        && attempt.boot_id == Some(boot_id)
        && attempt.target.revision == revision
}

async fn current_machine(
    work: &mut Work<'_>,
    caller: &MachineCaller,
) -> anyhow::Result<Option<MachineRow>> {
    Ok(machines::machine(&mut **work.sql(), caller.machine_id)
        .await?
        .filter(|row| {
            row.state != "revoked"
                && row.public_key.as_deref() == Some(caller.registration_key.as_str())
        }))
}

#[allow(clippy::too_many_arguments)]
async fn can_begin(
    state: &State,
    work: &mut Work<'_>,
    rollout: &AgentUpdates,
    row: &MachineRow,
    caller: &MachineCaller,
    attempt: &Attempt,
    boot_id: Uuid,
    now: DateTime<Utc>,
) -> anyhow::Result<bool> {
    if state.config.agent_updates_paused
        || rollout.paused
        || !safe_machine(row, now)
        || attempt.phase != Phase::Offered
        || rollout.migration_holds.contains_key(&caller.machine_id)
        || attempt.expires_at <= now
    {
        return Ok(false);
    }
    Ok(work
        .update_observation(caller.machine_id)
        .await?
        .as_ref()
        .is_some_and(|seen| {
            seen.registration_key == caller.registration_key
                && seen.boot_id == boot_id
                && seen.revision == attempt.previous_revision
                && seen.ready
                && now - seen.observed_at <= OBSERVATION_FRESHNESS
        }))
}

fn safe_machine(row: &MachineRow, now: DateTime<Utc>) -> bool {
    matches!(row.state.as_str(), "active" | "available" | "leased")
        && row.cordoned_at.is_none()
        && row
            .last_seen_at
            .is_some_and(|seen| now - seen <= OBSERVATION_FRESHNESS)
}

fn matches_attempt(attempt: &Attempt, caller: &MachineCaller, id: Uuid, generation: u64) -> bool {
    attempt.id == id
        && attempt.machine_id == caller.machine_id
        && attempt.registration_key == caller.registration_key
        && attempt.generation == generation
}

fn fence(attempt: &Attempt) -> Fence {
    Fence {
        attempt_id: attempt.id,
        machine_id: attempt.machine_id,
        registration_key: attempt.registration_key.clone(),
        generation: attempt.generation,
    }
}

async fn observed(
    work: &mut Work<'_>,
    caller: &MachineCaller,
    boot_id: Uuid,
    revision: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<bool> {
    Ok(work
        .update_observation(caller.machine_id)
        .await?
        .is_some_and(|seen| {
            seen.registration_key == caller.registration_key
                && seen.boot_id == boot_id
                && seen.revision == revision
                && seen.ready
                && now - seen.observed_at <= OBSERVATION_FRESHNESS
        }))
}

fn valid_revision(revision: &str) -> bool {
    revision.len() == 40
        && revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn instance_target() -> Option<PublicBuild> {
    let revision = crate::services::agents::expected_agent_revision();
    target_for(revision, crate::health::package())
}

fn target_for(revision: &str, package: &str) -> Option<PublicBuild> {
    PublicBuild::from_revision(revision, package)
        .or_else(|_| PublicBuild::main(revision))
        .ok()
}

/// Returns durable rollout state using only the locally configured database.
pub async fn status(database: &DatabaseArgs) -> anyhow::Result<AgentUpdates> {
    administer(database, None).await
}

/// Pauses new offers and authorizations; an authorized attempt still resolves safely.
pub async fn pause(database: &DatabaseArgs) -> anyhow::Result<AgentUpdates> {
    administer(database, Some(true)).await
}

/// Resumes the durable pause without clearing or cancelling an active attempt.
pub async fn resume(database: &DatabaseArgs) -> anyhow::Result<AgentUpdates> {
    administer(database, Some(false)).await
}

async fn administer(database: &DatabaseArgs, paused: Option<bool>) -> anyhow::Result<AgentUpdates> {
    let pool = crate::db::connect(database).await?;
    let events = mire::EventStore::new(pool.clone());
    let mut work = Work::begin(&events, Uuid::now_v7(), "instance:local-admin").await?;
    let state = work.load_agent_updates().await?;
    if let Some(paused) = paused {
        let now = Utc::now();
        if !state.initialized {
            work.agent_updates(Command::Initialize { at: now }).await?;
        }
        work.agent_updates(if paused {
            Command::Pause { at: now }
        } else {
            Command::Resume { at: now }
        })
        .await?;
    }
    let state = work.load_agent_updates().await?;
    work.commit().await?;
    pool.close().await;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_private_changes_do_not_change_the_selected_public_package() {
        let public = "a".repeat(40);
        let first = target_for(&format!("{}+{public}", "1".repeat(40)), "0.1.0").unwrap();
        let second = target_for(&format!("{}+{public}", "2".repeat(40)), "0.1.0").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.package, format!("main-{public}"));
    }

    #[test]
    fn only_an_explicit_release_tag_overrides_the_exact_main_package() {
        let revision = "b".repeat(40);
        assert_eq!(
            target_for(&revision, "v1.2.3-alpha.4").unwrap().package,
            "v1.2.3-alpha.4"
        );
        for package in [
            "1.2.3",
            "latest",
            "https://example.com/agent",
            "v1.2.3-beta.1",
        ] {
            assert_eq!(
                target_for(&revision, package).unwrap().package,
                format!("main-{revision}")
            );
        }
        assert!(target_for("unknown", "v1.2.3").is_none());
        assert!(target_for(&"B".repeat(40), "v1.2.3").is_none());
    }

    #[test]
    fn a_report_cannot_cross_a_registration_or_generation_fence() {
        let machine_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        let caller = MachineCaller {
            machine_id,
            organisation_id: None,
            endpoint_key_prefix: [b'a'; 12],
            registration_key: "a".repeat(64),
        };
        let attempt: Attempt = serde_json::from_value(serde_json::json!({
            "id": attempt_id, "machine_id": machine_id, "registration_key": "a".repeat(64),
            "generation": 7, "previous_revision": "1".repeat(40),
            "target": {"revision": "2".repeat(40), "package": format!("main-{}", "2".repeat(40))},
            "phase": "offered", "offered_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T00:10:00Z", "authorized_at": null,
            "boot_id": null, "failure": null
        }))
        .unwrap();
        assert!(matches_attempt(&attempt, &caller, attempt_id, 7));
        assert!(!matches_attempt(&attempt, &caller, attempt_id, 8));
        assert!(!matches_attempt(&attempt, &caller, Uuid::now_v7(), 7));
        let mut reregistered = caller.clone();
        reregistered.registration_key = "b".repeat(64);
        assert!(!matches_attempt(&attempt, &reregistered, attempt_id, 7));
    }

    #[test]
    fn a_durable_commit_survives_outage_without_a_new_heartbeat_but_requires_verified_health() {
        let original_boot = Uuid::from_u128(1);
        let candidate_boot = Uuid::from_u128(2);
        let revision = "2".repeat(40);
        let mut attempt: Attempt = serde_json::from_value(serde_json::json!({
            "id": Uuid::from_u128(3), "machine_id": Uuid::from_u128(4),
            "registration_key": "a".repeat(64), "generation": 7,
            "previous_revision": "1".repeat(40),
            "target": {"revision": revision, "package": format!("main-{revision}")},
            "phase": "health_verified", "offered_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T00:10:00Z", "authorized_at": "2026-01-01T00:01:00Z",
            "authorized_boot_id": original_boot, "boot_id": candidate_boot, "failure": null
        }))
        .unwrap();
        assert!(verified_commit(&attempt, candidate_boot, &revision));
        attempt.phase = Phase::Failed;
        attempt.failure = Some(Failure::Offline);
        assert!(verified_commit(&attempt, candidate_boot, &revision));
        assert!(!verified_commit(&attempt, original_boot, &revision));
        assert!(!verified_commit(&attempt, Uuid::from_u128(5), &revision));
        assert!(!verified_commit(&attempt, candidate_boot, &"3".repeat(40)));
        attempt.boot_id = Some(original_boot);
        assert!(!verified_commit(&attempt, original_boot, &revision));
        assert!(!verified_commit(&attempt, candidate_boot, &revision));
        attempt.boot_id = Some(candidate_boot);
        attempt.phase = Phase::Authorized;
        assert!(!verified_commit(&attempt, candidate_boot, &revision));
    }
}

#[cfg(test)]
#[path = "agent_updates_tests.rs"]
mod fence_tests;
