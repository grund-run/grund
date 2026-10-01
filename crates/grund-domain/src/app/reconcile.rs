//! The app reconciler's decision (grund-docs design/apps.md §8, §9, §10.3):
//! from an app, what its machines report and where it could run, the events
//! that move it one step closer to running its target release on every
//! slot. The Deployment and ReplicaSet controllers in one pure function.
//!
//! One pass may decide several things (a lost replica, a drain finished, a
//! surge placed); each is applied to a working copy before the next is
//! decided, so the events always fold to a consistent app. Calling it again
//! with nothing changed decides nothing.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    App, AppEvent, DrainReason, PlaceReason, Release, Replica, ReplicaState,
    placement::{self, MachineView, Unplaceable, Usage},
};

/// The least time between two moves that only repair an app's spread
/// (apps.md §5.5).
pub const SPREAD_MOVE_EVERY: Duration = Duration::minutes(5);

/// Exits before a new replica was ever ready that fail its rollout.
pub const EXITS_BEFORE_READY: u32 = 3;

/// What a replica's machine last reported about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observed {
    Pulling,
    Starting,
    Running,
    Exited,
    Failed,
    Refused,
    Stopping,
}

impl Observed {
    pub fn as_str(self) -> &'static str {
        match self {
            Observed::Pulling => "pulling",
            Observed::Starting => "starting",
            Observed::Running => "running",
            Observed::Exited => "exited",
            Observed::Failed => "failed",
            Observed::Refused => "refused",
            Observed::Stopping => "stopping",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "pulling" => Observed::Pulling,
            "starting" => Observed::Starting,
            "running" => Observed::Running,
            "exited" => Observed::Exited,
            "failed" => Observed::Failed,
            "refused" => Observed::Refused,
            "stopping" => Observed::Stopping,
            _ => return None,
        })
    }
}

/// One replica as its machine last reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub replica_id: Uuid,
    pub state: Observed,
    pub ready: bool,
    /// Since when it has been ready without a break.
    pub ready_since: Option<DateTime<Utc>>,
    /// It has been ready at some point since it was placed.
    pub ever_ready: bool,
    pub restarts: u32,
    pub last_exit_code: i32,
    pub reason: String,
    /// Draining, with nothing in flight through its machine's gate: its
    /// drain may end now (apps.md §12.3).
    pub idle: bool,
}

/// A slot that cannot be placed now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiting {
    pub slot: u32,
    pub reason: Unplaceable,
    /// In words for the customer.
    pub message: String,
}

/// What one pass decided.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Decision {
    pub events: Vec<AppEvent>,
    /// Slots left unplaced, and why: a fact about now, not an event.
    pub waiting: Vec<Waiting>,
}

struct Pass<'a> {
    work: App,
    events: Vec<AppEvent>,
    waiting: Vec<Waiting>,
    observations: &'a [Observation],
    machines: &'a [MachineView],
    now: DateTime<Utc>,
}

impl Pass<'_> {
    fn emit(&mut self, event: AppEvent) {
        mire::Aggregate::apply(&mut self.work, &event);
        self.events.push(event);
    }

    fn machine(&self, id: Uuid) -> Option<&MachineView> {
        self.machines.iter().find(|m| m.machine_id == id)
    }

    fn observation(&self, id: Uuid) -> Option<&Observation> {
        self.observations.iter().find(|o| o.replica_id == id)
    }

    fn connected(&self, machine_id: Uuid) -> bool {
        self.machine(machine_id)
            .is_some_and(|m| m.connected(self.now))
    }

    fn available(&self, replica: &Replica) -> bool {
        let min_ready = Duration::seconds(i64::from(self.work.settings.rollout.min_ready_seconds));
        replica.state == ReplicaState::Running
            && self.connected(replica.machine_id)
            && self.observation(replica.replica_id).is_some_and(|o| {
                o.ready
                    && o.state == Observed::Running
                    && o.ready_since
                        .is_some_and(|since| self.now - since >= min_ready)
            })
    }

    fn ever_ready(&self, replica: &Replica) -> bool {
        self.observation(replica.replica_id)
            .is_some_and(|o| o.ever_ready)
    }

    fn running(&self) -> Vec<Replica> {
        self.work
            .replicas
            .iter()
            .filter(|r| r.state == ReplicaState::Running)
            .cloned()
            .collect()
    }

    fn usage(&self, machine_id: Uuid) -> Usage {
        let mut usage = Usage::default();
        for replica in self
            .work
            .replicas
            .iter()
            .filter(|r| r.machine_id == machine_id)
        {
            if replica.state == ReplicaState::Running {
                usage.running += 1;
            }
            if let Some(release) = self.work.release(replica.release) {
                usage.memory_mib += release.spec.memory_mib;
                usage.cpu_millis += release.spec.cpu_millis;
            }
        }
        usage
    }

    fn drain(&mut self, replica_id: Uuid, reason: DrainReason) {
        let now = self.now;
        self.emit(AppEvent::ReplicaDraining {
            replica_id,
            reason,
            draining_at: now,
        });
    }

    fn place(
        &mut self,
        slot: u32,
        release: &Release,
        reason: PlaceReason,
        prefer: Option<Uuid>,
        new_id: &mut dyn FnMut() -> Uuid,
    ) -> Result<Uuid, Unplaceable> {
        let usage = |machine_id: Uuid| self.usage(machine_id);
        let chosen = placement::place(
            release,
            &self.work.settings,
            self.machines,
            &usage,
            prefer,
            self.now,
        );
        match chosen {
            Ok(machine_id) => {
                let placement = self.work.next_placement;
                let now = self.now;
                self.emit(AppEvent::ReplicaPlaced {
                    replica_id: new_id(),
                    slot,
                    release: release.number,
                    machine_id,
                    placement,
                    reason,
                    placed_at: now,
                });
                Ok(machine_id)
            }
            Err(unplaceable) => Err(unplaceable),
        }
    }

    fn fits_without(&self, release: &Release, leaving: &Replica) -> bool {
        let freed = self.work.release(leaving.release).map(|r| &r.spec);
        let usage = |machine_id: Uuid| {
            let mut usage = self.usage(machine_id);
            if machine_id == leaving.machine_id
                && let Some(spec) = freed
            {
                usage.running = usage.running.saturating_sub(1);
                usage.memory_mib = usage.memory_mib.saturating_sub(spec.memory_mib);
                usage.cpu_millis = usage.cpu_millis.saturating_sub(spec.cpu_millis);
            }
            usage
        };
        placement::place(
            release,
            &self.work.settings,
            self.machines,
            &usage,
            Some(leaving.machine_id),
            self.now,
        )
        .is_ok()
    }

    fn wait(&mut self, slot: u32, reason: Unplaceable, release: &Release) {
        let name = self
            .work
            .name
            .as_ref()
            .map_or("The app".to_string(), |n| n.to_string());
        self.waiting.push(Waiting {
            slot,
            reason,
            message: reason.message(&name, release),
        });
    }

    fn unavailable_slots(&self, copies: u32) -> u32 {
        let running = self.running();
        (0..copies)
            .filter(|slot| !running.iter().any(|r| r.slot == *slot && self.available(r)))
            .count() as u32
    }
}

/// Decides the next steps for `app`. `new_id` gives each new replica its
/// id. Pure: the same inputs give the same decision.
pub fn reconcile(
    app: &App,
    observations: &[Observation],
    machines: &[MachineView],
    now: DateTime<Utc>,
    new_id: &mut dyn FnMut() -> Uuid,
) -> Decision {
    let mut pass = Pass {
        work: app.clone(),
        events: Vec::new(),
        waiting: Vec::new(),
        observations,
        machines,
        now,
    };
    if !app.exists || app.deleted {
        return Decision::default();
    }
    let lost_slots = lose_replicas(&mut pass);
    finish_drains(&mut pass);
    if pass.work.halted {
        return pass.into_decision();
    }
    fail_rollout_on_a_bad_replica(&mut pass);
    if pass.work.halted {
        return pass.into_decision();
    }
    converge(&mut pass, &lost_slots, new_id);
    finish_rollout(&mut pass);
    repair_spread(&mut pass, new_id);
    pass.into_decision()
}

impl Pass<'_> {
    fn into_decision(self) -> Decision {
        Decision {
            events: self.events,
            waiting: self.waiting,
        }
    }
}

fn lose_replicas(pass: &mut Pass<'_>) -> BTreeSet<u32> {
    let after = Duration::seconds(i64::from(pass.work.settings.reschedule_after_seconds));
    let mut slots = BTreeSet::new();
    let lost: Vec<Replica> = pass
        .work
        .replicas
        .iter()
        .filter(|r| match pass.machine(r.machine_id) {
            None => true,
            Some(machine) => {
                !machine.connected(pass.now)
                    && machine
                        .last_seen
                        .is_none_or(|seen| pass.now - seen >= after)
            }
        })
        .cloned()
        .collect();
    for replica in lost {
        if replica.state == ReplicaState::Running {
            slots.insert(replica.slot);
        }
        let now = pass.now;
        pass.emit(AppEvent::ReplicaLost {
            replica_id: replica.replica_id,
            machine_id: replica.machine_id,
            lost_at: now,
        });
    }
    slots
}

fn finish_drains(pass: &mut Pass<'_>) {
    let drain = Duration::seconds(i64::from(pass.work.settings.rollout.drain_seconds));
    let done: Vec<Uuid> = pass
        .work
        .replicas
        .iter()
        .filter(|r| r.state == ReplicaState::Draining)
        .filter(|r| {
            r.draining_since
                .is_none_or(|since| pass.now - since >= drain)
                || pass.observation(r.replica_id).is_some_and(|o| {
                    o.idle
                        || matches!(
                            o.state,
                            Observed::Exited | Observed::Failed | Observed::Refused
                        )
                })
        })
        .map(|r| r.replica_id)
        .collect();
    for replica_id in done {
        let now = pass.now;
        pass.emit(AppEvent::ReplicaRemoved {
            replica_id,
            removed_at: now,
        });
    }
}

fn failure_reason(pass: &Pass<'_>, replica: &Replica, release: &Release) -> Option<String> {
    let machine = pass
        .machine(replica.machine_id)
        .map_or("its machine".to_string(), |m| m.name.clone());
    let observation = pass.observation(replica.replica_id);
    if let Some(o) = observation {
        if o.state == Observed::Refused {
            return Some(format!(
                "v{} was refused by {machine}: {}",
                release.number, o.reason
            ));
        }
        if o.restarts >= EXITS_BEFORE_READY && !o.ever_ready {
            return Some(format!(
                "v{} didn't start: it exited {} times before it was ever ready (last exit code {}).",
                release.number, o.restarts, o.last_exit_code
            ));
        }
    }
    let deadline = Duration::seconds(i64::from(pass.work.settings.rollout.ready_deadline_seconds));
    if pass.now - replica.placed_at < deadline
        || pass.available(replica)
        || pass.ever_ready(replica)
    {
        return None;
    }
    let span = span_words(deadline);
    let last = observation
        .map(|o| o.reason.clone())
        .filter(|r| !r.is_empty());
    Some(match (observation.map(|o| o.state), &release.spec.check) {
        (Some(Observed::Pulling | Observed::Failed), _) | (None, _) => format!(
            "v{} didn't start on {machine} within {span}{}.",
            release.number,
            last.map_or(String::new(), |r| format!(": {r}"))
        ),
        (_, Some(check)) => format!(
            "v{} didn't become ready: its check on {} failed for {span}{}.",
            release.number,
            match &check.kind {
                super::spec::CheckKind::Http { path } => format!("{path} (port {})", check.port),
                super::spec::CheckKind::Tcp => format!("port {}", check.port),
            },
            last.map_or(String::new(), |r| format!(" (last answer: {r})"))
        ),
        (_, None) => format!(
            "v{} didn't keep running within {span}{}.",
            release.number,
            last.map_or(String::new(), |r| format!(": {r}"))
        ),
    })
}

/// A span in the customer's words: seconds below two minutes, else whole
/// minutes (a 90 s deadline is "90 s", never "2 min").
pub fn span_words(span: Duration) -> String {
    let seconds = span.num_seconds();
    if seconds < 120 || seconds % 60 != 0 {
        format!("{seconds} s")
    } else {
        format!("{} min", seconds / 60)
    }
}

fn fail_rollout(pass: &mut Pass<'_>, reason: String) {
    let Some(rollout) = pass.work.rollout.clone() else {
        return;
    };
    let rolled_back = pass.work.settings.auto_rollback;
    let now = pass.now;
    pass.emit(AppEvent::RolloutFailed {
        rollout_id: rollout.rollout_id,
        reason,
        rolled_back,
        failed_at: now,
    });
    if !rolled_back {
        return;
    }
    let never_ready: Vec<Uuid> = pass
        .running()
        .into_iter()
        .filter(|r| r.release == rollout.to && !pass.ever_ready(r))
        .map(|r| r.replica_id)
        .collect();
    for replica_id in never_ready {
        pass.emit(AppEvent::ReplicaRemoved {
            replica_id,
            removed_at: now,
        });
    }
}

fn fail_rollout_on_a_bad_replica(pass: &mut Pass<'_>) {
    let Some(rollout) = pass.work.rollout.clone() else {
        return;
    };
    let Some(release) = pass.work.release(rollout.to).cloned() else {
        return;
    };
    let reason = pass
        .running()
        .iter()
        .filter(|r| r.release == rollout.to)
        .find_map(|r| failure_reason(pass, r, &release));
    if let Some(reason) = reason {
        fail_rollout(pass, reason);
    }
}

fn converge(pass: &mut Pass<'_>, lost_slots: &BTreeSet<u32>, new_id: &mut dyn FnMut() -> Uuid) {
    let Some(target) = pass
        .work
        .target()
        .and_then(|t| pass.work.release(t).cloned())
    else {
        for replica in pass.running() {
            pass.drain(replica.replica_id, DrainReason::NoRelease);
        }
        return;
    };
    let copies = pass.work.settings.copies;
    let max_surge = pass.work.settings.rollout.max_surge;
    let max_unavailable = pass.work.settings.rollout.max_unavailable;
    for replica in pass.running() {
        if replica.slot >= copies {
            pass.drain(replica.replica_id, DrainReason::ScaledDown);
        }
    }
    for slot in 0..copies {
        let mut in_slot: Vec<Replica> = pass
            .running()
            .into_iter()
            .filter(|r| r.slot == slot)
            .collect();
        in_slot.sort_by_key(|r| std::cmp::Reverse(r.placement));
        let newest = in_slot.iter().find(|r| r.release == target.number).cloned();
        if let Some(newest) = newest {
            let keep_other = if pass.available(&newest) {
                None
            } else {
                in_slot
                    .iter()
                    .find(|r| r.replica_id != newest.replica_id && pass.available(r))
                    .map(|r| r.replica_id)
            };
            for other in &in_slot {
                if other.replica_id != newest.replica_id && Some(other.replica_id) != keep_other {
                    let reason = DrainReason::Replaced;
                    if pass.available(&newest) || !pass.available(other) {
                        pass.drain(other.replica_id, reason);
                    }
                }
            }
            continue;
        }
        let best = in_slot
            .iter()
            .find(|r| pass.available(r))
            .or(in_slot.first())
            .cloned();
        for other in &in_slot {
            if Some(other.replica_id) != best.as_ref().map(|b| b.replica_id) {
                pass.drain(other.replica_id, DrainReason::Replaced);
            }
        }
        let Some(old) = best else {
            let reason = if lost_slots.contains(&slot) {
                PlaceReason::ReplaceLost
            } else if pass.work.rollout.is_some() {
                PlaceReason::Rollout
            } else {
                PlaceReason::Scale
            };
            if let Err(unplaceable) = pass.place(slot, &target, reason, None, new_id) {
                pass.wait(slot, unplaceable, &target);
            }
            continue;
        };
        let running_in_range = pass.running().iter().filter(|r| r.slot < copies).count() as u32;
        if running_in_range < copies + max_surge {
            match pass.place(
                slot,
                &target,
                PlaceReason::Rollout,
                Some(old.machine_id),
                new_id,
            ) {
                Ok(_) => {}
                Err(Unplaceable::InsufficientResources)
                    if (copies == 1 || pass.unavailable_slots(copies) == 0)
                        && pass.fits_without(&target, &old) =>
                {
                    pass.drain(old.replica_id, DrainReason::NoRoom);
                }
                Err(unplaceable) => pass.wait(slot, unplaceable, &target),
            }
        } else if max_unavailable > 0 && pass.unavailable_slots(copies) < max_unavailable {
            pass.drain(old.replica_id, DrainReason::Replaced);
        }
    }
    if let Some(rollout) = pass.work.rollout.clone() {
        let deadline =
            Duration::seconds(i64::from(pass.work.settings.rollout.ready_deadline_seconds));
        if let Some(waiting) = pass.waiting.first().cloned()
            && pass.now - rollout.started_at >= deadline
        {
            fail_rollout(
                pass,
                format!(
                    "v{} couldn't be placed for {}: {}",
                    rollout.to,
                    span_words(deadline),
                    waiting.message
                ),
            );
        }
    }
}

fn finish_rollout(pass: &mut Pass<'_>) {
    let Some(rollout) = pass.work.rollout.clone() else {
        return;
    };
    let copies = pass.work.settings.copies;
    let running = pass.running();
    let every_slot_ready = (0..copies).all(|slot| {
        running
            .iter()
            .any(|r| r.slot == slot && r.release == rollout.to && pass.available(r))
    });
    let only_target = running
        .iter()
        .all(|r| r.release == rollout.to && r.slot < copies);
    if every_slot_ready && only_target {
        let now = pass.now;
        pass.emit(AppEvent::RolloutSucceeded {
            rollout_id: rollout.rollout_id,
            succeeded_at: now,
        });
        if pass.work.current_release != Some(rollout.to) {
            pass.emit(AppEvent::CurrentReleaseSet {
                release: rollout.to,
                set_at: now,
            });
        }
    }
}

fn repair_spread(pass: &mut Pass<'_>, new_id: &mut dyn FnMut() -> Uuid) {
    if pass.work.rollout.is_some() || !pass.waiting.is_empty() || !pass.events.is_empty() {
        return;
    }
    if pass
        .work
        .last_spread_move
        .is_some_and(|at| pass.now - at < SPREAD_MOVE_EVERY)
    {
        return;
    }
    let Some(target) = pass
        .work
        .target()
        .and_then(|t| pass.work.release(t).cloned())
    else {
        return;
    };
    let copies = pass.work.settings.copies;
    let running = pass.running();
    if running.len() as u32 != copies
        || pass.unavailable_slots(copies) > 0
        || running.iter().any(|r| r.release != target.number)
    {
        return;
    }
    let mut crowded: Vec<(u32, Uuid)> = Vec::new();
    for replica in &running {
        let count = running
            .iter()
            .filter(|r| r.machine_id == replica.machine_id)
            .count() as u32;
        if count >= 2 && !crowded.iter().any(|(_, m)| *m == replica.machine_id) {
            crowded.push((count, replica.machine_id));
        }
    }
    crowded.sort_by_key(|(count, machine)| (std::cmp::Reverse(*count), *machine));
    let Some((_, machine_id)) = crowded.first().copied() else {
        return;
    };
    let usage = |id: Uuid| pass.usage(id);
    let Ok(chosen) = placement::place(
        &target,
        &pass.work.settings,
        pass.machines,
        &usage,
        None,
        pass.now,
    ) else {
        return;
    };
    if chosen == machine_id || pass.usage(chosen).running > 0 {
        return;
    }
    let Some(slot) = running
        .iter()
        .filter(|r| r.machine_id == machine_id)
        .map(|r| r.slot)
        .max()
    else {
        return;
    };
    let placement = pass.work.next_placement;
    let now = pass.now;
    pass.emit(AppEvent::ReplicaPlaced {
        replica_id: new_id(),
        slot,
        release: target.number,
        machine_id: chosen,
        placement,
        reason: PlaceReason::Spread,
        placed_at: now,
    });
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use mire::{Aggregate, Command};

    use super::*;
    use crate::app::{
        AppCommand, AppName, AppSettings, ReleaseSource,
        spec::{AppSpec, CheckKind, CheckSpec, PortSpec, Protocol, SettingsInput, StopSpec},
    };

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Behaviour {
        Healthy,
        NeverReady,
        CrashLoop,
        Refused,
    }

    struct World {
        app: App,
        machines: Vec<MachineView>,
        observations: HashMap<Uuid, (Observation, DateTime<Utc>)>,
        behaviour: HashMap<u32, Behaviour>,
        now: DateTime<Utc>,
        ids: u128,
        log: Vec<AppEvent>,
        waiting: Vec<Waiting>,
        gate_idle: bool,
    }

    fn start() -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).unwrap()
    }

    fn machine(id: u128, memory_mib: u64) -> MachineView {
        MachineView {
            machine_id: Uuid::from_u128(id),
            name: format!("web-{id}"),
            last_seen: Some(start()),
            apps: true,
            arch: "x86_64".into(),
            memory_mib,
            cpu_millis: 4000,
            reserved_memory_mib: 0,
            reserved_cpu_millis: 0,
            max_replica_memory_mib: 0,
            max_replica_cpu_millis: 0,
        }
    }

    fn spec(memory_mib: u64) -> AppSpec {
        AppSpec {
            image: "nginx".into(),
            command: Vec::new(),
            ports: vec![PortSpec {
                name: "http".into(),
                port: 80,
                protocol: Protocol::Http,
                public: false,
            }],
            memory_mib,
            cpu_millis: 100,
            env: Vec::new(),
            secrets: Vec::new(),
            check: Some(CheckSpec {
                kind: CheckKind::Http {
                    path: "/healthz".into(),
                },
                port: 80,
                interval_ms: 2000,
                timeout_ms: 1000,
            }),
            stop: StopSpec::default(),
        }
    }

    impl World {
        fn new(copies: u32, machines: Vec<MachineView>) -> Self {
            let settings = AppSettings::validate(SettingsInput {
                copies: Some(copies),
                ..Default::default()
            })
            .unwrap();
            let mut app = App::default();
            for event in (AppCommand::Create {
                actor: Uuid::nil(),
                organisation_id: Uuid::from_u128(1),
                name: AppName::parse("shop").unwrap(),
                settings,
                at: start(),
            })
            .handle(&App::default())
            .unwrap()
            {
                app.apply(&event);
            }
            Self {
                app,
                machines,
                observations: HashMap::new(),
                behaviour: HashMap::new(),
                now: start(),
                ids: 1000,
                log: Vec::new(),
                waiting: Vec::new(),
                gate_idle: false,
            }
        }

        fn configure(&mut self, input: SettingsInput) {
            let mut input = input;
            if input.copies.is_none() {
                input.copies = Some(self.app.settings.copies);
            }
            let settings = AppSettings::validate(input).unwrap();
            for event in (AppCommand::Configure {
                actor: Uuid::nil(),
                settings,
                at: self.now,
            })
            .handle(&self.app)
            .unwrap()
            {
                self.app.apply(&event);
            }
        }

        fn deploy(&mut self, memory_mib: u64, behaviour: Behaviour) -> u32 {
            let number = self.app.releases.last().map_or(1, |r| r.number + 1);
            self.behaviour.insert(number, behaviour);
            for event in (AppCommand::Release {
                actor: Uuid::nil(),
                spec: spec(memory_mib),
                image_digest: format!("sha256:{}", "c".repeat(64)),
                platforms: Vec::new(),
                secret_versions: Vec::new(),
                source: ReleaseSource::Api,
                rollback_of: None,
                note: String::new(),
                rollout_id: Uuid::from_u128(u128::from(number)),
                at: self.now,
            })
            .handle(&self.app)
            .unwrap()
            {
                self.app.apply(&event);
                self.log.push(event);
            }
            number
        }

        fn observed(&self) -> Vec<Observation> {
            self.observations.values().map(|(o, _)| o.clone()).collect()
        }

        fn decide(&mut self) -> Decision {
            let mut ids = self.ids;
            let decision = reconcile(
                &self.app,
                &self.observed(),
                &self.machines,
                self.now,
                &mut || {
                    ids += 1;
                    Uuid::from_u128(ids)
                },
            );
            self.ids = ids;
            decision
        }

        fn pass(&mut self) -> Vec<AppEvent> {
            let decision = self.decide();
            for event in &decision.events {
                self.app.apply(event);
            }
            self.log.extend(decision.events.clone());
            self.waiting = decision.waiting;
            decision.events
        }

        fn machine_up(&self, id: Uuid) -> bool {
            self.machines
                .iter()
                .any(|m| m.machine_id == id && m.connected(self.now))
        }

        fn tick(&mut self, seconds: i64) {
            self.now += Duration::seconds(seconds);
            for machine in &mut self.machines {
                if machine
                    .last_seen
                    .is_some_and(|s| s >= self.now - Duration::seconds(seconds + 1))
                {
                    machine.last_seen = Some(self.now);
                }
            }
            let replicas = self.app.replicas.clone();
            self.observations
                .retain(|id, _| replicas.iter().any(|r| r.replica_id == *id));
            for replica in replicas {
                if !self.machine_up(replica.machine_id) {
                    continue;
                }
                let behaviour = self.behaviour[&replica.release];
                let now = self.now;
                let entry = self.observations.entry(replica.replica_id).or_insert((
                    Observation {
                        replica_id: replica.replica_id,
                        state: Observed::Starting,
                        ready: false,
                        ready_since: None,
                        ever_ready: false,
                        restarts: 0,
                        last_exit_code: 0,
                        reason: String::new(),
                        idle: false,
                    },
                    now,
                ));
                let (o, since) = entry;
                o.idle = self.gate_idle && replica.state == ReplicaState::Draining;
                let age = now - *since;
                match behaviour {
                    Behaviour::Healthy if age >= Duration::seconds(2) => {
                        if !o.ready {
                            o.ready = true;
                            o.ever_ready = true;
                            o.ready_since = Some(now);
                        }
                        o.state = Observed::Running;
                    }
                    Behaviour::Healthy => {}
                    Behaviour::NeverReady => {
                        o.state = Observed::Running;
                        o.reason = "status 502".into();
                    }
                    Behaviour::CrashLoop => {
                        o.state = Observed::Exited;
                        o.restarts += 1;
                        o.last_exit_code = 1;
                    }
                    Behaviour::Refused => {
                        o.state = Observed::Refused;
                        o.reason = "privileged".into();
                    }
                }
            }
        }

        fn available(&self) -> Vec<Replica> {
            let min_ready =
                Duration::seconds(i64::from(self.app.settings.rollout.min_ready_seconds));
            self.app
                .replicas
                .iter()
                .filter(|r| r.state == ReplicaState::Running && self.machine_up(r.machine_id))
                .filter(|r| {
                    self.observations.get(&r.replica_id).is_some_and(|(o, _)| {
                        o.ready && o.ready_since.is_some_and(|s| self.now - s >= min_ready)
                    })
                })
                .cloned()
                .collect()
        }

        fn run(&mut self, seconds: i64, mut check: impl FnMut(&World)) {
            for _ in 0..seconds {
                self.pass();
                check(self);
                self.tick(1);
            }
        }

        fn settled(&mut self) {
            self.run(120, |_| {});
        }

        fn releases_running(&self) -> Vec<u32> {
            let mut releases: Vec<u32> = self
                .app
                .replicas
                .iter()
                .filter(|r| r.state == ReplicaState::Running)
                .map(|r| r.release)
                .collect();
            releases.sort();
            releases
        }

        fn count(&self, matches: impl Fn(&AppEvent) -> bool) -> usize {
            self.log.iter().filter(|e| matches(e)).count()
        }
    }

    #[test]
    fn a_span_is_said_in_seconds_below_two_minutes_and_whole_minutes_above() {
        assert_eq!(span_words(Duration::seconds(90)), "90 s");
        assert_eq!(span_words(Duration::seconds(60)), "60 s");
        assert_eq!(span_words(Duration::seconds(300)), "5 min");
        assert_eq!(span_words(Duration::seconds(150)), "150 s");
    }

    #[test]
    fn a_first_release_places_every_copy_spread_and_goes_live() {
        let mut world = World::new(2, vec![machine(1, 4096), machine(2, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        let placed = world.pass();
        let machines: BTreeSet<Uuid> = placed
            .iter()
            .filter_map(|e| match e {
                AppEvent::ReplicaPlaced { machine_id, .. } => Some(*machine_id),
                _ => None,
            })
            .collect();
        assert_eq!(machines.len(), 2, "two copies on two machines");
        world.settled();
        assert_eq!(world.app.current_release, Some(1));
        assert!(world.app.rollout.is_none());
        assert_eq!(world.available().len(), 2);
        assert_eq!(
            world.count(|e| matches!(e, AppEvent::RolloutSucceeded { .. })),
            1
        );
    }

    #[test]
    fn a_pass_with_nothing_changed_decides_nothing() {
        let mut world = World::new(2, vec![machine(1, 4096), machine(2, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        assert!(world.decide().events.is_empty());
        assert!(world.decide().events.is_empty());
    }

    #[test]
    fn a_rolling_release_never_drops_below_the_copies_that_are_ready() {
        let mut world = World::new(2, vec![machine(1, 4096), machine(2, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        world.deploy(512, Behaviour::Healthy);
        let mut most = 0;
        world.run(180, |w| {
            assert!(
                w.available().len() >= 2,
                "fewer than 2 ready copies at {}",
                w.now
            );
            let running = w
                .app
                .replicas
                .iter()
                .filter(|r| r.state == ReplicaState::Running)
                .count();
            most = most.max(running);
        });
        assert_eq!(most, 3, "at most one surge copy at a time");
        assert_eq!(world.app.current_release, Some(2));
        assert_eq!(world.releases_running(), vec![2, 2]);
        assert!(
            world
                .app
                .replicas
                .iter()
                .all(|r| r.state == ReplicaState::Running)
        );
    }

    #[test]
    fn the_surge_copy_goes_on_the_machine_of_the_copy_it_replaces() {
        let mut world = World::new(2, vec![machine(1, 4096), machine(2, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        let before: HashMap<u32, Uuid> = world
            .app
            .replicas
            .iter()
            .map(|r| (r.slot, r.machine_id))
            .collect();
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        for replica in &world.app.replicas {
            assert_eq!(before[&replica.slot], replica.machine_id);
        }
    }

    #[test]
    fn a_release_that_never_becomes_ready_rolls_back_on_its_own_without_touching_the_old() {
        let mut world = World::new(2, vec![machine(1, 4096), machine(2, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        let old: BTreeSet<Uuid> = world.app.replicas.iter().map(|r| r.replica_id).collect();
        world.deploy(512, Behaviour::NeverReady);
        world.run(400, |w| {
            assert_eq!(w.available().len(), 2, "the old copies keep serving");
        });
        let failed = world
            .log
            .iter()
            .find_map(|e| match e {
                AppEvent::RolloutFailed {
                    reason,
                    rolled_back,
                    ..
                } => Some((reason.clone(), *rolled_back)),
                _ => None,
            })
            .expect("the rollout failed");
        assert!(failed.1);
        assert!(failed.0.contains("/healthz"), "{}", failed.0);
        assert!(failed.0.contains("status 502"), "{}", failed.0);
        assert!(failed.0.contains("failed for 5 min"), "{}", failed.0);
        assert_eq!(world.app.current_release, Some(1));
        assert!(world.app.rollout.is_none());
        let now: BTreeSet<Uuid> = world.app.replicas.iter().map(|r| r.replica_id).collect();
        assert_eq!(old, now);
        assert!(world.decide().events.is_empty());
    }

    #[test]
    fn a_release_that_keeps_exiting_fails_after_three_exits_not_the_deadline() {
        let mut world = World::new(1, vec![machine(1, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        let deployed_at = world.now;
        world.deploy(512, Behaviour::CrashLoop);
        world.run(30, |_| {});
        let failed_at = world.log.iter().find_map(|e| match e {
            AppEvent::RolloutFailed {
                failed_at, reason, ..
            } => Some((*failed_at, reason.clone())),
            _ => None,
        });
        let (failed_at, reason) = failed_at.expect("failed within 30 s");
        assert!(failed_at - deployed_at < Duration::seconds(10));
        assert!(reason.contains("exited 3 times"), "{reason}");
        assert_eq!(world.releases_running(), vec![1]);
    }

    #[test]
    fn a_replica_the_machine_refuses_fails_its_release_at_once() {
        let mut world = World::new(1, vec![machine(1, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        world.deploy(512, Behaviour::Refused);
        world.run(5, |_| {});
        assert_eq!(
            world.count(|e| matches!(e, AppEvent::RolloutFailed { .. })),
            1
        );
        assert_eq!(world.releases_running(), vec![1]);
    }

    #[test]
    fn a_first_release_that_fails_leaves_nothing_running_and_no_current_release() {
        let mut world = World::new(2, vec![machine(1, 4096), machine(2, 4096)]);
        world.deploy(512, Behaviour::CrashLoop);
        world.run(60, |_| {});
        assert_eq!(world.app.current_release, None);
        assert!(world.app.rollout.is_none());
        assert!(world.app.replicas.is_empty());
        assert!(world.decide().events.is_empty());
    }

    #[test]
    fn with_rollback_off_a_failed_release_halts_the_app_as_it_is() {
        let mut world = World::new(1, vec![machine(1, 4096)]);
        world.configure(SettingsInput {
            auto_rollback: Some(false),
            ..Default::default()
        });
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        world.deploy(512, Behaviour::CrashLoop);
        world.run(60, |_| {});
        assert!(world.app.halted);
        assert_eq!(world.releases_running(), vec![1, 2]);
        assert!(world.decide().events.is_empty());
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        assert_eq!(world.app.current_release, Some(3));
        assert_eq!(world.releases_running(), vec![3]);
    }

    #[test]
    fn a_newer_release_supersedes_one_rolling_out() {
        let mut world = World::new(2, vec![machine(1, 4096), machine(2, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        world.deploy(512, Behaviour::NeverReady);
        world.run(5, |_| {});
        world.deploy(512, Behaviour::Healthy);
        world.run(200, |w| assert!(w.available().len() >= 2));
        assert_eq!(
            world.count(|e| matches!(e, AppEvent::RolloutSuperseded { by: 3, .. })),
            1
        );
        assert_eq!(world.app.current_release, Some(3));
        assert_eq!(world.releases_running(), vec![3, 3]);
    }

    #[test]
    fn a_machine_down_past_reschedule_after_has_its_copy_started_elsewhere() {
        let mut world = World::new(
            2,
            vec![machine(1, 4096), machine(2, 4096), machine(3, 4096)],
        );
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        let victim = world.app.replicas[0].clone();
        world
            .machines
            .iter_mut()
            .find(|m| m.machine_id == victim.machine_id)
            .unwrap()
            .last_seen = Some(world.now);
        let down_at = world.now;
        let id = victim.machine_id;
        let mut machines = world.machines.clone();
        machines
            .iter_mut()
            .find(|m| m.machine_id == id)
            .unwrap()
            .last_seen = Some(down_at);
        world.machines = machines;
        world.tick(0);
        for _ in 0..119 {
            world.pass();
            world.now += Duration::seconds(1);
            for m in world.machines.iter_mut().filter(|m| m.machine_id != id) {
                m.last_seen = Some(world.now);
            }
        }
        assert!(
            world.app.replica(victim.replica_id).is_some(),
            "not before 2 min"
        );
        world.now += Duration::seconds(1);
        for m in world.machines.iter_mut().filter(|m| m.machine_id != id) {
            m.last_seen = Some(world.now);
        }
        let events = world.pass();
        assert!(events.iter().any(|e| matches!(e, AppEvent::ReplicaLost { replica_id, .. } if *replica_id == victim.replica_id)));
        let replacement = events.iter().find_map(|e| match e {
            AppEvent::ReplicaPlaced {
                machine_id,
                reason: PlaceReason::ReplaceLost,
                slot,
                ..
            } => Some((*machine_id, *slot)),
            _ => None,
        });
        let (machine_id, slot) = replacement.expect("replaced at once");
        assert_ne!(machine_id, id);
        assert_eq!(slot, victim.slot);
    }

    #[test]
    fn with_no_room_for_a_surge_a_single_copy_stops_before_its_successor_starts() {
        let mut world = World::new(1, vec![machine(1, 256 + 600)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        world.deploy(512, Behaviour::Healthy);
        let events = world.pass();
        assert!(events.iter().any(|e| matches!(
            e,
            AppEvent::ReplicaDraining {
                reason: DrainReason::NoRoom,
                ..
            }
        )));
        world.settled();
        assert_eq!(world.app.current_release, Some(2));
        assert_eq!(world.releases_running(), vec![2]);
    }

    #[test]
    fn with_no_room_two_copies_are_replaced_one_at_a_time() {
        let mut world = World::new(2, vec![machine(1, 256 + 1100)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        world.deploy(512, Behaviour::Healthy);
        world.run(300, |w| {
            assert!(!w.available().is_empty(), "one copy keeps serving")
        });
        assert_eq!(world.app.current_release, Some(2));
        assert_eq!(world.releases_running(), vec![2, 2]);
    }

    #[test]
    fn nothing_to_run_on_is_waiting_with_a_reason_not_an_event() {
        let mut world = World::new(1, Vec::new());
        world.deploy(512, Behaviour::Healthy);
        let events = world.pass();
        assert!(events.is_empty());
        assert_eq!(world.waiting.len(), 1);
        assert_eq!(world.waiting[0].reason, Unplaceable::NoMachine);
        assert!(world.waiting[0].message.contains("shop needs a machine"));
    }

    #[test]
    fn a_release_that_cannot_be_placed_until_its_deadline_fails() {
        let mut world = World::new(1, vec![machine(1, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        world.deploy(8192, Behaviour::Healthy);
        world.run(301, |_| {});
        let reason = world.log.iter().find_map(|e| match e {
            AppEvent::RolloutFailed { reason, .. } => Some(reason.clone()),
            _ => None,
        });
        assert!(reason.expect("failed").contains("couldn't be placed"));
        assert_eq!(world.releases_running(), vec![1]);
    }

    #[test]
    fn scaling_up_adds_copies_of_the_current_release_and_down_drains_the_highest_slots() {
        let mut world = World::new(1, vec![machine(1, 4096), machine(2, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        world.configure(SettingsInput {
            copies: Some(3),
            ..Default::default()
        });
        let events = world.pass();
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(
                    e,
                    AppEvent::ReplicaPlaced {
                        reason: PlaceReason::Scale,
                        ..
                    }
                ))
                .count(),
            2
        );
        assert_eq!(
            world.count(|e| matches!(e, AppEvent::ReleaseCreated { .. })),
            1
        );
        world.settled();
        assert_eq!(world.available().len(), 3);
        world.configure(SettingsInput {
            copies: Some(1),
            ..Default::default()
        });
        world.settled();
        let slots: Vec<u32> = world.app.replicas.iter().map(|r| r.slot).collect();
        assert_eq!(slots, vec![0]);
    }

    #[test]
    fn a_machine_that_comes_back_gets_a_copy_back_from_a_crowded_one() {
        let mut world = World::new(2, vec![machine(1, 4096), machine(2, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        let gone = world.machines.remove(1);
        world.settled();
        let on: BTreeSet<Uuid> = world.app.replicas.iter().map(|r| r.machine_id).collect();
        assert_eq!(on.len(), 1, "both copies on the one machine left");
        let mut back = gone;
        back.last_seen = Some(world.now);
        world.machines.push(back.clone());
        world.run(400, |w| assert!(w.available().len() >= 2));
        let on: BTreeSet<Uuid> = world.app.replicas.iter().map(|r| r.machine_id).collect();
        assert_eq!(on.len(), 2, "spread again");
        assert_eq!(
            world.count(|e| matches!(
                e,
                AppEvent::ReplicaPlaced {
                    reason: PlaceReason::Spread,
                    ..
                }
            )),
            1
        );
    }

    #[test]
    fn a_draining_copy_is_removed_after_the_drain_and_not_before() {
        let mut world = World::new(1, vec![machine(1, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        world.deploy(512, Behaviour::Healthy);
        let mut drained_at = None;
        let mut removed_at = None;
        world.run(120, |w| {
            for event in &w.log {
                match event {
                    AppEvent::ReplicaDraining { draining_at, .. } if drained_at.is_none() => {
                        drained_at = Some(*draining_at)
                    }
                    AppEvent::ReplicaRemoved { removed_at: at, .. } if removed_at.is_none() => {
                        removed_at = Some(*at)
                    }
                    _ => {}
                }
            }
        });
        let gap = removed_at.unwrap() - drained_at.unwrap();
        assert_eq!(gap, Duration::seconds(30));
    }

    #[test]
    fn a_draining_copy_the_gate_reports_idle_is_removed_before_its_drain_ends() {
        let mut world = World::new(1, vec![machine(1, 4096)]);
        world.gate_idle = true;
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        world.deploy(512, Behaviour::Healthy);
        let mut drained_at = None;
        let mut removed_at = None;
        world.run(120, |w| {
            for event in &w.log {
                match event {
                    AppEvent::ReplicaDraining { draining_at, .. } if drained_at.is_none() => {
                        drained_at = Some(*draining_at)
                    }
                    AppEvent::ReplicaRemoved { removed_at: at, .. } if removed_at.is_none() => {
                        removed_at = Some(*at)
                    }
                    _ => {}
                }
            }
        });
        let gap = removed_at.unwrap() - drained_at.unwrap();
        assert!(gap <= Duration::seconds(2), "{gap}");
    }

    #[test]
    fn a_replica_on_a_machine_that_left_the_organisation_is_lost_at_once() {
        let mut world = World::new(1, vec![machine(1, 4096), machine(2, 4096)]);
        world.deploy(512, Behaviour::Healthy);
        world.settled();
        let on = world.app.replicas[0].machine_id;
        world.machines.retain(|m| m.machine_id != on);
        let events = world.pass();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, AppEvent::ReplicaLost { .. }))
        );
        assert!(events.iter().any(|e| matches!(
            e,
            AppEvent::ReplicaPlaced {
                reason: PlaceReason::ReplaceLost,
                ..
            }
        )));
    }
}
