//! Where a new replica runs (grund-docs design/apps.md §5): filter the
//! machines that can run it, then score them, spread first. Pure: the
//! caller passes what each machine reported and what is already reserved on
//! it.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{AppSettings, Release};

/// A machine is unreachable once its last report is older than this
/// (six missed 5 s heartbeats, apps.md §9.2).
pub const UNREACHABLE_AFTER: Duration = Duration::seconds(30);

/// Memory kept back on every machine for the agent and the runtime.
pub const RESERVED_MEMORY_MIB: u64 = 256;
/// CPU kept back on every machine for the agent and the runtime.
pub const RESERVED_CPU_MILLIS: u32 = 250;

/// One of the organisation's machines, as placement sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineView {
    pub machine_id: Uuid,
    pub name: String,
    /// When its agent last reported; `None`: never.
    pub last_seen: Option<DateTime<Utc>>,
    /// It reported the apps capability.
    pub apps: bool,
    /// `x86_64` or `aarch64`, as reported.
    pub arch: String,
    pub memory_mib: u64,
    pub cpu_millis: u32,
    /// What replicas of the organisation's other apps reserve on it.
    pub reserved_memory_mib: u64,
    pub reserved_cpu_millis: u32,
    /// The owner's caps on one replica (apps.md §6.4); 0: none.
    pub max_replica_memory_mib: u64,
    pub max_replica_cpu_millis: u32,
}

impl MachineView {
    pub fn connected(&self, now: DateTime<Utc>) -> bool {
        self.last_seen
            .is_some_and(|seen| now - seen <= UNREACHABLE_AFTER)
    }

    /// Memory replicas may reserve here in all.
    pub fn allocatable_memory_mib(&self) -> u64 {
        self.memory_mib.saturating_sub(RESERVED_MEMORY_MIB)
    }

    pub fn allocatable_cpu_millis(&self) -> u32 {
        self.cpu_millis.saturating_sub(RESERVED_CPU_MILLIS)
    }
}

/// What this app already has on one machine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Its replicas that should run there (not draining).
    pub running: u32,
    /// What all its replicas there reserve, draining ones included: they
    /// still run.
    pub memory_mib: u64,
    pub cpu_millis: u32,
}

/// Why no machine can take the replica now (apps.md §5.4). Ordered: a later
/// reason means a machine got further through the filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unplaceable {
    NoMachine,
    NoCapability,
    NoArchitecture,
    RefusedByMachine,
    InsufficientResources,
}

impl Unplaceable {
    pub fn as_str(self) -> &'static str {
        match self {
            Unplaceable::NoMachine => "no_machine",
            Unplaceable::NoCapability => "no_capability",
            Unplaceable::NoArchitecture => "no_architecture",
            Unplaceable::RefusedByMachine => "refused_by_machine",
            Unplaceable::InsufficientResources => "insufficient_resources",
        }
    }

    /// In words for the customer.
    pub fn message(self, app: &str, release: &Release) -> String {
        match self {
            Unplaceable::NoMachine => {
                format!(
                    "{app} needs a machine to run on. Add a machine, or check that yours are connected."
                )
            }
            Unplaceable::NoCapability => format!(
                "{app} needs a machine that can run containers. None of your connected machines can."
            ),
            Unplaceable::NoArchitecture => format!(
                "The image has no version for your machines' architecture (it offers {}).",
                release.platforms.join(", ")
            ),
            Unplaceable::RefusedByMachine => format!(
                "Your machines' owners allow less memory or CPU per copy than {app} asks for."
            ),
            Unplaceable::InsufficientResources => format!(
                "No machine has {} MiB of memory and {} CPU free. Add a machine, or give {app} less.",
                release.spec.memory_mib,
                format_cpu(release.spec.cpu_millis)
            ),
        }
    }
}

fn format_cpu(millis: u32) -> String {
    if millis.is_multiple_of(1000) {
        (millis / 1000).to_string()
    } else {
        format!("{:.2}", f64::from(millis) / 1000.0)
    }
}

/// The machine for one new replica of `release`, or why there is none.
/// `usage(machine)` is what this app already has there. `prefer` is the
/// machine of the replica a surge replaces: kept when it fits, so the app
/// keeps its spread.
pub fn place(
    release: &Release,
    settings: &AppSettings,
    machines: &[MachineView],
    usage: &dyn Fn(Uuid) -> Usage,
    prefer: Option<Uuid>,
    now: DateTime<Utc>,
) -> Result<Uuid, Unplaceable> {
    let memory = release.spec.memory_mib;
    let cpu = release.spec.cpu_millis;
    let mut furthest = Unplaceable::NoMachine;
    let mut candidates: Vec<(&MachineView, Usage)> = Vec::new();
    for machine in machines {
        if !machine.connected(now)
            || (!settings.machines.is_empty() && !settings.machines.contains(&machine.name))
        {
            continue;
        }
        if !machine.apps {
            furthest = furthest.max(Unplaceable::NoCapability);
            continue;
        }
        if !release.platforms.is_empty() && !release.platforms.contains(&machine.arch) {
            furthest = furthest.max(Unplaceable::NoArchitecture);
            continue;
        }
        if (machine.max_replica_memory_mib > 0 && memory > machine.max_replica_memory_mib)
            || (machine.max_replica_cpu_millis > 0 && cpu > machine.max_replica_cpu_millis)
        {
            furthest = furthest.max(Unplaceable::RefusedByMachine);
            continue;
        }
        let used = usage(machine.machine_id);
        let free_memory = machine
            .allocatable_memory_mib()
            .saturating_sub(machine.reserved_memory_mib + used.memory_mib);
        let free_cpu = machine
            .allocatable_cpu_millis()
            .saturating_sub(machine.reserved_cpu_millis + used.cpu_millis);
        if memory > free_memory || cpu > free_cpu {
            furthest = furthest.max(Unplaceable::InsufficientResources);
            continue;
        }
        candidates.push((machine, used));
    }
    candidates
        .into_iter()
        .min_by_key(|(machine, used)| {
            let reserved = machine.reserved_memory_mib + used.memory_mib;
            let share =
                reserved.saturating_mul(1_000_000) / machine.allocatable_memory_mib().max(1);
            (
                used.running,
                prefer != Some(machine.machine_id),
                share,
                machine.machine_id,
            )
        })
        .map(|(machine, _)| machine.machine_id)
        .ok_or(furthest)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::app::{
        ReleaseSource,
        spec::{AppSpec, StopSpec},
    };

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).unwrap()
    }

    fn release(memory_mib: u64, platforms: &[&str]) -> Release {
        Release {
            number: 1,
            spec: AppSpec {
                image: "nginx".into(),
                command: Vec::new(),
                ports: Vec::new(),
                memory_mib,
                cpu_millis: 500,
                env: Vec::new(),
                secrets: Vec::new(),
                check: None,
                stop: StopSpec::default(),
            },
            image_digest: String::new(),
            platforms: platforms.iter().map(|p| p.to_string()).collect(),
            secret_versions: Vec::new(),
            source: ReleaseSource::Api,
            rollback_of: None,
            note: String::new(),
            created_by: Uuid::nil(),
            created_at: now(),
        }
    }

    fn machine(id: u128, name: &str) -> MachineView {
        MachineView {
            machine_id: Uuid::from_u128(id),
            name: name.into(),
            last_seen: Some(now()),
            apps: true,
            arch: "x86_64".into(),
            memory_mib: 4096,
            cpu_millis: 4000,
            reserved_memory_mib: 0,
            reserved_cpu_millis: 0,
            max_replica_memory_mib: 0,
            max_replica_cpu_millis: 0,
        }
    }

    fn place_with(
        release: &Release,
        settings: &AppSettings,
        machines: &[MachineView],
        usage: HashMap<u128, Usage>,
        prefer: Option<u128>,
    ) -> Result<Uuid, Unplaceable> {
        place(
            release,
            settings,
            machines,
            &|id| usage.get(&id.as_u128()).copied().unwrap_or_default(),
            prefer.map(Uuid::from_u128),
            now(),
        )
    }

    #[test]
    fn copies_spread_over_machines_before_sharing_one() {
        let machines = [machine(1, "a"), machine(2, "b")];
        let usage = HashMap::from([(
            1,
            Usage {
                running: 1,
                memory_mib: 512,
                cpu_millis: 500,
            },
        )]);
        let chosen = place_with(
            &release(512, &[]),
            &AppSettings::default(),
            &machines,
            usage,
            None,
        );
        assert_eq!(chosen, Ok(Uuid::from_u128(2)));
    }

    #[test]
    fn a_surge_stays_on_the_machine_it_replaces_when_spread_ties() {
        let machines = [machine(1, "a"), machine(2, "b")];
        let one = Usage {
            running: 1,
            memory_mib: 512,
            cpu_millis: 500,
        };
        let usage = HashMap::from([(1, one), (2, one)]);
        let chosen = place_with(
            &release(512, &[]),
            &AppSettings::default(),
            &machines,
            usage,
            Some(2),
        );
        assert_eq!(chosen, Ok(Uuid::from_u128(2)));
    }

    #[test]
    fn with_one_machine_both_copies_share_it() {
        let usage = HashMap::from([(
            1,
            Usage {
                running: 1,
                memory_mib: 512,
                cpu_millis: 500,
            },
        )]);
        let chosen = place_with(
            &release(512, &[]),
            &AppSettings::default(),
            &[machine(1, "a")],
            usage,
            None,
        );
        assert_eq!(chosen, Ok(Uuid::from_u128(1)));
    }

    #[test]
    fn ties_go_to_the_least_allocated_then_the_lowest_id() {
        let mut busy = machine(1, "a");
        busy.reserved_memory_mib = 2048;
        let machines = [busy, machine(3, "c"), machine(2, "b")];
        let chosen = place_with(
            &release(512, &[]),
            &AppSettings::default(),
            &machines,
            HashMap::new(),
            None,
        );
        assert_eq!(chosen, Ok(Uuid::from_u128(2)));
    }

    #[test]
    fn the_reason_names_the_filter_a_machine_got_furthest_through() {
        let settings = AppSettings::default();
        let place = |machines: &[MachineView], release: &Release| {
            place_with(release, &settings, machines, HashMap::new(), None)
        };
        assert_eq!(place(&[], &release(512, &[])), Err(Unplaceable::NoMachine));
        let mut gone = machine(1, "a");
        gone.last_seen = Some(now() - Duration::seconds(31));
        assert_eq!(
            place(&[gone], &release(512, &[])),
            Err(Unplaceable::NoMachine)
        );
        let mut no_apps = machine(1, "a");
        no_apps.apps = false;
        assert_eq!(
            place(&[no_apps.clone()], &release(512, &[])),
            Err(Unplaceable::NoCapability)
        );
        let mut arm = machine(2, "pi");
        arm.arch = "aarch64".into();
        assert_eq!(
            place(&[no_apps, arm.clone()], &release(512, &["x86_64"])),
            Err(Unplaceable::NoArchitecture)
        );
        let mut capped = machine(3, "c");
        capped.max_replica_memory_mib = 256;
        assert_eq!(
            place(&[arm, capped], &release(512, &["x86_64"])),
            Err(Unplaceable::RefusedByMachine)
        );
        assert_eq!(
            place(&[machine(4, "d")], &release(4000, &[])),
            Err(Unplaceable::InsufficientResources)
        );
    }

    #[test]
    fn memory_reserved_by_this_and_other_apps_is_not_offered_again() {
        let mut m = machine(1, "a");
        m.reserved_memory_mib = 2048;
        let usage = HashMap::from([(
            1,
            Usage {
                running: 0,
                memory_mib: 1024,
                cpu_millis: 0,
            },
        )]);
        assert_eq!(
            place_with(
                &release(1024, &[]),
                &AppSettings::default(),
                &[m.clone()],
                usage.clone(),
                None
            ),
            Err(Unplaceable::InsufficientResources)
        );
        assert_eq!(
            place_with(
                &release(768, &[]),
                &AppSettings::default(),
                &[m],
                usage,
                None
            ),
            Ok(Uuid::from_u128(1))
        );
    }

    #[test]
    fn placement_by_name_keeps_copies_off_other_machines() {
        let settings = AppSettings {
            machines: vec!["b".into()],
            ..AppSettings::default()
        };
        let chosen = place_with(
            &release(512, &[]),
            &settings,
            &[machine(1, "a"), machine(2, "b")],
            HashMap::from([(
                2,
                Usage {
                    running: 3,
                    memory_mib: 1536,
                    cpu_millis: 1500,
                },
            )]),
            None,
        );
        assert_eq!(chosen, Ok(Uuid::from_u128(2)));
    }
}
