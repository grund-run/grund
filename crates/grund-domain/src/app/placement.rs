//! Where a new replica runs (grund-docs design/apps.md §5): filter the
//! machines that can run it, then score them, spread first. Pure: the
//! caller passes what each machine reported and what is already reserved on
//! it.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    AppSettings, Release,
    spec::{MachineKind, PlacementRules},
};
use crate::labels::{Labels, labels_text};

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
    /// What its owner labelled it (apps.md §5.6).
    #[serde(default)]
    pub labels: Labels,
    /// Taken out of service by its owner: nothing new is placed on it, and
    /// the copies on it move off (apps.md §5.7).
    #[serde(default)]
    pub cordoned: bool,
    #[serde(default = "own")]
    pub kind: MachineKind,
    /// The organisation's other apps with a copy on it, by name.
    #[serde(default)]
    pub running_apps: Vec<String>,
}

fn own() -> MachineKind {
    MachineKind::Own
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

    /// Its failure domain under `spread_by`: the label's value, or the
    /// empty domain every machine without the label shares.
    pub fn domain(&self, spread_by: Option<&str>) -> &str {
        spread_by
            .and_then(|key| self.labels.get(key))
            .map_or("", String::as_str)
    }
}

/// Whether the app's rules allow a copy on `machine`, its connection and
/// room aside: in service, named (when names are given), carrying every
/// label, of the kind asked for. A copy on a machine that no longer
/// matches moves off (apps.md §5.7).
pub fn allowed(settings: &AppSettings, machine: &MachineView) -> bool {
    let rules = &settings.placement;
    !machine.cordoned
        && (settings.machines.is_empty() || settings.machines.contains(&machine.name))
        && rules
            .labels
            .iter()
            .all(|(k, v)| machine.labels.get(k) == Some(v))
        && rules.kind.is_none_or(|kind| kind == machine.kind)
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
    /// Connected machines exist, but none the app's placement allows, or
    /// none in service.
    NoMatchingMachine,
    NoCapability,
    NoArchitecture,
    RefusedByMachine,
    InsufficientResources,
}

impl Unplaceable {
    pub fn as_str(self) -> &'static str {
        match self {
            Unplaceable::NoMachine => "no_machine",
            Unplaceable::NoMatchingMachine => "no_matching_machine",
            Unplaceable::NoCapability => "no_capability",
            Unplaceable::NoArchitecture => "no_architecture",
            Unplaceable::RefusedByMachine => "refused_by_machine",
            Unplaceable::InsufficientResources => "insufficient_resources",
        }
    }

    /// What the app waits for, as a fact (apps.md §8.5: no advice).
    pub fn message(self, release: &Release, settings: &AppSettings) -> String {
        let size = format!(
            "{} MiB of memory and {} CPU",
            release.spec.memory_mib,
            format_cpu(release.spec.cpu_millis)
        );
        match self {
            Unplaceable::NoMachine => "Waiting for a machine.".into(),
            Unplaceable::NoMatchingMachine => match rules_words(settings) {
                Some(words) => format!("Waiting for a machine {words}."),
                None => "Waiting for a machine in service.".into(),
            },
            Unplaceable::NoCapability => "Waiting for a machine that can run containers.".into(),
            Unplaceable::NoArchitecture => format!(
                "Waiting for a machine the image runs on ({}).",
                release.platforms.join(", ")
            ),
            Unplaceable::RefusedByMachine => {
                format!("Waiting for a machine that allows {size} per copy.")
            }
            Unplaceable::InsufficientResources => {
                format!("Waiting for a machine with {size} free.")
            }
        }
    }
}

/// The app's placement in words, `None` when it names nothing:
/// "named web-1 or web-2, labelled zone=a, of your own".
pub fn rules_words(settings: &AppSettings) -> Option<String> {
    let PlacementRules { labels, kind, .. } = &settings.placement;
    let mut parts = Vec::new();
    if !settings.machines.is_empty() {
        parts.push(format!("named {}", settings.machines.join(" or ")));
    }
    if !labels.is_empty() {
        parts.push(format!("labelled {}", labels_text(labels)));
    }
    match kind {
        Some(MachineKind::Own) => parts.push("of your own".into()),
        Some(MachineKind::Hosted) => parts.push("hosted by grund".into()),
        None => {}
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

fn format_cpu(millis: u32) -> String {
    if millis.is_multiple_of(1000) {
        (millis / 1000).to_string()
    } else {
        format!("{:.2}", f64::from(millis) / 1000.0)
            .trim_end_matches('0')
            .to_string()
    }
}

/// The machine for one new replica of `release`, or why there is none.
/// `usage(machine)` is what this app already has there. `prefer` is the
/// machine of the replica a surge replaces: kept when it fits, so the app
/// keeps its spread.
///
/// The score, lowest first (apps.md §5.3, §5.6): copies of the app in the
/// machine's failure domain (with `spread_by`), copies on the machine, not
/// the preferred machine, running none of the `near` apps, how many
/// `apart` apps it runs, the share of its memory reserved, its id.
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
    let rules = &settings.placement;
    let spread_by = rules.spread_by.as_deref();
    let mut furthest = Unplaceable::NoMachine;
    let mut candidates: Vec<(&MachineView, Usage)> = Vec::new();
    for machine in machines {
        if !machine.connected(now) {
            continue;
        }
        if !allowed(settings, machine) {
            furthest = furthest.max(Unplaceable::NoMatchingMachine);
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
    let in_domain = |domain: &str| -> u32 {
        spread_by.map_or(0, |_| {
            machines
                .iter()
                .filter(|m| m.domain(spread_by) == domain)
                .map(|m| usage(m.machine_id).running)
                .sum()
        })
    };
    candidates
        .into_iter()
        .min_by_key(|(machine, used)| {
            let reserved = machine.reserved_memory_mib + used.memory_mib;
            let share =
                reserved.saturating_mul(1_000_000) / machine.allocatable_memory_mib().max(1);
            let far = !rules.near.is_empty()
                && !rules.near.iter().any(|a| machine.running_apps.contains(a));
            let beside = rules
                .apart
                .iter()
                .filter(|a| machine.running_apps.contains(a))
                .count();
            (
                in_domain(machine.domain(spread_by)),
                used.running,
                prefer != Some(machine.machine_id),
                far,
                beside,
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
            labels: Labels::new(),
            cordoned: false,
            kind: MachineKind::Own,
            running_apps: Vec::new(),
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

    fn rules(change: impl FnOnce(&mut PlacementRules)) -> AppSettings {
        let mut settings = AppSettings::default();
        change(&mut settings.placement);
        settings
    }

    #[test]
    fn copies_go_to_the_zone_with_fewest_first_then_the_machine_with_fewest() {
        let zone = |id, z: &str| {
            let mut m = machine(id, &format!("m{id}"));
            m.labels.insert("zone".into(), z.into());
            m
        };
        let machines = [zone(1, "a"), zone(2, "a"), zone(3, "b")];
        let one = Usage {
            running: 1,
            memory_mib: 512,
            cpu_millis: 500,
        };
        let settings = rules(|r| r.spread_by = Some("zone".into()));
        let chosen = place_with(
            &release(512, &[]),
            &settings,
            &machines,
            HashMap::from([(3, one)]),
            None,
        );
        assert_eq!(chosen, Ok(Uuid::from_u128(1)), "zone a has none");
        let chosen = place_with(
            &release(512, &[]),
            &settings,
            &machines,
            HashMap::from([(1, one)]),
            None,
        );
        assert_eq!(
            chosen,
            Ok(Uuid::from_u128(3)),
            "zone b before machine 2 of zone a"
        );
    }

    #[test]
    fn near_prefers_machines_running_the_named_app_and_apart_avoids_them_after_the_spread() {
        let mut with_db = machine(2, "b");
        with_db.running_apps = vec!["db".into()];
        let machines = [machine(1, "a"), with_db];
        let near = rules(|r| r.near = vec!["db".into()]);
        let apart = rules(|r| r.apart = vec!["db".into()]);
        let place = |settings: &AppSettings, usage| {
            place_with(&release(512, &[]), settings, &machines, usage, None)
        };
        assert_eq!(place(&near, HashMap::new()), Ok(Uuid::from_u128(2)));
        assert_eq!(place(&apart, HashMap::new()), Ok(Uuid::from_u128(1)));
        let one = Usage {
            running: 1,
            memory_mib: 512,
            cpu_millis: 500,
        };
        assert_eq!(
            place(&near, HashMap::from([(2, one)])),
            Ok(Uuid::from_u128(1)),
            "the spread comes first"
        );
    }

    #[test]
    fn labels_kind_and_cordon_filter_and_say_what_the_app_waits_for() {
        let mut ssd = machine(1, "a");
        ssd.labels.insert("disk".into(), "ssd".into());
        let mut hosted = machine(2, "b");
        hosted.kind = MachineKind::Hosted;
        let settings = rules(|r| {
            r.labels.insert("disk".into(), "ssd".into());
        });
        assert_eq!(
            place_with(
                &release(512, &[]),
                &settings,
                &[ssd.clone(), hosted.clone()],
                HashMap::new(),
                None
            ),
            Ok(Uuid::from_u128(1))
        );
        let hosted_only = rules(|r| r.kind = Some(MachineKind::Hosted));
        assert_eq!(
            place_with(
                &release(512, &[]),
                &hosted_only,
                &[ssd.clone(), hosted.clone()],
                HashMap::new(),
                None
            ),
            Ok(Uuid::from_u128(2))
        );
        let mut cordoned = ssd.clone();
        cordoned.cordoned = true;
        let refused = place_with(
            &release(512, &[]),
            &settings,
            &[cordoned, hosted],
            HashMap::new(),
            None,
        );
        assert_eq!(refused, Err(Unplaceable::NoMatchingMachine));
        assert_eq!(
            Unplaceable::NoMatchingMachine.message(&release(512, &[]), &settings),
            "Waiting for a machine labelled disk=ssd."
        );
        let mut named = rules(|r| r.kind = Some(MachineKind::Own));
        named.machines = vec!["a".into(), "b".into()];
        assert_eq!(
            Unplaceable::NoMatchingMachine.message(&release(512, &[]), &named),
            "Waiting for a machine named a or b, of your own."
        );
        assert_eq!(
            Unplaceable::NoMatchingMachine.message(&release(512, &[]), &AppSettings::default()),
            "Waiting for a machine in service."
        );
        assert_eq!(
            Unplaceable::InsufficientResources.message(&release(512, &[]), &AppSettings::default()),
            "Waiting for a machine with 512 MiB of memory and 0.5 CPU free."
        );
    }
}
