//! An app's Resources setting (`?edit=resources`): memory and CPU per copy,
//! each a number with a slider over the usual values, and presets that
//! fill both. The values on offer stop at what the organisation's largest
//! machine can give one copy and at what an app spec allows
//! (grund-docs design/apps.md §5.2).

use grund_domain::app::placement::MachineView;

#[cfg_attr(test, derive(serde::Serialize))]
pub struct ResourcePreset {
    pub value: &'static str,
    pub title: &'static str,
    pub text: String,
    pub sets: Option<(u64, String)>,
    pub icon: Option<&'static str>,
}

#[cfg_attr(test, derive(serde::Serialize))]
pub struct ResourceView {
    pub memory: String,
    pub cpu: String,
    pub preset: &'static str,
    pub presets: Vec<ResourcePreset>,
    pub memory_steps: Vec<(u64, String)>,
    pub cpu_steps: Vec<(String, String)>,
    pub memory_max: u64,
    pub cpu_max: String,
    pub memory_min: u64,
    pub cpu_min: String,
}

/// The memory slider's stops, in MiB.
pub const MEMORY_STEPS: &[u64] = &[64, 128, 256, 512, 1024, 2048, 4096, 8192];

/// The CPU slider's stops, in thousandths of a CPU.
pub const CPU_STEPS: &[u32] = &[100, 250, 500, 1000, 2000, 4000];

/// The presets: key, title, memory in MiB, CPU in thousandths.
pub const PRESETS: &[(&str, &str, u64, u32)] = &[
    ("low", "Low", 128, 250),
    ("medium", "Medium", 512, 1000),
    ("high", "High", 2048, 2000),
];

/// What a spec with no memory or CPU set gets (`AppSpec`'s defaults).
pub const DEFAULT_MEMORY_MIB: u64 = 512;
pub const DEFAULT_CPU_MILLIS: u32 = 1000;

const MODEL_MEMORY_MIB: (u64, u64) = (16, 262_144);
const MODEL_CPU_MILLIS: (u32, u32) = (10, 64_000);

/// The most one copy can have on any of these machines: the largest
/// allocatable memory and CPU of a machine that runs apps, under its
/// owner's per-copy caps. `None` without such a machine.
pub fn ceiling(machines: &[MachineView]) -> Option<(u64, u32)> {
    let cap = |allocatable: u64, max: u64| {
        if max > 0 {
            allocatable.min(max)
        } else {
            allocatable
        }
    };
    machines
        .iter()
        .filter(|m| m.apps && !m.cordoned)
        .map(|m| {
            (
                cap(m.allocatable_memory_mib(), m.max_replica_memory_mib),
                cap(
                    u64::from(m.allocatable_cpu_millis()),
                    u64::from(m.max_replica_cpu_millis),
                ) as u32,
            )
        })
        .reduce(|a, b| (a.0.max(b.0), a.1.max(b.1)))
}

/// A number of thousandths of a CPU as vCPUs: 250 is `0.25`, 1000 is `1`.
pub fn vcpus(millis: u32) -> String {
    if millis.is_multiple_of(1000) {
        (millis / 1000).to_string()
    } else {
        format!("{:.3}", f64::from(millis) / 1000.0)
            .trim_end_matches('0')
            .to_string()
    }
}

/// vCPUs as typed (`0.25`, `1`) in thousandths of a CPU; `None` for
/// anything that is not a positive number.
pub fn millis_of(text: &str) -> Option<u32> {
    let value: f64 = text.trim().parse().ok()?;
    (value.is_finite() && value > 0.0 && value <= 1_000.0).then(|| (value * 1000.0).round() as u32)
}

fn memory_words(mib: u64) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{} GB", mib / 1024)
    } else {
        mib.to_string()
    }
}

/// The preset these values are, or `custom`.
pub fn preset_of(memory_mib: u64, cpu_millis: u32) -> &'static str {
    PRESETS
        .iter()
        .find(|(_, _, m, c)| *m == memory_mib && *c == cpu_millis)
        .map_or("custom", |(key, ..)| key)
}

/// The values a posted form means: a preset chosen on this page (not the
/// one it was shown with) wins, so the form works without the script;
/// otherwise the numbers as typed. Returns memory in MiB and vCPUs, as
/// text for the form.
pub fn chosen(preset: &str, shown: &str, memory: &str, cpu: &str) -> (String, String) {
    match PRESETS.iter().find(|(key, ..)| *key == preset) {
        Some((_, _, m, c)) if preset != shown => (m.to_string(), vcpus(*c)),
        _ => (memory.to_string(), cpu.to_string()),
    }
}

/// What the Resources form shows for these values (MiB and vCPUs as
/// text; empty is the default) under the machines' ceiling.
pub fn view(memory: &str, cpu: &str, ceiling: Option<(u64, u32)>) -> ResourceView {
    let memory_max = ceiling.map_or(MODEL_MEMORY_MIB.1, |(m, _)| {
        m.clamp(MODEL_MEMORY_MIB.0, MODEL_MEMORY_MIB.1)
    });
    let cpu_max = ceiling.map_or(MODEL_CPU_MILLIS.1, |(_, c)| {
        c.clamp(MODEL_CPU_MILLIS.0, MODEL_CPU_MILLIS.1)
    });
    let memory_steps: Vec<(u64, String)> = MEMORY_STEPS
        .iter()
        .filter(|m| **m <= memory_max)
        .map(|m| (*m, memory_words(*m)))
        .collect();
    let cpu_steps: Vec<(String, String)> = CPU_STEPS
        .iter()
        .filter(|c| **c <= cpu_max)
        .map(|c| (vcpus(*c), vcpus(*c)))
        .collect();
    let memory = if memory.trim().is_empty() {
        DEFAULT_MEMORY_MIB.to_string()
    } else {
        memory.trim().to_string()
    };
    let cpu = if cpu.trim().is_empty() {
        vcpus(DEFAULT_CPU_MILLIS)
    } else {
        cpu.trim().to_string()
    };
    let preset = match (memory.parse::<u64>(), millis_of(&cpu)) {
        (Ok(m), Some(c)) => preset_of(m, c),
        _ => "custom",
    };
    let mut presets: Vec<ResourcePreset> = PRESETS
        .iter()
        .filter(|(_, _, m, c)| *m <= memory_max && *c <= cpu_max)
        .map(|(key, title, m, c)| ResourcePreset {
            value: key,
            title,
            text: format!("{} MiB · {} vCPU", m, vcpus(*c)),
            sets: Some((*m, vcpus(*c))),
            icon: None,
        })
        .collect();
    presets.push(ResourcePreset {
        value: "custom",
        title: "Custom",
        text: "The values above".into(),
        sets: None,
        icon: Some("sliders"),
    });
    ResourceView {
        memory,
        cpu,
        preset,
        presets,
        memory_steps,
        cpu_steps,
        memory_max,
        cpu_max: vcpus(cpu_max),
        memory_min: MODEL_MEMORY_MIB.0,
        cpu_min: vcpus(MODEL_CPU_MILLIS.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpus_read_as_people_write_them() {
        assert_eq!(vcpus(250), "0.25");
        assert_eq!(vcpus(1000), "1");
        assert_eq!(vcpus(100), "0.1");
        assert_eq!(millis_of("0.25"), Some(250));
        assert_eq!(millis_of("2"), Some(2000));
        assert_eq!(millis_of("-1"), None);
        assert_eq!(millis_of("lots"), None);
    }

    #[test]
    fn a_preset_chosen_on_the_page_wins_and_one_left_as_shown_does_not() {
        assert_eq!(
            chosen("high", "medium", "512", "1"),
            ("2048".into(), "2".into())
        );
        assert_eq!(
            chosen("medium", "medium", "700", "1.5"),
            ("700".into(), "1.5".into())
        );
        assert_eq!(
            chosen("custom", "medium", "700", "1.5"),
            ("700".into(), "1.5".into())
        );
    }

    #[test]
    fn values_that_match_no_preset_are_custom() {
        assert_eq!(preset_of(512, 1000), "medium");
        assert_eq!(preset_of(700, 1000), "custom");
    }

    fn machine(memory_mib: u64, cpu_millis: u32, cap_mib: u64) -> MachineView {
        MachineView {
            machine_id: uuid::Uuid::nil(),
            name: "m".into(),
            last_seen: None,
            apps: true,
            arch: "x86_64".into(),
            memory_mib,
            cpu_millis,
            reserved_memory_mib: 0,
            reserved_cpu_millis: 0,
            max_replica_memory_mib: cap_mib,
            max_replica_cpu_millis: 0,
            labels: Default::default(),
            cordoned: false,
            kind: grund_domain::app::spec::MachineKind::Own,
            running_apps: Vec::new(),
        }
    }

    #[test]
    fn the_ceiling_is_the_largest_machine_under_its_owners_cap() {
        let small = machine(2048, 2000, 0);
        let capped = machine(16384, 8000, 1024);
        let (memory, cpu) = ceiling(&[small.clone(), capped]).unwrap();
        assert_eq!(cpu, 8000 - 250);
        assert_eq!(memory, small.allocatable_memory_mib().max(1024));
        assert_eq!(ceiling(&[]), None);
    }

    #[test]
    fn the_slider_stops_at_the_ceiling() {
        let page = view("", "", Some((1100, 1500)));
        assert_eq!(page.memory_steps.len(), 5);
        assert_eq!(page.cpu_steps.len(), 4);
        assert_eq!(page.preset, "medium");
    }
}
