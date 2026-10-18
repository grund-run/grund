//! A machine's workloads, reservations and last reported host usage.

use axum::{
    extract::{Path, State as AxumState},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use grund_domain::organisation::Role;
use grund_store::{
    machine_activity::{self, MachineSummary},
    machines::MachineRow,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    services::{agents::AgentsState, machines::MachinesState},
    state::State,
    web::{
        machines::{self, MachineItem, MachinesForm},
        orgs::Member,
        pages::{PageResult, not_found_page, signed_in_typed},
    },
};

pub struct WorkloadView {
    pub name: String,
    pub href: String,
    pub detail: String,
    pub recovery: String,
    pub status: String,
    pub tone: &'static str,
    pub icon: &'static str,
}

pub struct MachineDetailPage<'a> {
    pub slug: &'a str,
    pub csrf: &'a str,
    pub manages: bool,
    pub machine: MachineItem<'a>,
    pub metadata: Vec<(&'static str, String)>,
    pub workloads: Vec<WorkloadView>,
    pub sample: String,
    pub outdated: bool,
}

fn cpu(millis: u64) -> String {
    let text = format!("{:.2}", millis as f64 / 1000.0);
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn bytes(value: u64) -> String {
    if value < 1024 * 1024 {
        format!("{} KB", value / 1024)
    } else {
        machines::human_size(value / (1024 * 1024))
    }
}

fn usage(row: &MachineRow) -> Option<&Value> {
    row.capabilities
        .as_ref()
        .and_then(|c| c.0.get("usage"))
        .filter(|v| v.is_object())
}

fn sampled_at(value: &Value) -> Option<DateTime<Utc>> {
    value["sampled_at"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}

fn stale(value: &Value, now: DateTime<Utc>) -> bool {
    sampled_at(value)
        .is_none_or(|at| at > now || now.signed_duration_since(at) > chrono::Duration::seconds(30))
}

fn actual(row: &MachineRow, now: DateTime<Utc>) -> [String; 3] {
    let Some(value) = usage(row) else {
        return std::array::from_fn(|_| "Used: Not reported".into());
    };
    let values = [
        value["cpu_millis"]
            .as_u64()
            .map(|n| format!("{} vCPU", cpu(n))),
        value["memory_used_bytes"].as_u64().map(bytes),
        value["disk_used_bytes"].as_u64().map(bytes),
    ];
    values.map(|v| match v {
        Some(v) => format!(
            "{v} used{}",
            if stale(value, now) { " · stale" } else { "" }
        ),
        None => "Used: Not reported".into(),
    })
}

pub(super) fn add_activity(
    item: &mut MachineItem<'_>,
    row: &MachineRow,
    summary: Option<&MachineSummary>,
    now: DateTime<Utc>,
) {
    let empty = MachineSummary::default();
    let summary = summary.unwrap_or(&empty);
    item.workloads = format!(
        "{} {} · {} {}",
        summary.apps,
        if summary.apps == 1 { "app" } else { "apps" },
        summary.instances,
        if summary.instances == 1 {
            "instance"
        } else {
            "instances"
        }
    );
    let capacity = crate::services::apps::machine_view(row, None);
    if capacity.memory_mib > 0 || capacity.resources_allocatable {
        item.facts[1].1 = machines::human_size(capacity.allocatable_memory_mib());
    }
    if capacity.cpu_millis > 0 || capacity.resources_allocatable {
        item.facts[0].1 = format!("{} vCPU", cpu(u64::from(capacity.allocatable_cpu_millis())));
    }
    let reserved = [
        cpu(summary.cpu_millis.max(0) as u64),
        machines::human_size(summary.memory_mib.max(0) as u64),
        if summary.disk_unbounded {
            format!(
                "{} + unbounded",
                machines::human_size(summary.disk_gib.max(0) as u64 * 1024)
            )
        } else {
            machines::human_size(summary.disk_gib.max(0) as u64 * 1024)
        },
    ];
    item.reserved = std::array::from_fn(|i| {
        format!(
            "{} reserved / {} allocatable",
            reserved[i],
            if item.facts[i].1.is_empty() {
                "Not reported"
            } else {
                &item.facts[i].1
            }
        )
    });
    item.actual = actual(row, now);
}

fn status_tone(status: &str) -> &'static str {
    match status {
        "running" | "ready" | "attached" | "available" => "ok",
        "failed" | "lost" | "exited" => "orange",
        _ => "muted",
    }
}

fn reported(value: Option<&str>) -> String {
    value
        .filter(|s| !s.is_empty())
        .unwrap_or("Not reported")
        .to_string()
}

fn uptime(seconds: u64) -> String {
    format!(
        "{}d {}h {}m",
        seconds / 86400,
        seconds / 3600 % 24,
        seconds / 60 % 60
    )
}

fn recovery_detail(
    policy: &grund_store::machine_recovery::RecoveryPolicy,
    disconnected: bool,
    seen: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> String {
    if policy.has_volumes {
        return "Pinned: has volumes".into();
    }
    let after = chrono::Duration::seconds(policy.reschedule_after_seconds);
    let mut text = format!(
        "Moves after {}",
        grund_domain::app::reconcile::span_words(after)
    );
    if disconnected {
        if let Some(at) = seen.and_then(|seen| seen.checked_add_signed(after)) {
            text.push_str(&format!(
                " · Replacement eligible {} {}",
                if at > now { "at" } else { "since" },
                at.format("%d %b %Y %H:%M:%S UTC")
            ));
        } else {
            text.push_str(" · Replacement eligible now");
        }
    }
    text
}

/// `GET /{org}/machines/{machine}`; an outsider sees the same missing page.
pub async fn page(
    AxumState(state): AxumState<State>,
    member: Member,
    Path((_slug, id)): Path<(String, Uuid)>,
) -> PageResult {
    let org = member.membership.organisation_id;
    let resolved = state.machine_id(org, id).await?;
    let Some(row) = state.machines().organisation_machine(org, resolved).await? else {
        return not_found_page(&state, &member.browser);
    };
    if row.pool == "management" {
        return not_found_page(&state, &member.browser);
    }
    let mut listings = Vec::new();
    for extension in state.extensions.iter() {
        listings.extend(
            extension
                .machine_listings(&state, org, &member.membership.slug)
                .await?,
        );
    }
    let listing = listings
        .iter()
        .find(|l| l.machine_id == Some(row.machine_id));
    if listing.is_some() {
        return not_found_page(&state, &member.browser);
    }
    let now = Utc::now();
    let summaries = machine_activity::summaries(&state.pool, org)
        .await
        .map_err(anyhow::Error::from)?;
    let summary = summaries.iter().find(|s| s.machine_id == row.machine_id);
    let mut machine = machines::machine_context(
        &row,
        summary.map_or(0, |s| s.instances),
        now,
        &MachinesForm::default(),
        &member.membership.slug,
        None,
    );
    add_activity(&mut machine, &row, summary, now);
    let slug = &member.membership.slug;
    let policies = grund_store::machine_recovery::policies(&state.pool, org, row.machine_id)
        .await
        .map_err(anyhow::Error::from)?;
    let disconnected = !crate::services::agents::connected(row.last_seen_at, now);
    let seen = state.hearing.seen(row.last_seen_at);
    let rows = machine_activity::workloads(&state.pool, org, row.machine_id)
        .await
        .map_err(anyhow::Error::from)?;
    let mut workloads: Vec<WorkloadView> = rows
        .into_iter()
        .map(|w| {
            let allocation = if w.kind == "volume" {
                let capacity = w
                    .disk_gib
                    .map(|n| machines::human_size(n.max(0) as u64 * 1024))
                    .unwrap_or_else(|| "Unbounded".into());
                format!(
                    "Volume · {capacity} reserved · last measured {}",
                    w.measured_bytes
                        .map(|n| bytes(n.max(0) as u64))
                        .unwrap_or_else(|| "Not reported".into())
                )
            } else {
                format!(
                    "Instance · {} vCPU · {} reserved",
                    cpu(w.cpu_millis.max(0) as u64),
                    machines::human_size(w.memory_mib.max(0) as u64)
                )
            };
            WorkloadView {
                name: format!("{} / {}", w.app_name, w.name),
                href: format!("/{slug}/apps/{}", w.app_name),
                recovery: policies
                    .iter()
                    .find(|policy| policy.app_id == w.app_id)
                    .map(|policy| recovery_detail(policy, disconnected, seen, now))
                    .unwrap_or_default(),
                detail: format!("{allocation} · desired {}", w.desired),
                tone: status_tone(&w.observed),
                status: reported(Some(&w.observed)),
                icon: if w.kind == "volume" { "disk" } else { "box" },
            }
        })
        .collect();
    if disconnected {
        let replaced =
            grund_store::machine_recovery::replacements(&state.pool, org, row.machine_id)
                .await
                .map_err(anyhow::Error::from)?;
        for replacement in replaced {
            let when = match replacement.placed_at {
                Some(at) => format!(
                    "Replacement placed {} on {}",
                    at.format("%d %b %Y %H:%M:%S UTC"),
                    replacement
                        .machine_name
                        .as_deref()
                        .unwrap_or("Not reported")
                ),
                None => format!(
                    "Removed {} · awaiting replacement placement",
                    replacement.lost_at.format("%d %b %Y %H:%M:%S UTC")
                ),
            };
            workloads.push(WorkloadView {
                name: format!(
                    "{} / {}-{}",
                    replacement.app_name,
                    replacement.app_name,
                    replacement.slot + 1
                ),
                href: format!("/{slug}/apps/{}", replacement.app_name),
                detail: when,
                recovery: format!(
                    "Moves after {}",
                    grund_domain::app::reconcile::span_words(chrono::Duration::seconds(
                        replacement.reschedule_after_seconds
                    ))
                ),
                status: if replacement.placed_at.is_some() {
                    "Replacement placed"
                } else {
                    "Waiting for replacement"
                }
                .into(),
                tone: if replacement.placed_at.is_some() {
                    "blue"
                } else {
                    "orange"
                },
                icon: "box",
            });
        }
    }
    for vm in state
        .agents()
        .vms(org)
        .await?
        .into_iter()
        .filter(|v| v.host_machine_id == row.machine_id)
    {
        let observed = vm.observed_state.as_deref().unwrap_or("Not reported");
        workloads.push(WorkloadView {
            name: vm.name,
            recovery: "Virtual machine: no automatic replacement".into(),
            href: format!("/{slug}/machines"),
            detail: format!(
                "Virtual machine · {} vCPU · {} MiB · {} GiB reserved · desired {}",
                vm.vcpus, vm.memory_mib, vm.disk_gib, vm.state
            ),
            status: observed.to_string(),
            tone: status_tone(observed),
            icon: "server",
        });
    }
    let facts = &row.facts.0;
    let version = row
        .agent_version
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| facts["agent_version"].as_str());
    let snapshot = usage(&row);
    let revision = snapshot
        .and_then(|u| u["agent_revision"].as_str())
        .filter(|s| !s.is_empty() && *s != "unknown");
    let current = crate::services::agents::expected_agent_revision();
    let build = match revision {
        Some(revision) if current != "unknown" && revision != current => {
            format!("{revision} · Different build")
        }
        Some(revision) => revision.to_string(),
        None => "Not reported".into(),
    };
    let outdated = version.is_some_and(crate::services::agents::outdated_version);
    let mut metadata = vec![
        ("Software version", reported(version)),
        ("Build", build),
        ("Operating system", reported(facts["os"].as_str())),
        ("Kernel", reported(facts["kernel"].as_str())),
        ("Architecture", reported(facts["arch"].as_str())),
        ("CPU model", reported(facts["cpu_model"].as_str())),
        (
            "Last seen",
            row.last_seen_at
                .map(|at| at.format("%d %b %Y %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Not reported".into()),
        ),
        (
            "Uptime at sample",
            snapshot
                .and_then(|u| u["uptime_seconds"].as_u64())
                .map(uptime)
                .unwrap_or_else(|| "Not reported".into()),
        ),
    ];
    if row.pool != "management" && listing.is_none() {
        metadata.push(("Hostname", reported(facts["hostname"].as_str())));
    }
    let addresses = machine_activity::addresses(&state.pool, org, row.machine_id)
        .await
        .map_err(anyhow::Error::from)?;
    metadata.push((
        "Direct addresses",
        if addresses.is_empty() {
            "Not reported".into()
        } else {
            addresses.join(", ")
        },
    ));
    metadata.push(("Network traffic", "Not reported".into()));
    let sample = snapshot
        .map(|u| {
            format!(
                "{}{}",
                sampled_at(u)
                    .map(|at| at.format("%d %b %Y %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Not reported".into()),
                if stale(u, now) { " · stale" } else { "" }
            )
        })
        .unwrap_or_else(|| "Not reported".into());
    signed_in_typed(
        &state,
        &member.browser,
        &member.session,
        Some(&member.membership),
        StatusCode::OK,
        machine.name,
        "machines",
        None,
        None,
        None,
        |_, csrf| {
            crate::templates::compiled::pages::machine_detail::render(&MachineDetailPage {
                slug,
                csrf,
                manages: Role::parse(&member.membership.role).is_some_and(|r| r.manages_members()),
                machine,
                metadata,
                workloads,
                sample,
                outdated,
            })
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn usage_freshness_uses_the_sample_clock_and_not_a_later_presence_report() {
        let now = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let sample = |seconds| json!({"sampled_at": (now + chrono::Duration::seconds(seconds)).to_rfc3339()});
        assert!(!stale(&sample(-30), now));
        assert!(stale(&sample(-31), now));
        assert!(stale(&sample(1), now));
        assert!(stale(&json!({}), now));
        assert!(stale(&json!({"sampled_at": "invalid"}), now));
    }
}
