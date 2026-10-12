//! Operator-only fleet inventory and hosted organisation access.

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::Uri,
};
use chrono::{DateTime, Utc};
use grund_store::{machines, operator as operator_store, organisations::Membership};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    services::{billing, machines::MachinesState, operator_inventory::OperatorInventory},
    state::State,
    templates::compiled::pages::admin,
    web::{
        billing::AccountView,
        browser::Browser,
        orgs::{Member, member_of},
        pages::{PageResult, forged, not_found_page, redirect, signed_in_typed},
    },
};

#[derive(Default, Deserialize)]
pub struct AdminQuery {
    #[serde(default)]
    tab: String,
    #[serde(default)]
    host_filter: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    page: String,
    #[serde(default)]
    machines_page: String,
    #[serde(default)]
    organisation: String,
    #[serde(default)]
    done: String,
    #[serde(default)]
    error: String,
}

fn protobuf_i64<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    struct Int64;

    impl<'de> serde::de::Visitor<'de> for Int64 {
        type Value = i64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a proto3 JSON int64")
        }

        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<i64, E> {
            Ok(value)
        }

        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<i64, E> {
            value.try_into().map_err(E::custom)
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<i64, E> {
            value.parse().map_err(E::custom)
        }
    }

    deserializer.deserialize_any(Int64)
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Host {
    pub id: String,
    pub name: String,
    pub state: String,
    pub provider: String,
    pub region: String,
    pub vcpus: i64,
    #[serde(deserialize_with = "protobuf_i64")]
    pub memory_mib: i64,
    #[serde(deserialize_with = "protobuf_i64")]
    pub disk_gib: i64,
    pub allocated_vcpus: i64,
    #[serde(deserialize_with = "protobuf_i64")]
    pub allocated_memory_mib: i64,
    #[serde(deserialize_with = "protobuf_i64")]
    pub allocated_disk_gib: i64,
    pub reachable: bool,
    pub last_heartbeat_at: String,
    pub machine_count: i64,
    pub cordon_reason: String,
    pub host_kernel: String,
    pub firecracker_version: String,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FleetMachine {
    pub id: String,
    pub host_id: String,
    pub pool_id: String,
    pub region: String,
    pub size: String,
    pub state: String,
    pub assigned: bool,
    pub reason: String,
    pub updated_at: String,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FleetPool {
    pub id: String,
    pub name: String,
    pub region: String,
    pub size: String,
    pub desired: i64,
    pub headroom: i64,
    pub warm: i64,
    pub ready: i64,
    pub unschedulable_reason: String,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FleetFailure {
    pub machine_id: String,
    pub host_id: String,
    pub state: String,
    pub reason: String,
    pub updated_at: String,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FleetEvent {
    pub resource_id: String,
    pub kind: String,
    pub event_type: String,
    pub occurred_at: String,
}

pub struct Lease {
    pub name: String,
    pub lessee: String,
    pub since: String,
    pub end: &'static str,
}

pub fn host_name(host: &Host) -> &str {
    host.name
        .strip_suffix(&host.id)
        .and_then(|prefix| prefix.strip_suffix("-retired-"))
        .filter(|name| !name.is_empty())
        .unwrap_or(&host.name)
}

pub fn gb(mib: i64) -> String {
    let mut value = format!("{:.2}", mib as f64 / 1024.0);
    let digits = value.trim_end_matches('0').trim_end_matches('.').len();
    value.truncate(digits);
    if mib > 0 && value == "0" {
        "<0.01".to_owned()
    } else {
        value
    }
}

pub fn fleet_state(state: &str) -> (&str, &str) {
    match state {
        "ready" => ("Ready", "ok"),
        "retired" => ("Retired", "muted"),
        "booted" => ("Running", "ok"),
        "cordoned" => ("Cordoned", "orange"),
        "draining" => ("Draining", "orange"),
        "maintenance" => ("Maintenance", "orange"),
        "failed" => ("Failed", "danger"),
        "pending" => ("Pending", "blue"),
        "provisioning" => ("Provisioning", "blue"),
        "stopped" => ("Stopped", "muted"),
        _ => ("Unknown", "muted"),
    }
}

pub fn fleet_event(event_type: &str) -> String {
    let (resource, action) = event_type.split_once('.').unwrap_or(("", event_type));
    let resource = resource.strip_prefix("fleet-").unwrap_or(resource);
    let action = if action == "booted" {
        "running"
    } else {
        action
    };
    let words = format!("{} {}", resource, action.replace('_', " "));
    let mut chars = words.trim().chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

pub struct AdminPage<'a> {
    pub slug: &'a str,
    pub csrf: &'a str,
    pub manages: bool,
    pub host_filter: &'a str,
    pub retired_count: usize,
    pub now: DateTime<Utc>,
    pub tab: &'a str,
    pub hosts: Vec<Host>,
    pub selected_host: Option<usize>,
    pub machines: Vec<FleetMachine>,
    pub pools: Vec<FleetPool>,
    pub failures: Vec<FleetFailure>,
    pub events: Vec<FleetEvent>,
    pub leases: Vec<Lease>,
    pub organisations: Vec<operator_store::HostedOrganisation>,
    pub available: usize,
    pub leased: usize,
    pub next_page: String,
    pub next_machines_page: String,
    pub organisation: &'a str,
    pub entitlement: Option<bool>,
    pub billing: Option<AccountView>,
    pub billing_enabled: bool,
    pub grant_key: String,
    pub revoke_key: String,
    pub error: &'static str,
    pub notice: &'static str,
}

fn rows<T: DeserializeOwned>(value: Value, field: &str) -> Result<(Vec<T>, String), ()> {
    let next = value
        .get("nextPageToken")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let list = value
        .get(field)
        .cloned()
        .unwrap_or_else(|| Value::Array(vec![]));
    serde_json::from_value(list)
        .map(|list| (list, next))
        .map_err(|_| ())
}

fn inventory_error(error: impl std::fmt::Display) -> &'static str {
    tracing::warn!(%error, "operator inventory unavailable");
    "Fleet inventory is unavailable. Try again later."
}

async fn operator(state: &State, membership: &Membership) -> anyhow::Result<bool> {
    Ok(state.machines().operator().await? == Some(membership.organisation_id))
}

fn manages(membership: &Membership) -> bool {
    matches!(membership.role.as_str(), "owner" | "admin")
}

pub fn admin_url(slug: &str, tab: &str, key: &str, value: &str) -> String {
    let query = serde_urlencoded::to_string([("tab", tab), (key, value)]).unwrap_or_default();
    format!("/{slug}/admin?{query}")
}

pub fn host_url(slug: &str, host: &str, page: &str, machines_page: &str) -> String {
    let query = serde_urlencoded::to_string([
        ("tab", "hosts"),
        ("host", host),
        ("page", page),
        ("machines_page", machines_page),
    ])
    .unwrap_or_default();
    format!("/{slug}/admin?{query}")
}

/// GET /{org}/admin: operator fleet inventory, leases and entitlements.
pub async fn admin_page(
    AxumState(state): AxumState<State>,
    member: Member,
    Query(query): Query<AdminQuery>,
) -> PageResult {
    if !operator(&state, &member.membership).await? {
        return not_found_page(&state, &member.browser);
    }
    let tab = match query.tab.as_str() {
        "pool" => "pool",
        "leases" => "leases",
        "failures" => "failures",
        "events" => "events",
        "organisations" => "organisations",
        _ => "hosts",
    };
    let inventory = OperatorInventory::new(&state);
    let mut error = match query.error.as_str() {
        "not-allowed" => "Your role does not allow that.",
        "organisation" => "There is no organisation by that name.",
        "reason" => "A reason is required.",
        "failed" => "The change could not be made. Try again later.",
        "billing" => "Billing is unavailable. Try again later.",
        _ => "",
    };
    let notice = match query.done.as_str() {
        "host" => "Host action requested.",
        "grant" => "Hosted machines enabled for the organisation.",
        "revoke" => "Hosted machines disabled for the organisation.",
        "billing" => "Complimentary billing changed.",
        _ => "",
    };
    let mut hosts: Vec<Host> = vec![];
    let mut machines = vec![];
    let mut pools = vec![];
    let mut failures = vec![];
    let mut events = vec![];
    let mut leases = vec![];
    let mut organisations = vec![];
    let mut available = 0;
    let mut leased = 0;
    let mut next_page = String::new();
    let mut next_machines_page = String::new();
    let mut entitlement = None;
    let mut billing = None;
    let mut selected_host = None;
    let host_filter = if query.host_filter == "retired" {
        "retired"
    } else {
        "active"
    };
    let mut retired_count = 0;
    let now = Utc::now();
    match tab {
        "hosts" => {
            let mut token = String::new();
            loop {
                let value = match inventory.list("ListInventoryHosts", 100, &token, "").await {
                    Ok(value) => value,
                    Err(err) => {
                        error = inventory_error(err);
                        break;
                    }
                };
                match rows(value, "hosts") {
                    Ok((list, next)) => {
                        hosts.extend(list);
                        if next.is_empty() {
                            break;
                        }
                        token = next;
                    }
                    Err(()) => {
                        error = inventory_error("invalid hosts response");
                        break;
                    }
                }
            }
            hosts.sort_by_key(|host| host.state == "retired");
            for host in &hosts {
                if host.state == "retired" {
                    retired_count += 1;
                }
            }
            if let Some((index, host)) = hosts
                .iter()
                .enumerate()
                .find(|(_, host)| !host.id.is_empty() && host.id == query.host)
            {
                selected_host = Some(index);
                match inventory
                    .list("ListInventoryMachines", 50, &query.machines_page, &host.id)
                    .await
                {
                    Ok(value) => match rows(value, "machines") {
                        Ok((list, next)) => {
                            machines = list;
                            next_machines_page = next;
                        }
                        Err(()) => error = inventory_error("invalid machines response"),
                    },
                    Err(err) => error = inventory_error(err),
                }
            }
        }
        "pool" => {
            match inventory
                .list("ListInventoryPools", 100, &query.page, "")
                .await
            {
                Ok(value) => match rows(value, "pools") {
                    Ok((list, next)) => {
                        pools = list;
                        next_page = next;
                    }
                    Err(()) => error = inventory_error("invalid pools response"),
                },
                Err(err) => error = inventory_error(err),
            }
            for row in state.machines().pool(None).await?.into_iter() {
                match row.state.as_str() {
                    "available" => available += 1,
                    "leased" => leased += 1,
                    _ => {}
                }
            }
        }
        "leases" => {
            leases = state
                .machines()
                .pool(None)
                .await?
                .into_iter()
                .filter(|row| row.state == "leased")
                .map(|row| Lease {
                    name: row.lease_name.unwrap_or(row.name),
                    lessee: row
                        .lessee_slug
                        .unwrap_or_else(|| "Unknown organisation".to_owned()),
                    since: row.leased_at.map_or_else(String::new, |at| at.to_rfc3339()),
                    end: "when removed",
                })
                .collect();
        }
        "failures" => {
            match inventory
                .list("ListInventoryFailures", 100, &query.page, "")
                .await
            {
                Ok(value) => match rows(value, "failures") {
                    Ok((list, next)) => {
                        failures = list;
                        next_page = next;
                    }
                    Err(()) => error = inventory_error("invalid failures response"),
                },
                Err(err) => error = inventory_error(err),
            }
        }
        "events" => {
            match inventory
                .list("ListInventoryEvents", 50, &query.page, "")
                .await
            {
                Ok(value) => match rows(value, "events") {
                    Ok((list, next)) => {
                        events = list;
                        next_page = next;
                    }
                    Err(()) => error = inventory_error("invalid events response"),
                },
                Err(err) => error = inventory_error(err),
            }
        }
        "organisations" => {
            match operator_store::hosted_organisations(&state.pool).await {
                Ok(list) => organisations = list,
                Err(err) => {
                    tracing::warn!(%err, "organisation listing failed");
                    error = "Hosted access is unavailable. Try again later.";
                }
            }
            if !query.organisation.trim().is_empty() {
                match machines::live_organisation_by_slug(&state.pool, query.organisation.trim())
                    .await
                {
                    Ok(Some(id)) => {
                        match state.machines().hosted_enabled(id).await {
                            Ok(enabled) => entitlement = Some(enabled),
                            Err(err) => {
                                tracing::warn!(%err, "hosted access lookup failed");
                                error = "Hosted access is unavailable. Try again later.";
                            }
                        }
                        if state.billing.enabled() {
                            billing = AccountView::from_billing_operator(
                                state.billing.account(id),
                                &state.billing,
                            );
                        }
                    }
                    Ok(None) => error = "There is no organisation by that name.",
                    Err(err) => {
                        tracing::warn!(%err, "organisation lookup failed");
                        error = "Hosted access is unavailable. Try again later.";
                    }
                }
            }
        }
        _ => unreachable!(),
    }
    signed_in_typed(
        &state,
        &member.browser,
        &member.session,
        Some(&member.membership),
        axum::http::StatusCode::OK,
        "Admin",
        "admin",
        None,
        None,
        None,
        |_, csrf| {
            admin::render(&AdminPage {
                slug: &member.membership.slug,
                csrf,
                manages: manages(&member.membership),
                host_filter,
                retired_count,
                now,
                tab,
                selected_host,
                hosts,
                machines,
                pools,
                failures,
                events,
                leases,
                organisations,
                available,
                leased,
                next_page,
                next_machines_page,
                organisation: query.organisation.trim(),
                billing,
                billing_enabled: state.billing.enabled(),
                grant_key: if state.billing.enabled() {
                    uuid::Uuid::now_v7().to_string()
                } else {
                    String::new()
                },
                revoke_key: if state.billing.enabled() {
                    uuid::Uuid::now_v7().to_string()
                } else {
                    String::new()
                },
                entitlement,
                error,
                notice,
            })
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct HostActionForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    host_id: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    reason: String,
}

/// POST /{org}/admin/hosts/action: cordon, uncordon or drain one host.
pub async fn host_action(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<HostActionForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (_, membership) = match member_of(&state, &browser, &uri, &slug).await {
        Ok(member) => member,
        Err(response) => return Ok(*response),
    };
    if !operator(&state, &membership).await? {
        return not_found_page(&state, &browser);
    }
    if !manages(&membership) {
        return Ok(redirect(&admin_url(&slug, "hosts", "error", "not-allowed")));
    }
    let method = match form.action.as_str() {
        "cordon" => "CordonInventoryHost",
        "uncordon" => "UncordonInventoryHost",
        "drain" => "DrainInventoryHost",
        _ => return Ok(redirect(&admin_url(&slug, "hosts", "error", "failed"))),
    };
    if form.host_id.trim().is_empty() {
        return Ok(redirect(&admin_url(&slug, "hosts", "error", "failed")));
    }
    if form.action == "cordon" && form.reason.trim().is_empty() {
        return Ok(redirect(&admin_url(&slug, "hosts", "error", "reason")));
    }
    let outcome = OperatorInventory::new(&state)
        .host_action(method, &form.host_id, form.reason.trim())
        .await;
    let marker = match outcome {
        Ok(_) => "done",
        Err(err) => {
            tracing::warn!(%err, "host action failed");
            "error"
        }
    };
    Ok(redirect(&admin_url(
        &slug,
        "hosts",
        marker,
        if marker == "done" { "host" } else { "failed" },
    )))
}

#[derive(Deserialize)]
pub struct EntitlementForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    organisation: String,
    #[serde(default)]
    action: String,
}

/// POST /{org}/admin/organisations/entitlement: change hosted access by slug.
pub async fn entitlement_action(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<EntitlementForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (_, membership) = match member_of(&state, &browser, &uri, &slug).await {
        Ok(member) => member,
        Err(response) => return Ok(*response),
    };
    if !operator(&state, &membership).await? {
        return not_found_page(&state, &browser);
    }
    if !manages(&membership) {
        return Ok(redirect(&admin_url(
            &slug,
            "organisations",
            "error",
            "not-allowed",
        )));
    }
    let enabled = match form.action.as_str() {
        "grant" => true,
        "revoke" => false,
        _ => {
            return Ok(redirect(&admin_url(
                &slug,
                "organisations",
                "error",
                "failed",
            )));
        }
    };
    let named = form.organisation.trim();
    let outcome = machines::live_organisation_by_slug(&state.pool, named).await;
    let marker = match outcome {
        Ok(Some(id)) => match state.machines().grant_hosted(id, enabled).await {
            Ok(()) => ("done", form.action.as_str()),
            Err(err) => {
                tracing::warn!(%err, "hosted access change failed");
                ("error", "failed")
            }
        },
        Ok(None) => ("error", "organisation"),
        Err(err) => {
            tracing::warn!(%err, "organisation lookup failed");
            ("error", "failed")
        }
    };
    let query =
        serde_urlencoded::to_string([("tab", "organisations"), ("organisation", named), marker])
            .unwrap_or_default();
    Ok(redirect(&format!("/{slug}/admin?{query}")))
}

#[derive(Deserialize)]
pub struct ComplimentaryForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    organisation: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    plan: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    expires_at: String,
    #[serde(default)]
    idempotency_key: String,
}

pub async fn complimentary_action(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<ComplimentaryForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = match member_of(&state, &browser, &uri, &slug).await {
        Ok(member) => member,
        Err(response) => return Ok(*response),
    };
    if !operator(&state, &membership).await? || !state.billing.enabled() {
        return not_found_page(&state, &browser);
    }
    if !manages(&membership) {
        return Ok(redirect(&admin_url(
            &slug,
            "organisations",
            "error",
            "not-allowed",
        )));
    }
    let enabled = match form.action.as_str() {
        "grant" => true,
        "revoke" => false,
        _ => {
            return Ok(redirect(&admin_url(
                &slug,
                "organisations",
                "error",
                "billing",
            )));
        }
    };
    let Ok(key) = uuid::Uuid::parse_str(&form.idempotency_key) else {
        return Ok(redirect(&admin_url(
            &slug,
            "organisations",
            "error",
            "billing",
        )));
    };
    let named = form.organisation.trim();
    let result = match machines::live_organisation_by_slug(&state.pool, named).await {
        Ok(Some(id)) => {
            if let Err(reason) =
                billing::validate_complimentary(enabled, &form.plan, &form.reason, &form.expires_at)
            {
                tracing::debug!(reason, "complimentary billing request refused");
                Err("reason")
            } else {
                state
                    .billing
                    .complimentary(billing::Complimentary {
                        organisation_id: id,
                        enabled,
                        plan: &form.plan,
                        reason: form.reason.trim(),
                        expires_at: enabled.then_some(form.expires_at.as_str()),
                        actor_id: session.account_id,
                        key,
                    })
                    .await
                    .map_err(|_| "billing")
            }
        }
        Ok(None) => Err("organisation"),
        Err(err) => {
            tracing::warn!(%err, "organisation lookup failed");
            Err("billing")
        }
    };
    let marker = match result {
        Ok(()) => ("done", "billing"),
        Err(error) => ("error", error),
    };
    let query =
        serde_urlencoded::to_string([("tab", "organisations"), ("organisation", named), marker])
            .unwrap_or_default();
    Ok(redirect(&format!("/{slug}/admin?{query}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_inventory_decodes_protobuf_json_capacity_as_strings() {
        let wire = serde_json::json!({
            "hosts": [{
                "id": "host-id",
                "name": "test-host",
                "vcpus": 2,
                "memoryMib": "1536",
                "diskGib": "6",
                "allocatedVcpus": 1,
                "allocatedMemoryMib": "512",
                "allocatedDiskGib": "2"
            }]
        });
        let (hosts, _) = rows::<Host>(wire, "hosts").expect("a real host response");
        assert_eq!(hosts[0].memory_mib - hosts[0].allocated_memory_mib, 1024);
        assert_eq!(hosts[0].disk_gib - hosts[0].allocated_disk_gib, 4);
    }
}
