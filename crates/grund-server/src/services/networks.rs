//! Private networks' membership (grund-docs design/network.md §5, §6): one
//! network per organisation, made on first use, whose members are the
//! machines in the organisation's pool (its own and those leased to it).
//!
//! Membership is not tracked command by command. [`Networks::reconcile`]
//! compares the pool with the network's slots under the network's row lock,
//! and when they differ frees and assigns slots, raises the epoch and signs
//! the new list with the network key. Anything that changes the pool
//! (registering, revoking, a lease) shows in the list the next time a member
//! asks, and a member waiting in [`Networks::membership`] reconciles every
//! second, so a revoked machine is dropped within about a second.
//!
//! A new member gets its own slot again if it held one that nobody has
//! taken since, otherwise the lowest slot that is neither held nor freed
//! within [`SLOT_HOLD`]. A prefix is a /48 in `fd00::/8` with a random 40-bit
//! global id (RFC 4193 §3.2).
//!
//! Each member is named as in its pool, and the list names grund's relays
//! (GRUND_RELAY_URL's and GRUND_RELAYS). Neither lives in the slot rows, so
//! the stored list is compared with the one that would be signed now: a
//! renamed machine or a relay added to the configuration is a change, and
//! reaches every member at the next epoch.
//!
//! The same goes for each member's app replicas ([`Member::apps`]): every
//! running replica the organisation's apps have on it, at its
//! [`replica_address`], with the TCP ports its release declares (apps.md
//! §3.1: every port is reachable by the organisation's other apps) and
//! whether its machine last reported it ready. A placement, a drain or a
//! change in readiness is a new epoch.

use std::{
    collections::{HashMap, HashSet},
    net::Ipv6Addr,
};

use chrono::{DateTime, Duration, Utc};
use grund_domain::machine::{KeyPurpose, prefix};
use grund_net::membership::{
    AppReplica, MAX_DIRECT_ADDRS, Member, MembershipList, Port, Relay, Transport, replica_address,
};
use grund_store::networks::{self, NetworkRow, SlotRow};
use uuid::Uuid;

use crate::{
    keys::{KeysState, PublicKey},
    services::agents::MachineCaller,
    state::State,
};

/// How long a freed slot stays held before another machine may get it
/// (network.md §6.1).
pub const SLOT_HOLD: Duration = Duration::hours(24);

/// How long a member's reported direct addresses stay in the list without a
/// fresh report: a member that stops asking (gone, or cut off) drops out of
/// its peers' dials once they age past this.
pub const DIRECT_ADDRS_FRESH: Duration = Duration::minutes(5);

/// How often a member's unchanged direct addresses are written again, to
/// keep them fresh.
pub const DIRECT_ADDRS_REFRESH: Duration = Duration::minutes(1);

/// The longest a membership request waits for a newer epoch. Below the
/// request timeout (15 s by default), so the wait ends before the server
/// gives up on the request.
pub const LONG_POLL: std::time::Duration = std::time::Duration::from_secs(10);

/// A network as a member is told of it.
#[derive(Debug, Clone)]
pub struct NetworkView {
    pub network_id: Uuid,
    pub prefix: Ipv6Addr,
    pub key: PublicKey,
    pub epoch: u64,
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
    /// Each member's slot, by machine.
    pub slots: HashMap<Uuid, u16>,
}

/// What a membership request came to.
#[derive(Debug)]
pub enum MembershipOutcome {
    /// The list, newer than the caller had.
    Newer(Box<NetworkView>),
    /// Nothing changed while the request waited.
    Unchanged { network_id: Uuid, epoch: u64 },
    /// Not a network the caller is a member of.
    NotFound,
}

/// `network` as a member is told of it at registration or in a lease grant:
/// its key, its prefix, `machine_id`'s slot and the relays. `None` when the
/// machine holds no slot in it.
pub fn network_message(
    network: &NetworkView,
    machine_id: Uuid,
    relay_urls: Vec<String>,
) -> Option<grund_proto::grund::agent::v1::Network> {
    Some(grund_proto::grund::agent::v1::Network {
        network_id: network.network_id.to_string(),
        key: buffa::MessageField::from(crate::services::machines::public_key_message(&network.key)),
        prefix: network.prefix.to_string(),
        slot: u32::from(*network.slots.get(&machine_id)?),
        relay_urls,
        ..Default::default()
    })
}

/// Private network flows.
#[derive(Clone)]
pub struct Networks {
    state: State,
}

impl Networks {
    /// Brings the organisation's network in line with its pool, making the
    /// network on first use, and returns it as it now stands.
    pub async fn reconcile(&self, organisation_id: Uuid) -> anyhow::Result<NetworkView> {
        let mut tx = self.state.pool.begin().await?;
        let network = match networks::lock_organisation_network(&mut tx, organisation_id).await? {
            Some(network) => network,
            None => self.create(&mut tx, organisation_id).await?,
        };
        let key = self
            .state
            .keys()
            .ensure(&mut tx, KeyPurpose::Network, Some(organisation_id))
            .await?;
        anyhow::ensure!(
            key.key_id == network.key_id,
            "a network is signed by its organisation's current network key"
        );
        let candidates = networks::candidates(&mut *tx, organisation_id).await?;
        let slots = networks::slots(&mut *tx, network.network_id).await?;
        let now = Utc::now();
        let plan = plan(
            &slots,
            &candidates
                .iter()
                .map(|c| (c.machine_id, c.public_key.clone()))
                .collect::<Vec<_>>(),
            now,
        );
        let prefix: Ipv6Addr = network.prefix.parse()?;
        let names: HashMap<Uuid, (&str, Vec<Port>)> = candidates
            .iter()
            .map(|c| (c.machine_id, (c.name.as_str(), ports(&c.network_ports))))
            .collect();
        let relays = self.relays();
        let endpoints =
            grund_store::apps::organisation_endpoints(&mut *tx, organisation_id).await?;
        let replicas = |slots: &[SlotRow]| app_replicas(prefix, slots, &endpoints);
        if plan.is_empty()
            && network.epoch > 0
            && network.body.as_deref().is_some_and(|body| {
                same_contents(body, &members(&slots, &names, &replicas(&slots)), &relays)
            })
        {
            tx.commit().await?;
            return view(network, key, prefix, &slots);
        }
        for slot in &plan.free {
            networks::free_slot(&mut *tx, network.network_id, i32::from(*slot), now).await?;
        }
        for (slot, endpoint_id) in &plan.rekey {
            networks::rekey_slot(&mut *tx, network.network_id, i32::from(*slot), endpoint_id)
                .await?;
        }
        for (slot, machine_id, endpoint_id) in &plan.assign {
            networks::assign_slot(
                &mut *tx,
                network.network_id,
                i32::from(*slot),
                *machine_id,
                endpoint_id,
                now,
            )
            .await?;
        }
        let slots = networks::slots(&mut *tx, network.network_id).await?;
        let epoch = network.epoch + 1;
        let list = MembershipList {
            network_id: network.network_id.to_string(),
            epoch: epoch as u64,
            prefix,
            issued_at: now.timestamp(),
            members: members(&slots, &names, &replicas(&slots)),
            relays,
        };
        list.validate()?;
        let body = list.encode();
        let signature = self
            .state
            .keys()
            .sign(key.key_id, prefix::NET_MEMBERSHIP, &body);
        networks::store_list(&mut *tx, network.network_id, epoch, &body, &signature, now).await?;
        tx.commit().await?;
        view(
            NetworkRow {
                epoch,
                body: Some(body),
                signature: Some(signature.to_vec()),
                issued_at: Some(now),
                ..network
            },
            key,
            prefix,
            &slots,
        )
    }

    fn relays(&self) -> Vec<Relay> {
        self.state
            .config
            .relay
            .list()
            .into_iter()
            .map(|r| Relay {
                url: r.url,
                region: r.region,
            })
            .collect()
    }

    async fn create(
        &self,
        tx: &mut sqlx::PgConnection,
        organisation_id: Uuid,
    ) -> anyhow::Result<NetworkRow> {
        let key = self
            .state
            .keys()
            .ensure(&mut *tx, KeyPurpose::Network, Some(organisation_id))
            .await?;
        for _ in 0..4 {
            networks::insert_network(
                &mut *tx,
                Uuid::now_v7(),
                organisation_id,
                &random_prefix().to_string(),
                key.key_id,
            )
            .await?;
            if let Some(network) =
                networks::lock_organisation_network(&mut *tx, organisation_id).await?
            {
                return Ok(network);
            }
        }
        anyhow::bail!("four random network prefixes were all taken")
    }

    /// The newest list of the network the caller is a member of, once its
    /// epoch is newer than `since_epoch`, waiting up to [`LONG_POLL`]. First
    /// it records `home_relay_url` as the caller's home relay, when it is one
    /// of grund's relays (anything else is ignored), or clears it when empty:
    /// the list names it, so the members dial the caller through it.
    pub async fn membership(
        &self,
        caller: &MachineCaller,
        network_id: Option<Uuid>,
        since_epoch: u64,
        home_relay_url: &str,
        direct_addrs: &[String],
    ) -> anyhow::Result<MembershipOutcome> {
        let Some(organisation_id) = caller.organisation_id else {
            return Ok(MembershipOutcome::NotFound);
        };
        let hint = home_relay_url.trim_end_matches('/');
        if hint.is_empty() {
            networks::set_home_relay(&self.state.pool, caller.machine_id, None).await?;
        } else if self.relays().iter().any(|r| r.url == hint) {
            networks::set_home_relay(&self.state.pool, caller.machine_id, Some(hint)).await?;
        }
        networks::set_direct_addrs(
            &self.state.pool,
            caller.machine_id,
            &usable_direct_addrs(direct_addrs),
            Utc::now(),
            DIRECT_ADDRS_REFRESH,
        )
        .await?;
        let deadline = tokio::time::Instant::now() + LONG_POLL;
        loop {
            let network = self.reconcile(organisation_id).await?;
            if network_id.is_some_and(|id| id != network.network_id)
                || !network.slots.contains_key(&caller.machine_id)
            {
                return Ok(MembershipOutcome::NotFound);
            }
            if network.epoch > since_epoch {
                return Ok(MembershipOutcome::Newer(Box::new(network)));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(MembershipOutcome::Unchanged {
                    network_id: network.network_id,
                    epoch: network.epoch,
                });
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

fn usable_direct_addrs(reported: &[String]) -> Vec<String> {
    let mut addrs: Vec<std::net::SocketAddr> = reported
        .iter()
        .filter_map(|a| a.parse::<std::net::SocketAddr>().ok())
        .filter(|a| {
            let ip = a.ip();
            a.port() != 0
                && !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !matches!(ip, std::net::IpAddr::V4(v4) if v4.is_link_local())
                && !matches!(ip, std::net::IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80)
        })
        .collect();
    addrs.sort();
    addrs.dedup();
    addrs.truncate(MAX_DIRECT_ADDRS);
    addrs.iter().map(ToString::to_string).collect()
}

fn fresh_direct_addrs(slot: &SlotRow, now: DateTime<Utc>) -> Vec<std::net::SocketAddr> {
    match slot.direct_addrs_at {
        Some(at) if now - at <= DIRECT_ADDRS_FRESH => slot
            .direct_addrs
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect(),
        _ => Vec::new(),
    }
}

fn members(
    slots: &[SlotRow],
    names: &HashMap<Uuid, (&str, Vec<Port>)>,
    apps: &HashMap<Uuid, Vec<AppReplica>>,
) -> Vec<Member> {
    slots
        .iter()
        .filter(|s| s.freed_at.is_none())
        .map(|s| {
            let entry = names.get(&s.machine_id);
            Member {
                machine_id: s.machine_id.to_string(),
                endpoint_id: s.endpoint_id.clone(),
                slot: s.slot as u16,
                name: entry.map(|(n, _)| n.to_string()),
                ports: entry.map(|(_, p)| p.clone()).unwrap_or_default(),
                relay_url: s.home_relay_url.clone(),
                apps: apps.get(&s.machine_id).cloned().unwrap_or_default(),
                direct_addrs: fresh_direct_addrs(s, Utc::now()),
            }
        })
        .collect()
}

fn app_replicas(
    prefix: Ipv6Addr,
    slots: &[SlotRow],
    endpoints: &[grund_store::apps::EndpointRow],
) -> HashMap<Uuid, Vec<AppReplica>> {
    let slot_of: HashMap<Uuid, u16> = slots
        .iter()
        .filter(|s| s.freed_at.is_none())
        .map(|s| (s.machine_id, s.slot as u16))
        .collect();
    let mut out: HashMap<Uuid, Vec<AppReplica>> = HashMap::new();
    for e in endpoints {
        let Some(slot) = slot_of.get(&e.machine_id) else {
            continue;
        };
        let id = e.replica_id.to_string();
        let mut ports: Vec<Port> = e
            .spec
            .ports
            .iter()
            .map(|p| Port {
                transport: Transport::Tcp,
                port: p.port,
            })
            .collect();
        ports.sort();
        ports.dedup();
        out.entry(e.machine_id).or_default().push(AppReplica {
            app: e.app_name.clone(),
            address: replica_address(prefix, *slot, &id),
            replica_id: id,
            ports,
            ready: e.ready,
        });
    }
    out
}

fn ports(declared: &[grund_domain::machine::NetworkPort]) -> Vec<Port> {
    declared
        .iter()
        .map(|p| Port {
            transport: match p.transport {
                grund_domain::machine::Transport::Tcp => Transport::Tcp,
                grund_domain::machine::Transport::Udp => Transport::Udp,
            },
            port: p.port,
        })
        .collect()
}

fn same_contents(signed_body: &[u8], members: &[Member], relays: &[Relay]) -> bool {
    serde_json::from_slice::<MembershipList>(signed_body)
        .is_ok_and(|list| list.members == members && list.relays == relays)
}

fn view(
    network: NetworkRow,
    key: PublicKey,
    prefix: Ipv6Addr,
    slots: &[SlotRow],
) -> anyhow::Result<NetworkView> {
    Ok(NetworkView {
        network_id: network.network_id,
        prefix,
        key,
        epoch: network.epoch as u64,
        body: network.body.unwrap_or_default(),
        signature: network.signature.unwrap_or_default(),
        slots: slots
            .iter()
            .filter(|s| s.freed_at.is_none())
            .map(|s| (s.machine_id, s.slot as u16))
            .collect(),
    })
}

fn random_prefix() -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    getrandom::fill(&mut octets[1..6]).expect("the operating system provides randomness");
    Ipv6Addr::from(octets)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
    free: Vec<u16>,
    rekey: Vec<(u16, String)>,
    assign: Vec<(u16, Uuid, String)>,
}

impl Plan {
    fn is_empty(&self) -> bool {
        self.free.is_empty() && self.rekey.is_empty() && self.assign.is_empty()
    }
}

fn plan(slots: &[SlotRow], candidates: &[(Uuid, String)], now: DateTime<Utc>) -> Plan {
    let wanted: HashMap<Uuid, &str> = candidates
        .iter()
        .map(|(id, key)| (*id, key.as_str()))
        .collect();
    let mut plan = Plan::default();
    let mut members = HashSet::new();
    let mut unavailable = HashSet::new();
    for slot in slots {
        let number = slot.slot as u16;
        match slot.freed_at {
            None => match wanted.get(&slot.machine_id) {
                Some(key) => {
                    members.insert(slot.machine_id);
                    unavailable.insert(number);
                    if *key != slot.endpoint_id {
                        plan.rekey.push((number, key.to_string()));
                    }
                }
                None => {
                    plan.free.push(number);
                    unavailable.insert(number);
                }
            },
            Some(freed) if now - freed < SLOT_HOLD => {
                unavailable.insert(number);
            }
            Some(_) => {}
        }
    }
    let mut next = 1u16;
    for (machine_id, key) in candidates {
        if members.contains(machine_id) {
            continue;
        }
        let own = slots
            .iter()
            .find(|s| s.machine_id == *machine_id && s.freed_at.is_some())
            .map(|s| s.slot as u16);
        let slot = match own {
            Some(own) => own,
            None => {
                while unavailable.contains(&next) && next < u16::MAX {
                    next += 1;
                }
                if unavailable.contains(&next) {
                    continue;
                }
                next
            }
        };
        unavailable.insert(slot);
        plan.assign.push((slot, *machine_id, key.clone()));
    }
    plan
}

/// Access to [`Networks`] from [`State`].
pub trait NetworksState {
    fn networks(&self) -> Networks;
}

impl NetworksState for State {
    fn networks(&self) -> Networks {
        Networks {
            state: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(n: u16, machine: Uuid, key: &str, freed: Option<DateTime<Utc>>) -> SlotRow {
        SlotRow {
            slot: i32::from(n),
            machine_id: machine,
            endpoint_id: key.into(),
            freed_at: freed,
            home_relay_url: None,
            direct_addrs: Vec::new(),
            direct_addrs_at: None,
        }
    }

    #[test]
    fn reported_direct_addresses_keep_only_what_a_peer_could_dial() {
        let reported: Vec<String> = [
            "198.51.100.11:41641",
            "10.1.0.2:41641",
            "127.0.0.1:41641",
            "0.0.0.0:41641",
            "169.254.1.2:41641",
            "[fe80::1]:41641",
            "[ff02::1]:41641",
            "198.51.100.11:0",
            "not an address",
            "198.51.100.11:41641",
            "[2001:db8::7]:41641",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(
            usable_direct_addrs(&reported),
            [
                "10.1.0.2:41641",
                "198.51.100.11:41641",
                "[2001:db8::7]:41641"
            ]
        );
        let many: Vec<String> = (1..=20).map(|n| format!("198.51.100.{n}:1")).collect();
        assert_eq!(usable_direct_addrs(&many).len(), MAX_DIRECT_ADDRS);
    }

    #[test]
    fn direct_addresses_reported_long_ago_leave_the_list() {
        let now = Utc::now();
        let mut row = slot(1, Uuid::now_v7(), "k", None);
        row.direct_addrs = vec!["198.51.100.11:41641".into()];
        row.direct_addrs_at = Some(now - Duration::minutes(4));
        assert_eq!(fresh_direct_addrs(&row, now).len(), 1);
        row.direct_addrs_at = Some(now - DIRECT_ADDRS_FRESH - Duration::seconds(1));
        assert!(fresh_direct_addrs(&row, now).is_empty());
        row.direct_addrs_at = None;
        assert!(fresh_direct_addrs(&row, now).is_empty());
    }

    #[test]
    fn new_members_get_the_lowest_slot_that_is_neither_held_nor_recently_freed() {
        let now = Utc::now();
        let (a, b, c, d) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        let slots = [
            slot(1, a, "ka", None),
            slot(2, b, "kb", Some(now - Duration::hours(1))),
            slot(3, c, "kc", Some(now - Duration::hours(25))),
        ];
        let got = plan(
            &slots,
            &[
                (a, "ka".into()),
                (d, "kd".into()),
                (Uuid::nil(), "kn".into()),
            ],
            now,
        );
        assert!(got.free.is_empty() && got.rekey.is_empty());
        assert_eq!(
            got.assign,
            vec![(3, d, "kd".to_string()), (4, Uuid::nil(), "kn".to_string())]
        );
    }

    #[test]
    fn a_machine_that_left_frees_its_slot_and_gets_it_back_within_the_hold() {
        let now = Utc::now();
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let left = plan(
            &[slot(1, a, "ka", None), slot(2, b, "kb", None)],
            &[(a, "ka".into())],
            now,
        );
        assert_eq!(left.free, vec![2]);
        let back = plan(
            &[slot(1, a, "ka", None), slot(2, b, "kb", Some(now))],
            &[(a, "ka".into()), (b, "kb2".into())],
            now,
        );
        assert_eq!(back.assign, vec![(2, b, "kb2".to_string())]);
    }

    #[test]
    fn a_new_key_for_a_member_is_a_change_and_an_unchanged_pool_is_none() {
        let now = Utc::now();
        let a = Uuid::now_v7();
        let slots = [slot(1, a, "ka", None)];
        assert!(plan(&slots, &[(a, "ka".into())], now).is_empty());
        assert_eq!(
            plan(&slots, &[(a, "kz".into())], now).rekey,
            vec![(1, "kz".to_string())]
        );
    }

    #[test]
    fn a_random_prefix_is_a_ula_slash_48() {
        let octets = random_prefix().octets();
        assert_eq!(octets[0], 0xfd);
        assert!(octets[6..].iter().all(|b| *b == 0));
    }
}
