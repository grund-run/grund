//! The private network between a network's members (network.md §6, §11).
//!
//! Every member runs a [`Mesh`]. It reads IPv6 packets from `grund0`, finds
//! the member whose /64 holds the destination, and sends each packet to that
//! member's key in QUIC datagrams ([`crate::frame`]). Connections open on the
//! first packet to a member and go through grund's relay until iroh punches a
//! direct path.
//!
//! The inbound filter is the security boundary (network.md §11.4):
//! - only a key on the current membership list may connect (ALPN
//!   [`crate::NET_ALPN`]); a key that leaves the list loses its connections;
//! - a packet's source must lie in the sender's own /64 (no spoofing another
//!   member), and its destination in this machine's /64;
//! - a list is accepted only with a newer epoch. Until a newer one arrives the
//!   mesh keeps the last one it verified (fail-static, network.md §5.3).
//!
//! Not built yet: the closed-by-default filter on declared ports, epoch
//! gossip between members, and containers' addresses in the /64.

use std::{
    collections::HashMap,
    net::Ipv6Addr,
    str::FromStr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Instant,
};

use anyhow::{Context, bail};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayUrl, TransportAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use serde::Serialize;
use tokio::sync::watch;

use crate::{
    NET_ALPN,
    frame::{Framer, Reassembler},
    membership::MembershipList,
    tun::Tun,
};

/// How long a dial to a member may take before the next packet to it tries
/// again. iroh's connect has no deadline of its own when no path answers.
pub const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How a mesh is set up.
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// The TUN device's name, `grund0` in production.
    pub tun_name: String,
    /// grund's relays, used to reach members before a direct path exists.
    pub relays: Vec<RelayUrl>,
}

/// One machine's side of a private network. Clone it freely: clones share
/// the same state. Register it with an iroh `Router` for [`crate::NET_ALPN`],
/// then call [`Mesh::run`].
#[derive(Debug, Clone)]
pub struct Mesh {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    endpoint: Endpoint,
    config: MeshConfig,
    view: RwLock<Option<View>>,
    tun: tokio::sync::OnceCell<Tun>,
    peers: Mutex<HashMap<EndpointId, Peer>>,
    counters: Counters,
}

#[derive(Debug, Clone)]
struct View {
    list: MembershipList,
    own_slot: u16,
}

#[derive(Debug, Default)]
struct Peer {
    connections: Vec<Connection>,
    dialing: bool,
    framer: Framer,
}

#[derive(Debug, Default)]
struct Counters {
    tun_in: AtomicU64,
    sent_whole: AtomicU64,
    sent_split: AtomicU64,
    dropped_no_member: AtomicU64,
    dropped_bad_source_out: AtomicU64,
    dropped_while_dialing: AtomicU64,
    dropped_send: AtomicU64,
    received: AtomicU64,
    dropped_spoofed_in: AtomicU64,
    dropped_not_for_us: AtomicU64,
    refused_non_members: AtomicU64,
    lists_applied: AtomicU64,
    lists_refused_stale: AtomicU64,
}

/// What a mesh is doing, for status output and tests.
#[derive(Debug, Clone, Serialize)]
pub struct MeshStatus {
    /// The epoch of the list in force, if any.
    pub epoch: Option<u64>,
    /// This machine's address on the network, once it is a member.
    pub address: Option<Ipv6Addr>,
    /// Every member this machine has a connection to, or is dialing.
    pub peers: Vec<PeerStatus>,
    /// Packet and list counters since start.
    pub counters: HashMap<&'static str, u64>,
}

/// One peer in [`MeshStatus`].
#[derive(Debug, Clone, Serialize)]
pub struct PeerStatus {
    /// The peer's key.
    pub endpoint_id: String,
    /// The peer's slot, if it is still on the list.
    pub slot: Option<u16>,
    /// Open connections to it (a dial from each side can make two).
    pub connections: usize,
    /// The selected path of the newest connection: `direct <addr>`,
    /// `relay <url>` or `none`.
    pub path: String,
}

impl Mesh {
    /// A mesh on `endpoint`. Nothing runs until [`Mesh::run`].
    pub fn new(endpoint: Endpoint, config: MeshConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                endpoint,
                config,
                view: RwLock::new(None),
                tun: tokio::sync::OnceCell::new(),
                peers: Mutex::new(HashMap::new()),
                counters: Counters::default(),
            }),
        }
    }

    /// Runs the mesh: waits for the first verified list that names this
    /// machine, creates the TUN device with its address, and from then on
    /// moves packets and applies newer lists. Returns only on an error, or
    /// when `lists`' sender is dropped.
    pub async fn run(
        &self,
        mut lists: watch::Receiver<Option<MembershipList>>,
    ) -> anyhow::Result<()> {
        let own = self.inner.endpoint.id();
        let first = loop {
            if let Some(list) = lists.borrow_and_update().clone()
                && list.member_by_id(&own).is_some()
            {
                break list;
            }
            lists
                .changed()
                .await
                .context("the membership list source closed")?;
        };
        let own_slot = first
            .member_by_id(&own)
            .map(|m| m.slot)
            .expect("checked above");
        let address = first.address(own_slot);
        let tun = Tun::create(&self.inner.config.tun_name, address, 48)?;
        self.inner.tun.set(tun).expect("run is called once");
        self.apply(first)?;
        tracing::info!(%address, "mesh: up");

        let reader = tokio::spawn(self.clone().tun_to_peers());
        loop {
            if lists.changed().await.is_err() {
                reader.abort();
                return Ok(());
            }
            let Some(list) = lists.borrow_and_update().clone() else {
                continue;
            };
            if let Err(e) = self.apply(list) {
                tracing::warn!(error = %e, "mesh: list not applied");
            }
        }
    }

    /// What the mesh is doing now.
    pub fn status(&self) -> MeshStatus {
        let view = self.inner.view.read().expect("view lock").clone();
        let peers = self.inner.peers.lock().expect("peers lock");
        let c = &self.inner.counters;
        let counters = [
            ("tun_in", &c.tun_in),
            ("sent_whole", &c.sent_whole),
            ("sent_split", &c.sent_split),
            ("dropped_no_member", &c.dropped_no_member),
            ("dropped_bad_source_out", &c.dropped_bad_source_out),
            ("dropped_while_dialing", &c.dropped_while_dialing),
            ("dropped_send", &c.dropped_send),
            ("received", &c.received),
            ("dropped_spoofed_in", &c.dropped_spoofed_in),
            ("dropped_not_for_us", &c.dropped_not_for_us),
            ("refused_non_members", &c.refused_non_members),
            ("lists_applied", &c.lists_applied),
            ("lists_refused_stale", &c.lists_refused_stale),
        ]
        .into_iter()
        .map(|(k, v)| (k, v.load(Relaxed)))
        .collect();
        MeshStatus {
            epoch: view.as_ref().map(|v| v.list.epoch),
            address: view.as_ref().map(|v| v.list.address(v.own_slot)),
            peers: peers
                .iter()
                .map(|(id, p)| PeerStatus {
                    endpoint_id: id.to_string(),
                    slot: view
                        .as_ref()
                        .and_then(|v| v.list.member_by_id(id))
                        .map(|m| m.slot),
                    connections: p.connections.len(),
                    path: p
                        .connections
                        .last()
                        .map(describe_path)
                        .unwrap_or_else(|| "none".into()),
                })
                .collect(),
            counters,
        }
    }

    fn apply(&self, list: MembershipList) -> anyhow::Result<()> {
        list.validate()?;
        let own = self.inner.endpoint.id();
        let mut view = self.inner.view.write().expect("view lock");
        if let Some(current) = view.as_ref() {
            if list.epoch <= current.list.epoch {
                self.inner
                    .counters
                    .lists_refused_stale
                    .fetch_add(1, Relaxed);
                bail!(
                    "epoch {} is not newer than {}",
                    list.epoch,
                    current.list.epoch
                );
            }
            if list.network_id != current.list.network_id || list.prefix != current.list.prefix {
                bail!("the list is for another network or prefix");
            }
        }
        let own_slot = match list.member_by_id(&own) {
            Some(m) => m.slot,
            None => {
                tracing::warn!("mesh: this machine is no longer a member; dropping every peer");
                self.inner
                    .peers
                    .lock()
                    .expect("peers lock")
                    .drain()
                    .for_each(|(_, p)| close_all(p));
                *view = Some(View { list, own_slot: 0 });
                return Ok(());
            }
        };
        if let Some(current) = view.as_ref()
            && current.own_slot != 0
            && current.own_slot != own_slot
        {
            bail!(
                "this machine's slot changed from {} to {own_slot}",
                current.own_slot
            );
        }
        let mut peers = self.inner.peers.lock().expect("peers lock");
        let gone: Vec<EndpointId> = peers
            .keys()
            .filter(|id| list.member_by_id(id).is_none())
            .copied()
            .collect();
        for id in gone {
            if let Some(p) = peers.remove(&id) {
                close_all(p);
            }
        }
        *view = Some(View { list, own_slot });
        self.inner.counters.lists_applied.fetch_add(1, Relaxed);
        Ok(())
    }

    async fn tun_to_peers(self) {
        let tun = self.inner.tun.get().expect("tun is set before this runs");
        let c = &self.inner.counters;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match tun.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(error = %e, "mesh: reading the TUN device failed");
                    return;
                }
            };
            c.tun_in.fetch_add(1, Relaxed);
            let packet = &buf[..n];
            let Some((src, dst)) = ipv6_addrs(packet) else {
                c.dropped_no_member.fetch_add(1, Relaxed);
                continue;
            };
            let target = {
                let view = self.inner.view.read().expect("view lock");
                let Some(view) = view.as_ref().filter(|v| v.own_slot != 0) else {
                    c.dropped_no_member.fetch_add(1, Relaxed);
                    continue;
                };
                if view.list.member_for(src).map(|m| m.slot) != Some(view.own_slot) {
                    c.dropped_bad_source_out.fetch_add(1, Relaxed);
                    continue;
                }
                match view.list.member_for(dst) {
                    Some(m) if m.slot != view.own_slot => EndpointId::from_str(&m.endpoint_id).ok(),
                    _ => None,
                }
            };
            let Some(target) = target else {
                c.dropped_no_member.fetch_add(1, Relaxed);
                continue;
            };
            self.send(target, packet);
        }
    }

    fn send(&self, target: EndpointId, packet: &[u8]) {
        let c = &self.inner.counters;
        let mut peers = self.inner.peers.lock().expect("peers lock");
        let peer = peers.entry(target).or_default();
        peer.connections
            .retain(|conn| conn.close_reason().is_none());
        let Some(conn) = peer.connections.last().cloned() else {
            c.dropped_while_dialing.fetch_add(1, Relaxed);
            if !peer.dialing {
                peer.dialing = true;
                tokio::spawn(self.clone().dial(target));
            }
            return;
        };
        let max = conn.max_datagram_size().unwrap_or(0);
        let datagrams = peer.framer.frame(packet, max);
        match datagrams.len() {
            1 => c.sent_whole.fetch_add(1, Relaxed),
            2 => c.sent_split.fetch_add(1, Relaxed),
            _ => c.dropped_send.fetch_add(1, Relaxed),
        };
        for d in datagrams {
            if conn.send_datagram(d).is_err() {
                c.dropped_send.fetch_add(1, Relaxed);
            }
        }
    }

    async fn dial(self, target: EndpointId) {
        let mut addr = EndpointAddr::new(target);
        for url in &self.inner.config.relays {
            addr = addr.with_relay_url(url.clone());
        }
        let result =
            match tokio::time::timeout(DIAL_TIMEOUT, self.inner.endpoint.connect(addr, NET_ALPN))
                .await
            {
                Ok(r) => r.map_err(|e| e.to_string()),
                Err(_) => Err(format!("no connection within {DIAL_TIMEOUT:?}")),
            };
        {
            let mut peers = self.inner.peers.lock().expect("peers lock");
            if let Some(peer) = peers.get_mut(&target) {
                peer.dialing = false;
            }
        }
        match result {
            Ok(conn) => {
                if self.admit(&conn) {
                    self.receive(conn).await;
                }
            }
            Err(e) => tracing::debug!(peer = %target, error = %e, "mesh: dial failed"),
        }
    }

    fn admit(&self, conn: &Connection) -> bool {
        let id = conn.remote_id();
        let is_member = self
            .inner
            .view
            .read()
            .expect("view lock")
            .as_ref()
            .is_some_and(|v| v.own_slot != 0 && v.list.member_by_id(&id).is_some());
        if !is_member {
            self.inner
                .counters
                .refused_non_members
                .fetch_add(1, Relaxed);
            conn.close(1u32.into(), b"not a member");
            return false;
        }
        let mut peers = self.inner.peers.lock().expect("peers lock");
        let peer = peers.entry(id).or_default();
        peer.connections.retain(|c| c.close_reason().is_none());
        peer.connections.push(conn.clone());
        true
    }

    async fn receive(&self, conn: Connection) {
        let sender = conn.remote_id();
        let c = &self.inner.counters;
        let Some(tun) = self.inner.tun.get() else {
            return;
        };
        let mut reassembler = Reassembler::default();
        while let Ok(datagram) = conn.read_datagram().await {
            let Some(packet) = reassembler.push(datagram, Instant::now()) else {
                continue;
            };
            let verdict = {
                let view = self.inner.view.read().expect("view lock");
                match view.as_ref() {
                    Some(v) => match v.list.member_by_id(&sender) {
                        None => Verdict::NotMember,
                        Some(m) => match ipv6_addrs(&packet) {
                            Some((src, _))
                                if v.list.member_for(src).map(|x| x.slot) != Some(m.slot) =>
                            {
                                Verdict::Spoofed
                            }
                            Some((_, dst))
                                if v.list.member_for(dst).map(|x| x.slot) != Some(v.own_slot) =>
                            {
                                Verdict::NotForUs
                            }
                            Some(_) => Verdict::Deliver,
                            None => Verdict::Spoofed,
                        },
                    },
                    None => Verdict::NotMember,
                }
            };
            match verdict {
                Verdict::Deliver => {
                    c.received.fetch_add(1, Relaxed);
                    let _ = tun.write(&packet).await;
                }
                Verdict::Spoofed => {
                    c.dropped_spoofed_in.fetch_add(1, Relaxed);
                }
                Verdict::NotForUs => {
                    c.dropped_not_for_us.fetch_add(1, Relaxed);
                }
                Verdict::NotMember => {
                    conn.close(1u32.into(), b"not a member");
                    return;
                }
            }
        }
    }
}

enum Verdict {
    Deliver,
    Spoofed,
    NotForUs,
    NotMember,
}

impl ProtocolHandler for Mesh {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        if !self.admit(&connection) {
            return Err(AcceptError::from_err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "not a member of this network",
            )));
        }
        self.receive(connection).await;
        Ok(())
    }
}

fn close_all(peer: Peer) {
    for conn in peer.connections {
        conn.close(1u32.into(), b"removed from the network");
    }
}

fn describe_path(conn: &Connection) -> String {
    match conn.paths().iter().find(|p| p.is_selected()) {
        Some(p) => match p.remote_addr() {
            TransportAddr::Ip(a) => format!("direct {a}"),
            TransportAddr::Relay(u) => format!("relay {u}"),
            other => format!("other {other:?}"),
        },
        None => "none".into(),
    }
}

fn ipv6_addrs(packet: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr)> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let src: [u8; 16] = packet[8..24].try_into().ok()?;
    let dst: [u8; 16] = packet[24..40].try_into().ok()?;
    Some((Ipv6Addr::from(src), Ipv6Addr::from(dst)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ipv6_packets_have_addresses() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[8..24].copy_from_slice(&"fd00::1".parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(
            ipv6_addrs(&p),
            Some(("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap()))
        );
        p[0] = 0x45;
        assert_eq!(ipv6_addrs(&p), None);
        assert_eq!(ipv6_addrs(&[0x60; 20]), None);
    }
}
