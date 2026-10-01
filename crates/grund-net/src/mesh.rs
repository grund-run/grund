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
//! The endpoint can be replaced while the mesh runs ([`Mesh::attach`]): a
//! machine whose uplink address changed binds a new one with the same key,
//! and its peers find it again through the relay.
//!
//! Past those checks, a packet reaches `grund0` only through the
//! closed-by-default filter ([`crate::filter`]): a port this machine
//! declares in the list, a reply to its own flow, or ICMPv6 IPv6 needs.
//!
//! A member is dialled through the relay the list says it is homed on
//! ([`dial_through`]), or through every relay when there is no hint or the
//! last dial through it failed.
//!
//! Members also hand each other grund's newest signed list over their
//! connections ([`crate::gossip`], [`Mesh::gossip`]); the mesh's owner
//! checks each before using it.
//!
//! A peer reached only through the relay for [`RELAYED_BEFORE_PROBE`] is
//! probed: a short connection on [`crate::PROBE_ALPN`] ([`Prober`]), on the
//! backoff [`probe_backoff`]. iroh 1.2 punches when a connection opens, once
//! more 5 s after a punch, and otherwise only every 60 s, so without the
//! probe a direct path that comes back after a longer outage, or that was
//! never there when the peers first met, waits up to a minute. A direct path
//! resets the backoff. Every relayed peer is probed, whether or not iroh
//! has told us direct addresses for it: iroh learns a peer's candidates
//! inside the connection and does not expose them, and its `remote_info`
//! lists only addresses of paths that once worked.
//!
//! App replicas on this machine ([`Mesh::attach_replica`]) each have a TUN
//! of their own inside their container's network namespace, and an address
//! in the machine's /64 (network.md §6.1). The mesh moves their packets as it
//! moves the machine's, and nothing is routed by the host:
//! - to a member's /64 over the network, as the machine's own packets go;
//! - to another replica on this machine, or to the machine itself, by
//!   writing it to that device;
//! - to anywhere else (the internet, IPv4) through the replica's
//!   [`crate::egress`].
//!
//! What reaches a replica passes its own filter with the ports its app
//! declares in the list ([`crate::membership::AppReplica::ports`]), whether
//! it comes from a member, from another replica here, or is a reply to the
//! replica's own flow. The machine itself (its agent and anything else on
//! the host, through `grund0`) reaches its replicas on any port. What a
//! replica sends to the machine passes the machine's filter, with the stub
//! resolver's port 53 open to it. A replica speaks only from its own
//! address.

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

/// How long a dial through a member's hinted home relay alone may take
/// before the next dial names every relay. Short: the hint may be stale (the
/// member moved to another relay and the list has not caught up), and then
/// nothing answers.
pub const HINTED_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// How long a connection may receive nothing at all, not even the
/// acknowledgements of its own keep-alives (sent every 500 ms, [`crate::endpoint::PATH_KEEPALIVE`]),
/// before the mesh closes it. Such a connection is stuck on a path that is
/// gone, typically a relay that stopped while its peer moved to another. iroh
/// keeps a relay path for 30 s and answers the peer's new handshake along it,
/// so the two would not meet again; closed, the next dial tries every relay.
pub const SILENT_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a peer must be reached only through the relay before the mesh
/// probes it. Longer than a path switch takes, so a probe does not race
/// iroh's own punch after a new connection.
pub const RELAYED_BEFORE_PROBE: std::time::Duration = std::time::Duration::from_secs(3);

/// How long a probe connection stays open, so that a punch iroh starts on it
/// can open the path on the peer's other connections before it closes.
pub const PROBE_HOLD: std::time::Duration = std::time::Duration::from_secs(3);

/// The wait after the `n`th probe of a peer that is still relayed: 5, 10, 20
/// and 40 s, then every 60 s, iroh's own path check. A peer that can never
/// punch costs four probes in its first 75 s and one a minute after that.
pub fn probe_backoff(n: u32) -> std::time::Duration {
    std::time::Duration::from_secs(match n {
        0 => 5,
        1 => 10,
        2 => 20,
        3 => 40,
        _ => 60,
    })
}

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
    own: EndpointId,
    replicas: RwLock<HashMap<Ipv6Addr, Arc<LocalReplica>>>,
    endpoint: RwLock<Option<Endpoint>>,
    relays: RwLock<Vec<RelayUrl>>,
    up: watch::Sender<Option<Ipv6Addr>>,
    config: MeshConfig,
    view: RwLock<Option<View>>,
    tun: tokio::sync::OnceCell<Tun>,
    peers: Mutex<HashMap<EndpointId, Peer>>,
    filter: crate::filter::Filter,
    gossip: std::sync::OnceLock<crate::gossip::GossipLink>,
    counters: Counters,
}

#[derive(Debug)]
struct LocalReplica {
    address: Ipv6Addr,
    tun: Arc<Tun>,
    filter: crate::filter::Filter,
    egress: Box<dyn crate::egress::Egress>,
    reader: std::sync::OnceLock<tokio::task::AbortHandle>,
}

impl Drop for LocalReplica {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.get() {
            reader.abort();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    Host,
    Replica,
    Member,
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
    heard: HashMap<usize, (u64, Instant)>,
    hint_failed: bool,
    relayed_since: Option<Instant>,
    next_probe: Option<Instant>,
    probes: u32,
    probing: bool,
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
    endpoints_attached: AtomicU64,
    closed_silent: AtomicU64,
    dropped_closed_in: AtomicU64,
    admitted_replies: AtomicU64,
    gossip_sent: AtomicU64,
    replica_out: AtomicU64,
    replica_in: AtomicU64,
    replica_egress: AtomicU64,
    dropped_replica_spoofed: AtomicU64,
    dropped_replica_closed: AtomicU64,
    probes_sent: AtomicU64,
    probes_failed: AtomicU64,
    probes_answered: AtomicU64,
    probe_bytes: AtomicU64,
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
    /// The peer's direct addresses this machine knows, as the peer offered
    /// them or as they were seen: its candidates for hole punching.
    pub direct_addrs: Vec<std::net::SocketAddr>,
    /// The relay the list says the peer is homed on, which dials use.
    pub relay_hint: Option<String>,
}

impl Mesh {
    /// A mesh for the machine whose key is `own`. It moves packets once it
    /// has an endpoint ([`Mesh::attach`]) and runs ([`Mesh::run`]).
    pub fn new(own: EndpointId, config: MeshConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                own,
                replicas: RwLock::new(HashMap::new()),
                endpoint: RwLock::new(None),
                relays: RwLock::new(config.relays.clone()),
                up: watch::Sender::new(None),
                config,
                view: RwLock::new(None),
                tun: tokio::sync::OnceCell::new(),
                peers: Mutex::new(HashMap::new()),
                filter: crate::filter::Filter::default(),
                gossip: std::sync::OnceLock::new(),
                counters: Counters::default(),
            }),
        }
    }

    /// Makes `endpoint` the one the mesh dials from, in place of any
    /// earlier one, whose connections are closed: they ran over sockets the
    /// machine no longer offers. Register the mesh with the new endpoint's
    /// iroh `Router` for [`crate::NET_ALPN`] too.
    pub fn attach(&self, endpoint: Endpoint) -> anyhow::Result<()> {
        if endpoint.id() != self.inner.own {
            bail!("the endpoint's key is not this machine's");
        }
        let old = self
            .inner
            .endpoint
            .write()
            .expect("endpoint lock")
            .replace(endpoint);
        if old.is_some() {
            self.inner
                .peers
                .lock()
                .expect("peers lock")
                .drain()
                .for_each(|(_, p)| close_all(p));
        }
        self.inner.counters.endpoints_attached.fetch_add(1, Relaxed);
        Ok(())
    }

    /// Makes `relays` the ones the mesh dials members through. A member is
    /// reachable at whichever of them is its home, so every dial names them
    /// all.
    pub fn set_relays(&self, relays: Vec<RelayUrl>) {
        *self.inner.relays.write().expect("relays lock") = relays;
    }

    /// Makes the mesh gossip ([`crate::gossip`]): hand `link.outgoing` to
    /// every member it connects to and to every connected member when it
    /// changes, and pass what members send to `link.incoming`. Set it
    /// before [`Mesh::run`]; a second call is ignored.
    pub fn gossip(&self, link: crate::gossip::GossipLink) {
        let _ = self.inner.gossip.set(link);
    }

    /// The relays the mesh dials members through now.
    pub fn relays(&self) -> Vec<RelayUrl> {
        self.inner.relays.read().expect("relays lock").clone()
    }

    /// The endpoint the mesh dials from now, if it has one.
    pub fn endpoint(&self) -> Option<Endpoint> {
        self.inner.endpoint.read().expect("endpoint lock").clone()
    }

    /// Waits until `grund0` is up, and returns the machine's address on it.
    pub async fn up(&self) -> Ipv6Addr {
        let mut up = self.inner.up.subscribe();
        loop {
            if let Some(address) = *up.borrow_and_update() {
                return address;
            }
            if up.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// `grund0`'s interface index, once the mesh is [`Mesh::up`].
    pub fn ifindex(&self) -> Option<i32> {
        self.inner.tun.get().map(Tun::ifindex)
    }

    /// Gives `grund0` another address in the machine's /64, such as the
    /// stub resolver's. Only once the mesh is [`Mesh::up`].
    pub fn add_address(&self, address: Ipv6Addr) -> anyhow::Result<()> {
        let tun = self.inner.tun.get().context("grund0 is not up yet")?;
        tun.add_address(address, 48)
    }

    /// Runs the mesh: waits for the first verified list that names this
    /// machine, creates the TUN device with its address, and from then on
    /// moves packets and applies newer lists. Returns only on an error, or
    /// when `lists`' sender is dropped.
    pub async fn run(
        &self,
        mut lists: watch::Receiver<Option<MembershipList>>,
    ) -> anyhow::Result<()> {
        let own = self.inner.own;
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
        self.inner.up.send_replace(Some(address));
        tracing::info!(%address, "mesh: up");

        let reader = tokio::spawn(self.clone().tun_to_peers());
        let watchdog = tokio::spawn(self.clone().close_silent_connections());
        let pusher = tokio::spawn(self.clone().push_newer_lists());
        let prober = tokio::spawn(self.clone().probe_relayed_peers());
        loop {
            if lists.changed().await.is_err() {
                reader.abort();
                watchdog.abort();
                pusher.abort();
                prober.abort();
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

    /// Carries the packets of the replica at `address`, whose own device
    /// is `tun` ([`Tun::create_in`]), in place of any earlier device for
    /// it. `egress` takes what it sends outside the private network.
    pub fn attach_replica(
        &self,
        address: Ipv6Addr,
        tun: Tun,
        egress: impl FnOnce(Arc<Tun>) -> Box<dyn crate::egress::Egress>,
    ) {
        let tun = Arc::new(tun);
        let replica = Arc::new(LocalReplica {
            address,
            egress: egress(tun.clone()),
            tun,
            filter: crate::filter::Filter::default(),
            reader: std::sync::OnceLock::new(),
        });
        let reader = tokio::spawn(self.clone().carry_replica(replica.clone()));
        let _ = replica.reader.set(reader.abort_handle());
        self.inner
            .replicas
            .write()
            .expect("replicas lock")
            .insert(address, replica);
        tracing::info!(%address, "mesh: replica attached");
    }

    /// Stops carrying the replica at `address`. Its device goes with its
    /// container's namespace.
    pub fn detach_replica(&self, address: Ipv6Addr) {
        if self
            .inner
            .replicas
            .write()
            .expect("replicas lock")
            .remove(&address)
            .is_some()
        {
            tracing::info!(%address, "mesh: replica detached");
        }
    }

    /// The addresses of the replicas the mesh carries.
    pub fn replicas(&self) -> Vec<Ipv6Addr> {
        let mut out: Vec<Ipv6Addr> = self
            .inner
            .replicas
            .read()
            .expect("replicas lock")
            .keys()
            .copied()
            .collect();
        out.sort();
        out
    }

    /// What each replica's egress has carried.
    pub fn egress_counters(&self) -> Vec<(Ipv6Addr, crate::egress::EgressCounters)> {
        let mut out: Vec<_> = self
            .inner
            .replicas
            .read()
            .expect("replicas lock")
            .values()
            .map(|r| (r.address, r.egress.counters()))
            .collect();
        out.sort_by_key(|(a, _)| *a);
        out
    }

    fn replica(&self, address: Ipv6Addr) -> Option<Arc<LocalReplica>> {
        self.inner
            .replicas
            .read()
            .expect("replicas lock")
            .get(&address)
            .cloned()
    }

    async fn carry_replica(self, replica: Arc<LocalReplica>) {
        let c = &self.inner.counters;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match replica.tun.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(address = %replica.address, error = %e, "mesh: reading a replica's device failed");
                    return;
                }
            };
            let packet = &buf[..n];
            let Some(&first) = packet.first() else {
                continue;
            };
            if first >> 4 == 4 {
                c.replica_egress.fetch_add(1, Relaxed);
                replica.egress.send(packet);
                continue;
            }
            let Some((src, dst)) = ipv6_addrs(packet) else {
                continue;
            };
            if src != replica.address {
                c.dropped_replica_spoofed.fetch_add(1, Relaxed);
                continue;
            }
            let (in_network, own_slot, target) = {
                let view = self.inner.view.read().expect("view lock");
                match view.as_ref() {
                    Some(v) => {
                        let in_network = v.list.prefix.octets()[..6] == dst.octets()[..6];
                        let target = v
                            .list
                            .member_for(dst)
                            .filter(|m| m.slot != v.own_slot)
                            .and_then(|m| EndpointId::from_str(&m.endpoint_id).ok());
                        (in_network, Some(v.own_slot), target)
                    }
                    None => (false, None, None),
                }
            };
            if !in_network {
                c.replica_egress.fetch_add(1, Relaxed);
                replica.egress.send(packet);
                continue;
            }
            c.replica_out.fetch_add(1, Relaxed);
            if let Some(target) = target {
                replica.filter.note_outbound(packet, Instant::now());
                self.send(target, packet);
            } else if own_slot.is_some() {
                replica.filter.note_outbound(packet, Instant::now());
                self.deliver_local(packet, dst, Origin::Replica).await;
            } else {
                c.dropped_no_member.fetch_add(1, Relaxed);
            }
        }
    }

    async fn deliver_local(&self, packet: &[u8], dst: Ipv6Addr, from: Origin) {
        let c = &self.inner.counters;
        let now = Instant::now();
        if let Some(replica) = self.replica(dst) {
            if from != Origin::Host {
                let ports = {
                    let view = self.inner.view.read().expect("view lock");
                    view.as_ref()
                        .and_then(|v| v.list.replica_at(dst).map(|(_, r)| r.ports.clone()))
                        .unwrap_or_default()
                };
                match replica.filter.inbound(packet, &ports, now) {
                    crate::filter::Inbound::Closed => {
                        c.dropped_replica_closed.fetch_add(1, Relaxed);
                        return;
                    }
                    crate::filter::Inbound::Reply => {
                        c.admitted_replies.fetch_add(1, Relaxed);
                    }
                    _ => {}
                }
            }
            c.replica_in.fetch_add(1, Relaxed);
            let _ = replica.tun.write(packet).await;
            return;
        }
        let Some(tun) = self.inner.tun.get() else {
            return;
        };
        let (mut open, resolver) = {
            let view = self.inner.view.read().expect("view lock");
            let open: Vec<crate::membership::Port> = view
                .as_ref()
                .and_then(|v| v.list.members.iter().find(|m| m.slot == v.own_slot))
                .map(|m| m.ports.clone())
                .unwrap_or_default();
            let resolver = view
                .as_ref()
                .map(|v| crate::dns::resolver_address(&v.list, v.own_slot));
            (open, resolver)
        };
        if from == Origin::Replica && Some(dst) == resolver {
            for transport in [
                crate::membership::Transport::Udp,
                crate::membership::Transport::Tcp,
            ] {
                open.push(crate::membership::Port {
                    transport,
                    port: 53,
                });
            }
        }
        match self.inner.filter.inbound(packet, &open, now) {
            crate::filter::Inbound::Closed => {
                c.dropped_closed_in.fetch_add(1, Relaxed);
                return;
            }
            crate::filter::Inbound::Reply => {
                c.admitted_replies.fetch_add(1, Relaxed);
            }
            _ => {}
        }
        c.received.fetch_add(1, Relaxed);
        let _ = tun.write(packet).await;
    }

    /// What the mesh is doing now.
    pub async fn status(&self) -> MeshStatus {
        let mut status = self.snapshot();
        if let Some(endpoint) = self.endpoint() {
            for peer in &mut status.peers {
                let Ok(id) = EndpointId::from_str(&peer.endpoint_id) else {
                    continue;
                };
                let info = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    endpoint.remote_info(id),
                )
                .await
                .ok()
                .flatten();
                if let Some(info) = info {
                    peer.direct_addrs = info
                        .addrs()
                        .filter_map(|a| match a.addr() {
                            TransportAddr::Ip(ip) => Some(*ip),
                            _ => None,
                        })
                        .collect();
                    peer.direct_addrs.sort();
                }
            }
        }
        status
    }

    fn snapshot(&self) -> MeshStatus {
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
            ("endpoints_attached", &c.endpoints_attached),
            ("closed_silent", &c.closed_silent),
            ("dropped_closed_in", &c.dropped_closed_in),
            ("admitted_replies", &c.admitted_replies),
            ("gossip_sent", &c.gossip_sent),
            ("replica_out", &c.replica_out),
            ("replica_in", &c.replica_in),
            ("replica_egress", &c.replica_egress),
            ("dropped_replica_spoofed", &c.dropped_replica_spoofed),
            ("dropped_replica_closed", &c.dropped_replica_closed),
            ("probes_sent", &c.probes_sent),
            ("probes_failed", &c.probes_failed),
            ("probes_answered", &c.probes_answered),
            ("probe_bytes", &c.probe_bytes),
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
                    direct_addrs: Vec::new(),
                    relay_hint: view
                        .as_ref()
                        .and_then(|v| v.list.member_by_id(id))
                        .and_then(|m| m.relay_url.clone()),
                })
                .collect(),
            counters,
        }
    }

    fn apply(&self, list: MembershipList) -> anyhow::Result<()> {
        list.validate()?;
        let own = self.inner.own;
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

    async fn push_newer_lists(self) {
        let Some(link) = self.inner.gossip.get() else {
            return;
        };
        let mut outgoing = link.outgoing.clone();
        while outgoing.changed().await.is_ok() {
            let Some(list) = outgoing.borrow_and_update().clone() else {
                continue;
            };
            let connections: Vec<Connection> = self
                .inner
                .peers
                .lock()
                .expect("peers lock")
                .values()
                .flat_map(|p| p.connections.iter().cloned())
                .filter(|c| c.close_reason().is_none())
                .collect();
            for conn in connections {
                let (list, mesh) = (list.clone(), self.clone());
                tokio::spawn(async move {
                    if crate::gossip::send(&conn, &list).await.is_ok() {
                        mesh.inner.counters.gossip_sent.fetch_add(1, Relaxed);
                    }
                });
            }
        }
    }

    async fn close_silent_connections(self) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let now = Instant::now();
            let mut peers = self.inner.peers.lock().expect("peers lock");
            for (id, peer) in peers.iter_mut() {
                peer.connections.retain(|c| c.close_reason().is_none());
                let live: Vec<usize> = peer.connections.iter().map(Connection::stable_id).collect();
                peer.heard.retain(|conn, _| live.contains(conn));
                for conn in &peer.connections {
                    let received = conn.stats().udp_rx.datagrams;
                    let heard = peer
                        .heard
                        .entry(conn.stable_id())
                        .or_insert((received, now));
                    if received != heard.0 {
                        *heard = (received, now);
                    } else if now.duration_since(heard.1) >= SILENT_LIMIT {
                        tracing::info!(peer = %id, path = %describe_path(conn), "mesh: closing a connection that hears nothing");
                        self.inner.counters.closed_silent.fetch_add(1, Relaxed);
                        conn.close(2u32.into(), b"silent");
                    }
                }
                peer.connections.retain(|c| c.close_reason().is_none());
            }
        }
    }

    async fn probe_relayed_peers(self) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let now = Instant::now();
            let due: Vec<EndpointId> = {
                let mut peers = self.inner.peers.lock().expect("peers lock");
                peers
                    .iter_mut()
                    .filter_map(|(id, peer)| {
                        peer.connections.retain(|c| c.close_reason().is_none());
                        match peer.connections.last().and_then(selected_is_relay) {
                            Some(true) => {
                                let since = *peer.relayed_since.get_or_insert(now);
                                let due = !peer.probing
                                    && now.duration_since(since) >= RELAYED_BEFORE_PROBE
                                    && peer.next_probe.is_none_or(|t| now >= t);
                                due.then_some(*id)
                            }
                            Some(false) | None => {
                                peer.relayed_since = None;
                                peer.next_probe = None;
                                peer.probes = 0;
                                None
                            }
                        }
                    })
                    .collect()
            };
            let Some(endpoint) = self.endpoint() else {
                continue;
            };
            for id in due {
                {
                    let mut peers = self.inner.peers.lock().expect("peers lock");
                    let Some(peer) = peers.get_mut(&id) else {
                        continue;
                    };
                    peer.probing = true;
                    peer.next_probe = Some(now + probe_backoff(peer.probes));
                    peer.probes += 1;
                }
                tokio::spawn(self.clone().probe(endpoint.clone(), id));
            }
        }
    }

    async fn probe(self, endpoint: Endpoint, target: EndpointId) {
        let c = &self.inner.counters;
        let mut addr = EndpointAddr::new(target);
        for url in self.dial_relays(target) {
            addr = addr.with_relay_url(url);
        }
        c.probes_sent.fetch_add(1, Relaxed);
        match tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(addr, crate::PROBE_ALPN)).await {
            Ok(Ok(conn)) => {
                let _ = tokio::time::timeout(PROBE_HOLD, conn.closed()).await;
                let stats = conn.stats();
                c.probe_bytes
                    .fetch_add(stats.udp_tx.bytes + stats.udp_rx.bytes, Relaxed);
                conn.close(0u32.into(), b"probe");
            }
            Ok(Err(e)) => {
                c.probes_failed.fetch_add(1, Relaxed);
                tracing::debug!(peer = %target, error = %e, "mesh: probe failed");
            }
            Err(_) => {
                c.probes_failed.fetch_add(1, Relaxed);
                tracing::debug!(peer = %target, "mesh: probe timed out");
            }
        }
        if let Some(peer) = self
            .inner
            .peers
            .lock()
            .expect("peers lock")
            .get_mut(&target)
        {
            peer.probing = false;
        }
    }

    /// The handler for [`crate::PROBE_ALPN`]: register it with the same iroh
    /// `Router` as the mesh.
    pub fn prober(&self) -> Prober {
        Prober { mesh: self.clone() }
    }

    fn is_member(&self, id: &EndpointId) -> bool {
        self.inner
            .view
            .read()
            .expect("view lock")
            .as_ref()
            .is_some_and(|v| v.own_slot != 0 && v.list.member_by_id(id).is_some())
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
                    Some(m) if m.slot != view.own_slot => {
                        EndpointId::from_str(&m.endpoint_id).ok().map(Some)
                    }
                    Some(_) => Some(None),
                    None => None,
                }
            };
            let target = match target {
                Some(Some(target)) => target,
                Some(None) => {
                    self.inner.filter.note_outbound(packet, Instant::now());
                    self.deliver_local(packet, dst, Origin::Host).await;
                    continue;
                }
                None => {
                    c.dropped_no_member.fetch_add(1, Relaxed);
                    continue;
                }
            };
            self.inner.filter.note_outbound(packet, Instant::now());
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
        let through = self.dial_relays(target);
        let timeout =
            if through.len() == 1 && self.inner.relays.read().expect("relays lock").len() > 1 {
                HINTED_DIAL_TIMEOUT
            } else {
                DIAL_TIMEOUT
            };
        for url in through {
            addr = addr.with_relay_url(url);
        }
        let result = match self.endpoint() {
            None => Err("no endpoint yet".to_string()),
            Some(endpoint) => {
                match tokio::time::timeout(timeout, endpoint.connect(addr, NET_ALPN)).await {
                    Ok(r) => r.map_err(|e| e.to_string()),
                    Err(_) => Err(format!("no connection within {timeout:?}")),
                }
            }
        };
        {
            let mut peers = self.inner.peers.lock().expect("peers lock");
            if let Some(peer) = peers.get_mut(&target) {
                peer.dialing = false;
                peer.hint_failed = result.is_err();
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

    fn dial_relays(&self, target: EndpointId) -> Vec<RelayUrl> {
        let relays = self.inner.relays.read().expect("relays lock").clone();
        let hint = self
            .inner
            .view
            .read()
            .expect("view lock")
            .as_ref()
            .and_then(|v| v.list.member_by_id(&target))
            .and_then(|m| m.relay_url.clone())
            .and_then(|url| RelayUrl::from_str(&url).ok());
        let failed = self
            .inner
            .peers
            .lock()
            .expect("peers lock")
            .get(&target)
            .is_some_and(|p| p.hint_failed);
        dial_through(&relays, hint, failed)
    }

    fn admit(&self, conn: &Connection) -> bool {
        let id = conn.remote_id();
        if !self.is_member(&id) {
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
        drop(peers);
        if let Some(link) = self.inner.gossip.get() {
            let (conn, link, mesh) = (conn.clone(), link.clone(), self.clone());
            tokio::spawn(async move {
                let current = link.outgoing.borrow().clone();
                if let Some(list) = current
                    && crate::gossip::send(&conn, &list).await.is_ok()
                {
                    mesh.inner.counters.gossip_sent.fetch_add(1, Relaxed);
                }
                crate::gossip::receive(conn, link.incoming).await;
            });
        }
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
            let (verdict, open) = {
                let view = self.inner.view.read().expect("view lock");
                let open: Vec<crate::membership::Port> = view
                    .as_ref()
                    .and_then(|v| v.list.members.iter().find(|m| m.slot == v.own_slot))
                    .map(|m| m.ports.clone())
                    .unwrap_or_default();
                let verdict = match view.as_ref() {
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
                };
                (verdict, open)
            };
            match verdict {
                Verdict::Deliver => {
                    let dst = ipv6_addrs(&packet).map(|(_, d)| d);
                    if let Some(dst) = dst.filter(|d| self.replica(*d).is_some()) {
                        self.deliver_local(&packet, dst, Origin::Member).await;
                        continue;
                    }
                    match self.inner.filter.inbound(&packet, &open, Instant::now()) {
                        crate::filter::Inbound::Closed => {
                            c.dropped_closed_in.fetch_add(1, Relaxed);
                            continue;
                        }
                        crate::filter::Inbound::Reply => {
                            c.admitted_replies.fetch_add(1, Relaxed);
                        }
                        _ => {}
                    }
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

/// Answers a member's probe ([`crate::PROBE_ALPN`]): holds the connection
/// until the member closes it, and refuses anyone else. A probe carries
/// nothing; it exists so that iroh punches again.
#[derive(Debug, Clone)]
pub struct Prober {
    mesh: Mesh,
}

impl ProtocolHandler for Prober {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let c = &self.mesh.inner.counters;
        if !self.mesh.is_member(&connection.remote_id()) {
            c.refused_non_members.fetch_add(1, Relaxed);
            connection.close(1u32.into(), b"not a member");
            return Err(AcceptError::from_err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "not a member of this network",
            )));
        }
        c.probes_answered.fetch_add(1, Relaxed);
        let _ = tokio::time::timeout(PROBE_HOLD * 2, connection.closed()).await;
        Ok(())
    }
}

/// The relays a dial to a member names: the one the list says it is homed
/// on, when that is one of ours and the last dial through it did not fail;
/// otherwise all of ours, since any may be its home.
pub fn dial_through(
    relays: &[RelayUrl],
    hint: Option<RelayUrl>,
    hint_failed: bool,
) -> Vec<RelayUrl> {
    match hint {
        Some(hint) if !hint_failed && relays.contains(&hint) => vec![hint],
        _ => relays.to_vec(),
    }
}

fn close_all(peer: Peer) {
    for conn in peer.connections {
        conn.close(1u32.into(), b"removed from the network");
    }
}

fn selected_is_relay(conn: &Connection) -> Option<bool> {
    conn.paths()
        .iter()
        .find(|p| p.is_selected())
        .map(|p| matches!(p.remote_addr(), TransportAddr::Relay(_)))
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
    fn a_member_is_dialled_through_its_home_relay_alone_until_that_fails() {
        let a: RelayUrl = "https://relay-a.example.com".parse().unwrap();
        let b: RelayUrl = "https://relay-b.example.com".parse().unwrap();
        let other: RelayUrl = "https://elsewhere.example.com".parse().unwrap();
        let ours = vec![a.clone(), b.clone()];
        assert_eq!(dial_through(&ours, Some(b.clone()), false), vec![b.clone()]);
        assert_eq!(dial_through(&ours, Some(b.clone()), true), ours);
        assert_eq!(dial_through(&ours, None, false), ours);
        assert_eq!(
            dial_through(&ours, Some(other), false),
            ours,
            "a hint that is none of ours is ignored"
        );
    }

    #[test]
    fn a_relayed_peer_is_probed_after_5_10_20_and_40_s_then_every_minute() {
        let waits: Vec<u64> = (0..7).map(|n| probe_backoff(n).as_secs()).collect();
        assert_eq!(waits, [5, 10, 20, 40, 60, 60, 60]);
    }

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
