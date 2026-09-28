//! The machine's side of its organisation's private network (grund/fleet
//! docs/design/network.md §5, §6; grund-net).
//!
//! When `grund join` pinned a network ([`crate::join::NetworkRecord`]), the
//! agent binds an iroh endpoint with the machine key, runs grund-net's mesh on
//! `grund0`, and keeps it fed with membership lists: `GetMembership` over the
//! control link, which answers at once when the epoch moved and otherwise
//! waits up to 10 s, so a revocation reaches the machine in about a second.
//!
//! A list is used only if it is signed by the key pinned at join (same key id
//! and public key), is for the pinned network and prefix, and is newer than
//! the last one. Otherwise the mesh keeps the last good list (fail-static).
//!
//! The endpoint binds only the uplink's addresses, so peers are never
//! offered docker, WireGuard or tailnet addresses (grund-net `endpoint`).
//! Every [`UPLINK_POLL`] the agent looks again: when an address it bound is
//! gone it binds a new endpoint with the same key and hands it to the mesh;
//! when only the route or the other addresses changed it tells iroh
//! (`network_change`), which probes its paths again at once instead of at
//! its next scheduled check.
//!
//! Once `grund0` is up, the agent answers `<name>.machines.grund.internal`
//! on `prefix:slot::53` from the list (grund-net `dns`), and forwards other
//! names to the resolvers in `/etc/resolv.conf`. It does not point the
//! machine's own resolver at itself.
//!
//! The relays come from the signed list when it names any, and otherwise
//! from join. A change in the list reaches the live endpoint at once
//! (`insert_relay`, `remove_relay`), with no re-join and no rebind.
//!
//! The mesh needs `CAP_NET_ADMIN` for the TUN device, so a machine whose
//! agent does not run as root skips it; service forwards for rootless
//! machines are not built. Relays are trusted by the system's certificate
//! store ([`relay_roots`]). With no relay, members reach each other only
//! where a direct path exists (the same LAN, or open UDP).

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};

use anyhow::{Context, bail};
use ed25519_dalek::VerifyingKey;
use grund_net::{
    NET_ALPN,
    endpoint::{self, Bind, NetConfig},
    membership::{MembershipList, SignedList},
    mesh::{Mesh, MeshConfig},
};
use grund_proto::grund::agent::v1::{GetMembershipRequest, GetMembershipResponse};
use iroh::RelayUrl;
use rustls::pki_types::CertificateDer;
use tokio::sync::watch;

use crate::{agent::Link, join::NetworkRecord};

/// The TUN device the mesh uses.
pub const TUN_NAME: &str = "grund0";

/// Why a membership list from the instance was not used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListRefusal {
    /// Signed by a key other than the one pinned at join.
    #[error("the list is signed by key {0}, not the network key pinned at join")]
    UnknownKey(String),
    /// The signature or the list's own rules failed.
    #[error("the list does not verify: {0}")]
    Invalid(String),
    /// For another network or prefix than the one pinned.
    #[error("the list is for another network or prefix")]
    WrongNetwork,
    /// Not newer than the list in force.
    #[error("epoch {0} is not newer than {1}")]
    Older(u64, u64),
}

/// Checks a list from `GetMembership` against the network pinned at join and
/// the epoch in force, and returns it when it may be used.
pub fn accept_list(
    network: &NetworkRecord,
    key_id: &str,
    body: &[u8],
    signature: &[u8],
    current_epoch: u64,
) -> Result<MembershipList, ListRefusal> {
    if key_id != network.key.key_id {
        return Err(ListRefusal::UnknownKey(key_id.to_string()));
    }
    let key = pinned_key(network).map_err(|e| ListRefusal::Invalid(e.to_string()))?;
    let signed = SignedList {
        body: body.to_vec(),
        signature: signature.to_vec(),
    };
    let list = signed
        .verify(&key)
        .map_err(|e| ListRefusal::Invalid(e.to_string()))?;
    let prefix = Ipv6Addr::from_str(&network.prefix).map_err(|_| ListRefusal::WrongNetwork)?;
    if list.network_id != network.network_id || list.prefix != prefix {
        return Err(ListRefusal::WrongNetwork);
    }
    if list.epoch <= current_epoch {
        return Err(ListRefusal::Older(list.epoch, current_epoch));
    }
    Ok(list)
}

fn pinned_key(network: &NetworkRecord) -> anyhow::Result<VerifyingKey> {
    if network.key.purpose != "network" {
        bail!(
            "the pinned key is a {} key, not a network key",
            network.key.purpose
        );
    }
    let bytes: [u8; 32] = hex::decode(&network.key.public_key)
        .context("the pinned network key is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the pinned network key is not 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("the pinned network key")
}

/// The file where the agent writes what its network is doing, every
/// second, for operators and tests: the mesh's peers and paths, the uplink
/// it offers, and how often it rebound.
pub const STATUS_FILE: &str = "network.json";

/// How long a home relay that stopped answering is left out of the
/// endpoint's relays, so that iroh homes on another at once rather than
/// retrying it (it took about 25 s in the lab). Peers still dial through it.
pub const RELAY_BENCH: Duration = Duration::from_secs(30);

/// How often the agent looks at the uplink for a changed address or route.
pub const UPLINK_POLL: Duration = Duration::from_secs(2);

/// The root certificates the machine trusts for grund's relays: the
/// system's store, as for the instance itself ([`crate::join::http_client`]),
/// so a self-hosted relay with its own CA works once that CA is installed.
/// `None` without a store: iroh's built-in web roots.
pub fn relay_roots() -> anyhow::Result<Option<Vec<CertificateDer<'static>>>> {
    use rustls::pki_types::pem::PemObject;
    let path = std::env::var_os("SSL_CERT_FILE")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            crate::join::SYSTEM_ROOTS
                .iter()
                .map(std::path::PathBuf::from)
                .find(|p| std::fs::metadata(p).is_ok_and(|m| m.len() > 0))
        });
    let Some(path) = path else {
        return Ok(None);
    };
    let pem = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let roots = CertificateDer::pem_slice_iter(&pem)
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    Ok((!roots.is_empty()).then_some(roots))
}

/// Whether the endpoint bound to `bound` must be replaced for an uplink
/// now offering `now`: an address it holds is gone, or an address family
/// appeared or went. A new address beside ones still there is not a reason.
pub fn needs_rebind(bound: &[SocketAddr], now: &[IpAddr]) -> bool {
    let families = |v4: bool| now.iter().any(|a| a.is_ipv4() == v4);
    bound.iter().any(|b| !now.contains(&b.ip()))
        || [true, false]
            .into_iter()
            .any(|v4| families(v4) != bound.iter().any(|b| b.is_ipv4() == v4))
}

#[derive(Debug)]
struct Counters {
    rebinds: AtomicU64,
    network_changes: AtomicU64,
    relay_failovers: AtomicU64,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            rebinds: AtomicU64::new(0),
            network_changes: AtomicU64::new(0),
            relay_failovers: AtomicU64::new(0),
        }
    }
}

pub(crate) async fn run(
    link: Link,
    network: NetworkRecord,
    seed: [u8; 32],
    data_dir: std::path::PathBuf,
) -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        tracing::warn!(
            "private network skipped: grund0 needs root (CAP_NET_ADMIN); rootless forwards are not built"
        );
        return Ok(());
    }
    pinned_key(&network)?;
    let relays = network
        .relay_urls
        .iter()
        .map(|u| RelayUrl::from_str(u).with_context(|| format!("relay URL {u}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let key = grund_net::key::secret_key(&seed);
    let own_id = key.public();
    let mesh = Mesh::new(
        own_id,
        MeshConfig {
            tun_name: TUN_NAME.into(),
            relays: relays.clone(),
        },
    );
    let config = NetConfig {
        relays,
        relay_roots: relay_roots()?,
        ..NetConfig::default()
    };
    let counters = Arc::new(Counters::default());
    let (tx, rx) = watch::channel(None);
    let lists = tx.subscribe();
    let (relays_tx, relays_rx) = watch::channel(config.relays.clone());
    tracing::info!(network = %network.network_id, slot = network.slot, "private network: starting");
    tokio::select! {
        result = mesh.run(rx) => result,
        result = follow(&link, &network, tx, relays_tx) => result,
        result = carry(&mesh, key, &config, relays_rx.clone(), &counters) => result,
        () = track_relays(&mesh, relays_rx) => Ok(()),
        () = resolve_or_warn(resolve(&mesh, lists, own_id)) => Ok(()),
        () = report(&mesh, &counters, &data_dir) => Ok(()),
    }
}

/// The relays a list names, when it names any: lists signed before relays
/// were carried leave the ones from join in force.
pub fn relays_of(list: &MembershipList) -> Option<Vec<RelayUrl>> {
    let relays: Vec<RelayUrl> = list
        .relays
        .iter()
        .filter_map(|r| RelayUrl::from_str(&r.url).ok())
        .collect();
    (!relays.is_empty()).then_some(relays)
}

async fn sync_relays(endpoint: &iroh::Endpoint, have: &[RelayUrl], wanted: &[RelayUrl]) {
    for url in have.iter().filter(|u| !wanted.contains(u)) {
        endpoint.remove_relay(url).await;
        tracing::info!(relay = %url, "private network: relay removed");
    }
    for url in wanted.iter().filter(|u| !have.contains(u)) {
        endpoint
            .insert_relay(url.clone(), Arc::new(iroh::RelayConfig::from(url.clone())))
            .await;
        tracing::info!(relay = %url, "private network: relay added");
    }
}

async fn track_relays(mesh: &Mesh, mut relays: watch::Receiver<Vec<RelayUrl>>) {
    while relays.changed().await.is_ok() {
        let wanted = relays.borrow_and_update().clone();
        let have = mesh.relays();
        mesh.set_relays(wanted.clone());
        if let Some(endpoint) = mesh.endpoint() {
            sync_relays(&endpoint, &have, &wanted).await;
        }
    }
}

async fn carry(
    mesh: &Mesh,
    key: iroh::SecretKey,
    config: &NetConfig,
    relays: watch::Receiver<Vec<RelayUrl>>,
    counters: &Counters,
) -> anyhow::Result<()> {
    let mut bound: Option<(Vec<SocketAddr>, iroh::protocol::Router)> = None;
    let mut last = endpoint::Uplinks::default();
    let mut homeless = 0u32;
    let mut benched: Vec<(RelayUrl, tokio::time::Instant)> = Vec::new();
    let mut tick = tokio::time::interval(UPLINK_POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        if let Some((_, router)) = &bound {
            let endpoint = router.endpoint();
            let wanted = relays.borrow().clone();
            let back: Vec<RelayUrl> = benched
                .iter()
                .filter(|(url, since)| since.elapsed() >= RELAY_BENCH && wanted.contains(url))
                .map(|(url, _)| url.clone())
                .collect();
            benched.retain(|(url, since)| since.elapsed() < RELAY_BENCH && wanted.contains(url));
            for url in back {
                endpoint
                    .insert_relay(url.clone(), Arc::new(iroh::RelayConfig::from(url.clone())))
                    .await;
                tracing::info!(relay = %url, "private network: trying a benched relay again");
            }
            match unanswering_home(endpoint) {
                Some(home) if wanted.len() > benched.len() + 1 => {
                    homeless += 1;
                    if homeless >= 2 {
                        tracing::info!(relay = %home, "private network: the home relay does not answer; benching it so iroh homes on another");
                        endpoint.remove_relay(&home).await;
                        benched.push((home, tokio::time::Instant::now()));
                        counters.relay_failovers.fetch_add(1, Relaxed);
                        homeless = 0;
                    }
                }
                _ => homeless = 0,
            }
        }
        let now = endpoint::uplinks().await;
        match &bound {
            Some((addrs, router)) if !needs_rebind(addrs, &now.addrs) => {
                if now != last {
                    tracing::info!(uplink = ?now.default_route, addrs = ?now.addrs, "private network: the network changed; telling iroh");
                    router.endpoint().network_change().await;
                    counters.network_changes.fetch_add(1, Relaxed);
                }
            }
            _ => {
                let addrs = endpoint::bind_addrs(&now.addrs, 0);
                if addrs.is_empty() {
                    if now != last {
                        tracing::warn!("private network: no uplink address; waiting for one");
                    }
                    last = now;
                    continue;
                }
                let bound_relays = relays.borrow().clone();
                let config = NetConfig {
                    bind: Bind::Addrs(addrs),
                    relays: bound_relays.clone(),
                    ..config.clone()
                };
                let endpoint = match endpoint::bind(key.clone(), &config, vec![NET_ALPN.to_vec()])
                    .await
                {
                    Ok(endpoint) => endpoint,
                    Err(error) => {
                        tracing::warn!(error = %format!("{error:#}"), "private network: binding the uplink failed; trying again");
                        continue;
                    }
                };
                let addrs = endpoint.bound_sockets();
                mesh.attach(endpoint.clone())?;
                let wanted = relays.borrow().clone();
                sync_relays(&endpoint, &bound_relays, &wanted).await;
                let router = iroh::protocol::Router::builder(endpoint)
                    .accept(NET_ALPN, mesh.clone())
                    .spawn();
                if let Some((old, old_router)) = bound.replace((addrs.clone(), router)) {
                    tracing::info!(from = ?old, to = ?addrs, "private network: the uplink's address changed; rebound");
                    counters.rebinds.fetch_add(1, Relaxed);
                    let _ = old_router.shutdown().await;
                } else {
                    tracing::info!(bound = ?addrs, "private network: bound to the uplink");
                }
            }
        }
        last = now;
    }
}

async fn resolve_or_warn(resolving: impl std::future::Future<Output = anyhow::Result<()>>) {
    if let Err(error) = resolving.await {
        tracing::warn!(
            error = %format!("{error:#}"),
            "private network: the stub resolver stopped; the mesh carries on without names"
        );
    }
    std::future::pending::<()>().await;
}

async fn bind_resolver(address: Ipv6Addr) -> anyhow::Result<tokio::net::UdpSocket> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::net::UdpSocket::bind(SocketAddr::new(address.into(), 53)).await {
            Ok(socket) => return Ok(socket),
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrNotAvailable
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("bind the stub resolver on [{address}]:53"));
            }
        }
    }
}

async fn resolve(
    mesh: &Mesh,
    lists: watch::Receiver<Option<MembershipList>>,
    own_id: iroh::EndpointId,
) -> anyhow::Result<()> {
    let own = mesh.up().await;
    let address = {
        let mut segments = own.segments();
        segments[7] = grund_net::dns::RESOLVER_HOST;
        Ipv6Addr::from(segments)
    };
    mesh.add_address(address)?;
    let socket = bind_resolver(address).await?;
    let prefix = Ipv6Addr::from({
        let mut o = own.octets();
        o[6..].fill(0);
        o
    });
    let upstreams = grund_net::dns::upstreams(
        &std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default(),
        prefix,
    );
    tracing::info!(%address, ?upstreams, "private network: resolving *.machines.grund.internal");
    grund_net::dns::serve(socket, lists, own_id, upstreams)
        .await
        .context("the stub resolver stopped")
}

fn unanswering_home(endpoint: &iroh::Endpoint) -> Option<RelayUrl> {
    use iroh::Watcher;
    let homes = endpoint.home_relay_status().get();
    if homes.iter().any(|s| s.is_connected()) {
        return None;
    }
    homes.first().map(|s| s.url().clone())
}

fn relay_status(endpoint: &iroh::Endpoint, relays: &[RelayUrl]) -> Vec<serde_json::Value> {
    use iroh::Watcher;
    let home = endpoint.home_relay_status().get();
    relays
        .iter()
        .map(|url| {
            let status = home.iter().find(|s| s.url() == url);
            serde_json::json!({
                "url": url.to_string(),
                "home": status.is_some(),
                "connected": status.is_some_and(|s| s.is_connected()),
                "denied": status.and_then(|s| s.auth_denied_reason()),
            })
        })
        .collect()
}

async fn report(mesh: &Mesh, counters: &Counters, data_dir: &std::path::Path) {
    let path = data_dir.join(STATUS_FILE);
    let temporary = data_dir.join(format!("{STATUS_FILE}.tmp"));
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let status = serde_json::json!({
            "mesh": mesh.status().await,
            "bound": mesh.endpoint().map(|e| e.bound_sockets()).unwrap_or_default(),
            "relays": mesh.endpoint().map(|e| relay_status(&e, &mesh.relays())).unwrap_or_default(),
            "rebinds": counters.rebinds.load(Relaxed),
            "network_changes": counters.network_changes.load(Relaxed),
            "relay_failovers": counters.relay_failovers.load(Relaxed),
        });
        if std::fs::write(&temporary, status.to_string()).is_ok() {
            let _ = std::fs::rename(&temporary, &path);
        }
    }
}

async fn follow(
    link: &Link,
    network: &NetworkRecord,
    tx: watch::Sender<Option<MembershipList>>,
    relays: watch::Sender<Vec<RelayUrl>>,
) -> anyhow::Result<()> {
    let mut epoch = 0;
    loop {
        let answer: anyhow::Result<GetMembershipResponse> = link
            .call(
                "GetMembership",
                &GetMembershipRequest {
                    network_id: network.network_id.clone(),
                    since_epoch: epoch,
                    ..Default::default()
                },
            )
            .await;
        match answer {
            Ok(answer) => {
                if let Some(signed) = answer.list.as_option() {
                    match accept_list(
                        network,
                        &signed.key_id,
                        &signed.body,
                        &signed.signature,
                        epoch,
                    ) {
                        Ok(list) => {
                            tracing::info!(
                                epoch = list.epoch,
                                members = list.members.len(),
                                "private network: list applied"
                            );
                            epoch = list.epoch;
                            if let Some(named) = relays_of(&list) {
                                relays.send_if_modified(|current| {
                                    let changed = *current != named;
                                    if changed {
                                        tracing::info!(relays = ?named, "private network: the list names new relays");
                                        *current = named;
                                    }
                                    changed
                                });
                            }
                            if tx.send(Some(list)).is_err() {
                                return Ok(());
                            }
                        }
                        Err(refusal) => {
                            tracing::warn!(%refusal, "private network: list refused; keeping the last good one");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "private network: GetMembership failed; keeping the last list");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use grund_net::membership::Member;

    use super::*;
    use crate::join::PinnedKey;

    fn network(key: &SigningKey) -> NetworkRecord {
        NetworkRecord {
            network_id: "net-1".into(),
            key: PinnedKey {
                key_id: "k1".into(),
                public_key: hex::encode(key.verifying_key().as_bytes()),
                purpose: "network".into(),
            },
            prefix: "fd12:3456:789a::".into(),
            slot: 1,
            relay_urls: vec![],
        }
    }

    fn list(epoch: u64, network_id: &str) -> MembershipList {
        MembershipList {
            network_id: network_id.into(),
            epoch,
            prefix: "fd12:3456:789a::".parse().unwrap(),
            issued_at: 1_790_000_000,
            relays: vec![],
            members: vec![Member {
                machine_id: "m1".into(),
                endpoint_id: grund_net::key::endpoint_id(&[1; 32]).to_string(),
                slot: 1,
                name: Some("m1".into()),
            }],
        }
    }

    #[test]
    fn only_a_lost_address_or_family_makes_the_agent_rebind() {
        let bound: Vec<SocketAddr> = vec![
            "192.168.1.20:4000".parse().unwrap(),
            "[2a01:4f8::20]:4000".parse().unwrap(),
        ];
        let ips = |list: &[&str]| {
            list.iter()
                .map(|a| a.parse().unwrap())
                .collect::<Vec<IpAddr>>()
        };
        assert!(!needs_rebind(
            &bound,
            &ips(&["192.168.1.20", "2a01:4f8::20"])
        ));
        assert!(!needs_rebind(
            &bound,
            &ips(&["192.168.1.20", "2a01:4f8::1", "2a01:4f8::20"])
        ));
        assert!(needs_rebind(
            &bound,
            &ips(&["192.168.1.21", "2a01:4f8::20"])
        ));
        assert!(needs_rebind(&bound, &ips(&["192.168.1.20"])));
        assert!(needs_rebind(
            &bound[..1],
            &ips(&["192.168.1.20", "2a01:4f8::20"])
        ));
        assert!(needs_rebind(&bound, &[]));
    }

    #[test]
    fn a_list_signed_by_the_pinned_key_for_this_network_and_newer_is_used() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let s = SignedList::sign(&list(2, "net-1"), &key);
        assert_eq!(
            accept_list(&network(&key), "k1", &s.body, &s.signature, 1),
            Ok(list(2, "net-1"))
        );
    }

    #[test]
    fn another_key_id_another_key_another_network_or_an_older_epoch_is_refused() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let net = network(&key);
        let s = SignedList::sign(&list(2, "net-1"), &key);
        assert_eq!(
            accept_list(&net, "k2", &s.body, &s.signature, 1),
            Err(ListRefusal::UnknownKey("k2".into()))
        );
        let forged = SignedList::sign(&list(2, "net-1"), &SigningKey::from_bytes(&[6; 32]));
        assert!(matches!(
            accept_list(&net, "k1", &forged.body, &forged.signature, 1),
            Err(ListRefusal::Invalid(_))
        ));
        let other = SignedList::sign(&list(2, "net-2"), &key);
        assert_eq!(
            accept_list(&net, "k1", &other.body, &other.signature, 1),
            Err(ListRefusal::WrongNetwork)
        );
        assert_eq!(
            accept_list(&net, "k1", &s.body, &s.signature, 2),
            Err(ListRefusal::Older(2, 2))
        );
    }
}
