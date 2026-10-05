//! grund's policy for an iroh endpoint (network.md §3, §8.2, §10).
//!
//! - **No n0 service**: `presets::Minimal`, no address lookup. A machine
//!   learns its peers' keys from the membership list, and reaches them
//!   through grund's relays.
//! - **grund's relays only**: the relay URLs come from grund (the enrolment
//!   response), and a self-hosted instance's own relay can use its own CA
//!   ([`NetConfig::relay_roots`]).
//! - **Short path timeouts**: a 2 s idle timeout and a 500 ms keep-alive.
//!   With iroh's defaults (15 s and 5 s), traffic stalled for over 25 s after
//!   a network change; with these it resumed in 3.1 s (network-verification.md
//!   U4).
//! - **Uplink addresses only**: iroh offers its peers every address of every
//!   socket it binds. Bound to the unspecified address, that is every
//!   interface, tailnets, WireGuard and docker bridges included. So the
//!   endpoint binds the addresses of the interface that carries the default
//!   route ([`uplink_addrs`]), and iroh's address discovery adds the public
//!   address a NAT maps them to. iroh cannot move a bound socket to another
//!   address, so when the uplink's addresses change, the machine binds a new
//!   endpoint with the same key (grund-agent `net.rs`, [`uplinks`]).

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, anyhow};
use iroh::{
    Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{QuicTransportConfig, presets},
    tls::CaTlsConfig,
};
use rustls::pki_types::CertificateDer;

/// The per-path idle timeout grund uses (iroh's default and maximum: 15 s).
pub const PATH_IDLE: Duration = Duration::from_secs(2);
/// How many bidirectional streams a peer may have open at once: the gate's
/// entry streams, one per proxied connection (grund-docs traffic.md §6.4,
/// §13). The mesh itself uses datagrams.
pub const MAX_BIDI_STREAMS: u32 = 1024;

/// How much a stream may have in flight unread, per stream (traffic.md §13).
pub const STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;

/// The per-path keep-alive grund uses (iroh's default and maximum: 5 s).
pub const PATH_KEEPALIVE: Duration = Duration::from_millis(500);

/// Interface name prefixes that are never uplinks: tunnels, bridges, and
/// grund's own device.
pub const NOT_UPLINKS: &[&str] = &[
    "lo",
    "grund",
    "tailscale",
    "wg",
    "docker",
    "br-",
    "veth",
    "virbr",
    "cni",
    "flannel",
    "cali",
    "cilium",
    "kube-",
    "weave",
    "vxlan",
    "podman",
    "lxcbr",
    "lxdbr",
    "vnet",
    "tun",
    "tap",
    "utun",
    "zt",
    "nebula",
];

/// How an endpoint is built.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// grund's relay URLs. Empty: no relay, direct paths only (the backplane,
    /// or a machine on one LAN with its peers).
    pub relays: Vec<RelayUrl>,
    /// Which local addresses to bind, and so to offer peers.
    pub bind: Bind,
    /// Root certificates for the relays' TLS. `None`: the embedded web PKI
    /// roots, as for grund's hosted relays.
    pub relay_roots: Option<Vec<CertificateDer<'static>>>,
    /// The per-path idle timeout.
    pub path_idle: Duration,
    /// The per-path keep-alive.
    pub path_keepalive: Duration,
}

/// The local addresses an endpoint binds.
#[derive(Debug, Clone)]
pub enum Bind {
    /// The uplink's addresses ([`uplink_addrs`]), on this UDP port, the same
    /// for IPv4 and IPv6 (0: any free port).
    Uplinks(u16),
    /// Exactly these, at most one per address family.
    Addrs(Vec<SocketAddr>),
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            bind: Bind::Uplinks(0),
            relay_roots: None,
            path_idle: PATH_IDLE,
            path_keepalive: PATH_KEEPALIVE,
        }
    }
}

/// Builds and binds an endpoint with grund's policy, for the given ALPNs.
/// Its TLS, to peers and to relays, uses `grund_tls::provider()`, so it
/// prefers X25519MLKEM768 and still sends an X25519 share for a peer or
/// relay without it.
/// Waits up to 5 s for the home relay when there is one, so the endpoint can
/// be dialed through it as soon as this returns.
pub async fn bind(
    key: SecretKey,
    config: &NetConfig,
    alpns: Vec<Vec<u8>>,
) -> anyhow::Result<Endpoint> {
    let endpoint = bind_now(key, config, alpns).await?;
    if !config.relays.is_empty() {
        let _ = tokio::time::timeout(Duration::from_secs(5), endpoint.online()).await;
    }
    Ok(endpoint)
}

/// [`bind`] without waiting for a relay: for an endpoint that only dials,
/// whose owner must not wait on a relay that may be down.
pub async fn bind_now(
    key: SecretKey,
    config: &NetConfig,
    alpns: Vec<Vec<u8>>,
) -> anyhow::Result<Endpoint> {
    let transport = QuicTransportConfig::builder()
        .default_path_max_idle_timeout(config.path_idle)
        .default_path_keep_alive_interval(config.path_keepalive)
        .datagram_receive_buffer_size(Some(4 << 20))
        .datagram_send_buffer_size(4 << 20)
        .max_concurrent_bidi_streams(iroh::endpoint::VarInt::from_u32(MAX_BIDI_STREAMS))
        .stream_receive_window(iroh::endpoint::VarInt::from_u32(STREAM_RECEIVE_WINDOW))
        .build();
    let mut builder = Endpoint::builder(presets::Minimal)
        .crypto_provider(grund_tls::provider())
        .secret_key(key)
        .alpns(alpns)
        .transport_config(transport)
        .clear_ip_transports();
    let addrs = match &config.bind {
        Bind::Addrs(addrs) => addrs.clone(),
        Bind::Uplinks(port) => bind_addrs(&uplink_addrs().await, *port),
    };
    if addrs.is_empty() {
        anyhow::bail!("no uplink address to bind: no interface carries a default route");
    }
    for family_v4 in [true, false] {
        if let Some(addr) = addrs.iter().find(|a| a.is_ipv4() == family_v4) {
            builder = builder
                .bind_addr(*addr)
                .map_err(|e| anyhow!("bind {addr}: {e}"))?;
        }
    }
    builder = if config.relays.is_empty() {
        builder.relay_mode(RelayMode::Disabled)
    } else {
        builder.relay_mode(RelayMode::Custom(RelayMap::from_iter(
            config.relays.iter().cloned(),
        )))
    };
    if let Some(roots) = &config.relay_roots {
        builder = builder.ca_tls_config(CaTlsConfig::custom_roots(roots.iter().cloned()));
    }
    builder.bind().await.context("bind the iroh endpoint")
}

/// The endpoint's home relay while it is not connected to any, as iroh's
/// relay actor backs off: up to 16 s between attempts, with no way to reset
/// it but a new endpoint ([`relay_ping_url`]).
pub fn unanswering_home(endpoint: &Endpoint) -> Option<RelayUrl> {
    use iroh::Watcher;
    let homes = endpoint.home_relay_status().get();
    if homes.iter().any(|s| s.is_connected()) {
        return None;
    }
    homes.first().map(|s| s.url().clone())
}

/// The URL that answers once the relay at `relay` serves again: its
/// `/ping`. An endpoint bound anew when it answers reaches the relay at
/// once, where the old one may wait out its back-off.
pub fn relay_ping_url(relay: &RelayUrl) -> String {
    format!("{}/ping", relay.as_str().trim_end_matches('/'))
}

/// The uplink as the machine sees it now: the interface carrying the
/// default route, and the addresses [`select_uplinks`] offers from it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Uplinks {
    /// The interface with the default route, if any.
    pub default_route: Option<String>,
    /// What the endpoint binds and offers peers, sorted.
    pub addrs: Vec<IpAddr>,
}

/// One interface as [`select_uplinks`] sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub up: bool,
    pub addrs: Vec<IpAddr>,
}

/// Reads the interfaces and picks the uplink ([`select_uplinks`]).
pub async fn uplinks() -> Uplinks {
    let state = netwatch::interfaces::State::new().await;
    let interfaces: Vec<Interface> = state
        .interfaces
        .values()
        .map(|i| Interface {
            name: i.name().to_string(),
            up: i.is_up(),
            addrs: i.addrs().map(|net| net.addr()).collect(),
        })
        .collect();
    let default_route = state.default_route_interface.clone();
    Uplinks {
        addrs: select_uplinks(default_route.as_deref(), &interfaces),
        default_route,
    }
}

/// What an endpoint binds of `addrs`: the first of each address family, on
/// `port`. A machine that has two IPv6 addresses on its uplink (a stable one
/// and a temporary one) binds one, so a new temporary address is not a
/// reason to rebind.
pub fn bind_addrs(addrs: &[IpAddr], port: u16) -> Vec<SocketAddr> {
    [true, false]
        .into_iter()
        .filter_map(|v4| addrs.iter().find(|a| a.is_ipv4() == v4))
        .map(|ip| SocketAddr::new(*ip, port))
        .collect()
}

/// The addresses a machine offers its peers ([`uplinks`]).
pub async fn uplink_addrs() -> Vec<IpAddr> {
    uplinks().await.addrs
}

/// The addresses a machine offers its peers: those of the interface that
/// carries the default route, or, when there is none or it is itself a
/// tunnel, of every interface that is not a tunnel or bridge
/// ([`NOT_UPLINKS`]). Loopback, link-local and IPv6 unique-local addresses
/// are left out: the last are what private networks and tailnets hand out.
pub fn select_uplinks(default_route: Option<&str>, interfaces: &[Interface]) -> Vec<IpAddr> {
    let usable = |name: &str| !NOT_UPLINKS.iter().any(|p| name.starts_with(p));
    let chosen: Vec<&Interface> = match default_route {
        Some(name) if usable(name) => interfaces.iter().filter(|i| i.name == name).collect(),
        _ => interfaces.iter().filter(|i| usable(&i.name)).collect(),
    };
    let mut out: Vec<IpAddr> = chosen
        .into_iter()
        .filter(|i| i.up)
        .flat_map(|i| i.addrs.iter().copied())
        .filter(is_offerable)
        .collect();
    out.sort();
    out.dedup();
    out
}

fn is_offerable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !v6.is_loopback()
                && !v6.is_unspecified()
                && (first & 0xffc0) != 0xfe80
                && (first & 0xfe00) != 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, addrs: &[&str]) -> Interface {
        Interface {
            name: name.into(),
            up: true,
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    fn a_busy_host() -> Vec<Interface> {
        vec![
            iface("lo", &["127.0.0.1", "::1"]),
            iface("enp5s0", &["192.168.1.20", "2a01:4f8::20", "fe80::1"]),
            iface("wg0", &["10.0.0.5"]),
            iface("tailscale0", &["100.101.1.2", "fd7a:115c:a1e0::2"]),
            iface("docker0", &["172.17.0.1"]),
            iface("br-3f2a", &["172.18.0.1", "10.254.1.1"]),
            iface("veth12ab", &["fe80::2"]),
            iface("grund0", &["fd12:3456:789a:1::1"]),
        ]
    }

    #[test]
    fn only_the_default_routes_interface_is_offered_never_tunnels_or_bridges() {
        let got = select_uplinks(Some("enp5s0"), &a_busy_host());
        assert_eq!(
            got,
            vec![
                "192.168.1.20".parse::<IpAddr>().unwrap(),
                "2a01:4f8::20".parse().unwrap()
            ]
        );
    }

    #[test]
    fn a_default_route_through_a_tunnel_falls_back_to_the_real_interfaces() {
        for tunnel in ["wg0", "tailscale0", "tun0"] {
            let got = select_uplinks(Some(tunnel), &a_busy_host());
            assert_eq!(
                got,
                vec![
                    "192.168.1.20".parse::<IpAddr>().unwrap(),
                    "2a01:4f8::20".parse().unwrap()
                ],
                "{tunnel}"
            );
        }
        assert_eq!(select_uplinks(None, &a_busy_host()).len(), 2);
    }

    #[test]
    fn one_address_per_family_is_bound() {
        let addrs: Vec<IpAddr> = [
            "192.168.1.20",
            "2a01:4f8::20",
            "2a01:4f8::99",
            "192.168.1.21",
        ]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
        assert_eq!(
            bind_addrs(&addrs, 7),
            vec![
                "192.168.1.20:7".parse::<SocketAddr>().unwrap(),
                "[2a01:4f8::20]:7".parse().unwrap()
            ]
        );
    }

    #[test]
    fn a_down_uplink_offers_nothing() {
        let mut interfaces = a_busy_host();
        interfaces[1].up = false;
        assert!(select_uplinks(Some("enp5s0"), &interfaces).is_empty());
    }

    #[test]
    fn link_local_loopback_and_unique_local_addresses_are_never_offered() {
        for bad in [
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "fd7a:115c:a1e0::1",
            "0.0.0.0",
        ] {
            assert!(!is_offerable(&bad.parse().unwrap()), "{bad}");
        }
        for good in ["192.168.1.20", "100.64.0.9", "2a01:4f8::1"] {
            assert!(is_offerable(&good.parse().unwrap()), "{good}");
        }
    }

    fn loopback() -> NetConfig {
        NetConfig {
            bind: Bind::Addrs(vec!["127.0.0.1:0".parse().unwrap()]),
            ..NetConfig::default()
        }
    }

    const ALPN: &[u8] = b"grund-test/hybrid";

    async fn ring_only_endpoint(seed: u8) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .alpns(vec![ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap()
    }

    async fn connects(from: &Endpoint, to: &Endpoint) {
        let accepting = to.clone();
        let accepted = tokio::spawn(async move {
            let incoming = accepting.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            conn.closed().await;
        });
        let conn = tokio::time::timeout(Duration::from_secs(10), from.connect(to.addr(), ALPN))
            .await
            .expect("no connection within 10 s")
            .unwrap();
        assert_eq!(conn.remote_id(), to.id());
        conn.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(Duration::from_secs(5), accepted).await;
    }

    #[tokio::test]
    async fn the_endpoint_prefers_the_hybrid_post_quantum_group() {
        let endpoint = bind(
            SecretKey::from_bytes(&[1; 32]),
            &loopback(),
            vec![ALPN.to_vec()],
        )
        .await
        .unwrap();
        let groups: Vec<_> = endpoint
            .tls_config()
            .crypto_provider()
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect();
        assert_eq!(
            groups[..2],
            [
                rustls::NamedGroup::X25519MLKEM768,
                rustls::NamedGroup::X25519
            ]
        );
        endpoint.close().await;
    }

    #[tokio::test]
    async fn grund_endpoints_connect_to_each_other_and_to_a_ring_only_endpoint_both_ways() {
        let a = bind(
            SecretKey::from_bytes(&[2; 32]),
            &loopback(),
            vec![ALPN.to_vec()],
        )
        .await
        .unwrap();
        let b = bind(
            SecretKey::from_bytes(&[3; 32]),
            &loopback(),
            vec![ALPN.to_vec()],
        )
        .await
        .unwrap();
        let old = ring_only_endpoint(4).await;
        connects(&a, &b).await;
        connects(&a, &old).await;
        connects(&old, &b).await;
        for endpoint in [a, b, old] {
            endpoint.close().await;
        }
    }
}
