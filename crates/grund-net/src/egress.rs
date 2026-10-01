//! A replica's way to the internet (grund-docs design/network.md §6.1): its
//! IPv4 traffic, and IPv6 outside the private network, ends in a userspace
//! TCP/UDP stack in the agent (smoltcp, through [netstack_smoltcp]), and each
//! flow is carried on an ordinary socket the agent opens on the host.
//!
//! Nothing is routed or translated by the host kernel: the host's packets
//! are its own, sent from the agent, so they leave through the OUTPUT hook
//! and never FORWARD. A firewall that drops forwarded traffic, as Docker's
//! `FORWARD` chain does with policy drop, does not touch them, and the host
//! needs no `ip_forward`, masquerade or nftables of grund's.
//!
//! What is carried: TCP and UDP. ICMP is not (a replica cannot ping the
//! internet), nor other protocols. A replica never reaches the host's
//! loopback, link-local addresses (a cloud host's metadata service), or
//! multicast and broadcast through it ([`allowed`]); its private network
//! traffic never comes here, the mesh carries it.
//!
//! [`Egress`] is the seam: a kernel fast path, where the host's firewall
//! forwards, can take a replica's packets instead of [`Userspace`].

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};

use tokio::{io::AsyncWriteExt, sync::mpsc, task::JoinHandle};

use crate::tun::{MTU, Tun};

/// How long a flow's host socket may take to connect.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a UDP flow lives without a datagram either way.
pub const UDP_IDLE: Duration = Duration::from_secs(60);

/// Packets from a replica waiting for the stack; past it, the newest are
/// dropped, as a full queue drops.
pub const QUEUE: usize = 1024;

/// Takes a replica's packets bound outside the private network.
pub trait Egress: Send + Sync + fmt::Debug {
    /// One packet the replica sent, IPv4 or IPv6, whole.
    fn send(&self, packet: &[u8]);
    /// What it has carried so far.
    fn counters(&self) -> EgressCounters;
}

/// What an [`Egress`] has done since it started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct EgressCounters {
    pub tcp_flows: u64,
    pub udp_flows: u64,
    pub refused: u64,
    pub failed: u64,
    pub dropped: u64,
}

#[derive(Debug, Default)]
struct Counts {
    tcp_flows: AtomicU64,
    udp_flows: AtomicU64,
    refused: AtomicU64,
    failed: AtomicU64,
    dropped: AtomicU64,
}

/// Whether a replica may reach `addr` on the internet: not loopback,
/// unspecified, link-local, multicast or broadcast, nor an address of the
/// private network (`fd00::/8` is grund's, the mesh carries it).
pub fn allowed(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.octets()[0] == 0)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return allowed(IpAddr::V4(v4));
            }
            let first = a.segments()[0];
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (first & 0xffc0) == 0xfe80
                || (first & 0xff00) == 0xfd00)
        }
    }
}

/// The userspace stack: smoltcp terminates the replica's TCP flows, its UDP
/// datagrams are matched to flows here, and each flow gets a host socket.
pub struct Userspace {
    packets: mpsc::Sender<Vec<u8>>,
    counts: Arc<Counts>,
    tasks: Vec<JoinHandle<()>>,
}

impl fmt::Debug for Userspace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Userspace").finish_non_exhaustive()
    }
}

impl Drop for Userspace {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Bytes each direction of a TCP flow may have buffered in the stack; with
/// smoltcp's window scaling this is the flow's receive window.
pub const TCP_BUFFER: u32 = 512 * 1024;

type UdpMessage = (Vec<u8>, SocketAddr, SocketAddr);

impl Userspace {
    /// Starts a stack whose packets back to the replica are written to
    /// `tun`, the replica's own device.
    pub fn start(tun: Arc<Tun>) -> Self {
        use futures::{SinkExt, StreamExt};
        let (packets, mut from_replica) = mpsc::channel::<Vec<u8>>(QUEUE);
        let counts = Arc::new(Counts::default());
        let built = netstack_smoltcp::StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .mtu(usize::from(MTU))
            .stack_buffer_size(QUEUE)
            .tcp_buffer_size(QUEUE)
            .udp_buffer_size(QUEUE)
            .tcp_recv_buffer_size(TCP_BUFFER)
            .tcp_send_buffer_size(TCP_BUFFER)
            .build();
        let mut tasks = Vec::new();
        let (stack, runner, udp, listener) = match built {
            Ok(built) => built,
            Err(error) => {
                tracing::error!(%error, "egress: the userspace stack did not start");
                return Self {
                    packets,
                    counts,
                    tasks,
                };
            }
        };
        if let Some(runner) = runner {
            tasks.push(tokio::spawn(async move {
                let _ = runner.await;
            }));
        }
        let (mut into_stack, mut out_of_stack) = stack.split();
        tasks.push(tokio::spawn(async move {
            while let Some(packet) = from_replica.recv().await {
                if into_stack.send(packet).await.is_err() {
                    return;
                }
            }
        }));
        tasks.push(tokio::spawn(async move {
            while let Some(packet) = out_of_stack.next().await {
                if let Ok(packet) = packet {
                    let _ = tun.write(&packet).await;
                }
            }
        }));
        if let Some(mut listener) = listener {
            let flows = counts.clone();
            tasks.push(tokio::spawn(async move {
                while let Some((stream, _replica, destination)) = listener.next().await {
                    tokio::spawn(carry_tcp(stream, destination, flows.clone()));
                }
            }));
        }
        if let Some(udp) = udp {
            let (mut datagrams, mut replies) = udp.split();
            let (reply_tx, mut reply_rx) = mpsc::channel::<UdpMessage>(QUEUE);
            tasks.push(tokio::spawn(async move {
                while let Some(message) = reply_rx.recv().await {
                    if replies.send(message).await.is_err() {
                        return;
                    }
                }
            }));
            let flows = counts.clone();
            tasks.push(tokio::spawn(async move {
                let mut open: std::collections::HashMap<
                    (SocketAddr, SocketAddr),
                    mpsc::Sender<Vec<u8>>,
                > = Default::default();
                while let Some((payload, replica, destination)) = datagrams.next().await {
                    open.retain(|_, flow| !flow.is_closed());
                    if let Some(flow) = open.get(&(replica, destination)) {
                        let _ = flow.try_send(payload);
                        continue;
                    }
                    if !allowed(destination.ip()) {
                        flows.refused.fetch_add(1, Relaxed);
                        continue;
                    }
                    let (flow_tx, flow_rx) = mpsc::channel(QUEUE);
                    let _ = flow_tx.try_send(payload);
                    open.insert((replica, destination), flow_tx);
                    tokio::spawn(carry_udp(
                        flow_rx,
                        replica,
                        destination,
                        reply_tx.clone(),
                        flows.clone(),
                    ));
                }
            }));
        }
        Self {
            packets,
            counts,
            tasks,
        }
    }
}

impl Egress for Userspace {
    fn send(&self, packet: &[u8]) {
        if self.packets.try_send(packet.to_vec()).is_err() {
            self.counts.dropped.fetch_add(1, Relaxed);
        }
    }

    fn counters(&self) -> EgressCounters {
        let c = &self.counts;
        EgressCounters {
            tcp_flows: c.tcp_flows.load(Relaxed),
            udp_flows: c.udp_flows.load(Relaxed),
            refused: c.refused.load(Relaxed),
            failed: c.failed.load(Relaxed),
            dropped: c.dropped.load(Relaxed),
        }
    }
}

async fn carry_tcp(
    mut stream: netstack_smoltcp::TcpStream,
    destination: SocketAddr,
    counts: Arc<Counts>,
) {
    if !allowed(destination.ip()) {
        counts.refused.fetch_add(1, Relaxed);
        return;
    }
    counts.tcp_flows.fetch_add(1, Relaxed);
    let host =
        match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(destination))
            .await
        {
            Ok(Ok(host)) => host,
            _ => {
                counts.failed.fetch_add(1, Relaxed);
                return;
            }
        };
    let _ = host.set_nodelay(true);
    let mut host = host;
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut host).await;
    let _ = host.shutdown().await;
    let _ = stream.shutdown().await;
}

async fn carry_udp(
    mut from_replica: mpsc::Receiver<Vec<u8>>,
    replica: SocketAddr,
    destination: SocketAddr,
    replies: mpsc::Sender<UdpMessage>,
    counts: Arc<Counts>,
) {
    counts.udp_flows.fetch_add(1, Relaxed);
    let bind: SocketAddr = if destination.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let Ok(socket) = tokio::net::UdpSocket::bind(bind).await else {
        counts.failed.fetch_add(1, Relaxed);
        return;
    };
    if socket.connect(destination).await.is_err() {
        counts.failed.fetch_add(1, Relaxed);
        return;
    }
    let mut from_host = vec![0u8; 65_536];
    loop {
        tokio::select! {
            datagram = tokio::time::timeout(UDP_IDLE, from_replica.recv()) => match datagram {
                Ok(Some(datagram)) => {
                    let _ = socket.send(&datagram).await;
                }
                _ => return,
            },
            received = socket.recv(&mut from_host) => match received {
                Ok(n) => {
                    if replies.send((from_host[..n].to_vec(), destination, replica)).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replica_reaches_the_internet_but_not_the_hosts_loopback_link_local_or_grunds_network() {
        for ok in ["1.1.1.1", "192.168.1.10", "10.0.0.5", "2606:4700::1111"] {
            assert!(allowed(ok.parse().unwrap()), "{ok}");
        }
        for no in [
            "127.0.0.1",
            "127.0.0.53",
            "0.0.0.0",
            "169.254.169.254",
            "224.0.0.251",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
            "fd12:3456:789a:1::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!allowed(no.parse().unwrap()), "{no}");
        }
    }
}
