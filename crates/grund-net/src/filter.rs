//! The private network's inbound filter: closed by default (grund-docs
//! design/network.md §11.4, decision 7).
//!
//! A packet from another member reaches `grund0` only if it is
//! - to a port this machine declares open, as its entry in the signed
//!   membership list says ([`crate::membership::Member::ports`]);
//! - or a reply to a flow this machine started: TCP or UDP from the
//!   address and port it sent to, back to the port it sent from, seen
//!   within [`TCP_IDLE`] or [`UDP_IDLE`];
//! - or ICMPv6 that IPv6 needs (destination unreachable, packet too big,
//!   time exceeded, parameter problem), or an echo request or reply. Echo is
//!   kept open so members can tell whether a peer is reachable; it tells a
//!   member nothing the list does not.
//!
//! Everything else is dropped: undeclared ports, other protocols, and IPv6
//! fragments, whose ports cannot be checked without reassembling them.
//! `grund0`'s MTU is 1280, so TCP never fragments; a UDP datagram larger
//! than about 1230 bytes does, and is dropped.
//!
//! It runs in the mesh's TUN path, in userspace, not in nftables: the same
//! code then guards a rootless machine's service forwards, which have no
//! TUN device and no firewall to lean on, and a change of the list takes
//! effect with the list, at once, with nothing on the host to keep in step.
//!
//! Outbound traffic is not filtered: the machine's own software decides
//! what it sends. Its flows are remembered ([`Filter::note_outbound`]) so
//! their replies pass.

use std::{
    collections::HashMap,
    net::Ipv6Addr,
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::membership::{Port, Transport};

/// How long a TCP flow this machine started admits replies after its last
/// outbound packet.
pub const TCP_IDLE: Duration = Duration::from_secs(60 * 60);

/// How long a UDP flow this machine started admits replies after its last
/// outbound packet.
pub const UDP_IDLE: Duration = Duration::from_secs(120);

/// The most flows remembered. Past it, expired flows go first, then the
/// oldest half.
pub const MAX_FLOWS: usize = 65_536;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMPV6: u8 = 58;

/// What the filter makes of an inbound packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    /// To a declared port.
    Declared,
    /// A reply to a flow this machine started.
    Reply,
    /// ICMPv6 that is let through.
    Icmp,
    /// Dropped.
    Closed,
}

impl Inbound {
    /// Whether the packet goes on to `grund0`.
    pub fn admitted(self) -> bool {
        !matches!(self, Inbound::Closed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Flow {
    transport: u8,
    local_port: u16,
    remote: Ipv6Addr,
    remote_port: u16,
}

/// The flows this machine started, for admitting their replies.
#[derive(Debug, Default)]
pub struct Filter {
    flows: Mutex<HashMap<Flow, Instant>>,
}

struct Parsed {
    transport: u8,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    icmp_type: u8,
}

fn parse(packet: &[u8]) -> Option<Parsed> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    let mut next = packet[6];
    let mut at = 40usize;
    loop {
        match next {
            0 | 43 | 60 => {
                let header = packet.get(at..at + 2)?;
                next = header[0];
                at += (usize::from(header[1]) + 1) * 8;
            }
            TCP | UDP => {
                let ports = packet.get(at..at + 4)?;
                return Some(Parsed {
                    transport: next,
                    src,
                    dst,
                    src_port: u16::from_be_bytes([ports[0], ports[1]]),
                    dst_port: u16::from_be_bytes([ports[2], ports[3]]),
                    icmp_type: 0,
                });
            }
            ICMPV6 => {
                return Some(Parsed {
                    transport: ICMPV6,
                    src,
                    dst,
                    src_port: 0,
                    dst_port: 0,
                    icmp_type: *packet.get(at)?,
                });
            }
            _ => return None,
        }
    }
}

fn idle(transport: u8) -> Duration {
    if transport == TCP { TCP_IDLE } else { UDP_IDLE }
}

impl Filter {
    /// Remembers the flow of a packet this machine sends, so its replies
    /// pass.
    pub fn note_outbound(&self, packet: &[u8], now: Instant) {
        let Some(p) = parse(packet).filter(|p| p.transport == TCP || p.transport == UDP) else {
            return;
        };
        let flow = Flow {
            transport: p.transport,
            local_port: p.src_port,
            remote: p.dst,
            remote_port: p.dst_port,
        };
        let mut flows = self.flows.lock().expect("flows lock");
        if flows.len() >= MAX_FLOWS && !flows.contains_key(&flow) {
            flows.retain(|f, seen| now.duration_since(*seen) < idle(f.transport));
            if flows.len() >= MAX_FLOWS {
                let mut ages: Vec<Instant> = flows.values().copied().collect();
                ages.sort();
                let cut = ages[ages.len() / 2];
                flows.retain(|_, seen| *seen > cut);
            }
        }
        flows.insert(flow, now);
    }

    /// Whether an inbound packet from another member may reach `grund0`,
    /// for a machine that declares `declared` open.
    pub fn inbound(&self, packet: &[u8], declared: &[Port], now: Instant) -> Inbound {
        let Some(p) = parse(packet) else {
            return Inbound::Closed;
        };
        if p.transport == ICMPV6 {
            return match p.icmp_type {
                1..=4 | 128 | 129 => Inbound::Icmp,
                _ => Inbound::Closed,
            };
        }
        let transport = if p.transport == TCP {
            Transport::Tcp
        } else {
            Transport::Udp
        };
        if declared
            .iter()
            .any(|d| d.transport == transport && d.port == p.dst_port)
        {
            return Inbound::Declared;
        }
        let flow = Flow {
            transport: p.transport,
            local_port: p.dst_port,
            remote: p.src,
            remote_port: p.src_port,
        };
        match self.flows.lock().expect("flows lock").get(&flow) {
            Some(seen) if now.duration_since(*seen) < idle(p.transport) => Inbound::Reply,
            _ => Inbound::Closed,
        }
    }

    /// How many flows are remembered.
    pub fn flows(&self) -> usize {
        self.flows.lock().expect("flows lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HERE: &str = "fd12:3456:789a:1::1";
    const PEER: &str = "fd12:3456:789a:2::1";

    fn packet(src: &str, dst: &str, next: u8, l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(l4.len() as u16).to_be_bytes());
        p[6] = next;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(l4);
        p
    }

    fn ports(src: u16, dst: u16) -> Vec<u8> {
        let mut l4 = vec![0u8; 20];
        l4[0..2].copy_from_slice(&src.to_be_bytes());
        l4[2..4].copy_from_slice(&dst.to_be_bytes());
        l4
    }

    fn tcp(port: u16) -> Port {
        Port {
            transport: Transport::Tcp,
            port,
        }
    }

    #[test]
    fn nothing_gets_in_unless_it_is_declared() {
        let filter = Filter::default();
        let now = Instant::now();
        let to_ssh = packet(PEER, HERE, TCP, &ports(40000, 22));
        assert_eq!(filter.inbound(&to_ssh, &[], now), Inbound::Closed);
        assert_eq!(filter.inbound(&to_ssh, &[tcp(80)], now), Inbound::Closed);
        assert_eq!(filter.inbound(&to_ssh, &[tcp(22)], now), Inbound::Declared);
        let udp_22 = packet(PEER, HERE, UDP, &ports(40000, 22));
        assert_eq!(
            filter.inbound(&udp_22, &[tcp(22)], now),
            Inbound::Closed,
            "a TCP port does not open UDP"
        );
    }

    #[test]
    fn replies_to_this_machines_own_flows_pass_until_they_go_idle() {
        let filter = Filter::default();
        let now = Instant::now();
        filter.note_outbound(&packet(HERE, PEER, TCP, &ports(51000, 5432)), now);
        let reply = packet(PEER, HERE, TCP, &ports(5432, 51000));
        assert_eq!(filter.inbound(&reply, &[], now), Inbound::Reply);
        let other_port = packet(PEER, HERE, TCP, &ports(5433, 51000));
        assert_eq!(filter.inbound(&other_port, &[], now), Inbound::Closed);
        let other_host = packet("fd12:3456:789a:3::1", HERE, TCP, &ports(5432, 51000));
        assert_eq!(filter.inbound(&other_host, &[], now), Inbound::Closed);
        assert_eq!(filter.inbound(&reply, &[], now + TCP_IDLE), Inbound::Closed);
        filter.note_outbound(&packet(HERE, PEER, UDP, &ports(53000, 53)), now);
        let dns = packet(PEER, HERE, UDP, &ports(53, 53000));
        assert_eq!(
            filter.inbound(&dns, &[], now + UDP_IDLE / 2),
            Inbound::Reply
        );
        assert_eq!(filter.inbound(&dns, &[], now + UDP_IDLE), Inbound::Closed);
    }

    #[test]
    fn icmp_that_ipv6_needs_and_echo_pass_and_the_rest_does_not() {
        let filter = Filter::default();
        let now = Instant::now();
        for (kind, admitted) in [
            (1, true),
            (2, true),
            (3, true),
            (4, true),
            (128, true),
            (129, true),
            (133, false),
            (135, false),
            (143, false),
        ] {
            let p = packet(PEER, HERE, ICMPV6, &[kind, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(
                filter.inbound(&p, &[], now).admitted(),
                admitted,
                "type {kind}"
            );
        }
    }

    #[test]
    fn fragments_other_protocols_and_garbage_are_dropped_and_extension_headers_are_walked() {
        let filter = Filter::default();
        let now = Instant::now();
        let mut fragment = vec![6u8, 0, 0, 0, 0, 0, 0, 1];
        fragment.extend_from_slice(&ports(40000, 22));
        assert_eq!(
            filter.inbound(&packet(PEER, HERE, 44, &fragment), &[tcp(22)], now),
            Inbound::Closed
        );
        assert_eq!(
            filter.inbound(&packet(PEER, HERE, 132, &ports(1, 22)), &[tcp(22)], now),
            Inbound::Closed
        );
        assert_eq!(
            filter.inbound(&[0x60; 30], &[tcp(22)], now),
            Inbound::Closed
        );
        let mut hop_by_hop = vec![6u8, 0, 0, 0, 0, 0, 0, 0];
        hop_by_hop.extend_from_slice(&ports(40000, 22));
        assert_eq!(
            filter.inbound(&packet(PEER, HERE, 0, &hop_by_hop), &[tcp(22)], now),
            Inbound::Declared
        );
    }

    #[test]
    fn the_flow_table_stays_bounded() {
        let filter = Filter::default();
        let now = Instant::now();
        for i in 0..(MAX_FLOWS + 10) {
            let port = (i % 60000) as u16 + 1;
            let host = format!("fd12:3456:789a:2::{:x}", i / 60000 + 1);
            filter.note_outbound(
                &packet(HERE, &host, UDP, &ports(port, 53)),
                now + Duration::from_millis(i as u64),
            );
        }
        assert!(filter.flows() <= MAX_FLOWS);
    }
}
