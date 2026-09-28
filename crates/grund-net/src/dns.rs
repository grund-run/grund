//! The stub resolver for `grund.internal` (network.md §6.2, §6.6).
//!
//! It answers from the membership list the machine holds, and from nothing
//! else: `<name>.machines.grund.internal` has an AAAA record, the member's
//! `prefix:slot::1`, for exactly the members of the current list. Every
//! other name under `grund.internal` does not exist. Names outside it are
//! forwarded to the resolvers the machine had ([`upstreams`]).
//!
//! When grund is unreachable the list stays the last one verified
//! (fail-static, network.md §5.3), so the names keep answering. Before any
//! list arrives the resolver says SERVFAIL: it does not know yet.
//!
//! A queries for members get no data. network.md §6.6 gives each name a
//! loopback alias (`127.77.x.y`) with service forwards listening behind it;
//! the forwards are not built, and an alias with nothing behind it would
//! send IPv4-only software to a port that refuses. So until they are, an
//! empty answer tells it at once that the name has no IPv4 address.
//!
//! UDP only, one question per query, no EDNS: every answer this zone gives
//! fits in 512 bytes.

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use iroh::EndpointId;
use tokio::{
    net::UdpSocket,
    sync::{Semaphore, watch},
};

use crate::membership::MembershipList;

/// The zone the resolver answers for itself.
pub const ZONE: &str = "grund.internal";

/// Machines' names live under this.
pub const MACHINES: &str = "machines.grund.internal";

/// The TTL of every answer, and of the negative ones. Short, because a
/// revocation or a new member changes the list within seconds.
pub const TTL: u32 = 5;

/// The interface id of the resolver's address in the machine's /64:
/// `prefix:slot::53` (network.md §6.2).
pub const RESOLVER_HOST: u16 = 0x53;

/// How long a forwarded query may take across all upstreams.
pub const FORWARD_BUDGET: Duration = Duration::from_secs(4);

/// How many forwarded queries may be in flight; more are dropped, and the
/// client retries as it would against any busy resolver.
pub const MAX_FORWARDS: usize = 64;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
const CLASS_ANY: u16 = 255;

/// Response codes the resolver gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

/// What to do with a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Send this response back.
    Reply(Vec<u8>),
    /// Not for `grund.internal`: ask the machine's own resolvers.
    Forward,
    /// Not a DNS query at all; say nothing.
    Ignore,
}

/// The resolver's address for a list: `prefix:slot::53`.
pub fn resolver_address(list: &MembershipList, slot: u16) -> Ipv6Addr {
    let mut segments = list.address(slot).segments();
    segments[7] = RESOLVER_HOST;
    Ipv6Addr::from(segments)
}

/// Answers `query` from `list`, the list this machine is a member of, or
/// `None` while it has none.
pub fn answer(query: &[u8], list: Option<&MembershipList>) -> Outcome {
    let Some(header) = query.get(..12) else {
        return Outcome::Ignore;
    };
    if header[2] & 0x80 != 0 {
        return Outcome::Ignore;
    }
    let opcode = (header[2] >> 3) & 0x0f;
    let qdcount = u16::from_be_bytes([header[4], header[5]]);
    if opcode != 0 {
        return Outcome::Reply(reply(query, None, Rcode::NotImp, &[]));
    }
    if qdcount != 1 {
        return Outcome::Reply(reply(query, None, Rcode::FormErr, &[]));
    }
    let Some(question) = Question::parse(query) else {
        return Outcome::Reply(reply(query, None, Rcode::FormErr, &[]));
    };
    let name = question.name.to_ascii_lowercase();
    if name != ZONE && !name.ends_with(&format!(".{ZONE}")) {
        return Outcome::Forward;
    }
    let Some(list) = list else {
        return Outcome::Reply(reply(query, Some(&question), Rcode::ServFail, &[]));
    };
    if question.class != CLASS_IN && question.class != CLASS_ANY {
        return Outcome::Reply(reply(query, Some(&question), Rcode::Refused, &[]));
    }
    if name == ZONE || name == MACHINES {
        return Outcome::Reply(reply(query, Some(&question), Rcode::NoError, &[]));
    }
    let member = name
        .strip_suffix(&format!(".{MACHINES}"))
        .filter(|label| !label.contains('.'))
        .and_then(|label| list.member_by_name(label));
    let Some(member) = member else {
        return Outcome::Reply(reply(query, Some(&question), Rcode::NxDomain, &[]));
    };
    let answers = match question.qtype {
        TYPE_AAAA | TYPE_ANY => vec![list.address(member.slot)],
        TYPE_A => vec![],
        _ => vec![],
    };
    Outcome::Reply(reply(query, Some(&question), Rcode::NoError, &answers))
}

/// A response saying `rcode` to `query`, for when it cannot be answered or
/// forwarded (no upstream, or none answered).
pub fn failure(query: &[u8], rcode: Rcode) -> Option<Vec<u8>> {
    let question = Question::parse(query)?;
    Some(reply(query, Some(&question), rcode, &[]))
}

struct Question {
    name: String,
    qtype: u16,
    class: u16,
    end: usize,
}

impl Question {
    fn parse(query: &[u8]) -> Option<Self> {
        let mut at = 12;
        let mut labels = Vec::new();
        loop {
            let len = *query.get(at)? as usize;
            at += 1;
            if len == 0 {
                break;
            }
            if len > 63 {
                return None;
            }
            let label = query.get(at..at + len)?;
            if !label.iter().all(|b| b.is_ascii_graphic() && *b != b'.') {
                return None;
            }
            labels.push(std::str::from_utf8(label).ok()?);
            at += len;
            if at > 12 + 255 {
                return None;
            }
        }
        let fixed = query.get(at..at + 4)?;
        Some(Self {
            name: labels.join("."),
            qtype: u16::from_be_bytes([fixed[0], fixed[1]]),
            class: u16::from_be_bytes([fixed[2], fixed[3]]),
            end: at + 4,
        })
    }
}

fn reply(query: &[u8], question: Option<&Question>, rcode: Rcode, aaaa: &[Ipv6Addr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + aaaa.len() * 28);
    out.extend_from_slice(&query[..2]);
    let rd = query[2] & 0x01;
    let authoritative = if question.is_some() && rcode != Rcode::ServFail {
        0x04
    } else {
        0
    };
    out.push(0x80 | authoritative | rd);
    out.push(0x80 | rcode as u8);
    out.extend_from_slice(&u16::from(question.is_some()).to_be_bytes());
    out.extend_from_slice(&(aaaa.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    if let Some(question) = question {
        out.extend_from_slice(&query[12..question.end]);
        for address in aaaa {
            out.extend_from_slice(&[0xc0, 0x0c]);
            out.extend_from_slice(&TYPE_AAAA.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&TTL.to_be_bytes());
            out.extend_from_slice(&16u16.to_be_bytes());
            out.extend_from_slice(&address.octets());
        }
    }
    out
}

/// The resolvers a machine had, from its `resolv.conf`, for names outside
/// `grund.internal`. Addresses inside the network's prefix (the stub itself,
/// or another member's) are left out, so the stub never asks itself.
pub fn upstreams(resolv_conf: &str, network_prefix: Ipv6Addr) -> Vec<SocketAddr> {
    let inside = |ip: &IpAddr| match ip {
        IpAddr::V6(v6) => v6.octets()[..6] == network_prefix.octets()[..6],
        IpAddr::V4(_) => false,
    };
    resolv_conf
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver")).then(|| words.next())?
        })
        .filter_map(|word| word.split('%').next()?.parse::<IpAddr>().ok())
        .filter(|ip| !inside(ip))
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

/// Serves the resolver on `socket` until the list source closes. Each query
/// is answered from the newest list in `lists`, taken as no list at all
/// while `own` is not a member of it.
pub async fn serve(
    socket: UdpSocket,
    lists: watch::Receiver<Option<MembershipList>>,
    own: EndpointId,
    upstreams: Vec<SocketAddr>,
) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    let upstreams: Arc<[SocketAddr]> = upstreams.into();
    let forwards = Arc::new(Semaphore::new(MAX_FORWARDS));
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, client) = socket.recv_from(&mut buf).await?;
        let query = &buf[..n];
        let list = lists
            .borrow()
            .clone()
            .filter(|l| l.member_by_id(&own).is_some());
        match answer(query, list.as_ref()) {
            Outcome::Reply(response) => {
                let _ = socket.send_to(&response, client).await;
            }
            Outcome::Ignore => {}
            Outcome::Forward => {
                let Ok(permit) = forwards.clone().try_acquire_owned() else {
                    continue;
                };
                let (socket, upstreams, query) =
                    (socket.clone(), upstreams.clone(), query.to_vec());
                tokio::spawn(async move {
                    let response = match forward(&query, &upstreams).await {
                        Some(response) => Some(response),
                        None if upstreams.is_empty() => failure(&query, Rcode::Refused),
                        None => failure(&query, Rcode::ServFail),
                    };
                    if let Some(response) = response {
                        let _ = socket.send_to(&response, client).await;
                    }
                    drop(permit);
                });
            }
        }
    }
}

async fn forward(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + FORWARD_BUDGET;
    let each = FORWARD_BUDGET / upstreams.len().max(1) as u32;
    for upstream in upstreams {
        let bind: SocketAddr = if upstream.is_ipv4() {
            "0.0.0.0:0".parse().expect("an address")
        } else {
            "[::]:0".parse().expect("an address")
        };
        let Ok(socket) = UdpSocket::bind(bind).await else {
            continue;
        };
        if socket.connect(upstream).await.is_err() || socket.send(query).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; 4096];
        let wait = each.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        if let Ok(Ok(n)) = tokio::time::timeout(wait, socket.recv(&mut buf)).await
            && n >= 12
            && buf[..2] == query[..2]
        {
            buf.truncate(n);
            return Some(buf);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::Member;

    fn list() -> MembershipList {
        MembershipList {
            network_id: "net_test".into(),
            epoch: 2,
            prefix: "fd12:3456:789a::".parse().unwrap(),
            issued_at: 1_790_000_000,
            members: vec![
                Member {
                    machine_id: "m_a".into(),
                    endpoint_id: crate::key::endpoint_id(&[1; 32]).to_string(),
                    slot: 1,
                    name: Some("web-1".into()),
                },
                Member {
                    machine_id: "m_b".into(),
                    endpoint_id: crate::key::endpoint_id(&[2; 32]).to_string(),
                    slot: 2,
                    name: Some("db".into()),
                },
            ],
        }
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn rcode(response: &[u8]) -> u8 {
        response[3] & 0x0f
    }

    fn aaaa(response: &[u8]) -> Vec<Ipv6Addr> {
        let count = u16::from_be_bytes([response[6], response[7]]) as usize;
        let question_end = Question::parse(response).unwrap().end;
        (0..count)
            .map(|i| {
                let rdata = question_end + i * 28 + 12;
                Ipv6Addr::from(<[u8; 16]>::try_from(&response[rdata..rdata + 16]).unwrap())
            })
            .collect()
    }

    fn reply_to(name: &str, qtype: u16, list: Option<&MembershipList>) -> Vec<u8> {
        match answer(&query(name, qtype), list) {
            Outcome::Reply(r) => r,
            other => panic!("{name}: {other:?}"),
        }
    }

    #[test]
    fn a_member_resolves_to_its_machine_address_in_any_case() {
        let l = list();
        let r = reply_to("DB.machines.grund.internal", TYPE_AAAA, Some(&l));
        assert_eq!(rcode(&r), 0);
        assert_eq!(&r[..2], &[0xab, 0xcd], "the id is the query's");
        assert_eq!(r[2] & 0x84, 0x84, "an authoritative response");
        assert_eq!(
            aaaa(&r),
            vec!["fd12:3456:789a:2::1".parse::<Ipv6Addr>().unwrap()]
        );
    }

    #[test]
    fn a_name_that_is_not_a_member_does_not_exist() {
        let l = list();
        for name in [
            "cache.machines.grund.internal",
            "a.db.machines.grund.internal",
            "db.grund.internal",
        ] {
            let r = reply_to(name, TYPE_AAAA, Some(&l));
            assert_eq!(rcode(&r), Rcode::NxDomain as u8, "{name}");
            assert!(aaaa(&r).is_empty());
        }
    }

    #[test]
    fn a_member_has_no_ipv4_address_until_loopback_aliases_exist() {
        let l = list();
        let r = reply_to("web-1.machines.grund.internal", TYPE_A, Some(&l));
        assert_eq!(rcode(&r), 0);
        assert!(aaaa(&r).is_empty());
    }

    #[test]
    fn before_any_list_the_zone_fails_rather_than_denying() {
        let r = reply_to("db.machines.grund.internal", TYPE_AAAA, None);
        assert_eq!(rcode(&r), Rcode::ServFail as u8);
    }

    #[test]
    fn names_outside_the_zone_go_to_the_machines_own_resolvers() {
        let l = list();
        for name in ["example.com", "grund.internal.example.com", "internal"] {
            assert_eq!(answer(&query(name, TYPE_A), Some(&l)), Outcome::Forward);
        }
    }

    #[test]
    fn responses_and_garbage_are_ignored_and_bad_questions_refused() {
        let l = list();
        let mut response = query("db.machines.grund.internal", TYPE_AAAA);
        response[2] |= 0x80;
        assert_eq!(answer(&response, Some(&l)), Outcome::Ignore);
        assert_eq!(answer(&[1, 2, 3], Some(&l)), Outcome::Ignore);
        let mut two = query("db.machines.grund.internal", TYPE_AAAA);
        two[5] = 2;
        assert!(matches!(answer(&two, Some(&l)), Outcome::Reply(r) if rcode(&r) == 1));
        let mut pointer = query("db.machines.grund.internal", TYPE_AAAA);
        pointer[12] = 0xc0;
        assert!(matches!(answer(&pointer, Some(&l)), Outcome::Reply(r) if rcode(&r) == 1));
    }

    #[test]
    fn upstreams_are_the_machines_resolvers_never_the_network_itself() {
        let conf = "# generated\nnameserver 192.168.1.1\nnameserver fd12:3456:789a:1::53\n\
                    nameserver fe80::1%eth0\noptions edns0\nnameserver 2001:db8::53\n";
        assert_eq!(
            upstreams(conf, "fd12:3456:789a::".parse().unwrap()),
            vec![
                "192.168.1.1:53".parse::<SocketAddr>().unwrap(),
                "[fe80::1]:53".parse().unwrap(),
                "[2001:db8::53]:53".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn the_resolver_listens_on_the_machines_53() {
        assert_eq!(
            resolver_address(&list(), 2),
            "fd12:3456:789a:2::53".parse::<Ipv6Addr>().unwrap()
        );
    }
}
