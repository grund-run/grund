//! What the gate routes to (grund-docs design/traffic.md §7.3, §8): the
//! apps placed on this machine with a published port, by host, and each
//! copy's state as the gate sees it now.
//!
//! The table is rebuilt from the agent's document and its apps loop's view
//! of each replica ([`ReplicaEndpoint`], grund-net2's interface) whenever
//! either changes. A copy's in-flight count, its passive ejection and its
//! close signal live in [`CopyState`], which survives rebuilds, so a request
//! picked before a rollout finishes on the copy it was given.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

use grund_proto::grund::agent::v1::{DesiredState, ReplicaState};
use tokio_util::sync::CancellationToken;

/// How long a passive ejection lasts when no probe clears it sooner: one
/// default check interval (§8.3: "until the next pass").
pub const EJECTION: Duration = Duration::from_secs(2);

/// One port of a replica, as its document entry declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPort {
    pub name: String,
    pub port: u16,
    /// `http`, `h2c` or `tcp`.
    pub protocol: String,
}

/// One local replica as the apps loop sees it: grund-net2's
/// `ReplicaEndpoint` (container-net-design.md, "The interface for the
/// gate"). Until the agent publishes it, [`endpoints_from`] builds it from
/// the document and the apps loop's last reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaEndpoint {
    pub replica_id: String,
    pub app: String,
    pub address: Option<IpAddr>,
    pub ports: Vec<EndpointPort>,
    /// The agent's probe (apps.md §8.1).
    pub ready: bool,
    /// The document marks it draining.
    pub draining: bool,
}

/// A ready copy of an app on another machine, reached over the private
/// network (from the signed list's `members[].apps[]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCopy {
    pub replica_id: String,
    pub app: String,
    pub machine_id: String,
    pub address: IpAddr,
    pub ports: Vec<u16>,
    pub ready: bool,
}

/// Builds the apps loop's view of each replica from what the agent already
/// shares: the document's entries, joined with the last reports' `ready`.
pub fn endpoints_from(
    document: Option<&DesiredState>,
    reports: &[grund_proto::grund::agent::v1::ReplicaObserved],
) -> Vec<ReplicaEndpoint> {
    let Some(document) = document else {
        return Vec::new();
    };
    document
        .replicas
        .iter()
        .map(|replica| ReplicaEndpoint {
            replica_id: replica.replica_id.clone(),
            app: replica.app.clone(),
            address: None,
            ports: replica
                .ports
                .iter()
                .filter_map(|p| {
                    Some(EndpointPort {
                        name: p.name.clone(),
                        port: u16::try_from(p.port).ok()?,
                        protocol: p.protocol.clone(),
                    })
                })
                .collect(),
            ready: reports
                .iter()
                .any(|r| r.replica_id == replica.replica_id && r.ready),
            draining: replica.state.as_known() == Some(ReplicaState::REPLICA_STATE_DRAINING),
        })
        .collect()
}

/// The protocol the gate speaks to a copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upstream {
    Http1,
    H2c,
}

/// What the gate keeps of one copy across table rebuilds.
#[derive(Debug)]
pub struct CopyState {
    pub replica_id: String,
    pub inflight: AtomicUsize,
    ejected_until: Mutex<Option<Instant>>,
    /// Cancelled when the copy leaves the document: what is still open to it
    /// is closed (§8.5, the end of `drain`).
    pub closing: CancellationToken,
}

impl CopyState {
    fn new(replica_id: &str) -> Self {
        Self {
            replica_id: replica_id.to_string(),
            inflight: AtomicUsize::new(0),
            ejected_until: Mutex::new(None),
            closing: CancellationToken::new(),
        }
    }

    /// Takes the copy out of the gate's choice at once: a refused connection
    /// (§8.3, passive).
    pub fn eject(&self) {
        *self.ejected_until.lock().expect("ejection lock") = Some(Instant::now() + EJECTION);
    }

    pub fn ejected(&self) -> bool {
        self.ejected_until
            .lock()
            .expect("ejection lock")
            .is_some_and(|until| Instant::now() < until)
    }

    fn clear_ejection(&self) {
        *self.ejected_until.lock().expect("ejection lock") = None;
    }
}

/// Where one pick sends a request.
#[derive(Debug, Clone)]
pub enum Target {
    Local {
        replica_id: String,
        address: IpAddr,
        port: u16,
    },
    Remote {
        address: IpAddr,
        port: u16,
    },
}

/// One copy the gate may pick for an app.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub copy: Arc<CopyState>,
    pub target: Target,
    pub upstream: Upstream,
    pub local: bool,
    pub ready: bool,
    pub draining: bool,
}

/// An app placed here with a published port.
#[derive(Debug)]
pub struct AppRoute {
    pub app: String,
    /// Every name its copies' entries list.
    pub hostnames: Vec<String>,
    /// Its address on the instance's app domain, HTTPS only: answers on it
    /// carry Strict-Transport-Security (§7.5).
    pub platform_host: Option<String>,
    pub local: Vec<Candidate>,
    pub remote: Vec<Candidate>,
}

impl AppRoute {
    /// Whether `host` is one of the app's names.
    pub fn serves(&self, host: &str) -> bool {
        self.hostnames.iter().any(|h| h.eq_ignore_ascii_case(host))
    }

    fn usable(candidate: &Candidate) -> bool {
        candidate.ready && !candidate.draining && !candidate.copy.ejected()
    }

    /// Ready local copies that are not draining: what decides the entry
    /// stream's answer.
    pub fn ready_local(&self) -> usize {
        self.local.iter().filter(|c| Self::usable(c)).count()
    }

    /// Whether a ready copy runs elsewhere.
    pub fn ready_remote(&self) -> bool {
        self.remote.iter().any(Self::usable)
    }

    /// Whether a draining local copy still answers: the last resort when
    /// nothing else is ready anywhere (§8.5).
    pub fn draining_fallback(&self) -> bool {
        self.local
            .iter()
            .any(|c| c.ready && c.draining && !c.copy.ejected())
    }

    /// A copy for one request (§8.2): two random choices on in-flight
    /// requests among ready local copies, else among ready remote ones,
    /// else a draining local copy that still answers. `tried` are left out.
    pub fn pick(
        &self,
        tried: &[String],
        random: &mut impl FnMut(usize) -> usize,
    ) -> Option<Candidate> {
        let fresh = |c: &&Candidate| !tried.contains(&c.copy.replica_id);
        let local: Vec<&Candidate> = self
            .local
            .iter()
            .filter(|c| Self::usable(c))
            .filter(fresh)
            .collect();
        if !local.is_empty() {
            return Some(two_choices(&local, random).clone());
        }
        let remote: Vec<&Candidate> = self
            .remote
            .iter()
            .filter(|c| Self::usable(c))
            .filter(fresh)
            .collect();
        if !remote.is_empty() {
            return Some(two_choices(&remote, random).clone());
        }
        let draining: Vec<&Candidate> = self
            .local
            .iter()
            .filter(|c| c.ready && c.draining && !c.copy.ejected())
            .filter(fresh)
            .collect();
        (!draining.is_empty()).then(|| two_choices(&draining, random).clone())
    }
}

fn two_choices<'a>(
    candidates: &[&'a Candidate],
    random: &mut impl FnMut(usize) -> usize,
) -> &'a Candidate {
    if candidates.len() == 1 {
        return candidates[0];
    }
    let a = candidates[random(candidates.len())];
    let b = candidates[random(candidates.len())];
    if a.copy.inflight.load(Relaxed) <= b.copy.inflight.load(Relaxed) {
        a
    } else {
        b
    }
}

/// The whole table, by host.
#[derive(Debug, Default)]
pub struct Table {
    pub by_host: HashMap<String, Arc<AppRoute>>,
    pub apps: Vec<Arc<AppRoute>>,
}

impl Table {
    pub fn app_for(&self, host: &str) -> Option<Arc<AppRoute>> {
        self.by_host.get(&host.to_ascii_lowercase()).cloned()
    }
}

#[derive(Default)]
struct Building {
    hostnames: Vec<String>,
    platform_host: Option<String>,
    local: Vec<Candidate>,
    published: Option<(u16, Upstream)>,
}

fn published(ports: &[grund_proto::grund::agent::v1::Port]) -> Option<(u16, Upstream)> {
    ports.iter().filter(|p| p.public).find_map(|p| {
        let upstream = match p.protocol.as_str() {
            "http" | "" => Upstream::Http1,
            "h2c" => Upstream::H2c,
            _ => return None,
        };
        Some((u16::try_from(p.port).ok()?, upstream))
    })
}

/// Every copy the gate has seen, by replica id, kept across rebuilds.
#[derive(Debug, Default)]
pub struct Copies {
    known: Mutex<HashMap<String, Arc<CopyState>>>,
}

impl Copies {
    pub fn get(&self, replica_id: &str) -> Arc<CopyState> {
        self.known
            .lock()
            .expect("copies lock")
            .entry(replica_id.to_string())
            .or_insert_with(|| Arc::new(CopyState::new(replica_id)))
            .clone()
    }

    /// Forgets every copy not in `keep`, closing what is still open to it.
    pub fn retain(&self, keep: &HashSet<String>) {
        self.known.lock().expect("copies lock").retain(|id, copy| {
            let kept = keep.contains(id);
            if !kept {
                copy.closing.cancel();
            }
            kept
        });
    }

    /// The draining copies with nothing in flight through the gate.
    pub fn idle(&self, draining: &[String]) -> Vec<String> {
        let known = self.known.lock().expect("copies lock");
        draining
            .iter()
            .filter(|id| known.get(*id).is_none_or(|c| c.inflight.load(Relaxed) == 0))
            .cloned()
            .collect()
    }
}

/// Builds the table from the document, the apps loop's view of the local
/// replicas, and the ready copies elsewhere.
pub fn build(
    document: Option<&DesiredState>,
    local: &[ReplicaEndpoint],
    remote: &[RemoteCopy],
    copies: &Copies,
) -> Table {
    let mut keep = HashSet::new();
    let mut apps: BTreeMap<String, Building> = BTreeMap::new();
    for replica in document.map(|d| d.replicas.as_slice()).unwrap_or_default() {
        let Some((port, upstream)) = published(&replica.ports) else {
            continue;
        };
        keep.insert(replica.replica_id.clone());
        let entry = apps.entry(replica.app.clone()).or_default();
        for host in &replica.hostnames {
            let host = host.to_ascii_lowercase();
            if !entry.hostnames.contains(&host) {
                entry.hostnames.push(host);
            }
        }
        if entry.platform_host.is_none() {
            entry.platform_host = replica.hostnames.first().map(|h| h.to_ascii_lowercase());
        }
        if entry.published.is_none() {
            entry.published = Some((port, upstream));
        }
        let view = local.iter().find(|e| e.replica_id == replica.replica_id);
        let Some(address) = view.and_then(|v| v.address) else {
            continue;
        };
        let copy = copies.get(&replica.replica_id);
        let ready = view.is_some_and(|v| v.ready);
        if !ready {
            copy.clear_ejection();
        }
        entry.local.push(Candidate {
            copy,
            target: Target::Local {
                replica_id: replica.replica_id.clone(),
                address,
                port,
            },
            upstream,
            local: true,
            ready,
            draining: replica.state.as_known() == Some(ReplicaState::REPLICA_STATE_DRAINING)
                || view.is_some_and(|v| v.draining),
        });
    }
    let mut table = Table::default();
    for (
        app,
        Building {
            hostnames,
            platform_host,
            local: local_copies,
            published,
        },
    ) in apps
    {
        let (port, upstream) = published.unwrap_or((80, Upstream::Http1));
        let remote_copies: Vec<Candidate> = remote
            .iter()
            .filter(|r| r.app == app && r.ready && r.ports.contains(&port))
            .map(|r| {
                keep.insert(r.replica_id.clone());
                Candidate {
                    copy: copies.get(&r.replica_id),
                    target: Target::Remote {
                        address: r.address,
                        port,
                    },
                    upstream,
                    local: false,
                    ready: true,
                    draining: false,
                }
            })
            .collect();
        let route = Arc::new(AppRoute {
            app,
            hostnames: hostnames.clone(),
            platform_host,
            local: local_copies,
            remote: remote_copies,
        });
        for host in hostnames {
            table.by_host.insert(host, route.clone());
        }
        table.apps.push(route);
    }
    copies.retain(&keep);
    table
}
