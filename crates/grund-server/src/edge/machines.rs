//! The machines an edge hands connections to (grund-docs design/traffic.md
//! §6.4, §8.2, §8.3): one iroh connection per machine, opened on first need
//! and closed after 5 idle minutes; a machine per client connection by two
//! random choices on open streams, weighted by the ready copies its gate
//! last reported; and ejection per (machine, address) for a refused or
//! unanswered stream, 5 s doubling to 5 minutes, reset by an accepted one. A
//! lost connection ejects the machine for every address at once.

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicUsize, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayUrl, TransportAddr,
    endpoint::{Connection, RecvStream, SendStream},
};

/// The first ejection.
pub const EJECT_FIRST: Duration = Duration::from_secs(5);

/// The longest ejection.
pub const EJECT_MAX: Duration = Duration::from_secs(300);

/// An idle connection to a machine is closed after this.
pub const IDLE: Duration = Duration::from_secs(300);

/// How long the edge waits to reach a machine.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The least, and the most, the edge waits for a gate's answer (§6.3: 1 s,
/// or three times the round trip if that is larger).
pub const ANSWER_MIN: Duration = Duration::from_secs(1);
pub const ANSWER_MAX: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
struct Ejection {
    until: Instant,
    next: Duration,
}

/// One machine.
#[derive(Debug)]
pub struct Machine {
    pub endpoint_id: EndpointId,
    relays: Mutex<Vec<RelayUrl>>,
    connection: tokio::sync::Mutex<Option<(Connection, u64)>>,
    pub streams: AtomicUsize,
    ready: AtomicU32,
    ejected: Mutex<HashMap<String, Ejection>>,
    down: Mutex<Option<Ejection>>,
    last_used: Mutex<Instant>,
}

impl Machine {
    fn new(endpoint_id: EndpointId) -> Self {
        Self {
            endpoint_id,
            relays: Mutex::new(Vec::new()),
            connection: tokio::sync::Mutex::new(None),
            streams: AtomicUsize::new(0),
            ready: AtomicU32::new(1),
            ejected: Mutex::new(HashMap::new()),
            down: Mutex::new(None),
            last_used: Mutex::new(Instant::now()),
        }
    }

    fn ejected_for(&self, name: &str, now: Instant) -> Option<Instant> {
        let down = self
            .down
            .lock()
            .expect("machine lock")
            .filter(|e| e.until > now);
        let for_name = self
            .ejected
            .lock()
            .expect("machine lock")
            .get(name)
            .copied()
            .filter(|e| e.until > now);
        [down, for_name]
            .into_iter()
            .flatten()
            .map(|e| e.until)
            .max()
    }

    /// The gate refused or did not answer a stream for `name`.
    pub fn eject(&self, name: &str) {
        let now = Instant::now();
        let mut ejected = self.ejected.lock().expect("machine lock");
        let next = ejected.get(name).map_or(EJECT_FIRST, |e| e.next);
        ejected.insert(
            name.to_string(),
            Ejection {
                until: now + next,
                next: (next * 2).min(EJECT_MAX),
            },
        );
    }

    /// The machine could not be reached, or its connection was lost.
    pub fn eject_all(&self) {
        let now = Instant::now();
        let mut down = self.down.lock().expect("machine lock");
        let next = down.map_or(EJECT_FIRST, |e| e.next);
        *down = Some(Ejection {
            until: now + next,
            next: (next * 2).min(EJECT_MAX),
        });
    }

    /// The gate accepted a stream for `name`, with `ready` copies.
    pub fn accepted(&self, name: &str, ready: u16) {
        self.ejected.lock().expect("machine lock").remove(name);
        *self.down.lock().expect("machine lock") = None;
        self.ready.store(u32::from(ready.max(1)), Relaxed);
    }

    fn load(&self) -> f64 {
        self.streams.load(Relaxed) as f64 / f64::from(self.ready.load(Relaxed).max(1))
    }

    /// Whether the open connection's chosen path goes through a relay.
    pub fn relayed(connection: &Connection) -> bool {
        connection
            .paths()
            .iter()
            .find(|p| p.is_selected())
            .is_some_and(|p| matches!(p.remote_addr(), TransportAddr::Relay(_)))
    }
}

/// Every machine the edge knows, by endpoint id, and the endpoint that
/// dials them. The endpoint can be replaced ([`Pool::replace_endpoint`]);
/// connections the old one opened are then not handed out again.
#[derive(Debug, Clone)]
pub struct Pool {
    endpoint: Arc<Mutex<(Endpoint, u64)>>,
    machines: Arc<Mutex<HashMap<EndpointId, Arc<Machine>>>>,
}

fn random_below(n: usize) -> usize {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    (u64::from_le_bytes(bytes) % n.max(1) as u64) as usize
}

impl Pool {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint: Arc::new(Mutex::new((endpoint, 0))),
            machines: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The endpoint new connections are opened from.
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.lock().expect("pool lock").0.clone()
    }

    /// Opens new connections from `endpoint` from now on, and returns the
    /// one it replaces, whose open streams carry on until it is closed.
    pub fn replace_endpoint(&self, endpoint: Endpoint) -> Endpoint {
        let mut current = self.endpoint.lock().expect("pool lock");
        let generation = current.1 + 1;
        std::mem::replace(&mut *current, (endpoint, generation)).0
    }

    /// Whether every open connection goes direct, and there is one: then a
    /// relay that comes back changes nothing for the edge.
    pub fn all_direct(&self) -> bool {
        let machines: Vec<Arc<Machine>> = self
            .machines
            .lock()
            .expect("pool lock")
            .values()
            .cloned()
            .collect();
        let mut any = false;
        for machine in machines {
            let Ok(slot) = machine.connection.try_lock() else {
                return false;
            };
            if let Some((connection, _)) = slot.as_ref()
                && connection.close_reason().is_none()
            {
                if Machine::relayed(connection) {
                    return false;
                }
                any = true;
            }
        }
        any
    }

    /// The machines for `name` in the order to try them: those not ejected
    /// for it, the first by two random choices on load, then the ejected
    /// ones, soonest back first, as a last resort.
    pub fn order(&self, name: &str, machines: &[(String, Vec<String>)]) -> Vec<Arc<Machine>> {
        let now = Instant::now();
        let mut known = self.machines.lock().expect("pool lock");
        let mut ok = Vec::new();
        let mut ejected = Vec::new();
        for (endpoint_id, relays) in machines {
            let Ok(id) = EndpointId::from_str(endpoint_id) else {
                continue;
            };
            let machine = known
                .entry(id)
                .or_insert_with(|| Arc::new(Machine::new(id)))
                .clone();
            *machine.relays.lock().expect("machine lock") = relays
                .iter()
                .filter_map(|r| RelayUrl::from_str(r).ok())
                .collect();
            match machine.ejected_for(name, now) {
                Some(until) => ejected.push((until, machine)),
                None => ok.push(machine),
            }
        }
        if ok.len() >= 2 {
            let first = random_below(ok.len());
            let mut second = random_below(ok.len() - 1);
            if second >= first {
                second += 1;
            }
            let pick = if ok[first].load() <= ok[second].load() {
                first
            } else {
                second
            };
            ok.swap(0, pick);
        }
        ejected.sort_by_key(|(until, _)| *until);
        ok.into_iter()
            .chain(ejected.into_iter().map(|(_, m)| m))
            .collect()
    }

    /// The open connection to `machine`, opened now if there is none.
    pub async fn connection(&self, machine: &Machine) -> anyhow::Result<Connection> {
        let mut slot = machine.connection.lock().await;
        *machine.last_used.lock().expect("machine lock") = Instant::now();
        let (endpoint, generation) = self.endpoint.lock().expect("pool lock").clone();
        if let Some((connection, opened_by)) = slot.as_ref()
            && *opened_by == generation
            && connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }
        let mut addr = EndpointAddr::new(machine.endpoint_id);
        for relay in machine.relays.lock().expect("machine lock").iter() {
            addr = addr.with_relay_url(relay.clone());
        }
        let connection = tokio::time::timeout(
            CONNECT_TIMEOUT,
            endpoint.connect(addr, grund_entry::ENTRY_ALPN),
        )
        .await
        .map_err(|_| anyhow::anyhow!("no connection within {} s", CONNECT_TIMEOUT.as_secs()))?
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
        *slot = Some((connection.clone(), generation));
        Ok(connection)
    }

    /// Opens an entry stream on `connection`.
    pub async fn open(connection: &Connection) -> anyhow::Result<(SendStream, RecvStream)> {
        Ok(tokio::time::timeout(ANSWER_MAX, connection.open_bi())
            .await
            .map_err(|_| anyhow::anyhow!("no stream in time"))??)
    }

    /// How long to wait for a gate's answer on `connection`.
    pub fn answer_timeout(connection: &Connection) -> Duration {
        let rtt = connection
            .paths()
            .iter()
            .find(|p| p.is_selected())
            .map(|p| p.rtt());
        rtt.map_or(ANSWER_MIN, |rtt| (rtt * 3).clamp(ANSWER_MIN, ANSWER_MAX))
    }

    /// Closes connections idle longer than [`IDLE`] with no stream open.
    pub async fn sweep(&self) {
        let machines: Vec<Arc<Machine>> = self
            .machines
            .lock()
            .expect("pool lock")
            .values()
            .cloned()
            .collect();
        for machine in machines {
            let idle = machine.last_used.lock().expect("machine lock").elapsed() >= IDLE;
            if idle && machine.streams.load(Relaxed) == 0 {
                let mut slot = machine.connection.lock().await;
                if let Some((connection, _)) = slot.take() {
                    connection.close(0u32.into(), b"idle");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> Machine {
        Machine::new(iroh::SecretKey::from_bytes(&[3; 32]).public())
    }

    #[test]
    fn an_ejection_doubles_to_five_minutes_and_an_accepted_stream_ends_it() {
        let m = machine();
        let now = Instant::now();
        m.eject("photos.grund.run");
        let first = m.ejected_for("photos.grund.run", now).unwrap();
        assert!(first > now + Duration::from_secs(4) && first <= now + Duration::from_secs(6));
        assert!(
            m.ejected_for("blog.grund.run", now).is_none(),
            "per address"
        );
        for _ in 0..10 {
            m.eject("photos.grund.run");
        }
        let long = m.ejected_for("photos.grund.run", Instant::now()).unwrap();
        assert!(long <= Instant::now() + EJECT_MAX + Duration::from_secs(1));
        m.accepted("photos.grund.run", 2);
        assert!(m.ejected_for("photos.grund.run", Instant::now()).is_none());
        m.eject_all();
        assert!(
            m.ejected_for("blog.grund.run", Instant::now()).is_some(),
            "every address"
        );
    }
}
