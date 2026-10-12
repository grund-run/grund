//! The machines an edge hands connections to (grund-docs design/traffic.md
//! §6.4, §8.2, §8.3): one iroh connection per machine, opened on first need
//! and closed after 5 idle minutes; a machine per client connection by two
//! random choices on open streams, weighted by the ready copies its gate
//! last reported; and ejection per (machine, address) for a refused or
//! unanswered stream, 5 s doubling to 5 minutes, reset by an accepted one. A
//! lost connection ejects the machine for every address at once.

use std::{
    collections::HashMap,
    ops::Deref,
    str::FromStr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU32, AtomicUsize, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

use super::RelayDialOverride;
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

/// After a machine closes its connection (an agent restarting), the edge
/// dials it again this often, each attempt given [`REDIAL_TIMEOUT`], until
/// it answers or [`REDIAL_FOR`] has passed.
pub const REDIAL_EVERY: Duration = Duration::from_millis(250);
pub const REDIAL_TIMEOUT: Duration = Duration::from_secs(1);
pub const REDIAL_FOR: Duration = Duration::from_secs(300);

/// The least, and the most, the edge waits for a gate's answer (§6.3: 1 s,
/// or three times the round trip if that is larger).
pub const ANSWER_MIN: Duration = Duration::from_secs(1);
pub const ANSWER_MAX: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
struct Ejection {
    until: Instant,
    next: Duration,
}

/// A retired connection closes only after every hand-over using it has
/// finished, including accepted streams that are already carrying client data.
#[derive(Debug)]
pub struct Session {
    connection: Connection,
}

impl Deref for Session {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.connection
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"retired");
    }
}

/// One machine.
#[derive(Debug)]
pub struct Machine {
    pub endpoint_id: EndpointId,
    relays: Mutex<Vec<RelayUrl>>,
    connection: tokio::sync::Mutex<Option<(Arc<Session>, u64)>>,
    live: Mutex<Vec<Weak<Session>>>,
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
            live: Mutex::new(Vec::new()),
            streams: AtomicUsize::new(0),
            ready: AtomicU32::new(1),
            ejected: Mutex::new(HashMap::new()),
            down: Mutex::new(None),
            last_used: Mutex::new(Instant::now()),
        }
    }

    fn remember(&self, session: &Arc<Session>) {
        let mut live = self.live.lock().expect("machine lock");
        live.retain(|session| session.strong_count() != 0);
        live.push(Arc::downgrade(session));
    }

    fn live_sessions(&self) -> Vec<Arc<Session>> {
        let mut sessions = Vec::new();
        self.live.lock().expect("machine lock").retain(|weak| {
            if let Some(session) = weak.upgrade() {
                sessions.push(session);
                true
            } else {
                false
            }
        });
        sessions
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

    fn back(&self) {
        *self.down.lock().expect("machine lock") = None;
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
    relay_override: Option<RelayDialOverride>,
}

fn random_below(n: usize) -> usize {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    (u64::from_le_bytes(bytes) % n.max(1) as u64) as usize
}

impl Pool {
    pub(super) fn new(endpoint: Endpoint, relay_override: Option<RelayDialOverride>) -> Self {
        Self {
            endpoint: Arc::new(Mutex::new((endpoint, 0))),
            machines: Arc::new(Mutex::new(HashMap::new())),
            relay_override,
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

    /// The machines for `name` in the order to try them: ready healthy
    /// machines, running healthy fallbacks, then ejected ones. A planned
    /// migration never receives new connections.
    pub fn order(
        &self,
        name: &str,
        machines: &[(String, Vec<String>, u32, bool)],
    ) -> Vec<Arc<Machine>> {
        let now = Instant::now();
        let mut known = self.machines.lock().expect("pool lock");
        let mut ready = Vec::new();
        let mut running = Vec::new();
        let mut ejected = Vec::new();
        for (endpoint_id, relays, ready_copies, migration_paused) in machines {
            if *migration_paused {
                continue;
            }
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
                .map(|url| match &self.relay_override {
                    Some(dial) => dial.dial(url),
                    None => url,
                })
                .collect();
            machine.ready.store((*ready_copies).max(1), Relaxed);
            match machine.ejected_for(name, now) {
                Some(until) => ejected.push((until, machine)),
                None if *ready_copies > 0 => ready.push(machine),
                None => running.push(machine),
            }
        }
        for candidates in [&mut ready, &mut running] {
            if candidates.len() >= 2 {
                let first = random_below(candidates.len());
                let mut second = random_below(candidates.len() - 1);
                if second >= first {
                    second += 1;
                }
                let pick = if candidates[first].load() <= candidates[second].load() {
                    first
                } else {
                    second
                };
                candidates.swap(0, pick);
            }
        }
        ejected.sort_by_key(|(until, _)| *until);
        ready
            .into_iter()
            .chain(running)
            .chain(ejected.into_iter().map(|(_, machine)| machine))
            .collect()
    }

    /// The open connection to `machine`, opened now if there is none.
    pub async fn connection(&self, machine: &Arc<Machine>) -> anyhow::Result<Arc<Session>> {
        let mut slot = machine.connection.lock().await;
        *machine.last_used.lock().expect("machine lock") = Instant::now();
        let (endpoint, generation) = self.endpoint.lock().expect("pool lock").clone();
        if let Some((connection, opened_by)) = slot.as_ref()
            && *opened_by == generation
            && connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }
        let connection = tokio::time::timeout(
            CONNECT_TIMEOUT,
            endpoint.connect(Self::addr(machine), grund_entry::ENTRY_ALPN),
        )
        .await
        .map_err(|_| anyhow::anyhow!("no connection within {} s", CONNECT_TIMEOUT.as_secs()))?
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
        let session = Arc::new(Session { connection });
        machine.remember(&session);
        self.watch(machine.clone(), session.connection.clone());
        *slot = Some((session.clone(), generation));
        Ok(session)
    }

    /// Stops reusing an unanswered connection without closing its accepted streams.
    /// A concurrent replacement is left alone.
    pub fn discard(&self, machine: &Arc<Machine>, connection: &Arc<Session>) {
        if let Ok(mut slot) = machine.connection.try_lock() {
            if slot
                .as_ref()
                .is_some_and(|(cached, _)| Arc::ptr_eq(cached, connection))
            {
                slot.take();
            }
        } else {
            let machine = machine.clone();
            let connection = connection.clone();
            tokio::spawn(async move {
                let mut slot = machine.connection.lock().await;
                if slot
                    .as_ref()
                    .is_some_and(|(cached, _)| Arc::ptr_eq(cached, &connection))
                {
                    slot.take();
                }
            });
        }
    }

    /// A whole-attempt deadline may interrupt the handshake before it can
    /// report which pooled connection failed. Drop only the reusable slot.
    pub fn discard_current(&self, machine: &Machine) {
        if let Ok(mut slot) = machine.connection.try_lock() {
            slot.take();
        }
    }

    fn addr(machine: &Machine) -> EndpointAddr {
        let mut addr = EndpointAddr::new(machine.endpoint_id);
        for relay in machine.relays.lock().expect("machine lock").iter() {
            addr = addr.with_relay_url(relay.clone());
        }
        addr
    }

    fn watch(&self, machine: Arc<Machine>, connection: Connection) {
        let pool = self.clone();
        tokio::spawn(async move {
            let reason = connection.closed().await;
            match &reason {
                iroh::endpoint::ConnectionError::LocallyClosed => return,
                iroh::endpoint::ConnectionError::ApplicationClosed(close)
                    if close.error_code == grund_entry::NOT_AN_ENTRY_KEY.into() =>
                {
                    machine.eject_all();
                    return;
                }
                _ => {}
            }
            {
                let slot = machine.connection.lock().await;
                if slot
                    .as_ref()
                    .is_none_or(|(c, _)| c.stable_id() != connection.stable_id())
                {
                    return;
                }
            }
            machine.eject_all();
            tracing::info!(machine = %machine.endpoint_id, %reason, "edge: a machine closed its connection; dialing it again");
            pool.redial(machine).await;
        });
    }

    async fn redial(&self, machine: Arc<Machine>) {
        let lost = Instant::now();
        while lost.elapsed() < REDIAL_FOR {
            tokio::time::sleep(REDIAL_EVERY).await;
            let mut slot = machine.connection.lock().await;
            let (endpoint, generation) = self.endpoint.lock().expect("pool lock").clone();
            if let Some((connection, opened_by)) = slot.as_ref()
                && *opened_by == generation
                && connection.close_reason().is_none()
            {
                return;
            }
            let dialed = tokio::time::timeout(
                REDIAL_TIMEOUT,
                endpoint.connect(Self::addr(&machine), grund_entry::ENTRY_ALPN),
            )
            .await;
            if let Ok(Ok(connection)) = dialed {
                let session = Arc::new(Session { connection });
                machine.remember(&session);
                self.watch(machine.clone(), session.connection.clone());
                *slot = Some((session, generation));
                machine.back();
                tracing::info!(machine = %machine.endpoint_id, after_ms = lost.elapsed().as_millis() as u64, "edge: a machine answers again");
                return;
            }
        }
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

    async fn drain_one(machine: &Machine, retire: bool) -> bool {
        let mut slot = machine.connection.lock().await;
        let sessions = machine.live_sessions();
        if retire {
            slot.take();
        }
        drop(slot);
        let live = sessions.len();
        let notified =
            futures_util::future::join_all(sessions.into_iter().map(|session| async move {
                let notice = async {
                    let mut send = session.open_uni().await?;
                    send.write_all(grund_entry::DRAIN).await?;
                    send.finish()?;
                    anyhow::Ok(())
                };
                matches!(
                    tokio::time::timeout(Duration::from_secs(1), notice).await,
                    Ok(Ok(()))
                )
            }))
            .await
            .into_iter()
            .filter(|sent| *sent)
            .count();
        if live != 0 {
            tracing::info!(machine = %machine.endpoint_id, live, notified, "edge: gate drain notices delivered");
        }
        notified != 0
    }

    /// Drain idle HTTP connections on a migrating gate, then retire the
    /// reusable iroh session. Accepted streams retain their own Arc lease;
    /// the first request after unpause must dial the restored endpoint.
    pub async fn drain_machine(&self, endpoint_id: EndpointId) -> bool {
        let machine = self
            .machines
            .lock()
            .expect("pool lock")
            .get(&endpoint_id)
            .cloned();
        match machine {
            Some(machine) => Self::drain_one(&machine, true).await,
            None => false,
        }
    }

    /// Tells every machine the edge holds a connection to that it is
    /// stopping ([`grund_entry::DRAIN`]), so its gate closes each client
    /// connection after the current request. Returns how many were told.
    pub async fn drain(&self) -> usize {
        let machines: Vec<Arc<Machine>> = self
            .machines
            .lock()
            .expect("pool lock")
            .values()
            .cloned()
            .collect();
        let mut told = 0;
        for machine in machines {
            told += usize::from(Self::drain_one(&machine, false).await);
        }
        told
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
                slot.take();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_edge_dials_the_direct_relay_without_advertising_it_to_machines()
    -> anyhow::Result<()> {
        use grund_proto::grund::edge::v1::{Route as WireRoute, RouteMachine, RouteTable};

        let public = "https://relay.example.com";
        let direct = "https://relay.example.com:8446";
        let override_url = RelayDialOverride::parse(direct)?;
        let endpoint_id = iroh::SecretKey::from_bytes(&[3; 32]).public().to_string();
        let table = |version: &str, home: &str| RouteTable {
            version: version.to_string(),
            relay_urls: vec![public.to_string()],
            routes: vec![WireRoute {
                name: "photos.example.com".to_string(),
                machines: vec![RouteMachine {
                    endpoint_id: endpoint_id.clone(),
                    relay_url: home.to_string(),
                    ready_copies: 1,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let dir = std::env::temp_dir().join(format!("grund-edge-relays-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir)?;
        let routes = super::super::routes::Routes::load(&dir);
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[2; 32]))
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await?;
        let pool = Pool::new(endpoint, Some(override_url.clone()));
        for (version, home) in [("first", public), ("second", "")] {
            routes.install(&table(version, home))?;
            override_url.validate_table(&routes.current())?;
            let route = routes.current().get("photos.example.com").unwrap();
            assert_eq!(routes.current().relay_urls, vec![public]);
            assert_eq!(route.machines[0].1, vec![public]);
            let endpoint_relays = super::super::relay_urls(&routes, Some(&override_url));
            assert_eq!(endpoint_relays[0].as_str(), format!("{direct}/"));
            assert_eq!(
                grund_net::endpoint::relay_ping_url(&endpoint_relays[0]),
                format!("{direct}/ping")
            );
            let selected = pool.order("photos.example.com", &route.machines);
            let address = Pool::addr(&selected[0]);
            assert_eq!(
                address.relay_urls().next().unwrap().as_str(),
                format!("{direct}/")
            );
        }
        assert!(
            RelayDialOverride::parse("https://other.example.com:8446")?
                .validate_table(&routes.current())
                .is_err()
        );
        for invalid in [
            "http://relay.example.com:8446",
            "https://relay.example.com:8446/other",
            "https://user@relay.example.com:8446",
        ] {
            assert!(RelayDialOverride::parse(invalid).is_err());
        }
        pool.endpoint().close().await;
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

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
    #[tokio::test]
    async fn a_ready_machine_precedes_an_unready_one_and_a_stall_is_skipped() {
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[2; 32]))
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let pool = Pool::new(endpoint, None);
        let ready = iroh::SecretKey::from_bytes(&[3; 32]).public().to_string();
        let fallback = iroh::SecretKey::from_bytes(&[4; 32]).public().to_string();
        let route = vec![
            (fallback.clone(), vec![], 0, false),
            (ready.clone(), vec![], 1, false),
        ];
        let selected = pool.order("photos.grund.run", &route);
        assert_eq!(selected[0].endpoint_id.to_string(), ready);
        selected[0].eject("photos.grund.run");
        let selected = pool.order("photos.grund.run", &route);
        assert_eq!(selected[0].endpoint_id.to_string(), fallback);
        let selected = pool.order("blog.grund.run", &route);
        assert_eq!(selected[0].endpoint_id.to_string(), ready);
        let route = vec![
            (fallback.clone(), vec![], 1, true),
            (ready.clone(), vec![], 1, false),
        ];
        let selected = pool.order("photos.grund.run", &route);
        assert_eq!(selected.len(), 1, "a migration pause excludes its machine");
        assert_eq!(selected[0].endpoint_id.to_string(), ready);
    }
    #[tokio::test]
    async fn migration_tells_retired_and_current_sessions_to_drain() -> anyhow::Result<()> {
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug)]
        struct Notices(tokio::sync::mpsc::UnboundedSender<()>);

        impl ProtocolHandler for Notices {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                while let Ok(mut stream) = connection.accept_uni().await {
                    if stream
                        .read_to_end(grund_entry::DRAIN.len())
                        .await
                        .as_deref()
                        == Ok(grund_entry::DRAIN)
                    {
                        let _ = self.0.send(());
                    }
                }
                Ok(())
            }
        }

        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[4; 32]))
            .relay_mode(iroh::RelayMode::Disabled)
            .bind_addr(("127.0.0.1", 0))?
            .bind()
            .await?;
        let (sent, mut notices) = tokio::sync::mpsc::unbounded_channel();
        let router = Router::builder(server.clone())
            .accept(grund_entry::ENTRY_ALPN, Notices(sent))
            .spawn();
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[5; 32]))
            .relay_mode(iroh::RelayMode::Disabled)
            .bind_addr(("127.0.0.1", 0))?
            .bind()
            .await?;
        let address = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
        let pool = Pool::new(client, None);
        let machine = Arc::new(Machine::new(server.id()));
        pool.machines
            .lock()
            .expect("pool lock")
            .insert(server.id(), machine.clone());

        let old = Arc::new(Session {
            connection: pool
                .endpoint()
                .connect(address.clone(), grund_entry::ENTRY_ALPN)
                .await?,
        });
        machine.remember(&old);
        *machine.connection.lock().await = Some((old.clone(), 0));
        pool.discard(&machine, &old);
        let current = Arc::new(Session {
            connection: pool
                .endpoint()
                .connect(address, grund_entry::ENTRY_ALPN)
                .await?,
        });
        machine.remember(&current);
        *machine.connection.lock().await = Some((current.clone(), 0));

        assert!(pool.drain_machine(server.id()).await);
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(2), notices.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("the gate missed a live session's drain"))?;
        }
        assert!(
            old.close_reason().is_none(),
            "accepted streams still own the old session"
        );
        drop((old, current));
        router.shutdown().await?;
        pool.endpoint().close().await;
        Ok(())
    }
}
