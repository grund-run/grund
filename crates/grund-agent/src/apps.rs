//! The agent's apps loop (grund-docs design/apps.md §7.2, §8.1, §9.1): every
//! second, and at once on a new document, make this machine's containers
//! match the replicas its document lists, through a [`ContainerRuntime`].
//!
//! Each pass observes what runs, plans from that, and acts; every step is
//! idempotent and a failed step ends nothing but itself, so the next pass
//! plans again from what is really there. The agent is not the parent of
//! any container: it can restart or update while apps keep running, and
//! adopts what it finds.
//!
//! - **Missing**: pull its image by digest (in the background, so one slow
//!   pull holds up nothing else), fetch its secrets, create, start.
//! - **A different spec** under the same id: remove, then create again.
//! - **Exited**: restart at once, then after 10 s, 20 s, 40 s, … capped at
//!   5 minutes, and forget the back-off after 10 minutes of running
//!   ([`backoff`], the kubelet's schedule except for the first restart).
//! - **Not in the document**: stopped with the stop settings its container
//!   carries, each stop on its own, never holding up a start (§7.3).
//! - **Refused** by the machine's policy: not run, and reported with why.
//!
//! Readiness is checked from the machine: ready after one pass of its
//! check, not ready after three failures in a row, and at once on an exit. A
//! replica with no check is ready while its process runs; the instance
//! applies `min_ready` itself.
//!
//! **Its network** (network.md §6.1, §6.2): on a machine on a private
//! network, each replica gets its own device inside its container's network
//! namespace before the container starts ([`ContainerRuntime::network_namespace`],
//! grund-net `Tun::create_in`), with its address
//! (`grund_net::membership::replica_address`), and the mesh carries its
//! packets, through its filter and to the internet through its egress. Its
//! `/etc/resolv.conf` names the machine's stub resolver. Its check then runs
//! against that address from the machine, the path its peers take, so ready
//! means reachable. A replica that answers only on IPv4 inside its namespace
//! gets its ports forwarded from its address ([`crate::forward`]) and is
//! then checked again. Where the network is not up, a replica runs
//! with loopback only and is checked inside its namespace. What it reaches
//! and what reaches it is published for the gate ([`Shared::endpoints`]).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use std::net::{IpAddr, Ipv6Addr};

use grund_net::{
    membership::{MembershipList, replica_address},
    mesh::Mesh,
    tun::Tun,
};
use grund_proto::grund::agent::v1::{
    DesiredState, GetReplicaSecretsRequest, GetReplicaSecretsResponse, Replica, ReplicaObserved,
    ReplicaObservedState, ReplicaState, replica_check,
};
use sha2::{Digest, Sha256};
use tokio::{sync::Notify, task::JoinHandle};

use crate::{
    agent::Link,
    policy::Policy,
    runtime::{ContainerRuntime, ContainerSpec, ContainerStatus, ImageRef, Probe, TaskState},
    secrets,
};

/// How often a pass runs when nothing wakes it.
pub const PASS_EVERY: Duration = Duration::from_secs(1);

/// Failures in a row of a replica's check before it is not ready.
pub const FAILURES_BEFORE_UNREADY: u32 = 3;

/// Running this long without an exit forgets a replica's back-off.
pub const BACKOFF_RESET: Duration = Duration::from_secs(600);

/// The longest a restart waits.
pub const BACKOFF_CAP: Duration = Duration::from_secs(300);

/// How long a failed pull or create waits before it is tried again.
pub const RETRY_FAILED: Duration = Duration::from_secs(10);

/// The wait before the restart that follows the `exits`-th exit since the
/// last reset: at once for the first, then 10 s, doubling, at most 5 min.
pub fn backoff(exits: u32) -> Duration {
    if exits <= 1 {
        return Duration::ZERO;
    }
    let seconds = 10u64.saturating_mul(1u64 << (exits - 2).min(16));
    Duration::from_secs(seconds).min(BACKOFF_CAP)
}

/// The name of a replica's device inside its namespace.
pub const REPLICA_TUN: &str = "grund0";

/// One of this machine's replicas, as the gate reaches it (grund-docs
/// design/traffic.md): an ordinary TCP connect from the machine to
/// `[address]:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaEndpoint {
    pub replica_id: String,
    pub app: String,
    /// Its address on the private network.
    pub address: Ipv6Addr,
    /// The ports its release declares.
    pub ports: Vec<EndpointPort>,
    /// The agent's check passes (apps.md §8.1).
    pub ready: bool,
    /// Its document marks it draining: no new requests.
    pub draining: bool,
}

/// One declared port of a [`ReplicaEndpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPort {
    pub name: String,
    pub port: u16,
    /// `http`, `h2c` or `tcp`.
    pub protocol: String,
}

/// The replicas that have an address, as of the apps loop's last pass.
#[derive(Debug)]
pub struct Endpoints(tokio::sync::watch::Sender<Vec<ReplicaEndpoint>>);

impl Default for Endpoints {
    fn default() -> Self {
        Self(tokio::sync::watch::Sender::new(Vec::new()))
    }
}

/// What the apps loop needs of the private network to give its replicas
/// addresses: the list in force, the mesh once it runs, and this machine's
/// key.
#[derive(Clone)]
pub struct NetworkAccess {
    pub lists: tokio::sync::watch::Receiver<Option<MembershipList>>,
    pub mesh: Arc<std::sync::OnceLock<Mesh>>,
    /// This machine's endpoint id, to find its own entry in the list.
    pub own: String,
}

#[derive(Clone)]
struct Net {
    mesh: Mesh,
    prefix: Ipv6Addr,
    slot: u16,
    resolver: Ipv6Addr,
}

/// What the apps loop and the agent's main loop share.
#[derive(Default)]
pub struct Shared {
    /// The replicas with an address, for the gate.
    pub endpoints: Endpoints,
    /// The document applied last.
    pub desired: Mutex<Option<DesiredState>>,
    /// The replicas as last observed, for the next status report.
    pub reports: Mutex<Vec<ReplicaObserved>>,
    /// Why the machine refused a replica, for the next status report.
    pub refusals: Mutex<Vec<String>>,
    /// The main loop applied a new document.
    pub document: Notify,
    /// Something a report carries changed: report now.
    pub changed: Notify,
    /// Why the agent refused a document, for the next status report.
    pub document_refusals: Mutex<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
struct Readiness {
    ready: bool,
    since: Option<Instant>,
    failures: u32,
    last_probe: Option<Instant>,
    reason: String,
}

#[derive(Debug, Default)]
struct Tracked {
    restarts: u32,
    exits_since_reset: u32,
    started: Option<Instant>,
    restart_at: Option<Instant>,
    last_exit_code: i32,
    failed: Option<(String, Instant)>,
    readiness: Readiness,
}

impl Shared {
    /// The replicas with an address, as of the last pass, and every change.
    pub fn endpoints(&self) -> tokio::sync::watch::Receiver<Vec<ReplicaEndpoint>> {
        self.endpoints.0.subscribe()
    }
}

fn container_hash(replica: &Replica, net: Option<&Net>) -> String {
    let base = spec_hash(replica);
    match net {
        None => base,
        Some(net) => {
            let mut h = Sha256::new();
            h.update(base.as_bytes());
            h.update(b"\nnetwork-v1 ");
            h.update(net.resolver.to_string().as_bytes());
            hex::encode(h.finalize())
        }
    }
}

/// The hash of everything that makes a container this container, secret
/// values left out (their names and versions are in).
pub fn spec_hash(replica: &Replica) -> String {
    let mut hasher = Sha256::new();
    let mut part = |label: &str, value: &[u8]| {
        hasher.update(label.as_bytes());
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    };
    let image = replica.image.as_option();
    part(
        "digest",
        image.map(|i| i.digest.as_bytes()).unwrap_or_default(),
    );
    for arg in &replica.command {
        part("arg", arg.as_bytes());
    }
    for env in &replica.env {
        part("env", env.name.as_bytes());
        part("value", env.value.as_bytes());
    }
    for secret in &replica.secrets {
        part("secret", secret.name.as_bytes());
        part("version", &secret.version.to_le_bytes());
    }
    for env in &replica.secret_env {
        part("secret-env", env.env.as_bytes());
        part("secret-of", env.secret.as_bytes());
    }
    part("memory", &replica.memory_mib.to_le_bytes());
    part("cpu", &replica.cpu_millis.to_le_bytes());
    let stop = replica.stop.as_option();
    part(
        "signal",
        stop.map(|s| s.signal.as_bytes()).unwrap_or_default(),
    );
    part("grace", &stop.map_or(30, |s| s.grace_seconds).to_le_bytes());
    hex::encode(hasher.finalize())
}

/// The probe a replica's check makes, if it has one.
pub fn probe_of(replica: &Replica) -> Option<(Probe, Duration, Duration)> {
    let check = replica.check.as_option()?;
    let port = u16::try_from(check.port).ok().filter(|p| *p > 0)?;
    let probe = match &check.kind {
        Some(replica_check::Kind::HttpPath(path)) => Probe::Http {
            port,
            path: path.clone(),
        },
        Some(replica_check::Kind::Tcp(_)) => Probe::Tcp { port },
        None => return None,
    };
    let interval = Duration::from_millis(u64::from(check.interval_ms.max(500)));
    let timeout = Duration::from_millis(u64::from(check.timeout_ms.clamp(100, 30_000)));
    Some((probe, interval, timeout))
}

fn spec(
    replica: &Replica,
    secret_values: &[secrets::Cached],
    net: Option<&Net>,
) -> Result<ContainerSpec, String> {
    let image = replica.image.as_option().ok_or("no image")?;
    let reference = grund_domain::app::spec::ImageReference::parse(&image.reference)
        .map_err(|e| e.to_string())?;
    let mut env: Vec<(String, String)> = replica
        .env
        .iter()
        .map(|e| (e.name.clone(), e.value.clone()))
        .collect();
    for secret_env in &replica.secret_env {
        let value = secret_values
            .iter()
            .find(|v| v.name == secret_env.secret)
            .ok_or_else(|| format!("the value of secret {} is not here", secret_env.secret))?;
        env.push((
            secret_env.env.clone(),
            String::from_utf8_lossy(&value.value).into_owned(),
        ));
    }
    let stop = replica.stop.as_option();
    let mut labels = BTreeMap::new();
    labels.insert("grund.app".to_string(), replica.app.clone());
    labels.insert("grund.app-id".to_string(), replica.app_id.clone());
    labels.insert("grund.release".to_string(), replica.release.to_string());
    labels.insert("grund.slot".to_string(), replica.slot.to_string());
    Ok(ContainerSpec {
        id: replica.replica_id.clone(),
        image: ImageRef {
            reference: reference.pinned(&image.digest),
            digest: image.digest.clone(),
        },
        command: replica.command.clone(),
        env,
        memory_mib: replica.memory_mib,
        cpu_millis: replica.cpu_millis,
        stop_signal: stop
            .map(|s| s.signal.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "SIGTERM".into()),
        stop_grace: Duration::from_secs(u64::from(
            stop.map(|s| s.grace_seconds)
                .filter(|g| *g > 0)
                .unwrap_or(30),
        )),
        labels,
        spec_hash: container_hash(replica, net),
        resolv_conf: net.map(|n| format!("nameserver {}\n", n.resolver)),
    })
}

/// The apps loop's state between passes.
pub struct Apps<C> {
    runtime: Arc<C>,
    link: Option<Link>,
    shared: Arc<Shared>,
    policy: Policy,
    data_dir: PathBuf,
    cache_key: ring::aead::LessSafeKey,
    tracked: HashMap<String, Tracked>,
    pulls: HashMap<String, JoinHandle<Result<(), String>>>,
    pull_failed: HashMap<String, (String, Instant)>,
    stops: HashMap<String, JoinHandle<()>>,
    secrets: secrets::Values,
    last_reports: Vec<ReplicaObserved>,
    network: Option<NetworkAccess>,
    attached: HashMap<String, Ipv6Addr>,
    netns_of: HashMap<String, PathBuf>,
    forwards: HashMap<String, Vec<crate::forward::Forward>>,
}

impl<C: ContainerRuntime + 'static> Apps<C> {
    pub(crate) fn new(
        runtime: Arc<C>,
        link: Option<Link>,
        shared: Arc<Shared>,
        policy: Policy,
        data_dir: PathBuf,
        machine_seed: &[u8; 32],
    ) -> Self {
        let cache_key = secrets::key(machine_seed);
        let secrets = secrets::load(&data_dir, &cache_key);
        Self {
            runtime,
            link,
            shared,
            policy,
            data_dir,
            cache_key,
            tracked: HashMap::new(),
            pulls: HashMap::new(),
            pull_failed: HashMap::new(),
            stops: HashMap::new(),
            secrets,
            last_reports: Vec::new(),
            network: None,
            attached: HashMap::new(),
            netns_of: HashMap::new(),
            forwards: HashMap::new(),
        }
    }

    /// Gives replicas addresses on the private network once it is up.
    pub fn with_network(mut self, access: NetworkAccess) -> Self {
        self.network = Some(access);
        self
    }

    fn net(&self) -> Option<Net> {
        let access = self.network.as_ref()?;
        let mesh = access.mesh.get()?.clone();
        mesh.ifindex()?;
        let list = access.lists.borrow();
        let list = list.as_ref()?;
        let own = list.members.iter().find(|m| m.endpoint_id == access.own)?;
        Some(Net {
            mesh,
            prefix: list.prefix,
            slot: own.slot,
            resolver: grund_net::dns::resolver_address(list, own.slot),
        })
    }

    async fn attach(&mut self, id: &str, net: &Net) -> Result<Option<Ipv6Addr>, String> {
        if let Some(address) = self.attached.get(id) {
            return Ok(Some(*address));
        }
        let Some(netns) = self
            .runtime
            .network_namespace(id)
            .await
            .map_err(|e| format!("could not make its network namespace: {e:#}"))?
        else {
            return Ok(None);
        };
        let address = replica_address(net.prefix, net.slot, id);
        self.netns_of.insert(id.to_string(), netns.clone());
        let tun =
            tokio::task::spawn_blocking(move || Tun::create_in(&netns, REPLICA_TUN, address, 48))
                .await
                .map_err(|e| format!("could not give it a network: {e}"))?
                .map_err(|e| format!("could not give it a network: {e:#}"))?;
        net.mesh.attach_replica(address, tun, |tun| {
            Box::new(grund_net::egress::Userspace::start(tun))
        });
        tracing::info!(replica = %id, %address, "gave a replica its address");
        self.attached.insert(id.to_string(), address);
        Ok(Some(address))
    }

    async fn forward_ipv4(&mut self, replica: &Replica) {
        let id = replica.replica_id.clone();
        let (Some(&address), Some(netns)) =
            (self.attached.get(&id), self.netns_of.get(&id).cloned())
        else {
            return;
        };
        let mut ports: Vec<u16> = replica
            .ports
            .iter()
            .filter_map(|p| u16::try_from(p.port).ok())
            .collect();
        if let Some((Probe::Http { port, .. } | Probe::Tcp { port }, _, _)) = probe_of(replica) {
            ports.push(port);
        }
        ports.sort();
        ports.dedup();
        let have: Vec<u16> = self
            .forwards
            .get(&id)
            .map(|f| f.iter().map(|f| f.port).collect())
            .unwrap_or_default();
        for port in ports.into_iter().filter(|p| !have.contains(p)) {
            let answers = crate::probe::connect(netns.clone(), port, Duration::from_secs(1))
                .await
                .is_ok();
            if !answers {
                continue;
            }
            match crate::forward::start(netns.clone(), address, port).await {
                Ok(forward) => {
                    tracing::info!(replica = %id, %address, port, "the replica listens on IPv4 only; forwarding its address to 127.0.0.1 inside its namespace");
                    self.forwards.entry(id.clone()).or_default().push(forward);
                }
                Err(crate::forward::NotForwarded::Taken) => {}
                Err(crate::forward::NotForwarded::Failed(error)) => {
                    tracing::warn!(replica = %id, port, %error, "could not forward an IPv4-only replica's port");
                }
            }
        }
    }

    fn detach(&mut self, id: &str) {
        self.forwards.remove(id);
        self.netns_of.remove(id);
        if let Some(address) = self.attached.remove(id)
            && let Some(net) = self.net()
        {
            net.mesh.detach_replica(address);
        }
    }

    /// Runs passes forever: every [`PASS_EVERY`], and at once on a new
    /// document.
    pub async fn run(mut self) {
        loop {
            if let Err(error) = self.pass().await {
                tracing::warn!(error = %format!("{error:#}"), "apps pass failed; trying again");
            }
            tokio::select! {
                _ = tokio::time::sleep(PASS_EVERY) => {}
                _ = self.shared.document.notified() => {}
            }
        }
    }

    async fn secret_values(&mut self, replica: &Replica) -> Result<Vec<secrets::Cached>, String> {
        if replica.secrets.is_empty() {
            return Ok(Vec::new());
        }
        let wanted: Vec<(String, u32)> = replica
            .secrets
            .iter()
            .map(|s| (s.name.clone(), s.version))
            .collect();
        if let Some(cached) = self.secrets.get(&replica.replica_id)
            && wanted
                .iter()
                .all(|(n, v)| cached.iter().any(|c| c.name == *n && c.version == *v))
        {
            return Ok(cached.clone());
        }
        let link = self
            .link
            .as_ref()
            .ok_or("its secrets are not cached and the instance is not reachable")?;
        let answer: GetReplicaSecretsResponse = link
            .call(
                "GetReplicaSecrets",
                &GetReplicaSecretsRequest {
                    replica_id: replica.replica_id.clone(),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| format!("could not fetch its secrets: {e:#}"))?;
        let values: Vec<secrets::Cached> = answer
            .secrets
            .into_iter()
            .map(|s| secrets::Cached {
                name: s.name,
                version: s.version,
                value: s.value,
            })
            .collect();
        self.secrets
            .insert(replica.replica_id.clone(), values.clone());
        if let Err(error) = secrets::store(&self.data_dir, &self.cache_key, &self.secrets) {
            tracing::warn!(error = %format!("{error:#}"), "could not keep the secrets cache");
        }
        Ok(values)
    }

    fn stop(&mut self, status: &ContainerStatus) {
        if self.stops.get(&status.id).is_some_and(|h| !h.is_finished()) {
            return;
        }
        self.detach(&status.id.clone());
        let runtime = self.runtime.clone();
        let (id, signal, grace) = (
            status.id.clone(),
            status.stop_signal.clone(),
            status.stop_grace,
        );
        tracing::info!(replica = %id, %signal, grace_s = grace.as_secs(), "stopping a replica");
        self.stops.insert(
            status.id.clone(),
            tokio::spawn(async move {
                if let Err(error) = runtime.remove(&id, &signal, grace).await {
                    tracing::warn!(replica = %id, error = %format!("{error:#}"), "could not stop a replica");
                }
            }),
        );
    }

    fn stopping(&self, id: &str) -> bool {
        self.stops.get(id).is_some_and(|h| !h.is_finished())
    }

    /// One pass: observe, plan, act, check, report.
    pub async fn pass(&mut self) -> anyhow::Result<()> {
        self.stops.retain(|_, h| !h.is_finished());
        let desired = self.shared.desired.lock().expect("shared lock").clone();
        let wanted: Vec<Replica> = desired
            .as_ref()
            .map(|d| d.replicas.clone())
            .unwrap_or_default();
        let mut reports: BTreeMap<String, ReplicaObserved> = BTreeMap::new();
        let mut refusals = Vec::new();
        if wanted.is_empty() && self.tracked.is_empty() {
            let containers: Vec<ContainerStatus> = self.runtime.list().await.unwrap_or_default();
            for container in &containers {
                self.stop(container);
            }
            self.publish(Vec::new(), Vec::new());
            return Ok(());
        }
        if let Err(error) = self.runtime.prepare().await {
            let reason = format!("the container runtime is not ready: {error:#}");
            for replica in &wanted {
                reports.insert(
                    replica.replica_id.clone(),
                    report(
                        replica,
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_FAILED,
                        &reason,
                    ),
                );
            }
            self.publish(reports.into_values().collect(), refusals);
            return Ok(());
        }
        let containers = self.runtime.list().await?;
        let net = self.net();
        let wanted_ids: HashSet<&str> = wanted.iter().map(|r| r.replica_id.as_str()).collect();
        for container in &containers {
            if !wanted_ids.contains(container.id.as_str()) {
                self.stop(container);
                reports.insert(
                    container.id.clone(),
                    ReplicaObserved {
                        replica_id: container.id.clone(),
                        state: ReplicaObservedState::REPLICA_OBSERVED_STATE_STOPPING.into(),
                        ..Default::default()
                    },
                );
            }
        }
        self.tracked
            .retain(|id, _| wanted_ids.contains(id.as_str()));
        let before = self.secrets.len();
        self.secrets
            .retain(|id, _| wanted_ids.contains(id.as_str()));
        if self.secrets.len() != before
            && let Err(error) = secrets::store(&self.data_dir, &self.cache_key, &self.secrets)
        {
            tracing::warn!(error = %format!("{error:#}"), "could not keep the secrets cache");
        }
        let now = Instant::now();
        let mut probes = Vec::new();
        for replica in &wanted {
            let id = replica.replica_id.clone();
            if let Some(reason) = self.policy.refuses(replica) {
                refusals.push(format!("replica {id} of {}: {reason}", replica.app));
                if let Some(container) = containers.iter().find(|c| c.id == id) {
                    self.stop(container);
                }
                reports.insert(
                    id,
                    report(
                        replica,
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_REFUSED,
                        &reason,
                    ),
                );
                continue;
            }
            let existing = containers.iter().find(|c| c.id == id);
            if self.stopping(&id) {
                reports.insert(
                    id.clone(),
                    report(
                        replica,
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_STOPPING,
                        "",
                    ),
                );
                continue;
            }
            let hash = container_hash(replica, net.as_ref());
            if let Some(container) = existing
                && container.spec_hash != hash
            {
                self.stop(container);
                reports.insert(
                    id.clone(),
                    report(
                        replica,
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_STARTING,
                        "",
                    ),
                );
                continue;
            }
            if existing.is_some()
                && let Some(net) = &net
                && let Err(reason) = self.attach(&id, net).await
            {
                tracing::warn!(replica = %id, %reason, "could not give a running replica its address again");
            }
            match existing.map(|c| &c.state) {
                None => {
                    let state = self.start(replica, now, net.as_ref()).await;
                    reports.insert(id.clone(), state);
                }
                Some(TaskState::Created) => {
                    let tracked = self.tracked.entry(id.clone()).or_default();
                    tracked.started = Some(now);
                    let state = match self.runtime.restart(&id).await {
                        Ok(()) => report(
                            replica,
                            ReplicaObservedState::REPLICA_OBSERVED_STATE_STARTING,
                            "",
                        ),
                        Err(error) => report(
                            replica,
                            ReplicaObservedState::REPLICA_OBSERVED_STATE_FAILED,
                            &format!("could not start it: {error:#}"),
                        ),
                    };
                    reports.insert(id.clone(), state);
                }
                Some(TaskState::Running { .. }) => {
                    let tracked = self.tracked.entry(id.clone()).or_default();
                    let started = *tracked.started.get_or_insert(now);
                    tracked.restart_at = None;
                    if now.duration_since(started) >= BACKOFF_RESET {
                        tracked.exits_since_reset = 0;
                    }
                    match probe_of(replica) {
                        None => {
                            if !tracked.readiness.ready {
                                tracked.readiness = Readiness {
                                    ready: true,
                                    since: Some(now),
                                    ..Readiness::default()
                                };
                            }
                        }
                        Some((probe, interval, timeout)) => {
                            let due = tracked
                                .readiness
                                .last_probe
                                .is_none_or(|at| now.duration_since(at) >= interval);
                            if due {
                                tracked.readiness.last_probe = Some(now);
                                let address = self.attached.get(&id).copied();
                                probes.push((id.clone(), probe, timeout, address));
                            }
                        }
                    }
                    reports.insert(id.clone(), ReplicaObserved::default());
                }
                Some(TaskState::Exited { code, .. }) => {
                    let code = *code;
                    let tracked = self.tracked.entry(id.clone()).or_default();
                    if tracked.restart_at.is_none() {
                        tracked.exits_since_reset += 1;
                        tracked.last_exit_code = code;
                        tracked.readiness = Readiness {
                            reason: format!("its process exited with code {code}"),
                            ..Readiness::default()
                        };
                        let wait = backoff(tracked.exits_since_reset);
                        tracked.restart_at = Some(now + wait);
                        tracing::info!(replica = %id, code, wait_s = wait.as_secs(), "a replica exited; restarting after its back-off");
                    }
                    if tracked.restart_at.is_some_and(|at| now >= at) {
                        match self.runtime.restart(&id).await {
                            Ok(()) => {
                                let tracked = self.tracked.entry(id.clone()).or_default();
                                tracked.restarts += 1;
                                tracked.restart_at = None;
                                tracked.started = Some(now);
                            }
                            Err(error) => {
                                tracing::warn!(replica = %id, error = %format!("{error:#}"), "could not restart a replica");
                            }
                        }
                    }
                    reports.insert(
                        id.clone(),
                        report(
                            replica,
                            ReplicaObservedState::REPLICA_OBSERVED_STATE_EXITED,
                            "",
                        ),
                    );
                }
            }
        }
        let results = futures_join(
            probes
                .into_iter()
                .map(|(id, probe, timeout, address)| {
                    let runtime = self.runtime.clone();
                    async move {
                        let mut ipv4_only = false;
                        let result = match address {
                            None => runtime.probe(&id, &probe, timeout).await,
                            Some(address) => {
                                let result = crate::probe::run_at(
                                    IpAddr::V6(address),
                                    probe.clone(),
                                    timeout,
                                )
                                .await;
                                match result {
                                    Err(reason)
                                        if runtime.probe(&id, &probe, timeout).await.is_ok() =>
                                    {
                                        ipv4_only = true;
                                        Err(format!(
                                            "it answers only on IPv4 inside its container ({reason} on its address {address}); forwarding its address to it"
                                        ))
                                    }
                                    other => other,
                                }
                            }
                        };
                        (id, result, ipv4_only)
                    }
                })
                .collect(),
        )
        .await;
        let mut forward = Vec::new();
        for (id, result, ipv4_only) in results {
            if ipv4_only {
                forward.push(id.clone());
            }
            let tracked = self.tracked.entry(id).or_default();
            let readiness = &mut tracked.readiness;
            match result {
                Ok(()) => {
                    readiness.failures = 0;
                    readiness.reason.clear();
                    if !readiness.ready {
                        readiness.ready = true;
                        readiness.since = Some(Instant::now());
                    }
                }
                Err(reason) => {
                    readiness.failures += 1;
                    readiness.reason = reason;
                    if readiness.failures >= FAILURES_BEFORE_UNREADY || !readiness.ready {
                        readiness.ready = false;
                        readiness.since = None;
                    }
                }
            }
        }
        for replica in &wanted {
            let Some(observed) = reports.get_mut(&replica.replica_id) else {
                continue;
            };
            let tracked = self.tracked.get(&replica.replica_id);
            if observed.replica_id.is_empty() {
                *observed = report(
                    replica,
                    ReplicaObservedState::REPLICA_OBSERVED_STATE_RUNNING,
                    "",
                );
                if let Some(tracked) = tracked {
                    observed.ready = tracked.readiness.ready;
                    observed.ready_for_ms = tracked
                        .readiness
                        .since
                        .map_or(0, |since| since.elapsed().as_millis() as u64);
                    observed.reason = tracked.readiness.reason.clone();
                }
            }
            if let Some(tracked) = tracked {
                observed.restarts = tracked.restarts;
                observed.last_exit_code = tracked.last_exit_code;
                if observed.state.as_known()
                    == Some(ReplicaObservedState::REPLICA_OBSERVED_STATE_EXITED)
                    && observed.reason.is_empty()
                {
                    observed.reason = tracked.readiness.reason.clone();
                }
            }
        }
        for id in forward {
            if let Some(replica) = wanted.iter().find(|r| r.replica_id == id) {
                self.forward_ipv4(replica).await;
            }
        }
        let known: Vec<String> = self.attached.keys().cloned().collect();
        for id in known {
            if !wanted_ids.contains(id.as_str()) && !containers.iter().any(|c| c.id == id) {
                self.detach(&id);
            }
        }
        let endpoints: Vec<ReplicaEndpoint> = wanted
            .iter()
            .filter_map(|replica| {
                let address = *self.attached.get(&replica.replica_id)?;
                Some(ReplicaEndpoint {
                    replica_id: replica.replica_id.clone(),
                    app: replica.app.clone(),
                    address,
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
                    ready: self
                        .tracked
                        .get(&replica.replica_id)
                        .is_some_and(|t| t.readiness.ready),
                    draining: replica.state.as_known()
                        == Some(ReplicaState::REPLICA_STATE_DRAINING),
                })
            })
            .collect();
        self.shared.endpoints.0.send_if_modified(|current| {
            let changed = *current != endpoints;
            if changed {
                *current = endpoints;
            }
            changed
        });
        self.publish(reports.into_values().collect(), refusals);
        Ok(())
    }

    async fn start(
        &mut self,
        replica: &Replica,
        now: Instant,
        net: Option<&Net>,
    ) -> ReplicaObserved {
        let id = replica.replica_id.clone();
        let Some(image) = replica.image.as_option() else {
            return report(
                replica,
                ReplicaObservedState::REPLICA_OBSERVED_STATE_FAILED,
                "no image",
            );
        };
        if let Some((reason, at)) = self.tracked.get(&id).and_then(|t| t.failed.clone())
            && now.duration_since(at) < RETRY_FAILED
        {
            return report(
                replica,
                ReplicaObservedState::REPLICA_OBSERVED_STATE_FAILED,
                &reason,
            );
        }
        let values = match self.secret_values(replica).await {
            Ok(values) => values,
            Err(reason) => {
                self.tracked.entry(id).or_default().failed = Some((reason.clone(), now));
                return report(
                    replica,
                    ReplicaObservedState::REPLICA_OBSERVED_STATE_FAILED,
                    &reason,
                );
            }
        };
        let spec = match spec(replica, &values, net) {
            Ok(spec) => spec,
            Err(reason) => {
                return report(
                    replica,
                    ReplicaObservedState::REPLICA_OBSERVED_STATE_REFUSED,
                    &reason,
                );
            }
        };
        let digest = image.digest.clone();
        if let Some(handle) = self.pulls.get(&digest) {
            if !handle.is_finished() {
                return report(
                    replica,
                    ReplicaObservedState::REPLICA_OBSERVED_STATE_PULLING,
                    "",
                );
            }
            let handle = self.pulls.remove(&digest).expect("the pull just looked at");
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(reason)) => {
                    self.pull_failed.insert(digest.clone(), (reason, now));
                }
                Err(error) => {
                    self.pull_failed
                        .insert(digest.clone(), (format!("the pull stopped: {error}"), now));
                }
            }
        }
        if let Some((reason, at)) = self.pull_failed.get(&digest).cloned() {
            if now.duration_since(at) < RETRY_FAILED {
                return report(
                    replica,
                    ReplicaObservedState::REPLICA_OBSERVED_STATE_PULLING,
                    &format!("could not fetch its image: {reason}"),
                );
            }
            self.pull_failed.remove(&digest);
        }
        match self.runtime.has_image(&spec.image).await {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                let runtime = self.runtime.clone();
                let image = spec.image.clone();
                tracing::info!(image = %image.reference, "pulling an image");
                self.pulls.insert(
                    digest,
                    tokio::spawn(async move {
                        runtime.pull(&image).await.map_err(|e| format!("{e:#}"))
                    }),
                );
                return report(
                    replica,
                    ReplicaObservedState::REPLICA_OBSERVED_STATE_PULLING,
                    "",
                );
            }
        }
        let mut spec = spec;
        if let Some(net) = net {
            match self.attach(&id, net).await {
                Ok(Some(_)) => {}
                Ok(None) => spec.resolv_conf = None,
                Err(reason) => {
                    self.tracked.entry(id).or_default().failed = Some((reason.clone(), now));
                    return report(
                        replica,
                        ReplicaObservedState::REPLICA_OBSERVED_STATE_FAILED,
                        &reason,
                    );
                }
            }
        }
        match self.runtime.create(&spec).await {
            Ok(()) => {
                tracing::info!(replica = %id, app = %replica.app, release = replica.release, "started a replica");
                let tracked = self.tracked.entry(id).or_default();
                tracked.started = Some(now);
                tracked.failed = None;
                report(
                    replica,
                    ReplicaObservedState::REPLICA_OBSERVED_STATE_STARTING,
                    "",
                )
            }
            Err(error) => {
                let reason = format!("could not start it: {error:#}");
                tracing::warn!(replica = %id, %reason, "could not create a replica");
                self.tracked.entry(id).or_default().failed = Some((reason.clone(), now));
                report(
                    replica,
                    ReplicaObservedState::REPLICA_OBSERVED_STATE_FAILED,
                    &reason,
                )
            }
        }
    }

    fn publish(&mut self, reports: Vec<ReplicaObserved>, refusals: Vec<String>) {
        let changed = reports.len() != self.last_reports.len()
            || reports.iter().zip(&self.last_reports).any(|(a, b)| {
                a.replica_id != b.replica_id
                    || a.state != b.state
                    || a.ready != b.ready
                    || a.restarts != b.restarts
            });
        *self.shared.reports.lock().expect("shared lock") = reports.clone();
        *self.shared.refusals.lock().expect("shared lock") = refusals;
        self.last_reports = reports;
        if changed {
            self.shared.changed.notify_one();
        }
    }
}

async fn futures_join<F: std::future::Future + Send + 'static>(futures: Vec<F>) -> Vec<F::Output>
where
    F::Output: Send + 'static,
{
    let handles: Vec<JoinHandle<F::Output>> = futures.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(output) = handle.await {
            out.push(output);
        }
    }
    out
}

fn report(replica: &Replica, state: ReplicaObservedState, reason: &str) -> ReplicaObserved {
    ReplicaObserved {
        replica_id: replica.replica_id.clone(),
        state: state.into(),
        reason: reason.chars().take(500).collect(),
        ..Default::default()
    }
}

/// Stops every container in parallel, each with its own grace: what the
/// agent does when the system shuts down, so `systemd-shutdown` never waits
/// on apps that ignore `SIGTERM` as PID 1 (apps.md §7.3 rule 3).
pub async fn stop_all<C: ContainerRuntime + 'static>(runtime: Arc<C>) -> anyhow::Result<usize> {
    let containers = runtime.list().await?;
    let count = containers.len();
    let stops: Vec<_> = containers
        .into_iter()
        .map(|c| {
            let runtime = runtime.clone();
            async move { runtime.remove(&c.id, &c.stop_signal, c.stop_grace).await }
        })
        .collect();
    for result in futures_join(stops).await {
        if let Err(error) = result {
            tracing::warn!(error = %format!("{error:#}"), "could not stop a replica at shutdown");
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use grund_proto::grund::agent::v1::{Image, ReplicaCheck, SecretRef};

    use super::*;
    use crate::simulated::SimulatedContainers;

    #[test]
    fn the_back_off_is_the_kubelets_but_the_first_restart_is_at_once() {
        let schedule: Vec<u64> = (1..=9).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(schedule, vec![0, 10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(backoff(64), BACKOFF_CAP);
    }

    fn replica(id: &str, env: &[(&str, &str)]) -> Replica {
        Replica {
            replica_id: id.into(),
            app: "web".into(),
            release: 1,
            image: buffa::MessageField::from(Image {
                reference: "traefik/whoami:v1.10".into(),
                digest: format!("sha256:{}", "e".repeat(64)),
                ..Default::default()
            }),
            env: env
                .iter()
                .map(|(n, v)| grund_proto::grund::agent::v1::EnvVar {
                    name: n.to_string(),
                    value: v.to_string(),
                    ..Default::default()
                })
                .collect(),
            memory_mib: 64,
            cpu_millis: 100,
            check: buffa::MessageField::from(ReplicaCheck {
                kind: Some(replica_check::Kind::HttpPath("/".into())),
                port: 80,
                interval_ms: 500,
                timeout_ms: 100,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn harness(name: &str) -> (Apps<SimulatedContainers>, Arc<Shared>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("grund-apps-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let shared = Arc::new(Shared::default());
        let apps = Apps::new(
            Arc::new(SimulatedContainers::new(dir.join("runtime"))),
            None,
            shared.clone(),
            Policy::default(),
            dir.clone(),
            &[9; 32],
        );
        (apps, shared, dir)
    }

    fn set(shared: &Shared, replicas: Vec<Replica>) {
        *shared.desired.lock().unwrap() = Some(DesiredState {
            replicas,
            ..Default::default()
        });
    }

    fn state_of(shared: &Shared, id: &str) -> (Option<ReplicaObservedState>, bool, u32) {
        let reports = shared.reports.lock().unwrap();
        let r = reports.iter().find(|r| r.replica_id == id).unwrap();
        (r.state.as_known(), r.ready, r.restarts)
    }

    #[tokio::test]
    async fn a_replica_is_pulled_started_and_ready_and_a_second_pass_changes_nothing() {
        let (mut apps, shared, dir) = harness("start");
        set(&shared, vec![replica("r1", &[])]);
        apps.pass().await.unwrap();
        assert_eq!(
            state_of(&shared, "r1").0,
            Some(ReplicaObservedState::REPLICA_OBSERVED_STATE_PULLING)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        apps.pass().await.unwrap();
        assert_eq!(
            state_of(&shared, "r1").0,
            Some(ReplicaObservedState::REPLICA_OBSERVED_STATE_STARTING)
        );
        apps.pass().await.unwrap();
        let (state, ready, _) = state_of(&shared, "r1");
        assert_eq!(
            state,
            Some(ReplicaObservedState::REPLICA_OBSERVED_STATE_RUNNING)
        );
        assert!(ready);
        let before = apps.runtime.list().await.unwrap();
        apps.pass().await.unwrap();
        assert_eq!(apps.runtime.list().await.unwrap(), before);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_killed_replica_is_restarted_at_once_and_then_after_its_back_off() {
        let (mut apps, shared, dir) = harness("kill");
        set(&shared, vec![replica("r1", &[])]);
        for _ in 0..3 {
            apps.pass().await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        std::fs::write(dir.join("runtime/kill/r1"), b"").unwrap();
        apps.pass().await.unwrap();
        apps.pass().await.unwrap();
        let (state, _, restarts) = state_of(&shared, "r1");
        assert_eq!(
            state,
            Some(ReplicaObservedState::REPLICA_OBSERVED_STATE_RUNNING)
        );
        assert_eq!(restarts, 1);
        std::fs::write(dir.join("runtime/kill/r1"), b"").unwrap();
        apps.pass().await.unwrap();
        apps.pass().await.unwrap();
        let (state, ready, restarts) = state_of(&shared, "r1");
        assert_eq!(
            state,
            Some(ReplicaObservedState::REPLICA_OBSERVED_STATE_EXITED)
        );
        assert!(!ready);
        assert_eq!(restarts, 1, "the second restart waits 10 s");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_replica_whose_check_fails_is_never_ready_and_says_why() {
        let (mut apps, shared, dir) = harness("unready");
        set(
            &shared,
            vec![replica("r1", &[("GRUND_SIMULATE", "unready")])],
        );
        for _ in 0..4 {
            apps.pass().await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let reports = shared.reports.lock().unwrap().clone();
        assert!(!reports[0].ready);
        assert_eq!(reports[0].reason, "status 503");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_replica_that_leaves_the_document_is_stopped_and_a_refused_one_never_runs() {
        let (mut apps, shared, dir) = harness("leave");
        set(&shared, vec![replica("r1", &[])]);
        for _ in 0..3 {
            apps.pass().await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let mut unpinned = replica("r2", &[]);
        unpinned.image = buffa::MessageField::from(Image {
            reference: "nginx".into(),
            digest: "latest".into(),
            ..Default::default()
        });
        set(&shared, vec![unpinned]);
        let deadline = Instant::now() + Duration::from_secs(5);
        let ids = loop {
            apps.pass().await.unwrap();
            let ids: Vec<String> = apps
                .runtime
                .list()
                .await
                .unwrap()
                .into_iter()
                .map(|c| c.id)
                .collect();
            if ids.is_empty() || Instant::now() >= deadline {
                break ids;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(ids.is_empty(), "r1 was not stopped within 5 s: {ids:?}");
        assert_eq!(
            state_of(&shared, "r2").0,
            Some(ReplicaObservedState::REPLICA_OBSERVED_STATE_REFUSED)
        );
        assert_eq!(shared.refusals.lock().unwrap().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn an_image_that_cannot_be_pulled_is_reported_with_the_reason() {
        let (mut apps, shared, dir) = harness("pull");
        let mut r = replica("r1", &[]);
        r.image = buffa::MessageField::from(Image {
            reference: "acme/missing:1".into(),
            digest: format!("sha256:{}", "f".repeat(64)),
            ..Default::default()
        });
        set(&shared, vec![r]);
        apps.pass().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        apps.pass().await.unwrap();
        let reports = shared.reports.lock().unwrap().clone();
        assert!(
            reports[0].reason.contains("could not fetch its image"),
            "{:?}",
            reports[0]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_secrets_version_changes_the_container_and_its_value_never_enters_the_hash() {
        let mut a = replica("r1", &[]);
        a.secrets.push(SecretRef {
            name: "db".into(),
            version: 1,
            ..Default::default()
        });
        let mut b = a.clone();
        b.secrets[0].version = 2;
        assert_ne!(spec_hash(&a), spec_hash(&b));
        assert_eq!(spec_hash(&a), spec_hash(&a.clone()));
    }
}
