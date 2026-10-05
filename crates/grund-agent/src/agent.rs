//! `grund agent`: the long-running half of the machine agent (grund-docs
//! design/machines.md §7b). After `grund join`, it keeps the machine
//! connected: a heartbeat with what the machine can do, the machine's desired
//! state when it changes, verified against the organisation key pinned at
//! registration, the VMs that state asks for, and a report of what runs.
//!
//! Every request is signed by the machine key (the control link over HTTPS,
//! until it moves onto iroh). A document is applied only if it verifies, is
//! for this machine and organisation, is newer than the last one applied, and
//! asks for no feature this agent does not know; otherwise the agent keeps
//! the last good one and reports why.
//!
//! A document arrives two ways: a long poll of WatchDesiredState, so it
//! applies within moments of its commit, and, as a fallback for an instance
//! without that call, the heartbeat's generation followed by
//! GetDesiredState. Either way it is verified the same way and handed to
//! the apps loop ([`crate::apps`]).
//!
//! At SIGTERM the agent tells a system shutdown from its own restart: only
//! when the system is stopping does it stop every replica first, in
//! parallel, each with its own grace (apps.md §7.3 rule 3); a restart or an
//! update leaves them running.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use buffa::Message;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use grund_proto::grund::agent::v1::{
    Capabilities, DesiredState, GetDesiredStateRequest, GetDesiredStateResponse,
    GetMachineJoinTokenRequest, GetMachineJoinTokenResponse, HeartbeatRequest, HeartbeatResponse,
    ReportStatusRequest, ReportStatusResponse, SignedDesiredState, VmDesiredState, VmObserved,
    VmObservedState, WatchDesiredStateRequest, WatchDesiredStateResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    apps::{Apps, Shared},
    join::{self, Record},
    policy::Policy,
    runtime::ContainerRuntime,
    vm::{self, Artifact, VmImage, VmRuntime, VmSpec, VmState, VmStatus},
};

/// Features this agent knows how to apply.
pub const KNOWN_FEATURES: &[&str] = &["machines", "replicas"];

/// The largest document the agent decodes (apps.md §15).
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The deadline the agent asks the instance to give each call, in
/// milliseconds: longer than GetMembership's 10 s long-poll, so a poll that
/// waits its full time is not cut short by the instance's own 10 s default,
/// and shorter than the agent's 15 s HTTP timeout, so the instance answers
/// first.
pub const CALL_DEADLINE_MS: u64 = 14_000;

/// The file keeping what the agent applied last.
pub const APPLIED_FILE: &str = "applied.json";

/// `grund agent`.
#[derive(Clone, Debug, clap::Args)]
pub struct AgentArgs {
    /// Where `grund join` kept the machine's key and identity.
    #[arg(
        long,
        env = "GRUND_AGENT_DATA_DIR",
        default_value = "/var/lib/grund/agent"
    )]
    pub data_dir: PathBuf,

    /// One round (heartbeat, desired state, VMs, report), then exit.
    #[arg(long, hide = true)]
    pub once: bool,

    /// Seconds between rounds, instead of what the instance asks for.
    #[arg(long, hide = true)]
    pub interval: Option<u64>,

    /// The machine owner's policy for what this machine runs (grund-docs
    /// design/apps.md §6.4). Missing: the defaults.
    #[arg(long, env = "GRUND_AGENT_POLICY", default_value = crate::policy::POLICY_FILE)]
    pub policy: PathBuf,

    /// Tests only: a JSON file of ready copies on other machines, read
    /// every second, standing in for the signed list's members' apps until
    /// the private network carries them.
    #[arg(long, hide = true)]
    pub gate_remote_copies: Option<PathBuf>,
}

/// What the agent applied last, kept across restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Applied {
    pub generation: u64,
    /// The document's payload, as verified, hex.
    pub payload: String,
}

/// Why a document was not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    TooLarge,
    BadSignature,
    Malformed,
    WrongMachine,
    Older,
    UnknownFeature(String),
    NoTrustKey,
    /// Signed by a key other than the one pinned.
    UnknownKey,
    /// The document applied last, again: nothing to do, and nothing to
    /// report.
    Same,
    /// The same generation as the one applied, with different content: the
    /// instance signed two documents it should not have, a bug or a
    /// compromise (apps.md §6.3).
    Equivocation,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::TooLarge => f.write_str("document larger than 1 MiB"),
            Refusal::BadSignature => f.write_str("document signature does not verify"),
            Refusal::Malformed => f.write_str("document does not decode"),
            Refusal::WrongMachine => f.write_str("document is for another machine or organisation"),
            Refusal::Older => f.write_str("document is not newer than the one applied"),
            Refusal::UnknownFeature(name) => write!(f, "document requires unknown feature {name}"),
            Refusal::NoTrustKey => f.write_str("this machine pinned no organisation key"),
            Refusal::UnknownKey => f.write_str("document is signed by a key this machine did not pin"),
            Refusal::Same => f.write_str("document is the one applied"),
            Refusal::Equivocation => f.write_str(
                "EQUIVOCATION: a second, different document for the generation already applied; the instance signed two",
            ),
        }
    }
}

/// Verifies and decodes a signed document against the pinned organisation
/// key, for this machine, newer than what was applied. The same generation
/// again is [`Refusal::Same`] with the same payload and
/// [`Refusal::Equivocation`] with a different one; only a lower generation
/// is [`Refusal::Older`].
pub fn verify(
    record: &Record,
    trust: &VerifyingKey,
    key_id: &str,
    payload: &[u8],
    signature: &[u8],
    applied: &Applied,
) -> Result<DesiredState, Refusal> {
    if payload.len() > MAX_DOCUMENT_BYTES {
        return Err(Refusal::TooLarge);
    }
    if key_id != record.trust_key.key_id {
        return Err(Refusal::UnknownKey);
    }
    let signature = Signature::from_slice(signature).map_err(|_| Refusal::BadSignature)?;
    let mut message = b"grund-desired-state-v1\n".to_vec();
    message.extend_from_slice(payload);
    trust
        .verify_strict(&message, &signature)
        .map_err(|_| Refusal::BadSignature)?;
    let state = DesiredState::decode_from_slice(payload).map_err(|_| Refusal::Malformed)?;
    if state.machine_id != record.machine_id || state.organisation_id != record.organisation_id {
        return Err(Refusal::WrongMachine);
    }
    if state.generation < applied.generation {
        return Err(Refusal::Older);
    }
    if state.generation == applied.generation && applied.generation > 0 {
        let same = hex::decode(&applied.payload)
            .is_ok_and(|kept| Sha256::digest(&kept) == Sha256::digest(payload));
        return Err(if same {
            Refusal::Same
        } else {
            Refusal::Equivocation
        });
    }
    if let Some(unknown) = state
        .required_features
        .iter()
        .find(|f| !KNOWN_FEATURES.contains(&f.as_str()))
    {
        return Err(Refusal::UnknownFeature(unknown.clone()));
    }
    Ok(state)
}

#[derive(Clone)]
pub(crate) struct Link {
    http: reqwest::Client,
    origin: String,
    machine_id: String,
    key: SigningKey,
}

impl Link {
    pub(crate) async fn call<Req: Message, Resp: Message>(
        &self,
        procedure: &str,
        request: &Req,
    ) -> anyhow::Result<Resp> {
        let path = format!("/grund.agent.v1.AgentService/{procedure}");
        let body = request.encode_to_vec();
        let signed_at = unix_now();
        let message = format!(
            "grund-agent-request-v1\n{path}\n{signed_at}\n{}",
            hex::encode(Sha256::digest(&body))
        );
        let signature = STANDARD.encode(self.key.sign(message.as_bytes()).to_bytes());
        let response = self
            .http
            .post(format!("{}{path}", self.origin))
            .header("Content-Type", "application/proto")
            .header("Connect-Protocol-Version", "1")
            .header("Connect-Timeout-Ms", CALL_DEADLINE_MS.to_string())
            .header("x-grund-machine", &self.machine_id)
            .header("x-grund-signed-at", signed_at.to_string())
            .header("x-grund-signature", signature)
            .body(body)
            .send()
            .await
            .with_context(|| format!("reach {}", self.origin))?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            bail!(
                "{procedure}: {} ({})",
                error["message"].as_str().unwrap_or("refused"),
                error["code"].as_str().unwrap_or("unknown")
            );
        }
        Resp::decode_from_slice(&bytes)
            .with_context(|| format!("{procedure}: an answer that does not decode"))
    }
}

/// Runs `grund agent` with `runtime` for VMs and `containers` for apps.
pub async fn run<R: VmRuntime, C: ContainerRuntime + 'static>(
    args: &AgentArgs,
    runtime: R,
    containers: C,
) -> anyhow::Result<()> {
    grund_tls::install_default();
    let record = join::read_record(&args.data_dir)?
        .context("this machine is not registered; run grund join first")?;
    let key = join::machine_key(&args.data_dir)?;
    let trust = trust_key(&record);
    let policy = Policy::load(&args.policy)?;
    let link = Link {
        http: join::http_client()?,
        origin: record.instance_url.clone(),
        machine_id: record.machine_id.clone(),
        key,
    };
    let applied = std::sync::Arc::new(tokio::sync::Mutex::new(read_applied(&args.data_dir)?));
    let shared = std::sync::Arc::new(Shared::default());
    *shared.desired.lock().expect("shared lock") = current(&*applied.lock().await);
    let containers = std::sync::Arc::new(containers);
    let gate = crate::gate::Gate::new(
        std::sync::Arc::new(crate::gate::Direct),
        crate::gate::Limits::default(),
    );
    tracing::info!(machine = %record.machine_id, name = %record.name, "agent running");
    let lists = tokio::sync::watch::Sender::new(None);
    let entry_relays = record
        .network
        .as_ref()
        .map(|n| n.relay_urls.clone())
        .unwrap_or_default();
    let entry_endpoint: EntryEndpoint = Default::default();
    if record.network.is_none() && !args.once {
        tokio::spawn(entry_only(
            gate.clone(),
            link.key.to_bytes(),
            entry_relays.clone(),
            entry_endpoint.clone(),
        ));
    }
    let mesh: std::sync::Arc<std::sync::OnceLock<grund_net::mesh::Mesh>> =
        std::sync::Arc::new(std::sync::OnceLock::new());
    if let Some(network) = record.network.clone().filter(|_| !args.once) {
        let (link, seed, data_dir) = (link.clone(), link.key.to_bytes(), args.data_dir.clone());
        let (lists, mesh) = (lists.clone(), mesh.clone());
        let entry_gate = gate.clone();
        let fallback_gate = gate.clone();
        let fallback_seed = link.key.to_bytes();
        let fallback_endpoint = entry_endpoint.clone();
        tokio::spawn(async move {
            let options = crate::net::NetOptions {
                lists: Some(lists),
                mesh: Some(mesh),
                extra: Some(crate::net::ExtraProtocol {
                    alpn: grund_entry::ENTRY_ALPN.to_vec(),
                    handler: std::sync::Arc::new(move || {
                        Box::new(crate::gate::entry::EntryProtocol(entry_gate.clone()))
                    }),
                }),
            };
            if let Err(error) = crate::net::run(link, network, seed, data_dir, options).await {
                tracing::error!(error = %format!("{error:#}"), "private network stopped");
            }
            entry_only(
                fallback_gate,
                fallback_seed,
                entry_relays,
                fallback_endpoint,
            )
            .await;
        });
    }
    let mut apps = Apps::new(
        containers.clone(),
        Some(link.clone()),
        shared.clone(),
        policy.clone(),
        args.data_dir.clone(),
        &link.key.to_bytes(),
    )
    .with_network(crate::apps::NetworkAccess {
        lists: lists.subscribe(),
        mesh: mesh.clone(),
        own: grund_net::key::endpoint_id(&link.key.to_bytes()).to_string(),
    });
    if !args.once {
        tokio::spawn(apps.run());
        apps = Apps::new(
            containers.clone(),
            None,
            std::sync::Arc::new(Shared::default()),
            policy.clone(),
            args.data_dir.clone(),
            &link.key.to_bytes(),
        );
        let watcher = Watcher {
            link: link.clone(),
            record: record.clone(),
            trust,
            applied: applied.clone(),
            shared: shared.clone(),
            data_dir: args.data_dir.clone(),
        };
        tokio::spawn(watcher.run());
        tokio::spawn(keep_gate(
            gate.clone(),
            shared.clone(),
            lists.subscribe(),
            record.machine_id.clone(),
            args.gate_remote_copies.clone(),
        ));
        tokio::spawn(stop_at_shutdown(
            containers.clone(),
            gate.clone(),
            mesh.clone(),
            entry_endpoint.clone(),
        ));
    }
    let context = Round {
        link: &link,
        record: &record,
        trust: trust.as_ref(),
        runtime: &runtime,
        containers: containers.as_ref(),
        policy: &policy,
        data_dir: &args.data_dir,
        applied: &applied,
        shared: &shared,
        gate: &gate,
    };
    loop {
        let interval = match round(&context).await {
            Ok(seconds) => args.interval.unwrap_or(seconds.max(1) as u64),
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "round failed; trying again");
                args.interval.unwrap_or(5)
            }
        };
        if args.once {
            if let Err(error) = apps.pass().await {
                tracing::warn!(error = %format!("{error:#}"), "apps pass failed");
            }
            return Ok(());
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {}
            _ = shared.changed.notified() => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn keep_gate(
    gate: crate::gate::Gate,
    shared: std::sync::Arc<Shared>,
    lists: tokio::sync::watch::Receiver<Option<grund_net::membership::MembershipList>>,
    own_machine_id: String,
    remote_file: Option<PathBuf>,
) {
    let mut from_file = Vec::new();
    let mut last_read = std::time::Instant::now() - Duration::from_secs(60);
    let mut last_logged = std::time::Instant::now();
    let mut logged = [0u64; 7];
    loop {
        if last_logged.elapsed() >= Duration::from_secs(10) {
            last_logged = std::time::Instant::now();
            let stats = gate.stats();
            let now = [
                &stats.streams,
                &stats.refused,
                &stats.requests,
                &stats.retried,
                &stats.misdirected,
                &stats.remote,
                &stats.failed,
            ]
            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed));
            if now != logged {
                logged = now;
                tracing::info!(
                    streams = now[0],
                    refused = now[1],
                    requests = now[2],
                    retried = now[3],
                    misdirected = now[4],
                    remote = now[5],
                    failed = now[6],
                    "gate: totals"
                );
            }
        }
        if let Some(path) = &remote_file
            && last_read.elapsed() >= Duration::from_secs(1)
        {
            last_read = std::time::Instant::now();
            from_file = read_remote_copies(path);
        }
        let mut remote = remote_copies(lists.borrow().as_ref(), &own_machine_id);
        remote.extend(from_file.iter().cloned());
        let document = shared.desired.lock().expect("shared lock").clone();
        let local: Vec<crate::gate::ReplicaEndpoint> = shared
            .endpoints()
            .borrow()
            .iter()
            .map(|e| crate::gate::ReplicaEndpoint {
                replica_id: e.replica_id.clone(),
                app: e.app.clone(),
                address: Some(e.address),
                ports: e
                    .ports
                    .iter()
                    .map(|p| crate::gate::EndpointPort {
                        name: p.name.clone(),
                        port: p.port,
                        protocol: p.protocol.clone(),
                    })
                    .collect(),
                ready: e.ready,
                draining: e.draining,
            })
            .collect();
        gate.update(document.as_ref(), &local, &remote);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

type EntryEndpoint = std::sync::Arc<std::sync::Mutex<Option<iroh::Endpoint>>>;

async fn entry_only(
    gate: crate::gate::Gate,
    seed: [u8; 32],
    relays: Vec<String>,
    held: EntryEndpoint,
) {
    let relays: Vec<iroh::RelayUrl> = relays.iter().filter_map(|u| u.parse().ok()).collect();
    let config = grund_net::endpoint::NetConfig {
        relays,
        relay_roots: crate::net::relay_roots().unwrap_or_default(),
        ..Default::default()
    };
    let mut retry = Duration::from_secs(1);
    loop {
        match grund_net::endpoint::bind(
            grund_net::key::secret_key(&seed),
            &config,
            vec![grund_entry::ENTRY_ALPN.to_vec()],
        )
        .await
        {
            Ok(endpoint) => {
                tracing::info!(bound = ?endpoint.bound_sockets(), "gate: taking entry streams on the machine key, beside no private network");
                *held.lock().expect("entry endpoint lock") = Some(endpoint.clone());
                let _router = iroh::protocol::Router::builder(endpoint)
                    .accept(
                        grund_entry::ENTRY_ALPN,
                        crate::gate::entry::EntryProtocol(gate.clone()),
                    )
                    .spawn();
                std::future::pending::<()>().await;
            }
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "gate: could not bind the entry endpoint; trying again");
                tokio::time::sleep(retry).await;
                retry = (retry * 2).min(Duration::from_secs(60));
            }
        }
    }
}

fn remote_copies(
    list: Option<&grund_net::membership::MembershipList>,
    own_machine_id: &str,
) -> Vec<crate::gate::RemoteCopy> {
    let Some(list) = list else {
        return Vec::new();
    };
    list.members
        .iter()
        .filter(|member| member.machine_id != own_machine_id)
        .flat_map(|member| {
            member.apps.iter().map(|app| crate::gate::RemoteCopy {
                replica_id: app.replica_id.clone(),
                app: app.app.clone(),
                machine_id: member.machine_id.clone(),
                address: std::net::IpAddr::V6(app.address),
                ports: app
                    .ports
                    .iter()
                    .filter(|p| p.transport == grund_net::membership::Transport::Tcp)
                    .map(|p| p.port)
                    .collect(),
                ready: app.ready,
            })
        })
        .collect()
}

fn read_remote_copies(path: &Path) -> Vec<crate::gate::RemoteCopy> {
    #[derive(Deserialize)]
    struct Listed {
        replica_id: String,
        app: String,
        machine_id: String,
        address: std::net::IpAddr,
        ports: Vec<u16>,
    }
    let listed: Vec<Listed> = std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    listed
        .into_iter()
        .map(|l| crate::gate::RemoteCopy {
            replica_id: l.replica_id,
            app: l.app,
            machine_id: l.machine_id,
            address: l.address,
            ports: l.ports,
            ready: true,
        })
        .collect()
}

/// How long the agent waits, at stop, for its peers to hear that its
/// endpoints close.
pub const CLOSE_ENDPOINTS_WITHIN: Duration = Duration::from_secs(1);

async fn stop_at_shutdown<C: ContainerRuntime + 'static>(
    containers: std::sync::Arc<C>,
    gate: crate::gate::Gate,
    mesh: std::sync::Arc<std::sync::OnceLock<grund_net::mesh::Mesh>>,
    entry_endpoint: EntryEndpoint,
) {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut term) = signal(SignalKind::terminate()) else {
        return;
    };
    term.recv().await;
    let draining = std::time::Instant::now();
    gate.drain().await;
    tracing::info!(
        elapsed_ms = draining.elapsed().as_millis() as u64,
        "the gate drained"
    );
    let endpoints: Vec<iroh::Endpoint> = mesh
        .get()
        .and_then(|m| m.endpoint())
        .into_iter()
        .chain(entry_endpoint.lock().expect("entry endpoint lock").clone())
        .collect();
    let closing = std::time::Instant::now();
    let mut closes = tokio::task::JoinSet::new();
    for endpoint in endpoints.clone() {
        closes.spawn(async move { endpoint.close().await });
    }
    let _ = tokio::time::timeout(CLOSE_ENDPOINTS_WITHIN, closes.join_all()).await;
    tracing::info!(
        endpoints = endpoints.len(),
        elapsed_ms = closing.elapsed().as_millis() as u64,
        "closed the endpoints, so the edge and peers know at once"
    );
    let stopping = tokio::process::Command::new("systemctl")
        .arg("is-system-running")
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "stopping")
        .unwrap_or(false);
    if stopping {
        let started = std::time::Instant::now();
        match crate::apps::stop_all(containers).await {
            Ok(count) => tracing::info!(
                count,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "the system is stopping; stopped every replica"
            ),
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "could not stop replicas at shutdown")
            }
        }
    } else {
        tracing::info!("the agent is stopping; replicas keep running");
    }
    std::process::exit(0);
}

fn consider(
    record: &Record,
    trust: Option<&VerifyingKey>,
    data_dir: &Path,
    applied: &mut Applied,
    shared: &Shared,
    document: &SignedDesiredState,
) -> anyhow::Result<Option<String>> {
    match trust.ok_or(Refusal::NoTrustKey).and_then(|trust| {
        verify(
            record,
            trust,
            &document.key_id,
            &document.payload,
            &document.signature,
            applied,
        )
    }) {
        Ok(state) => {
            *applied = Applied {
                generation: state.generation,
                payload: hex::encode(&document.payload),
            };
            write_applied(data_dir, applied)?;
            tracing::info!(
                generation = state.generation,
                replicas = state.replicas.len(),
                "applied a new desired state"
            );
            *shared.desired.lock().expect("shared lock") = Some(state);
            shared.document.notify_one();
            Ok(None)
        }
        Err(Refusal::Same) => Ok(None),
        Err(Refusal::Equivocation) => {
            tracing::error!(
                generation = applied.generation,
                "the instance signed two different documents for one generation; keeping the one applied"
            );
            Ok(Some(Refusal::Equivocation.to_string()))
        }
        Err(refusal) => {
            tracing::warn!(%refusal, "refused a desired state; keeping the last good one");
            Ok(Some(refusal.to_string()))
        }
    }
}

struct Watcher {
    link: Link,
    record: Record,
    trust: Option<VerifyingKey>,
    applied: std::sync::Arc<tokio::sync::Mutex<Applied>>,
    shared: std::sync::Arc<Shared>,
    data_dir: PathBuf,
}

impl Watcher {
    async fn run(self) {
        loop {
            let since = self.applied.lock().await.generation;
            let answer: anyhow::Result<WatchDesiredStateResponse> = self
                .link
                .call(
                    "WatchDesiredState",
                    &WatchDesiredStateRequest {
                        since_generation: since,
                        ..Default::default()
                    },
                )
                .await;
            match answer {
                Ok(answer) => {
                    if let Some(document) = answer.document.as_option() {
                        let mut applied = self.applied.lock().await;
                        match consider(
                            &self.record,
                            self.trust.as_ref(),
                            &self.data_dir,
                            &mut applied,
                            &self.shared,
                            document,
                        ) {
                            Ok(Some(refusal)) => {
                                self.shared
                                    .document_refusals
                                    .lock()
                                    .expect("shared lock")
                                    .push(refusal);
                                self.shared.changed.notify_one();
                                drop(applied);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                tracing::warn!(error = %format!("{error:#}"), "could not keep a document");
                            }
                        }
                    }
                }
                Err(error) => {
                    let unimplemented = format!("{error:#}").contains("unimplemented");
                    tokio::time::sleep(Duration::from_secs(if unimplemented { 60 } else { 2 }))
                        .await;
                }
            }
        }
    }
}

struct Round<'a, R, C> {
    link: &'a Link,
    record: &'a Record,
    trust: Option<&'a VerifyingKey>,
    runtime: &'a R,
    containers: &'a C,
    policy: &'a Policy,
    data_dir: &'a Path,
    applied: &'a tokio::sync::Mutex<Applied>,
    shared: &'a Shared,
    gate: &'a crate::gate::Gate,
}

async fn round<R: VmRuntime, C: ContainerRuntime>(
    context: &Round<'_, R, C>,
) -> anyhow::Result<i32> {
    let Round {
        link,
        record,
        trust,
        runtime,
        containers,
        policy,
        data_dir,
        applied,
        shared,
        gate,
    } = context;
    let capabilities = runtime.capabilities().await;
    let apps = containers.capabilities().await;
    let apps_reason = if !policy.apps {
        "this machine's owner turned apps off".to_string()
    } else {
        apps.reason.clone()
    };
    let beat: HeartbeatResponse = link
        .call(
            "Heartbeat",
            &HeartbeatRequest {
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                capabilities: buffa::MessageField::from(Capabilities {
                    kvm: capabilities.kvm,
                    root: capabilities.root,
                    egress: capabilities.egress,
                    free_vcpus: capabilities.free_vcpus,
                    free_memory_mib: capabilities.free_memory_mib,
                    apps: apps.apps && policy.apps,
                    arch: apps.arch.clone(),
                    memory_mib: apps.memory_mib,
                    cpu_millis: apps.cpu_millis,
                    apps_unavailable_reason: apps_reason,
                    max_replica_memory_mib: policy.max_replica_memory_mib,
                    max_replica_cpu_millis: policy.max_replica_cpu_millis,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await?;
    let mut refusals: Vec<String> =
        std::mem::take(&mut *shared.document_refusals.lock().expect("shared lock"));
    let generation = applied.lock().await.generation;
    if beat.generation > generation {
        let answer: GetDesiredStateResponse = link
            .call(
                "GetDesiredState",
                &GetDesiredStateRequest {
                    since_generation: generation,
                    ..Default::default()
                },
            )
            .await?;
        if let Some(document) = answer.document.as_option() {
            let mut applied = applied.lock().await;
            if let Some(refusal) =
                consider(record, *trust, data_dir, &mut applied, shared, document)?
            {
                refusals.push(refusal);
            }
        }
    }
    let applied_generation = applied.lock().await.generation;
    let desired = current(&*applied.lock().await);
    let observed = converge(link, record, *runtime, desired.as_ref()).await?;
    refusals.extend(shared.refusals.lock().expect("shared lock").iter().cloned());
    let mut replicas = shared.reports.lock().expect("shared lock").clone();
    let idle = gate.idle(desired.as_ref());
    for replica in &mut replicas {
        replica.idle = idle.contains(&replica.replica_id);
    }
    let _: ReportStatusResponse = link
        .call(
            "ReportStatus",
            &ReportStatusRequest {
                applied_generation,
                machines: observed.iter().map(observed_message).collect(),
                refusals,
                replicas,
                reports_replicas: true,
                ..Default::default()
            },
        )
        .await?;
    Ok(beat.heartbeat_interval_seconds)
}

fn current(applied: &Applied) -> Option<DesiredState> {
    let payload = hex::decode(&applied.payload).ok()?;
    DesiredState::decode_from_slice(&payload).ok()
}

async fn converge<R: VmRuntime>(
    link: &Link,
    record: &Record,
    runtime: &R,
    desired: Option<&DesiredState>,
) -> anyhow::Result<Vec<VmStatus>> {
    let observed = runtime.observe().await?;
    let empty = Vec::new();
    let wanted = desired.map_or(&empty, |d| &d.machines);
    for vm in wanted {
        let current = observed.iter().find(|o| o.id == vm.vm_id);
        let running = matches!(
            current.map(|c| &c.state),
            Some(VmState::Running | VmState::Starting)
        );
        match vm.state.as_known() {
            Some(VmDesiredState::VM_DESIRED_STATE_RUNNING) if !running => {
                let token: Option<GetMachineJoinTokenResponse> = link
                    .call(
                        "GetMachineJoinToken",
                        &GetMachineJoinTokenRequest {
                            vm_id: vm.vm_id.clone(),
                            ..Default::default()
                        },
                    )
                    .await
                    .ok();
                let (token, expires_at) = token.map_or((String::new(), String::new()), |t| {
                    let expires = t
                        .expires_at
                        .as_option()
                        .map(|ts| ts.seconds.to_string())
                        .unwrap_or_default();
                    (t.token, expires)
                });
                let spec = spec(
                    vm,
                    vm::metadata(&vm.vm_id, &record.instance_url, &token, &expires_at),
                );
                match runtime.ensure(&spec).await {
                    Ok(status) => {
                        tracing::info!(vm = %vm.vm_id, state = ?status.state, "ensured a VM")
                    }
                    Err(error) => {
                        tracing::warn!(vm = %vm.vm_id, error = %format!("{error:#}"), "could not start a VM")
                    }
                }
            }
            Some(VmDesiredState::VM_DESIRED_STATE_STOPPED) if running => {
                runtime.stop(&vm.vm_id).await?;
            }
            _ => {}
        }
    }
    for status in &observed {
        let still_wanted = wanted.iter().any(|vm| vm.vm_id == status.id);
        if !still_wanted && matches!(status.state, VmState::Running | VmState::Starting) {
            runtime.stop(&status.id).await?;
        }
    }
    Ok(reported(runtime.observe().await?, wanted))
}

fn reported(
    mut observed: Vec<VmStatus>,
    wanted: &[grund_proto::grund::agent::v1::Vm],
) -> Vec<VmStatus> {
    for vm in wanted {
        let stopped = vm.state.as_known() == Some(VmDesiredState::VM_DESIRED_STATE_STOPPED);
        if stopped && !observed.iter().any(|o| o.id == vm.vm_id) {
            observed.push(VmStatus {
                id: vm.vm_id.clone(),
                state: VmState::Stopped,
            });
        }
    }
    observed
}

fn spec(vm: &grund_proto::grund::agent::v1::Vm, mmds: serde_json::Value) -> VmSpec {
    let artifact = |a: Option<&grund_proto::grund::agent::v1::Artifact>| Artifact {
        url: a.map(|a| a.url.clone()).unwrap_or_default(),
        sha256: a.map(|a| a.sha256.clone()).unwrap_or_default(),
    };
    let image = vm.image.as_option();
    VmSpec {
        id: vm.vm_id.clone(),
        vcpus: vm.vcpus,
        memory_mib: vm.memory_mib,
        disk_gib: vm.disk_gib,
        image: VmImage {
            kernel: artifact(image.and_then(|i| i.kernel.as_option())),
            rootfs: artifact(image.and_then(|i| i.rootfs.as_option())),
        },
        mmds,
    }
}

fn observed_message(status: &VmStatus) -> VmObserved {
    let (state, reason, exit_code) = match &status.state {
        VmState::Starting => (
            VmObservedState::VM_OBSERVED_STATE_STARTING,
            String::new(),
            0,
        ),
        VmState::Running => (VmObservedState::VM_OBSERVED_STATE_RUNNING, String::new(), 0),
        VmState::Stopped => (VmObservedState::VM_OBSERVED_STATE_STOPPED, String::new(), 0),
        VmState::Exited { code } => (
            VmObservedState::VM_OBSERVED_STATE_EXITED,
            String::new(),
            code.unwrap_or(0),
        ),
        VmState::Failed { reason } => {
            (VmObservedState::VM_OBSERVED_STATE_FAILED, reason.clone(), 0)
        }
    };
    VmObserved {
        vm_id: status.id.clone(),
        state: state.into(),
        reason,
        exit_code,
        ..Default::default()
    }
}

fn trust_key(record: &Record) -> Option<VerifyingKey> {
    if record.trust_key.purpose != "organisation" {
        return None;
    }
    let bytes: [u8; 32] = hex::decode(&record.trust_key.public_key)
        .ok()?
        .try_into()
        .ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn read_applied(data_dir: &Path) -> anyhow::Result<Applied> {
    match std::fs::read_to_string(data_dir.join(APPLIED_FILE)) {
        Ok(text) => Ok(serde_json::from_str(&text).unwrap_or_default()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Applied::default()),
        Err(error) => Err(error).context("read the applied desired state"),
    }
}

fn write_applied(data_dir: &Path, applied: &Applied) -> anyhow::Result<()> {
    let temporary = data_dir.join(format!(".{APPLIED_FILE}.{}", std::process::id()));
    std::fs::write(&temporary, serde_json::to_vec(applied)?)?;
    std::fs::rename(&temporary, data_dir.join(APPLIED_FILE))
        .context("write the applied desired state")
}

#[cfg(test)]
mod tests {
    use grund_proto::grund::agent::v1::Vm;

    use super::*;
    use crate::join::PinnedKey;

    fn record(key: &SigningKey) -> Record {
        Record {
            machine_id: "m-1".into(),
            name: "box".into(),
            pool: "organisation".into(),
            organisation_id: "o-1".into(),
            instance_url: "https://grund.example.com".into(),
            instance_key: PinnedKey {
                key_id: "i".into(),
                public_key: hex::encode([0u8; 32]),
                purpose: "instance".into(),
            },
            trust_key: PinnedKey {
                key_id: "k".into(),
                public_key: hex::encode(key.verifying_key().to_bytes()),
                purpose: "organisation".into(),
            },
            heartbeat_interval_seconds: 5,
            registered_at_unix: 0,
            network: None,
        }
    }

    fn signed(key: &SigningKey, state: &DesiredState) -> (Vec<u8>, Vec<u8>) {
        let payload = state.encode_to_vec();
        let mut message = b"grund-desired-state-v1\n".to_vec();
        message.extend_from_slice(&payload);
        (payload, key.sign(&message).to_bytes().to_vec())
    }

    fn state(generation: u64) -> DesiredState {
        DesiredState {
            machine_id: "m-1".into(),
            organisation_id: "o-1".into(),
            generation,
            required_features: vec!["machines".into()],
            machines: vec![Vm {
                vm_id: "vm-1".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn applied(generation: u64, payload: &[u8]) -> Applied {
        Applied {
            generation,
            payload: hex::encode(payload),
        }
    }

    #[test]
    fn a_document_applies_only_when_signed_for_this_machine_newer_and_understood() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let record = record(&key);
        let trust = key.verifying_key();
        let none = Applied::default();
        let (payload, signature) = signed(&key, &state(2));
        assert_eq!(
            verify(&record, &trust, "k", &payload, &signature, &none)
                .unwrap()
                .generation,
            2
        );
        assert_eq!(
            verify(&record, &trust, "other", &payload, &signature, &none),
            Err(Refusal::UnknownKey)
        );

        let stranger = SigningKey::from_bytes(&[6; 32]);
        let (bad, bad_signature) = signed(&stranger, &state(3));
        assert_eq!(
            verify(&record, &trust, "k", &bad, &bad_signature, &none),
            Err(Refusal::BadSignature)
        );

        let mut other = state(3);
        other.machine_id = "m-2".into();
        let (bad, bad_signature) = signed(&key, &other);
        assert_eq!(
            verify(&record, &trust, "k", &bad, &bad_signature, &none),
            Err(Refusal::WrongMachine)
        );

        let mut newer = state(3);
        newer.required_features.push("volumes".into());
        let (bad, bad_signature) = signed(&key, &newer);
        assert_eq!(
            verify(&record, &trust, "k", &bad, &bad_signature, &none),
            Err(Refusal::UnknownFeature("volumes".into()))
        );

        let (mut bad, bad_signature) = signed(&key, &state(3));
        bad[0] ^= 1;
        assert_eq!(
            verify(&record, &trust, "k", &bad, &bad_signature, &none),
            Err(Refusal::BadSignature)
        );
    }

    #[test]
    fn the_same_generation_again_is_nothing_or_an_equivocation_and_only_a_lower_one_is_older() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let record = record(&key);
        let trust = key.verifying_key();
        let (payload, signature) = signed(&key, &state(2));
        let kept = applied(2, &payload);
        assert_eq!(
            verify(&record, &trust, "k", &payload, &signature, &kept),
            Err(Refusal::Same)
        );

        let mut twin = state(2);
        twin.machines.clear();
        let (other, other_signature) = signed(&key, &twin);
        assert_eq!(
            verify(&record, &trust, "k", &other, &other_signature, &kept),
            Err(Refusal::Equivocation)
        );

        let (older, older_signature) = signed(&key, &state(1));
        assert_eq!(
            verify(&record, &trust, "k", &older, &older_signature, &kept),
            Err(Refusal::Older)
        );
    }

    #[test]
    fn a_vm_told_to_stop_that_the_runtime_freed_is_reported_stopped() {
        let wanted = |id: &str, state: VmDesiredState| Vm {
            vm_id: id.into(),
            state: state.into(),
            ..Default::default()
        };
        let running = VmStatus {
            id: "kept".into(),
            state: VmState::Running,
        };
        let report = reported(
            vec![running.clone()],
            &[
                wanted("kept", VmDesiredState::VM_DESIRED_STATE_RUNNING),
                wanted("freed", VmDesiredState::VM_DESIRED_STATE_STOPPED),
                wanted("starting", VmDesiredState::VM_DESIRED_STATE_RUNNING),
            ],
        );
        assert_eq!(
            report,
            vec![
                running,
                VmStatus {
                    id: "freed".into(),
                    state: VmState::Stopped,
                },
            ]
        );
    }
}
