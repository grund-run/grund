use std::{
    collections::{BTreeMap, HashMap},
    fs::{File, OpenOptions},
    io::Write,
    net::Ipv6Addr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use buffa_types::google::protobuf::Timestamp;

use grund_proto::grund::{
    agent::v1::{
        DesiredRun, GetPullCredentialRequest, GetPullCredentialResponse, GetRunInputRequest,
        GetRunInputResponse, RunObserved,
    },
    run::v1::RunState,
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::{
    agent::Link,
    apps::{NetworkAccess, Shared},
    policy::Policy,
    runtime::{APP_ID_LABEL, ContainerRuntime, ContainerSpec, ImageRef, RUN_LABEL, TaskState},
    secrets,
};

#[derive(Debug, thiserror::Error)]
#[error("run private network unavailable")]
struct NetworkUnavailable;

enum Network {
    Private(NetworkAccess),
    #[cfg(test)]
    Isolated,
}

const POLL: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Outcome {
    Claimed,
    Running,
    Unknown,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    NotStarted,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Receipt {
    run_id: String,
    attempt_id: String,
    deadline_ms: i64,
    outcome: Outcome,
    started_ms: Option<i64>,
    finished_ms: Option<i64>,
    exit_code: Option<i32>,
    stop_confirmed: bool,
    reason: String,
    stop: Option<Stop>,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Stop {
    Cancel,
    Deadline,
}

impl Receipt {
    fn new(run: &DesiredRun) -> anyhow::Result<Self> {
        anyhow::ensure!(
            uuid::Uuid::parse_str(&run.run_id).is_ok(),
            "invalid run identity"
        );
        anyhow::ensure!(
            uuid::Uuid::parse_str(&run.attempt_id).is_ok(),
            "invalid attempt identity"
        );
        let deadline = run
            .deadline
            .as_option()
            .ok_or_else(|| anyhow::anyhow!("missing deadline"))?;
        anyhow::ensure!(
            (0..1_000_000_000).contains(&deadline.nanos),
            "invalid deadline"
        );
        let deadline_ms = deadline
            .seconds
            .checked_mul(1000)
            .and_then(|v| v.checked_add(i64::from(deadline.nanos / 1_000_000)))
            .ok_or_else(|| anyhow::anyhow!("invalid deadline"))?;
        Ok(Self {
            run_id: run.run_id.clone(),
            attempt_id: run.attempt_id.clone(),
            deadline_ms,
            outcome: Outcome::Claimed,
            started_ms: None,
            finished_ms: None,
            exit_code: None,
            stop_confirmed: false,
            reason: String::new(),
            stop: None,
        })
    }

    fn terminal(&self) -> bool {
        matches!(
            self.outcome,
            Outcome::Succeeded
                | Outcome::Failed
                | Outcome::Cancelled
                | Outcome::TimedOut
                | Outcome::NotStarted
        )
    }

    fn observe_exit(&mut self, code: i32, finished_ms: i64) {
        if self.terminal() {
            return;
        }
        self.exit_code = Some(code);
        self.finished_ms = Some(if finished_ms > 0 {
            finished_ms
        } else {
            now_ms()
        });
        self.stop_confirmed = true;
        self.outcome = match self.stop {
            Some(Stop::Cancel) => Outcome::Cancelled,
            Some(Stop::Deadline) => Outcome::TimedOut,
            None if code == 0 => Outcome::Succeeded,
            None => Outcome::Failed,
        };
        self.reason.clear();
    }

    fn observe_stop(&mut self, stopped: crate::runtime::RunStop, stop: Stop) {
        if !stopped.signalled {
            self.stop = None;
        }
        match stopped.state {
            Some(TaskState::Exited {
                code,
                exited_at_unix_ms,
            }) => self.observe_exit(code, exited_at_unix_ms),
            None | Some(TaskState::Created) => {
                self.outcome = match stop {
                    Stop::Cancel => Outcome::Cancelled,
                    Stop::Deadline => Outcome::TimedOut,
                };
                self.finished_ms = Some(now_ms());
                self.stop_confirmed = true;
                self.reason = "exit_status_unavailable".into();
            }
            _ => {
                self.stop_confirmed = false;
            }
        }
    }

    fn report(&self) -> RunObserved {
        let state = match self.outcome {
            Outcome::Claimed => RunState::RUN_STATE_PENDING,
            Outcome::Running if self.stop.is_some() => RunState::RUN_STATE_CANCELLING,
            Outcome::Running => RunState::RUN_STATE_RUNNING,
            Outcome::Unknown => RunState::RUN_STATE_UNKNOWN,
            Outcome::Succeeded => RunState::RUN_STATE_SUCCEEDED,
            Outcome::Failed => RunState::RUN_STATE_FAILED,
            Outcome::Cancelled => RunState::RUN_STATE_CANCELLED,
            Outcome::TimedOut => RunState::RUN_STATE_TIMED_OUT,
            Outcome::NotStarted => RunState::RUN_STATE_NOT_STARTED,
        };
        RunObserved {
            run_id: self.run_id.clone(),
            attempt_id: self.attempt_id.clone(),
            state: state.into(),
            exit_code: self.exit_code,
            signal: None,
            reason: self.reason.clone(),
            started_at: self
                .started_ms
                .map(|ms| timestamp(ms).into())
                .unwrap_or_default(),
            finished_at: self
                .finished_ms
                .map(|ms| timestamp(ms).into())
                .unwrap_or_default(),
            stop_confirmed: self.stop_confirmed,
            ..Default::default()
        }
    }
}

fn timestamp(ms: i64) -> Timestamp {
    Timestamp {
        seconds: ms.div_euclid(1000),
        nanos: (ms.rem_euclid(1000) * 1_000_000) as i32,
        ..Default::default()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

struct Store(PathBuf);

impl Store {
    fn open(data: &Path, id: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(uuid::Uuid::parse_str(id).is_ok(), "invalid run identity");
        let root = data.join("runs");
        let directory = root.join(id);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)?;
        File::open(data)?.sync_all()?;
        File::open(&root)?.sync_all()?;
        Ok(Self(directory))
    }

    fn load(&self) -> anyhow::Result<Option<Receipt>> {
        let claim = match std::fs::read(self.0.join("claim.json")) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        match std::fs::read(self.0.join("receipt.json")) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(Some(serde_json::from_slice(&claim)?))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn claim(&self, receipt: &Receipt) -> anyhow::Result<bool> {
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.0.join("claim.json"))
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        file.write_all(&serde_json::to_vec(receipt)?)?;
        file.sync_all()?;
        File::open(&self.0)?.sync_all()?;
        Ok(true)
    }

    fn save(&self, receipt: &Receipt) -> anyhow::Result<()> {
        let temporary = self.0.join(".receipt.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(receipt)?)?;
        file.sync_all()?;
        std::fs::rename(temporary, self.0.join("receipt.json"))?;
        File::open(&self.0)?.sync_all()?;
        Ok(())
    }

    fn forget_secrets(&self) -> anyhow::Result<()> {
        match std::fs::remove_file(self.0.join(secrets::CACHE_FILE)) {
            Ok(()) => File::open(&self.0)?.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

trait Inputs: Clone + Send + Sync + 'static {
    fn input(
        &self,
        run: &DesiredRun,
    ) -> impl Future<Output = anyhow::Result<GetRunInputResponse>> + Send;
    fn credential(
        &self,
        id: &str,
    ) -> impl Future<Output = anyhow::Result<GetPullCredentialResponse>> + Send;
}

impl Inputs for Link {
    async fn input(&self, run: &DesiredRun) -> anyhow::Result<GetRunInputResponse> {
        self.call(
            "GetRunInput",
            &GetRunInputRequest {
                run_id: run.run_id.clone(),
                attempt_id: run.attempt_id.clone(),
                ..Default::default()
            },
        )
        .await
    }

    async fn credential(&self, id: &str) -> anyhow::Result<GetPullCredentialResponse> {
        self.call(
            "GetPullCredential",
            &GetPullCredentialRequest {
                replica_id: id.into(),
                ..Default::default()
            },
        )
        .await
    }
}

pub(crate) async fn run<C: ContainerRuntime + 'static>(
    runtime: Arc<C>,
    link: Link,
    shared: Arc<Shared>,
    policy: Policy,
    data: PathBuf,
    seed: [u8; 32],
    network: NetworkAccess,
) {
    if !runtime.supports_runs() {
        return;
    }
    let mut workers: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    loop {
        let document = shared.desired.lock().expect("shared lock").clone();
        if let Some(document) = document {
            crate::telemetry_final::remember(&shared, Some(&document));
            for desired in document.runs {
                if workers
                    .get(&desired.run_id)
                    .is_some_and(|worker| !worker.is_finished())
                {
                    continue;
                }
                let worker = Worker {
                    runtime: runtime.clone(),
                    inputs: link.clone(),
                    shared: shared.clone(),
                    policy: policy.clone(),
                    data: data.clone(),
                    seed,
                    network: Network::Private(network.clone()),
                    attached: None,
                };
                workers.insert(desired.run_id.clone(), tokio::spawn(worker.run(desired)));
            }
            if runtime.prepare().await.is_ok()
                && let Ok(containers) = runtime.list_runs().await
            {
                for container in containers {
                    if workers
                        .get(&container.id)
                        .is_some_and(|worker| !worker.is_finished())
                    {
                        continue;
                    }
                    let worker = Worker {
                        runtime: runtime.clone(),
                        inputs: link.clone(),
                        shared: shared.clone(),
                        policy: policy.clone(),
                        data: data.clone(),
                        seed,
                        network: Network::Private(network.clone()),
                        attached: None,
                    };
                    let stored = Store::open(&data, &container.id).and_then(|store| store.load());
                    let receipt = match stored {
                        Ok(Some(receipt)) => receipt,
                        _ => {
                            let recovery = DesiredRun {
                                run_id: container.id.clone(),
                                attempt_id: container.spec_hash.clone(),
                                deadline: timestamp(now_ms() + 3_600_000).into(),
                                cancel: true,
                                ..Default::default()
                            };
                            let recovered = (|| -> anyhow::Result<Receipt> {
                                let mut receipt = Receipt::new(&recovery)?;
                                receipt.outcome = Outcome::Unknown;
                                receipt.reason = "run_receipt_unavailable".into();
                                let store = Store::open(&data, &container.id)?;
                                let _ = store.claim(&receipt)?;
                                store.save(&receipt)?;
                                Ok(receipt)
                            })();
                            let Ok(receipt) = recovered else {
                                let _ = runtime.stop_run(&container.id).await;
                                continue;
                            };
                            receipt
                        }
                    };
                    let mut desired = DesiredRun {
                        run_id: receipt.run_id.clone(),
                        attempt_id: receipt.attempt_id.clone(),
                        cancel: true,
                        ..Default::default()
                    };
                    desired.deadline = timestamp(receipt.deadline_ms).into();
                    workers.insert(container.id, tokio::spawn(worker.run(desired)));
                }
            }
        }
        workers.retain(|_, worker| !worker.is_finished());
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

struct Worker<C, I> {
    runtime: Arc<C>,
    inputs: I,
    shared: Arc<Shared>,
    policy: Policy,
    data: PathBuf,
    seed: [u8; 32],
    network: Network,
    attached: Option<(grund_net::mesh::Mesh, Ipv6Addr)>,
}

impl<C: ContainerRuntime + 'static, I: Inputs> Worker<C, I> {
    fn intent(&self, receipt: &Receipt) -> Option<Stop> {
        if now_ms() >= receipt.deadline_ms {
            return Some(Stop::Deadline);
        }
        let document = self.shared.desired.lock().expect("shared lock");
        match document.as_ref().and_then(|document| {
            document
                .runs
                .iter()
                .find(|run| run.run_id == receipt.run_id)
        }) {
            Some(run) if run.attempt_id == receipt.attempt_id && !run.cancel => None,
            _ => Some(Stop::Cancel),
        }
    }

    fn publish(&self, receipt: &Receipt) {
        let report = receipt.report();
        let mut reports = self.shared.run_reports.lock().expect("shared lock");
        if let Some(existing) = reports
            .iter_mut()
            .find(|report| report.run_id == receipt.run_id)
        {
            if *existing == report {
                return;
            }
            *existing = report;
        } else {
            reports.push(report);
        }
        self.shared.changed.notify_one();
    }

    async fn run(mut self, run: DesiredRun) {
        let Ok(store) = Store::open(&self.data, &run.run_id) else {
            return;
        };
        let Ok(mut receipt) = Receipt::new(&run) else {
            return;
        };
        self.shared
            .run_telemetry
            .lock()
            .expect("shared lock")
            .insert(run.run_id.clone());
        let values = secrets::load(&store.0, &secrets::key(&self.seed));
        if let Some(values) = values.get(&run.run_id) {
            self.shared
                .telemetry_secrets
                .lock()
                .insert(run.run_id.clone(), Arc::new(values.clone()));
        }
        loop {
            if let Err(error) = self.step(&run, &store, &mut receipt).await {
                if !receipt.terminal() {
                    if error.is::<NetworkUnavailable>() {
                        receipt.reason = "run_network_unavailable".into();
                    } else {
                        receipt.outcome = if store.0.join("claim.json").exists() {
                            Outcome::Unknown
                        } else {
                            Outcome::Claimed
                        };
                        receipt.reason = "run_observation_unavailable".into();
                    }
                    receipt.stop_confirmed = false;
                }
                self.publish(&receipt);
            }
            let wanted = self
                .shared
                .desired
                .lock()
                .expect("shared lock")
                .as_ref()
                .is_some_and(|document| {
                    document
                        .runs
                        .iter()
                        .any(|wanted| wanted.run_id == run.run_id)
                });
            if !wanted && receipt.stop_confirmed {
                self.shared
                    .run_telemetry
                    .lock()
                    .expect("shared lock")
                    .remove(&run.run_id);
                self.shared
                    .run_reports
                    .lock()
                    .expect("shared lock")
                    .retain(|report| report.run_id != run.run_id);
                if let Some((mesh, address)) = self.attached.take() {
                    mesh.detach_replica(address);
                }
                break;
            }
            tokio::time::sleep(POLL).await;
        }
    }

    async fn step(
        &mut self,
        run: &DesiredRun,
        store: &Store,
        receipt: &mut Receipt,
    ) -> anyhow::Result<()> {
        self.runtime.prepare().await?;
        let existing = self
            .runtime
            .list_runs()
            .await?
            .into_iter()
            .find(|container| container.id == run.run_id);
        let stored = store.load().unwrap_or_else(|_| {
            let mut uncertain = receipt.clone();
            uncertain.outcome = Outcome::Unknown;
            uncertain.reason = "run_receipt_unavailable".into();
            Some(uncertain)
        });
        let claimed = stored.is_some();
        if let Some(stored) = stored.as_ref() {
            anyhow::ensure!(
                stored.attempt_id == run.attempt_id && stored.deadline_ms == receipt.deadline_ms,
                "run attempt changed"
            );
            *receipt = stored.clone();
        }
        if receipt.terminal() {
            if existing.is_some()
                || self.attached.is_some()
                || store.0.join(secrets::CACHE_FILE).exists()
            {
                anyhow::ensure!(
                    self.runtime.remove_stopped(&run.run_id).await?,
                    "run cleanup unconfirmed"
                );
            }
            if let Some((mesh, address)) = self.attached.take() {
                mesh.detach_replica(address);
            }
            store.forget_secrets()?;
            self.publish(receipt);
            return Ok(());
        }
        match existing.as_ref().map(|container| &container.state) {
            Some(TaskState::Exited {
                code,
                exited_at_unix_ms,
            }) => {
                receipt.observe_exit(*code, *exited_at_unix_ms);
            }
            Some(TaskState::Running { .. }) => {
                receipt.outcome = Outcome::Running;
                receipt.reason.clear();
                if receipt.started_ms.is_none() {
                    receipt.started_ms = self
                        .runtime
                        .run_started_at(&run.run_id)
                        .await
                        .ok()
                        .flatten();
                }
                if let Some(stop) = receipt.stop.or_else(|| self.intent(receipt)) {
                    receipt.stop = Some(stop);
                    store.save(receipt)?;
                    self.publish(receipt);
                    let stopped = self.runtime.stop_run(&run.run_id).await?;
                    receipt.observe_stop(stopped, stop);
                } else {
                    self.attach(run).await?;
                }
            }
            Some(TaskState::Unknown) => {
                receipt.outcome = Outcome::Unknown;
                receipt.stop_confirmed = false;
                receipt.reason = "run_task_unobservable".into();
                if let Some(stop) = receipt.stop.or_else(|| self.intent(receipt)) {
                    receipt.stop = Some(stop);
                    store.save(receipt)?;
                    let stopped = self.runtime.stop_run(&run.run_id).await?;
                    receipt.observe_stop(stopped, stop);
                }
            }
            Some(TaskState::Created) | None if claimed => {
                receipt.outcome = Outcome::Unknown;
                receipt.stop_confirmed = true;
                receipt.reason = "run_start_or_exit_uncertain".into();
            }
            _ => {
                if let Some(stop) = self.intent(receipt) {
                    receipt.stop = Some(stop);
                    receipt.outcome = match stop {
                        Stop::Cancel => Outcome::Cancelled,
                        Stop::Deadline => Outcome::NotStarted,
                    };
                    receipt.stop_confirmed = true;
                    receipt.finished_ms = Some(now_ms());
                    receipt.reason = match stop {
                        Stop::Cancel => "run_cancelled_before_start",
                        Stop::Deadline => "run_deadline_before_start",
                    }
                    .into();
                    if !store.claim(receipt)? {
                        return Ok(());
                    }
                } else {
                    let shared = self.shared.clone();
                    let waiting = receipt.clone();
                    let prepared = tokio::select! {
                        prepared = self.prepare(run, store) => Some(prepared),
                        _ = wait_stop(shared, waiting) => None,
                    };
                    let Some(spec) = prepared else {
                        return Ok(());
                    };
                    let spec = spec?;
                    if self.intent(receipt).is_some() {
                        return Ok(());
                    }
                    if !store.claim(receipt)? {
                        return Ok(());
                    }
                    let cancel = CancellationToken::new();
                    let start = self.runtime.create_run(&spec, &cancel);
                    tokio::pin!(start);
                    let started = tokio::select! {
                        result = &mut start => result.is_ok(),
                        stop = wait_stop(self.shared.clone(), receipt.clone()) => {
                            receipt.stop = Some(stop);
                            store.save(receipt)?;
                            cancel.cancel();
                            let mut signalled = false;
                            loop {
                                tokio::select! {
                                    result = &mut start => break result.is_ok(),
                                    _ = tokio::time::sleep(POLL) => {
                                        if let Ok(stopped) = self.runtime.stop_run(&run.run_id).await {
                                            signalled |= stopped.signalled;
                                            if !signalled && matches!(stopped.state, Some(TaskState::Exited { .. })) {
                                                receipt.stop = None;
                                                store.save(receipt)?;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    };
                    if started {
                        receipt.outcome = Outcome::Running;
                        receipt.started_ms = self
                            .runtime
                            .run_started_at(&run.run_id)
                            .await
                            .ok()
                            .flatten();
                    } else {
                        receipt.outcome = Outcome::Unknown;
                        receipt.reason = "run_start_uncertain".into();
                    }
                }
            }
        }
        if !claimed {
            let _ = store.claim(receipt)?;
        }
        if stored.as_ref() != Some(receipt) {
            store.save(receipt)?;
        }
        if receipt.stop_confirmed
            && (existing.is_some()
                || self.attached.is_some()
                || store.0.join(secrets::CACHE_FILE).exists())
        {
            anyhow::ensure!(
                self.runtime.remove_stopped(&run.run_id).await?,
                "run cleanup unconfirmed"
            );
        }
        if receipt.stop_confirmed {
            if let Some((mesh, address)) = self.attached.take() {
                mesh.detach_replica(address);
            }
            store.forget_secrets()?;
        }
        self.publish(receipt);
        Ok(())
    }

    async fn attach(&mut self, run: &DesiredRun) -> anyhow::Result<Option<String>> {
        let access = match &self.network {
            Network::Private(access) => access,
            #[cfg(test)]
            Network::Isolated => return Ok(None),
        };
        let mesh = access
            .mesh
            .get()
            .filter(|mesh| mesh.ifindex().is_some())
            .cloned()
            .ok_or(NetworkUnavailable)?;
        let settings = {
            let list = access.lists.borrow();
            let list = list.as_ref().ok_or(NetworkUnavailable)?;
            let own = list
                .members
                .iter()
                .find(|member| member.endpoint_id == access.own && member.slot != 0)
                .ok_or(NetworkUnavailable)?;
            (
                grund_net::membership::replica_address(list.prefix, own.slot, &run.run_id),
                grund_net::dns::resolver_address(list, own.slot),
            )
        };
        if self.attached.is_none() {
            let path = self
                .runtime
                .network_namespace(&run.run_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("run network unsupported"))?;
            let address = settings.0;
            let tun = tokio::task::spawn_blocking(move || {
                grund_net::tun::Tun::create_in(&path, crate::apps::REPLICA_TUN, address, 48)
            })
            .await??;
            mesh.attach_replica(address, tun, |tun| {
                Box::new(grund_net::egress::Userspace::start(tun))
            });
            self.attached = Some((mesh, address));
        }
        let suffix = run
            .replica
            .as_option()
            .map(|replica| replica.stack_search.as_str())
            .unwrap_or_default();
        Ok(Some(if suffix.is_empty() {
            format!("nameserver {}\n", settings.1)
        } else {
            format!("nameserver {}\nsearch {suffix}\n", settings.1)
        }))
    }

    async fn prepare(&mut self, run: &DesiredRun, store: &Store) -> anyhow::Result<ContainerSpec> {
        let replica = run
            .replica
            .as_option()
            .ok_or_else(|| anyhow::anyhow!("missing run snapshot"))?;
        anyhow::ensure!(
            replica.replica_id == run.run_id
                && replica.volumes.is_empty()
                && replica.ports.is_empty()
                && replica.hostnames.is_empty()
                && replica.check.as_option().is_none()
                && replica.entrypoint.as_option().is_none()
                && replica.command.is_empty(),
            "invalid run snapshot"
        );
        anyhow::ensure!(
            self.policy.refuses(replica).is_none(),
            "run rejected by machine policy"
        );
        anyhow::ensure!(
            replica.stack_search.is_empty()
                || replica
                    .stack_search
                    .strip_suffix(".grund.internal")
                    .is_some_and(|name| grund_config::app::spec::AppName::parse(name).is_ok()),
            "invalid run DNS suffix"
        );
        let image = replica
            .image
            .as_option()
            .ok_or_else(|| anyhow::anyhow!("missing run image"))?;
        let reference = grund_config::app::spec::ImageReference::parse(&image.reference)?;
        let image = ImageRef {
            reference: reference.pinned(&image.digest),
            digest: image.digest.clone(),
        };
        if !self.runtime.has_image(&image).await? {
            let credential = self
                .inputs
                .credential(&run.run_id)
                .await?
                .credential
                .into_option();
            let authorization = if let Some(credential) = credential {
                crate::registry_login::authorization(
                    &reqwest::Client::new(),
                    &crate::registry_login::Credential {
                        host: credential.host,
                        username: credential.username,
                        password: credential.password,
                    },
                    &image.reference,
                    &image.digest,
                )
                .await?
            } else {
                None
            };
            self.runtime.pull(&image, authorization.as_deref()).await?;
        }
        let input = self.inputs.input(run).await?;
        anyhow::ensure!(
            input.args.len() <= 128
                && input.args.iter().map(String::len).sum::<usize>() <= 32768
                && input.args.iter().all(|arg| !arg.contains('\0')),
            "invalid run input"
        );
        anyhow::ensure!(
            input.env.iter().all(|env| !env.name.is_empty()
                && !env.name.contains(['=', '\0'])
                && !env.value.contains('\0')),
            "invalid run environment"
        );
        let mut values = Vec::new();
        for mapping in &replica.secret_env {
            let secret = replica
                .secrets
                .iter()
                .find(|secret| secret.name == mapping.secret)
                .ok_or_else(|| anyhow::anyhow!("missing run secret reference"))?;
            let value = input
                .env
                .iter()
                .rev()
                .find(|env| env.name == mapping.env)
                .ok_or_else(|| anyhow::anyhow!("missing run secret input"))?;
            values.push(secrets::Cached {
                name: secret.name.clone(),
                version: secret.version,
                value: value.value.as_bytes().to_vec(),
            });
        }
        secrets::store(
            &store.0,
            &secrets::key(&self.seed),
            &BTreeMap::from([(run.run_id.clone(), values.clone())]),
        )?;
        self.shared
            .telemetry_secrets
            .lock()
            .insert(run.run_id.clone(), Arc::new(values));
        let resolv_conf = self.attach(run).await?;
        Ok(ContainerSpec {
            id: run.run_id.clone(),
            image,
            command: Vec::new(),
            env: input
                .env
                .into_iter()
                .map(|env| (env.name, env.value))
                .collect(),
            memory_mib: replica.memory_mib,
            cpu_millis: replica.cpu_millis,
            stop_signal: "SIGTERM".into(),
            stop_grace: Duration::from_secs(10),
            labels: BTreeMap::from([
                (RUN_LABEL.into(), run.run_id.clone()),
                (APP_ID_LABEL.into(), replica.app_id.clone()),
            ]),
            spec_hash: run.attempt_id.clone(),
            resolv_conf,
            volumes: Vec::new(),
            volume_roots: Vec::new(),
            entrypoint: None,
            cmd: Some(input.args),
            working_dir: replica.working_dir.clone(),
            user: replica.user.clone(),
        })
    }
}

async fn wait_stop(shared: Arc<Shared>, receipt: Receipt) -> Stop {
    loop {
        if now_ms() >= receipt.deadline_ms {
            return Stop::Deadline;
        }
        let cancel = shared
            .desired
            .lock()
            .expect("shared lock")
            .as_ref()
            .and_then(|document| {
                document
                    .runs
                    .iter()
                    .find(|run| run.run_id == receipt.run_id)
            })
            .is_none_or(|run| run.attempt_id != receipt.attempt_id || run.cancel);
        if cancel {
            return Stop::Cancel;
        }
        tokio::time::sleep(POLL.min(Duration::from_millis(
            (receipt.deadline_ms - now_ms()).max(0) as u64,
        )))
        .await;
    }
}

#[cfg(test)]
#[path = "runs_tests.rs"]
mod tests;
