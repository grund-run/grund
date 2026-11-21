use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use grund_proto::grund::agent::v1::{DesiredState, EnvVar, Image, Replica, SecretEnv, SecretRef};
use parking_lot::Mutex;

use super::*;
use crate::runtime::{AppsCapabilities, ContainerStatus, Probe, RunStop};

#[derive(Default)]
struct Runtime {
    containers: Mutex<BTreeMap<String, ContainerStatus>>,
    starts: AtomicUsize,
    stops: AtomicUsize,
    lost_start_ack: AtomicBool,
    inspection_failed: AtomicBool,
    stop_failed: AtomicBool,
    exit_before_signal: AtomicBool,
    last_spec: Mutex<Option<ContainerSpec>>,
    suspend_start: AtomicBool,
    start_pending: tokio::sync::Notify,
    stop_applied: tokio::sync::Notify,
}

impl ContainerRuntime for Runtime {
    async fn capabilities(&self) -> AppsCapabilities {
        AppsCapabilities {
            apps: true,
            ..Default::default()
        }
    }
    fn supports_runs(&self) -> bool {
        true
    }
    async fn prepare(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn has_image(&self, _: &ImageRef) -> anyhow::Result<bool> {
        Ok(true)
    }
    async fn pull(&self, _: &ImageRef, _: Option<&str>) -> anyhow::Result<()> {
        Ok(())
    }
    async fn create(&self, _: &ContainerSpec) -> anyhow::Result<()> {
        anyhow::bail!("service create called for run")
    }
    async fn create_run(
        &self,
        spec: &ContainerSpec,
        cancel: &CancellationToken,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!cancel.is_cancelled(), "start revoked");
        self.starts.fetch_add(1, Ordering::Relaxed);
        self.containers.lock().insert(
            spec.id.clone(),
            ContainerStatus {
                id: spec.id.clone(),
                app_id: spec.labels[APP_ID_LABEL].clone(),
                spec_hash: spec.spec_hash.clone(),
                state: TaskState::Running { pid: 123 },
                network_resolver: None,
                stop_signal: "SIGTERM".into(),
                stop_grace: Duration::from_secs(10),
            },
        );
        *self.last_spec.lock() = Some(spec.clone());
        if self.suspend_start.load(Ordering::Relaxed) {
            self.start_pending.notify_one();
            std::future::pending::<()>().await;
        }
        anyhow::ensure!(
            !self.lost_start_ack.load(Ordering::Relaxed),
            "lost launch acknowledgement with private argv sentinel"
        );
        Ok(())
    }
    async fn restart(&self, _: &str) -> anyhow::Result<()> {
        anyhow::bail!("run restarted")
    }
    async fn remove(&self, _: &str, _: &str, _: Duration) -> anyhow::Result<()> {
        anyhow::bail!("service orphan cleanup called for run")
    }
    async fn remove_stopped(&self, id: &str) -> anyhow::Result<bool> {
        let mut containers = self.containers.lock();
        if containers.get(id).is_some_and(|container| {
            matches!(
                container.state,
                TaskState::Running { .. } | TaskState::Unknown
            )
        }) {
            return Ok(false);
        }
        containers.remove(id);
        Ok(true)
    }
    async fn list(&self) -> anyhow::Result<Vec<ContainerStatus>> {
        Ok(Vec::new())
    }
    async fn list_runs(&self) -> anyhow::Result<Vec<ContainerStatus>> {
        anyhow::ensure!(
            !self.inspection_failed.load(Ordering::Relaxed),
            "inspection unavailable"
        );
        Ok(self.containers.lock().values().cloned().collect())
    }
    async fn stop_run(&self, id: &str) -> anyhow::Result<RunStop> {
        self.stops.fetch_add(1, Ordering::Relaxed);
        anyhow::ensure!(
            !self.stop_failed.load(Ordering::Relaxed),
            "stop unavailable"
        );
        let mut containers = self.containers.lock();
        let Some(container) = containers.get_mut(id) else {
            return Ok(RunStop {
                state: None,
                signalled: false,
            });
        };
        let prior_exit = self.exit_before_signal.load(Ordering::Relaxed);
        container.state = TaskState::Exited {
            code: if prior_exit { 23 } else { 143 },
            exited_at_unix_ms: now_ms(),
        };
        self.stop_applied.notify_one();
        Ok(RunStop {
            state: Some(container.state.clone()),
            signalled: !prior_exit,
        })
    }
    async fn probe(&self, _: &str, _: &Probe, _: Duration) -> Result<(), String> {
        Err("runs have no probes".into())
    }
}

#[derive(Clone)]
struct Input;

impl Inputs for Input {
    async fn input(&self, _: &DesiredRun) -> anyhow::Result<GetRunInputResponse> {
        Ok(GetRunInputResponse {
            args: vec![
                "--email".into(),
                "private-argv-sentinel@example.invalid".into(),
                "a b;$HOME".into(),
            ],
            env: vec![EnvVar {
                name: "DATABASE_PASSWORD".into(),
                value: "private-secret-sentinel".into(),
                ..Default::default()
            }],
            ..Default::default()
        })
    }
    async fn credential(&self, _: &str) -> anyhow::Result<GetPullCredentialResponse> {
        Ok(Default::default())
    }
}

struct Fixture {
    data: PathBuf,
    desired: DesiredRun,
    shared: Arc<Shared>,
    runtime: Arc<Runtime>,
    seed: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let data = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../.workspace-cache/run-agent-tests")
            .join(uuid::Uuid::now_v7().to_string());
        std::fs::create_dir_all(&data).unwrap();
        let id = uuid::Uuid::now_v7().to_string();
        let desired = DesiredRun {
            run_id: id.clone(),
            attempt_id: uuid::Uuid::now_v7().to_string(),
            deadline: timestamp(now_ms() + 60_000).into(),
            replica: Replica {
                replica_id: id,
                app_id: uuid::Uuid::now_v7().to_string(),
                image: Image {
                    reference: "example.invalid/project/app".into(),
                    digest: format!("sha256:{}", "a".repeat(64)),
                    ..Default::default()
                }
                .into(),
                memory_mib: 128,
                cpu_millis: 250,
                working_dir: Some("/app".into()),
                user: Some("1000:1000".into()),
                secrets: vec![SecretRef {
                    name: "password".into(),
                    version: 3,
                    ..Default::default()
                }],
                secret_env: vec![SecretEnv {
                    env: "DATABASE_PASSWORD".into(),
                    secret: "password".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let shared = Arc::new(Shared::default());
        *shared.desired.lock().unwrap() = Some(DesiredState {
            runs: vec![desired.clone()],
            ..Default::default()
        });
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).unwrap();
        Self {
            data,
            desired,
            shared,
            runtime: Arc::new(Runtime::default()),
            seed,
        }
    }
    fn worker(&self) -> Worker<Runtime, Input> {
        Worker {
            runtime: self.runtime.clone(),
            inputs: Input,
            shared: self.shared.clone(),
            policy: Policy::default(),
            data: self.data.clone(),
            seed: self.seed,
            network: Network::Isolated,
            attached: None,
        }
    }
    fn receipt(&self) -> Receipt {
        Receipt::new(&self.desired).unwrap()
    }
    fn store(&self) -> Store {
        Store::open(&self.data, &self.desired.run_id).unwrap()
    }
    fn cancel(&self) {
        self.shared.desired.lock().unwrap().as_mut().unwrap().runs[0].cancel = true;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

#[tokio::test]
async fn replay_and_agent_restart_adopt_a_lost_launch_ack_without_starting_twice() {
    let fixture = Fixture::new();
    fixture
        .runtime
        .lost_start_ack
        .store(true, Ordering::Relaxed);
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    assert!(receipt.outcome == Outcome::Unknown);
    let mut after_restart = fixture.receipt();
    for _ in 0..3 {
        fixture
            .worker()
            .step(&fixture.desired, &fixture.store(), &mut after_restart)
            .await
            .unwrap();
    }
    assert!(after_restart.outcome == Outcome::Running);
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 1);
    let spec = fixture.runtime.last_spec.lock();
    let spec = spec.as_ref().unwrap();
    assert!(spec.command.is_empty() && spec.entrypoint.is_none() && spec.volumes.is_empty());
    assert_eq!(spec.cmd.as_ref().unwrap()[2], "a b;$HOME");
    assert_eq!((spec.memory_mib, spec.cpu_millis), (128, 250));
    assert_eq!(spec.user.as_deref(), Some("1000:1000"));
    assert_eq!(spec.working_dir.as_deref(), Some("/app"));
    for entry in std::fs::read_dir(fixture.store().0).unwrap() {
        let entry = entry.unwrap();
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let text = std::fs::read_to_string(entry.path()).unwrap();
            assert!(
                !text.contains("private-argv-sentinel")
                    && !text.contains("private-secret-sentinel")
            );
        }
    }
}

#[tokio::test]
async fn a_durable_latch_with_no_task_after_reboot_is_unknown_and_never_restarted() {
    let fixture = Fixture::new();
    let store = fixture.store();
    assert!(store.claim(&fixture.receipt()).unwrap());
    let mut receipt = fixture.receipt();
    for _ in 0..3 {
        fixture
            .worker()
            .step(&fixture.desired, &store, &mut receipt)
            .await
            .unwrap();
    }
    assert!(receipt.outcome == Outcome::Unknown && receipt.stop_confirmed);
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_torn_launch_receipt_does_not_authorize_another_start() {
    let fixture = Fixture::new();
    let store = fixture.store();
    std::fs::write(store.0.join("claim.json"), b"{").unwrap();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &store, &mut receipt)
        .await
        .unwrap();
    fixture
        .worker()
        .step(&fixture.desired, &store, &mut receipt)
        .await
        .unwrap();
    assert!(receipt.outcome == Outcome::Unknown);
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn cancel_before_launch_never_fetches_or_starts_a_task() {
    let fixture = Fixture::new();
    fixture.cancel();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    assert!(receipt.outcome == Outcome::Cancelled && receipt.stop_confirmed);
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn restart_after_signalling_during_creation_preserves_the_cancelled_outcome() {
    let fixture = Fixture::new();
    fixture.runtime.suspend_start.store(true, Ordering::Relaxed);
    let mut worker = fixture.worker();
    let store = fixture.store();
    let mut receipt = fixture.receipt();
    {
        let step = worker.step(&fixture.desired, &store, &mut receipt);
        tokio::pin!(step);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut step => panic!("creation unexpectedly completed: {result:?}"),
                _ = fixture.runtime.start_pending.notified() => {}
            }
            fixture.cancel();
            tokio::select! {
                result = &mut step => panic!("creation unexpectedly completed: {result:?}"),
                _ = fixture.runtime.stop_applied.notified() => {}
            }
        })
        .await
        .unwrap();
    }
    assert!(store.load().unwrap().unwrap().stop == Some(Stop::Cancel));
    let mut adopted = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &store, &mut adopted)
        .await
        .unwrap();
    assert!(adopted.outcome == Outcome::Cancelled && adopted.stop_confirmed);
    assert_eq!(adopted.exit_code, Some(143));
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn server_cancellation_after_launch_requires_observed_stop() {
    let fixture = Fixture::new();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    fixture.cancel();
    fixture.runtime.stop_failed.store(true, Ordering::Relaxed);
    assert!(
        fixture
            .worker()
            .step(&fixture.desired, &fixture.store(), &mut receipt)
            .await
            .is_err()
    );
    assert!(!receipt.stop_confirmed && !receipt.terminal());
    fixture.runtime.stop_failed.store(false, Ordering::Relaxed);
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    assert!(receipt.outcome == Outcome::Cancelled && receipt.stop_confirmed);
    assert_eq!(receipt.exit_code, Some(143));
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_prior_exit_racing_cancellation_retains_the_actual_process_outcome() {
    let fixture = Fixture::new();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    fixture.cancel();
    fixture
        .runtime
        .exit_before_signal
        .store(true, Ordering::Relaxed);
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    assert!(receipt.outcome == Outcome::Failed);
    assert_eq!(receipt.exit_code, Some(23));
}

#[tokio::test]
async fn restart_rearms_the_original_deadline_and_stops_an_overdue_adopted_task() {
    let fixture = Fixture::new();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    receipt.deadline_ms = now_ms() - 1;
    fixture.store().save(&receipt).unwrap();
    let mut desired = fixture.desired.clone();
    desired.deadline = timestamp(receipt.deadline_ms).into();
    let mut after_restart = Receipt::new(&desired).unwrap();
    fixture
        .worker()
        .step(&desired, &fixture.store(), &mut after_restart)
        .await
        .unwrap();
    assert!(after_restart.outcome == Outcome::TimedOut && after_restart.stop_confirmed);
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.runtime.stops.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn restart_waits_for_the_original_future_deadline_instead_of_resetting_it() {
    let fixture = Fixture::new();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    receipt.deadline_ms = now_ms() + 30;
    fixture.store().save(&receipt).unwrap();
    let mut desired = fixture.desired.clone();
    desired.deadline = timestamp(receipt.deadline_ms).into();
    fixture
        .shared
        .desired
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .runs[0] = desired.clone();
    let intent = wait_stop(fixture.shared.clone(), receipt.clone()).await;
    assert!(intent == Stop::Deadline);
    let mut after_restart = Receipt::new(&desired).unwrap();
    fixture
        .worker()
        .step(&desired, &fixture.store(), &mut after_restart)
        .await
        .unwrap();
    assert!(after_restart.outcome == Outcome::TimedOut);
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_exit_receipt_survives_cleanup_and_dropped_status_acknowledgements() {
    let fixture = Fixture::new();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    fixture
        .runtime
        .containers
        .lock()
        .get_mut(&fixture.desired.run_id)
        .unwrap()
        .state = TaskState::Exited {
        code: 23,
        exited_at_unix_ms: now_ms(),
    };
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    assert!(fixture.runtime.containers.lock().is_empty());
    let mut after_restart = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut after_restart)
        .await
        .unwrap();
    assert_eq!(after_restart.exit_code, Some(23));
    assert!(after_restart.outcome == Outcome::Failed && after_restart.stop_confirmed);
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_unobservable_task_is_neither_restarted_nor_reported_stopped() {
    let fixture = Fixture::new();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    fixture
        .runtime
        .containers
        .lock()
        .get_mut(&fixture.desired.run_id)
        .unwrap()
        .state = TaskState::Unknown;
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    assert!(receipt.outcome == Outcome::Unknown && !receipt.stop_confirmed);
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn ordinary_service_orphan_cleanup_does_not_see_or_stop_runs() {
    let fixture = Fixture::new();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    let mut apps = crate::apps::Apps::new(
        fixture.runtime.clone(),
        None,
        fixture.shared.clone(),
        Policy::default(),
        fixture.data.clone(),
        &fixture.seed,
    );
    apps.pass().await.unwrap();
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.runtime.containers.lock().len(), 1);
    assert!(fixture.shared.reports.lock().unwrap().is_empty());
    assert!(fixture.shared.endpoints().borrow().is_empty());
}

#[tokio::test]
async fn cancellation_still_signals_an_owned_run_whose_task_state_was_unknown() {
    let fixture = Fixture::new();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    fixture
        .runtime
        .containers
        .lock()
        .get_mut(&fixture.desired.run_id)
        .unwrap()
        .state = TaskState::Unknown;
    fixture.cancel();
    fixture
        .worker()
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    assert!(receipt.outcome == Outcome::Cancelled && receipt.stop_confirmed);
    assert_eq!(fixture.runtime.stops.load(Ordering::Relaxed), 1);
}

#[derive(Clone)]
struct SlowInput;

impl Inputs for SlowInput {
    async fn input(&self, _: &DesiredRun) -> anyhow::Result<GetRunInputResponse> {
        std::future::pending().await
    }
    async fn credential(&self, _: &str) -> anyhow::Result<GetPullCredentialResponse> {
        Ok(Default::default())
    }
}

#[tokio::test]
async fn a_deadline_during_input_retrieval_never_reaches_the_start_latch() {
    let mut fixture = Fixture::new();
    fixture.desired.deadline = timestamp(now_ms() + 20).into();
    fixture
        .shared
        .desired
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .runs[0] = fixture.desired.clone();
    let mut worker = Worker {
        runtime: fixture.runtime.clone(),
        inputs: SlowInput,
        shared: fixture.shared.clone(),
        policy: Policy::default(),
        data: fixture.data.clone(),
        seed: fixture.seed,
        network: Network::Isolated,
        attached: None,
    };
    let mut receipt = fixture.receipt();
    worker
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    worker
        .step(&fixture.desired, &fixture.store(), &mut receipt)
        .await
        .unwrap();
    assert!(receipt.outcome == Outcome::NotStarted && receipt.stop_confirmed);
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn cancellation_during_input_retrieval_cannot_start_a_task_later() {
    let fixture = Fixture::new();
    let mut worker = Worker {
        runtime: fixture.runtime.clone(),
        inputs: SlowInput,
        shared: fixture.shared.clone(),
        policy: Policy::default(),
        data: fixture.data.clone(),
        seed: fixture.seed,
        network: Network::Isolated,
        attached: None,
    };
    let mut receipt = fixture.receipt();
    let store = fixture.store();
    let preparation = worker.step(&fixture.desired, &store, &mut receipt);
    let cancel = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        fixture.cancel();
    };
    let (result, ()) = tokio::join!(preparation, cancel);
    result.unwrap();
    worker
        .step(&fixture.desired, &store, &mut receipt)
        .await
        .unwrap();
    assert!(receipt.outcome == Outcome::Cancelled && receipt.stop_confirmed);
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn run_telemetry_retains_its_identity_and_redacts_pinned_secrets_after_restart() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut receipt = fixture.receipt();
    fixture
        .worker()
        .step(&fixture.desired, &store, &mut receipt)
        .await
        .unwrap();
    let cached = secrets::load(&store.0, &secrets::key(&fixture.seed));
    let values = &cached[&fixture.desired.run_id];
    assert_eq!(values[0].version, 3);
    crate::telemetry_final::remember(
        &fixture.shared,
        fixture.shared.desired.lock().unwrap().as_ref(),
    );
    crate::telemetry_final::prune(&fixture.shared, &Default::default());
    assert!(
        fixture
            .shared
            .telemetry
            .identities
            .lock()
            .contains_key(&fixture.desired.run_id)
    );
    assert!(
        fixture
            .shared
            .telemetry_secrets
            .lock()
            .contains_key(&fixture.desired.run_id)
    );
    let path = fixture.data.join("stdout");
    std::fs::write(&path, "password=private-secret-sentinel\n").unwrap();
    let source = crate::runtime::LogSource {
        stream: "stdout",
        paths: vec![path],
    };
    let redactor = crate::telemetry_tail::Redactor::new(values);
    let (lines, _, _) =
        crate::telemetry_tail::read(&source, Default::default(), &redactor).unwrap();
    assert_eq!(lines.len(), 1);
    assert!(!lines[0].body.contains("private-secret-sentinel"));
}

#[test]
fn signed_run_documents_require_explicit_semantics_and_unsupported_runtimes_never_advertise_them() {
    let fixture = Fixture::new();
    let mut document = fixture.shared.desired.lock().unwrap().clone().unwrap();
    assert_eq!(
        crate::agent::check_features(&document),
        Err(crate::agent::Refusal::MissingRunFeature)
    );
    document.required_features.push("runs-v1".into());
    assert!(crate::agent::check_features(&document).is_ok());
    assert!(!crate::runtime::NoContainers.supports_runs());
}

#[tokio::test]
async fn an_unavailable_private_network_never_launches_a_loopback_only_run() {
    let fixture = Fixture::new();
    let mut worker = fixture.worker();
    let (_, lists) = tokio::sync::watch::channel(None);
    worker.network = Network::Private(NetworkAccess {
        lists,
        mesh: Arc::new(std::sync::OnceLock::new()),
        own: "unavailable-machine".into(),
    });
    let mut receipt = fixture.receipt();
    let store = fixture.store();
    let error = worker
        .step(&fixture.desired, &store, &mut receipt)
        .await
        .unwrap_err();
    assert!(error.is::<NetworkUnavailable>());
    assert!(store.load().unwrap().is_none());
    assert_eq!(fixture.runtime.starts.load(Ordering::Relaxed), 0);
}
