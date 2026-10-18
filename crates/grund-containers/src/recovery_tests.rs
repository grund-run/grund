use std::{
    os::{fd::AsRawFd, unix::fs::symlink},
    sync::Arc,
};

use connectrpc::{ConnectError, ErrorCode, Response, Router, handler_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use parking_lot::Mutex;

use super::*;
use crate::api::containerd::services::{
    containers::v1::{GetContainerResponse, ListContainersResponse},
    snapshots::v1::{MountsResponse, StatSnapshotResponse},
    tasks::v1::{
        CreateTaskResponse, DeleteResponse, GetResponse, ListTasksResponse, StartResponse,
    },
};

const ID: &str = "replica";
const PID: u32 = 4172;
const STARTED_PID: u32 = 9013;
const TASKS: &str = "containerd.services.tasks.v1.Tasks";
const CONTAINERS: &str = "containerd.services.containers.v1.Containers";
const SNAPSHOTS: &str = "containerd.services.snapshots.v1.Snapshots";

struct DaemonState {
    task: Option<Process>,
    get_error: Option<ErrorCode>,
    empty_get: bool,
    starts_during_delete: bool,
    mutations: Vec<&'static str>,
}

fn process(status: Status, pid: u32) -> Process {
    Process {
        id: ID.into(),
        container_id: ID.into(),
        pid,
        status: status.into(),
        ..Default::default()
    }
}

fn container() -> Container {
    Container {
        id: ID.into(),
        labels: [
            (REPLICA_LABEL.into(), ID.into()),
            (SPEC_HASH_LABEL.into(), "unchanged-spec".into()),
            (RESOLV_CONF_LABEL.into(), "nameserver fd00::53\n".into()),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

struct FakeContainerd {
    runtime: Containerd,
    state: Arc<Mutex<DaemonState>>,
    server: tokio::task::JoinHandle<()>,
    dir: PathBuf,
    _run_directory: std::fs::File,
}

impl Drop for FakeContainerd {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl FakeContainerd {
    async fn new(task: Option<Process>) -> Self {
        let dir = std::env::temp_dir().join(format!("grund-recovery-{}", uuid::Uuid::new_v4()));
        let run_dir = dir.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let run_directory = std::fs::File::open(run_dir).unwrap();
        let config = Config {
            data_dir: dir.join("data"),
            run_dir: PathBuf::from(format!("/proc/self/fd/{}", run_directory.as_raw_fd())),
            ..Config::default()
        };
        std::fs::create_dir_all(config.netns_dir()).unwrap();
        symlink("/proc/self/ns/net", config.netns_dir().join(ID)).unwrap();
        let listener = tokio::net::UnixListener::bind(config.socket()).unwrap();
        let state = Arc::new(Mutex::new(DaemonState {
            task,
            get_error: None,
            empty_get: false,
            starts_during_delete: false,
            mutations: Vec::new(),
        }));
        let mut router = Router::new();
        macro_rules! rpc {
            ($service:expr, $method:literal, $request:ty, $body:expr) => {{
                let state = Arc::clone(&state);
                router = router.route(
                    $service,
                    $method,
                    handler_fn(move |_ctx, request: $request| {
                        let result = ($body)(&mut state.lock(), request);
                        async move { result.and_then(Response::ok) }
                    }),
                );
            }};
        }
        rpc!(
            CONTAINERS,
            "List",
            ListContainersRequest,
            |_state: &mut DaemonState, _| {
                Ok::<_, ConnectError>(ListContainersResponse {
                    containers: vec![container()],
                    ..Default::default()
                })
            }
        );
        rpc!(
            CONTAINERS,
            "Get",
            GetContainerRequest,
            |_state: &mut DaemonState, _| {
                Ok::<_, ConnectError>(GetContainerResponse {
                    container: container().into(),
                    ..Default::default()
                })
            }
        );
        rpc!(
            TASKS,
            "List",
            ListTasksRequest,
            |_state: &mut DaemonState, _| { Ok::<_, ConnectError>(ListTasksResponse::default()) }
        );
        rpc!(TASKS, "Get", GetRequest, |state: &mut DaemonState, _| {
            if let Some(code) = state.get_error {
                return Err(ConnectError::new(code, "shim temporarily unreachable"));
            }
            if state.empty_get {
                return Ok(GetResponse::default());
            }
            let task = state
                .task
                .clone()
                .ok_or_else(|| ConnectError::not_found("no task"))?;
            Ok(GetResponse {
                process: task.into(),
                ..Default::default()
            })
        });
        rpc!(TASKS, "Kill", KillRequest, |state: &mut DaemonState, _| {
            state.mutations.push("kill");
            state.task = Some(process(Status::STOPPED, PID));
            Ok::<_, ConnectError>(Empty::default())
        });
        rpc!(
            TASKS,
            "Delete",
            DeleteTaskRequest,
            |state: &mut DaemonState, _| {
                state.mutations.push("delete");
                if state.starts_during_delete {
                    state.task = Some(process(Status::RUNNING, PID));
                }
                if state.task.as_ref().is_some_and(|task| {
                    matches!(
                        task.status.as_known(),
                        Some(Status::RUNNING | Status::PAUSED | Status::PAUSING)
                    )
                }) {
                    return Err(ConnectError::failed_precondition("task is running"));
                }
                state.task = None;
                Ok(DeleteResponse::default())
            }
        );
        rpc!(
            SNAPSHOTS,
            "Stat",
            StatSnapshotRequest,
            |_state: &mut DaemonState, _| {
                Ok::<_, ConnectError>(StatSnapshotResponse::default())
            }
        );
        rpc!(
            SNAPSHOTS,
            "Mounts",
            MountsRequest,
            |_state: &mut DaemonState, _| { Ok::<_, ConnectError>(MountsResponse::default()) }
        );
        rpc!(
            TASKS,
            "Create",
            CreateTaskRequest,
            |state: &mut DaemonState, _| {
                state.mutations.push("create");
                if state.task.is_some() {
                    return Err(ConnectError::already_exists("task exists"));
                }
                state.task = Some(process(Status::CREATED, STARTED_PID));
                Ok(CreateTaskResponse {
                    pid: STARTED_PID,
                    ..Default::default()
                })
            }
        );
        rpc!(
            TASKS,
            "Start",
            StartRequest,
            |state: &mut DaemonState, _| {
                state.mutations.push("start");
                state.task = Some(process(Status::RUNNING, STARTED_PID));
                Ok::<_, ConnectError>(StartResponse {
                    pid: STARTED_PID,
                    ..Default::default()
                })
            }
        );
        let service = connectrpc::ConnectRpcService::new(router);
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = TowerToHyperService::new(service.clone());
                connections.spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            runtime: Containerd::new(config),
            state,
            server,
            dir,
            _run_directory: run_directory,
        }
    }

    async fn status(&self) -> ContainerStatus {
        let mut statuses = self.runtime.list().await.unwrap();
        assert_eq!(statuses.len(), 1);
        statuses.pop().unwrap()
    }

    fn assert_untouched(&self, pid: u32) {
        let state = self.state.lock();
        assert!(
            state.mutations.is_empty(),
            "unexpected task mutations: {:?}",
            state.mutations
        );
        assert_eq!(state.task.as_ref().unwrap().pid, pid);
    }
}

#[tokio::test]
async fn a_running_task_omitted_from_a_successful_list_keeps_its_pid_through_recovery() {
    for status in [Status::RUNNING, Status::PAUSED, Status::PAUSING] {
        let daemon = FakeContainerd::new(Some(process(status, PID))).await;
        let observed = daemon.status().await;
        assert_eq!(observed.state, TaskState::Running { pid: PID });
        assert_eq!(observed.network_resolver, Some("fd00::53".parse().unwrap()));
        daemon.runtime.restart(ID).await.unwrap();
        assert!(!daemon.runtime.remove_stopped(ID).await.unwrap());
        assert_eq!(daemon.status().await.state, TaskState::Running { pid: PID });
        daemon.assert_untouched(PID);
    }
}

#[tokio::test]
async fn recovery_adopts_a_task_that_started_after_authoritative_absence() {
    let daemon = FakeContainerd::new(None).await;
    assert_eq!(daemon.status().await.state, TaskState::Created);
    daemon.state.lock().task = Some(process(Status::RUNNING, PID));
    daemon.runtime.restart(ID).await.unwrap();
    assert_eq!(daemon.status().await.state, TaskState::Running { pid: PID });
    daemon.assert_untouched(PID);
}

#[tokio::test]
async fn a_task_starting_between_get_and_delete_is_never_signalled_by_recovery() {
    let daemon = FakeContainerd::new(Some(process(Status::CREATED, PID))).await;
    daemon.state.lock().starts_during_delete = true;
    assert!(daemon.runtime.restart(ID).await.is_err());
    assert!(!daemon.runtime.remove_stopped(ID).await.unwrap());
    assert_eq!(daemon.status().await.state, TaskState::Running { pid: PID });
    let state = daemon.state.lock();
    assert_eq!(state.mutations, ["delete"]);
    assert_eq!(state.task.as_ref().unwrap().pid, PID);
}

#[tokio::test]
async fn failed_task_inspection_never_turns_a_running_task_into_a_new_process() {
    for code in [
        ErrorCode::Unavailable,
        ErrorCode::PermissionDenied,
        ErrorCode::Internal,
    ] {
        let daemon = FakeContainerd::new(Some(process(Status::RUNNING, PID))).await;
        daemon.state.lock().get_error = Some(code);
        assert_eq!(daemon.status().await.state, TaskState::Unknown);
        let error = daemon.runtime.restart(ID).await.unwrap_err();
        assert!(error.to_string().contains(code.as_str()), "{error:#}");
        assert!(daemon.runtime.remove_stopped(ID).await.is_err());
        daemon.assert_untouched(PID);
    }
}

#[tokio::test]
async fn unknown_or_missing_process_data_defers_recovery_without_mutating_the_task() {
    for (raw_status, missing) in [(0, false), (999, false), (0, true)] {
        let mut task = process(Status::UNKNOWN, PID);
        task.status = raw_status.into();
        let daemon = FakeContainerd::new(Some(task)).await;
        daemon.state.lock().empty_get = missing;
        assert_eq!(daemon.status().await.state, TaskState::Unknown);
        assert!(daemon.runtime.restart(ID).await.is_err());
        if missing {
            assert!(daemon.runtime.remove_stopped(ID).await.is_err());
        } else {
            assert!(!daemon.runtime.remove_stopped(ID).await.unwrap());
        }
        daemon.assert_untouched(PID);
    }
}

#[tokio::test]
async fn authoritative_task_absence_still_starts_the_persisted_container() {
    let daemon = FakeContainerd::new(None).await;
    assert_eq!(daemon.status().await.state, TaskState::Created);
    daemon.runtime.restart(ID).await.unwrap();
    assert_eq!(
        daemon.status().await.state,
        TaskState::Running { pid: STARTED_PID }
    );
    assert_eq!(daemon.state.lock().mutations, ["create", "start"]);
}

#[tokio::test]
async fn an_exited_task_is_discarded_without_a_signal_before_starting_a_new_process() {
    let daemon = FakeContainerd::new(Some(process(Status::STOPPED, PID))).await;
    daemon.runtime.restart(ID).await.unwrap();
    assert_eq!(
        daemon.status().await.state,
        TaskState::Running { pid: STARTED_PID }
    );
    assert_eq!(daemon.state.lock().mutations, ["delete", "create", "start"]);
}
