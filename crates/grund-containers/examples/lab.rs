use std::{collections::BTreeMap, time::Duration, time::Instant};

use anyhow::Context;
use buffa_types::google::protobuf::Any;
use grund_agent::runtime::{ContainerRuntime, ContainerSpec, ImageRef, Probe, TaskState};
use grund_containers::{
    Config, Containerd, IMAGE_STORE_TYPE_URL, OCI_REGISTRY_TYPE_URL,
    api::containerd::{
        services::{
            containers::v1::{
                Container, CreateContainerRequest, DeleteContainerRequest, GetContainerRequest,
                ListContainersRequest, container::Runtime,
            },
            images::v1::GetImageRequest,
            tasks::v1::GetRequest,
            transfer::v1::TransferRequest,
        },
        types::{
            Platform,
            transfer::{ImageStore, OCIRegistry},
        },
    },
    image,
};

const IMAGE: &str = "docker.io/traefik/whoami:v1.11.0";
const DIGEST: &str = "sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab";

fn image_ref() -> ImageRef {
    ImageRef {
        reference: std::env::var("LAB_IMAGE").unwrap_or_else(|_| IMAGE.into()),
        digest: std::env::var("LAB_DIGEST").unwrap_or_else(|_| DIGEST.into()),
    }
}

fn spec(id: &str, command: &[String]) -> ContainerSpec {
    ContainerSpec {
        id: id.into(),
        image: image_ref(),
        command: command.to_vec(),
        env: vec![("WHOAMI_NAME".into(), id.into())],
        memory_mib: 64,
        cpu_millis: 250,
        stop_signal: "SIGTERM".into(),
        stop_grace: Duration::from_secs(2),
        labels: BTreeMap::from([("grund.app".into(), "lab".into())]),
        spec_hash: format!("hash-{id}"),
        resolv_conf: None,
        volumes: Vec::new(),
        volume_roots: Vec::new(),
        entrypoint: None,
        cmd: None,
        working_dir: None,
        user: None,
    }
}

fn argv_env(name: &str) -> anyhow::Result<Option<Vec<String>>> {
    match std::env::var(name) {
        Ok(json) => serde_json::from_str(&json).with_context(|| format!("{name} is a JSON array")),
        Err(_) => Ok(None),
    }
}

async fn inspect(runtime: &Containerd, id: &str) -> anyhow::Result<()> {
    let container = runtime
        .client()
        .containers()
        .get(GetContainerRequest {
            id: id.into(),
            ..Default::default()
        })
        .await
        .context("get container")?
        .into_owned()
        .container
        .into_option()
        .context("no container")?;
    let spec: serde_json::Value =
        serde_json::from_slice(&container.spec.into_option().context("no spec")?.value)?;
    say(format!(
        "spec id={id} args={} user={} cwd={}",
        spec["process"]["args"], spec["process"]["user"], spec["process"]["cwd"]
    ));
    let pid = match runtime
        .client()
        .tasks()
        .get(GetRequest {
            container_id: id.into(),
            ..Default::default()
        })
        .await
    {
        Ok(response) => response
            .into_owned()
            .process
            .into_option()
            .map(|p| (p.pid, p.status)),
        Err(e) => {
            say(format!("task id={id}: {e}"));
            None
        }
    };
    let Some((pid, status)) = pid else {
        return Ok(());
    };
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let args: Vec<String> = cmdline
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    let proc_status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let ids: Vec<&str> = proc_status
        .lines()
        .filter(|l| l.starts_with("Uid:") || l.starts_with("Gid:") || l.starts_with("Groups:"))
        .collect();
    let cwd = std::fs::read_link(format!("/proc/{pid}/cwd"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|e| format!("unreadable: {e}"));
    say(format!(
        "task id={id} pid={pid} status={status:?} cmdline={args:?} {ids:?} cwd={cwd}"
    ));
    Ok(())
}

fn say(text: impl std::fmt::Display) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    println!("{now} {text}");
}

fn ms(since: Instant) -> u128 {
    since.elapsed().as_millis()
}

async fn transport(runtime: &Containerd) -> anyhow::Result<()> {
    let client = runtime.client();
    let t = Instant::now();
    let version = runtime
        .version(Duration::from_secs(2))
        .await
        .context("no answer")?;
    say(format!("unary Version: {version} in {} ms", ms(t)));
    let name = image::pinned_name(IMAGE, DIGEST)?;
    let platform = Platform {
        os: "linux".into(),
        architecture: runtime.config().arch.oci().into(),
        ..Default::default()
    };
    let source = OCIRegistry {
        reference: name.clone(),
        ..Default::default()
    };
    let destination = ImageStore {
        name: name.clone(),
        platforms: vec![platform],
        ..Default::default()
    };
    let t = Instant::now();
    client
        .transfer()
        .transfer(TransferRequest {
            source: Any {
                type_url: OCI_REGISTRY_TYPE_URL.into(),
                value: buffa::Message::encode_to_vec(&source).into(),
                ..Default::default()
            }
            .into(),
            destination: Any {
                type_url: IMAGE_STORE_TYPE_URL.into(),
                value: buffa::Message::encode_to_vec(&destination).into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        })
        .await
        .context("transfer")?;
    say(format!(
        "unary Transfer (no unpack) of {name}: {} ms",
        ms(t)
    ));
    let record = client
        .images()
        .get(GetImageRequest {
            name: name.clone(),
            ..Default::default()
        })
        .await?
        .into_owned();
    say(format!(
        "image record target {}",
        record
            .image
            .as_option()
            .and_then(|i| i.target.as_option())
            .map(|t| t.digest.clone())
            .unwrap_or_default()
    ));
    let t = Instant::now();
    let config = runtime
        .image_config(DIGEST)
        .await?
        .context("config missing")?;
    say(format!(
        "server-streaming Content.Read: index, manifest, config in {} ms; entrypoint {:?}, chain id {}",
        ms(t),
        config.config.entrypoint,
        config.chain_id()?
    ));
    let container = Container {
        id: "transport-check".into(),
        labels: [("grund.replica".to_string(), "transport-check".to_string())]
            .into_iter()
            .collect(),
        image: name,
        runtime: Runtime {
            name: grund_containers::RUNTIME.into(),
            ..Default::default()
        }
        .into(),
        spec: Any {
            type_url: grund_containers::spec::SPEC_TYPE_URL.into(),
            value: b"{}".to_vec().into(),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    };
    client
        .containers()
        .create(CreateContainerRequest {
            container: container.into(),
            ..Default::default()
        })
        .await
        .context("create container")?;
    let listed = client
        .containers()
        .list(ListContainersRequest {
            filters: vec!["labels.\"grund.replica\"".into()],
            ..Default::default()
        })
        .await?
        .into_owned()
        .containers;
    say(format!(
        "Containers.Create then List: {:?}",
        listed.iter().map(|c| c.id.clone()).collect::<Vec<_>>()
    ));
    client
        .containers()
        .delete(DeleteContainerRequest {
            id: "transport-check".into(),
            ..Default::default()
        })
        .await?;
    let missing = client
        .containers()
        .delete(DeleteContainerRequest {
            id: "transport-check".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    say(format!(
        "a second Delete: {:?} (not_found {})",
        missing.code,
        grund_containers::client::not_found(&missing)
    ));
    Ok(())
}

async fn wait_ready(runtime: &Containerd, id: &str, probe: &Probe) -> anyhow::Result<u128> {
    let t = Instant::now();
    let mut last = String::new();
    while t.elapsed() < Duration::from_secs(20) {
        match runtime.probe(id, probe, Duration::from_millis(500)).await {
            Ok(()) => return Ok(ms(t)),
            Err(reason) => last = reason,
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("{id} not ready after 20 s: {last}")
}

fn state_line(state: &TaskState) -> String {
    match state {
        TaskState::Unknown => "unknown".into(),
        TaskState::Created => "created".into(),
        TaskState::Running { pid } => format!("running pid={pid}"),
        TaskState::Exited {
            code,
            exited_at_unix_ms,
        } => {
            format!("exited code={code} at={exited_at_unix_ms}")
        }
    }
}

fn cgroup_counter(id: &str, file: &str, key: &str) -> anyhow::Result<u64> {
    let text = std::fs::read_to_string(format!("/sys/fs/cgroup/grund/{id}/{file}"))?;
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(' ')?;
            (name == key).then(|| value.parse::<u64>().ok()).flatten()
        })
        .with_context(|| format!("{file} has no {key} counter"))
}

async fn limits(runtime: &Containerd) -> anyhow::Result<()> {
    let caps = runtime.capabilities().await;
    anyhow::ensure!(caps.apps, "apps unavailable: {}", caps.reason);
    runtime.prepare().await?;
    runtime.pull(&image_ref(), None).await?;
    let cpu = spec(
        "limit-cpu",
        &["/bin/sh".into(), "-c".into(), "while :; do :; done".into()],
    );
    runtime.create(&cpu).await?;
    let cpu_result = async {
        let before_usage = cgroup_counter(&cpu.id, "cpu.stat", "usage_usec")?;
        let before_throttled = cgroup_counter(&cpu.id, "cpu.stat", "nr_throttled")?;
        let started = Instant::now();
        tokio::time::sleep(Duration::from_secs(10)).await;
        let elapsed = started.elapsed().as_micros() as u64;
        let usage = cgroup_counter(&cpu.id, "cpu.stat", "usage_usec")? - before_usage;
        let throttled = cgroup_counter(&cpu.id, "cpu.stat", "nr_throttled")? - before_throttled;
        say(format!(
            "CPU_PROOF elapsed_usec={elapsed} usage_usec={usage} throttled_periods={throttled}"
        ));
        anyhow::ensure!(throttled > 0, "the over-cap app was never CPU throttled");
        anyhow::ensure!(
            usage > elapsed / 20 && usage < elapsed / 2,
            "250m CPU app used {usage} us in {elapsed} us"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    runtime.remove(&cpu.id, "SIGKILL", Duration::ZERO).await?;
    cpu_result?;
    let memory = spec(
        "limit-memory",
        &[
            "/bin/awk".into(),
            "BEGIN { s=\"x\"; for (i=0;i<28;i++) s=s s; print length(s); }".into(),
        ],
    );
    runtime.create(&memory).await?;
    let memory_result = async {
        let started = Instant::now();
        loop {
            let state = runtime
                .list()
                .await?
                .into_iter()
                .find(|task| task.id == memory.id)
                .context("memory task disappeared")?
                .state;
            if let TaskState::Exited { code, .. } = state {
                let kills = cgroup_counter(&memory.id, "memory.events", "oom_kill")?;
                say(format!(
                    "MEMORY_PROOF limit_mib={} exit_code={code} oom_kills={kills}",
                    memory.memory_mib
                ));
                anyhow::ensure!(code == 137 && kills > 0, "over-cap app was not OOM-killed");
                break;
            }
            anyhow::ensure!(
                started.elapsed() < Duration::from_secs(30),
                "over-cap app survived 30 seconds"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    runtime
        .remove(&memory.id, "SIGKILL", Duration::ZERO)
        .await?;
    memory_result
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [flag, directory] = args.as_slice()
        && flag == "--container-logs"
    {
        return grund_agent::capture::run(std::path::Path::new(directory));
    }
    grund_crypto::install_default();
    let mut config = Config::default();
    if let Ok(dir) = std::env::var("GRUND_CONTAINERS_DATA_DIR") {
        config.data_dir = dir.into();
    }
    if let Ok(dir) = std::env::var("GRUND_CONTAINERS_RUN_DIR") {
        config.run_dir = dir.into();
    }
    let runtime = Containerd::new(config);
    let command = args.first().map(String::as_str).unwrap_or_default();
    match command {
        "transport" => transport(&runtime).await?,
        "watch" => {
            let seconds: u64 = args.get(1).map_or(Ok(10), |s| s.parse())?;
            let t = Instant::now();
            let mut last = None;
            while t.elapsed() < Duration::from_secs(seconds) {
                let answers = runtime.version(Duration::from_millis(500)).await.is_some();
                if last != Some(answers) {
                    say(format!("containerd answers={answers} at_ms={}", ms(t)));
                    last = Some(answers);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        "caps" => say(format!("capabilities {:?}", runtime.capabilities().await)),
        "limits" => limits(&runtime).await?,
        "prepare" => {
            let t = Instant::now();
            runtime.prepare().await?;
            say(format!(
                "prepare_ms={} version={}",
                ms(t),
                runtime
                    .version(Duration::from_secs(2))
                    .await
                    .unwrap_or_default()
            ));
        }
        "pull" => {
            let t = Instant::now();
            let image = image_ref();
            let before = runtime.has_image(&image).await?;
            let authorization = match std::env::var("LAB_LOGIN") {
                Ok(login) => {
                    let (username, password) = login
                        .split_once(':')
                        .context("LAB_LOGIN is user:password")?;
                    let host = match image.reference.split_once('/') {
                        Some((first, _)) if first.contains(['.', ':']) || first == "localhost" => {
                            first.to_string()
                        }
                        _ => "docker.io".to_string(),
                    };
                    let credential = grund_agent::registry_login::Credential {
                        host,
                        username: username.into(),
                        password: password.into(),
                    };
                    grund_agent::registry_login::authorization(
                        &grund_agent::join::http_client()?,
                        &credential,
                        &image.reference,
                        &image.digest,
                    )
                    .await?
                }
                Err(_) => None,
            };
            runtime.pull(&image, authorization.as_deref()).await?;
            say(format!(
                "pull_ms={} had_image_before={before} has_image_after={} with_login={}",
                ms(t),
                runtime.has_image(&image).await?,
                authorization.is_some()
            ));
        }
        "create" => {
            let id = args.get(1).context("create <id> [command...]")?;
            let t = Instant::now();
            runtime.create(&spec(id, &args[2..])).await?;
            say(format!("create_ms={} id={id}", ms(t)));
        }
        "create-with" => {
            let id = args.get(1).context("create-with <id>")?;
            let mut spec = spec(id, &[]);
            spec.entrypoint = argv_env("LAB_ENTRYPOINT")?;
            spec.cmd = argv_env("LAB_CMD")?;
            spec.working_dir = std::env::var("LAB_WORKDIR").ok();
            spec.user = std::env::var("LAB_USER").ok();
            let t = Instant::now();
            match runtime.create(&spec).await {
                Ok(()) => say(format!("create_ms={} id={id}", ms(t))),
                Err(e) => say(format!("create id={id} refused: {e:#}")),
            }
        }
        "inspect" => inspect(&runtime, args.get(1).context("inspect <id>")?).await?,
        "create-again" => {
            let id = args.get(1).context("create-again <id>")?;
            match runtime.create(&spec(id, &[])).await {
                Ok(()) => say(format!("UNEXPECTED: a second create of {id} succeeded")),
                Err(e) => say(format!("a second create of {id} is refused: {e}")),
            }
        }
        "ready" => {
            let id = args.get(1).context("ready <id> <port> [path]")?;
            let port: u16 = args.get(2).context("port")?.parse()?;
            let path = args.get(3).cloned().unwrap_or_else(|| "/".into());
            let probe = Probe::Http { port, path };
            let after = wait_ready(&runtime, id, &probe).await?;
            say(format!("ready id={id} port={port} after_ms={after}"));
        }
        "probe" => {
            let id = args.get(1).context("probe <id> <port>")?;
            let port: u16 = args.get(2).context("port")?.parse()?;
            let probe = Probe::Http {
                port,
                path: "/".into(),
            };
            match runtime.probe(id, &probe, Duration::from_millis(500)).await {
                Ok(()) => say(format!("probe id={id} port={port}: ok")),
                Err(reason) => say(format!("probe id={id} port={port}: {reason}")),
            }
        }
        "list" => {
            for status in runtime.list().await? {
                say(format!(
                    "list id={} state={} spec_hash={} stop={}/{}s",
                    status.id,
                    state_line(&status.state),
                    status.spec_hash,
                    status.stop_signal,
                    status.stop_grace.as_secs()
                ));
            }
        }
        "wait-exited" => {
            let id = args.get(1).context("wait-exited <id>")?;
            let t = Instant::now();
            loop {
                let state = runtime
                    .list()
                    .await?
                    .into_iter()
                    .find(|s| &s.id == id)
                    .map(|s| s.state);
                if let Some(state @ TaskState::Exited { .. }) = state {
                    say(format!(
                        "seen id={id} {} after_ms={}",
                        state_line(&state),
                        ms(t)
                    ));
                    break;
                }
                anyhow::ensure!(t.elapsed() < Duration::from_secs(10), "{id} never exited");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        "restart" => {
            let id = args.get(1).context("restart <id>")?;
            let t = Instant::now();
            runtime.restart(id).await?;
            say(format!("restart_ms={} id={id}", ms(t)));
        }
        "remove" => {
            let id = args.get(1).context("remove <id> <signal> <grace s>")?;
            let signal = args.get(2).context("signal")?;
            let grace = Duration::from_secs(args.get(3).context("grace")?.parse()?);
            let t = Instant::now();
            runtime.remove(id, signal, grace).await?;
            say(format!(
                "remove_ms={} id={id} signal={signal} grace_s={}",
                ms(t),
                grace.as_secs()
            ));
        }
        _ => anyhow::bail!(
            "usage: lab transport|watch|caps|prepare|pull|create|create-with|inspect|create-again|ready|probe|list|wait-exited|restart|remove"
        ),
    }
    Ok(())
}
