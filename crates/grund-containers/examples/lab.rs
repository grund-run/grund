use std::{collections::BTreeMap, time::Duration, time::Instant};

use anyhow::Context;
use buffa_types::google::protobuf::Any;
use grund_agent::runtime::{ContainerRuntime, ContainerSpec, ImageRef, Probe, TaskState};
use grund_containers::{
    Config, Containerd, IMAGE_STORE_TYPE_URL, OCI_REGISTRY_TYPE_URL,
    api::containerd::{
        services::{
            containers::v1::{
                Container, CreateContainerRequest, DeleteContainerRequest, ListContainersRequest,
                container::Runtime,
            },
            images::v1::GetImageRequest,
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
    }
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
            let before = runtime.has_image(&image_ref()).await?;
            runtime.pull(&image_ref()).await?;
            say(format!(
                "pull_ms={} had_image_before={before} has_image_after={}",
                ms(t),
                runtime.has_image(&image_ref()).await?
            ));
        }
        "create" => {
            let id = args.get(1).context("create <id> [command...]")?;
            let t = Instant::now();
            runtime.create(&spec(id, &args[2..])).await?;
            say(format!("create_ms={} id={id}", ms(t)));
        }
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
            "usage: lab transport|watch|caps|prepare|pull|create|create-again|ready|probe|list|wait-exited|restart|remove"
        ),
    }
    Ok(())
}
