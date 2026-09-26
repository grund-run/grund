use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub const TOKEN: &str = "accept-capacity-token-0123456789abcdef";

#[derive(Clone, Debug)]
pub struct Call {
    pub method: String,
    pub authorization: Option<String>,
    pub body: serde_json::Value,
}

#[derive(Default)]
struct Shared {
    calls: Vec<Call>,
    unavailable: BTreeSet<String>,
    boot_before_answer: Option<std::path::PathBuf>,
}

pub struct FakeCapacity {
    pub url: String,
    shared: Arc<Mutex<Shared>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeCapacity {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeCapacity {
    pub async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let shared = Arc::new(Mutex::new(Shared::default()));
        let handle = shared.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handle = handle.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, handle).await;
                });
            }
        });
        Ok(Self { url, shared, task })
    }

    pub fn unavailable_for(&self, method: &str, unavailable: bool) {
        let mut shared = self.shared.lock().unwrap();
        if unavailable {
            shared.unavailable.insert(method.to_string());
        } else {
            shared.unavailable.remove(method);
        }
    }

    pub fn boot_before_answering(&self, data_dir: std::path::PathBuf) {
        self.shared.lock().unwrap().boot_before_answer = Some(data_dir);
    }

    pub fn calls(&self, method: &str) -> Vec<Call> {
        self.shared
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.method == method)
            .cloned()
            .collect()
    }
}

async fn serve(mut stream: TcpStream, shared: Arc<Mutex<Shared>>) -> anyhow::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).await?;
        anyhow::ensure!(read > 0, "connection closed before the headers ended");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let path = head
        .split("\r\n")
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .unwrap_or_default()
        .to_string();
    let header = |name: &str| {
        head.split("\r\n").skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    };
    let length: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + length {
        let read = stream.read(&mut chunk).await?;
        anyhow::ensure!(read > 0, "connection closed before the body ended");
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = serde_json::from_slice(&buffer[header_end..header_end + length])
        .unwrap_or(serde_json::Value::Null);
    let method = path
        .strip_prefix("/grund.capacity.v1.CapacityService/")
        .unwrap_or(&path)
        .to_string();
    let boot = {
        let shared = shared.lock().unwrap();
        (method == "ProvisionMachine")
            .then(|| shared.boot_before_answer.clone())
            .flatten()
    };
    if let Some(data_dir) = boot {
        let url = body["grundUrl"].as_str().unwrap_or_default().to_string();
        let token = body["enrollmentToken"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_grund"))
                .args(["join", "--url", &url, &token])
                .arg("--data-dir")
                .arg(data_dir)
                .env_clear()
                .env("RUST_LOG", "warn")
                .status()
        })
        .await??;
    }
    let (status, answer) = {
        let mut shared = shared.lock().unwrap();
        shared.calls.push(Call {
            method: method.clone(),
            authorization: header("authorization"),
            body,
        });
        let provisioned = shared
            .calls
            .iter()
            .filter(|c| c.method == "ProvisionMachine")
            .count();
        if shared.unavailable.contains(&method) {
            (
                503,
                serde_json::json!({"code": "unavailable", "message": "the provider is down"}),
            )
        } else {
            match method.as_str() {
                "ProvisionMachine" => (
                    200,
                    serde_json::json!({"providerMachineId": format!("fm-{provisioned}")}),
                ),
                "RebuildMachine" | "ReleaseMachine" => (200, serde_json::json!({})),
                _ => (404, serde_json::json!({"code": "unimplemented"})),
            }
        }
    };
    let text = answer.to_string();
    let response = format!(
        "HTTP/1.1 {status} Answer\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
        text.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}
