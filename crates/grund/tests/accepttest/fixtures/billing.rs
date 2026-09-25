use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub const TOKEN: &str = "accept-billing-token-0123456789abcdef";

pub const MANAGE_URL: &str = "https://billing.accept.test/manage";

#[derive(Clone, Debug)]
pub struct Call {
    pub method: String,
    pub authorization: Option<String>,
    pub body: serde_json::Value,
}

#[derive(Clone, Debug)]
pub enum DeletionAnswer {
    Allow,
    Refuse(&'static str),
    Unavailable,
}

struct Shared {
    calls: Vec<Call>,
    deletion: DeletionAnswer,
}

pub struct FakeBilling {
    pub url: String,
    shared: Arc<Mutex<Shared>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeBilling {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeBilling {
    pub async fn start(deletion: DeletionAnswer) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let shared = Arc::new(Mutex::new(Shared {
            calls: Vec::new(),
            deletion,
        }));
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

    pub fn answer_deletions(&self, answer: DeletionAnswer) {
        self.shared.lock().unwrap().deletion = answer;
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

    pub async fn wait_for(
        &self,
        method: &str,
        count: usize,
        within: Duration,
    ) -> anyhow::Result<Vec<Call>> {
        let deadline = Instant::now() + within;
        loop {
            let calls = self.calls(method);
            if calls.len() >= count {
                return Ok(calls);
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "billing received {} {method} call(s) within {within:?}, expected {count}",
                calls.len()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
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
        .strip_prefix("/grund.billing.v1.BillingService/")
        .unwrap_or(&path)
        .to_string();
    let (status, answer) = {
        let mut shared = shared.lock().unwrap();
        shared.calls.push(Call {
            method: method.clone(),
            authorization: header("authorization"),
            body,
        });
        match method.as_str() {
            "GetAccount" => (
                200,
                serde_json::json!({
                    "account": {"plan": "Pro", "status": "ACCOUNT_STATUS_ACTIVE", "manageUrl": MANAGE_URL}
                }),
            ),
            "CheckDeletion" => match &shared.deletion {
                DeletionAnswer::Allow => (200, serde_json::json!({"allowed": true})),
                DeletionAnswer::Refuse(reason) => {
                    (200, serde_json::json!({"allowed": false, "reason": reason}))
                }
                DeletionAnswer::Unavailable => (503, serde_json::json!({"code": "unavailable"})),
            },
            "RecordOrganisation" => (200, serde_json::json!({})),
            _ => (404, serde_json::json!({"code": "unimplemented"})),
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
