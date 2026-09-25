use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub const TOKEN: &str = "accept-insights-token-0123456789abcdef";

#[derive(Clone, Debug)]
pub struct Report {
    pub path: String,
    pub authorization: Option<String>,
    pub body: serde_json::Value,
}

#[derive(Default)]
struct Recorded {
    reports: Vec<Report>,
    answers: VecDeque<u16>,
}

pub struct FakeInsights {
    pub url: String,
    recorded: Arc<Mutex<Recorded>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeInsights {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeInsights {
    pub async fn start(answers: &[u16]) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let recorded = Arc::new(Mutex::new(Recorded {
            reports: Vec::new(),
            answers: answers.iter().copied().collect(),
        }));
        let shared = recorded.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let shared = shared.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, shared).await;
                });
            }
        });
        Ok(Self {
            url,
            recorded,
            task,
        })
    }

    pub fn reports(&self) -> Vec<Report> {
        self.recorded.lock().unwrap().reports.clone()
    }

    pub async fn wait_for(&self, count: usize, within: Duration) -> anyhow::Result<Vec<Report>> {
        let deadline = Instant::now() + within;
        loop {
            let reports = self.reports();
            if reports.len() >= count {
                return Ok(reports);
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "insights received {} report(s) within {within:?}, expected {count}",
                reports.len()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

async fn serve(mut stream: TcpStream, recorded: Arc<Mutex<Recorded>>) -> anyhow::Result<()> {
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
    let mut lines = head.split("\r\n");
    let path = lines
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
    let status = {
        let mut recorded = recorded.lock().unwrap();
        recorded.reports.push(Report {
            path,
            authorization: header("authorization"),
            body,
        });
        recorded.answers.pop_front().unwrap_or(201)
    };
    let response = format!(
        "HTTP/1.1 {status} Answer\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}
