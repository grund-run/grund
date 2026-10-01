use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const TOKEN: &str = "fake-registry-token";

#[derive(Default)]
struct Shared {
    tags: HashMap<(String, String), Vec<u8>>,
    by_digest: HashMap<(String, String), Vec<u8>>,
    manifest_calls: usize,
}

pub struct FakeRegistry {
    pub host: String,
    shared: Arc<Mutex<Shared>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeRegistry {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeRegistry {
    pub async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let host = listener.local_addr()?.to_string();
        let shared = Arc::new(Mutex::new(Shared::default()));
        let handle = shared.clone();
        let realm = format!("http://{host}/token");
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handle = handle.clone();
                let realm = realm.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, handle, &realm).await;
                });
            }
        });
        Ok(Self { host, shared, task })
    }

    pub fn publish(&self, repository: &str, tag: &str) -> String {
        let salt = super::random_hex(8);
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                 "digest": format!("sha256:{}", hex::encode(Sha256::digest(format!("amd64-{salt}")))),
                 "size": 1, "platform": {"architecture": "amd64", "os": "linux"}},
                {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                 "digest": format!("sha256:{}", hex::encode(Sha256::digest(format!("arm64-{salt}")))),
                 "size": 1, "platform": {"architecture": "arm64", "os": "linux"}},
                {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                 "digest": format!("sha256:{}", hex::encode(Sha256::digest(format!("att-{salt}")))),
                 "size": 1, "platform": {"architecture": "unknown", "os": "unknown"}}
            ]
        })
        .to_string()
        .into_bytes();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&index)));
        let mut shared = self.shared.lock().unwrap();
        shared
            .tags
            .insert((repository.to_string(), tag.to_string()), index.clone());
        shared
            .by_digest
            .insert((repository.to_string(), digest.clone()), index);
        digest
    }

    pub fn image(&self, repository: &str, tag: &str) -> String {
        format!("{}/{repository}:{tag}", self.host)
    }

    pub fn manifest_calls(&self) -> usize {
        self.shared.lock().unwrap().manifest_calls
    }
}

async fn serve(
    mut stream: TcpStream,
    shared: Arc<Mutex<Shared>>,
    realm: &str,
) -> anyhow::Result<()> {
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
    let authorized = head.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("authorization") && v.trim() == format!("Bearer {TOKEN}")
        })
    });
    let (status, headers, body): (u16, Vec<(String, String)>, Vec<u8>) =
        if path.starts_with("/token?") {
            (
                200,
                vec![("content-type".into(), "application/json".into())],
                serde_json::json!({"token": TOKEN}).to_string().into_bytes(),
            )
        } else if let Some(rest) = path.strip_prefix("/v2/") {
            if !authorized {
                (
                    401,
                    vec![(
                        "www-authenticate".into(),
                        format!("Bearer realm=\"{realm}\",service=\"fake-registry\""),
                    )],
                    b"{}".to_vec(),
                )
            } else if let Some((repository, reference)) = rest.split_once("/manifests/") {
                let mut shared = shared.lock().unwrap();
                shared.manifest_calls += 1;
                let key = (repository.to_string(), reference.to_string());
                match shared
                    .tags
                    .get(&key)
                    .or_else(|| shared.by_digest.get(&key))
                    .cloned()
                {
                    Some(index) => (
                        200,
                        vec![
                            (
                                "content-type".into(),
                                "application/vnd.oci.image.index.v1+json".into(),
                            ),
                            (
                                "docker-content-digest".into(),
                                format!("sha256:{}", hex::encode(Sha256::digest(&index))),
                            ),
                        ],
                        index,
                    ),
                    None => (404, Vec::new(), b"{}".to_vec()),
                }
            } else {
                (404, Vec::new(), b"{}".to_vec())
            }
        } else {
            (404, Vec::new(), b"{}".to_vec())
        };
    let mut response = format!("HTTP/1.1 {status} Answer\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    ));
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;
    Ok(())
}
