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
    private: HashMap<String, String>,
    logins: usize,
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
        self.publish_exposing(repository, tag, &[])
    }

    pub fn publish_exposing(&self, repository: &str, tag: &str, ports: &[&str]) -> String {
        let salt = super::random_hex(8);
        let exposed: serde_json::Map<String, serde_json::Value> = ports
            .iter()
            .map(|p| (p.to_string(), serde_json::json!({})))
            .collect();
        let mut blobs = Vec::new();
        let mut variant = |architecture: &str| {
            let config = serde_json::json!({
                "architecture": architecture, "os": "linux",
                "config": {"ExposedPorts": exposed, "Labels": {"salt": salt}},
            })
            .to_string()
            .into_bytes();
            let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config)));
            let manifest = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                           "digest": config_digest, "size": config.len()},
                "layers": [],
            })
            .to_string()
            .into_bytes();
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest)));
            blobs.push((config_digest, config));
            blobs.push((digest.clone(), manifest));
            digest
        };
        let amd64 = variant("amd64");
        let arm64 = variant("arm64");
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                 "digest": amd64, "size": 1, "platform": {"architecture": "amd64", "os": "linux"}},
                {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                 "digest": arm64, "size": 1, "platform": {"architecture": "arm64", "os": "linux"}},
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
        for (blob_digest, blob) in blobs {
            shared
                .by_digest
                .insert((repository.to_string(), blob_digest), blob);
        }
        digest
    }

    pub fn make_private(&self, repository: &str, username: &str, password: &str) {
        use base64::Engine;
        let login =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        self.shared
            .lock()
            .unwrap()
            .private
            .insert(repository.to_string(), login);
    }

    pub fn logins(&self) -> usize {
        self.shared.lock().unwrap().logins
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
    let authorization = head
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    let private_login = |repository: &str| shared.lock().unwrap().private.get(repository).cloned();
    let repository_of_path = |rest: &str| {
        rest.split_once("/manifests/")
            .or_else(|| rest.split_once("/blobs/"))
            .map(|(repository, _)| repository.to_string())
            .unwrap_or_default()
    };
    let authorized = |rest: &str| match private_login(&repository_of_path(rest)) {
        Some(login) => authorization == format!("Bearer {TOKEN}-{login}"),
        None => authorization.starts_with(&format!("Bearer {TOKEN}")),
    };
    let (status, headers, body): (u16, Vec<(String, String)>, Vec<u8>) =
        if let Some(query) = path.strip_prefix("/token?") {
            let scope = serde_urlencoded::from_str::<Vec<(String, String)>>(query)
                .unwrap_or_default()
                .into_iter()
                .find(|(k, _)| k == "scope")
                .map(|(_, v)| v)
                .unwrap_or_default();
            let repository = scope
                .strip_prefix("repository:")
                .and_then(|s| s.strip_suffix(":pull"))
                .unwrap_or_default()
                .to_string();
            let presented = authorization.strip_prefix("Basic ").map(str::to_string);
            match (private_login(&repository), presented) {
                (Some(login), Some(presented)) if presented == login => {
                    shared.lock().unwrap().logins += 1;
                    (
                        200,
                        vec![("content-type".into(), "application/json".into())],
                        serde_json::json!({"token": format!("{TOKEN}-{login}")})
                            .to_string()
                            .into_bytes(),
                    )
                }
                (_, Some(_)) => (401, Vec::new(), b"{}".to_vec()),
                (_, None) => (
                    200,
                    vec![("content-type".into(), "application/json".into())],
                    serde_json::json!({"token": TOKEN}).to_string().into_bytes(),
                ),
            }
        } else if let Some(rest) = path.strip_prefix("/v2/") {
            if !authorized(rest) {
                (
                    401,
                    vec![(
                        "www-authenticate".into(),
                        format!("Bearer realm=\"{realm}\",service=\"fake-registry\""),
                    )],
                    b"{}".to_vec(),
                )
            } else if let Some((repository, digest)) = rest.split_once("/blobs/") {
                let shared = shared.lock().unwrap();
                match shared
                    .by_digest
                    .get(&(repository.to_string(), digest.to_string()))
                    .cloned()
                {
                    Some(blob) => (
                        200,
                        vec![("content-type".into(), "application/octet-stream".into())],
                        blob,
                    ),
                    None => (404, Vec::new(), b"{}".to_vec()),
                }
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
