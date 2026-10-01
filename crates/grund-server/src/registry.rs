//! Tag-to-digest resolution (grund-docs design/apps.md §3.1, §5.2): when a
//! release is made, grund asks the image's registry once what the
//! reference names, records the digest and the architectures it offers, and
//! machines only ever run that digest.
//!
//! The OCI distribution API, read-only: `GET /v2/<repository>/manifests/<tag
//! or digest>`, with the anonymous bearer token a registry hands out for a
//! public image (Docker Hub, GHCR) when it answers 401 with a
//! `WWW-Authenticate: Bearer` challenge. Registry credentials are not
//! supported yet: a private image is refused with that reason. A registry is
//! spoken to over HTTPS only, except the hosts `GRUND_INSECURE_REGISTRIES`
//! names (for tests).

use std::time::Duration;

use anyhow::Context;
use grund_domain::app::spec::{ImageReference, is_digest};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The largest manifest or config read.
pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

/// How long one registry call may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

/// What a reference resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// `sha256:…` of the manifest or index the reference names.
    pub digest: String,
    /// The Linux architectures it has a variant for, in grund's names
    /// (`x86_64`, `aarch64`), sorted.
    pub platforms: Vec<String>,
}

/// Why a reference did not resolve, in words for the person deploying.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("{0} has no such image or tag")]
    NotFound(String),
    #[error(
        "{0} asks for a login to pull this image; registry credentials are not supported yet, so use a public image"
    )]
    Unauthorized(String),
    #[error("{0} did not answer as a registry: {1}")]
    Unavailable(String, String),
    #[error("the manifest {0} sent does not match its digest")]
    DigestMismatch(String),
    #[error("the image has no Linux variant for x86_64 or aarch64 (it offers {0})")]
    Unsupported(String),
}

/// Resolves image references. Cheap to clone.
#[derive(Clone)]
pub struct Registry {
    http: reqwest::Client,
    insecure: Vec<String>,
}

#[derive(Deserialize)]
struct Index {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    #[serde(default)]
    manifests: Option<Vec<IndexEntry>>,
    #[serde(default)]
    config: Option<Descriptor>,
}

#[derive(Deserialize)]
struct IndexEntry {
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Deserialize)]
struct Descriptor {
    digest: String,
}

#[derive(Deserialize)]
struct Platform {
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
}

#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
}

#[derive(Deserialize)]
struct Token {
    #[serde(default)]
    token: String,
    #[serde(default)]
    access_token: String,
}

/// grund's name for an OCI architecture, for Linux only.
pub fn arch(os: &str, architecture: &str) -> Option<&'static str> {
    if os != "linux" {
        return None;
    }
    match architecture {
        "amd64" => Some("x86_64"),
        "arm64" => Some("aarch64"),
        _ => None,
    }
}

/// The parameters of a `WWW-Authenticate: Bearer realm="…",service="…"`
/// challenge.
pub fn bearer_challenge(header: &str) -> Option<(String, Vec<(String, String)>)> {
    let rest = header.trim().strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut params = Vec::new();
    let mut rest = rest.trim();
    while !rest.is_empty() {
        let (key, after) = rest.split_once('=')?;
        let after = after.trim_start();
        let (value, tail) = if let Some(quoted) = after.strip_prefix('"') {
            let end = quoted.find('"')?;
            (&quoted[..end], &quoted[end + 1..])
        } else {
            match after.find(',') {
                Some(end) => (&after[..end], &after[end..]),
                None => (after, ""),
            }
        };
        let key = key.trim().trim_start_matches(',').trim();
        if key == "realm" {
            realm = Some(value.to_string());
        } else {
            params.push((key.to_string(), value.to_string()));
        }
        rest = tail.trim_start_matches(',').trim();
    }
    Some((realm?, params))
}

impl Registry {
    pub fn new(insecure: Vec<String>) -> anyhow::Result<Self> {
        grund_tls::install_default();
        let http = reqwest::Client::builder()
            .timeout(CALL_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .user_agent(concat!("grund/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build the HTTP client for image registries")?;
        Ok(Self { http, insecure })
    }

    fn base(&self, registry: &str) -> String {
        let host = if registry == "docker.io" {
            "registry-1.docker.io"
        } else {
            registry
        };
        if self.insecure.iter().any(|h| h == registry) {
            format!("http://{host}")
        } else {
            format!("https://{host}")
        }
    }

    async fn get(
        &self,
        registry: &str,
        url: &str,
        token: &mut Option<String>,
        repository: &str,
    ) -> Result<(reqwest::header::HeaderMap, Vec<u8>), ResolveError> {
        let unavailable = |e: &dyn std::fmt::Display| {
            ResolveError::Unavailable(registry.to_string(), e.to_string())
        };
        for attempt in 0..2 {
            let mut request = self.http.get(url).header("Accept", ACCEPT);
            if let Some(token) = token.as_deref() {
                request = request.bearer_auth(token);
            }
            let response = request.send().await.map_err(|e| unavailable(&e))?;
            let status = response.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 && token.is_none() {
                let challenge = response
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .and_then(bearer_challenge)
                    .ok_or_else(|| ResolveError::Unauthorized(registry.to_string()))?;
                *token = Some(self.token(registry, challenge, repository).await?);
                continue;
            }
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(ResolveError::NotFound(registry.to_string()));
            }
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                return Err(ResolveError::Unauthorized(registry.to_string()));
            }
            if !status.is_success() {
                return Err(unavailable(&format!("HTTP {}", status.as_u16())));
            }
            let headers = response.headers().clone();
            let body = read_limited(response).await.map_err(|e| unavailable(&e))?;
            return Ok((headers, body));
        }
        Err(ResolveError::Unauthorized(registry.to_string()))
    }

    async fn token(
        &self,
        registry: &str,
        (realm, params): (String, Vec<(String, String)>),
        repository: &str,
    ) -> Result<String, ResolveError> {
        let unavailable = |e: &dyn std::fmt::Display| {
            ResolveError::Unavailable(registry.to_string(), e.to_string())
        };
        if !realm.starts_with("https://")
            && !self
                .insecure
                .iter()
                .any(|h| realm.starts_with(&format!("http://{h}/")))
        {
            return Err(unavailable(&"its token service is not HTTPS"));
        }
        let mut query: Vec<(String, String)> =
            params.into_iter().filter(|(k, _)| k == "service").collect();
        query.push(("scope".into(), format!("repository:{repository}:pull")));
        let query = serde_urlencoded::to_string(&query).map_err(|e| unavailable(&e))?;
        let separator = if realm.contains('?') { '&' } else { '?' };
        let response = self
            .http
            .get(format!("{realm}{separator}{query}"))
            .send()
            .await
            .map_err(|e| unavailable(&e))?;
        if !response.status().is_success() {
            return Err(ResolveError::Unauthorized(registry.to_string()));
        }
        let body = read_limited(response).await.map_err(|e| unavailable(&e))?;
        let token: Token = serde_json::from_slice(&body).map_err(|e| unavailable(&e))?;
        let token = if token.token.is_empty() {
            token.access_token
        } else {
            token.token
        };
        if token.is_empty() {
            return Err(ResolveError::Unauthorized(registry.to_string()));
        }
        Ok(token)
    }

    /// The digest and platforms `reference` names now.
    pub async fn resolve(&self, reference: &ImageReference) -> Result<Resolved, ResolveError> {
        let registry = reference.registry.as_str();
        let base = self.base(registry);
        let what = reference
            .digest
            .clone()
            .or_else(|| reference.tag.clone())
            .unwrap_or_else(|| "latest".into());
        let mut token = None;
        let url = format!("{base}/v2/{}/manifests/{what}", reference.repository);
        let (headers, body) = self
            .get(registry, &url, &mut token, &reference.repository)
            .await?;
        let computed = format!("sha256:{}", hex::encode(Sha256::digest(&body)));
        if let Some(pinned) = &reference.digest
            && *pinned != computed
        {
            return Err(ResolveError::DigestMismatch(registry.to_string()));
        }
        let announced = headers
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .filter(|d| is_digest(d));
        if announced.is_some_and(|d| d != computed) {
            return Err(ResolveError::DigestMismatch(registry.to_string()));
        }
        let index: Index = serde_json::from_slice(&body).map_err(|e| {
            ResolveError::Unavailable(
                registry.to_string(),
                format!("a manifest that does not parse: {e}"),
            )
        })?;
        let mut offered = Vec::new();
        let mut platforms = Vec::new();
        if let Some(entries) = &index.manifests {
            for platform in entries.iter().filter_map(|e| e.platform.as_ref()) {
                if platform.architecture == "unknown" {
                    continue;
                }
                offered.push(format!("{}/{}", platform.os, platform.architecture));
                if let Some(arch) = arch(&platform.os, &platform.architecture) {
                    platforms.push(arch.to_string());
                }
            }
        } else if let Some(config) = &index.config {
            let url = format!("{base}/v2/{}/blobs/{}", reference.repository, config.digest);
            let (_, body) = self
                .get(registry, &url, &mut token, &reference.repository)
                .await?;
            if format!("sha256:{}", hex::encode(Sha256::digest(&body))) != config.digest {
                return Err(ResolveError::DigestMismatch(registry.to_string()));
            }
            let config: Config = serde_json::from_slice(&body).map_err(|e| {
                ResolveError::Unavailable(
                    registry.to_string(),
                    format!("a config that does not parse: {e}"),
                )
            })?;
            offered.push(format!("{}/{}", config.os, config.architecture));
            if let Some(arch) = arch(&config.os, &config.architecture) {
                platforms.push(arch.to_string());
            }
        } else {
            return Err(ResolveError::Unavailable(
                registry.to_string(),
                format!("an unknown manifest type {:?}", index.media_type),
            ));
        }
        platforms.sort();
        platforms.dedup();
        if platforms.is_empty() {
            return Err(ResolveError::Unsupported(if offered.is_empty() {
                "nothing".into()
            } else {
                offered.join(", ")
            }));
        }
        Ok(Resolved {
            digest: computed,
            platforms,
        })
    }
}

async fn read_limited(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        body.extend_from_slice(&chunk);
        anyhow::ensure!(
            body.len() <= MAX_DOCUMENT_BYTES,
            "a document larger than 4 MiB"
        );
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bearer_challenge_gives_its_realm_and_service() {
        let (realm, params) = bearer_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull""#,
        )
        .unwrap();
        assert_eq!(realm, "https://auth.docker.io/token");
        assert_eq!(
            params,
            vec![
                ("service".to_string(), "registry.docker.io".to_string()),
                (
                    "scope".to_string(),
                    "repository:library/nginx:pull".to_string()
                ),
            ]
        );
        assert!(bearer_challenge("Basic realm=\"x\"").is_none());
    }

    #[test]
    fn only_linux_amd64_and_arm64_are_architectures_grund_runs() {
        assert_eq!(arch("linux", "amd64"), Some("x86_64"));
        assert_eq!(arch("linux", "arm64"), Some("aarch64"));
        assert_eq!(arch("windows", "amd64"), None);
        assert_eq!(arch("linux", "s390x"), None);
    }
}
