//! Logging in to a private registry for one pull (grund-docs design/apps.md
//! §6.5). Before a pull, the agent asks the instance for the organisation's
//! credential for the image's registry host (`GetPullCredential`, only for
//! a replica placed on this machine). With one, it asks the registry how to
//! log in, the way `docker login` does: a `Bearer` challenge gets a pull
//! token from the registry's token service with the login as HTTP Basic, a
//! `Basic` challenge gets the login itself. The runtime then sends the
//! resulting `Authorization` header with every request of the pull.
//!
//! The login travels only where the registry's own challenge points, and
//! only over HTTPS, except to a registry on this machine's loopback (which
//! containerd also speaks plain HTTP to). A token expires (Docker Hub's
//! after 5 minutes): a pull that outlasts it fails, and its retry logs in
//! again and resumes from the content already fetched. The credential is
//! never written to disk or to a log.

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use grund_domain::app::spec::ImageReference;
use serde::Deserialize;

/// The organisation's login to one registry host.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    pub host: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("host", &self.host)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

#[derive(Deserialize)]
struct Token {
    #[serde(default)]
    token: String,
    #[serde(default)]
    access_token: String,
}

/// Whether `host` (with or without a port) is this machine's loopback.
pub fn loopback(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        host.rsplit_once(':').map_or(host, |(name, _)| name)
    };
    name == "localhost"
        || name == "::1"
        || name
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Where a registry's API is: Docker Hub's real host for `docker.io`, and
/// plain HTTP only on loopback.
pub fn base(host: &str) -> String {
    let api = if host == "docker.io" {
        "registry-1.docker.io"
    } else {
        host
    };
    if loopback(host) {
        format!("http://{api}")
    } else {
        format!("https://{api}")
    }
}

/// The parameters of a `WWW-Authenticate: Bearer realm="…",service="…"`
/// challenge: its realm and the rest.
pub fn bearer_challenge(header: &str) -> Option<(String, Vec<(String, String)>)> {
    let rest = header.trim();
    let rest = rest
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("bearer "))
        .map(|_| &rest[7..])?;
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

/// The `Authorization` value of HTTP Basic for the credential.
pub fn basic(credential: &Credential) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", credential.username, credential.password))
    )
}

fn secure_enough(url: &str) -> bool {
    url.starts_with("https://")
        || url
            .strip_prefix("http://")
            .and_then(|rest| rest.split('/').next())
            .is_some_and(loopback)
}

/// The `Authorization` header to pull `reference` (pinned to `digest`)
/// with `credential`, or `None` when the registry asks for no login.
pub async fn authorization(
    http: &reqwest::Client,
    credential: &Credential,
    reference: &str,
    digest: &str,
) -> anyhow::Result<Option<String>> {
    let parsed = ImageReference::parse(reference)
        .map_err(|e| anyhow::anyhow!("the image reference does not parse: {}", e.problem))?;
    if parsed.registry != credential.host {
        bail!(
            "the credential is for {}, not for {}",
            credential.host,
            parsed.registry
        );
    }
    let host = &credential.host;
    let url = format!("{}/v2/{}/manifests/{digest}", base(host), parsed.repository);
    let response = http
        .get(&url)
        .header("Accept", ACCEPT)
        .send()
        .await
        .with_context(|| format!("reach {host}"))?;
    if response.status().is_success() {
        return Ok(None);
    }
    if response.status() != reqwest::StatusCode::UNAUTHORIZED {
        bail!("{host} answered HTTP {}", response.status().as_u16());
    }
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if let Some((realm, params)) = bearer_challenge(&challenge) {
        if !secure_enough(&realm) {
            bail!("{host}'s token service is not HTTPS");
        }
        let mut query: Vec<(String, String)> =
            params.into_iter().filter(|(k, _)| k == "service").collect();
        query.push((
            "scope".into(),
            format!("repository:{}:pull", parsed.repository),
        ));
        let query = serde_urlencoded::to_string(&query)?;
        let separator = if realm.contains('?') { '&' } else { '?' };
        let response = http
            .get(format!("{realm}{separator}{query}"))
            .basic_auth(&credential.username, Some(&credential.password))
            .send()
            .await
            .with_context(|| format!("reach {host}'s token service"))?;
        if !response.status().is_success() {
            bail!(
                "{host} refused the organisation's credential (HTTP {})",
                response.status().as_u16()
            );
        }
        let token: Token = response
            .json()
            .await
            .with_context(|| format!("{host}'s token service answered something else"))?;
        let token = if token.token.is_empty() {
            token.access_token
        } else {
            token.token
        };
        if token.is_empty() {
            bail!("{host} gave no token for the organisation's credential");
        }
        return Ok(Some(format!("Bearer {token}")));
    }
    let scheme_basic = challenge
        .get(..6)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("basic "));
    if scheme_basic {
        if !secure_enough(&url) {
            bail!("{host} asks for a password over plain HTTP");
        }
        return Ok(Some(basic(credential)));
    }
    bail!("{host} asks for a login grund does not know how to give")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_registries_are_spoken_to_in_plain_http() {
        assert_eq!(base("127.0.0.1:5000"), "http://127.0.0.1:5000");
        assert_eq!(base("localhost:5000"), "http://localhost:5000");
        assert_eq!(base("[::1]:5000"), "http://[::1]:5000");
        assert_eq!(base("ghcr.io"), "https://ghcr.io");
        assert_eq!(base("docker.io"), "https://registry-1.docker.io");
        assert_eq!(base("10.0.2.2:5000"), "https://10.0.2.2:5000");
        assert!(secure_enough("https://auth.docker.io/token"));
        assert!(secure_enough("http://127.0.0.1:5000/token"));
        assert!(!secure_enough("http://auth.example.com/token"));
    }

    #[test]
    fn a_bearer_challenge_gives_its_realm_and_service() {
        let (realm, params) = bearer_challenge(
            r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:acme/shop:pull""#,
        )
        .unwrap();
        assert_eq!(realm, "https://ghcr.io/token");
        assert_eq!(params[0], ("service".to_string(), "ghcr.io".to_string()));
        assert!(bearer_challenge(r#"Basic realm="Registry""#).is_none());
    }

    #[test]
    fn a_credential_is_sent_as_basic_and_never_printed() {
        let credential = Credential {
            host: "ghcr.io".into(),
            username: "acme".into(),
            password: "s3cret:token".into(),
        };
        assert_eq!(basic(&credential), "Basic YWNtZTpzM2NyZXQ6dG9rZW4=");
        assert!(!format!("{credential:?}").contains("s3cret"));
    }
}
