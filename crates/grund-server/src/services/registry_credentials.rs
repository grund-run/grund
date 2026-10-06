//! Registry credentials (grund-docs design/apps.md §6.5): an organisation's
//! login to a private image registry, one per registry host, as an
//! organisation secret.
//!
//! The password is sealed (AES-256-GCM under `secret.derive("registry-
//! credentials")`, bound to the organisation, host, username and version)
//! before it reaches PostgreSQL, and opened only to resolve a tag when a
//! release is made ([`crate::registry::Registry::with_credential`]) and for
//! the agent of a machine that pulls an image of one of the organisation's
//! replicas placed on it (`AgentService.GetPullCredential`,
//! [`RegistryCredentials::for_replica`]). It never
//! enters an event, a release, a signed document, a page or a log line.

use anyhow::Context;
use grund_domain::{app::spec::ImageReference, organisation::Role};
use grund_store::{
    organisations::Membership,
    registry_credentials::{self, CredentialView, SealedCredential},
};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use uuid::Uuid;

use crate::{services::agents::MachineCaller, state::State};

/// Credentials one organisation may hold.
pub const MAX_PER_ORGANISATION: i64 = 20;

/// The longest password or registry token accepted, in bytes: cloud
/// registries' short-lived tokens run to a few KiB.
pub const MAX_PASSWORD_BYTES: usize = 8192;

/// The longest username accepted, in characters.
pub const MAX_USERNAME_CHARS: usize = 256;

/// A login to one registry, opened.
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

/// Why a credential was not set or removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NotAllowed,
    Invalid {
        field: &'static str,
        problem: String,
    },
    TooMany,
}

/// The registry host as image references name it: lowercase, no scheme or
/// path, and Docker Hub's other names folded into `docker.io`, the name an
/// image without a host gets.
pub fn normalize_host(text: &str) -> Result<String, String> {
    let text = text.trim().to_ascii_lowercase();
    let text = text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"))
        .unwrap_or(&text);
    let text = text.trim_end_matches('/');
    if text.contains('/') {
        return Err("Give the registry's host only, such as ghcr.io or registry.example.com:5000, without a path.".into());
    }
    let host = match text {
        "index.docker.io"
        | "registry-1.docker.io"
        | "registry.hub.docker.com"
        | "hub.docker.com" => "docker.io",
        other => other,
    };
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    let name_ok = !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric());
    let port_ok = port.is_none_or(|p| p.parse::<u16>().is_ok_and(|p| p > 0));
    if !name_ok || !port_ok {
        return Err(
            "That is not a registry host, such as ghcr.io or registry.example.com:5000.".into(),
        );
    }
    Ok(host.to_string())
}

fn sealing_key(state: &State) -> LessSafeKey {
    let key = state.secret.derive("registry-credentials");
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).expect("a 32-byte AES-256 key"))
}

fn aad(organisation_id: Uuid, host: &str, username: &str, version: i32) -> Vec<u8> {
    format!("grund-registry-credential-v1\n{organisation_id}\n{host}\n{version}\n{username}")
        .into_bytes()
}

fn seal(
    key: &LessSafeKey,
    organisation_id: Uuid,
    host: &str,
    username: &str,
    version: i32,
    password: &[u8],
) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).expect("the system's random source");
    let mut sealed = password.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad(organisation_id, host, username, version)),
        &mut sealed,
    )
    .expect("sealing a value within AES-GCM's limits");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&sealed);
    out
}

fn open(key: &LessSafeKey, sealed: &SealedCredential) -> Option<Credential> {
    let bytes = &sealed.sealed_password;
    if bytes.len() < 12 + 16 {
        return None;
    }
    let (nonce, rest) = bytes.split_at(12);
    let mut buffer = rest.to_vec();
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let plain = key
        .open_in_place(
            nonce,
            Aad::from(aad(
                sealed.organisation_id,
                &sealed.host,
                &sealed.username,
                sealed.version,
            )),
            &mut buffer,
        )
        .ok()?;
    Some(Credential {
        host: sealed.host.clone(),
        username: sealed.username.clone(),
        password: String::from_utf8(plain.to_vec()).ok()?,
    })
}

fn manages(membership: &Membership) -> bool {
    Role::parse(&membership.role).is_some_and(Role::manages_members)
}

/// Sets, removes, lists and opens registry credentials.
#[derive(Clone)]
pub struct RegistryCredentials {
    state: State,
}

impl RegistryCredentials {
    /// Sets the organisation's credential for `host`, replacing any before
    /// it. Owners and admins only.
    pub async fn set(
        &self,
        actor: Uuid,
        membership: &Membership,
        host: &str,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Result<String, Refusal>> {
        if !manages(membership) {
            return Ok(Err(Refusal::NotAllowed));
        }
        let host = match normalize_host(host) {
            Ok(host) => host,
            Err(problem) => {
                return Ok(Err(Refusal::Invalid {
                    field: "host",
                    problem,
                }));
            }
        };
        let username = username.trim();
        if username.is_empty()
            || username.chars().count() > MAX_USERNAME_CHARS
            || username.chars().any(char::is_control)
        {
            return Ok(Err(Refusal::Invalid {
                field: "username",
                problem: format!(
                    "Give the username the registry knows, up to {MAX_USERNAME_CHARS} characters."
                ),
            }));
        }
        if password.is_empty()
            || password.len() > MAX_PASSWORD_BYTES
            || password.chars().any(char::is_control)
        {
            return Ok(Err(Refusal::Invalid {
                field: "password",
                problem: format!(
                    "Give the password or access token, up to {MAX_PASSWORD_BYTES} bytes."
                ),
            }));
        }
        let organisation_id = membership.organisation_id;
        let mut tx = self.state.pool.begin().await?;
        let Some(version) = registry_credentials::next_version(
            &mut tx,
            organisation_id,
            &host,
            MAX_PER_ORGANISATION,
        )
        .await?
        else {
            return Ok(Err(Refusal::TooMany));
        };
        let sealed = seal(
            &sealing_key(&self.state),
            organisation_id,
            &host,
            username,
            version,
            password.as_bytes(),
        );
        registry_credentials::put(
            &mut tx,
            &SealedCredential {
                organisation_id,
                host: host.clone(),
                username: username.to_string(),
                sealed_password: sealed,
                version,
            },
            actor,
        )
        .await?;
        tx.commit().await?;
        tracing::info!(
            organisation = %organisation_id,
            host = %host,
            version,
            account = %actor,
            "registry credential set"
        );
        Ok(Ok(host))
    }

    /// Removes the organisation's credential for `host`. Owners and admins
    /// only. `Ok(false)` when there is none.
    pub async fn remove(
        &self,
        actor: Uuid,
        membership: &Membership,
        host: &str,
    ) -> anyhow::Result<Result<bool, Refusal>> {
        if !manages(membership) {
            return Ok(Err(Refusal::NotAllowed));
        }
        let Ok(host) = normalize_host(host) else {
            return Ok(Ok(false));
        };
        let removed =
            registry_credentials::remove(&self.state.pool, membership.organisation_id, &host)
                .await?;
        if removed {
            tracing::info!(
                organisation = %membership.organisation_id,
                host = %host,
                account = %actor,
                "registry credential removed"
            );
        }
        Ok(Ok(removed))
    }

    /// The organisation's credentials, without their passwords.
    pub async fn list(&self, organisation_id: Uuid) -> anyhow::Result<Vec<CredentialView>> {
        Ok(registry_credentials::list(&self.state.pool, organisation_id).await?)
    }

    /// The organisation's credential for `host`, opened, to resolve an
    /// image.
    pub async fn for_organisation(
        &self,
        organisation_id: Uuid,
        host: &str,
    ) -> anyhow::Result<Option<Credential>> {
        let Some(sealed) =
            registry_credentials::for_host(&self.state.pool, organisation_id, host).await?
        else {
            return Ok(None);
        };
        open(&sealing_key(&self.state), &sealed)
            .map(Some)
            .context("a stored registry credential does not open with this instance's key")
    }

    /// The credential a machine pulls a replica's image with: `None` when
    /// the replica is not placed on the calling machine (whether it exists
    /// or not), `Some(None)` when its organisation has no credential for
    /// the image's registry host.
    pub async fn for_replica(
        &self,
        caller: &MachineCaller,
        replica_id: Uuid,
    ) -> anyhow::Result<Option<Option<Credential>>> {
        let Some(placed) =
            grund_store::apps::placed_replica(&self.state.pool, caller.machine_id, replica_id)
                .await?
        else {
            return Ok(None);
        };
        let Ok(reference) = ImageReference::parse(&placed.spec.0.image) else {
            return Ok(Some(None));
        };
        let Some(sealed) =
            registry_credentials::for_app(&self.state.pool, placed.app_id, &reference.registry)
                .await?
        else {
            return Ok(Some(None));
        };
        open(&sealing_key(&self.state), &sealed)
            .map(|c| Some(Some(c)))
            .context("a stored registry credential does not open with this instance's key")
    }
}

/// Access to [`RegistryCredentials`] from [`State`].
pub trait RegistryCredentialsState {
    fn registry_credentials(&self) -> RegistryCredentials;
}

impl RegistryCredentialsState for State {
    fn registry_credentials(&self) -> RegistryCredentials {
        RegistryCredentials {
            state: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_is_normalised_the_way_image_references_name_it() {
        assert_eq!(normalize_host(" GHCR.io ").unwrap(), "ghcr.io");
        assert_eq!(normalize_host("https://ghcr.io/").unwrap(), "ghcr.io");
        assert_eq!(
            normalize_host("registry.example.com:5000").unwrap(),
            "registry.example.com:5000"
        );
        for hub in ["index.docker.io", "registry-1.docker.io", "docker.io"] {
            assert_eq!(normalize_host(hub).unwrap(), "docker.io");
        }
        for bad in [
            "",
            "ghcr.io/acme",
            "-bad.example",
            "host:0",
            "host:99999",
            "user@host",
            "spa ce",
        ] {
            assert!(normalize_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_sealed_password_opens_only_for_its_organisation_host_username_and_version() {
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[7u8; 32]).unwrap());
        let organisation_id = Uuid::now_v7();
        let sealed = SealedCredential {
            organisation_id,
            host: "ghcr.io".into(),
            username: "acme".into(),
            sealed_password: seal(
                &key,
                organisation_id,
                "ghcr.io",
                "acme",
                3,
                b"hunter2-token",
            ),
            version: 3,
        };
        assert_eq!(open(&key, &sealed).unwrap().password, "hunter2-token");
        let moved = [
            SealedCredential {
                organisation_id: Uuid::now_v7(),
                ..sealed.clone()
            },
            SealedCredential {
                host: "docker.io".into(),
                ..sealed.clone()
            },
            SealedCredential {
                username: "other".into(),
                ..sealed.clone()
            },
            SealedCredential {
                version: 4,
                ..sealed.clone()
            },
        ];
        for moved in moved {
            assert!(open(&key, &moved).is_none(), "{moved:?}");
        }
    }

    #[test]
    fn a_credential_never_prints_its_password() {
        let credential = Credential {
            host: "ghcr.io".into(),
            username: "acme".into(),
            password: "hunter2-token".into(),
        };
        assert!(!format!("{credential:?}").contains("hunter2"));
    }
}
