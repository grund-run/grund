//! `grund relay`s enrolled with this instance (grund-docs design/traffic.md
//! §5.7): the one-time tokens an operator mints for a relay host, the
//! enrollment that binds the relay's own Ed25519 key to that host, and the
//! signature every later call from the relay carries.
//!
//! A relay's identity is its key and nothing else: the host it may serve
//! comes from the token it enrolled with, never from a request. A host must
//! be in GRUND_RELAYS when the relay enrolls and on every call, so taking a
//! relay out of the list shuts it out without touching the database.
//!
//! The signature scheme is the control link's (`agents::request_message`),
//! under the header `x-grund-relay` instead of `x-grund-machine`: one scheme
//! to learn, and a relay id is never a machine id (they are different
//! tables), so neither can pass as the other.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use grund_store::relays::{self, RelayRow};
use uuid::Uuid;

use crate::{config::PublicOrigin, crypto, services::agents::request_message, state::State};

/// The prefix of an enrollment token.
pub const TOKEN_PREFIX: &str = "grund_relay_";

/// How long a minted token can be used.
pub const TOKEN_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// The purpose prefix of an enrollment proof.
pub const ENROLL_PREFIX: &str = "grund-relay-enroll-v1\n";

/// The relay a request is from, as its signature proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCaller {
    pub relay_id: Uuid,
    /// The host it serves: the host of its URL in GRUND_RELAYS.
    pub host: String,
}

/// What a relay sends to enroll.
#[derive(Debug, Clone)]
pub struct EnrollRequest {
    pub token: String,
    pub public_key: Vec<u8>,
    pub signed_at_unix: i64,
    pub signature: Vec<u8>,
    pub address: String,
}

/// How an enrollment ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollOutcome {
    Enrolled(RelayCaller),
    TokenInvalid,
    ProofInvalid,
    KeyReused,
    RateLimited,
}

/// The bytes a relay signs to enroll with a token whose SHA-256 is
/// `token_sha256_hex`.
pub fn enrollment_message(origin: &str, signed_at: i64, token_sha256_hex: &str) -> Vec<u8> {
    format!("{ENROLL_PREFIX}{origin}\n{signed_at}\n{token_sha256_hex}").into_bytes()
}

/// The hosts of GRUND_RELAYS: the only hosts a relay may enroll for.
pub fn listed_hosts(state: &State) -> Vec<String> {
    state
        .config
        .relay
        .relays
        .iter()
        .filter_map(|relay| PublicOrigin::parse(relay.url.trim_end_matches('/')))
        .map(|origin| origin.host)
        .collect()
}

/// Normalises a host an operator typed, refusing what cannot be a relay
/// URL's host.
pub fn parse_host(host: &str) -> anyhow::Result<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    anyhow::ensure!(
        !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && !host.starts_with(['.', '-'])
            && !host.ends_with(['.', '-']),
        "a relay host is a DNS name like relay.example.com, with no scheme or port: {host:?}"
    );
    Ok(host)
}

/// Mints a one-time token that enrolls one relay for `host` within
/// [`TOKEN_TTL`]. Only its digest is stored; the token is returned once.
pub async fn mint_token(pool: &sqlx::PgPool, host: &str) -> anyhow::Result<String> {
    let host = parse_host(host)?;
    let token = format!("{TOKEN_PREFIX}{}", crypto::random_token());
    relays::insert_token(
        pool,
        &crypto::digest(&token),
        &host,
        TOKEN_TTL.as_secs_f64(),
    )
    .await?;
    Ok(token)
}

fn verifying_key(bytes: &[u8]) -> Option<VerifyingKey> {
    <[u8; 32]>::try_from(bytes)
        .ok()
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
}

fn fresh(signed_at: i64, now: DateTime<Utc>) -> bool {
    DateTime::from_timestamp(signed_at, 0)
        .is_some_and(|at| (at - now).abs() <= grund_domain::machine::CLOCK_SKEW)
}

/// Relay enrollment and authentication.
#[derive(Clone)]
pub struct Relays {
    state: State,
}

impl Relays {
    /// Enrolls a relay under its key for the token's host, revoking the relay
    /// that host had. A token whose host is not in GRUND_RELAYS is invalid.
    pub async fn enroll(&self, request: EnrollRequest) -> anyhow::Result<EnrollOutcome> {
        use crate::services::LimitsState;
        if !self
            .state
            .limits()
            .admit_enroll_address(&request.address)
            .await?
        {
            return Ok(EnrollOutcome::RateLimited);
        }
        if !request.token.starts_with(TOKEN_PREFIX) || request.token.len() > 128 {
            return Ok(EnrollOutcome::TokenInvalid);
        }
        let now = Utc::now();
        let digest = crypto::digest(&request.token);
        let Some(key) = verifying_key(&request.public_key) else {
            return Ok(EnrollOutcome::ProofInvalid);
        };
        let proven = <[u8; 64]>::try_from(request.signature.as_slice())
            .ok()
            .filter(|_| fresh(request.signed_at_unix, now))
            .is_some_and(|signature| {
                key.verify_strict(
                    &enrollment_message(
                        &self.state.config.public_origin().serialized,
                        request.signed_at_unix,
                        &hex::encode(digest),
                    ),
                    &Signature::from_bytes(&signature),
                )
                .is_ok()
            });
        if !proven {
            return Ok(EnrollOutcome::ProofInvalid);
        }
        let mut tx = self.state.pool.begin().await?;
        let Some(token) = relays::token_for_update(&mut tx, &digest).await? else {
            return Ok(EnrollOutcome::TokenInvalid);
        };
        if token.expires_at <= now || !listed_hosts(&self.state).contains(&token.host) {
            return Ok(EnrollOutcome::TokenInvalid);
        }
        if let Some(relay_id) = token.relay_id {
            return Ok(
                if token.consumed_key.as_deref() == Some(&request.public_key[..]) {
                    EnrollOutcome::Enrolled(RelayCaller {
                        relay_id,
                        host: token.host,
                    })
                } else {
                    EnrollOutcome::TokenInvalid
                },
            );
        }
        if relays::key_known(&mut *tx, &request.public_key).await? {
            return Ok(EnrollOutcome::KeyReused);
        }
        let relay_id = Uuid::now_v7();
        relays::enroll(&mut tx, &digest, relay_id, &token.host, &request.public_key).await?;
        tx.commit().await?;
        tracing::info!(%relay_id, host = %token.host, "relay enrolled");
        Ok(EnrollOutcome::Enrolled(RelayCaller {
            relay_id,
            host: token.host,
        }))
    }

    /// The relay that signed this request, or `None` for a missing, stale or
    /// wrong signature, an unknown relay, a revoked one and one whose host
    /// left GRUND_RELAYS alike.
    pub async fn authenticate(
        &self,
        relay: &str,
        signed_at: &str,
        signature: &str,
        path: &str,
        body: &[u8],
    ) -> anyhow::Result<Option<RelayCaller>> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let (Ok(relay_id), Ok(signed_at)) = (Uuid::parse_str(relay), signed_at.parse::<i64>())
        else {
            return Ok(None);
        };
        if !fresh(signed_at, Utc::now()) {
            return Ok(None);
        }
        let Some(signature) = STANDARD
            .decode(signature)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
        else {
            return Ok(None);
        };
        let Some(RelayRow {
            host,
            public_key,
            state,
            ..
        }) = relays::relay(&self.state.pool, relay_id).await?
        else {
            return Ok(None);
        };
        let Some(key) = verifying_key(&public_key) else {
            return Ok(None);
        };
        if state != "active"
            || !listed_hosts(&self.state).contains(&host)
            || key
                .verify_strict(
                    &request_message(path, signed_at, body),
                    &Signature::from_bytes(&signature),
                )
                .is_err()
        {
            return Ok(None);
        }
        Ok(Some(RelayCaller { relay_id, host }))
    }
}

/// Relay enrollment and authentication.
pub trait RelaysState {
    fn relays(&self) -> Relays;
}

impl RelaysState for State {
    fn relays(&self) -> Relays {
        Relays {
            state: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relay_host_is_a_bare_dns_name() {
        assert_eq!(
            parse_host(" Relay.Example.com. ").unwrap(),
            "relay.example.com"
        );
        for bad in [
            "https://relay.example.com",
            "relay.example.com:443",
            "",
            "-a.b",
            "a b",
        ] {
            assert!(parse_host(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_enrollment_proof_binds_the_origin_the_time_and_the_token() {
        let message = enrollment_message("https://grund.example.com", 1700000000, "ab");
        assert_eq!(
            message,
            b"grund-relay-enroll-v1\nhttps://grund.example.com\n1700000000\nab".to_vec()
        );
    }
}
