//! Machines: minting one-time enrollment tokens, enrolling a machine with
//! one, listing and revoking. The contract is grund/fleet's
//! docs/design/enrollment-contract.md: one path for the customer's own
//! hardware and for grund machines, which differ only in who minted the
//! token.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use grund_domain::{
    machine::{MachineCommand, MachineError, MachineFacts},
    names::MachineName,
    organisation::Role,
};
use grund_store::{
    machines::{self, MachineRow, NewToken},
    organisations::Membership,
    work::{Work, WorkError},
};
use uuid::Uuid;

use crate::{
    crypto,
    services::{
        accounts::RequestMeta,
        limits::{Limits, LimitsState},
    },
    state::State,
};

/// Every enrollment token starts with this, so scanners and log redaction
/// can find one.
pub const TOKEN_PREFIX: &str = "grund_enr_";
/// How long a token works when the minter does not say.
pub const DEFAULT_TOKEN_TTL: Duration = Duration::minutes(10);
/// The longest a token may work.
pub const MAX_TOKEN_TTL: Duration = Duration::minutes(15);
/// Unused tokens an organisation may hold at once.
pub const MAX_OPEN_TOKENS: i64 = 20;
/// Calls naming one token, replays included.
pub const MAX_TOKEN_USES: i32 = 5;
/// How far a machine's clock may be from grund's when it signs.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 300;
/// The domain every enrollment signature starts with.
pub const SIGNATURE_DOMAIN: &str = "grund-enroll-v1";
/// How often an enrolled machine reports.
pub const HEARTBEAT_INTERVAL_SECONDS: i32 = 30;

const TOKEN_LEN: usize = 10 + 52;

/// Makes a new enrollment token: the prefix and 32 random bytes in base32.
pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    format!("{TOKEN_PREFIX}{}", crypto::base32(&bytes))
}

/// What a machine signs to prove it holds its key, bound to this grund's
/// origin, the time and the token.
pub fn signed_message(origin: &str, signed_at_unix: i64, token: &str) -> Vec<u8> {
    let mut message = format!("{SIGNATURE_DOMAIN}\n{origin}\n{signed_at_unix}\n").into_bytes();
    message.extend_from_slice(&crypto::digest(token));
    message
}

/// How minting a token ended.
#[derive(Debug, PartialEq, Eq)]
pub enum MintOutcome {
    Minted {
        token: String,
        expires_at: DateTime<Utc>,
    },
    Invalid(String),
    NotAllowed,
    TooMany,
}

/// How revoking a machine ended.
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    Revoked,
    NotAllowed,
    NotFound,
}

/// What a machine asks with.
#[derive(Debug, Clone)]
pub struct Enrollment {
    pub token: String,
    pub public_key: Vec<u8>,
    pub signed_at_unix: i64,
    pub signature: Vec<u8>,
    pub facts: MachineFacts,
    pub requested_name: String,
}

/// What an enrolled machine is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    pub machine_id: Uuid,
    pub name: String,
    pub organisation_id: Uuid,
}

/// How an enrollment ended. `TokenInvalid` is one answer for an unknown,
/// expired, used or malformed token and a gone organisation, so a prober
/// learns nothing about which tokens exist.
#[derive(Debug, PartialEq, Eq)]
pub enum EnrollOutcome {
    Enrolled(Enrolled),
    TokenInvalid,
    ProofInvalid,
    RateLimited,
    NameTaken,
}

/// The machines service.
pub struct Machines {
    state: State,
    limits: Limits,
}

impl Machines {
    /// Mints a token for a new machine of `organisation`. Owners and admins.
    pub async fn mint(
        &self,
        actor: Uuid,
        organisation: &Membership,
        machine_name: &str,
        ttl_seconds: i32,
    ) -> anyhow::Result<MintOutcome> {
        if !Role::parse(&organisation.role).is_some_and(Role::manages_members) {
            return Ok(MintOutcome::NotAllowed);
        }
        let name = match machine_name.trim() {
            "" => None,
            given => match MachineName::parse(given) {
                Ok(name) => Some(name),
                Err(error) => return Ok(MintOutcome::Invalid(format!("machine_name: {error}"))),
            },
        };
        let ttl = match ttl_seconds {
            0 => DEFAULT_TOKEN_TTL,
            s if s > 0 && i64::from(s) <= MAX_TOKEN_TTL.num_seconds() => {
                Duration::seconds(i64::from(s))
            }
            _ => {
                return Ok(MintOutcome::Invalid(format!(
                    "ttl_seconds must be between 1 and {}",
                    MAX_TOKEN_TTL.num_seconds()
                )));
            }
        };
        let now = Utc::now();
        if machines::open_tokens(&self.state.pool, organisation.organisation_id, now).await?
            >= MAX_OPEN_TOKENS
        {
            return Ok(MintOutcome::TooMany);
        }
        let token = new_token();
        let expires_at = now + ttl;
        machines::insert_token(
            &self.state.pool,
            &NewToken {
                token_digest: &crypto::digest(&token),
                organisation_id: organisation.organisation_id,
                machine_name: name.as_ref().map(MachineName::as_str),
                minted_by: &format!("user:{actor}"),
                created_at: now,
                expires_at,
            },
        )
        .await?;
        Ok(MintOutcome::Minted { token, expires_at })
    }

    /// The organisation's machines.
    pub async fn list(&self, organisation_id: Uuid) -> Result<Vec<MachineRow>, sqlx::Error> {
        machines::list(&self.state.pool, organisation_id).await
    }

    /// Revokes a machine of `organisation`. Owners and admins.
    pub async fn revoke(
        &self,
        actor: Uuid,
        organisation: &Membership,
        machine_id: Uuid,
        meta: &RequestMeta,
    ) -> anyhow::Result<RevokeOutcome> {
        if machines::get(&self.state.pool, organisation.organisation_id, machine_id)
            .await?
            .is_none()
        {
            return Ok(RevokeOutcome::NotFound);
        }
        if !Role::parse(&organisation.role).is_some_and(Role::manages_members) {
            return Ok(RevokeOutcome::NotAllowed);
        }
        let mut work = Work::begin(&self.state.events, meta.request_id, "revoke-machine").await?;
        work.machine(
            machine_id,
            MachineCommand::Revoke {
                actor: Some(actor),
                at: Utc::now(),
            },
        )
        .await?;
        work.commit().await?;
        Ok(RevokeOutcome::Revoked)
    }

    /// Enrolls a machine: the proof first, then the token, which it consumes.
    /// A replay with the same token and key while the token would still be
    /// valid gets the same machine back.
    pub async fn enroll(
        &self,
        request: Enrollment,
        address: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<EnrollOutcome> {
        if !self.limits.admit_enroll_address(address).await? {
            return Ok(EnrollOutcome::RateLimited);
        }
        let now = Utc::now();
        if !self.proof_holds(&request, now) {
            return Ok(EnrollOutcome::ProofInvalid);
        }
        if request.token.len() != TOKEN_LEN || !request.token.starts_with(TOKEN_PREFIX) {
            return Ok(EnrollOutcome::TokenInvalid);
        }
        let digest = crypto::digest(&request.token);
        match machines::count_use(&self.state.pool, &digest).await? {
            None => return Ok(EnrollOutcome::TokenInvalid),
            Some(uses) if uses > MAX_TOKEN_USES => return Ok(EnrollOutcome::RateLimited),
            Some(_) => {}
        }
        let public_key = crypto::encode(&request.public_key);
        let mut work = Work::begin(&self.state.events, meta.request_id, "enroll-machine").await?;
        let Some(token) = machines::lock_token(work.sql(), &digest).await? else {
            return Ok(EnrollOutcome::TokenInvalid);
        };
        if token.expires_at <= now
            || !machines::organisation_live(&mut **work.sql(), token.organisation_id).await?
        {
            return Ok(EnrollOutcome::TokenInvalid);
        }
        if token.consumed_at.is_some() {
            let same_key = token
                .public_key
                .as_deref()
                .is_some_and(|k| crypto::constant_time_eq(k.as_bytes(), public_key.as_bytes()));
            let replayed = match (same_key, token.machine_id) {
                (true, Some(machine_id)) => {
                    machines::get(&mut **work.sql(), token.organisation_id, machine_id).await?
                }
                _ => None,
            };
            return Ok(match replayed {
                Some(machine) if machine.revoked_at.is_none() => {
                    EnrollOutcome::Enrolled(Enrolled {
                        machine_id: machine.machine_id,
                        name: machine.name,
                        organisation_id: machine.organisation_id,
                    })
                }
                _ => EnrollOutcome::TokenInvalid,
            });
        }
        let Some(name) = self
            .choose_name(&mut work, &token, &request, token.organisation_id)
            .await?
        else {
            return Ok(EnrollOutcome::NameTaken);
        };
        let machine_id = Uuid::now_v7();
        let enrolled = work
            .machine(
                machine_id,
                MachineCommand::Enroll {
                    organisation_id: token.organisation_id,
                    name: name.clone(),
                    public_key: public_key.clone(),
                    minted_by: token.minted_by.clone(),
                    facts: Box::new(request.facts),
                    at: now,
                },
            )
            .await;
        match enrolled {
            Ok(_) => {}
            Err(WorkError::Machine(MachineError::AlreadyEnrolled)) => {
                return Ok(EnrollOutcome::TokenInvalid);
            }
            Err(error) if key_taken(&error) => return Ok(EnrollOutcome::ProofInvalid),
            Err(error) => return Err(error.into()),
        }
        machines::consume_token(work.sql(), &digest, machine_id, &public_key, now).await?;
        match work.commit().await {
            Ok(()) => {}
            Err(error) if key_taken(&error) => return Ok(EnrollOutcome::ProofInvalid),
            Err(error) => return Err(error.into()),
        }
        Ok(EnrollOutcome::Enrolled(Enrolled {
            machine_id,
            name: name.to_string(),
            organisation_id: token.organisation_id,
        }))
    }

    fn proof_holds(&self, request: &Enrollment, now: DateTime<Utc>) -> bool {
        let Ok(key_bytes) = <[u8; 32]>::try_from(request.public_key.as_slice()) else {
            return false;
        };
        let Ok(signature_bytes) = <[u8; 64]>::try_from(request.signature.as_slice()) else {
            return false;
        };
        if (now.timestamp() - request.signed_at_unix).abs() > MAX_CLOCK_SKEW_SECONDS {
            return false;
        }
        let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
            return false;
        };
        let origin = self.state.config.public_origin().serialized;
        let message = signed_message(&origin, request.signed_at_unix, &request.token);
        key.verify(&message, &Signature::from_bytes(&signature_bytes))
            .is_ok()
    }

    async fn choose_name(
        &self,
        work: &mut Work<'_>,
        token: &machines::TokenRow,
        request: &Enrollment,
        organisation_id: Uuid,
    ) -> Result<Option<MachineName>, sqlx::Error> {
        if let Some(bound) = token
            .machine_name
            .as_deref()
            .and_then(|n| MachineName::parse(n).ok())
        {
            let taken =
                machines::name_taken(&mut **work.sql(), organisation_id, bound.as_str()).await?;
            return Ok((!taken).then_some(bound));
        }
        let base = MachineName::parse(&request.requested_name)
            .ok()
            .or_else(|| MachineName::suggest(&request.facts.hostname))
            .unwrap_or_else(|| MachineName::parse("machine").expect("a valid name"));
        if !machines::name_taken(&mut **work.sql(), organisation_id, base.as_str()).await? {
            return Ok(Some(base));
        }
        for n in 2..100 {
            let stem: String = base.as_str().chars().take(59).collect();
            let candidate = MachineName::parse(&format!("{}-{n}", stem.trim_end_matches('-')))
                .expect("a valid name");
            if !machines::name_taken(&mut **work.sql(), organisation_id, candidate.as_str()).await?
            {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }
}

fn key_taken(error: &WorkError) -> bool {
    error.unique_violation().as_deref() == Some("grund_machines_public_key_key")
}

/// Access to [`Machines`] from [`State`].
pub trait MachinesState {
    fn machines(&self) -> Machines;
}

impl MachinesState for State {
    fn machines(&self) -> Machines {
        Machines {
            state: self.clone(),
            limits: self.limits(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_the_prefix_and_52_base32_characters() {
        let token = new_token();
        assert_eq!(token.len(), TOKEN_LEN);
        assert!(token.starts_with(TOKEN_PREFIX));
        assert!(
            token[TOKEN_PREFIX.len()..]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        );
        assert_ne!(token, new_token());
    }

    #[test]
    fn the_signed_message_binds_origin_time_and_token() {
        let message = signed_message("https://grund.example", 1_790_000_000, "grund_enr_x");
        let text_end = message.len() - 32;
        assert_eq!(
            &message[..text_end],
            b"grund-enroll-v1\nhttps://grund.example\n1790000000\n"
        );
        assert_eq!(&message[text_end..], &crypto::digest("grund_enr_x"));
    }
}
