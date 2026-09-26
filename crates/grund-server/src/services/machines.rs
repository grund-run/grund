//! Machines (grund-docs design/machines.md): registration tokens, enrollment,
//! the management pool the operator organisation runs, leases, and each
//! organisation's own pool. The rules of a machine's life are the
//! aggregate's (grund-domain `machine`); this decides who may ask, and
//! writes the rows and keys that go with its events.

use buffa::Message;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use grund_domain::{
    machine::{
        Authority, KeyPurpose, MAX_MACHINES_PER_ORGANISATION, MAX_OPEN_TOKENS, MAX_REPLAYS,
        MachineCommand, MachineError, MachineFacts, MachineKey, Pool, TOKEN_TTL, TOKEN_TTL_MAX,
        TokenKind, enrollment_message, prefix,
    },
    names::MachineName,
    organisation::Role,
};
use grund_proto::grund::agent::v1 as agent;
use grund_store::{
    machines::{self, MachineRow, NewToken, TokenRow},
    organisations,
    work::{Work, WorkError},
};
use uuid::Uuid;

use crate::{
    config::OrganisationMode,
    crypto,
    keys::{Keys, KeysState, PublicKey},
    services::limits::LimitsState,
    state::State,
};

/// How often a registered machine is asked to report, once the control link
/// exists.
pub const HEARTBEAT_INTERVAL_SECONDS: i32 = 5;

/// The shortest lifetime a minted token may be given.
pub const TOKEN_TTL_MIN: Duration = Duration::seconds(60);

/// What the caller may do with a pool, from their membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Owners and admins: mint, lease, revoke.
    Manage,
    /// Members: list and get.
    Read,
}

impl Access {
    fn of(role: &str) -> Option<Access> {
        Some(match Role::parse(role)? {
            Role::Owner | Role::Admin => Access::Manage,
            Role::Member => Access::Read,
        })
    }
}

/// A minted token, shown once.
#[derive(Debug, Clone)]
pub struct Minted {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// How minting ended.
#[derive(Debug)]
pub enum MintOutcome {
    Minted(Minted),
    /// A name or lifetime the caller gave is not acceptable.
    Invalid(String),
    TooMany,
    /// A re-registration token for a machine that is not returning.
    NotReturning,
    NotFound,
}

/// A machine's registration, as the enrolling machine is told.
#[derive(Debug, Clone)]
pub struct Enrollment {
    pub machine_id: Uuid,
    pub name: String,
    pub pool: Pool,
    pub instance_key: PublicKey,
    pub trust_key: PublicKey,
}

/// What a machine sent to register.
#[derive(Debug, Clone)]
pub struct EnrollRequest {
    pub token: String,
    pub machine_public_key: Vec<u8>,
    pub signed_at_unix: i64,
    pub signature: Vec<u8>,
    pub facts: MachineFacts,
    pub requested_name: String,
    pub address: String,
}

/// How a registration ended.
#[derive(Debug)]
pub enum EnrollOutcome {
    Enrolled(Enrollment),
    /// Unknown, used, expired or malformed, or its organisation is gone: one
    /// answer for all of them.
    TokenInvalid,
    ProofInvalid,
    MachineLimit,
    NameTaken,
    NameInvalid(String),
    /// The key is some live machine's already, or this machine's before.
    KeyReused,
    RateLimited,
}

/// A lease grant the management key signed.
#[derive(Debug, Clone)]
pub struct SignedGrant {
    pub key_id: Uuid,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}

/// How a change to a machine ended.
#[derive(Debug)]
pub enum ChangeOutcome {
    Done(MachineRow),
    Leased(MachineRow, SignedGrant),
    NotFound,
    NoOrganisation,
    NotAvailable,
    NotLeased,
    NotAllowed,
    PoolFull,
    NameTaken,
    NameInvalid(String),
}

/// Machine flows.
#[derive(Clone)]
pub struct Machines {
    state: State,
}

impl Machines {
    fn keys(&self) -> Keys {
        self.state.keys()
    }

    /// The operator organisation: GRUND_OPERATOR_ORGANISATION (an id, or a
    /// slug), else the instance's organisation in `single` mode. `None`: no
    /// management pool.
    pub async fn operator(&self) -> anyhow::Result<Option<Uuid>> {
        if let Some(named) = &self.state.config.operator_organisation {
            if let Ok(organisation_id) = Uuid::parse_str(named) {
                return Ok(
                    machines::organisation_live(&self.state.pool, organisation_id)
                        .await?
                        .then_some(organisation_id),
                );
            }
            return Ok(machines::live_organisation_by_slug(&self.state.pool, named).await?);
        }
        Ok(match self.state.config.organisations {
            OrganisationMode::Single => organisations::instance(&self.state.pool).await?,
            OrganisationMode::Multi => None,
        })
    }

    /// What `account_id` may do with the management pool; `None` when it is
    /// not a member of the operator organisation, or there is none.
    pub async fn operator_access(&self, account_id: Uuid) -> anyhow::Result<Option<Access>> {
        let Some(operator) = self.operator().await? else {
            return Ok(None);
        };
        Ok(machines::role_in(&self.state.pool, operator, account_id)
            .await?
            .and_then(|role| Access::of(&role)))
    }

    /// Mints a one-time token for one pool. `kind` says which: management
    /// (optionally bound to a returning `machine_id`) or an organisation's.
    pub async fn mint(
        &self,
        kind: TokenKind,
        organisation_id: Option<Uuid>,
        machine_id: Option<Uuid>,
        name: &str,
        ttl_seconds: i32,
        minted_by: Uuid,
    ) -> anyhow::Result<MintOutcome> {
        let ttl = match ttl_seconds {
            0 => TOKEN_TTL,
            s if s < 0 => {
                return Ok(MintOutcome::Invalid(
                    "ttl_seconds must not be negative".into(),
                ));
            }
            s => Duration::seconds(i64::from(s)),
        };
        if ttl < TOKEN_TTL_MIN || ttl > TOKEN_TTL_MAX {
            return Ok(MintOutcome::Invalid(format!(
                "a token lives between {} and {} seconds",
                TOKEN_TTL_MIN.num_seconds(),
                TOKEN_TTL_MAX.num_seconds()
            )));
        }
        let name = match name.trim() {
            "" => None,
            text => match MachineName::parse(text) {
                Ok(name) => Some(name),
                Err(error) => return Ok(MintOutcome::Invalid(format!("name: {error}"))),
            },
        };
        if let Some(machine_id) = machine_id {
            match machines::machine(&self.state.pool, machine_id).await? {
                Some(row) if row.pool == "management" && row.state == "returning" => {}
                Some(row) if row.pool == "management" => return Ok(MintOutcome::NotReturning),
                _ => return Ok(MintOutcome::NotFound),
            }
        }
        let now = Utc::now();
        if machines::open_tokens(&self.state.pool, kind.as_str(), organisation_id, now).await?
            >= MAX_OPEN_TOKENS
        {
            return Ok(MintOutcome::TooMany);
        }
        let token = format!("{}{}", kind.prefix(), base32(&random_bytes()));
        let expires_at = now + ttl;
        machines::insert_token(
            &self.state.pool,
            &NewToken {
                token_id: Uuid::now_v7(),
                digest: crypto::digest(&token),
                kind: kind.as_str(),
                organisation_id,
                machine_id,
                name: name.as_ref().map(MachineName::as_str),
                minted_by: &format!("account:{minted_by}"),
                expires_at,
            },
        )
        .await?;
        Ok(MintOutcome::Minted(Minted { token, expires_at }))
    }

    /// Registers a machine with a one-time token (the contract's
    /// `EnrollMachine`). The proof is checked before the token is looked up,
    /// and the token is consumed only by a registration that commits.
    pub async fn enroll(&self, request: EnrollRequest) -> anyhow::Result<EnrollOutcome> {
        if !self
            .state
            .limits()
            .admit_enroll_address(&request.address)
            .await?
        {
            return Ok(EnrollOutcome::RateLimited);
        }
        let Some(kind) = TokenKind::of(&request.token) else {
            return Ok(EnrollOutcome::TokenInvalid);
        };
        let Some(key) = MachineKey::from_bytes(&request.machine_public_key) else {
            return Ok(EnrollOutcome::ProofInvalid);
        };
        let now = Utc::now();
        let digest = crypto::digest(&request.token);
        if !proof_holds(
            &self.state.config.public_origin().serialized,
            &request,
            &hex::encode(digest),
            now,
        ) {
            return Ok(EnrollOutcome::ProofInvalid);
        }

        let mut work =
            Work::begin(&self.state.events, Uuid::now_v7(), "machine:enrollment").await?;
        let Some(token) = machines::token_for_update(work.sql(), &digest).await? else {
            return Ok(EnrollOutcome::TokenInvalid);
        };
        if token.expires_at <= now || token.kind != kind.as_str() {
            return Ok(EnrollOutcome::TokenInvalid);
        }
        if let Some(consumed_key) = &token.consumed_key {
            return self.replay(work, &token, consumed_key, &key).await;
        }
        let pool = match (kind, token.organisation_id) {
            (TokenKind::Management, _) => Pool::Management,
            (TokenKind::Organisation, Some(organisation_id)) => {
                if !machines::organisation_live(&mut **work.sql(), organisation_id).await? {
                    return Ok(EnrollOutcome::TokenInvalid);
                }
                if machines::count_organisation_machines(&mut **work.sql(), organisation_id).await?
                    >= MAX_MACHINES_PER_ORGANISATION
                {
                    return Ok(EnrollOutcome::MachineLimit);
                }
                Pool::Organisation { organisation_id }
            }
            (TokenKind::Organisation, None) => return Ok(EnrollOutcome::TokenInvalid),
        };

        let machine_id = token.machine_id.unwrap_or_else(Uuid::now_v7);
        let command = match token.machine_id {
            Some(_) => MachineCommand::Reregister {
                key: key.clone(),
                token_id: token.token_id,
                facts: request.facts.clone(),
                at: now,
            },
            None => {
                let name = match chosen_name(&token, &request, machine_id) {
                    Ok(name) => name,
                    Err(message) => return Ok(EnrollOutcome::NameInvalid(message)),
                };
                MachineCommand::Register {
                    pool,
                    name,
                    key: key.clone(),
                    token_id: token.token_id,
                    minted_by: token.minted_by.clone(),
                    facts: request.facts.clone(),
                    at: now,
                }
            }
        };
        match work.machine(machine_id, command).await {
            Ok(_) => {}
            Err(WorkError::Machine(MachineError::KeyReused)) => {
                return Ok(EnrollOutcome::KeyReused);
            }
            Err(WorkError::Machine(_)) => return Ok(EnrollOutcome::TokenInvalid),
            Err(error) => {
                return Ok(match error.unique_violation().as_deref() {
                    Some("grund_machines_key_idx") => EnrollOutcome::KeyReused,
                    Some("grund_machines_pool_name_idx" | "grund_machines_management_name_idx") => {
                        EnrollOutcome::NameTaken
                    }
                    _ => return Err(error.into()),
                });
            }
        }
        machines::consume_token(work.sql(), token.token_id, key.as_hex(), machine_id, now).await?;
        let enrollment = self.enrollment(&mut work, machine_id, pool).await?;
        work.commit().await?;
        Ok(EnrollOutcome::Enrolled(enrollment))
    }

    async fn replay(
        &self,
        mut work: Work<'_>,
        token: &TokenRow,
        consumed_key: &str,
        key: &MachineKey,
    ) -> anyhow::Result<EnrollOutcome> {
        let same_key = crypto::constant_time_eq(consumed_key.as_bytes(), key.as_hex().as_bytes());
        let (Some(machine_id), true, true) = (
            token.consumed_machine_id,
            same_key,
            token.replays < MAX_REPLAYS,
        ) else {
            return Ok(EnrollOutcome::TokenInvalid);
        };
        let Some(row) = machines::machine(&mut **work.sql(), machine_id).await? else {
            return Ok(EnrollOutcome::TokenInvalid);
        };
        if row.public_key.as_deref() != Some(key.as_hex()) {
            return Ok(EnrollOutcome::TokenInvalid);
        }
        let pool = match row.home_organisation_id {
            Some(organisation_id) => Pool::Organisation { organisation_id },
            None => Pool::Management,
        };
        machines::count_replay(work.sql(), token.token_id).await?;
        let enrollment = self.enrollment(&mut work, machine_id, pool).await?;
        work.commit().await?;
        Ok(EnrollOutcome::Enrolled(enrollment))
    }

    async fn enrollment(
        &self,
        work: &mut Work<'_>,
        machine_id: Uuid,
        pool: Pool,
    ) -> anyhow::Result<Enrollment> {
        let keys = self.keys();
        let row = machines::machine(&mut **work.sql(), machine_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("a registered machine has a row"))?;
        let instance_key = keys.ensure(work.sql(), KeyPurpose::Instance, None).await?;
        let trust_key = match pool {
            Pool::Management => {
                keys.ensure(work.sql(), KeyPurpose::Management, None)
                    .await?
            }
            Pool::Organisation { organisation_id } => {
                keys.ensure(work.sql(), KeyPurpose::Organisation, Some(organisation_id))
                    .await?
            }
        };
        Ok(Enrollment {
            machine_id,
            name: row.name,
            pool,
            instance_key,
            trust_key,
        })
    }

    /// The management pool, optionally in one state.
    pub async fn pool(&self, state: Option<&str>) -> anyhow::Result<Vec<MachineRow>> {
        Ok(machines::management_machines(&self.state.pool, state).await?)
    }

    /// One management machine.
    pub async fn pool_machine(&self, machine_id: Uuid) -> anyhow::Result<Option<MachineRow>> {
        Ok(machines::machine(&self.state.pool, machine_id)
            .await?
            .filter(|row| row.pool == "management"))
    }

    /// Leases an available management machine to the organisation `slug`,
    /// and signs the grant.
    pub async fn lease(
        &self,
        actor: Uuid,
        machine_id: Uuid,
        slug: &str,
        name: &str,
    ) -> anyhow::Result<ChangeOutcome> {
        let Some(row) = self.pool_machine(machine_id).await? else {
            return Ok(ChangeOutcome::NotFound);
        };
        let Some(organisation_id) =
            machines::live_organisation_by_slug(&self.state.pool, slug).await?
        else {
            return Ok(ChangeOutcome::NoOrganisation);
        };
        let name = match MachineName::parse(if name.trim().is_empty() {
            &row.name
        } else {
            name
        }) {
            Ok(name) => name,
            Err(error) => return Ok(ChangeOutcome::NameInvalid(format!("name: {error}"))),
        };
        let now = Utc::now();
        let lease_id = Uuid::now_v7();
        let mut work = Work::begin(
            &self.state.events,
            Uuid::now_v7(),
            &format!("account:{actor}"),
        )
        .await?;
        if machines::count_organisation_machines(&mut **work.sql(), organisation_id).await?
            >= MAX_MACHINES_PER_ORGANISATION
        {
            return Ok(ChangeOutcome::PoolFull);
        }
        let leased = work
            .machine(
                machine_id,
                MachineCommand::Lease {
                    actor,
                    lease_id,
                    organisation_id,
                    name,
                    at: now,
                },
            )
            .await;
        if let Some(outcome) = refused(leased)? {
            return Ok(outcome);
        }
        let keys = self.keys();
        let management = keys
            .ensure(work.sql(), KeyPurpose::Management, None)
            .await?;
        let organisation_key = keys
            .ensure(work.sql(), KeyPurpose::Organisation, Some(organisation_id))
            .await?;
        let payload = agent::LeaseGrant {
            lease_id: lease_id.to_string(),
            machine_id: machine_id.to_string(),
            organisation_id: organisation_id.to_string(),
            organisation_key: buffa::MessageField::from(public_key_message(&organisation_key)),
            issued_at_unix: now.timestamp(),
            ..Default::default()
        }
        .encode_to_vec();
        let signature = keys.sign(management.key_id, prefix::LEASE_GRANT, &payload);
        work.commit().await?;
        let row = self
            .pool_machine(machine_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("a leased machine has a row"))?;
        Ok(ChangeOutcome::Leased(
            row,
            SignedGrant {
                key_id: management.key_id,
                payload,
                signature,
            },
        ))
    }

    /// Ends a management machine's lease.
    pub async fn end_lease(&self, actor: Uuid, machine_id: Uuid) -> anyhow::Result<ChangeOutcome> {
        if self.pool_machine(machine_id).await?.is_none() {
            return Ok(ChangeOutcome::NotFound);
        }
        self.change(
            actor,
            machine_id,
            MachineCommand::EndLease {
                actor,
                at: Utc::now(),
            },
        )
        .await
    }

    /// Revokes a machine, as the operator (a management machine) or as an
    /// organisation's owner or admin (its own machine).
    pub async fn revoke(
        &self,
        actor: Uuid,
        machine_id: Uuid,
        authority: Authority,
    ) -> anyhow::Result<ChangeOutcome> {
        self.change(
            actor,
            machine_id,
            MachineCommand::Revoke {
                actor,
                authority,
                at: Utc::now(),
            },
        )
        .await
    }

    async fn change(
        &self,
        actor: Uuid,
        machine_id: Uuid,
        command: MachineCommand,
    ) -> anyhow::Result<ChangeOutcome> {
        let mut work = Work::begin(
            &self.state.events,
            Uuid::now_v7(),
            &format!("account:{actor}"),
        )
        .await?;
        if let Some(outcome) = refused(work.machine(machine_id, command).await)? {
            return Ok(outcome);
        }
        work.commit().await?;
        let row = machines::machine(&self.state.pool, machine_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("a changed machine has a row"))?;
        Ok(ChangeOutcome::Done(row))
    }

    /// The machines in an organisation's pool.
    pub async fn organisation_machines(
        &self,
        organisation_id: Uuid,
    ) -> anyhow::Result<Vec<MachineRow>> {
        Ok(machines::organisation_machines(&self.state.pool, organisation_id).await?)
    }

    /// One machine of an organisation's pool.
    pub async fn organisation_machine(
        &self,
        organisation_id: Uuid,
        machine_id: Uuid,
    ) -> anyhow::Result<Option<MachineRow>> {
        Ok(machines::organisation_machine(&self.state.pool, organisation_id, machine_id).await?)
    }

    /// The organisation's desired-state key, made on first use.
    pub async fn organisation_key(&self, organisation_id: Uuid) -> anyhow::Result<PublicKey> {
        let mut connection = self.state.pool.acquire().await?;
        self.keys()
            .ensure(
                &mut connection,
                KeyPurpose::Organisation,
                Some(organisation_id),
            )
            .await
    }
}

fn refused(
    result: Result<Vec<grund_domain::machine::MachineEvent>, WorkError>,
) -> anyhow::Result<Option<ChangeOutcome>> {
    Ok(match result {
        Ok(_) => None,
        Err(WorkError::Machine(error)) => Some(match error {
            MachineError::NotFound => ChangeOutcome::NotFound,
            MachineError::NotAvailable => ChangeOutcome::NotAvailable,
            MachineError::NotLeased => ChangeOutcome::NotLeased,
            MachineError::NotAllowed => ChangeOutcome::NotAllowed,
            MachineError::AlreadyExists | MachineError::NotReturning | MachineError::KeyReused => {
                ChangeOutcome::NotAllowed
            }
        }),
        Err(error) => match error.unique_violation().as_deref() {
            Some("grund_machines_pool_name_idx") => Some(ChangeOutcome::NameTaken),
            _ => return Err(error.into()),
        },
    })
}

fn chosen_name(
    token: &TokenRow,
    request: &EnrollRequest,
    machine_id: Uuid,
) -> Result<MachineName, String> {
    if let Some(bound) = &token.name {
        return MachineName::parse(bound).map_err(|e| format!("name: {e}"));
    }
    if !request.requested_name.trim().is_empty() {
        return MachineName::parse(&request.requested_name)
            .map_err(|e| format!("requested_name: {e}"));
    }
    Ok(
        MachineName::suggest(&request.facts.hostname).unwrap_or_else(|| {
            MachineName::parse(&format!("m-{}", &machine_id.simple().to_string()[24..]))
                .expect("m- and hex digits make a machine name")
        }),
    )
}

/// Whether the enrollment proof holds: a 32-byte Ed25519 key, `signed_at`
/// within the clock skew of `now`, and a signature over the enrollment
/// message for this instance's origin and this token.
pub fn proof_holds(
    origin: &str,
    request: &EnrollRequest,
    token_sha256_hex: &str,
    now: DateTime<Utc>,
) -> bool {
    let Ok(public_key) = <[u8; 32]>::try_from(request.machine_public_key.as_slice()) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&public_key) else {
        return false;
    };
    let Ok(signature) = <[u8; 64]>::try_from(request.signature.as_slice()) else {
        return false;
    };
    let Some(signed_at) = DateTime::from_timestamp(request.signed_at_unix, 0) else {
        return false;
    };
    if (signed_at - now).abs() > grund_domain::machine::CLOCK_SKEW {
        return false;
    }
    let message = enrollment_message(origin, request.signed_at_unix, token_sha256_hex);
    verifying
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .is_ok()
}

/// The protobuf form of one of the instance's keys.
pub fn public_key_message(key: &PublicKey) -> agent::PublicKey {
    agent::PublicKey {
        key_id: key.key_id.to_string(),
        public_key: key.public_key.to_vec(),
        purpose: match key.purpose {
            KeyPurpose::Instance => agent::KeyPurpose::KEY_PURPOSE_INSTANCE,
            KeyPurpose::Management => agent::KeyPurpose::KEY_PURPOSE_MANAGEMENT,
            KeyPurpose::Organisation => agent::KeyPurpose::KEY_PURPOSE_ORGANISATION,
        }
        .into(),
        ..Default::default()
    }
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    bytes
}

/// RFC 4648 base32, lowercase, without padding: the alphabet
/// `TokenKind::of` accepts.
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Access to [`Machines`] from [`State`].
pub trait MachinesState {
    fn machines(&self) -> Machines;
}

impl MachinesState for State {
    fn machines(&self) -> Machines {
        Machines {
            state: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    #[test]
    fn base32_of_thirty_two_bytes_is_a_token_secret() {
        let secret = base32(&[0xff; 32]);
        assert_eq!(secret.len(), grund_domain::machine::TOKEN_SECRET_CHARS);
        assert_eq!(
            TokenKind::of(&format!("grund_reg_{secret}")),
            Some(TokenKind::Management)
        );
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
    }

    fn request(signing: &SigningKey, origin: &str, signed_at: i64, token: &str) -> EnrollRequest {
        let digest = hex::encode(crypto::digest(token));
        let signature = signing.sign(&enrollment_message(origin, signed_at, &digest));
        EnrollRequest {
            token: token.into(),
            machine_public_key: signing.verifying_key().to_bytes().to_vec(),
            signed_at_unix: signed_at,
            signature: signature.to_bytes().to_vec(),
            facts: MachineFacts::default(),
            requested_name: String::new(),
            address: String::new(),
        }
    }

    #[test]
    fn the_proof_holds_only_for_this_origin_token_and_time() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let now = Utc::now();
        let token = "grund_reg_x";
        let digest = hex::encode(crypto::digest(token));
        let origin = "https://app.grund.sh";
        let good = request(&signing, origin, now.timestamp(), token);
        assert!(proof_holds(origin, &good, &digest, now));
        assert!(!proof_holds("https://other.example", &good, &digest, now));
        assert!(!proof_holds(
            origin,
            &good,
            &hex::encode(crypto::digest("grund_reg_y")),
            now
        ));
        let late = request(&signing, origin, now.timestamp() - 301, token);
        assert!(!proof_holds(origin, &late, &digest, now));
        let mut short_key = good.clone();
        short_key.machine_public_key.pop();
        assert!(!proof_holds(origin, &short_key, &digest, now));
    }
}
