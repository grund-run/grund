//! The machine aggregate (`grund-machine`), and the pure rules of
//! registration: token shapes, the enrollment proof's message and the
//! purposes every instance key signs for.
//!
//! A machine belongs to exactly one pool at a time: the management pool, run
//! by the operator organisation, or an organisation's own pool. A management
//! machine reaches an organisation only through a lease, and every lease ends
//! with the machine wiped and registered again under a new key
//! (grund-docs design/machines.md).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::names::MachineName;

pub const MACHINE_CATEGORY: &str = "grund-machine";

/// How long a registration token lives unless the minter asks for less.
pub const TOKEN_TTL: Duration = Duration::minutes(10);

/// The longest a registration token may live.
pub const TOKEN_TTL_MAX: Duration = Duration::minutes(15);

/// The most unexpired, unused registration tokens a pool may hold.
pub const MAX_OPEN_TOKENS: i64 = 20;

/// How often the same machine may repeat a registration with one token.
pub const MAX_REPLAYS: i32 = 5;

/// How far a registration's `signed_at` may be from the instance's clock.
pub const CLOCK_SKEW: Duration = Duration::seconds(300);

/// The most machines an organisation's pool (own and leased) may hold.
pub const MAX_MACHINES_PER_ORGANISATION: i64 = 50;

/// What each instance key signs, so nothing signed for one purpose verifies
/// as another.
pub mod prefix {
    /// A machine key, over its registration.
    pub const ENROLL: &[u8] = b"grund-enroll-v1\n";
    /// The management key, over a lease grant.
    pub const LEASE_GRANT: &[u8] = b"grund-lease-grant-v1\n";
    /// An organisation key, over a desired-state document.
    pub const DESIRED_STATE: &[u8] = b"grund-desired-state-v1\n";
    /// A network key, over a membership list.
    pub const NET_MEMBERSHIP: &[u8] = b"grund-net-membership-v1\n";
}

/// The keys the instance holds, one purpose each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    /// The instance's identity to its machines, pinned at registration.
    Instance,
    /// Signs lease grants; pinned by management machines.
    Management,
    /// One per organisation; signs its desired-state documents.
    Organisation,
}

impl KeyPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyPurpose::Instance => "instance",
            KeyPurpose::Management => "management",
            KeyPurpose::Organisation => "organisation",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "instance" => Some(KeyPurpose::Instance),
            "management" => Some(KeyPurpose::Management),
            "organisation" => Some(KeyPurpose::Organisation),
            _ => None,
        }
    }
}

/// Which pool a registration token opens, told apart by its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// `grund_reg_`: the management pool, minted by the operator organisation.
    Management,
    /// `grund_join_`: one organisation's pool, minted by its owners and admins.
    Organisation,
}

/// The length of a token's secret part: 32 bytes in unpadded base32.
pub const TOKEN_SECRET_CHARS: usize = 52;

impl TokenKind {
    pub fn prefix(self) -> &'static str {
        match self {
            TokenKind::Management => "grund_reg_",
            TokenKind::Organisation => "grund_join_",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Management => "management",
            TokenKind::Organisation => "organisation",
        }
    }

    /// The kind of a well-formed token, or `None` for anything else: a wrong
    /// prefix, length or alphabet. Callers treat `None` exactly as an unknown
    /// token.
    pub fn of(token: &str) -> Option<TokenKind> {
        [TokenKind::Management, TokenKind::Organisation]
            .into_iter()
            .find(|kind| {
                token.strip_prefix(kind.prefix()).is_some_and(|secret| {
                    secret.len() == TOKEN_SECRET_CHARS
                        && secret
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
                })
            })
    }
}

/// The bytes a machine signs to register: the purpose, the instance's
/// origin, the time and the token's SHA-256 in lowercase hex, so a proof
/// cannot be replayed against another instance, later, or with another token.
pub fn enrollment_message(origin: &str, signed_at_unix: i64, token_sha256_hex: &str) -> Vec<u8> {
    let mut message = prefix::ENROLL.to_vec();
    message.extend_from_slice(origin.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(signed_at_unix.to_string().as_bytes());
    message.push(b'\n');
    message.extend_from_slice(token_sha256_hex.as_bytes());
    message
}

/// A machine's Ed25519 public key: 32 bytes, kept as 64 lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MachineKey(String);

impl MachineKey {
    /// The key, if `bytes` is 32 bytes long. Whether it is a valid curve
    /// point is checked where the signature is verified.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == 32)
            .then(|| Self(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()))
    }

    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Which pool a machine is registered into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "pool", rename_all = "snake_case")]
pub enum Pool {
    Management,
    Organisation { organisation_id: Uuid },
}

impl Pool {
    pub fn as_str(self) -> &'static str {
        match self {
            Pool::Management => "management",
            Pool::Organisation { .. } => "organisation",
        }
    }
}

/// Where a machine is in its life (design/machines.md §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineState {
    /// In the management pool, waiting to be leased.
    Available,
    /// A management machine on lease to an organisation.
    Leased,
    /// A lease ended; the machine must be wiped and registered again under a
    /// new key before it can be leased.
    Returning,
    /// An organisation's own machine.
    Active,
    /// Terminal: its key is refused everywhere.
    Revoked,
}

impl MachineState {
    pub fn as_str(self) -> &'static str {
        match self {
            MachineState::Available => "available",
            MachineState::Leased => "leased",
            MachineState::Returning => "returning",
            MachineState::Active => "active",
            MachineState::Revoked => "revoked",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "available" => Some(MachineState::Available),
            "leased" => Some(MachineState::Leased),
            "returning" => Some(MachineState::Returning),
            "active" => Some(MachineState::Active),
            "revoked" => Some(MachineState::Revoked),
            _ => None,
        }
    }
}

/// What a machine said about itself. Recorded for display and placement
/// hints, never used to authorize anything: a machine can claim any of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineFacts {
    pub hostname: String,
    pub arch: String,
    pub cpu_model: String,
    pub cpus: i32,
    pub memory_mib: i64,
    pub disk_gib: i64,
    pub os: String,
    pub kernel: String,
    pub agent_version: String,
    pub fleet_machine_id: String,
}

/// Who asks to revoke, as the service established it from the caller's
/// memberships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// An owner or admin of the operator organisation.
    Operator,
    /// An owner or admin of this organisation.
    Organisation(Uuid),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, mire::EventData)]
#[serde(tag = "type", rename_all = "snake_case")]
#[mire(entity = "grund-machine")]
pub enum MachineEvent {
    Registered {
        #[serde(flatten)]
        pool: Pool,
        name: MachineName,
        key: MachineKey,
        token_id: Uuid,
        minted_by: String,
        facts: MachineFacts,
        registered_at: DateTime<Utc>,
    },
    Leased {
        lease_id: Uuid,
        organisation_id: Uuid,
        name: MachineName,
        leased_by: Uuid,
        leased_at: DateTime<Utc>,
    },
    LeaseEnded {
        lease_id: Uuid,
        organisation_id: Uuid,
        ended_by: Uuid,
        ended_at: DateTime<Utc>,
    },
    /// A returning machine, wiped, registered again under a new key. The key
    /// it had during the lease is retired in the same event.
    Reregistered {
        key: MachineKey,
        retired_key: MachineKey,
        token_id: Uuid,
        facts: MachineFacts,
        reregistered_at: DateTime<Utc>,
    },
    Revoked {
        revoked_by: Uuid,
        revoked_at: DateTime<Utc>,
    },
}

/// A lease in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub lease_id: Uuid,
    pub organisation_id: Uuid,
    pub name: MachineName,
}

/// What `apply` builds; also the snapshot.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Machine {
    pub exists: bool,
    pub pool: Option<Pool>,
    pub name: Option<MachineName>,
    pub key: Option<MachineKey>,
    pub retired_keys: Vec<MachineKey>,
    pub state: Option<MachineState>,
    pub lease: Option<Lease>,
}

impl Machine {
    /// The organisation whose pool the machine is in now: its own
    /// organisation, or the lessee while leased.
    pub fn organisation(&self) -> Option<Uuid> {
        match (self.state, self.pool, &self.lease) {
            (Some(MachineState::Active), Some(Pool::Organisation { organisation_id }), _) => {
                Some(organisation_id)
            }
            (Some(MachineState::Leased), _, Some(lease)) => Some(lease.organisation_id),
            _ => None,
        }
    }

    fn used(&self, key: &MachineKey) -> bool {
        self.key.as_ref() == Some(key) || self.retired_keys.contains(key)
    }
}

impl mire::Aggregate for Machine {
    type Event = MachineEvent;

    fn stream_category() -> &'static str {
        MACHINE_CATEGORY
    }

    fn apply(&mut self, event: &MachineEvent) {
        match event {
            MachineEvent::Registered {
                pool, name, key, ..
            } => {
                self.exists = true;
                self.pool = Some(*pool);
                self.name = Some(name.clone());
                self.key = Some(key.clone());
                self.state = Some(match pool {
                    Pool::Management => MachineState::Available,
                    Pool::Organisation { .. } => MachineState::Active,
                });
            }
            MachineEvent::Leased {
                lease_id,
                organisation_id,
                name,
                ..
            } => {
                self.state = Some(MachineState::Leased);
                self.lease = Some(Lease {
                    lease_id: *lease_id,
                    organisation_id: *organisation_id,
                    name: name.clone(),
                });
            }
            MachineEvent::LeaseEnded { .. } => {
                self.state = Some(MachineState::Returning);
                self.lease = None;
            }
            MachineEvent::Reregistered {
                key, retired_key, ..
            } => {
                self.retired_keys.push(retired_key.clone());
                self.key = Some(key.clone());
                self.state = Some(MachineState::Available);
            }
            MachineEvent::Revoked { .. } => {
                if let Some(key) = self.key.take() {
                    self.retired_keys.push(key);
                }
                self.state = Some(MachineState::Revoked);
                self.lease = None;
            }
        }
    }
}

impl mire::Snapshot for Machine {
    const SNAPSHOT_VERSION: i32 = 1;
    const SNAPSHOT_FREQUENCY: i64 = 100;
}

#[derive(Debug, Clone)]
pub enum MachineCommand {
    /// Registers a new machine into `pool` under `key`.
    Register {
        pool: Pool,
        name: MachineName,
        key: MachineKey,
        token_id: Uuid,
        minted_by: String,
        facts: MachineFacts,
        at: DateTime<Utc>,
    },
    /// Leases an available management machine to an organisation, under the
    /// name it will have in that organisation's pool.
    Lease {
        actor: Uuid,
        lease_id: Uuid,
        organisation_id: Uuid,
        name: MachineName,
        at: DateTime<Utc>,
    },
    /// Ends the lease in force; the machine must be wiped and registered
    /// again before it can be leased.
    EndLease { actor: Uuid, at: DateTime<Utc> },
    /// Registers a returning machine again under a key it has never used.
    Reregister {
        key: MachineKey,
        token_id: Uuid,
        facts: MachineFacts,
        at: DateTime<Utc>,
    },
    /// Revokes the machine for good. Revoking a revoked machine changes
    /// nothing.
    Revoke {
        actor: Uuid,
        authority: Authority,
        at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MachineError {
    #[error("the machine already exists")]
    AlreadyExists,
    #[error("no such machine")]
    NotFound,
    #[error("only an available management machine can be leased")]
    NotAvailable,
    #[error("the machine is not on lease")]
    NotLeased,
    #[error("only a machine whose lease ended can register again")]
    NotReturning,
    #[error("a machine must register again under a key it has never used")]
    KeyReused,
    #[error("the machine is not yours to revoke")]
    NotAllowed,
}

impl mire::Command for MachineCommand {
    type Aggregate = Machine;
    type Error = MachineError;
    type Events = Vec<MachineEvent>;

    fn handle(self, machine: &Machine) -> Result<Vec<MachineEvent>, MachineError> {
        if let MachineCommand::Register {
            pool,
            name,
            key,
            token_id,
            minted_by,
            facts,
            at,
        } = self
        {
            if machine.exists {
                return Err(MachineError::AlreadyExists);
            }
            return Ok(vec![MachineEvent::Registered {
                pool,
                name,
                key,
                token_id,
                minted_by,
                facts,
                registered_at: at,
            }]);
        }
        if !machine.exists {
            return Err(MachineError::NotFound);
        }
        let state = machine.state.ok_or(MachineError::NotFound)?;
        match self {
            MachineCommand::Register { .. } => unreachable!("handled above"),
            MachineCommand::Lease {
                actor,
                lease_id,
                organisation_id,
                name,
                at,
            } => {
                if state != MachineState::Available {
                    return Err(MachineError::NotAvailable);
                }
                Ok(vec![MachineEvent::Leased {
                    lease_id,
                    organisation_id,
                    name,
                    leased_by: actor,
                    leased_at: at,
                }])
            }
            MachineCommand::EndLease { actor, at } => {
                let lease = machine.lease.as_ref().ok_or(MachineError::NotLeased)?;
                Ok(vec![MachineEvent::LeaseEnded {
                    lease_id: lease.lease_id,
                    organisation_id: lease.organisation_id,
                    ended_by: actor,
                    ended_at: at,
                }])
            }
            MachineCommand::Reregister {
                key,
                token_id,
                facts,
                at,
            } => {
                if state != MachineState::Returning {
                    return Err(MachineError::NotReturning);
                }
                if machine.used(&key) {
                    return Err(MachineError::KeyReused);
                }
                let retired_key = machine.key.clone().ok_or(MachineError::NotFound)?;
                Ok(vec![MachineEvent::Reregistered {
                    key,
                    retired_key,
                    token_id,
                    facts,
                    reregistered_at: at,
                }])
            }
            MachineCommand::Revoke {
                actor,
                authority,
                at,
            } => {
                if state == MachineState::Revoked {
                    return Ok(Vec::new());
                }
                let allowed = match (authority, machine.pool) {
                    (Authority::Operator, Some(Pool::Management)) => true,
                    (
                        Authority::Organisation(asker),
                        Some(Pool::Organisation { organisation_id }),
                    ) => asker == organisation_id,
                    _ => false,
                };
                if !allowed {
                    return Err(MachineError::NotAllowed);
                }
                Ok(vec![MachineEvent::Revoked {
                    revoked_by: actor,
                    revoked_at: at,
                }])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use mire::{Aggregate, Command};

    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).unwrap()
    }

    fn key(byte: u8) -> MachineKey {
        MachineKey::from_bytes(&[byte; 32]).unwrap()
    }

    fn name(text: &str) -> MachineName {
        MachineName::parse(text).unwrap()
    }

    fn run(
        machine: &mut Machine,
        command: MachineCommand,
    ) -> Result<Vec<MachineEvent>, MachineError> {
        let events = command.handle(machine)?;
        for event in &events {
            machine.apply(event);
        }
        Ok(events)
    }

    fn registered(pool: Pool) -> Machine {
        let mut machine = Machine::default();
        run(
            &mut machine,
            MachineCommand::Register {
                pool,
                name: name("gm-1"),
                key: key(1),
                token_id: Uuid::now_v7(),
                minted_by: "account:test".into(),
                facts: MachineFacts::default(),
                at: at(),
            },
        )
        .unwrap();
        machine
    }

    fn lease(
        machine: &mut Machine,
        organisation_id: Uuid,
    ) -> Result<Vec<MachineEvent>, MachineError> {
        run(
            machine,
            MachineCommand::Lease {
                actor: Uuid::now_v7(),
                lease_id: Uuid::now_v7(),
                organisation_id,
                name: name("web-1"),
                at: at(),
            },
        )
    }

    #[test]
    fn a_management_registration_is_available_and_an_organisation_one_active() {
        assert_eq!(
            registered(Pool::Management).state,
            Some(MachineState::Available)
        );
        let org = Uuid::now_v7();
        let machine = registered(Pool::Organisation {
            organisation_id: org,
        });
        assert_eq!(machine.state, Some(MachineState::Active));
        assert_eq!(machine.organisation(), Some(org));
    }

    #[test]
    fn a_lease_puts_the_machine_in_the_lessee_pool_until_it_ends() {
        let org = Uuid::now_v7();
        let mut machine = registered(Pool::Management);
        assert_eq!(machine.organisation(), None);
        lease(&mut machine, org).unwrap();
        assert_eq!(machine.organisation(), Some(org));
        run(
            &mut machine,
            MachineCommand::EndLease {
                actor: Uuid::now_v7(),
                at: at(),
            },
        )
        .unwrap();
        assert_eq!(machine.state, Some(MachineState::Returning));
        assert_eq!(machine.organisation(), None);
    }

    #[test]
    fn only_an_available_management_machine_can_be_leased() {
        let org = Uuid::now_v7();
        let mut own = registered(Pool::Organisation {
            organisation_id: org,
        });
        assert_eq!(
            lease(&mut own, Uuid::now_v7()),
            Err(MachineError::NotAvailable)
        );
        let mut machine = registered(Pool::Management);
        lease(&mut machine, org).unwrap();
        assert_eq!(
            lease(&mut machine, Uuid::now_v7()),
            Err(MachineError::NotAvailable)
        );
        run(
            &mut machine,
            MachineCommand::EndLease {
                actor: Uuid::now_v7(),
                at: at(),
            },
        )
        .unwrap();
        assert_eq!(lease(&mut machine, org), Err(MachineError::NotAvailable));
    }

    #[test]
    fn a_returning_machine_comes_back_only_under_a_key_it_never_used() {
        let mut machine = registered(Pool::Management);
        lease(&mut machine, Uuid::now_v7()).unwrap();
        run(
            &mut machine,
            MachineCommand::EndLease {
                actor: Uuid::now_v7(),
                at: at(),
            },
        )
        .unwrap();
        let reregister = |k: u8| MachineCommand::Reregister {
            key: key(k),
            token_id: Uuid::now_v7(),
            facts: MachineFacts::default(),
            at: at(),
        };
        assert_eq!(
            run(&mut machine, reregister(1)),
            Err(MachineError::KeyReused)
        );
        run(&mut machine, reregister(2)).unwrap();
        assert_eq!(machine.state, Some(MachineState::Available));
        assert_eq!(machine.key, Some(key(2)));
        lease(&mut machine, Uuid::now_v7()).unwrap();
        run(
            &mut machine,
            MachineCommand::EndLease {
                actor: Uuid::now_v7(),
                at: at(),
            },
        )
        .unwrap();
        assert_eq!(
            run(&mut machine, reregister(1)),
            Err(MachineError::KeyReused)
        );
        assert_eq!(
            run(&mut machine, reregister(2)),
            Err(MachineError::KeyReused)
        );
        run(&mut machine, reregister(3)).unwrap();
    }

    #[test]
    fn a_machine_that_is_not_returning_cannot_register_again() {
        let mut machine = registered(Pool::Management);
        assert_eq!(
            run(
                &mut machine,
                MachineCommand::Reregister {
                    key: key(9),
                    token_id: Uuid::now_v7(),
                    facts: MachineFacts::default(),
                    at: at(),
                }
            ),
            Err(MachineError::NotReturning)
        );
    }

    #[test]
    fn the_operator_revokes_management_machines_and_an_organisation_only_its_own() {
        let org = Uuid::now_v7();
        let revoke = |authority| MachineCommand::Revoke {
            actor: Uuid::now_v7(),
            authority,
            at: at(),
        };
        let mut leased = registered(Pool::Management);
        lease(&mut leased, org).unwrap();
        assert_eq!(
            run(&mut leased, revoke(Authority::Organisation(org))),
            Err(MachineError::NotAllowed)
        );
        run(&mut leased, revoke(Authority::Operator)).unwrap();
        assert_eq!(leased.state, Some(MachineState::Revoked));
        assert_eq!(leased.organisation(), None);

        let mut own = registered(Pool::Organisation {
            organisation_id: org,
        });
        assert_eq!(
            run(&mut own, revoke(Authority::Operator)),
            Err(MachineError::NotAllowed)
        );
        assert_eq!(
            run(&mut own, revoke(Authority::Organisation(Uuid::now_v7()))),
            Err(MachineError::NotAllowed)
        );
        run(&mut own, revoke(Authority::Organisation(org))).unwrap();
        assert_eq!(
            run(&mut own, revoke(Authority::Organisation(org))),
            Ok(Vec::new())
        );
    }

    #[test]
    fn a_revoked_machine_keeps_no_current_key() {
        let mut machine = registered(Pool::Management);
        run(
            &mut machine,
            MachineCommand::Revoke {
                actor: Uuid::now_v7(),
                authority: Authority::Operator,
                at: at(),
            },
        )
        .unwrap();
        assert_eq!(machine.key, None);
        assert_eq!(machine.retired_keys, vec![key(1)]);
        assert_eq!(
            lease(&mut machine, Uuid::now_v7()),
            Err(MachineError::NotAvailable)
        );
    }

    #[test]
    fn a_second_registration_of_one_machine_is_refused() {
        let mut machine = registered(Pool::Management);
        assert_eq!(
            run(
                &mut machine,
                MachineCommand::Register {
                    pool: Pool::Management,
                    name: name("x"),
                    key: key(2),
                    token_id: Uuid::now_v7(),
                    minted_by: "account:test".into(),
                    facts: MachineFacts::default(),
                    at: at(),
                }
            ),
            Err(MachineError::AlreadyExists)
        );
    }

    #[test]
    fn tokens_are_told_apart_by_prefix_and_anything_malformed_is_unknown() {
        let secret = "a".repeat(TOKEN_SECRET_CHARS);
        assert_eq!(
            TokenKind::of(&format!("grund_reg_{secret}")),
            Some(TokenKind::Management)
        );
        assert_eq!(
            TokenKind::of(&format!("grund_join_{secret}")),
            Some(TokenKind::Organisation)
        );
        for bad in [
            format!("grund_enr_{secret}"),
            format!("grund_reg_{}", "a".repeat(TOKEN_SECRET_CHARS - 1)),
            format!("grund_reg_{}", "A".repeat(TOKEN_SECRET_CHARS)),
            format!("grund_reg_{}1", "a".repeat(TOKEN_SECRET_CHARS - 1)),
            String::new(),
        ] {
            assert_eq!(TokenKind::of(&bad), None, "{bad}");
        }
    }

    #[test]
    fn the_enrollment_message_binds_purpose_origin_time_and_token() {
        let message = enrollment_message("https://grund.example.com", 1_790_000_000, "ab12");
        assert_eq!(
            message,
            b"grund-enroll-v1\nhttps://grund.example.com\n1790000000\nab12".to_vec()
        );
    }

    #[test]
    fn a_registration_event_keeps_its_pool_in_flat_json() {
        let org = Uuid::nil();
        let event = MachineEvent::Registered {
            pool: Pool::Organisation {
                organisation_id: org,
            },
            name: name("box"),
            key: key(7),
            token_id: Uuid::nil(),
            minted_by: "account:x".into(),
            facts: MachineFacts::default(),
            registered_at: at(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "registered");
        assert_eq!(json["pool"], "organisation");
        assert_eq!(json["organisation_id"], org.to_string());
        assert_eq!(serde_json::from_value::<MachineEvent>(json).unwrap(), event);
    }
}
