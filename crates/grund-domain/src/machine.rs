//! The machine aggregate (`grund-machine`): a machine an organisation runs
//! on, its own hardware or a grund machine alike. A machine is an identity:
//! its id, the organisation it belongs to, its name and the Ed25519 key it
//! proved at enrollment. It ends only when it is revoked.
//!
//! Who may enroll is decided by the one-time token (grund-server's
//! machines service); who may revoke, by the actor's role in the
//! organisation. This aggregate keeps the identity's own rules: it enrolls
//! once and is revoked once.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::names::MachineName;

pub const MACHINE_CATEGORY: &str = "grund-machine";

/// The longest text kept of any fact a machine reports.
pub const MAX_FACT_CHARS: usize = 256;

/// What a machine said about itself when it enrolled. Recorded for display,
/// never used to authorize anything: a machine can claim any of it.
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

impl MachineFacts {
    /// The facts with every text cut to [`MAX_FACT_CHARS`] and every number
    /// at least zero.
    pub fn bounded(self) -> Self {
        let cut = |s: String| s.chars().take(MAX_FACT_CHARS).collect::<String>();
        Self {
            hostname: cut(self.hostname),
            arch: cut(self.arch),
            cpu_model: cut(self.cpu_model),
            cpus: self.cpus.max(0),
            memory_mib: self.memory_mib.max(0),
            disk_gib: self.disk_gib.max(0),
            os: cut(self.os),
            kernel: cut(self.kernel),
            agent_version: cut(self.agent_version),
            fleet_machine_id: cut(self.fleet_machine_id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, mire::EventData)]
#[serde(tag = "type", rename_all = "snake_case")]
#[mire(entity = "grund-machine")]
pub enum MachineEvent {
    Enrolled {
        organisation_id: Uuid,
        name: MachineName,
        public_key: String,
        minted_by: String,
        facts: Box<MachineFacts>,
        enrolled_at: DateTime<Utc>,
    },
    Revoked {
        revoked_by: Option<Uuid>,
        revoked_at: DateTime<Utc>,
    },
}

/// The folded state of one machine.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Machine {
    pub exists: bool,
    pub organisation_id: Option<Uuid>,
    pub name: Option<MachineName>,
    pub public_key: Option<String>,
    pub revoked: bool,
}

impl mire::Aggregate for Machine {
    type Event = MachineEvent;

    fn stream_category() -> &'static str {
        MACHINE_CATEGORY
    }

    fn apply(&mut self, event: &MachineEvent) {
        match event {
            MachineEvent::Enrolled {
                organisation_id,
                name,
                public_key,
                ..
            } => {
                self.exists = true;
                self.organisation_id = Some(*organisation_id);
                self.name = Some(name.clone());
                self.public_key = Some(public_key.clone());
            }
            MachineEvent::Revoked { .. } => self.revoked = true,
        }
    }
}

impl mire::Snapshot for Machine {
    const SNAPSHOT_VERSION: i32 = 1;
    const SNAPSHOT_FREQUENCY: i64 = 100;
}

#[derive(Debug, Clone)]
pub enum MachineCommand {
    /// Enrolls the machine into `organisation_id` with the key it proved.
    Enroll {
        organisation_id: Uuid,
        name: MachineName,
        public_key: String,
        minted_by: String,
        facts: Box<MachineFacts>,
        at: DateTime<Utc>,
    },
    /// Ends the machine's identity. `actor` is the member who revoked it,
    /// or `None` when grund did (a released grund machine). Nothing when it
    /// is revoked already.
    Revoke {
        actor: Option<Uuid>,
        at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MachineError {
    #[error("the machine is enrolled already")]
    AlreadyEnrolled,
    #[error("no such machine")]
    NotFound,
}

impl mire::Command for MachineCommand {
    type Aggregate = Machine;
    type Error = MachineError;
    type Events = Vec<MachineEvent>;

    fn handle(self, machine: &Machine) -> Result<Vec<MachineEvent>, MachineError> {
        match self {
            MachineCommand::Enroll {
                organisation_id,
                name,
                public_key,
                minted_by,
                facts,
                at,
            } => {
                if machine.exists {
                    return Err(MachineError::AlreadyEnrolled);
                }
                Ok(vec![MachineEvent::Enrolled {
                    organisation_id,
                    name,
                    public_key,
                    minted_by,
                    facts: Box::new(facts.bounded()),
                    enrolled_at: at,
                }])
            }
            MachineCommand::Revoke { actor, at } => {
                if !machine.exists {
                    return Err(MachineError::NotFound);
                }
                if machine.revoked {
                    return Ok(vec![]);
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

    fn enroll() -> MachineCommand {
        MachineCommand::Enroll {
            organisation_id: Uuid::from_u128(1),
            name: MachineName::parse("web-1").unwrap(),
            public_key: "key".into(),
            minted_by: "user:1".into(),
            facts: Box::new(MachineFacts {
                hostname: "h".repeat(1000),
                cpus: -3,
                ..Default::default()
            }),
            at: at(),
        }
    }

    fn fold(events: &[MachineEvent]) -> Machine {
        let mut machine = Machine::default();
        for event in events {
            machine.apply(event);
        }
        machine
    }

    #[test]
    fn a_machine_enrolls_once_with_bounded_facts() {
        let events = enroll().handle(&Machine::default()).unwrap();
        let MachineEvent::Enrolled { facts, .. } = &events[0] else {
            panic!("expected Enrolled");
        };
        assert_eq!(facts.hostname.chars().count(), MAX_FACT_CHARS);
        assert_eq!(facts.cpus, 0);
        let machine = fold(&events);
        assert_eq!(machine.organisation_id, Some(Uuid::from_u128(1)));
        assert_eq!(
            enroll().handle(&machine),
            Err(MachineError::AlreadyEnrolled)
        );
    }

    #[test]
    fn revoking_ends_the_machine_once() {
        let revoke = || MachineCommand::Revoke {
            actor: None,
            at: at(),
        };
        assert_eq!(
            revoke().handle(&Machine::default()),
            Err(MachineError::NotFound)
        );
        let mut events = enroll().handle(&Machine::default()).unwrap();
        events.extend(revoke().handle(&fold(&events)).unwrap());
        let machine = fold(&events);
        assert!(machine.revoked);
        assert_eq!(revoke().handle(&machine), Ok(vec![]));
    }
}
