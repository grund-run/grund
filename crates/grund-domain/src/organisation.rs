//! The organisation aggregate (`grund-organisation`). Everything grund will
//! manage (apps, machines, releases) belongs to an organisation, never to an
//! account. Signing up creates a personal one whose slug is the username.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::names::Username;

pub const ORGANISATION_CATEGORY: &str = "grund-organisation";

/// What a member may do. Only `Owner` is granted today (at sign-up); the
/// others exist so memberships and their checks have their final shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }
}

/// Personal organisations are created at sign-up; shared ones later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganisationKind {
    Personal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, mire::EventData)]
#[serde(tag = "type", rename_all = "snake_case")]
#[mire(entity = "grund-organisation")]
pub enum OrganisationEvent {
    Created {
        slug: Username,
        kind: OrganisationKind,
        created_by: Uuid,
        created_at: DateTime<Utc>,
    },
    MemberAdded {
        account_id: Uuid,
        role: Role,
        added_at: DateTime<Utc>,
    },
}

/// A member and their role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub account_id: Uuid,
    pub role: Role,
}

/// What `apply` builds. It is also the snapshot, taken every 100 events:
/// membership changes accumulate for the organisation's whole life.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Organisation {
    pub exists: bool,
    pub slug: Option<Username>,
    pub members: Vec<Member>,
}

impl Organisation {
    pub fn role_of(&self, account_id: Uuid) -> Option<Role> {
        self.members
            .iter()
            .find(|m| m.account_id == account_id)
            .map(|m| m.role)
    }
}

impl mire::Aggregate for Organisation {
    type Event = OrganisationEvent;

    fn stream_category() -> &'static str {
        ORGANISATION_CATEGORY
    }

    fn apply(&mut self, event: &OrganisationEvent) {
        match event {
            OrganisationEvent::Created { slug, .. } => {
                self.exists = true;
                self.slug = Some(slug.clone());
            }
            OrganisationEvent::MemberAdded {
                account_id, role, ..
            } => {
                match self
                    .members
                    .iter_mut()
                    .find(|m| m.account_id == *account_id)
                {
                    Some(member) => member.role = *role,
                    None => self.members.push(Member {
                        account_id: *account_id,
                        role: *role,
                    }),
                }
            }
        }
    }
}

impl mire::Snapshot for Organisation {
    const SNAPSHOT_VERSION: i32 = 1;
    const SNAPSHOT_FREQUENCY: i64 = 100;
}

#[derive(Debug, Clone)]
pub enum OrganisationCommand {
    /// Creates a personal organisation owned by `owner`.
    CreatePersonal {
        slug: Username,
        owner: Uuid,
        at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrganisationError {
    #[error("the organisation already exists")]
    AlreadyExists,
}

impl mire::Command for OrganisationCommand {
    type Aggregate = Organisation;
    type Error = OrganisationError;
    type Events = Vec<OrganisationEvent>;

    fn handle(
        self,
        organisation: &Organisation,
    ) -> Result<Vec<OrganisationEvent>, OrganisationError> {
        match self {
            OrganisationCommand::CreatePersonal { slug, owner, at } => {
                if organisation.exists {
                    return Err(OrganisationError::AlreadyExists);
                }
                Ok(vec![
                    OrganisationEvent::Created {
                        slug,
                        kind: OrganisationKind::Personal,
                        created_by: owner,
                        created_at: at,
                    },
                    OrganisationEvent::MemberAdded {
                        account_id: owner,
                        role: Role::Owner,
                        added_at: at,
                    },
                ])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use mire::AggregateRoot;

    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).unwrap()
    }

    #[test]
    fn a_personal_organisation_is_created_with_its_owner_as_the_only_member() {
        let owner = Uuid::now_v7();
        let mut root = AggregateRoot::<Organisation>::new("o");
        root.execute(OrganisationCommand::CreatePersonal {
            slug: Username::parse("kasper").unwrap(),
            owner,
            at: at(),
        })
        .unwrap();
        assert_eq!(root.state.role_of(owner), Some(Role::Owner));
        assert_eq!(root.state.members.len(), 1);
        assert_eq!(root.state.role_of(Uuid::now_v7()), None);
    }

    #[test]
    fn creating_it_twice_is_refused() {
        let mut root = AggregateRoot::<Organisation>::new("o");
        let create = || OrganisationCommand::CreatePersonal {
            slug: Username::parse("kasper").unwrap(),
            owner: Uuid::nil(),
            at: at(),
        };
        root.execute(create()).unwrap();
        assert_eq!(
            root.execute(create()).unwrap_err(),
            OrganisationError::AlreadyExists
        );
        assert_eq!(root.pending_count(), 2);
    }

    #[test]
    fn the_state_round_trips_as_its_own_snapshot() {
        let mut root = AggregateRoot::<Organisation>::new("o");
        root.execute(OrganisationCommand::CreatePersonal {
            slug: Username::parse("kasper").unwrap(),
            owner: Uuid::nil(),
            at: at(),
        })
        .unwrap();
        let back: Organisation =
            serde_json::from_value(serde_json::to_value(&root.state).unwrap()).unwrap();
        assert_eq!(back, root.state);
    }
}
