//! The organisation aggregate (`grund-organisation`). Everything grund will
//! manage (apps, machines, releases) belongs to an organisation, never to an
//! account, and so does billing. People act on those things as members.
//!
//! Every rule about who may change membership is decided here, from the
//! organisation's own state: roles, the last owner, invitations and their
//! expiry. The caller supplies the clock (`at`) and the acting account.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::names::Username;

pub const ORGANISATION_CATEGORY: &str = "grund-organisation";

/// How long an invitation link stays valid.
pub const INVITATION_TTL: Duration = Duration::days(7);

/// The most invitations an organisation may have pending at once.
pub const MAX_PENDING_INVITATIONS: usize = 50;

/// What a member may do. Owners may do everything, including billing and
/// managing other owners; admins manage members and admins; members use
/// what the organisation owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Member,
    Admin,
    Owner,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }

    /// The role named `text`, as stored and as submitted by forms.
    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "owner" => Some(Role::Owner),
            "admin" => Some(Role::Admin),
            "member" => Some(Role::Member),
            _ => None,
        }
    }

    /// Whether this role may invite, revoke and remove members and admins.
    pub fn manages_members(self) -> bool {
        self >= Role::Admin
    }
}

/// How an organisation came to be. Provenance only: no rule depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganisationKind {
    /// Made at sign-up, named after the account.
    Personal,
    /// Made later by someone signed in.
    Shared,
    /// The one organisation of a single-organisation instance.
    Instance,
}

impl OrganisationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OrganisationKind::Personal => "personal",
            OrganisationKind::Shared => "shared",
            OrganisationKind::Instance => "instance",
        }
    }
}

/// Why a member stopped being one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Departure {
    Removed,
    Left,
}

/// Why an invitation stopped working before it was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Withdrawal {
    Revoked,
    /// A new invitation to the same address took its place.
    Replaced,
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
    MemberRoleChanged {
        account_id: Uuid,
        role: Role,
        changed_by: Uuid,
        changed_at: DateTime<Utc>,
    },
    MemberRemoved {
        account_id: Uuid,
        departure: Departure,
        removed_by: Uuid,
        removed_at: DateTime<Utc>,
    },
    InvitationIssued {
        invitation_id: Uuid,
        email_digest: String,
        role: Role,
        invited_by: Uuid,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
    InvitationWithdrawn {
        invitation_id: Uuid,
        withdrawal: Withdrawal,
        withdrawn_by: Uuid,
        withdrawn_at: DateTime<Utc>,
    },
    InvitationAccepted {
        invitation_id: Uuid,
        account_id: Uuid,
        accepted_at: DateTime<Utc>,
    },
}

/// A member and their role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub account_id: Uuid,
    pub role: Role,
}

/// An invitation that has been neither used nor withdrawn. It may still have
/// expired: whether it has depends on the time of the question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingInvitation {
    pub invitation_id: Uuid,
    pub email_digest: String,
    pub role: Role,
    pub expires_at: DateTime<Utc>,
}

/// What `apply` builds. It is also the snapshot, taken every 100 events:
/// membership changes accumulate for the organisation's whole life.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Organisation {
    pub exists: bool,
    pub slug: Option<Username>,
    pub members: Vec<Member>,
    #[serde(default)]
    pub invitations: Vec<PendingInvitation>,
}

impl Organisation {
    pub fn role_of(&self, account_id: Uuid) -> Option<Role> {
        self.members
            .iter()
            .find(|m| m.account_id == account_id)
            .map(|m| m.role)
    }

    pub fn owners(&self) -> usize {
        self.members
            .iter()
            .filter(|m| m.role == Role::Owner)
            .count()
    }

    /// The invitation, if it is still usable at `at`.
    pub fn open_invitation(
        &self,
        invitation_id: Uuid,
        at: DateTime<Utc>,
    ) -> Option<&PendingInvitation> {
        self.invitations
            .iter()
            .find(|i| i.invitation_id == invitation_id && i.expires_at > at)
    }

    fn open_invitations(&self, at: DateTime<Utc>) -> impl Iterator<Item = &PendingInvitation> {
        self.invitations.iter().filter(move |i| i.expires_at > at)
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
            }
            | OrganisationEvent::MemberRoleChanged {
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
            OrganisationEvent::MemberRemoved { account_id, .. } => {
                self.members.retain(|m| m.account_id != *account_id);
            }
            OrganisationEvent::InvitationIssued {
                invitation_id,
                email_digest,
                role,
                issued_at,
                expires_at,
                ..
            } => {
                self.invitations.retain(|i| i.expires_at > *issued_at);
                self.invitations.push(PendingInvitation {
                    invitation_id: *invitation_id,
                    email_digest: email_digest.clone(),
                    role: *role,
                    expires_at: *expires_at,
                });
            }
            OrganisationEvent::InvitationWithdrawn { invitation_id, .. }
            | OrganisationEvent::InvitationAccepted { invitation_id, .. } => {
                self.invitations
                    .retain(|i| i.invitation_id != *invitation_id);
            }
        }
    }
}

impl mire::Snapshot for Organisation {
    const SNAPSHOT_VERSION: i32 = 2;
    const SNAPSHOT_FREQUENCY: i64 = 100;
}

#[derive(Debug, Clone)]
pub enum OrganisationCommand {
    /// Creates the organisation with `owner` as its only member.
    Create {
        slug: Username,
        kind: OrganisationKind,
        owner: Uuid,
        at: DateTime<Utc>,
    },
    /// Invites the address behind `email_digest`. A pending invitation to the
    /// same address is replaced.
    Invite {
        actor: Uuid,
        invitation_id: Uuid,
        email_digest: String,
        role: Role,
        at: DateTime<Utc>,
    },
    RevokeInvitation {
        actor: Uuid,
        invitation_id: Uuid,
        at: DateTime<Utc>,
    },
    /// Uses an invitation: the account joins with the invited role. The
    /// account's verified address must be the invited one.
    AcceptInvitation {
        invitation_id: Uuid,
        account_id: Uuid,
        email_digest: String,
        at: DateTime<Utc>,
    },
    ChangeRole {
        actor: Uuid,
        account_id: Uuid,
        role: Role,
        at: DateTime<Utc>,
    },
    /// Removes a member; when `actor` is the member, they leave.
    RemoveMember {
        actor: Uuid,
        account_id: Uuid,
        at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrganisationError {
    #[error("the organisation already exists")]
    AlreadyExists,
    #[error("no such organisation")]
    NotFound,
    #[error("your role does not allow that")]
    NotAllowed,
    #[error("no such member")]
    NoSuchMember,
    #[error("an organisation needs at least one owner")]
    LastOwner,
    #[error("this invitation has been used, withdrawn or has expired")]
    NoSuchInvitation,
    #[error("this invitation is for another address")]
    WrongAddress,
    #[error("already a member")]
    AlreadyMember,
    #[error("too many pending invitations")]
    TooManyInvitations,
    #[error("owners are made by promoting a member, not by invitation")]
    OwnerByInvitation,
}

impl mire::Command for OrganisationCommand {
    type Aggregate = Organisation;
    type Error = OrganisationError;
    type Events = Vec<OrganisationEvent>;

    fn handle(
        self,
        organisation: &Organisation,
    ) -> Result<Vec<OrganisationEvent>, OrganisationError> {
        if let OrganisationCommand::Create {
            slug,
            kind,
            owner,
            at,
        } = self
        {
            if organisation.exists {
                return Err(OrganisationError::AlreadyExists);
            }
            return Ok(vec![
                OrganisationEvent::Created {
                    slug,
                    kind,
                    created_by: owner,
                    created_at: at,
                },
                OrganisationEvent::MemberAdded {
                    account_id: owner,
                    role: Role::Owner,
                    added_at: at,
                },
            ]);
        }
        if !organisation.exists {
            return Err(OrganisationError::NotFound);
        }
        let managing = |actor: Uuid| match organisation.role_of(actor) {
            Some(role) if role.manages_members() => Ok(role),
            _ => Err(OrganisationError::NotAllowed),
        };
        match self {
            OrganisationCommand::Create { .. } => unreachable!("handled above"),
            OrganisationCommand::Invite {
                actor,
                invitation_id,
                email_digest,
                role,
                at,
            } => {
                managing(actor)?;
                if role == Role::Owner {
                    return Err(OrganisationError::OwnerByInvitation);
                }
                let replaced: Vec<Uuid> = organisation
                    .open_invitations(at)
                    .filter(|i| i.email_digest == email_digest)
                    .map(|i| i.invitation_id)
                    .collect();
                let open = organisation.open_invitations(at).count() - replaced.len();
                if open >= MAX_PENDING_INVITATIONS {
                    return Err(OrganisationError::TooManyInvitations);
                }
                let mut events: Vec<OrganisationEvent> = replaced
                    .into_iter()
                    .map(|invitation_id| OrganisationEvent::InvitationWithdrawn {
                        invitation_id,
                        withdrawal: Withdrawal::Replaced,
                        withdrawn_by: actor,
                        withdrawn_at: at,
                    })
                    .collect();
                events.push(OrganisationEvent::InvitationIssued {
                    invitation_id,
                    email_digest,
                    role,
                    invited_by: actor,
                    issued_at: at,
                    expires_at: at + INVITATION_TTL,
                });
                Ok(events)
            }
            OrganisationCommand::RevokeInvitation {
                actor,
                invitation_id,
                at,
            } => {
                managing(actor)?;
                if organisation.open_invitation(invitation_id, at).is_none() {
                    return Err(OrganisationError::NoSuchInvitation);
                }
                Ok(vec![OrganisationEvent::InvitationWithdrawn {
                    invitation_id,
                    withdrawal: Withdrawal::Revoked,
                    withdrawn_by: actor,
                    withdrawn_at: at,
                }])
            }
            OrganisationCommand::AcceptInvitation {
                invitation_id,
                account_id,
                email_digest,
                at,
            } => {
                let invitation = organisation
                    .open_invitation(invitation_id, at)
                    .ok_or(OrganisationError::NoSuchInvitation)?;
                if invitation.email_digest != email_digest {
                    return Err(OrganisationError::WrongAddress);
                }
                if organisation.role_of(account_id).is_some() {
                    return Err(OrganisationError::AlreadyMember);
                }
                Ok(vec![
                    OrganisationEvent::InvitationAccepted {
                        invitation_id,
                        account_id,
                        accepted_at: at,
                    },
                    OrganisationEvent::MemberAdded {
                        account_id,
                        role: invitation.role,
                        added_at: at,
                    },
                ])
            }
            OrganisationCommand::ChangeRole {
                actor,
                account_id,
                role,
                at,
            } => {
                let actor_role = managing(actor)?;
                let current = organisation
                    .role_of(account_id)
                    .ok_or(OrganisationError::NoSuchMember)?;
                if current == role {
                    return Ok(vec![]);
                }
                if (current == Role::Owner || role == Role::Owner) && actor_role != Role::Owner {
                    return Err(OrganisationError::NotAllowed);
                }
                if current == Role::Owner && organisation.owners() == 1 {
                    return Err(OrganisationError::LastOwner);
                }
                Ok(vec![OrganisationEvent::MemberRoleChanged {
                    account_id,
                    role,
                    changed_by: actor,
                    changed_at: at,
                }])
            }
            OrganisationCommand::RemoveMember {
                actor,
                account_id,
                at,
            } => {
                let current = organisation
                    .role_of(account_id)
                    .ok_or(OrganisationError::NoSuchMember)?;
                let departure = if actor == account_id {
                    Departure::Left
                } else {
                    let actor_role = managing(actor)?;
                    if current == Role::Owner && actor_role != Role::Owner {
                        return Err(OrganisationError::NotAllowed);
                    }
                    Departure::Removed
                };
                if current == Role::Owner && organisation.owners() == 1 {
                    return Err(OrganisationError::LastOwner);
                }
                Ok(vec![OrganisationEvent::MemberRemoved {
                    account_id,
                    departure,
                    removed_by: actor,
                    removed_at: at,
                }])
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

    struct Org {
        root: AggregateRoot<Organisation>,
        owner: Uuid,
    }

    impl Org {
        fn new() -> Self {
            let owner = Uuid::now_v7();
            let mut root = AggregateRoot::<Organisation>::new("o");
            root.execute(OrganisationCommand::Create {
                slug: Username::parse("acme").unwrap(),
                kind: OrganisationKind::Shared,
                owner,
                at: at(),
            })
            .unwrap();
            Org { root, owner }
        }

        fn run(&mut self, command: OrganisationCommand) -> Result<(), OrganisationError> {
            self.root.execute(command).map(|_| ())
        }

        fn invite(
            &mut self,
            actor: Uuid,
            digest: &str,
            role: Role,
        ) -> Result<Uuid, OrganisationError> {
            let invitation_id = Uuid::now_v7();
            self.run(OrganisationCommand::Invite {
                actor,
                invitation_id,
                email_digest: digest.into(),
                role,
                at: at(),
            })?;
            Ok(invitation_id)
        }

        fn join(&mut self, role: Role) -> Uuid {
            let account_id = Uuid::now_v7();
            let digest = account_id.to_string();
            let invitation_id = self.invite(self.owner, &digest, role).unwrap();
            self.run(OrganisationCommand::AcceptInvitation {
                invitation_id,
                account_id,
                email_digest: digest,
                at: at(),
            })
            .unwrap();
            account_id
        }

        fn role_of(&self, account_id: Uuid) -> Option<Role> {
            self.root.state.role_of(account_id)
        }
    }

    #[test]
    fn an_organisation_is_created_with_its_owner_as_the_only_member() {
        let org = Org::new();
        assert_eq!(org.role_of(org.owner), Some(Role::Owner));
        assert_eq!(org.root.state.members.len(), 1);
    }

    #[test]
    fn creating_it_twice_is_refused() {
        let mut org = Org::new();
        let error = org
            .run(OrganisationCommand::Create {
                slug: Username::parse("acme").unwrap(),
                kind: OrganisationKind::Shared,
                owner: org.owner,
                at: at(),
            })
            .unwrap_err();
        assert_eq!(error, OrganisationError::AlreadyExists);
    }

    #[test]
    fn an_invitation_admits_its_address_once_with_its_role() {
        let mut org = Org::new();
        let account_id = Uuid::now_v7();
        let invitation_id = org.invite(org.owner, "d1", Role::Admin).unwrap();
        let accept = |email_digest: &str| OrganisationCommand::AcceptInvitation {
            invitation_id,
            account_id,
            email_digest: email_digest.into(),
            at: at(),
        };
        assert_eq!(
            org.run(accept("other")),
            Err(OrganisationError::WrongAddress)
        );
        org.run(accept("d1")).unwrap();
        assert_eq!(org.role_of(account_id), Some(Role::Admin));
        assert_eq!(
            org.run(accept("d1")),
            Err(OrganisationError::NoSuchInvitation)
        );
    }

    #[test]
    fn an_invitation_expires_after_seven_days() {
        let mut org = Org::new();
        let invitation_id = org.invite(org.owner, "d1", Role::Member).unwrap();
        let late = OrganisationCommand::AcceptInvitation {
            invitation_id,
            account_id: Uuid::now_v7(),
            email_digest: "d1".into(),
            at: at() + INVITATION_TTL,
        };
        assert_eq!(org.run(late), Err(OrganisationError::NoSuchInvitation));
    }

    #[test]
    fn inviting_an_address_again_replaces_its_pending_invitation() {
        let mut org = Org::new();
        let first = org.invite(org.owner, "d1", Role::Member).unwrap();
        let second = org.invite(org.owner, "d1", Role::Admin).unwrap();
        assert!(org.root.state.open_invitation(first, at()).is_none());
        assert_eq!(
            org.root.state.open_invitation(second, at()).unwrap().role,
            Role::Admin
        );
    }

    #[test]
    fn members_cannot_invite_and_nobody_is_invited_as_owner() {
        let mut org = Org::new();
        let member = org.join(Role::Member);
        assert_eq!(
            org.invite(member, "d1", Role::Member),
            Err(OrganisationError::NotAllowed)
        );
        assert_eq!(
            org.invite(org.owner, "d1", Role::Owner),
            Err(OrganisationError::OwnerByInvitation)
        );
        let outsider = Uuid::now_v7();
        assert_eq!(
            org.invite(outsider, "d1", Role::Member),
            Err(OrganisationError::NotAllowed)
        );
    }

    #[test]
    fn pending_invitations_are_capped_and_expired_ones_do_not_count() {
        let mut org = Org::new();
        for n in 0..MAX_PENDING_INVITATIONS {
            org.invite(org.owner, &format!("d{n}"), Role::Member)
                .unwrap();
        }
        assert_eq!(
            org.invite(org.owner, "one-more", Role::Member),
            Err(OrganisationError::TooManyInvitations)
        );
        org.run(OrganisationCommand::Invite {
            actor: org.owner,
            invitation_id: Uuid::now_v7(),
            email_digest: "later".into(),
            role: Role::Member,
            at: at() + INVITATION_TTL,
        })
        .unwrap();
        assert_eq!(
            org.root.state.invitations.len(),
            1,
            "expired invitations were dropped"
        );
    }

    #[test]
    fn admins_manage_members_and_admins_but_not_owners() {
        let mut org = Org::new();
        let admin = org.join(Role::Admin);
        let member = org.join(Role::Member);
        let change = |actor, account_id, role| OrganisationCommand::ChangeRole {
            actor,
            account_id,
            role,
            at: at(),
        };
        org.run(change(admin, member, Role::Admin)).unwrap();
        org.run(change(admin, member, Role::Member)).unwrap();
        assert_eq!(
            org.run(change(admin, member, Role::Owner)),
            Err(OrganisationError::NotAllowed)
        );
        assert_eq!(
            org.run(change(admin, org.owner, Role::Member)),
            Err(OrganisationError::NotAllowed)
        );
        assert_eq!(
            org.run(OrganisationCommand::RemoveMember {
                actor: admin,
                account_id: org.owner,
                at: at(),
            }),
            Err(OrganisationError::NotAllowed)
        );
        assert_eq!(
            org.run(change(member, admin, Role::Member)),
            Err(OrganisationError::NotAllowed)
        );
        org.run(OrganisationCommand::RemoveMember {
            actor: admin,
            account_id: member,
            at: at(),
        })
        .unwrap();
        assert_eq!(org.role_of(member), None);
    }

    #[test]
    fn the_last_owner_can_neither_leave_nor_be_demoted() {
        let mut org = Org::new();
        let owner = org.owner;
        assert_eq!(
            org.run(OrganisationCommand::RemoveMember {
                actor: owner,
                account_id: owner,
                at: at(),
            }),
            Err(OrganisationError::LastOwner)
        );
        assert_eq!(
            org.run(OrganisationCommand::ChangeRole {
                actor: owner,
                account_id: owner,
                role: Role::Admin,
                at: at(),
            }),
            Err(OrganisationError::LastOwner)
        );
        let second = org.join(Role::Member);
        org.run(OrganisationCommand::ChangeRole {
            actor: owner,
            account_id: second,
            role: Role::Owner,
            at: at(),
        })
        .unwrap();
        org.run(OrganisationCommand::RemoveMember {
            actor: owner,
            account_id: owner,
            at: at(),
        })
        .unwrap();
        assert_eq!(org.role_of(owner), None);
        assert_eq!(org.root.state.owners(), 1);
    }

    #[test]
    fn a_member_may_leave_and_accepting_twice_is_refused() {
        let mut org = Org::new();
        let member = org.join(Role::Member);
        let invitation_id = org.invite(org.owner, "again", Role::Member).unwrap();
        assert_eq!(
            org.run(OrganisationCommand::AcceptInvitation {
                invitation_id,
                account_id: member,
                email_digest: "again".into(),
                at: at(),
            }),
            Err(OrganisationError::AlreadyMember)
        );
        org.run(OrganisationCommand::RemoveMember {
            actor: member,
            account_id: member,
            at: at(),
        })
        .unwrap();
        assert_eq!(org.role_of(member), None);
    }

    #[test]
    fn a_personal_event_stream_from_before_invitations_still_loads() {
        let created: OrganisationEvent = serde_json::from_value(serde_json::json!({
            "type": "created",
            "slug": "kasper",
            "kind": "personal",
            "created_by": Uuid::nil(),
            "created_at": at(),
        }))
        .unwrap();
        let snapshot: Organisation = serde_json::from_value(serde_json::json!({
            "exists": true,
            "slug": "kasper",
            "members": [{"account_id": Uuid::nil(), "role": "owner"}],
        }))
        .unwrap();
        assert!(matches!(
            created,
            OrganisationEvent::Created {
                kind: OrganisationKind::Personal,
                ..
            }
        ));
        assert!(snapshot.invitations.is_empty());
    }

    #[test]
    fn the_state_round_trips_as_its_own_snapshot() {
        let mut org = Org::new();
        org.invite(org.owner, "d1", Role::Member).unwrap();
        let back: Organisation =
            serde_json::from_value(serde_json::to_value(&org.root.state).unwrap()).unwrap();
        assert_eq!(back, org.root.state);
    }
}
