//! The account aggregate (`grund-account`): a person's security history.
//!
//! Events carry no email address, password hash or provider subject; those
//! live in plain tables that can be erased (docs/design/auth.md §1). The
//! verified address appears only as a SHA-256 digest.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::names::Username;

pub const ACCOUNT_CATEGORY: &str = "grund-account";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMethod {
    Password,
    Social { provider: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordChangeReason {
    /// Through an emailed reset link.
    Reset,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, mire::EventData)]
#[serde(tag = "type", rename_all = "snake_case")]
#[mire(entity = "grund-account")]
pub enum AccountEvent {
    Registered {
        username: Username,
        organisation_id: Uuid,
        method: RegistrationMethod,
        registered_at: DateTime<Utc>,
    },
    EmailVerified {
        email_digest: String,
        verified_at: DateTime<Utc>,
    },
    PasswordChanged {
        reason: PasswordChangeReason,
        changed_at: DateTime<Utc>,
    },
    IdentityLinked {
        provider: String,
        identity_id: Uuid,
        linked_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountStatus {
    #[default]
    NonExistent,
    Active,
}

/// What `apply` builds. It is also the snapshot, taken every 100 events:
/// resets and linked identities accumulate for the account's whole life.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub status: AccountStatus,
    pub username: Option<Username>,
    pub organisation_id: Option<Uuid>,
    pub verified_email_digest: Option<String>,
    pub identities: Vec<LinkedIdentity>,
    pub password_changes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedIdentity {
    pub provider: String,
    pub identity_id: Uuid,
}

impl Account {
    pub fn is_email_verified(&self) -> bool {
        self.verified_email_digest.is_some()
    }
}

impl mire::Aggregate for Account {
    type Event = AccountEvent;

    fn stream_category() -> &'static str {
        ACCOUNT_CATEGORY
    }

    fn apply(&mut self, event: &AccountEvent) {
        match event {
            AccountEvent::Registered {
                username,
                organisation_id,
                ..
            } => {
                self.status = AccountStatus::Active;
                self.username = Some(username.clone());
                self.organisation_id = Some(*organisation_id);
            }
            AccountEvent::EmailVerified { email_digest, .. } => {
                self.verified_email_digest = Some(email_digest.clone());
            }
            AccountEvent::PasswordChanged { .. } => {
                self.password_changes = self.password_changes.saturating_add(1);
            }
            AccountEvent::IdentityLinked {
                provider,
                identity_id,
                ..
            } => {
                if !self
                    .identities
                    .iter()
                    .any(|i| i.identity_id == *identity_id)
                {
                    self.identities.push(LinkedIdentity {
                        provider: provider.clone(),
                        identity_id: *identity_id,
                    });
                }
            }
        }
    }
}

impl mire::Snapshot for Account {
    const SNAPSHOT_VERSION: i32 = 1;
    const SNAPSHOT_FREQUENCY: i64 = 100;
}

#[derive(Debug, Clone)]
pub enum AccountCommand {
    Register {
        username: Username,
        organisation_id: Uuid,
        method: RegistrationMethod,
        at: DateTime<Utc>,
    },
    VerifyEmail {
        email_digest: String,
        at: DateTime<Utc>,
    },
    ChangePassword {
        reason: PasswordChangeReason,
        at: DateTime<Utc>,
    },
    LinkIdentity {
        provider: String,
        identity_id: Uuid,
        at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccountError {
    #[error("the account already exists")]
    AlreadyRegistered,
    #[error("no such account")]
    NotFound,
}

impl mire::Command for AccountCommand {
    type Aggregate = Account;
    type Error = AccountError;
    type Events = Vec<AccountEvent>;

    fn handle(self, account: &Account) -> Result<Vec<AccountEvent>, AccountError> {
        let exists = account.status == AccountStatus::Active;
        match self {
            AccountCommand::Register {
                username,
                organisation_id,
                method,
                at,
            } => {
                if exists {
                    return Err(AccountError::AlreadyRegistered);
                }
                Ok(vec![AccountEvent::Registered {
                    username,
                    organisation_id,
                    method,
                    registered_at: at,
                }])
            }
            _ if !exists => Err(AccountError::NotFound),
            AccountCommand::VerifyEmail { email_digest, at } => {
                if account.verified_email_digest.as_deref() == Some(email_digest.as_str()) {
                    return Ok(vec![]);
                }
                Ok(vec![AccountEvent::EmailVerified {
                    email_digest,
                    verified_at: at,
                }])
            }
            AccountCommand::ChangePassword { reason, at } => {
                Ok(vec![AccountEvent::PasswordChanged {
                    reason,
                    changed_at: at,
                }])
            }
            AccountCommand::LinkIdentity {
                provider,
                identity_id,
                at,
            } => {
                if account
                    .identities
                    .iter()
                    .any(|i| i.identity_id == identity_id)
                {
                    return Ok(vec![]);
                }
                Ok(vec![AccountEvent::IdentityLinked {
                    provider,
                    identity_id,
                    linked_at: at,
                }])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use mire::{AggregateRoot, Command};

    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).unwrap()
    }

    fn registered() -> AggregateRoot<Account> {
        let mut root = AggregateRoot::<Account>::new("a");
        root.execute(AccountCommand::Register {
            username: Username::parse("kasper").unwrap(),
            organisation_id: Uuid::nil(),
            method: RegistrationMethod::Password,
            at: at(),
        })
        .unwrap();
        root
    }

    #[test]
    fn registering_twice_is_refused_and_records_nothing() {
        let mut root = registered();
        let error = root
            .execute(AccountCommand::Register {
                username: Username::parse("other").unwrap(),
                organisation_id: Uuid::nil(),
                method: RegistrationMethod::Password,
                at: at(),
            })
            .unwrap_err();
        assert_eq!(error, AccountError::AlreadyRegistered);
        assert_eq!(root.pending_count(), 1);
        assert_eq!(root.state.username.as_ref().unwrap().as_str(), "kasper");
    }

    #[test]
    fn verifying_the_same_address_again_records_nothing() {
        let mut root = registered();
        let verify = || AccountCommand::VerifyEmail {
            email_digest: "d".into(),
            at: at(),
        };
        root.execute(verify()).unwrap();
        root.execute(verify()).unwrap();
        assert_eq!(root.pending_count(), 2);
        assert!(root.state.is_email_verified());
    }

    #[test]
    fn nothing_but_registration_applies_to_an_account_that_does_not_exist() {
        let account = Account::default();
        let error = AccountCommand::ChangePassword {
            reason: PasswordChangeReason::Reset,
            at: at(),
        }
        .handle(&account)
        .unwrap_err();
        assert_eq!(error, AccountError::NotFound);
    }

    #[test]
    fn linking_the_same_identity_twice_links_it_once() {
        let mut root = registered();
        let id = Uuid::now_v7();
        for _ in 0..2 {
            root.execute(AccountCommand::LinkIdentity {
                provider: "github".into(),
                identity_id: id,
                at: at(),
            })
            .unwrap();
        }
        assert_eq!(root.state.identities.len(), 1);
        assert_eq!(root.pending_count(), 2);
    }

    #[test]
    fn the_state_round_trips_as_its_own_snapshot() {
        let mut root = registered();
        root.execute(AccountCommand::VerifyEmail {
            email_digest: "d".into(),
            at: at(),
        })
        .unwrap();
        let json = serde_json::to_value(&root.state).unwrap();
        let back: Account = serde_json::from_value(json).unwrap();
        assert_eq!(back, root.state);
    }

    #[test]
    fn events_serialise_with_a_type_tag_and_no_address() {
        let event = AccountEvent::EmailVerified {
            email_digest: "abc".into(),
            verified_at: at(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "email_verified");
        assert!(!json.to_string().contains('@'));
    }
}
