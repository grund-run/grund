//! A custom domain (grund-docs website/design/app-domains.md §3,
//! design/traffic.md §5.3): a name an organisation owns, proved with a TXT
//! record grund generates, then bound to one of its apps. One stream per
//! domain the organisation added; adding the same name again after removing
//! it is a new stream.
//!
//! The aggregate decides only what follows from its own history. Whether
//! the TXT record is there, whether another organisation holds the name and
//! whether the name is cooling down after a release are the service's to
//! find out before it asks; the read model's unique index is the last word
//! on who holds a verified name.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CUSTOM_DOMAIN_CATEGORY: &str = "grund-custom-domain";

/// The label the verification record sits under: `_grund.<name>`.
pub const VERIFICATION_LABEL: &str = "_grund";

/// The longest name a domain may have (RFC 1035 §2.3.4, without the root).
pub const MAX_NAME_BYTES: usize = 253;

/// A custom domain's name, lowercase, without a trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DomainName(String);

/// Why a name is not a domain grund can serve.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainNameError {
    #[error("enter a domain name, like app.example.com")]
    Empty,
    #[error("a domain name is at most 253 characters")]
    TooLong,
    #[error(
        "write an international name in its xn-- form (punycode); grund takes letters, digits, hyphens and dots"
    )]
    NotAscii,
    #[error("a wildcard is not a name grund can verify; add each name on its own")]
    Wildcard,
    #[error("enter the name alone, without https:// or a path")]
    NotAName,
    #[error("a domain needs at least two labels, like example.com")]
    OneLabel,
    #[error(
        "each part between dots is 1 to 63 letters, digits or hyphens, not starting or ending with a hyphen"
    )]
    BadLabel,
    #[error("the last part of a domain is a top-level domain of letters, like com")]
    BadTld,
}

impl DomainName {
    /// Accepts `App.Example.com.` as `app.example.com`.
    pub fn parse(input: &str) -> Result<Self, DomainNameError> {
        let trimmed = input.trim();
        let name = trimmed.strip_suffix('.').unwrap_or(trimmed);
        if name.is_empty() {
            return Err(DomainNameError::Empty);
        }
        if !name.is_ascii() {
            return Err(DomainNameError::NotAscii);
        }
        if name.contains('*') {
            return Err(DomainNameError::Wildcard);
        }
        if name.contains(['/', ':', '@', ' ', '?', '#']) {
            return Err(DomainNameError::NotAName);
        }
        if name.len() > MAX_NAME_BYTES {
            return Err(DomainNameError::TooLong);
        }
        let name = name.to_ascii_lowercase();
        let labels: Vec<&str> = name.split('.').collect();
        if labels.len() < 2 {
            return Err(DomainNameError::OneLabel);
        }
        let label_ok = |label: &&str| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        };
        if !labels.iter().all(label_ok) {
            return Err(DomainNameError::BadLabel);
        }
        let tld = labels.last().copied().unwrap_or_default();
        let tld_ok = tld.len() >= 2
            && (tld.bytes().all(|b| b.is_ascii_lowercase()) || tld.starts_with("xn--"));
        if !tld_ok {
            return Err(DomainNameError::BadTld);
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Where the verification record goes: `_grund.<name>`.
    pub fn verification_name(&self) -> String {
        format!("{VERIFICATION_LABEL}.{}", self.0)
    }

    /// Whether this is `parent` or a name under it.
    pub fn is_within(&self, parent: &str) -> bool {
        let parent = parent.trim_end_matches('.').to_ascii_lowercase();
        !parent.is_empty()
            && (self.0 == parent
                || self
                    .0
                    .strip_suffix(&parent)
                    .is_some_and(|rest| rest.ends_with('.')))
    }
}

impl TryFrom<String> for DomainName {
    type Error = DomainNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<DomainName> for String {
    fn from(value: DomainName) -> Self {
        value.0
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, mire::EventData)]
#[serde(tag = "type", rename_all = "snake_case")]
#[mire(entity = "grund-custom-domain")]
pub enum DomainEvent {
    /// The organisation asked for the name; `token` is what its TXT record
    /// must hold.
    Added {
        organisation_id: Uuid,
        name: DomainName,
        token: String,
        added_by: Uuid,
        added_at: DateTime<Utc>,
    },
    /// The TXT record was found holding the token: the name is the
    /// organisation's on this instance until it is removed.
    Verified {
        verified_by: Uuid,
        verified_at: DateTime<Utc>,
    },
    /// Requests for the name go to the app's public port.
    Bound {
        app_id: Uuid,
        bound_by: Uuid,
        bound_at: DateTime<Utc>,
    },
    Unbound {
        app_id: Uuid,
        unbound_by: Uuid,
        unbound_at: DateTime<Utc>,
    },
    /// The organisation let the name go. If it was verified, another
    /// organisation can verify it only after the cool-down.
    Removed {
        removed_by: Uuid,
        removed_at: DateTime<Utc>,
    },
}

/// A custom domain as its events leave it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Domain {
    pub exists: bool,
    pub organisation_id: Uuid,
    pub name: Option<DomainName>,
    pub token: String,
    pub verified_at: Option<DateTime<Utc>>,
    pub app_id: Option<Uuid>,
    pub removed: bool,
}

impl mire::Aggregate for Domain {
    type Event = DomainEvent;

    fn stream_category() -> &'static str {
        CUSTOM_DOMAIN_CATEGORY
    }

    fn apply(&mut self, event: &DomainEvent) {
        match event {
            DomainEvent::Added {
                organisation_id,
                name,
                token,
                ..
            } => {
                self.exists = true;
                self.organisation_id = *organisation_id;
                self.name = Some(name.clone());
                self.token = token.clone();
            }
            DomainEvent::Verified { verified_at, .. } => self.verified_at = Some(*verified_at),
            DomainEvent::Bound { app_id, .. } => self.app_id = Some(*app_id),
            DomainEvent::Unbound { .. } => self.app_id = None,
            DomainEvent::Removed { .. } => {
                self.removed = true;
                self.app_id = None;
            }
        }
    }
}

impl mire::Snapshot for Domain {
    const SNAPSHOT_VERSION: i32 = 1;
    const SNAPSHOT_FREQUENCY: i64 = 100;
}

/// What can be asked of a custom domain. Authorization, the DNS lookup and
/// the checks across organisations are the service's, before.
#[derive(Debug, Clone)]
pub enum DomainCommand {
    Add {
        actor: Uuid,
        organisation_id: Uuid,
        name: DomainName,
        token: String,
        at: DateTime<Utc>,
    },
    /// The service found the token in the name's TXT record. Verifying a
    /// verified name again changes nothing.
    Verify { actor: Uuid, at: DateTime<Utc> },
    /// Binding to the app it is bound to changes nothing; binding to
    /// another moves it.
    Bind {
        actor: Uuid,
        app_id: Uuid,
        at: DateTime<Utc>,
    },
    /// Unbinding a name bound to nothing changes nothing.
    Unbind { actor: Uuid, at: DateTime<Utc> },
    /// Unbinds it first if it is bound.
    Remove { actor: Uuid, at: DateTime<Utc> },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("the domain already exists")]
    AlreadyExists,
    #[error("no such domain")]
    NotFound,
    #[error("the domain is not verified yet")]
    NotVerified,
}

impl mire::Command for DomainCommand {
    type Aggregate = Domain;
    type Error = DomainError;
    type Events = Vec<DomainEvent>;

    fn handle(self, domain: &Domain) -> Result<Vec<DomainEvent>, DomainError> {
        if let DomainCommand::Add {
            actor,
            organisation_id,
            name,
            token,
            at,
        } = self
        {
            if domain.exists {
                return Err(DomainError::AlreadyExists);
            }
            return Ok(vec![DomainEvent::Added {
                organisation_id,
                name,
                token,
                added_by: actor,
                added_at: at,
            }]);
        }
        if !domain.exists || domain.removed {
            return Err(DomainError::NotFound);
        }
        Ok(match self {
            DomainCommand::Add { .. } => unreachable!("handled above"),
            DomainCommand::Verify { actor, at } => match domain.verified_at {
                Some(_) => Vec::new(),
                None => vec![DomainEvent::Verified {
                    verified_by: actor,
                    verified_at: at,
                }],
            },
            DomainCommand::Bind { actor, app_id, at } => {
                if domain.verified_at.is_none() {
                    return Err(DomainError::NotVerified);
                }
                match domain.app_id {
                    Some(bound) if bound == app_id => Vec::new(),
                    _ => vec![DomainEvent::Bound {
                        app_id,
                        bound_by: actor,
                        bound_at: at,
                    }],
                }
            }
            DomainCommand::Unbind { actor, at } => match domain.app_id {
                Some(app_id) => vec![DomainEvent::Unbound {
                    app_id,
                    unbound_by: actor,
                    unbound_at: at,
                }],
                None => Vec::new(),
            },
            DomainCommand::Remove { actor, at } => {
                let mut events = Vec::new();
                if let Some(app_id) = domain.app_id {
                    events.push(DomainEvent::Unbound {
                        app_id,
                        unbound_by: actor,
                        unbound_at: at,
                    });
                }
                events.push(DomainEvent::Removed {
                    removed_by: actor,
                    removed_at: at,
                });
                events
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use mire::{Aggregate, Command};

    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).unwrap()
    }

    fn fold(events: &[DomainEvent]) -> Domain {
        let mut domain = Domain::default();
        for event in events {
            domain.apply(event);
        }
        domain
    }

    fn added() -> Vec<DomainEvent> {
        DomainCommand::Add {
            actor: Uuid::nil(),
            organisation_id: Uuid::from_u128(7),
            name: DomainName::parse("app.example.com").unwrap(),
            token: "token".into(),
            at: at(),
        }
        .handle(&Domain::default())
        .unwrap()
    }

    #[test]
    fn a_name_is_lowercased_and_loses_its_trailing_dot() {
        assert_eq!(
            DomainName::parse(" App.Example.COM. ").unwrap().as_str(),
            "app.example.com"
        );
        assert_eq!(
            DomainName::parse("xn--bcher-kva.example").unwrap().as_str(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn what_is_not_a_servable_name_is_refused_with_the_reason() {
        for (input, error) in [
            ("", DomainNameError::Empty),
            ("localhost", DomainNameError::OneLabel),
            ("*.example.com", DomainNameError::Wildcard),
            ("https://app.example.com", DomainNameError::NotAName),
            ("app.example.com/x", DomainNameError::NotAName),
            ("bücher.example", DomainNameError::NotAscii),
            ("-app.example.com", DomainNameError::BadLabel),
            ("app..example.com", DomainNameError::BadLabel),
            ("app_1.example.com", DomainNameError::BadLabel),
            ("app.example.c0m", DomainNameError::BadTld),
            ("10.0.0.1", DomainNameError::BadTld),
        ] {
            assert_eq!(DomainName::parse(input), Err(error), "{input}");
        }
        let long = format!("{}.com", "a.".repeat(130));
        assert_eq!(DomainName::parse(&long), Err(DomainNameError::TooLong));
    }

    #[test]
    fn a_name_is_within_its_parents_only() {
        let name = DomainName::parse("app.apps.example.com").unwrap();
        assert!(name.is_within("apps.example.com"));
        assert!(name.is_within("APPS.example.com."));
        assert!(name.is_within("app.apps.example.com"));
        assert!(!name.is_within("ps.example.com"));
        assert!(!name.is_within(""));
        assert_eq!(name.verification_name(), "_grund.app.apps.example.com");
    }

    #[test]
    fn an_unverified_domain_cannot_be_bound() {
        let domain = fold(&added());
        assert_eq!(
            DomainCommand::Bind {
                actor: Uuid::nil(),
                app_id: Uuid::from_u128(1),
                at: at()
            }
            .handle(&domain),
            Err(DomainError::NotVerified)
        );
    }

    #[test]
    fn a_verified_domain_binds_moves_and_verifying_again_changes_nothing() {
        let mut events = added();
        let verify = || DomainCommand::Verify {
            actor: Uuid::nil(),
            at: at(),
        };
        events.extend(verify().handle(&fold(&events)).unwrap());
        assert!(verify().handle(&fold(&events)).unwrap().is_empty());
        let bind = |app| DomainCommand::Bind {
            actor: Uuid::nil(),
            app_id: Uuid::from_u128(app),
            at: at(),
        };
        events.extend(bind(1).handle(&fold(&events)).unwrap());
        assert!(bind(1).handle(&fold(&events)).unwrap().is_empty());
        events.extend(bind(2).handle(&fold(&events)).unwrap());
        assert_eq!(fold(&events).app_id, Some(Uuid::from_u128(2)));
    }

    #[test]
    fn removing_a_bound_domain_unbinds_it_first_and_then_it_is_gone() {
        let mut events = added();
        for command in [
            DomainCommand::Verify {
                actor: Uuid::nil(),
                at: at(),
            },
            DomainCommand::Bind {
                actor: Uuid::nil(),
                app_id: Uuid::from_u128(1),
                at: at(),
            },
        ] {
            events.extend(command.handle(&fold(&events)).unwrap());
        }
        let removed = DomainCommand::Remove {
            actor: Uuid::nil(),
            at: at(),
        }
        .handle(&fold(&events))
        .unwrap();
        assert!(matches!(removed[0], DomainEvent::Unbound { .. }));
        assert!(matches!(removed[1], DomainEvent::Removed { .. }));
        events.extend(removed);
        assert_eq!(
            DomainCommand::Unbind {
                actor: Uuid::nil(),
                at: at()
            }
            .handle(&fold(&events)),
            Err(DomainError::NotFound)
        );
    }
}
