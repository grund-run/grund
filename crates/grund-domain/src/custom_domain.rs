//! A custom domain (grund-docs website/design/app-domains.md §3,
//! design/traffic.md §5.3): a name an organisation owns, proved with a TXT
//! record grund generates, then bound to one of its apps. A verified parent
//! can also authorise app addresses with durable parent and app ownership.
//! One stream per domain the organisation added; adding the same name again
//! after removing it is a new stream.
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
    #[error(
        "add the parent name without *.; app subdomains are configured after ownership verification"
    )]
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
    /// Ownership was proved by TXT or a verified parent: the name is the
    /// organisation's on this instance until it is removed.
    Verified {
        verified_by: Uuid,
        verified_at: DateTime<Utc>,
    },
    /// The verified name became the organisation's app namespace.
    AppDomainEnabled {
        enabled_by: Uuid,
        enabled_at: DateTime<Utc>,
    },
    /// A verified parent authorised this name for its managed app.
    GeneratedFromParent {
        parent_domain_id: Uuid,
        parent_domain: DomainName,
        managed_app_id: Uuid,
        parent_verified_at: DateTime<Utc>,
        generated_by: Uuid,
        generated_at: DateTime<Utc>,
    },
    /// The owning stack selected another child without releasing its hostname.
    GeneratedReassigned {
        previous_app_id: Uuid,
        app_id: Uuid,
        reassigned_by: Uuid,
        reassigned_at: DateTime<Utc>,
    },
    /// Whether automatic allocation may restore this app's assignment.
    AppDomainAllocationSet {
        enabled: bool,
        changed_by: Uuid,
        changed_at: DateTime<Utc>,
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
    #[serde(default)]
    pub is_app_domain: bool,
    #[serde(default)]
    pub parent_domain_id: Option<Uuid>,
    #[serde(default)]
    pub parent_domain: Option<DomainName>,
    #[serde(default)]
    pub managed_app_id: Option<Uuid>,
    #[serde(default)]
    pub assignment_disabled: bool,
}

/// Proof that a live verified parent enabled app-domain allocation.
#[derive(Debug, Clone)]
pub struct AppDomainAuthority {
    organisation_id: Uuid,
    parent_domain_id: Uuid,
    parent_domain: DomainName,
    parent_verified_at: DateTime<Utc>,
}

impl Domain {
    /// Captures the parent's authority after the service locks namespace policy.
    pub fn app_domain_authority(
        &self,
        parent_domain_id: Uuid,
    ) -> Result<AppDomainAuthority, DomainError> {
        if !self.exists || self.removed {
            return Err(DomainError::NotFound);
        }
        let parent_verified_at = self.verified_at.ok_or(DomainError::NotVerified)?;
        if !self.is_app_domain || self.parent_domain_id.is_some() {
            return Err(DomainError::InvalidAuthority);
        }
        let parent_domain = self.name.clone().ok_or(DomainError::InvalidAuthority)?;
        Ok(AppDomainAuthority {
            organisation_id: self.organisation_id,
            parent_domain_id,
            parent_domain,
            parent_verified_at,
        })
    }
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
            DomainEvent::AppDomainEnabled { .. } => self.is_app_domain = true,
            DomainEvent::GeneratedFromParent {
                parent_domain_id,
                parent_domain,
                managed_app_id,
                ..
            } => {
                self.parent_domain_id = Some(*parent_domain_id);
                self.parent_domain = Some(parent_domain.clone());
                self.managed_app_id = Some(*managed_app_id);
            }
            DomainEvent::GeneratedReassigned { app_id, .. } => {
                self.managed_app_id = Some(*app_id);
                if self.app_id.is_some() {
                    self.app_id = Some(*app_id);
                }
            }
            DomainEvent::AppDomainAllocationSet { enabled, .. } => {
                self.assignment_disabled = !enabled;
            }
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
    const SNAPSHOT_VERSION: i32 = 2;
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
    /// Enables app addresses without changing an existing apex binding.
    EnableAppDomain { actor: Uuid, at: DateTime<Utc> },
    /// Creates a verified, bound child with durable parent and app ownership.
    Generate {
        actor: Uuid,
        organisation_id: Uuid,
        name: DomainName,
        token: String,
        authority: AppDomainAuthority,
        app_id: Uuid,
        at: DateTime<Utc>,
    },
    /// The service found the token in the name's TXT record. Verifying a
    /// verified name again changes nothing.
    Verify { actor: Uuid, at: DateTime<Utc> },
    /// Binding to the same app is idempotent. Ordinary names may move;
    /// generated names remain owned by their managed app.
    Bind {
        actor: Uuid,
        app_id: Uuid,
        at: DateTime<Utc>,
    },
    /// Transfers only an expected generated assignment. The service must prove
    /// both apps belong to the same locked stack before issuing this command.
    ReassignGenerated {
        actor: Uuid,
        expected_app_id: Uuid,
        app_id: Uuid,
        at: DateTime<Utc>,
    },
    /// Unbinds the name and opts generated names out of automatic allocation.
    Unbind { actor: Uuid, at: DateTime<Utc> },
    /// Suspends a binding without changing the app's allocation preference.
    UnbindForAppDeletion { actor: Uuid, at: DateTime<Utc> },
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
    #[error("the domain cannot authorise app addresses")]
    InvalidAuthority,
    #[error("a generated domain can only be bound to its managed app")]
    ManagedAppMismatch,
    #[error("an app address must be one DNS label below its parent")]
    InvalidGeneratedName,
}

impl mire::Command for DomainCommand {
    type Aggregate = Domain;
    type Error = DomainError;
    type Events = Vec<DomainEvent>;

    fn handle(self, domain: &Domain) -> Result<Vec<DomainEvent>, DomainError> {
        match self {
            DomainCommand::Add {
                actor,
                organisation_id,
                name,
                token,
                at,
            } => {
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
            DomainCommand::Generate {
                actor,
                organisation_id,
                name,
                token,
                authority,
                app_id,
                at,
            } => {
                if domain.exists {
                    return Err(DomainError::AlreadyExists);
                }
                if authority.organisation_id != organisation_id {
                    return Err(DomainError::InvalidAuthority);
                }
                let label = name
                    .as_str()
                    .strip_suffix(authority.parent_domain.as_str())
                    .and_then(|prefix| prefix.strip_suffix('.'));
                if !label.is_some_and(|label| {
                    !label.is_empty()
                        && !label.contains('.')
                        && !matches!(label, "_grund" | "_acme-challenge" | "*")
                }) {
                    return Err(DomainError::InvalidGeneratedName);
                }
                return Ok(vec![
                    DomainEvent::Added {
                        organisation_id,
                        name,
                        token,
                        added_by: actor,
                        added_at: at,
                    },
                    DomainEvent::GeneratedFromParent {
                        parent_domain_id: authority.parent_domain_id,
                        parent_domain: authority.parent_domain,
                        managed_app_id: app_id,
                        parent_verified_at: authority.parent_verified_at,
                        generated_by: actor,
                        generated_at: at,
                    },
                    DomainEvent::Verified {
                        verified_by: actor,
                        verified_at: at,
                    },
                    DomainEvent::Bound {
                        app_id,
                        bound_by: actor,
                        bound_at: at,
                    },
                ]);
            }
            _ => {}
        }
        if !domain.exists || domain.removed {
            return Err(DomainError::NotFound);
        }
        Ok(match self {
            DomainCommand::Add { .. } | DomainCommand::Generate { .. } => {
                unreachable!("handled above")
            }
            DomainCommand::EnableAppDomain { actor, at } => {
                if domain.parent_domain_id.is_some() {
                    return Err(DomainError::InvalidAuthority);
                }
                if domain.verified_at.is_none() {
                    return Err(DomainError::NotVerified);
                }
                if domain.is_app_domain {
                    Vec::new()
                } else {
                    vec![DomainEvent::AppDomainEnabled {
                        enabled_by: actor,
                        enabled_at: at,
                    }]
                }
            }
            DomainCommand::Verify { actor, at } => match domain.verified_at {
                Some(_) => Vec::new(),
                None => vec![DomainEvent::Verified {
                    verified_by: actor,
                    verified_at: at,
                }],
            },
            DomainCommand::ReassignGenerated {
                actor,
                expected_app_id,
                app_id,
                at,
            } => {
                if domain.parent_domain_id.is_none()
                    || domain.managed_app_id != Some(expected_app_id)
                    || domain.app_id.is_some_and(|bound| bound != expected_app_id)
                {
                    return Err(DomainError::ManagedAppMismatch);
                }
                if expected_app_id == app_id {
                    Vec::new()
                } else {
                    vec![DomainEvent::GeneratedReassigned {
                        previous_app_id: expected_app_id,
                        app_id,
                        reassigned_by: actor,
                        reassigned_at: at,
                    }]
                }
            }
            DomainCommand::Bind { actor, app_id, at } => {
                if domain.verified_at.is_none() {
                    return Err(DomainError::NotVerified);
                }
                if domain
                    .managed_app_id
                    .is_some_and(|managed| managed != app_id)
                {
                    return Err(DomainError::ManagedAppMismatch);
                }
                let mut events = Vec::new();
                if domain.assignment_disabled {
                    events.push(DomainEvent::AppDomainAllocationSet {
                        enabled: true,
                        changed_by: actor,
                        changed_at: at,
                    });
                }
                if domain.app_id != Some(app_id) {
                    events.push(DomainEvent::Bound {
                        app_id,
                        bound_by: actor,
                        bound_at: at,
                    });
                }
                events
            }
            DomainCommand::Unbind { actor, at }
            | DomainCommand::UnbindForAppDeletion { actor, at } => {
                let mut events = Vec::new();
                if let Some(app_id) = domain.app_id {
                    events.push(DomainEvent::Unbound {
                        app_id,
                        unbound_by: actor,
                        unbound_at: at,
                    });
                }
                if matches!(self, DomainCommand::Unbind { .. })
                    && domain.parent_domain_id.is_some()
                    && !domain.assignment_disabled
                {
                    events.push(DomainEvent::AppDomainAllocationSet {
                        enabled: false,
                        changed_by: actor,
                        changed_at: at,
                    });
                }
                events
            }
            DomainCommand::Remove { actor, at } => {
                let mut events = Vec::new();
                if let Some(app_id) = domain.app_id {
                    events.push(DomainEvent::Unbound {
                        app_id,
                        unbound_by: actor,
                        unbound_at: at,
                    });
                }
                if domain.parent_domain_id.is_some() && !domain.assignment_disabled {
                    events.push(DomainEvent::AppDomainAllocationSet {
                        enabled: false,
                        changed_by: actor,
                        changed_at: at,
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
    use mire::{Aggregate, AggregateRoot, Command};

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

    fn verified_parent() -> AggregateRoot<Domain> {
        let mut root = AggregateRoot::new("parent");
        root.execute(DomainCommand::Add {
            actor: Uuid::nil(),
            organisation_id: Uuid::from_u128(7),
            name: DomainName::parse("apps.example.com").unwrap(),
            token: "parent-token".into(),
            at: at(),
        })
        .unwrap();
        root.execute(DomainCommand::Verify {
            actor: Uuid::nil(),
            at: at(),
        })
        .unwrap();
        root
    }

    fn generate(parent: &Domain, name: &str, organisation_id: Uuid) -> DomainCommand {
        DomainCommand::Generate {
            actor: Uuid::nil(),
            organisation_id,
            name: DomainName::parse(name).unwrap(),
            token: "child-token".into(),
            authority: parent.app_domain_authority(Uuid::from_u128(10)).unwrap(),
            app_id: Uuid::from_u128(1),
            at: at() + chrono::Duration::seconds(60),
        }
    }

    fn generated() -> AggregateRoot<Domain> {
        let mut parent = verified_parent();
        parent
            .execute(DomainCommand::EnableAppDomain {
                actor: Uuid::nil(),
                at: at(),
            })
            .unwrap();
        let mut root = AggregateRoot::new("child");
        root.execute(generate(
            &parent.state,
            "api.apps.example.com",
            parent.state.organisation_id,
        ))
        .unwrap();
        root
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

    #[test]
    fn enabling_an_app_domain_requires_a_live_verified_parent_and_preserves_its_binding() {
        let enable = || DomainCommand::EnableAppDomain {
            actor: Uuid::nil(),
            at: at(),
        };
        assert_eq!(
            enable().handle(&Domain::default()),
            Err(DomainError::NotFound)
        );
        assert!(matches!(
            Domain::default().app_domain_authority(Uuid::from_u128(10)),
            Err(DomainError::NotFound)
        ));
        let unverified = fold(&added());
        assert_eq!(enable().handle(&unverified), Err(DomainError::NotVerified));
        assert!(matches!(
            unverified.app_domain_authority(Uuid::from_u128(10)),
            Err(DomainError::NotVerified)
        ));

        let mut parent = verified_parent();
        assert!(matches!(
            parent.state.app_domain_authority(Uuid::from_u128(10)),
            Err(DomainError::InvalidAuthority)
        ));
        parent
            .execute(DomainCommand::Bind {
                actor: Uuid::nil(),
                app_id: Uuid::from_u128(2),
                at: at(),
            })
            .unwrap();
        let before = parent.pending_count();
        parent.execute(enable()).unwrap();
        assert_eq!(parent.pending_count(), before + 1);
        assert!(parent.state.is_app_domain);
        assert_eq!(parent.state.app_id, Some(Uuid::from_u128(2)));
        assert!(
            parent
                .state
                .app_domain_authority(Uuid::from_u128(10))
                .is_ok()
        );
        parent.execute(enable()).unwrap();
        assert_eq!(parent.pending_count(), before + 1);
        parent
            .execute(DomainCommand::Remove {
                actor: Uuid::nil(),
                at: at(),
            })
            .unwrap();
        assert!(matches!(
            parent.state.app_domain_authority(Uuid::from_u128(10)),
            Err(DomainError::NotFound)
        ));
        assert_eq!(enable().handle(&parent.state), Err(DomainError::NotFound));
    }

    #[test]
    fn generation_requires_the_parents_organisation_and_exactly_one_child_label() {
        let mut parent = verified_parent();
        parent
            .execute(DomainCommand::EnableAppDomain {
                actor: Uuid::nil(),
                at: at(),
            })
            .unwrap();
        assert_eq!(
            generate(&parent.state, "api.apps.example.com", Uuid::from_u128(8))
                .handle(&Domain::default()),
            Err(DomainError::InvalidAuthority)
        );
        for name in [
            "apps.example.com",
            "api.example.com",
            "api.notapps.example.com",
            "api.deep.apps.example.com",
            "apps.example.com.other.com",
        ] {
            assert_eq!(
                generate(&parent.state, name, parent.state.organisation_id)
                    .handle(&Domain::default()),
                Err(DomainError::InvalidGeneratedName),
                "{name}"
            );
        }
        for name in [
            "api.apps.example.com",
            "www.apps.example.com",
            "admin.apps.example.com",
            "a-1.apps.example.com",
        ] {
            assert!(
                generate(&parent.state, name, parent.state.organisation_id)
                    .handle(&Domain::default())
                    .is_ok()
            );
        }
    }

    #[test]
    fn generated_reassignment_preserves_authority_hostname_and_allocation_preferences() {
        for disabled in [false, true] {
            let mut domain = generated().state;
            domain.assignment_disabled = disabled;
            if disabled {
                domain.app_id = None;
            }
            let before = domain.clone();
            let replacement = Uuid::from_u128(2);
            let events = DomainCommand::ReassignGenerated {
                actor: Uuid::nil(),
                expected_app_id: Uuid::from_u128(1),
                app_id: replacement,
                at: at(),
            }
            .handle(&domain)
            .unwrap();
            for event in events {
                domain.apply(&event);
                assert!(domain.app_id.is_none() || domain.app_id == domain.managed_app_id);
            }
            assert_eq!(domain.managed_app_id, Some(replacement));
            assert_eq!(
                domain.app_id,
                if disabled { None } else { Some(replacement) }
            );
            domain.managed_app_id = before.managed_app_id;
            domain.app_id = before.app_id;
            assert_eq!(domain, before);
        }
    }

    #[test]
    fn a_stale_generated_owner_or_binding_cannot_be_reassigned() {
        let original = generated().state;
        let command = || DomainCommand::ReassignGenerated {
            actor: Uuid::nil(),
            expected_app_id: Uuid::from_u128(9),
            app_id: Uuid::from_u128(2),
            at: at(),
        };
        assert_eq!(
            command().handle(&original),
            Err(DomainError::ManagedAppMismatch)
        );
        let mut stale_binding = original.clone();
        stale_binding.app_id = Some(Uuid::from_u128(9));
        assert_eq!(
            DomainCommand::ReassignGenerated {
                actor: Uuid::nil(),
                expected_app_id: Uuid::from_u128(1),
                app_id: Uuid::from_u128(2),
                at: at(),
            }
            .handle(&stale_binding),
            Err(DomainError::ManagedAppMismatch)
        );
        assert_eq!(original.managed_app_id, Some(Uuid::from_u128(1)));
    }

    #[test]
    fn a_generated_domain_records_parent_authority_and_cannot_move_or_become_a_parent() {
        let root = generated();
        assert_eq!(root.pending_count(), 4);
        assert!(root.state.exists);
        assert!(!root.state.is_app_domain);
        assert!(!root.state.assignment_disabled);
        assert_eq!(root.state.parent_domain_id, Some(Uuid::from_u128(10)));
        assert_eq!(
            root.state.parent_domain.as_ref().unwrap().as_str(),
            "apps.example.com"
        );
        assert_eq!(root.state.managed_app_id, Some(Uuid::from_u128(1)));
        assert_eq!(root.state.app_id, Some(Uuid::from_u128(1)));
        assert_eq!(
            root.state.verified_at,
            Some(at() + chrono::Duration::seconds(60))
        );
        assert_eq!(
            DomainCommand::Bind {
                actor: Uuid::nil(),
                app_id: Uuid::from_u128(2),
                at: at(),
            }
            .handle(&root.state),
            Err(DomainError::ManagedAppMismatch)
        );
        assert_eq!(
            DomainCommand::EnableAppDomain {
                actor: Uuid::nil(),
                at: at(),
            }
            .handle(&root.state),
            Err(DomainError::InvalidAuthority)
        );
        assert!(matches!(
            root.state.app_domain_authority(Uuid::from_u128(11)),
            Err(DomainError::InvalidAuthority)
        ));
        let mut parent = verified_parent();
        parent
            .execute(DomainCommand::EnableAppDomain {
                actor: Uuid::nil(),
                at: at(),
            })
            .unwrap();
        let events = generate(
            &parent.state,
            "api.apps.example.com",
            parent.state.organisation_id,
        )
        .handle(&Domain::default())
        .unwrap();
        assert!(matches!(
            &events[1],
            DomainEvent::GeneratedFromParent {
                parent_domain_id,
                parent_domain,
                managed_app_id,
                parent_verified_at,
                generated_by,
                generated_at,
            } if *parent_domain_id == Uuid::from_u128(10)
                && parent_domain.as_str() == "apps.example.com"
                && *managed_app_id == Uuid::from_u128(1)
                && *parent_verified_at == at()
                && *generated_by == Uuid::nil()
                && *generated_at == at() + chrono::Duration::seconds(60)
        ));
        assert!(matches!(events[0], DomainEvent::Added { .. }));
        assert!(matches!(events[2], DomainEvent::Verified { .. }));
        assert!(matches!(events[3], DomainEvent::Bound { .. }));
        assert_eq!(
            generate(
                &parent.state,
                "api.apps.example.com",
                parent.state.organisation_id,
            )
            .handle(&root.state),
            Err(DomainError::AlreadyExists)
        );
    }

    #[test]
    fn explicit_unbinding_opts_out_even_after_app_deletion_suspended_the_binding() {
        let mut root = generated();
        let provenance = (
            root.state.parent_domain_id,
            root.state.parent_domain.clone(),
            root.state.managed_app_id,
        );
        let suspend = || DomainCommand::UnbindForAppDeletion {
            actor: Uuid::nil(),
            at: at(),
        };
        root.execute(suspend()).unwrap();
        assert_eq!(root.state.app_id, None);
        assert!(!root.state.assignment_disabled);
        let before = root.pending_count();
        root.execute(suspend()).unwrap();
        assert_eq!(root.pending_count(), before);
        let unbind = || DomainCommand::Unbind {
            actor: Uuid::nil(),
            at: at(),
        };
        root.execute(unbind()).unwrap();
        assert!(root.state.assignment_disabled);
        assert_eq!(root.pending_count(), before + 1);
        root.execute(unbind()).unwrap();
        root.execute(suspend()).unwrap();
        assert!(root.state.assignment_disabled);
        assert_eq!(root.pending_count(), before + 1);
        assert_eq!(
            (
                root.state.parent_domain_id,
                root.state.parent_domain.clone(),
                root.state.managed_app_id,
            ),
            provenance
        );
        assert_eq!(
            DomainCommand::Bind {
                actor: Uuid::nil(),
                app_id: Uuid::from_u128(2),
                at: at(),
            }
            .handle(&root.state),
            Err(DomainError::ManagedAppMismatch)
        );
        assert!(root.state.assignment_disabled);
        let bind = || DomainCommand::Bind {
            actor: Uuid::nil(),
            app_id: Uuid::from_u128(1),
            at: at(),
        };
        root.execute(bind()).unwrap();
        assert!(!root.state.assignment_disabled);
        assert_eq!(root.state.app_id, Some(Uuid::from_u128(1)));
        assert_eq!(root.pending_count(), before + 3);
        root.execute(bind()).unwrap();
        assert_eq!(root.pending_count(), before + 3);
        root.execute(unbind()).unwrap();
        assert!(root.state.assignment_disabled);
        assert_eq!(root.state.app_id, None);
    }

    #[test]
    fn removing_a_generated_domain_preserves_its_opt_out_and_provenance() {
        for suspend_first in [false, true] {
            let mut root = generated();
            if suspend_first {
                root.execute(DomainCommand::UnbindForAppDeletion {
                    actor: Uuid::nil(),
                    at: at(),
                })
                .unwrap();
            }
            root.execute(DomainCommand::Remove {
                actor: Uuid::nil(),
                at: at(),
            })
            .unwrap();
            assert!(root.state.removed);
            assert!(root.state.assignment_disabled);
            assert_eq!(root.state.app_id, None);
            assert_eq!(root.state.parent_domain_id, Some(Uuid::from_u128(10)));
            assert_eq!(root.state.managed_app_id, Some(Uuid::from_u128(1)));
            assert_eq!(
                root.state.parent_domain.as_ref().unwrap().as_str(),
                "apps.example.com"
            );
            assert_eq!(
                DomainCommand::Bind {
                    actor: Uuid::nil(),
                    app_id: Uuid::from_u128(1),
                    at: at(),
                }
                .handle(&root.state),
                Err(DomainError::NotFound)
            );
        }
    }

    #[test]
    fn namespace_snapshots_roundtrip_parent_authority_and_removed_assignment_preferences() {
        assert_eq!(<Domain as mire::Snapshot>::SNAPSHOT_VERSION, 2);
        let mut parent = verified_parent();
        parent
            .execute(DomainCommand::EnableAppDomain {
                actor: Uuid::nil(),
                at: at(),
            })
            .unwrap();
        let restored_parent: Domain =
            serde_json::from_str(&serde_json::to_string(&parent.state).unwrap()).unwrap();
        assert_eq!(restored_parent, parent.state);
        assert!(
            restored_parent
                .app_domain_authority(Uuid::from_u128(10))
                .is_ok()
        );
        let mut child = generated();
        child
            .execute(DomainCommand::Remove {
                actor: Uuid::nil(),
                at: at(),
            })
            .unwrap();
        let restored_child: Domain =
            serde_json::from_str(&serde_json::to_string(&child.state).unwrap()).unwrap();
        assert_eq!(restored_child, child.state);
        assert!(restored_child.assignment_disabled);
        assert!(restored_child.removed);
    }

    #[test]
    fn old_domain_json_defaults_to_an_ordinary_domain_without_namespace_authority() {
        let original = fold(&added());
        let value = serde_json::json!({
            "exists": original.exists,
            "organisation_id": original.organisation_id,
            "name": original.name,
            "token": original.token,
            "verified_at": original.verified_at,
            "app_id": original.app_id,
            "removed": original.removed,
        });
        let restored: Domain = serde_json::from_value(value).unwrap();
        assert_eq!(restored, original);
        assert!(!restored.is_app_domain);
        assert_eq!(restored.parent_domain_id, None);
        assert_eq!(restored.parent_domain, None);
        assert_eq!(restored.managed_app_id, None);
        assert!(!restored.assignment_disabled);
        assert_eq!(
            serde_json::from_str::<Domain>(&serde_json::to_string(&restored).unwrap()).unwrap(),
            restored
        );
    }
}
