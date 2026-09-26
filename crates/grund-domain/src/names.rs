//! The grammar of the names people type: usernames (and the organisation
//! slugs made from them), email addresses and passwords.
//!
//! Every constructor normalises and refuses; a value of one of these types is
//! valid by construction.

use serde::{Deserialize, Serialize};

const RESERVED: &[&str] = &[
    "admin",
    "administrator",
    "api",
    "app",
    "apps",
    "auth",
    "billing",
    "dashboard",
    "dev",
    "docs",
    "grund",
    "health",
    "help",
    "info",
    "invitations",
    "invite",
    "licenses",
    "login",
    "logout",
    "mail",
    "me",
    "new",
    "org",
    "orgs",
    "reset",
    "root",
    "security",
    "sessions",
    "settings",
    "signin",
    "signup",
    "staff",
    "static",
    "status",
    "style-guide",
    "support",
    "system",
    "team",
    "verify",
    "www",
];

/// A username, also the slug of the person's own organisation: 3–32 of
/// `a-z 0-9`, single hyphens between them, stored lowercase.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Username(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("use 3 to 32 characters")]
    Length,
    #[error("use only letters a–z, digits and single hyphens between them")]
    Characters,
    #[error("that name is reserved")]
    Reserved,
}

impl Username {
    pub fn parse(input: &str) -> Result<Self, NameError> {
        let name = input.trim().to_ascii_lowercase();
        if !(3..=32).contains(&name.len()) {
            return Err(NameError::Length);
        }
        let grammar = name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !name.starts_with('-')
            && !name.ends_with('-')
            && !name.contains("--");
        if !grammar {
            return Err(NameError::Characters);
        }
        if RESERVED.contains(&name.as_str()) {
            return Err(NameError::Reserved);
        }
        Ok(Self(name))
    }

    /// Makes a username out of something a provider suggested (a GitHub
    /// login, the part of an address before the `@`), or `None` when nothing
    /// usable is left. Only a suggestion: the person confirms or changes it.
    pub fn suggest(input: &str) -> Option<Self> {
        let mut name = String::new();
        for c in input.trim().chars() {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                name.push(c);
            } else if !name.is_empty() && !name.ends_with('-') {
                name.push('-');
            }
        }
        let name = name.trim_end_matches('-');
        let name: String = name.chars().take(32).collect();
        Self::parse(name.trim_end_matches('-')).ok()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A machine's name: a DNS label, because a machine is reached as
/// `<name>.machines.grund.internal` on its private network (grund/fleet
/// docs/design/network.md §6.2). 1 to 63 of a–z, 0–9 and inner hyphens.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MachineName(String);

impl MachineName {
    pub fn parse(input: &str) -> Result<Self, NameError> {
        let name = input.trim().to_ascii_lowercase();
        if !(1..=63).contains(&name.len()) {
            return Err(NameError::Length);
        }
        let grammar = name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !name.starts_with('-')
            && !name.ends_with('-');
        if !grammar {
            return Err(NameError::Characters);
        }
        Ok(Self(name))
    }

    /// A name made from what a machine reported (its hostname), or `None`
    /// when nothing usable is left. Only the first DNS label counts.
    pub fn suggest(input: &str) -> Option<Self> {
        let label = input.trim().split('.').next().unwrap_or_default();
        let mut name = String::new();
        for c in label.chars() {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                name.push(c);
            } else if !name.is_empty() && !name.ends_with('-') {
                name.push('-');
            }
        }
        let name: String = name.trim_end_matches('-').chars().take(63).collect();
        Self::parse(name.trim_end_matches('-')).ok()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MachineName {
    type Error = NameError;

    fn try_from(value: String) -> Result<Self, NameError> {
        Self::parse(&value)
    }
}

impl From<MachineName> for String {
    fn from(name: MachineName) -> String {
        name.0
    }
}

impl std::fmt::Display for MachineName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An email address as typed (trimmed), and the lowercase form it is
/// compared by. No plus-address or dot folding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailAddress {
    address: String,
    normalized: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("enter an email address like name@example.com")]
pub struct EmailError;

impl EmailAddress {
    pub fn parse(input: &str) -> Result<Self, EmailError> {
        let address = input.trim();
        if address.len() > 254 || address.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(EmailError);
        }
        let (local, domain) = address.split_once('@').ok_or(EmailError)?;
        let domain_ok = domain.len() >= 3
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && !domain.contains("..")
            && !domain.contains('@');
        if local.is_empty()
            || local.len() > 64
            || !domain_ok
            || address.contains(['<', '>', ',', ';', '"'])
        {
            return Err(EmailError);
        }
        Ok(Self {
            address: address.to_string(),
            normalized: address.to_lowercase(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.address
    }

    /// The form uniqueness and lookups use.
    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    /// What the local part suggests as a username.
    pub fn local_part(&self) -> &str {
        self.address.split_once('@').map_or("", |(local, _)| local)
    }
}

/// Password policy. The hash itself is the server's business.
pub const PASSWORD_MIN_CHARS: usize = 12;
pub const PASSWORD_MAX_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PasswordError {
    #[error("use at least 12 characters")]
    TooShort,
    #[error("use at most 1024 bytes")]
    TooLong,
    #[error("don't use your username or email address as your password")]
    SameAsName,
}

/// Checks a new password against the policy: length
/// only, no composition rules, and not the username or address itself.
pub fn check_new_password(
    password: &str,
    username: Option<&Username>,
    email: Option<&EmailAddress>,
) -> Result<(), PasswordError> {
    if password.len() > PASSWORD_MAX_BYTES {
        return Err(PasswordError::TooLong);
    }
    if password.chars().count() < PASSWORD_MIN_CHARS {
        return Err(PasswordError::TooShort);
    }
    let lower = password.to_lowercase();
    if username.is_some_and(|u| lower == u.as_str())
        || email.is_some_and(|e| lower == e.normalized())
    {
        return Err(PasswordError::SameAsName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_username_is_lowercased_and_trimmed() {
        assert_eq!(Username::parse("  Kasper-J ").unwrap().as_str(), "kasper-j");
    }

    #[test]
    fn a_username_refuses_edges_doubles_and_symbols() {
        for bad in ["-ab", "ab-", "a--b", "ab_c", "ab.c", "äbc", "ab c"] {
            assert_eq!(Username::parse(bad), Err(NameError::Characters), "{bad}");
        }
        assert_eq!(Username::parse("ab"), Err(NameError::Length));
        assert_eq!(Username::parse(&"a".repeat(33)), Err(NameError::Length));
    }

    #[test]
    fn names_that_read_as_grund_are_reserved() {
        assert_eq!(Username::parse("Admin"), Err(NameError::Reserved));
        assert_eq!(Username::parse("grund"), Err(NameError::Reserved));
    }

    #[test]
    fn a_provider_login_becomes_a_usable_suggestion() {
        assert_eq!(
            Username::suggest("Kasper_Juul.H").unwrap().as_str(),
            "kasper-juul-h"
        );
        assert_eq!(Username::suggest("--x--y--").unwrap().as_str(), "x-y");
        assert_eq!(Username::suggest("__x__").map(|u| u.0), None);
        assert_eq!(Username::suggest("ab").map(|u| u.0), None);
        assert!(
            Username::suggest(&"long-".repeat(20))
                .unwrap()
                .as_str()
                .len()
                <= 32
        );
    }

    #[test]
    fn an_email_keeps_its_spelling_but_compares_lowercase() {
        let email = EmailAddress::parse(" Kasper+grund@Example.COM ").unwrap();
        assert_eq!(email.as_str(), "Kasper+grund@Example.COM");
        assert_eq!(email.normalized(), "kasper+grund@example.com");
    }

    #[test]
    fn an_email_without_a_real_domain_or_with_header_characters_is_refused() {
        for bad in [
            "kasper",
            "@example.com",
            "a@b",
            "a@.com",
            "a@example..com",
            "a b@example.com",
            "a@example.com\r\nBcc: x@y.z",
            "\"a\"@example.com",
            "a@b@c.com",
        ] {
            assert!(EmailAddress::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_password_is_checked_by_length_only_and_not_the_name() {
        let user = Username::parse("kasper-j").unwrap();
        assert_eq!(
            check_new_password("short", None, None),
            Err(PasswordError::TooShort)
        );
        assert_eq!(
            check_new_password(&"x".repeat(1025), None, None),
            Err(PasswordError::TooLong)
        );
        assert!(check_new_password("correct horse battery", None, None).is_ok());
        let email = EmailAddress::parse("kasper@example.com").unwrap();
        assert_eq!(
            check_new_password("KASPER@example.com", Some(&user), Some(&email)),
            Err(PasswordError::SameAsName)
        );
        assert!(check_new_password("ææææææææææææ", None, None).is_ok());
    }

    #[test]
    fn a_machine_name_is_a_dns_label() {
        assert_eq!(MachineName::parse(" Web-1 ").unwrap().as_str(), "web-1");
        assert_eq!(MachineName::parse("a").unwrap().as_str(), "a");
        assert!(MachineName::parse("-web").is_err());
        assert!(MachineName::parse("web_1").is_err());
        assert!(MachineName::parse(&"a".repeat(64)).is_err());
        assert!(MachineName::parse("").is_err());
    }

    #[test]
    fn a_machine_name_is_suggested_from_a_hostname() {
        assert_eq!(
            MachineName::suggest("Kasper's NUC.local").unwrap().as_str(),
            "kasper-s-nuc"
        );
        assert_eq!(MachineName::suggest("___").map(|n| n.0), None);
    }
}
