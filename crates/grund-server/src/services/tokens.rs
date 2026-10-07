//! Personal access tokens (grund-docs design/auth.md §6): how CI calls the
//! Connect API without a dashboard session.
//!
//! A token is `grund_pat_` plus 32 random bytes in base62, shown once when it
//! is made; PostgreSQL keeps only its SHA-256. It is scoped to one
//! organisation and acts as the account that made it, with that account's
//! role there at the time of each call, so it can never do more than its
//! maker could. Which procedures a token may call at all is the
//! authorization table's (`api::AUTHORIZATION`), by the token's scope:
//! `deploy` (the default) or `full` (Kasper may overrule `full`; auth.md
//! §6).

use chrono::{DateTime, Utc};
use grund_domain::organisation::Role;
use grund_store::{
    api_tokens::{self, NewToken, TokenView},
    organisations::Membership,
};
use uuid::Uuid;

use crate::{crypto, state::State};

/// What every token starts with, so secret scanners can find a leaked one.
pub const PREFIX: &str = "grund_pat_";

/// The lifetimes a token may be given, in days; the first is the default.
pub const LIFETIMES_DAYS: &[u32] = &[30, 7, 90, 365];

/// Live tokens one organisation may hold at once.
pub const MAX_LIVE_PER_ORGANISATION: i64 = 100;

/// The longest name a token may have, in characters.
pub const MAX_NAME_CHARS: usize = 64;

/// What a token may call (design/auth.md §6; `api::AUTHORIZATION`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenScope {
    /// The app procedures CI needs, without DeleteApp. The default.
    Deploy,
    /// Every organisation procedure its maker's role allows, in its own
    /// organisation.
    Full,
}

impl TokenScope {
    /// The stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            TokenScope::Deploy => "deploy",
            TokenScope::Full => "full",
        }
    }

    /// A stored name; anything else reads as the narrower `deploy`.
    pub fn parse(text: &str) -> Self {
        match text {
            "full" => TokenScope::Full,
            _ => TokenScope::Deploy,
        }
    }
}

/// Who a token-authenticated API call is from: the account that made the
/// token, limited to the token's organisation and scope.
#[derive(Debug, Clone, Copy)]
pub struct TokenCaller {
    pub account_id: Uuid,
    pub token_id: Uuid,
    pub organisation_id: Uuid,
    pub scope: TokenScope,
}

/// A token just made: its secret, shown once and never again.
#[derive(Debug)]
pub struct Minted {
    pub token: String,
    pub token_id: Uuid,
    pub name: String,
    pub scope: TokenScope,
    pub expires_at: DateTime<Utc>,
}

/// Why a token was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateRefusal {
    Invalid(String),
    TooMany,
}

/// Whether `text` has a token's shape, before anything is looked up.
pub fn well_formed(text: &str) -> bool {
    text.strip_prefix(PREFIX).is_some_and(|rest| {
        rest.len() == crypto::BASE62_32_BYTES && rest.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// The name a person gave, trimmed, or why it cannot be one.
pub fn valid_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Give the token a name, such as the CI job that uses it.".into());
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(format!("A name is at most {MAX_NAME_CHARS} characters."));
    }
    if name.chars().any(char::is_control) {
        return Err("A name cannot hold control characters.".into());
    }
    Ok(name.to_string())
}

fn manages(membership: &Membership) -> bool {
    Role::parse(&membership.role).is_some_and(Role::manages_members)
}

/// Makes, finds, lists and revokes tokens.
#[derive(Clone)]
pub struct Tokens {
    pool: sqlx::PgPool,
}

impl Tokens {
    /// Makes a token for `account_id` in the organisation, valid for
    /// `lifetime_days` (one of [`LIFETIMES_DAYS`]).
    pub async fn create(
        &self,
        account_id: Uuid,
        membership: &Membership,
        name: &str,
        lifetime_days: u32,
        scope: TokenScope,
    ) -> anyhow::Result<Result<Minted, CreateRefusal>> {
        let name = match valid_name(name) {
            Ok(name) => name,
            Err(problem) => return Ok(Err(CreateRefusal::Invalid(problem))),
        };
        if !LIFETIMES_DAYS.contains(&lifetime_days) {
            return Ok(Err(CreateRefusal::Invalid(
                "Choose one of the lifetimes offered.".into(),
            )));
        }
        let token = format!("{PREFIX}{}", crypto::random_base62());
        let token_id = Uuid::now_v7();
        let mut tx = self.pool.begin().await?;
        let expires_at = api_tokens::insert(
            &mut tx,
            NewToken {
                organisation_id: membership.organisation_id,
                token_id,
                token_digest: &crypto::digest(&token),
                account_id,
                name: &name,
                lifetime_days,
                scope: scope.as_str(),
            },
            MAX_LIVE_PER_ORGANISATION,
        )
        .await?;
        let Some(expires_at) = expires_at else {
            return Ok(Err(CreateRefusal::TooMany));
        };
        tx.commit().await?;
        tracing::info!(
            organisation = %membership.organisation_id,
            token = %token_id,
            account = %account_id,
            lifetime_days,
            scope = scope.as_str(),
            "API token created"
        );
        Ok(Ok(Minted {
            token,
            token_id,
            name,
            scope,
            expires_at,
        }))
    }

    /// The caller a token names, if it is live. A malformed token is
    /// refused without a query.
    pub async fn authenticate(&self, token: &str) -> Result<Option<TokenCaller>, sqlx::Error> {
        if !well_formed(token) {
            return Ok(None);
        }
        Ok(api_tokens::authenticate(&self.pool, &crypto::digest(token))
            .await?
            .map(|live| TokenCaller {
                account_id: live.account_id,
                token_id: live.token_id,
                organisation_id: live.organisation_id,
                scope: TokenScope::parse(&live.scope),
            }))
    }

    /// The tokens the viewer sees: every live token of the organisation for
    /// owners and admins, their own for members.
    pub async fn list(
        &self,
        account_id: Uuid,
        membership: &Membership,
    ) -> anyhow::Result<Vec<TokenView>> {
        let only = (!manages(membership)).then_some(account_id);
        Ok(api_tokens::list(&self.pool, membership.organisation_id, only).await?)
    }

    /// One live token of the organisation, by id.
    pub async fn get(
        &self,
        organisation_id: Uuid,
        token_id: Uuid,
    ) -> anyhow::Result<Option<TokenView>> {
        Ok(api_tokens::get(&self.pool, organisation_id, token_id).await?)
    }

    /// Revokes a token: any of the organisation's for owners and admins,
    /// only their own for members. `false` when the viewer has no such
    /// token to revoke, including another organisation's.
    pub async fn revoke(
        &self,
        account_id: Uuid,
        membership: &Membership,
        token_id: Uuid,
    ) -> anyhow::Result<bool> {
        let only = (!manages(membership)).then_some(account_id);
        let revoked =
            api_tokens::revoke(&self.pool, membership.organisation_id, token_id, only).await?;
        if revoked {
            tracing::info!(
                organisation = %membership.organisation_id,
                token = %token_id,
                account = %account_id,
                "API token revoked"
            );
        }
        Ok(revoked)
    }
}

/// Access to [`Tokens`] from [`State`].
pub trait TokensState {
    fn tokens(&self) -> Tokens;
}

impl TokensState for State {
    fn tokens(&self) -> Tokens {
        Tokens {
            pool: self.pool.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_prefix_and_43_base62_characters_are_a_token() {
        let token = format!("{PREFIX}{}", crypto::random_base62());
        assert!(well_formed(&token));
        for bad in [
            "",
            "grund_pat_",
            &token[..token.len() - 1],
            &format!("{token}0"),
            &token.replace(PREFIX, "grund_pa_"),
            &format!("{PREFIX}{}-", "a".repeat(42)),
            &format!("{PREFIX}{}", "é".repeat(43)),
        ] {
            assert!(!well_formed(bad), "{bad}");
        }
    }

    #[test]
    fn a_name_is_trimmed_and_bounded() {
        assert_eq!(valid_name("  ci deploy ").unwrap(), "ci deploy");
        assert!(valid_name("   ").is_err());
        assert!(valid_name(&"x".repeat(65)).is_err());
        assert!(valid_name(&"x".repeat(64)).is_ok());
        assert!(valid_name("a\nb").is_err());
    }
}
