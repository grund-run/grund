//! `grund setup-link`: the owner's one-time setup link, which creates the
//! first account of a `single` instance with no mail (grund-docs
//! design/auth.md §5). Run where `grund serve` runs, with the same settings:
//! `docker compose exec grund /grund setup-link`.
//!
//! The link is printed once, to standard output, and never logged. Only
//! `HMAC-SHA256(secret.derive("setup-link"), token)` is stored, so a link
//! works only on the instance whose key and database minted it.

use std::time::Duration;

use anyhow::Context;
use grund_store::setup_links::{self, Minted};

use crate::{
    config::{OrganisationMode, ServeConfig},
    crypto, db, keys,
    secrets::SecretKey,
};

/// How long a setup link works.
pub const TTL: Duration = Duration::from_secs(3600);

/// What every setup link starts with, so secret scanners can find one pasted
/// somewhere it should not be.
pub const PREFIX: &str = "grund_setup_";

/// Where a setup link opens.
pub const PATH: &str = "/signup/owner";

/// The digest a setup link is stored and looked up as.
pub fn digest(secret: &SecretKey, token: &str) -> [u8; 32] {
    crypto::hmac(&secret.derive("setup-link"), &[token.as_bytes()])
}

/// Whether `token` has the shape of a setup link, before any lookup.
pub fn well_formed(token: &str) -> bool {
    token.strip_prefix(PREFIX).is_some_and(|rest| {
        rest.len() == 43
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// A minted link, for the one place that shows it.
pub struct Link {
    pub url: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Mints a link, refusing with the cause when this instance cannot have one.
pub async fn mint(config: &ServeConfig) -> anyhow::Result<Link> {
    anyhow::ensure!(
        config.organisations == OrganisationMode::Single,
        "GRUND_ORGANISATIONS is multi: sign-up is open there, so the first account signs up like \
         any other and no setup link is needed"
    );
    anyhow::ensure!(
        config.secret_key.is_some() || config.secret_key_file.is_some(),
        "no secret key is configured (GRUND_SECRET_KEY or GRUND_SECRET_KEY_FILE): a development \
         mode throwaway key differs in every process, so the instance could never check the link"
    );
    let secret = SecretKey::load(config)?;
    let pool = db::connect(&config.database).await?;
    let mismatched = keys::Keys::new(std::sync::Arc::new(secret.clone()))
        .mismatched(&pool)
        .await
        .context("read the instance's keys; has `grund serve` started on this database?")?;
    anyhow::ensure!(
        mismatched.is_empty(),
        "this secret key is not the one the instance's keys were made with: run the command where \
         `grund serve` runs, with the same GRUND_SECRET_KEY or GRUND_SECRET_KEY_FILE"
    );
    let token = format!("{PREFIX}{}", crypto::random_token());
    let minted = setup_links::mint(&pool, &digest(&secret, &token), TTL).await;
    let expires_at = match minted {
        Ok(Minted::Issued(expires_at)) => expires_at,
        Ok(Minted::AccountsExist) => anyhow::bail!(
            "this instance already has an account, so it has its owner and a setup link would \
             create nothing. Sign in, or reset the password from the sign-in page"
        ),
        Err(error) if undefined_table(&error) => anyhow::bail!(
            "the database has no setup links yet: start `grund serve` of this build once, which \
             applies its migrations, then run this again"
        ),
        Err(error) => return Err(error).context("store the setup link"),
    };
    let url = format!("{}{PATH}?token={token}", config.public_origin().serialized);
    Ok(Link { url, expires_at })
}

fn undefined_table(error: &sqlx::Error) -> bool {
    error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42P01")
}

/// `grund setup-link`.
pub async fn run(mut config: ServeConfig) -> anyhow::Result<()> {
    config.validate()?;
    let link = mint(&config).await?;
    let minutes = TTL.as_secs() / 60;
    println!(
        "Open this link within {minutes} minutes to create the owner of {}.\n\
         It works once, and only while the instance has no account. Anyone with it can\n\
         become the owner, so do not paste it anywhere else.\n\n  {}\n\n\
         It expires at {}.",
        config.public_origin().serialized,
        link.url,
        link.expires_at
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_setup_link_is_the_prefix_and_a_random_token() {
        assert!(well_formed(&format!("{PREFIX}{}", crypto::random_token())));
        assert!(!well_formed(&crypto::random_token()));
        assert!(!well_formed(&format!("{PREFIX}short")));
        assert!(!well_formed(&format!(
            "{PREFIX}{}!",
            &crypto::random_token()[1..]
        )));
    }

    #[test]
    fn a_link_verifies_only_under_the_key_that_minted_it() {
        let token = format!("{PREFIX}{}", crypto::random_token());
        let one = SecretKey::generate();
        let other = SecretKey::generate();
        assert_eq!(digest(&one, &token), digest(&one, &token));
        assert_ne!(digest(&one, &token), digest(&other, &token));
        assert_ne!(digest(&one, &token), crypto::digest(&token));
    }
}
