//! Password hashing (docs/design/auth.md §2): Argon2id, m = 19 MiB, t = 2,
//! p = 1, at most four hashes at once per process, and a dummy hash so an
//! unknown account costs what a wrong password costs.

use std::sync::Arc;

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::{SaltString, rand_core::OsRng},
};
use tokio::sync::Semaphore;

use crate::state::State;

/// Memory cost in KiB (19 MiB).
pub const MEMORY_KIB: u32 = 19_456;
/// Iterations.
pub const ITERATIONS: u32 = 2;
/// Lanes.
pub const PARALLELISM: u32 = 1;
/// Hashes allowed at once; the rest wait for a slot.
pub const CONCURRENT_HASHES: usize = 4;

/// The outcome of checking a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub matches: bool,
    /// The stored hash uses other parameters and should be replaced.
    pub needs_rehash: bool,
}

/// Hashes and verifies passwords on the blocking pool, four at a time.
#[derive(Clone)]
pub struct Passwords {
    permits: Arc<Semaphore>,
    dummy: Arc<String>,
}

fn argon() -> Argon2<'static> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(32))
        .expect("valid Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash_blocking(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(argon()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("hash password: {error}"))?
        .to_string())
}

fn verify_blocking(password: &str, phc: &str) -> Verified {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return Verified {
            matches: false,
            needs_rehash: false,
        };
    };
    let matches = argon()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok();
    let current = parsed.algorithm.as_str() == "argon2id"
        && Params::try_from(&parsed).is_ok_and(|p| {
            p.m_cost() == MEMORY_KIB && p.t_cost() == ITERATIONS && p.p_cost() == PARALLELISM
        });
    Verified {
        matches,
        needs_rehash: matches && !current,
    }
}

impl Passwords {
    /// Builds the service, hashing the dummy password once. Call at startup.
    pub fn new() -> anyhow::Result<Self> {
        let mut dummy_password = [0u8; 24];
        getrandom::fill(&mut dummy_password).expect("randomness");
        Ok(Self {
            permits: Arc::new(Semaphore::new(CONCURRENT_HASHES)),
            dummy: Arc::new(hash_blocking(&hex::encode(dummy_password))?),
        })
    }

    /// Hashes a new password.
    pub async fn hash(&self, password: &str) -> anyhow::Result<String> {
        let _permit = self.permits.acquire().await?;
        let password = password.to_string();
        tokio::task::spawn_blocking(move || hash_blocking(&password)).await?
    }

    /// Verifies `password` against `phc`, or against the dummy hash when there
    /// is none, so both cost the same. Without a stored hash it never matches.
    pub async fn verify(&self, password: &str, phc: Option<&str>) -> anyhow::Result<Verified> {
        let _permit = self.permits.acquire().await?;
        let password = password.to_string();
        let (phc, real) = match phc {
            Some(phc) => (phc.to_string(), true),
            None => (self.dummy.as_str().to_string(), false),
        };
        let verified =
            tokio::task::spawn_blocking(move || verify_blocking(&password, &phc)).await?;
        Ok(Verified {
            matches: verified.matches && real,
            needs_rehash: verified.needs_rehash && real,
        })
    }
}

/// Access to [`Passwords`] from [`State`].
pub trait PasswordsState {
    fn passwords(&self) -> Passwords;
}

impl PasswordsState for State {
    fn passwords(&self) -> Passwords {
        self.passwords.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_hash_verifies_its_password_and_nothing_else() {
        let passwords = Passwords::new().unwrap();
        let phc = passwords.hash("correct horse battery").await.unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(
            passwords
                .verify("correct horse battery", Some(&phc))
                .await
                .unwrap()
                .matches
        );
        assert!(
            !passwords
                .verify("wrong horse battery", Some(&phc))
                .await
                .unwrap()
                .matches
        );
    }

    #[tokio::test]
    async fn no_stored_hash_never_matches_even_the_dummy_password() {
        let passwords = Passwords::new().unwrap();
        let verified = passwords.verify("anything at all", None).await.unwrap();
        assert!(!verified.matches && !verified.needs_rehash);
    }

    #[tokio::test]
    async fn a_hash_with_old_parameters_matches_and_asks_to_be_replaced() {
        let passwords = Passwords::new().unwrap();
        let old = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(8192, 1, 1, Some(32)).unwrap(),
        )
        .hash_password(b"correct horse battery", &SaltString::generate(&mut OsRng))
        .unwrap()
        .to_string();
        let verified = passwords
            .verify("correct horse battery", Some(&old))
            .await
            .unwrap();
        assert!(verified.matches && verified.needs_rehash);
    }

    #[tokio::test]
    async fn a_malformed_stored_hash_fails_closed() {
        let passwords = Passwords::new().unwrap();
        assert!(
            !passwords
                .verify("x", Some("not a hash"))
                .await
                .unwrap()
                .matches
        );
    }
}
