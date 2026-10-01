//! Password hashing: Argon2id, m = 19 MiB, t = 2, p = 1.
//!
//! Blocking and CPU-bound; callers run it off the async runtime. This crate
//! is where the Argon2 code is instantiated, so `[profile.release.package]`
//! can compile it, with argon2 and the crates it inlines, at opt-level 3
//! while the rest of the release build optimises for size.

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::{SaltString, rand_core::OsRng},
};

/// Memory cost in KiB (19 MiB).
pub const MEMORY_KIB: u32 = 19_456;
/// Iterations.
pub const ITERATIONS: u32 = 2;
/// Lanes.
pub const PARALLELISM: u32 = 1;

/// The outcome of checking a password against a stored hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub matches: bool,
    /// The stored hash uses other parameters and should be replaced.
    pub needs_rehash: bool,
}

fn argon() -> Argon2<'static> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(32))
        .expect("valid Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hashes `password` with a fresh salt, as a PHC string.
pub fn hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(argon()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("hash password: {error}"))?
        .to_string())
}

/// Checks `password` against the PHC string `phc`. A malformed `phc` never
/// matches.
pub fn verify(password: &str, phc: &str) -> Verified {
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
