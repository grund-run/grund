//! The machine key as the iroh key (network.md §4).
//!
//! `grund join` keeps the machine key as a 32-byte Ed25519 seed
//! (`grund_agent::join::machine_key`). iroh's secret key is the same kind of
//! key, so the seed is used as it is: the endpoint id peers and the relay see
//! is the machine's public key, the one grund registered at enrolment.

use iroh::{EndpointId, SecretKey};

/// The iroh secret key for a machine key seed.
pub fn secret_key(seed: &[u8; 32]) -> SecretKey {
    SecretKey::from_bytes(seed)
}

/// The endpoint id (the public key) of a machine key seed.
pub fn endpoint_id(seed: &[u8; 32]) -> EndpointId {
    secret_key(seed).public()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn the_endpoint_id_is_the_machine_keys_ed25519_public_key() {
        let seed = [7u8; 32];
        let dalek = SigningKey::from_bytes(&seed).verifying_key();
        assert_eq!(endpoint_id(&seed).as_bytes(), dalek.as_bytes());
    }
}
