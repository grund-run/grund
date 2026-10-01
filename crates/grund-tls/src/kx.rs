//! The hybrid post-quantum key exchange every grund TLS endpoint prefers:
//! X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem, codepoint 0x11EC), built from
//! ring's X25519 and RustCrypto's pure-Rust ML-KEM-768 (FIPS 203), so grund
//! needs no C crypto library beyond ring.
//!
//! The wire layout is the draft's:
//!
//! - the client's share is the ML-KEM-768 encapsulation key (1184 bytes)
//!   followed by its X25519 public key (32);
//! - the server's share is the ML-KEM-768 ciphertext (1088) followed by its
//!   X25519 public key (32);
//! - the shared secret is the ML-KEM secret (32) followed by the X25519
//!   secret (32).
//!
//! The group is TLS 1.3 only. A client offering it also sends a plain
//! X25519 share from the same X25519 key, so a server without the group
//! picks X25519 without a HelloRetryRequest.

use ml_kem::kem::{Decapsulate, Encapsulate, Generate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

/// X25519MLKEM768, ML-KEM-768 and X25519 combined as the draft specifies.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &X25519MlKem768;

/// The length of a client's X25519MLKEM768 share.
pub const CLIENT_SHARE_LEN: usize = ENCAPSULATION_KEY_LEN + X25519_LEN;

/// The length of a server's X25519MLKEM768 share.
pub const SERVER_SHARE_LEN: usize = CIPHERTEXT_LEN + X25519_LEN;

const ENCAPSULATION_KEY_LEN: usize = 1184;
const CIPHERTEXT_LEN: usize = 1088;
const X25519_LEN: usize = 32;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

fn classical() -> &'static dyn SupportedKxGroup {
    rustls::crypto::ring::kx_group::X25519
}

#[derive(Debug)]
struct X25519MlKem768;

impl SupportedKxGroup for X25519MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = classical().start()?;
        let decapsulation = DecapsulationKey::try_generate_from_rng(&mut ml_kem_rng())
            .map_err(|_| Error::FailedToGetRandomBytes)?;
        let share = [
            decapsulation.encapsulation_key().to_bytes().as_slice(),
            classical.pub_key(),
        ]
        .concat();
        Ok(Box::new(Active {
            classical,
            decapsulation,
            share,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != CLIENT_SHARE_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (post_quantum, x25519) = client_share.split_at(ENCAPSULATION_KEY_LEN);
        let encapsulation =
            EncapsulationKey::new(&post_quantum.try_into().map_err(|_| INVALID_KEY_SHARE)?)
                .map_err(|_| INVALID_KEY_SHARE)?;
        let classical = classical().start_and_complete(x25519)?;
        let (ciphertext, post_quantum_secret) = encapsulation.encapsulate();
        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key: [ciphertext.as_slice(), &classical.pub_key].concat(),
            secret: SharedSecret::from(
                [
                    post_quantum_secret.as_slice(),
                    classical.secret.secret_bytes(),
                ]
                .concat(),
            ),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

fn ml_kem_rng() -> ml_kem::kem::common::getrandom::SysRng {
    ml_kem::kem::common::getrandom::SysRng
}

struct Active {
    classical: Box<dyn ActiveKeyExchange>,
    decapsulation: DecapsulationKey,
    share: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        if server_share.len() != SERVER_SHARE_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (ciphertext, x25519) = server_share.split_at(CIPHERTEXT_LEN);
        let ciphertext = Ciphertext::try_from(ciphertext).map_err(|_| INVALID_KEY_SHARE)?;
        let post_quantum_secret = self.decapsulation.decapsulate(&ciphertext);
        let classical_secret = self.classical.complete(x25519)?;
        Ok(SharedSecret::from(
            [
                post_quantum_secret.as_slice(),
                classical_secret.secret_bytes(),
            ]
            .concat(),
        ))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        server_share: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(server_share)
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

#[cfg(test)]
mod tests {
    use ml_kem::kem::common::getrandom::SysRng;
    use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
    use ring::rand::SystemRandom;

    use super::*;

    fn x25519_pair() -> (EphemeralPrivateKey, Vec<u8>) {
        let private =
            EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new()).unwrap();
        let public = private.compute_public_key().unwrap().as_ref().to_vec();
        (private, public)
    }

    fn x25519_secret(private: EphemeralPrivateKey, peer: &[u8]) -> Vec<u8> {
        agreement::agree_ephemeral(
            private,
            &UnparsedPublicKey::new(&agreement::X25519, peer),
            |secret| secret.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn the_server_answers_with_the_ciphertext_then_x25519_and_derives_ml_kem_then_x25519() {
        let decapsulation = DecapsulationKey::try_generate_from_rng(&mut SysRng).unwrap();
        let (x25519, x25519_public) = x25519_pair();
        let client_share = [
            decapsulation.encapsulation_key().to_bytes().as_slice(),
            &x25519_public,
        ]
        .concat();

        let completed = X25519MLKEM768.start_and_complete(&client_share).unwrap();

        assert_eq!(completed.group, NamedGroup::X25519MLKEM768);
        assert_eq!(completed.pub_key.len(), SERVER_SHARE_LEN);
        let (ciphertext, server_x25519) = completed.pub_key.split_at(CIPHERTEXT_LEN);
        let expected = [
            decapsulation
                .decapsulate(&Ciphertext::try_from(ciphertext).unwrap())
                .as_slice(),
            &x25519_secret(x25519, server_x25519),
        ]
        .concat();
        assert_eq!(completed.secret.secret_bytes(), expected.as_slice());
    }

    #[test]
    fn the_client_offers_the_encapsulation_key_then_x25519_and_derives_ml_kem_then_x25519() {
        let active = X25519MLKEM768.start().unwrap();
        let client_share = active.pub_key().to_vec();
        assert_eq!(client_share.len(), CLIENT_SHARE_LEN);
        let (encapsulation, client_x25519) = client_share.split_at(ENCAPSULATION_KEY_LEN);
        assert_eq!(
            active.hybrid_component(),
            Some((NamedGroup::X25519, client_x25519))
        );

        let encapsulation = EncapsulationKey::new(&encapsulation.try_into().unwrap()).unwrap();
        let (ciphertext, post_quantum_secret) = encapsulation.encapsulate();
        let (x25519, x25519_public) = x25519_pair();
        let server_share = [ciphertext.as_slice(), &x25519_public].concat();

        let secret = active.complete(&server_share).unwrap();

        let expected = [
            post_quantum_secret.as_slice(),
            &x25519_secret(x25519, client_x25519),
        ]
        .concat();
        assert_eq!(secret.secret_bytes(), expected.as_slice());
    }

    #[test]
    fn a_client_and_a_server_derive_the_same_64_byte_secret() {
        let client = X25519MLKEM768.start().unwrap();
        let server = X25519MLKEM768.start_and_complete(client.pub_key()).unwrap();
        let secret = client.complete(&server.pub_key).unwrap();
        assert_eq!(secret.secret_bytes().len(), 64);
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }

    #[test]
    fn a_client_share_of_the_wrong_length_is_refused() {
        let client = X25519MLKEM768.start().unwrap();
        for share in [
            &client.pub_key()[..CLIENT_SHARE_LEN - 1],
            &[client.pub_key(), &[0]].concat(),
            &client.pub_key()[ENCAPSULATION_KEY_LEN..],
        ] {
            assert_eq!(
                X25519MLKEM768.start_and_complete(share).err(),
                Some(INVALID_KEY_SHARE)
            );
        }
    }

    #[test]
    fn an_encapsulation_key_failing_the_fips_203_modulus_check_is_refused() {
        let (_, x25519_public) = x25519_pair();
        let share = [&[0xff; ENCAPSULATION_KEY_LEN][..], &x25519_public].concat();
        assert_eq!(
            X25519MLKEM768.start_and_complete(&share).err(),
            Some(INVALID_KEY_SHARE)
        );
    }

    #[test]
    fn a_server_share_of_the_wrong_length_is_refused() {
        let client = X25519MLKEM768.start().unwrap();
        let server = X25519MLKEM768.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(
            client.complete(&server.pub_key[1..]).err(),
            Some(INVALID_KEY_SHARE)
        );
    }

    #[test]
    fn the_group_is_offered_for_tls_1_3_only() {
        assert!(X25519MLKEM768.usable_for_version(ProtocolVersion::TLSv1_3));
        assert!(!X25519MLKEM768.usable_for_version(ProtocolVersion::TLSv1_2));
    }
}
