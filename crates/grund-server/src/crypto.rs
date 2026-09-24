//! The few primitives grund builds its tokens from: random values, SHA-256
//! digests, HMAC and constant-time comparison.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// 32 random bytes as base64url: sessions, email links, CSRF nonces.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The SHA-256 a token is stored as.
pub fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// SHA-256 of a normalised address, hex: how the event log refers to it.
pub fn email_digest(normalized: &str) -> String {
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

/// HMAC-SHA256 over `parts`, each length-prefixed so no two different part
/// lists produce the same input.
pub fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Equality that takes the same time wherever the inputs differ.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Base64url without padding, the form tokens travel in.
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_url_safe() {
        let a = random_token();
        assert_ne!(a, random_token());
        assert_eq!(a.len(), 43);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }

    #[test]
    fn hmac_parts_cannot_be_shifted_into_each_other() {
        let key = [7u8; 32];
        assert_ne!(hmac(&key, &[b"ab", b"c"]), hmac(&key, &[b"a", b"bc"]));
    }

    #[test]
    fn constant_time_eq_compares_length_and_content() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
