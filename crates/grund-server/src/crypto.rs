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

/// How many base62 characters 32 bytes take: 62^43 > 2^256 > 62^42.
pub const BASE62_32_BYTES: usize = 43;

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// 32 bytes as a fixed-width base62 number, most significant digit first:
/// always [`BASE62_32_BYTES`] characters, so a token's length says nothing
/// about its value.
pub fn base62(bytes: &[u8; 32]) -> String {
    let mut number = *bytes;
    let mut digits = [0u8; BASE62_32_BYTES];
    for digit in digits.iter_mut().rev() {
        let mut remainder = 0u32;
        for byte in number.iter_mut() {
            let value = (remainder << 8) | u32::from(*byte);
            *byte = (value / 62) as u8;
            remainder = value % 62;
        }
        *digit = BASE62[remainder as usize];
    }
    String::from_utf8(digits.to_vec()).expect("base62 digits are ASCII")
}

/// 32 random bytes in base62: API tokens, whose characters survive any
/// shell, URL or YAML without quoting.
pub fn random_base62() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    base62(&bytes)
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

    #[test]
    fn base62_is_fixed_width_and_keeps_the_extremes_apart() {
        assert_eq!(base62(&[0u8; 32]), "0".repeat(43));
        let top = base62(&[0xff; 32]);
        assert_eq!(top.len(), 43);
        assert_eq!(top, "yhjskwdA6OZ1AL1YmHWZWm8LLG7HjnuCA2j5rOw8Xp1");
        let mut one = [0u8; 32];
        one[31] = 61;
        assert_eq!(base62(&one), format!("{}z", "0".repeat(42)));
        one[31] = 62;
        assert_eq!(base62(&one), format!("{}10", "0".repeat(41)));
    }

    #[test]
    fn random_base62_tokens_are_unique_and_alphanumeric() {
        let a = random_base62();
        assert_ne!(a, random_base62());
        assert_eq!(a.len(), BASE62_32_BYTES);
        assert!(a.bytes().all(|b| b.is_ascii_alphanumeric()));
    }
}
