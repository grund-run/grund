//! License keys (docs/design/licensing.md §4): a signed token verified
//! offline against keys compiled into this binary. No network call, ever.
//!
//! `grund-license-v1.<payload>.<signature>`, where the payload is base64url
//! JSON and the signature is Ed25519 over `grund-license-v1.` followed by the
//! payload text.

use std::collections::BTreeSet;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Deserialize;

/// The prefix every key starts with, and the domain the signature binds.
pub const PREFIX: &str = "grund-license-v1.";

/// A public key grund trusts to sign licenses.
pub struct TrustedKey {
    pub kid: &'static str,
    pub public_key: [u8; 32],
}

/// The keys this build trusts. Empty until Kasper creates the first
/// production signing key (docs/design/licensing.md §4): until then no key
/// verifies and every commercial feature stays off. Only the public half is
/// ever here.
pub const TRUSTED_KEYS: &[TrustedKey] = &[];

/// A commercial feature a license can include.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Feature {
    SocialLogin,
}

impl Feature {
    pub fn as_str(self) -> &'static str {
        match self {
            Feature::SocialLogin => "social_login",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "social_login" => Some(Feature::SocialLogin),
            _ => None,
        }
    }
}

/// A verified license.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct License {
    pub id: String,
    pub plan: String,
    pub features: BTreeSet<Feature>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Why a key was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LicenseError {
    #[error("the license key is not a grund license key")]
    Malformed,
    #[error("the license key was signed by a key this build does not trust")]
    UnknownKey,
    #[error("the license key's signature does not verify")]
    BadSignature,
    #[error("the license key is in a format this build does not read")]
    UnsupportedVersion,
    #[error("the license key is not valid yet")]
    NotYetValid,
    #[error("the license key has expired")]
    Expired,
}

#[derive(Deserialize)]
struct Claims {
    v: u32,
    kid: String,
    id: String,
    plan: String,
    #[serde(default)]
    features: Vec<String>,
    not_before: i64,
    expires_at: i64,
}

#[derive(Deserialize)]
struct Header {
    kid: String,
}

/// Checks license keys against a set of trusted public keys.
pub struct Verifier {
    keys: Vec<(String, VerifyingKey)>,
}

impl Verifier {
    /// The keys compiled into this build ([`TRUSTED_KEYS`]).
    pub fn grund() -> Self {
        Self::with_keys(
            TRUSTED_KEYS
                .iter()
                .map(|k| (k.kid.to_string(), k.public_key)),
        )
    }

    /// Any set of keys, for tests. A key that is not a valid Ed25519 point is
    /// skipped.
    pub fn with_keys(keys: impl IntoIterator<Item = (String, [u8; 32])>) -> Self {
        Self {
            keys: keys
                .into_iter()
                .filter_map(|(kid, bytes)| {
                    VerifyingKey::from_bytes(&bytes).ok().map(|key| (kid, key))
                })
                .collect(),
        }
    }

    /// Verifies `token` at `now`.
    pub fn verify(&self, token: &str, now: DateTime<Utc>) -> Result<License, LicenseError> {
        let body = token
            .trim()
            .strip_prefix(PREFIX)
            .ok_or(LicenseError::Malformed)?;
        let (payload, signature) = body.split_once('.').ok_or(LicenseError::Malformed)?;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| LicenseError::Malformed)?;
        let header: Header =
            serde_json::from_slice(&payload_bytes).map_err(|_| LicenseError::Malformed)?;
        let key = self
            .keys
            .iter()
            .find(|(kid, _)| *kid == header.kid)
            .map(|(_, key)| key)
            .ok_or(LicenseError::UnknownKey)?;
        let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(LicenseError::Malformed)?;
        let signed = format!("{PREFIX}{payload}");
        key.verify(signed.as_bytes(), &Signature::from_bytes(&signature_bytes))
            .map_err(|_| LicenseError::BadSignature)?;

        let claims: Claims =
            serde_json::from_slice(&payload_bytes).map_err(|_| LicenseError::Malformed)?;
        if claims.v != 1 {
            return Err(LicenseError::UnsupportedVersion);
        }
        debug_assert_eq!(claims.kid, header.kid);
        let not_before =
            DateTime::from_timestamp(claims.not_before, 0).ok_or(LicenseError::Malformed)?;
        let expires_at =
            DateTime::from_timestamp(claims.expires_at, 0).ok_or(LicenseError::Malformed)?;
        if now < not_before {
            return Err(LicenseError::NotYetValid);
        }
        if now >= expires_at {
            return Err(LicenseError::Expired);
        }
        Ok(License {
            id: claims.id,
            plan: claims.plan,
            features: claims
                .features
                .iter()
                .filter_map(|f| Feature::parse(f))
                .collect(),
            not_before,
            expires_at,
        })
    }
}

#[cfg(test)]
pub mod testing {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    pub fn signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("randomness");
        SigningKey::from_bytes(&seed)
    }

    pub fn sign(key: &SigningKey, claims: serde_json::Value) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signed = format!("{PREFIX}{payload}");
        let signature = URL_SAFE_NO_PAD.encode(key.sign(signed.as_bytes()).to_bytes());
        format!("{signed}.{signature}")
    }

    pub fn claims(
        kid: &str,
        features: &[&str],
        not_before: i64,
        expires_at: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "v": 1, "kid": kid, "id": "lic_test", "customer": "cus_test", "plan": "pro",
            "features": features, "issued_at": not_before, "not_before": not_before, "expires_at": expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::*, *};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).unwrap()
    }

    fn verifier_for(key: &ed25519_dalek::SigningKey) -> Verifier {
        Verifier::with_keys([("test-1".to_string(), key.verifying_key().to_bytes())])
    }

    #[test]
    fn a_key_signed_by_a_trusted_key_verifies_with_its_features() {
        let key = signing_key();
        let token = sign(
            &key,
            claims(
                "test-1",
                &["social_login", "future_thing"],
                1_700_000_000,
                1_900_000_000,
            ),
        );
        let license = verifier_for(&key).verify(&token, now()).unwrap();
        assert_eq!(license.plan, "pro");
        assert_eq!(
            license.features,
            [Feature::SocialLogin].into_iter().collect()
        );
    }

    #[test]
    fn a_key_signed_by_an_untrusted_key_is_refused_even_with_a_known_kid() {
        let trusted = signing_key();
        let forger = signing_key();
        let token = sign(
            &forger,
            claims("test-1", &["social_login"], 1_700_000_000, 1_900_000_000),
        );
        assert_eq!(
            verifier_for(&trusted).verify(&token, now()),
            Err(LicenseError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_payload_no_longer_verifies() {
        let key = signing_key();
        let token = sign(&key, claims("test-1", &[], 1_700_000_000, 1_900_000_000));
        let (head, signature) = token.rsplit_once('.').unwrap();
        let forged_payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&claims(
                "test-1",
                &["social_login"],
                1_700_000_000,
                1_900_000_000,
            ))
            .unwrap(),
        );
        let forged = format!("{PREFIX}{forged_payload}.{signature}");
        assert_ne!(head, format!("{PREFIX}{forged_payload}"));
        assert_eq!(
            verifier_for(&key).verify(&forged, now()),
            Err(LicenseError::BadSignature)
        );
    }

    #[test]
    fn an_unknown_kid_expiry_and_start_are_each_refused_by_name() {
        let key = signing_key();
        let verifier = verifier_for(&key);
        let unknown = sign(&key, claims("other", &[], 1_700_000_000, 1_900_000_000));
        assert_eq!(
            verifier.verify(&unknown, now()),
            Err(LicenseError::UnknownKey)
        );
        let expired = sign(&key, claims("test-1", &[], 1_700_000_000, 1_790_000_000));
        assert_eq!(verifier.verify(&expired, now()), Err(LicenseError::Expired));
        let early = sign(&key, claims("test-1", &[], 1_790_000_001, 1_900_000_000));
        assert_eq!(
            verifier.verify(&early, now()),
            Err(LicenseError::NotYetValid)
        );
    }

    #[test]
    fn garbage_is_malformed_not_a_panic() {
        let verifier = verifier_for(&signing_key());
        for token in [
            "",
            "grund-license-v1.",
            "grund-license-v1.abc",
            "grund-license-v1.e30.xyz",
            "license",
        ] {
            assert_eq!(
                verifier.verify(token, now()),
                Err(LicenseError::Malformed),
                "{token:?}"
            );
        }
    }

    #[test]
    fn this_build_trusts_no_production_key_yet() {
        let key = signing_key();
        let token = sign(
            &key,
            claims("test-1", &["social_login"], 1_700_000_000, 1_900_000_000),
        );
        assert!(TRUSTED_KEYS.is_empty());
        assert_eq!(
            Verifier::grund().verify(&token, now()),
            Err(LicenseError::UnknownKey)
        );
    }
}
