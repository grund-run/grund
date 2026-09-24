//! The commercial seam (docs/design/auth.md §7): the one place that answers
//! "may this instance use feature X". It is built once at startup from the
//! license key. Nothing else in grund turns a commercial feature on: no flag,
//! no config value, no `cfg`.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::{
    license::{Feature, License, LicenseError, Verifier},
    state::State,
};

/// Why a feature is not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("no license key is configured")]
    NoLicense,
    #[error("{0}")]
    Invalid(LicenseError),
    #[error("the license has expired")]
    Expired,
    #[error("the license does not include {}", .0.as_str())]
    NotIncluded(Feature),
}

/// What this instance's license allows.
#[derive(Debug)]
pub struct Entitlements {
    license: Result<License, Refusal>,
}

impl Entitlements {
    /// No license: every free feature, no commercial one.
    pub fn community() -> Self {
        Self {
            license: Err(Refusal::NoLicense),
        }
    }

    /// Verifies `key` with `verifier` at `now`. A bad key is logged and
    /// treated as no license: an invalid or expired key never stops grund.
    pub fn from_key(key: Option<&str>, verifier: &Verifier, now: DateTime<Utc>) -> Self {
        let Some(key) = key else {
            return Self::community();
        };
        match verifier.verify(key, now) {
            Ok(license) => {
                tracing::info!(license = %license.id, plan = %license.plan, expires_at = %license.expires_at, "license verified");
                Self {
                    license: Ok(license),
                }
            }
            Err(error) => {
                tracing::error!(error = %error, "license key not accepted; commercial features are off");
                Self {
                    license: Err(Refusal::Invalid(error)),
                }
            }
        }
    }

    /// Whether `feature` may be used at `now`. Expiry is checked on every
    /// call, so a license that lapses while grund runs turns off on time.
    pub fn check(&self, feature: Feature, now: DateTime<Utc>) -> Result<(), Refusal> {
        let license = self.license.as_ref().map_err(|refusal| *refusal)?;
        if now >= license.expires_at {
            return Err(Refusal::Expired);
        }
        if !license.features.contains(&feature) {
            return Err(Refusal::NotIncluded(feature));
        }
        Ok(())
    }

    /// [`Entitlements::check`] at the current time.
    pub fn allows(&self, feature: Feature) -> Result<(), Refusal> {
        self.check(feature, Utc::now())
    }
}

/// Access to [`Entitlements`] from [`State`].
pub trait EntitlementsState {
    fn entitlements(&self) -> Arc<Entitlements>;
}

impl EntitlementsState for State {
    fn entitlements(&self) -> Arc<Entitlements> {
        self.entitlements.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::testing::{claims, sign, signing_key};

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    fn licensed(features: &[&str], expires_at: i64) -> Entitlements {
        let key = signing_key();
        let verifier =
            Verifier::with_keys([("test-1".to_string(), key.verifying_key().to_bytes())]);
        let token = sign(&key, claims("test-1", features, 1_700_000_000, expires_at));
        Entitlements::from_key(Some(&token), &verifier, at(1_790_000_000))
    }

    #[test]
    fn without_a_license_social_sign_in_is_refused() {
        assert_eq!(
            Entitlements::community().check(Feature::SocialLogin, at(1_790_000_000)),
            Err(Refusal::NoLicense)
        );
    }

    #[test]
    fn a_license_that_includes_social_sign_in_allows_it_until_it_expires() {
        let entitlements = licensed(&["social_login"], 1_800_000_000);
        assert_eq!(
            entitlements.check(Feature::SocialLogin, at(1_790_000_000)),
            Ok(())
        );
        assert_eq!(
            entitlements.check(Feature::SocialLogin, at(1_800_000_000)),
            Err(Refusal::Expired)
        );
    }

    #[test]
    fn a_license_without_the_feature_does_not_grant_it() {
        let entitlements = licensed(&[], 1_800_000_000);
        assert_eq!(
            entitlements.check(Feature::SocialLogin, at(1_790_000_000)),
            Err(Refusal::NotIncluded(Feature::SocialLogin))
        );
    }

    #[test]
    fn a_key_from_an_untrusted_signer_counts_as_no_license_and_does_not_panic() {
        let key = signing_key();
        let token = sign(
            &key,
            claims("test-1", &["social_login"], 1_700_000_000, 1_800_000_000),
        );
        let entitlements =
            Entitlements::from_key(Some(&token), &Verifier::grund(), at(1_790_000_000));
        assert_eq!(
            entitlements.check(Feature::SocialLogin, at(1_790_000_000)),
            Err(Refusal::Invalid(LicenseError::UnknownKey))
        );
    }
}
