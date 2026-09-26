//! The instance's Ed25519 keys (grund-docs design/machines.md §4): the
//! instance key machines pin as its identity, the management key that signs
//! lease grants, and one key per organisation for its desired-state
//! documents.
//!
//! Each private key is derived from the instance secret and the key's id,
//! `HMAC-SHA256(GRUND_SECRET_KEY, "grund/ed25519/<key id>/v1")`, and never
//! stored: `grund_keys` holds only ids, purposes and public halves. At start
//! every stored key is derived again and compared, so a changed secret is
//! caught before a machine sees a key it did not pin.

use std::sync::Arc;

use anyhow::Context;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use grund_domain::machine::KeyPurpose;
use grund_store::machines::{self, KeyRow};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::{secrets::SecretKey, state::State};

/// Derives, signs with and publishes the instance's keys. Cheap to clone.
#[derive(Clone)]
pub struct Keys {
    secret: Arc<SecretKey>,
}

/// A key's id and public half, as machines pin it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub key_id: Uuid,
    pub purpose: KeyPurpose,
    pub public_key: [u8; 32],
}

impl Keys {
    pub fn new(secret: Arc<SecretKey>) -> Self {
        Self { secret }
    }

    fn signing_key(&self, key_id: Uuid) -> SigningKey {
        SigningKey::from_bytes(&self.secret.derive(&format!("ed25519/{key_id}")))
    }

    /// The public half of the key with this id.
    pub fn public(&self, key_id: Uuid) -> [u8; 32] {
        self.signing_key(key_id).verifying_key().to_bytes()
    }

    /// Signs `prefix || payload` with the key `key_id`. Every caller passes
    /// one of `grund_domain::machine::prefix`, so nothing signed for one
    /// purpose verifies as another.
    pub fn sign(&self, key_id: Uuid, prefix: &[u8], payload: &[u8]) -> [u8; 64] {
        let mut message = Vec::with_capacity(prefix.len() + payload.len());
        message.extend_from_slice(prefix);
        message.extend_from_slice(payload);
        self.signing_key(key_id).sign(&message).to_bytes()
    }

    /// The current key for `purpose` (and organisation), made now if there is
    /// none. Of two racing callers one inserts and both read the same row.
    pub async fn ensure(
        &self,
        connection: &mut sqlx::PgConnection,
        purpose: KeyPurpose,
        organisation_id: Option<Uuid>,
    ) -> anyhow::Result<PublicKey> {
        if let Some(row) =
            machines::current_key(&mut *connection, purpose.as_str(), organisation_id).await?
        {
            return public(row);
        }
        let key_id = Uuid::now_v7();
        machines::insert_key(
            &mut *connection,
            key_id,
            purpose.as_str(),
            organisation_id,
            &self.public(key_id),
        )
        .await?;
        let row = machines::current_key(&mut *connection, purpose.as_str(), organisation_id)
            .await?
            .context("a current key exists after inserting one")?;
        public(row)
    }

    async fn mismatched(&self, executor: impl PgExecutor<'_>) -> anyhow::Result<Vec<Uuid>> {
        Ok(machines::current_keys(executor)
            .await?
            .into_iter()
            .filter(|row| row.public_key.as_slice() != self.public(row.key_id))
            .map(|row| row.key_id)
            .collect())
    }
}

fn public(row: KeyRow) -> anyhow::Result<PublicKey> {
    let public_key: [u8; 32] = row
        .public_key
        .as_slice()
        .try_into()
        .context("a stored public key is 32 bytes")?;
    VerifyingKey::from_bytes(&public_key).context("a stored public key is a valid Ed25519 key")?;
    Ok(PublicKey {
        key_id: row.key_id,
        purpose: KeyPurpose::parse(&row.purpose).context("a stored key purpose is known")?,
        public_key,
    })
}

/// Checks the stored keys against the instance secret, then makes the
/// instance and management keys if this is the instance's first start.
///
/// A key that no longer derives means GRUND_SECRET_KEY changed. Outside dev
/// mode that refuses to start: every machine pinned the old keys. In dev mode
/// (a throwaway secret on every restart) the old keys are retired and new ones
/// made.
pub async fn check_at_start(
    pool: &sqlx::PgPool,
    keys: &Keys,
    dev_mode: bool,
) -> anyhow::Result<()> {
    let mismatched = keys.mismatched(pool).await?;
    if !mismatched.is_empty() {
        anyhow::ensure!(
            dev_mode,
            "{} of the instance's keys do not match GRUND_SECRET_KEY: the secret key changed since \
             they were made. Every machine pinned those keys, so grund will not start with another \
             secret. Restore the previous GRUND_SECRET_KEY (or GRUND_SECRET_KEY_FILE); rotating it \
             needs every machine to register again, which is not built",
            mismatched.len()
        );
        let retired = machines::retire_all_keys(pool).await?;
        tracing::warn!(
            retired,
            "the throwaway secret key changed (GRUND_DEV_MODE); retired the instance's keys and \
             made new ones. Machines registered before must register again"
        );
    }
    let mut connection = pool.acquire().await?;
    for purpose in [KeyPurpose::Instance, KeyPurpose::Management] {
        let key = keys.ensure(&mut connection, purpose, None).await?;
        tracing::info!(
            purpose = purpose.as_str(),
            key_id = %key.key_id,
            "instance key ready"
        );
    }
    Ok(())
}

/// Access to the instance's keys.
pub trait KeysState {
    fn keys(&self) -> Keys;
}

impl KeysState for State {
    fn keys(&self) -> Keys {
        Keys::new(self.secret.clone())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier};

    use super::*;

    #[test]
    fn a_key_derives_the_same_from_the_same_secret_and_id_and_differs_by_id() {
        let keys = Keys::new(Arc::new(SecretKey::generate()));
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        assert_eq!(keys.public(a), keys.public(a));
        assert_ne!(keys.public(a), keys.public(b));
        let other = Keys::new(Arc::new(SecretKey::generate()));
        assert_ne!(keys.public(a), other.public(a));
    }

    #[test]
    fn a_signature_verifies_only_with_its_prefix() {
        let keys = Keys::new(Arc::new(SecretKey::generate()));
        let key_id = Uuid::now_v7();
        let signature =
            Signature::from_bytes(&keys.sign(key_id, b"grund-lease-grant-v1\n", b"payload"));
        let verifying = VerifyingKey::from_bytes(&keys.public(key_id)).unwrap();
        assert!(
            verifying
                .verify(b"grund-lease-grant-v1\npayload", &signature)
                .is_ok()
        );
        assert!(
            verifying
                .verify(b"grund-desired-state-v1\npayload", &signature)
                .is_err()
        );
    }
}
