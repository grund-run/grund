//! A management machine's lease (grund-docs design/machines.md §5.3). A
//! machine registered into the management pool pins the management key,
//! not an organisation's, so it can verify no organisation's documents on
//! its own. When the operator leases it, the instance answers
//! `AgentService.GetLease` with a grant the management key signed, naming
//! the lessee, the lessee's organisation key and its private network. The
//! agent verifies the grant against the key it pinned and from then on
//! runs as a machine of that organisation: it accepts documents signed by
//! that key, for itself only, and joins that network.
//!
//! The lease the agent runs under is fixed for the life of the process.
//! At start it asks for the grant once and keeps it in `lease.json`, so a
//! restart without the instance keeps running as before (fail-static).
//! While it runs it asks again every [`WATCH_EVERY`]; a different answer
//! (another lease, a changed network, or none) ends the process, and the
//! next start takes the new answer. A lease that ended or changed lessee
//! also drops what the agent applied and the secrets it cached, so the
//! apps loop stops every copy of the old lessee's when it starts again.

use std::{path::Path, time::Duration};

use anyhow::{Context, bail};
use buffa::Message;
use ed25519_dalek::{Signature, VerifyingKey};
use grund_proto::grund::agent::v1::{
    GetLeaseRequest, GetLeaseResponse, LeaseGrant, SignedLeaseGrant,
};
use serde::{Deserialize, Serialize};

use crate::join::{self, NetworkRecord, PinnedKey, Record};

/// The file keeping the lease the machine runs under.
pub const LEASE_FILE: &str = "lease.json";

/// How often a running agent asks whether its lease still stands.
pub const WATCH_EVERY: Duration = Duration::from_secs(5);

/// What the management key granted, as the machine keeps it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    pub lease_id: String,
    pub organisation_id: String,
    pub organisation_key: PinnedKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkRecord>,
}

impl Lease {
    /// The machine's record as a machine of the lessee: its documents are
    /// the lessee's, signed by the lessee's key, and its network is the
    /// lessee's.
    pub fn applied_to(&self, registered: &Record) -> Record {
        Record {
            organisation_id: self.organisation_id.clone(),
            trust_key: self.organisation_key.clone(),
            network: self.network.clone(),
            ..registered.clone()
        }
    }
}

/// Verifies a grant against the management key `registered` pinned, for
/// this machine, and returns the lease it grants.
pub fn verify(registered: &Record, grant: &SignedLeaseGrant) -> anyhow::Result<Lease> {
    let pinned = &registered.trust_key;
    anyhow::ensure!(
        registered.pool == "management" && pinned.purpose == "management",
        "only a machine of the management pool is leased"
    );
    anyhow::ensure!(
        grant.key_id == pinned.key_id,
        "the grant is signed by a key this machine did not pin"
    );
    let bytes: [u8; 32] = hex::decode(&pinned.public_key)
        .ok()
        .and_then(|b| b.try_into().ok())
        .context("the pinned management key is not 32 bytes")?;
    let key = VerifyingKey::from_bytes(&bytes).context("the pinned management key")?;
    let signature =
        Signature::from_slice(&grant.signature).context("the grant's signature is not 64 bytes")?;
    let mut message = b"grund-lease-grant-v1\n".to_vec();
    message.extend_from_slice(&grant.payload);
    key.verify_strict(&message, &signature)
        .context("the grant's signature does not verify")?;
    let payload =
        LeaseGrant::decode_from_slice(&grant.payload).context("the grant does not decode")?;
    anyhow::ensure!(
        payload.machine_id == registered.machine_id,
        "the grant is for another machine"
    );
    let organisation_key = join::pinned(payload.organisation_key.as_option())?;
    anyhow::ensure!(
        organisation_key.purpose == "organisation",
        "a lessee's key is an organisation key"
    );
    if payload.lease_id.is_empty() || payload.organisation_id.is_empty() {
        bail!("the grant names no lease or organisation");
    }
    Ok(Lease {
        lease_id: payload.lease_id.clone(),
        organisation_id: payload.organisation_id.clone(),
        organisation_key,
        network: payload
            .network
            .as_option()
            .map(join::network_record)
            .transpose()?,
    })
}

/// The lease kept on the machine, if any.
pub fn read(data_dir: &Path) -> anyhow::Result<Option<Lease>> {
    let path = data_dir.join(LEASE_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            Ok(Some(serde_json::from_str(&text).with_context(|| {
                format!("{} is not a lease", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Keeps `lease` as the one the machine runs under, or forgets the kept one
/// for `None`. Moving to another lessee, or to none, also drops what the
/// agent applied and the secrets it cached for the old one.
pub fn keep(data_dir: &Path, kept: Option<&Lease>, lease: Option<&Lease>) -> anyhow::Result<()> {
    if kept == lease {
        return Ok(());
    }
    if kept.map(|l| &l.lease_id) != lease.map(|l| &l.lease_id) {
        for name in [crate::agent::APPLIED_FILE, crate::secrets::CACHE_FILE] {
            match std::fs::remove_file(data_dir.join(name)) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error).with_context(|| format!("remove {name}"));
                }
                _ => {}
            }
        }
    }
    match lease {
        Some(lease) => {
            join::replace_file(data_dir, LEASE_FILE, &serde_json::to_string_pretty(lease)?)
        }
        None => match std::fs::remove_file(data_dir.join(LEASE_FILE)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(error).context("remove the kept lease")
            }
            _ => Ok(()),
        },
    }
}

/// Asks the instance for the machine's lease: `Ok(None)` when it is on
/// none, an error when the instance cannot be asked or its grant does not
/// verify.
pub async fn fetch(
    link: &crate::agent::Link,
    registered: &Record,
) -> anyhow::Result<Option<Lease>> {
    let response: GetLeaseResponse = link.call("GetLease", &GetLeaseRequest::default()).await?;
    response
        .grant
        .as_option()
        .map(|grant| verify(registered, grant))
        .transpose()
}

/// The lease the agent starts under: the instance's answer, kept on disk,
/// or what was kept when the instance cannot be asked.
pub async fn at_start(
    link: &crate::agent::Link,
    registered: &Record,
    data_dir: &Path,
) -> anyhow::Result<Option<Lease>> {
    let kept = read(data_dir)?;
    match fetch(link, registered).await {
        Ok(lease) => {
            keep(data_dir, kept.as_ref(), lease.as_ref())?;
            match (&kept, &lease) {
                (None, Some(lease)) => {
                    tracing::info!(lease = %lease.lease_id, organisation = %lease.organisation_id, "leased; running as a machine of the lessee")
                }
                (Some(old), None) => {
                    tracing::info!(lease = %old.lease_id, "the lease ended; the lessee's copies stop")
                }
                (Some(old), Some(new)) if old.lease_id != new.lease_id => {
                    tracing::info!(old = %old.lease_id, lease = %new.lease_id, organisation = %new.organisation_id, "leased again; the previous lessee's copies stop")
                }
                _ => {}
            }
            Ok(lease)
        }
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "could not ask for this machine's lease; running under the one kept");
            Ok(kept)
        }
    }
}

/// Returns once the instance answers a lease other than `current`, asking
/// every [`WATCH_EVERY`]. A failed ask changes nothing.
pub async fn changed(link: crate::agent::Link, registered: Record, current: Option<Lease>) {
    loop {
        tokio::time::sleep(WATCH_EVERY).await;
        match fetch(&link, &registered).await {
            Ok(lease) if lease != current => return,
            Ok(_) => {}
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "could not ask for this machine's lease")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use grund_proto::grund::agent::v1::{KeyPurpose, Network, PublicKey};

    use super::*;

    fn management() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn registered(key: &SigningKey) -> Record {
        Record {
            machine_id: "m-1".into(),
            name: "gm-1".into(),
            pool: "management".into(),
            organisation_id: String::new(),
            instance_url: "https://grund.example.com".into(),
            instance_key: PinnedKey {
                key_id: "i".into(),
                public_key: hex::encode([0u8; 32]),
                purpose: "instance".into(),
            },
            trust_key: PinnedKey {
                key_id: "mk".into(),
                public_key: hex::encode(key.verifying_key().to_bytes()),
                purpose: "management".into(),
            },
            heartbeat_interval_seconds: 5,
            registered_at_unix: 0,
            network: None,
        }
    }

    fn key(byte: u8, purpose: KeyPurpose) -> PublicKey {
        PublicKey {
            key_id: format!("k{byte}"),
            public_key: SigningKey::from_bytes(&[byte; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
            purpose: purpose.into(),
            ..Default::default()
        }
    }

    fn grant(machine_id: &str) -> LeaseGrant {
        LeaseGrant {
            lease_id: "l-1".into(),
            machine_id: machine_id.into(),
            organisation_id: "o-1".into(),
            organisation_key: buffa::MessageField::from(key(
                9,
                KeyPurpose::KEY_PURPOSE_ORGANISATION,
            )),
            issued_at_unix: 1,
            network: buffa::MessageField::from(Network {
                network_id: "n-1".into(),
                key: buffa::MessageField::from(key(11, KeyPurpose::KEY_PURPOSE_NETWORK)),
                prefix: "fd12:3456:789a::".into(),
                slot: 3,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn signed(
        by: &SigningKey,
        key_id: &str,
        grant: &LeaseGrant,
        prefix: &[u8],
    ) -> SignedLeaseGrant {
        let payload = grant.encode_to_vec();
        let signature = by.sign(&[prefix, &payload].concat()).to_bytes().to_vec();
        SignedLeaseGrant {
            key_id: key_id.into(),
            payload,
            signature,
            ..Default::default()
        }
    }

    #[test]
    fn a_grant_the_pinned_management_key_signed_makes_the_machine_the_lessees() {
        let key = management();
        let record = registered(&key);
        let lease = verify(
            &record,
            &signed(&key, "mk", &grant("m-1"), b"grund-lease-grant-v1\n"),
        )
        .expect("a good grant verifies");
        assert_eq!(lease.organisation_id, "o-1");
        assert_eq!(lease.organisation_key.purpose, "organisation");
        assert_eq!(lease.network.as_ref().map(|n| n.slot), Some(3));
        let applied = lease.applied_to(&record);
        assert_eq!(applied.trust_key, lease.organisation_key);
        assert_eq!(applied.organisation_id, "o-1");
        assert_eq!(applied.machine_id, "m-1");
    }

    #[test]
    fn a_grant_signed_by_another_key_for_another_purpose_or_machine_is_refused() {
        let key = management();
        let record = registered(&key);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let prefix = b"grund-lease-grant-v1\n";
        assert!(verify(&record, &signed(&other, "mk", &grant("m-1"), prefix)).is_err());
        assert!(verify(&record, &signed(&key, "other", &grant("m-1"), prefix)).is_err());
        assert!(
            verify(
                &record,
                &signed(&key, "mk", &grant("m-1"), b"grund-desired-state-v1\n")
            )
            .is_err()
        );
        assert!(verify(&record, &signed(&key, "mk", &grant("m-2"), prefix)).is_err());
        let mut wrong_purpose = grant("m-1");
        wrong_purpose.organisation_key =
            buffa::MessageField::from(key_of_purpose(KeyPurpose::KEY_PURPOSE_MANAGEMENT));
        assert!(verify(&record, &signed(&key, "mk", &wrong_purpose, prefix)).is_err());
    }

    fn key_of_purpose(purpose: KeyPurpose) -> PublicKey {
        key(9, purpose)
    }

    #[test]
    fn a_machine_of_an_organisations_own_pool_takes_no_grant() {
        let key = management();
        let mut record = registered(&key);
        record.pool = "organisation".into();
        record.trust_key.purpose = "organisation".into();
        assert!(
            verify(
                &record,
                &signed(&key, "mk", &grant("m-1"), b"grund-lease-grant-v1\n")
            )
            .is_err()
        );
    }

    #[test]
    fn moving_to_another_lessee_or_none_drops_what_the_old_one_left() {
        let dir = std::env::temp_dir().join(format!("grund-lease-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a directory");
        let key = management();
        let record = registered(&key);
        let first = verify(
            &record,
            &signed(&key, "mk", &grant("m-1"), b"grund-lease-grant-v1\n"),
        )
        .expect("a good grant");
        keep(&dir, None, Some(&first)).expect("kept");
        assert_eq!(read(&dir).expect("read"), Some(first.clone()));
        std::fs::write(dir.join(crate::agent::APPLIED_FILE), b"{}").expect("applied");
        let mut moved = first.clone();
        moved.network = None;
        keep(&dir, Some(&first), Some(&moved)).expect("kept");
        assert!(dir.join(crate::agent::APPLIED_FILE).exists());
        let mut second = first.clone();
        second.lease_id = "l-2".into();
        keep(&dir, Some(&moved), Some(&second)).expect("kept");
        assert!(!dir.join(crate::agent::APPLIED_FILE).exists());
        std::fs::write(dir.join(crate::agent::APPLIED_FILE), b"{}").expect("applied");
        keep(&dir, Some(&second), None).expect("forgot");
        assert_eq!(read(&dir).expect("read"), None);
        assert!(!dir.join(crate::agent::APPLIED_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
