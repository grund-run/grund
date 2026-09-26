//! The machine's side of its organisation's private network (grund/fleet
//! docs/design/network.md §5, §6; grund-net).
//!
//! When `grund join` pinned a network ([`crate::join::NetworkRecord`]), the
//! agent binds an iroh endpoint with the machine key, runs grund-net's mesh on
//! `grund0`, and keeps it fed with membership lists: `GetMembership` over the
//! control link, which answers at once when the epoch moved and otherwise
//! waits up to 10 s, so a revocation reaches the machine in about a second.
//!
//! A list is used only if it is signed by the key pinned at join (same key id
//! and public key), is for the pinned network and prefix, and is newer than
//! the last one. Otherwise the mesh keeps the last good list (fail-static).
//!
//! The mesh needs `CAP_NET_ADMIN` for the TUN device, so a machine whose
//! agent does not run as root skips it; service forwards for rootless
//! machines are not built. With no relay URLs yet, members reach each other
//! only where a direct path exists (the same LAN, or open UDP).

use std::{net::Ipv6Addr, str::FromStr, time::Duration};

use anyhow::{Context, bail};
use ed25519_dalek::VerifyingKey;
use grund_net::{
    NET_ALPN,
    endpoint::{self, NetConfig},
    membership::{MembershipList, SignedList},
    mesh::{Mesh, MeshConfig},
};
use grund_proto::grund::agent::v1::{GetMembershipRequest, GetMembershipResponse};
use iroh::RelayUrl;
use tokio::sync::watch;

use crate::{agent::Link, join::NetworkRecord};

/// The TUN device the mesh uses.
pub const TUN_NAME: &str = "grund0";

/// Why a membership list from the instance was not used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListRefusal {
    /// Signed by a key other than the one pinned at join.
    #[error("the list is signed by key {0}, not the network key pinned at join")]
    UnknownKey(String),
    /// The signature or the list's own rules failed.
    #[error("the list does not verify: {0}")]
    Invalid(String),
    /// For another network or prefix than the one pinned.
    #[error("the list is for another network or prefix")]
    WrongNetwork,
    /// Not newer than the list in force.
    #[error("epoch {0} is not newer than {1}")]
    Older(u64, u64),
}

/// Checks a list from `GetMembership` against the network pinned at join and
/// the epoch in force, and returns it when it may be used.
pub fn accept_list(
    network: &NetworkRecord,
    key_id: &str,
    body: &[u8],
    signature: &[u8],
    current_epoch: u64,
) -> Result<MembershipList, ListRefusal> {
    if key_id != network.key.key_id {
        return Err(ListRefusal::UnknownKey(key_id.to_string()));
    }
    let key = pinned_key(network).map_err(|e| ListRefusal::Invalid(e.to_string()))?;
    let signed = SignedList {
        body: body.to_vec(),
        signature: signature.to_vec(),
    };
    let list = signed
        .verify(&key)
        .map_err(|e| ListRefusal::Invalid(e.to_string()))?;
    let prefix = Ipv6Addr::from_str(&network.prefix).map_err(|_| ListRefusal::WrongNetwork)?;
    if list.network_id != network.network_id || list.prefix != prefix {
        return Err(ListRefusal::WrongNetwork);
    }
    if list.epoch <= current_epoch {
        return Err(ListRefusal::Older(list.epoch, current_epoch));
    }
    Ok(list)
}

fn pinned_key(network: &NetworkRecord) -> anyhow::Result<VerifyingKey> {
    if network.key.purpose != "network" {
        bail!(
            "the pinned key is a {} key, not a network key",
            network.key.purpose
        );
    }
    let bytes: [u8; 32] = hex::decode(&network.key.public_key)
        .context("the pinned network key is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the pinned network key is not 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("the pinned network key")
}

pub(crate) async fn run(link: Link, network: NetworkRecord, seed: [u8; 32]) -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        tracing::warn!(
            "private network skipped: grund0 needs root (CAP_NET_ADMIN); rootless forwards are not built"
        );
        return Ok(());
    }
    pinned_key(&network)?;
    let relays = network
        .relay_urls
        .iter()
        .map(|u| RelayUrl::from_str(u).with_context(|| format!("relay URL {u}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let config = NetConfig {
        relays: relays.clone(),
        ..NetConfig::default()
    };
    let endpoint = endpoint::bind(
        grund_net::key::secret_key(&seed),
        &config,
        vec![NET_ALPN.to_vec()],
    )
    .await?;
    let mesh = Mesh::new(
        endpoint.clone(),
        MeshConfig {
            tun_name: TUN_NAME.into(),
            relays,
        },
    );
    let _router = iroh::protocol::Router::builder(endpoint)
        .accept(NET_ALPN, mesh.clone())
        .spawn();
    let (tx, rx) = watch::channel(None);
    tracing::info!(network = %network.network_id, slot = network.slot, "private network: starting");
    tokio::select! {
        result = mesh.run(rx) => result,
        result = follow(&link, &network, tx) => result,
    }
}

async fn follow(
    link: &Link,
    network: &NetworkRecord,
    tx: watch::Sender<Option<MembershipList>>,
) -> anyhow::Result<()> {
    let mut epoch = 0;
    loop {
        let answer: anyhow::Result<GetMembershipResponse> = link
            .call(
                "GetMembership",
                &GetMembershipRequest {
                    network_id: network.network_id.clone(),
                    since_epoch: epoch,
                    ..Default::default()
                },
            )
            .await;
        match answer {
            Ok(answer) => {
                if let Some(signed) = answer.list.as_option() {
                    match accept_list(
                        network,
                        &signed.key_id,
                        &signed.body,
                        &signed.signature,
                        epoch,
                    ) {
                        Ok(list) => {
                            tracing::info!(
                                epoch = list.epoch,
                                members = list.members.len(),
                                "private network: list applied"
                            );
                            epoch = list.epoch;
                            if tx.send(Some(list)).is_err() {
                                return Ok(());
                            }
                        }
                        Err(refusal) => {
                            tracing::warn!(%refusal, "private network: list refused; keeping the last good one");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "private network: GetMembership failed; keeping the last list");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use grund_net::membership::Member;

    use super::*;
    use crate::join::PinnedKey;

    fn network(key: &SigningKey) -> NetworkRecord {
        NetworkRecord {
            network_id: "net-1".into(),
            key: PinnedKey {
                key_id: "k1".into(),
                public_key: hex::encode(key.verifying_key().as_bytes()),
                purpose: "network".into(),
            },
            prefix: "fd12:3456:789a::".into(),
            slot: 1,
            relay_urls: vec![],
        }
    }

    fn list(epoch: u64, network_id: &str) -> MembershipList {
        MembershipList {
            network_id: network_id.into(),
            epoch,
            prefix: "fd12:3456:789a::".parse().unwrap(),
            issued_at: 1_790_000_000,
            members: vec![Member {
                machine_id: "m1".into(),
                endpoint_id: grund_net::key::endpoint_id(&[1; 32]).to_string(),
                slot: 1,
            }],
        }
    }

    #[test]
    fn a_list_signed_by_the_pinned_key_for_this_network_and_newer_is_used() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let s = SignedList::sign(&list(2, "net-1"), &key);
        assert_eq!(
            accept_list(&network(&key), "k1", &s.body, &s.signature, 1),
            Ok(list(2, "net-1"))
        );
    }

    #[test]
    fn another_key_id_another_key_another_network_or_an_older_epoch_is_refused() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let net = network(&key);
        let s = SignedList::sign(&list(2, "net-1"), &key);
        assert_eq!(
            accept_list(&net, "k2", &s.body, &s.signature, 1),
            Err(ListRefusal::UnknownKey("k2".into()))
        );
        let forged = SignedList::sign(&list(2, "net-1"), &SigningKey::from_bytes(&[6; 32]));
        assert!(matches!(
            accept_list(&net, "k1", &forged.body, &forged.signature, 1),
            Err(ListRefusal::Invalid(_))
        ));
        let other = SignedList::sign(&list(2, "net-2"), &key);
        assert_eq!(
            accept_list(&net, "k1", &other.body, &other.signature, 1),
            Err(ListRefusal::WrongNetwork)
        );
        assert_eq!(
            accept_list(&net, "k1", &s.body, &s.signature, 2),
            Err(ListRefusal::Older(2, 2))
        );
    }
}
