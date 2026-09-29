//! Epoch gossip (grund-docs design/network.md §5.2): members hand each other
//! the newest signed membership list, so a revocation reaches a member that
//! cannot reach grund, as long as it talks to one that can.
//!
//! A member sends its list, as grund signed it, on a unidirectional stream
//! of the mesh connection: when the connection opens, and to every
//! connected member whenever it takes a newer one. The mesh only carries
//! the bytes. What it receives goes to its owner ([`GossipLink::incoming`]),
//! which checks the signature against the key pinned at join, the network,
//! and that the epoch is newer, exactly as it checks a list from grund.
//! Nothing a member forges, and no older list, is ever used.

use std::sync::Arc;

use iroh::{EndpointId, endpoint::Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

use crate::membership::SignedList;

/// The largest list a member accepts from another: the agent's own limit
/// for a list (network.md §12), and room for the framing.
pub const MAX_GOSSIP_BYTES: usize = 256 * 1024 + 1024;

const MAGIC: &[u8] = b"grund-net-gossip-v1\n";

/// A membership list as grund signed it, with the id of the key it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipList {
    pub key_id: String,
    #[serde(flatten)]
    pub list: SignedList,
}

/// How the mesh gossips: what it sends and where what it receives goes.
#[derive(Debug, Clone)]
pub struct GossipLink {
    /// The newest list this machine holds, as it would hand it on.
    pub outgoing: watch::Receiver<Option<Arc<GossipList>>>,
    /// Lists members sent, for the owner to verify. Full: dropped, and the
    /// next one tries again.
    pub incoming: mpsc::Sender<(EndpointId, GossipList)>,
}

/// Sends `list` to the member at the other end of `conn`.
pub async fn send(conn: &Connection, list: &GossipList) -> anyhow::Result<()> {
    let body = serde_json::to_vec(list)?;
    anyhow::ensure!(
        MAGIC.len() + body.len() <= MAX_GOSSIP_BYTES,
        "the list is larger than a member takes"
    );
    let mut stream = conn.open_uni().await?;
    stream.write_all(MAGIC).await?;
    stream.write_all(&body).await?;
    stream.finish()?;
    Ok(())
}

/// Reads every list the member at the other end of `conn` sends, and hands
/// each to `incoming`, until the connection closes.
pub async fn receive(conn: Connection, incoming: mpsc::Sender<(EndpointId, GossipList)>) {
    let from = conn.remote_id();
    while let Ok(mut stream) = conn.accept_uni().await {
        let Ok(bytes) = stream.read_to_end(MAX_GOSSIP_BYTES).await else {
            continue;
        };
        let Some(body) = bytes.strip_prefix(MAGIC) else {
            continue;
        };
        if let Ok(list) = serde_json::from_slice::<GossipList>(body) {
            let _ = incoming.try_send((from, list));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gossiped_list_is_the_signed_bytes_and_the_key_id() {
        let list = GossipList {
            key_id: "k1".into(),
            list: SignedList {
                body: b"{}".to_vec(),
                signature: vec![1, 2, 3],
            },
        };
        let wire = serde_json::to_string(&list).unwrap();
        assert_eq!(wire, r#"{"key_id":"k1","body":"e30=","signature":"AQID"}"#);
        assert_eq!(serde_json::from_str::<GossipList>(&wire).unwrap(), list);
    }
}
