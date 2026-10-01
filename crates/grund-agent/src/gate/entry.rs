//! The gate's side of `grund/entry/1` (grund-docs design/traffic.md §6.3,
//! §7.1): an iroh protocol handler on the agent's endpoint.
//!
//! A connection from a key that is not one of the document's entry keys is
//! closed before any stream is read. Each stream's header names the host;
//! the gate answers from what is placed and ready now ([`Gate::admit`]),
//! and only on accept does it read the client's bytes and serve HTTP on the
//! stream.

use std::time::Duration;

use iroh::{
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};

use super::{EntryClient, Gate};

/// The QUIC application error code a refused entry connection is closed
/// with.
pub const NOT_AN_ENTRY_KEY: u32 = 403;

/// How long the edge has to send a stream's header.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// The gate as an iroh protocol handler for [`grund_entry::ENTRY_ALPN`].
#[derive(Debug, Clone)]
pub struct EntryProtocol(pub Gate);

impl ProtocolHandler for EntryProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id().to_string();
        if !self.0.is_entry_key(&remote) {
            tracing::warn!(%remote, "gate: refused an entry connection from a key that is not an entry key");
            connection.close(NOT_AN_ENTRY_KEY.into(), b"not an entry key");
            return Ok(());
        }
        while let Ok((send, recv)) = connection.accept_bi().await {
            let gate = self.0.clone();
            tokio::spawn(async move {
                if let Err(error) = stream(gate, send, recv).await {
                    tracing::debug!(%error, "gate: entry stream ended");
                }
            });
        }
        Ok(())
    }
}

async fn stream(
    gate: Gate,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<(), grund_entry::EntryError> {
    gate.stats()
        .streams
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let header = tokio::time::timeout(HEADER_TIMEOUT, grund_entry::Header::read(&mut recv))
        .await
        .map_err(|_| {
            grund_entry::EntryError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no entry header in time",
            ))
        })??;
    let host = header.host.trim_end_matches('.').to_ascii_lowercase();
    let answer = gate.admit(&host);
    grund_entry::write_answer(&mut send, answer).await?;
    if !matches!(answer, grund_entry::Answer::Accept { .. }) {
        gate.stats()
            .refused
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = send.finish();
        return Ok(());
    }
    let io = tokio::io::join(recv, send);
    gate.serve(
        io,
        EntryClient {
            client: header.client,
            host,
        },
    )
    .await;
    Ok(())
}
