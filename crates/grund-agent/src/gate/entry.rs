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

pub use grund_entry::NOT_AN_ENTRY_KEY;

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
        let (drain, drained) = tokio::sync::watch::channel(false);
        let notices = connection.clone();
        let listening = tokio::spawn(async move {
            while let Ok(mut notice) = notices.accept_uni().await {
                if let Ok(bytes) = notice.read_to_end(grund_entry::DRAIN.len()).await
                    && bytes == grund_entry::DRAIN
                {
                    tracing::info!(edge = %notices.remote_id(), "gate: the edge is stopping; closing its client connections after their current request");
                    let _ = drain.send(true);
                }
            }
        });
        while let Ok((send, recv)) = connection.accept_bi().await {
            let (gate, drained) = (self.0.clone(), drained.clone());
            tokio::spawn(async move {
                if let Err(error) = stream(gate, send, recv, drained).await {
                    tracing::debug!(%error, "gate: entry stream ended");
                }
            });
        }
        listening.abort();
        Ok(())
    }
}

async fn stream(
    gate: Gate,
    mut send: SendStream,
    mut recv: RecvStream,
    edge_stopping: tokio::sync::watch::Receiver<bool>,
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
    gate.serve_until(
        io,
        EntryClient {
            client: header.client,
            host,
        },
        edge_stopping,
    )
    .await;
    Ok(())
}
