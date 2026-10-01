//! `grund/entry/1` (grund-docs design/traffic.md §6.3): one QUIC stream per
//! client connection, opened by an edge to the gate on the machine it chose,
//! over the iroh connection between the edge's key and the machine's key.
//!
//! ```text
//! edge → gate:  u16 length, header (JSON: host, alpn, client, tls)
//!               then the client's bytes, after TLS
//! gate → edge:  1 byte answer + u16 ready copies
//!               0 accept | 1 no ready copy | 2 not placed here | 3 draining
//!               then the response bytes
//! ```
//!
//! Nothing of the client's reaches an app before the gate answers
//! [`Answer::Accept`], so the edge may retry any refusal on another machine,
//! whatever the request. The gate trusts the header's `client` only because
//! only an entry key may open the stream; it strips whatever forwarding
//! headers the client sent and sets its own from it (§7.5).

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The ALPN of the edge's connections to machines.
pub const ENTRY_ALPN: &[u8] = b"grund/entry/1";

/// The largest header either end accepts.
pub const MAX_HEADER_BYTES: usize = 4096;

/// Entry streams one edge-to-machine connection may hold open at once
/// (§13: one per client connection; iroh's default of 100 capped a machine
/// at 100 client connections per edge node).
pub const MAX_STREAMS: u32 = 1024;

/// The receive window of one entry stream (§13): memory is streams ×
/// window, so 1024 streams hold at most 256 MiB.
pub const STREAM_WINDOW: u32 = 256 * 1024;

/// What the edge tells the gate about the client connection it hands over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The name from the ClientHello, lowercase: the address the client
    /// asked for.
    pub host: String,
    /// The ALPN negotiated with the client: `h2` or `http/1.1`.
    pub alpn: String,
    /// The client's address as the edge saw it, `ip:port`.
    pub client: String,
    /// The TLS the client spoke to the edge, for logs.
    #[serde(default)]
    pub tls: Tls,
}

/// The TLS between the client and the edge.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tls {
    pub version: String,
    pub cipher: String,
}

/// The gate's answer, before any client byte reaches an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The gate serves this connection; `ready` copies of the app are ready
    /// here.
    Accept { ready: u16 },
    /// The app is placed here and has no ready copy on this machine.
    NoReadyCopy,
    /// No app of this name is placed on this machine with a published port.
    NotPlacedHere,
    /// The gate is draining: the agent is stopping or updating.
    Draining,
}

impl Answer {
    /// The answer's three bytes on the wire.
    pub fn encode(self) -> [u8; 3] {
        let (code, ready) = match self {
            Answer::Accept { ready } => (0, ready),
            Answer::NoReadyCopy => (1, 0),
            Answer::NotPlacedHere => (2, 0),
            Answer::Draining => (3, 0),
        };
        let [high, low] = ready.to_be_bytes();
        [code, high, low]
    }

    /// Reads an answer's three bytes.
    pub fn decode(bytes: [u8; 3]) -> Result<Self, EntryError> {
        let ready = u16::from_be_bytes([bytes[1], bytes[2]]);
        match bytes[0] {
            0 => Ok(Answer::Accept { ready }),
            1 => Ok(Answer::NoReadyCopy),
            2 => Ok(Answer::NotPlacedHere),
            3 => Ok(Answer::Draining),
            other => Err(EntryError::UnknownAnswer(other)),
        }
    }

    /// A stable word for logs and metrics.
    pub fn word(self) -> &'static str {
        match self {
            Answer::Accept { .. } => "accept",
            Answer::NoReadyCopy => "no_ready_copy",
            Answer::NotPlacedHere => "not_placed_here",
            Answer::Draining => "draining",
        }
    }
}

/// Why a stream's framing was refused.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    #[error("the entry header is {0} bytes; at most {MAX_HEADER_BYTES}")]
    TooLarge(usize),
    #[error("the entry header does not decode: {0}")]
    Malformed(String),
    #[error("an unknown entry answer {0}")]
    UnknownAnswer(u8),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Header {
    /// The header's bytes on the wire: its length, then its JSON.
    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        let body = serde_json::to_vec(self).map_err(|e| EntryError::Malformed(e.to_string()))?;
        if body.len() > MAX_HEADER_BYTES {
            return Err(EntryError::TooLarge(body.len()));
        }
        let mut out = Vec::with_capacity(2 + body.len());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Reads one header from the start of a stream.
    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, EntryError> {
        let length = usize::from(reader.read_u16().await?);
        if length > MAX_HEADER_BYTES {
            return Err(EntryError::TooLarge(length));
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).await?;
        let header: Header =
            serde_json::from_slice(&body).map_err(|e| EntryError::Malformed(e.to_string()))?;
        if header.host.is_empty() || header.host.len() > 253 {
            return Err(EntryError::Malformed("no host".into()));
        }
        Ok(header)
    }
}

/// Writes `answer`.
pub async fn write_answer<W: AsyncWrite + Unpin>(
    writer: &mut W,
    answer: Answer,
) -> Result<(), EntryError> {
    writer.write_all(&answer.encode()).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads the gate's answer.
pub async fn read_answer<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Answer, EntryError> {
    let mut bytes = [0u8; 3];
    reader.read_exact(&mut bytes).await?;
    Answer::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header {
            host: "photos-kasper.grund.run".into(),
            alpn: "h2".into(),
            client: "203.0.113.9:51234".into(),
            tls: Tls {
                version: "TLSv1_3".into(),
                cipher: "TLS13_AES_128_GCM_SHA256".into(),
            },
        }
    }

    #[tokio::test]
    async fn a_header_and_an_answer_survive_the_wire() {
        let bytes = header().encode().unwrap();
        let mut reader = bytes.as_slice();
        assert_eq!(Header::read(&mut reader).await.unwrap(), header());
        for answer in [
            Answer::Accept { ready: 513 },
            Answer::NoReadyCopy,
            Answer::NotPlacedHere,
            Answer::Draining,
        ] {
            let mut out = Vec::new();
            write_answer(&mut out, answer).await.unwrap();
            assert_eq!(read_answer(&mut out.as_slice()).await.unwrap(), answer);
        }
    }

    #[tokio::test]
    async fn an_oversized_empty_or_garbled_header_and_an_unknown_answer_are_refused() {
        let mut long = header();
        long.host = "a".repeat(MAX_HEADER_BYTES);
        assert!(matches!(long.encode(), Err(EntryError::TooLarge(_))));
        let mut claimed = (MAX_HEADER_BYTES as u16 + 1).to_be_bytes().to_vec();
        claimed.extend_from_slice(&[0; 8]);
        assert!(matches!(
            Header::read(&mut claimed.as_slice()).await,
            Err(EntryError::TooLarge(_))
        ));
        let mut garbled = 3u16.to_be_bytes().to_vec();
        garbled.extend_from_slice(b"{x}");
        assert!(matches!(
            Header::read(&mut garbled.as_slice()).await,
            Err(EntryError::Malformed(_))
        ));
        let mut empty = header();
        empty.host.clear();
        let bytes = empty.encode().unwrap();
        assert!(Header::read(&mut bytes.as_slice()).await.is_err());
        assert!(matches!(
            Answer::decode([9, 0, 0]),
            Err(EntryError::UnknownAnswer(9))
        ));
    }
}
