//! Firecracker's API over its Unix socket: one request per connection,
//! HTTP/1.1, JSON bodies. Firecracker answers 204 on success and a JSON
//! `fault_message` otherwise.

use std::{path::PathBuf, time::Duration};

use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

/// A refusal or a failure talking to Firecracker.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("firecracker {method} {path}: {status} {fault}")]
    Status {
        method: &'static str,
        path: String,
        status: u16,
        fault: String,
    },
    #[error("firecracker {method} {path}: {source}")]
    Io {
        method: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// A client for one VM's API socket.
#[derive(Debug, Clone)]
pub struct Api {
    socket: PathBuf,
    timeout: Duration,
}

impl Api {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: Duration::from_secs(10),
        }
    }

    pub async fn put(&self, path: &str, body: &Value) -> Result<(), ApiError> {
        self.send("PUT", path, body).await
    }

    pub async fn patch(&self, path: &str, body: &Value) -> Result<(), ApiError> {
        self.send("PATCH", path, body).await
    }

    async fn send(&self, method: &'static str, path: &str, body: &Value) -> Result<(), ApiError> {
        let io = |source| ApiError::Io {
            method,
            path: path.to_string(),
            source,
        };
        let exchange = async {
            let mut stream = UnixStream::connect(&self.socket).await?;
            let body = serde_json::to_vec(body).unwrap_or_default();
            let head = format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(&body).await?;
            let mut raw = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                if let Some(reply) = parse_reply(&raw) {
                    return Ok(reply);
                }
                let n = stream.read(&mut buffer).await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "firecracker closed the connection mid-reply",
                    ));
                }
                raw.extend_from_slice(&buffer[..n]);
            }
        };
        let (status, reply) = tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| io(std::io::Error::from(std::io::ErrorKind::TimedOut)))?
            .map_err(io)?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        let fault = serde_json::from_slice::<Value>(&reply)
            .ok()
            .and_then(|v| v["fault_message"].as_str().map(str::to_string))
            .unwrap_or_else(|| String::from_utf8_lossy(&reply).into_owned());
        Err(ApiError::Status {
            method,
            path: path.to_string(),
            status,
            fault,
        })
    }
}

/// A complete reply's status and body, or `None` until all of it arrived.
/// Firecracker keeps connections open, so the end is found by
/// Content-Length, never by EOF.
pub fn parse_reply(raw: &[u8]) -> Option<(u16, Vec<u8>)> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let body = &raw[end + 4..];
    (body.len() >= length).then(|| (status, body[..length].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_is_complete_only_once_its_body_has_arrived() {
        let raw = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 29\r\n\r\n{\"fault_message\":\"bad field\"}";
        assert_eq!(parse_reply(&raw[..raw.len() - 3]), None);
        let (status, body) = parse_reply(raw).unwrap();
        assert_eq!(status, 400);
        assert!(String::from_utf8(body).unwrap().contains("bad field"));
        assert_eq!(
            parse_reply(b"HTTP/1.1 204 No Content\r\n\r\n"),
            Some((204, vec![]))
        );
    }
}
