//! The instance's Connect API over HTTP, with Connect's JSON codec: every
//! request and answer is protobuf JSON, so what the CLI prints with
//! `--output json` is what the instance sent.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde_json::Value;

use crate::error::{CliError, CliResult, Code};

/// Where Linux and macOS keep their trusted certificate authorities.
pub const SYSTEM_ROOTS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// A client for one instance, with one credential or none.
#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    origin: String,
    credential: Option<String>,
}

impl Api {
    /// A client for `origin` (already normalised), presenting `credential`
    /// as `Authorization: Bearer` when given.
    pub fn new(origin: &str, credential: Option<String>) -> CliResult<Self> {
        grund_tls::install_default();
        let builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("grund-cli/", env!("CARGO_PKG_VERSION")));
        let system = std::env::var_os("SSL_CERT_FILE").is_some()
            || SYSTEM_ROOTS
                .iter()
                .any(|path| std::fs::metadata(path).is_ok_and(|m| m.len() > 0));
        let builder = if system {
            builder
        } else {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = grund_tls::client_config(roots)
                .map_err(|e| CliError::new(Code::Failed, format!("TLS setup: {e:#}")))?;
            builder.use_preconfigured_tls(config)
        };
        let http = builder
            .build()
            .map_err(|e| CliError::new(Code::Failed, format!("HTTP client: {e}")))?;
        Ok(Api {
            http,
            origin: origin.to_string(),
            credential,
        })
    }

    /// The instance's origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Calls `rpc` (`package.Service/Method`) with a protobuf JSON request.
    pub async fn call(&self, rpc: &str, request: Value) -> CliResult<Value> {
        let mut builder = self
            .http
            .post(format!("{}/{rpc}", self.origin))
            .header("Content-Type", "application/json")
            .header("Connect-Protocol-Version", "1")
            .header("Connect-Timeout-Ms", "55000")
            .body(request.to_string());
        if let Some(credential) = &self.credential {
            builder = builder.bearer_auth(credential);
        }
        let response = builder.send().await.map_err(|e| {
            CliError::new(
                Code::Unavailable,
                format!("could not reach {}: {}", self.origin, root_cause(&e)),
            )
            .hint("check the address (GRUND_INSTANCE) and the network")
            .with_rpc(rpc)
        })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|e| {
            CliError::new(Code::Unavailable, format!("the answer broke off: {e}")).with_rpc(rpc)
        })?;
        if status.is_success() {
            if bytes.is_empty() {
                return Ok(Value::Object(Default::default()));
            }
            return serde_json::from_slice(&bytes).map_err(|_| {
                CliError::new(
                    Code::Failed,
                    format!("{} answered something that is not JSON", self.origin),
                )
                .hint("is this the address of a grund instance?")
                .with_rpc(rpc)
            });
        }
        Err(refusal(rpc, status.as_u16(), &bytes))
    }
}

fn root_cause(error: &(dyn std::error::Error + 'static)) -> String {
    let mut cause = error;
    while let Some(source) = cause.source() {
        cause = source;
    }
    cause.to_string()
}

impl CliError {
    fn with_rpc(mut self, rpc: &str) -> Self {
        self.rpc = rpc.to_string();
        self
    }
}

/// The CLI error a Connect error answer stands for.
pub fn refusal(rpc: &str, status: u16, body: &[u8]) -> CliError {
    let Ok(error) = serde_json::from_slice::<Value>(body) else {
        return CliError::new(
            if status >= 500 {
                Code::Unavailable
            } else {
                Code::Failed
            },
            format!("the instance answered HTTP {status} without a Connect error"),
        )
        .hint("is this the address of a grund instance?")
        .with_rpc(rpc);
    };
    let connect = error["code"].as_str().unwrap_or("unknown");
    let message = error["message"].as_str().unwrap_or(connect).to_string();
    let reason = error["details"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|d| {
            d["type"]
                .as_str()
                .is_some_and(|t| t.ends_with(".ErrorReason"))
        })
        .find_map(|d| d["value"].as_str().and_then(reason_of))
        .unwrap_or_default();
    let code = match connect {
        "unauthenticated" => Code::Unauthenticated,
        "permission_denied" => Code::PermissionDenied,
        "not_found" => Code::NotFound,
        "already_exists" | "failed_precondition" | "aborted" => Code::Conflict,
        "invalid_argument" | "out_of_range" => Code::Invalid,
        "unavailable" | "deadline_exceeded" | "resource_exhausted" => Code::Unavailable,
        _ => Code::Failed,
    };
    let hint = match code {
        Code::Unauthenticated => "run grund login, or set GRUND_TOKEN to a live token",
        Code::PermissionDenied if message.contains("token") => {
            "a token of scope deploy reaches apps only; sign in with grund login or use a token of scope full"
        }
        _ => "",
    };
    let mut error = CliError::new(code, message).hint(hint).with_rpc(rpc);
    error.reason = reason;
    error
}

fn reason_of(value: &str) -> Option<String> {
    let bytes = STANDARD_NO_PAD.decode(value.trim_end_matches('=')).ok()?;
    let mut rest = bytes.as_slice();
    while let Some((&tag, after)) = rest.split_first() {
        let (length, after) = varint(after)?;
        let length = usize::try_from(length).ok()?;
        if tag == 0x0a {
            return String::from_utf8(after.get(..length)?.to_vec()).ok();
        }
        if tag & 0x07 != 2 {
            return None;
        }
        rest = after.get(length..)?;
    }
    None
}

fn varint(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    for (i, byte) in bytes.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, &bytes[i + 1..]));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connect_error_becomes_a_code_with_its_reason() {
        let reason = STANDARD_NO_PAD.encode([
            0x0a, 0x0a, b'n', b'a', b'm', b'e', b'_', b't', b'a', b'k', b'e', b'n',
        ]);
        let body = serde_json::json!({
            "code": "failed_precondition",
            "message": "an app has that name",
            "details": [{"type": "grund.app.v1.ErrorReason", "value": reason}],
        });
        let error = refusal(
            "grund.app.v1.AppService/CreateApp",
            400,
            body.to_string().as_bytes(),
        );
        assert_eq!(error.code, Code::Conflict);
        assert_eq!(error.reason, "name_taken");
        assert_eq!(error.rpc, "grund.app.v1.AppService/CreateApp");
    }

    #[test]
    fn an_answer_that_is_not_connect_says_so() {
        let error = refusal("x/y", 502, b"<html>bad gateway</html>");
        assert_eq!(error.code, Code::Unavailable);
        assert!(error.hint.contains("grund instance"));
    }
}
