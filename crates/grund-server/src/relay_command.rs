//! `grund relay`: a relay for an instance's machines, on a host of its own
//! (grund-docs design/network.md §10.1, §14 grund item 3).
//!
//! It is iroh-relay's server behind its own TLS certificate, with QUIC
//! address discovery on UDP 7842, and nothing else. It keeps no state: it
//! asks its instance which keys to admit ([`crate::relay::Callout`]), so any
//! number of them can run in any number of places. The instance lists them
//! in GRUND_RELAYS, and machines learn of them from their signed membership
//! list.
//!
//! It must see machines' own addresses: address discovery tells each
//! machine the public address and port its packets came from, and hole
//! punching starts from that answer. So it runs on a host with a public
//! address and nothing that rewrites the source of UDP 7842 in front of it.
//!
//! Its certificate comes from [`RelayTls`]: files today; a certificate the
//! instance obtains for it later (grund-tls), as another variant.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{Router, http::StatusCode, routing::get};
use clap::Args;
use grund_net::relay::Relay;
use notmad::{Component, ComponentInfo, MadError};
use tokio_util::sync::CancellationToken;

use crate::relay::{Callout, KeyPolicy, RelayAccess, sweep};

/// Where a relay's TLS certificate comes from. The relay and its address
/// discovery use the same one.
#[derive(Debug, Clone)]
pub enum RelayTls {
    /// A certificate chain and its key, PEM files, read at start.
    Files { cert: PathBuf, key: PathBuf },
}

impl RelayTls {
    /// The TLS server configuration for the relay's listener and its QUIC
    /// address discovery.
    pub fn server_config(&self) -> anyhow::Result<rustls::ServerConfig> {
        match self {
            RelayTls::Files { cert, key } => grund_net::relay::tls_from_pem(
                &std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?,
                &std::fs::read(key).with_context(|| format!("read {}", key.display()))?,
            )
            .context("the relay's certificate"),
        }
    }
}

/// `grund relay`.
#[derive(Clone, Debug, Args)]
pub struct RelayCommand {
    /// Where the relay listens (TCP, HTTPS): machines' relay connections,
    /// and /ping, /health/live and /health/ready.
    #[arg(long, env = "GRUND_RELAY_LISTEN", default_value = "0.0.0.0:443")]
    pub listen: SocketAddr,

    /// Where QUIC address discovery listens (UDP). Machines ask it at the
    /// relay URL's host, on 7842.
    #[arg(long, env = "GRUND_RELAY_QUIC_LISTEN", default_value = "0.0.0.0:7842")]
    pub quic_listen: SocketAddr,

    /// The relay's certificate chain (PEM), for the name machines reach it
    /// by. It must chain to a CA the machines trust: iroh refuses a
    /// self-signed one.
    #[arg(long, env = "GRUND_RELAY_TLS_CERT_FILE")]
    pub tls_cert_file: PathBuf,

    /// The private key of --tls-cert-file (PEM).
    #[arg(long, env = "GRUND_RELAY_TLS_KEY_FILE")]
    pub tls_key_file: PathBuf,

    /// The instance whose machines this relay serves, e.g.
    /// https://grund.example.com. Plain http only for loopback.
    #[arg(long = "grund-url", env = "GRUND_URL")]
    pub grund_url: String,

    /// The instance's GRUND_RELAY_ACCESS_TOKEN, presented when the relay
    /// asks which keys to admit.
    #[arg(long, env = "GRUND_RELAY_ACCESS_TOKEN", hide_env_values = true)]
    pub access_token: String,

    /// Seconds between checks of every connected key, which cut a revoked
    /// machine's open connection.
    #[arg(long, env = "GRUND_RELAY_SWEEP_SECONDS", value_parser = secs, default_value = "2")]
    pub sweep: Duration,

    /// Seconds to finish open work on SIGTERM.
    #[arg(long, env = "GRUND_SHUTDOWN_GRACE", value_parser = secs, default_value = "10")]
    pub shutdown_grace: Duration,
}

fn secs(input: &str) -> Result<Duration, String> {
    input
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|e| e.to_string())
}

impl RelayCommand {
    /// Refuses a configuration that cannot work, naming what to fix.
    pub fn validate(&self) -> anyhow::Result<()> {
        let origin = crate::config::PublicOrigin::parse(self.grund_url.trim_end_matches('/'))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "GRUND_URL must be the instance's origin, like https://grund.example.com"
                )
            })?;
        anyhow::ensure!(
            origin.https || origin.is_loopback(),
            "GRUND_URL must be https, except on loopback: the relay sends its access token there"
        );
        anyhow::ensure!(
            self.access_token.len() >= 32,
            "GRUND_RELAY_ACCESS_TOKEN must be at least 32 characters"
        );
        anyhow::ensure!(
            !self.sweep.is_zero(),
            "GRUND_RELAY_SWEEP_SECONDS must be at least 1"
        );
        Ok(())
    }

    /// Where the certificate comes from.
    pub fn tls(&self) -> RelayTls {
        RelayTls::Files {
            cert: self.tls_cert_file.clone(),
            key: self.tls_key_file.clone(),
        }
    }
}

/// Runs `grund relay` until SIGTERM or SIGINT.
pub async fn run(command: RelayCommand) -> anyhow::Result<()> {
    command.validate()?;
    let tls = command.tls().server_config()?;
    let policy = Callout::new(&command.grund_url, &command.access_token)?;
    let grace = command.shutdown_grace;
    notmad::Mad::builder()
        .add(StandaloneRelay {
            command,
            tls,
            policy,
        })
        .cancellation(Some(grace))
        .run()
        .await?;
    Ok(())
}

struct StandaloneRelay {
    command: RelayCommand,
    tls: rustls::ServerConfig,
    policy: Callout,
}

impl Component for StandaloneRelay {
    fn info(&self) -> ComponentInfo {
        "grund-relay/relay".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let _discovery =
            grund_net::relay::spawn_address_discovery(self.command.quic_listen, self.tls.clone())
                .await?;
        let listener = tokio::net::TcpListener::bind(self.command.listen)
            .await
            .with_context(|| format!("bind the relay on {}", self.command.listen))?;
        tracing::info!(
            listen = %self.command.listen,
            quic = %self.command.quic_listen,
            grund = %self.command.grund_url,
            "relay listening"
        );
        let access = RelayAccess::new(self.policy.clone());
        let relay = Relay::new(access.clone());
        let routes = Relay::probe_routes()
            .route("/health/live", get(|| async { r#"{"status":"ok"}"# }))
            .merge(ready(self.policy.clone()));
        tokio::select! {
            served = grund_net::relay::serve(listener, Some(Arc::new(self.tls.clone())), relay.clone(), routes) => {
                served.map_err(anyhow::Error::from)?;
            }
            () = sweep(&access, &relay, self.command.sweep) => {}
            () = cancellation.cancelled() => {}
        }
        Ok(())
    }
}

fn ready(policy: Callout) -> Router {
    Router::new().route(
        "/health/ready",
        get(move || {
            let policy = policy.clone();
            async move {
                match tokio::time::timeout(Duration::from_secs(2), policy.admitted(&[])).await {
                    Ok(Ok(_)) => (StatusCode::OK, r#"{"status":"ok"}"#),
                    _ => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        r#"{"status":"unavailable","reason":"the instance does not answer the access check"}"#,
                    ),
                }
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        relay: RelayCommand,
    }

    fn parse(args: &[&str]) -> Result<RelayCommand, clap::Error> {
        Cli::try_parse_from(std::iter::once("grund-relay").chain(args.iter().copied()))
            .map(|c| c.relay)
    }

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn the_relay_command_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn a_relay_listens_on_443_and_7842_by_default_and_needs_its_instance_and_certificate() {
        let relay = parse(&[
            "--tls-cert-file",
            "c.pem",
            "--tls-key-file",
            "k.pem",
            "--grund-url",
            "https://grund.example.com",
            "--access-token",
            TOKEN,
        ])
        .unwrap();
        assert_eq!(relay.listen, "0.0.0.0:443".parse().unwrap());
        assert_eq!(relay.quic_listen, "0.0.0.0:7842".parse().unwrap());
        assert_eq!(relay.sweep, Duration::from_secs(2));
        relay.validate().unwrap();
        assert!(parse(&["--grund-url", "https://grund.example.com"]).is_err());
    }

    #[test]
    fn plain_http_to_the_instance_a_short_token_or_a_typo_is_refused() {
        let with = |url: &str, token: &str| {
            parse(&[
                "--tls-cert-file",
                "c.pem",
                "--tls-key-file",
                "k.pem",
                "--grund-url",
                url,
                "--access-token",
                token,
            ])
            .unwrap()
            .validate()
        };
        assert!(with("http://grund.example.com", TOKEN).is_err());
        assert!(with("http://127.0.0.1:8080", TOKEN).is_ok());
        assert!(with("https://grund.example.com", "short").is_err());
        assert!(parse(&["--tls-cert", "c.pem"]).is_err());
    }
}
