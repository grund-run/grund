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
//! Its certificate comes from [`RelayTls`]: files, or its instance
//! (`Instance`, grund-docs design/traffic.md §5.7). For the latter the relay
//! enrolls its own key with the instance once
//! (GRUND_RELAY_ENROLLMENT_TOKEN), makes its certificate key and a CSR in
//! GRUND_RELAY_DATA_DIR, answers the CA's TLS-ALPN-01 on its own listener
//! and renews when the instance asks ([`crate::relay_certificate`]).

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{Router, http::StatusCode, routing::get};
use clap::Args;
use grund_net::relay::Relay;
use notmad::{Component, ComponentInfo, MadError};
use tokio_util::sync::CancellationToken;

use crate::{
    relay::{Callout, KeyPolicy, RelayAccess, sweep},
    relay_certificate::{CertificateClient, Instance, RelayKey},
};

/// Where a relay's TLS certificate comes from. The relay and its address
/// discovery use the same one.
#[derive(Debug, Clone)]
pub enum RelayTls {
    /// A certificate chain and its key, PEM files, read at start.
    Files { cert: PathBuf, key: PathBuf },
    /// A certificate its instance orders for it, served as it is renewed,
    /// with the CA's TLS-ALPN-01 answered from `answers`. Beside `grund
    /// serve` this is the instance's own resolver and nothing is answered
    /// here: the instance's HTTPS answers for both names.
    Instance(crate::relay_certificate::InstanceTls),
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
            RelayTls::Instance(tls) => tls.server_config(),
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
    /// self-signed one. Unset: the instance orders the relay's certificate
    /// (the relay must be enrolled).
    #[arg(long, env = "GRUND_RELAY_TLS_CERT_FILE")]
    pub tls_cert_file: Option<PathBuf>,

    /// The private key of --tls-cert-file (PEM).
    #[arg(long, env = "GRUND_RELAY_TLS_KEY_FILE")]
    pub tls_key_file: Option<PathBuf>,

    /// Where the relay keeps its own key, its enrollment and its certificate
    /// (each file 0600). The default is inside the image's /var/lib/grund,
    /// which belongs to the image's user, so a volume there is writable.
    #[arg(
        long,
        env = "GRUND_RELAY_DATA_DIR",
        default_value = "/var/lib/grund/relay"
    )]
    pub data_dir: PathBuf,

    /// A one-time grund_relay_ token from `grund relays token <host>` on the
    /// instance: the relay enrolls its key with it at its first start, and
    /// ignores it once enrolled.
    #[arg(long, env = "GRUND_RELAY_ENROLLMENT_TOKEN", hide_env_values = true)]
    pub enrollment_token: Option<String>,

    /// The instance whose machines this relay serves, e.g.
    /// https://grund.example.com. Plain http only for loopback.
    #[arg(long = "grund-url", env = "GRUND_URL")]
    pub grund_url: String,

    /// The instance's GRUND_RELAY_ACCESS_TOKEN, presented when the relay
    /// asks which keys to admit. Deprecated: an enrolled relay signs that
    /// question with its own key instead, and needs no shared token.
    #[arg(long, env = "GRUND_RELAY_ACCESS_TOKEN", hide_env_values = true)]
    pub access_token: Option<String>,

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
        if let Some(token) = &self.access_token {
            anyhow::ensure!(
                token.len() >= 32,
                "GRUND_RELAY_ACCESS_TOKEN must be at least 32 characters"
            );
        }
        anyhow::ensure!(
            self.tls_cert_file.is_some() == self.tls_key_file.is_some(),
            "GRUND_RELAY_TLS_CERT_FILE and GRUND_RELAY_TLS_KEY_FILE must be set together"
        );
        if let Some(token) = &self.enrollment_token {
            anyhow::ensure!(
                token.starts_with(crate::services::relays::TOKEN_PREFIX),
                "GRUND_RELAY_ENROLLMENT_TOKEN must be a grund_relay_ token from `grund relays \
                 token <host>`"
            );
        }
        anyhow::ensure!(
            !self.sweep.is_zero(),
            "GRUND_RELAY_SWEEP_SECONDS must be at least 1"
        );
        Ok(())
    }

    /// The instance's origin, as the relay enrolls with it.
    pub fn instance(&self) -> String {
        crate::config::PublicOrigin::parse(self.grund_url.trim_end_matches('/'))
            .map(|origin| origin.serialized)
            .unwrap_or_else(|| self.grund_url.trim_end_matches('/').to_string())
    }

    /// The relay's enrollment: the one in GRUND_RELAY_DATA_DIR, or a new one
    /// made with GRUND_RELAY_ENROLLMENT_TOKEN. None when it has neither and
    /// does not need one (files and the shared token). Refuses to start,
    /// naming the variable, when it needs one and cannot get it.
    pub async fn enrollment(&self) -> anyhow::Result<Option<RelayKey>> {
        let instance = self.instance();
        if let Some(key) = RelayKey::load(&self.data_dir).with_context(|| {
            format!(
                "the relay's enrollment in GRUND_RELAY_DATA_DIR {}",
                self.data_dir.display()
            )
        })? {
            anyhow::ensure!(
                key.instance == instance,
                "the relay in GRUND_RELAY_DATA_DIR {} is enrolled with {}, not GRUND_URL {instance}; \
                 give it a new data directory to enroll with this one",
                self.data_dir.display(),
                key.instance
            );
            if self.enrollment_token.is_some() {
                tracing::info!(relay_id = %key.relay_id, "relay: enrolled already; GRUND_RELAY_ENROLLMENT_TOKEN is not used");
            }
            return Ok(Some(key));
        }
        let Some(token) = &self.enrollment_token else {
            anyhow::ensure!(
                self.tls_cert_file.is_some() && self.access_token.is_some(),
                "the relay is not enrolled with its instance: set GRUND_RELAY_ENROLLMENT_TOKEN (from \
                 `grund relays token <host>` on the instance), or give it GRUND_RELAY_TLS_CERT_FILE \
                 and the deprecated GRUND_RELAY_ACCESS_TOKEN"
            );
            return Ok(None);
        };
        let http =
            crate::relay_certificate::http_client(Some(crate::relay_certificate::CALL_TIMEOUT))?;
        let key = RelayKey::enroll(&self.data_dir, &instance, token, &http)
            .await
            .context("GRUND_RELAY_ENROLLMENT_TOKEN: the instance did not enroll this relay")?;
        tracing::info!(relay_id = %key.relay_id, host = %key.host, "relay: enrolled with the instance");
        Ok(Some(key))
    }

    /// Where the certificate comes from: the files, or the instance.
    pub fn tls(&self) -> RelayTls {
        match (&self.tls_cert_file, &self.tls_key_file) {
            (Some(cert), Some(key)) => RelayTls::Files {
                cert: cert.clone(),
                key: key.clone(),
            },
            _ => RelayTls::Instance(Default::default()),
        }
    }
}

/// Runs `grund relay` until SIGTERM or SIGINT.
pub async fn run(command: RelayCommand) -> anyhow::Result<()> {
    command.validate()?;
    let enrollment = command.enrollment().await?;
    let relay_tls = command.tls();
    let tls = relay_tls.server_config()?;
    let policy = match &enrollment {
        Some(key) => Callout::signed(&command.grund_url, key.clone())?,
        None => Callout::new(
            &command.grund_url,
            command.access_token.as_deref().unwrap_or_default(),
        )?,
    };
    let grace = command.shutdown_grace;
    let mut mad = notmad::Mad::builder();
    mad.add(StandaloneRelay {
        command: command.clone(),
        tls,
        policy,
    });
    if let (RelayTls::Instance(instance_tls), Some(key)) = (relay_tls, enrollment) {
        mad.add(CertificateClient::new(
            Instance::new(key)?,
            instance_tls,
            &command.data_dir,
        ));
    }
    mad.cancellation(Some(grace)).run().await?;
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
        let access = RelayAccess::remembering(
            self.policy.clone(),
            crate::relay::Remembered::in_file(self.command.data_dir.join("admitted-keys.json")),
        );
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
        assert!(matches!(relay.tls(), RelayTls::Files { .. }));
        assert!(parse(&["--access-token", TOKEN]).is_err());
    }

    #[test]
    fn without_certificate_files_the_instance_orders_the_relays_certificate() {
        let relay = parse(&["--grund-url", "https://grund.example.com/"]).unwrap();
        relay.validate().unwrap();
        assert!(matches!(relay.tls(), RelayTls::Instance(_)));
        assert_eq!(relay.instance(), "https://grund.example.com");
        assert_eq!(relay.data_dir, PathBuf::from("/var/lib/grund/relay"));
        let half = parse(&[
            "--grund-url",
            "https://grund.example.com",
            "--tls-cert-file",
            "c.pem",
        ])
        .unwrap();
        assert!(half.validate().is_err());
        let not_a_token = parse(&[
            "--grund-url",
            "https://grund.example.com",
            "--enrollment-token",
            "grund_join_abc",
        ])
        .unwrap();
        let error = not_a_token.validate().unwrap_err().to_string();
        assert!(error.contains("GRUND_RELAY_ENROLLMENT_TOKEN"), "{error}");
        assert!(
            !error.contains("grund_join_abc"),
            "the token is never echoed"
        );
    }

    #[tokio::test]
    async fn a_relay_that_is_not_enrolled_and_has_no_token_is_refused_naming_it() {
        let dir =
            std::env::temp_dir().join(format!("grund-relay-cmd-{}", uuid::Uuid::now_v7().simple()));
        let relay = parse(&[
            "--grund-url",
            "https://grund.example.com",
            "--data-dir",
            dir.to_str().unwrap(),
        ])
        .unwrap();
        let error = format!("{:#}", relay.enrollment().await.unwrap_err());
        assert!(error.contains("GRUND_RELAY_ENROLLMENT_TOKEN"), "{error}");
        let legacy = parse(&[
            "--grund-url",
            "https://grund.example.com",
            "--data-dir",
            dir.to_str().unwrap(),
            "--tls-cert-file",
            "c.pem",
            "--tls-key-file",
            "k.pem",
            "--access-token",
            TOKEN,
        ])
        .unwrap();
        assert!(legacy.enrollment().await.unwrap().is_none());
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
