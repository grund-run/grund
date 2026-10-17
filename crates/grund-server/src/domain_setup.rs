//! Fresh DNS observations and pinned edge probes, independently of ACME orders.

use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use grund_store::{
    certificates,
    domain_setup::{self as store, Step, StepState},
};
use hickory_resolver::{
    Resolver,
    config::{ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use notmad::{Component, ComponentInfo, MadError};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::state::State;

/// DNS work is bounded independently of the resolver's own retransmissions.
pub const DNS_DEADLINE: Duration = Duration::from_secs(5);
/// Each fixed-port edge request, including its response, gets this budget.
pub const PROBE_DEADLINE: Duration = Duration::from_secs(4);
/// A setup attempt finishes before its thirty-second database lease expires.
pub const ATTEMPT_DEADLINE: Duration = Duration::from_secs(25);
/// A domain with more addresses is refused instead of creating unbounded work.
pub const MAX_ADDRESSES: usize = 16;
/// Independent checker slots, so one slow domain does not stop other checks.
pub const CHECKERS: usize = 16;

struct Dns {
    addresses: BTreeSet<IpAddr>,
    expected: BTreeSet<IpAddr>,
    aliases: BTreeSet<String>,
}

fn resolver(server: Option<SocketAddr>) -> anyhow::Result<Resolver<TokioRuntimeProvider>> {
    let builder = match server {
        Some(server) => {
            let connection = |mut config: ConnectionConfig| {
                config.port = server.port();
                config
            };
            let name_server = NameServerConfig::new(
                server.ip(),
                true,
                vec![
                    connection(ConnectionConfig::udp()),
                    connection(ConnectionConfig::tcp()),
                ],
            );
            Resolver::builder_with_config(
                ResolverConfig::from_name_servers(vec![name_server]),
                TokioRuntimeProvider::default(),
            )
        }
        None => Resolver::builder_tokio()?,
    };
    let mut builder = builder;
    builder.options_mut().cache_size = 0;
    builder.options_mut().use_hosts_file = ResolveHosts::Never;
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    builder.options_mut().timeout = Duration::from_secs(2);
    Ok(builder.build()?)
}

async fn dns(state: &State, name: &str) -> anyhow::Result<Dns> {
    let resolver = resolver(state.config.entry.dns_resolver)?;
    let domain = resolver.lookup_ip(format!("{name}."));
    let mut queries = futures_util::stream::FuturesUnordered::new();
    for edge in &state.config.entry.edges {
        queries.push(resolver.lookup_ip(format!("{edge}.")));
    }
    let edges = async move {
        let mut addresses = BTreeSet::new();
        while let Some(answer) = queries.next().await {
            if let Ok(answer) = answer {
                addresses.extend(answer);
            }
        }
        addresses
    };
    let (domain, expected) = tokio::join!(domain, edges);
    let domain = domain.context("the domain did not resolve")?;
    let addresses = domain.iter().collect();
    let aliases = domain
        .as_lookup()
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::CNAME(alias) => Some(alias.to_string()),
            _ => None,
        })
        .collect();
    Ok(Dns {
        addresses,
        expected,
        aliases,
    })
}

fn matches_edges(addresses: &BTreeSet<IpAddr>, expected: &BTreeSet<IpAddr>) -> bool {
    !addresses.is_empty() && addresses.len() <= MAX_ADDRESSES && addresses.is_subset(expected)
}

fn observation(claim: &store::Claim, name: &str, state: StepState, detail: String) -> Step {
    Step {
        name: name.into(),
        state,
        detail,
        checked_at: (state != StepState::Waiting).then(chrono::Utc::now),
        next_retry_at: Some(claim.next_check_at),
    }
}

fn pinned_client(name: &str, address: SocketAddr) -> reqwest::ClientBuilder {
    grund_tls::install_default();
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROBE_DEADLINE)
        .connect_timeout(Duration::from_secs(2))
        .resolve(name, address)
}

fn client(
    name: &str,
    address: IpAddr,
    https: bool,
    roots: &[reqwest::Certificate],
) -> anyhow::Result<reqwest::Client> {
    Ok(
        pinned_client(name, SocketAddr::new(address, if https { 443 } else { 80 }))
            .tls_certs_merge(roots.iter().cloned())
            .build()?,
    )
}

async fn http_probe(
    client: &reqwest::Client,
    name: &str,
    token: &str,
    value: &str,
) -> anyhow::Result<()> {
    let mut response = client
        .get(format!("http://{name}/.well-known/acme-challenge/{token}"))
        .send()
        .await?;
    anyhow::ensure!(
        response.status() == reqwest::StatusCode::OK,
        "the edge did not return the probe"
    );
    let mut received = 0;
    while let Some(chunk) = response.chunk().await? {
        let end = received + chunk.len();
        anyhow::ensure!(
            value.as_bytes().get(received..end) == Some(chunk.as_ref()),
            "the edge returned a different probe value"
        );
        received = end;
    }
    anyhow::ensure!(
        received == value.len(),
        "the edge returned a different probe value"
    );
    Ok(())
}

async fn https_probe(client: &reqwest::Client, name: &str) -> anyhow::Result<()> {
    client.head(format!("https://{name}/")).send().await?;
    Ok(())
}

async fn observe(
    state: &State,
    claim: &store::Claim,
    holder: Uuid,
    steps: &mut [Step; 3],
) -> anyhow::Result<()> {
    let resolved = match tokio::time::timeout(DNS_DEADLINE, dns(state, &claim.name)).await {
        Ok(Ok(resolved)) => resolved,
        _ => return Ok(()),
    };
    let ready = matches_edges(&resolved.addresses, &resolved.expected);
    let addresses = resolved
        .addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let aliases = resolved.aliases.into_iter().collect::<Vec<_>>().join(", ");
    let expected = resolved
        .expected
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    steps[0] = observation(
        claim,
        "dns_record",
        if ready {
            StepState::Done
        } else {
            StepState::Failed
        },
        format!(
            "Addresses: {}. CNAME: {}. Configured edge addresses: {}.{}",
            if addresses.is_empty() {
                "none"
            } else {
                &addresses
            },
            if aliases.is_empty() {
                "none observed"
            } else {
                &aliases
            },
            if expected.is_empty() {
                "none resolved"
            } else {
                &expected
            },
            if resolved.addresses.len() > MAX_ADDRESSES {
                " More than 16 addresses; no probes sent."
            } else if ready {
                " All observed addresses match."
            } else {
                " Not all observed addresses match."
            }
        ),
    );
    if !ready {
        return Ok(());
    }
    steps[1] = observation(
        claim,
        "edge_reachable",
        StepState::Failed,
        "The temporary HTTP challenge check did not complete.".into(),
    );
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)?;
    let token = URL_SAFE_NO_PAD.encode(random);
    getrandom::fill(&mut random)?;
    let value = URL_SAFE_NO_PAD.encode(random);
    if !store::put_probe(&state.pool, claim, holder, &token, &value).await? {
        return Ok(());
    }
    let mut addresses = resolved.addresses.iter().copied();
    let mut reachable = true;
    loop {
        let mut probes = futures_util::stream::FuturesUnordered::new();
        for address in addresses.by_ref().take(8) {
            let name = &claim.name;
            let token = &token;
            let value = &value;
            probes.push(async move {
                let client = client(name, address, false, &[])?;
                http_probe(&client, name, token, value).await
            });
        }
        if probes.is_empty() {
            break;
        }
        while let Some(result) = probes.next().await {
            reachable &= result.is_ok();
        }
    }
    certificates::remove_challenge(
        &state.pool,
        certificates::Challenge::Http01,
        &claim.name,
        &token,
    )
    .await?;
    steps[1] = observation(
        claim,
        "edge_reachable",
        if reachable {
            StepState::Done
        } else {
            StepState::Failed
        },
        if reachable {
            "Every observed edge address returned the exact temporary HTTP challenge on port 80."
        } else {
            "An observed edge address did not return the exact temporary HTTP challenge on port 80."
        }
        .into(),
    );
    if !reachable {
        return Ok(());
    }
    steps[2] = observation(
        claim,
        "serving_https",
        StepState::Failed,
        "The verified HTTPS check did not complete.".into(),
    );
    let roots = if let Some(path) = &state.config.tls.acme_ca_file {
        let pem = tokio::fs::read(path)
            .await
            .context("read GRUND_ACME_CA_FILE")?;
        let roots = reqwest::Certificate::from_pem_bundle(&pem)?;
        anyhow::ensure!(!roots.is_empty(), "GRUND_ACME_CA_FILE has no certificates");
        roots
    } else {
        Vec::new()
    };
    let roots = &roots;
    let mut addresses = resolved.addresses.iter().copied();
    let mut serving = true;
    loop {
        let mut probes = futures_util::stream::FuturesUnordered::new();
        for address in addresses.by_ref().take(8) {
            let name = &claim.name;
            probes.push(async move {
                let client = client(name, address, true, roots)?;
                https_probe(&client, name).await
            });
        }
        if probes.is_empty() {
            break;
        }
        while let Some(result) = probes.next().await {
            serving &= result.is_ok();
        }
    }
    steps[2] = observation(claim, "serving_https", if serving { StepState::Done } else { StepState::Failed },
        if serving { "Every observed edge address completed HTTPS with a verified certificate for this hostname on port 443." }
        else { "An observed edge address did not complete HTTPS with a verified certificate for this hostname on port 443." }.into());
    Ok(())
}

/// Runs the durable checker once, including a bounded attempt and fenced write.
/// A timeout is itself an observation, never a permanent failure of the worker.
pub async fn work_once(state: &State) -> anyhow::Result<bool> {
    let holder = Uuid::now_v7();
    let Some(claim) = store::claim(&state.pool, holder).await? else {
        return Ok(false);
    };
    let mut observations = [
        observation(
            &claim,
            "dns_record",
            StepState::Failed,
            "The DNS lookup did not complete.".into(),
        ),
        observation(
            &claim,
            "edge_reachable",
            StepState::Waiting,
            "Waiting for the domain to point at a configured edge.".into(),
        ),
        observation(
            &claim,
            "serving_https",
            StepState::Waiting,
            "Waiting for an edge reachability check.".into(),
        ),
    ];
    let failure = match tokio::time::timeout(
        ATTEMPT_DEADLINE,
        observe(state, &claim, holder, &mut observations),
    )
    .await
    {
        Ok(Ok(())) => None,
        Ok(Err(error)) => {
            tracing::warn!(domain_id = %claim.domain_id, error = %error, "domains: setup check failed; retrying");
            Some("The setup check could not finish.")
        }
        Err(_) => Some("The setup check exceeded its 25-second deadline."),
    };
    if let Some(detail) = failure
        && let Some(step) = observations
            .iter_mut()
            .find(|step| step.state == StepState::Failed)
    {
        step.detail = detail.into();
        step.checked_at = Some(chrono::Utc::now());
    }
    store::finish(&state.pool, &claim, holder, &observations).await?;
    Ok(true)
}

/// Separate checker slots keep DNS observations independent of long CA orders.
pub struct DomainSetup {
    state: State,
}

impl DomainSetup {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

impl Component for DomainSetup {
    fn info(&self) -> ComponentInfo {
        "grund/domain-setup".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let mut workers = tokio::task::JoinSet::new();
        for _ in 0..CHECKERS {
            let state = self.state.clone();
            let cancellation = cancellation.clone();
            workers.spawn(async move {
                loop {
                    tokio::select! {
                        () = cancellation.cancelled() => return,
                        result = work_once(&state) => match result {
                            Ok(true) => continue,
                            Ok(false) => {},
                            Err(error) => tracing::warn!(error = %error, "domains: checker failed; retrying"),
                        }
                    }
                    tokio::select! {
                        () = cancellation.cancelled() => return,
                        () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }
            });
        }
        cancellation.cancelled().await;
        workers.abort_all();
        while workers.join_next().await.is_some() {}
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_cannot_add_destinations_to_the_configured_edge_allowlist() {
        let edge = "192.0.2.10".parse().unwrap();
        let other = "192.0.2.11".parse().unwrap();
        let expected = BTreeSet::from([edge]);
        assert!(matches_edges(&BTreeSet::from([edge]), &expected));
        assert!(!matches_edges(&BTreeSet::from([edge, other]), &expected));
        assert!(!matches_edges(
            &BTreeSet::from(["127.0.0.1".parse().unwrap()]),
            &expected
        ));
        assert!(!matches_edges(&BTreeSet::new(), &expected));
        assert!(!matches_edges(&BTreeSet::from([edge]), &BTreeSet::new()));
    }

    async fn http_response(
        response: &'static str,
    ) -> (reqwest::Client, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let mut length = 0;
            while !request[..length].windows(4).any(|part| part == b"\r\n\r\n") {
                assert!(length < request.len());
                let read = socket.read(&mut request[length..]).await.unwrap();
                assert_ne!(read, 0);
                length += read;
            }
            assert!(
                request[..length].starts_with(b"GET /.well-known/acme-challenge/token HTTP/1.1")
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        (
            pinned_client("probe.example.com", address).build().unwrap(),
            server,
        )
    }

    #[tokio::test]
    async fn edge_reachability_requires_the_exact_probe_and_never_follows_redirects() {
        for (response, expected) in [
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret",
                true,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nwrong",
                false,
            ),
            (
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
        ] {
            let (client, server) = http_response(response).await;
            assert_eq!(
                http_probe(&client, "probe.example.com", "token", "secret")
                    .await
                    .is_ok(),
                expected
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn https_requires_a_trusted_chain_and_the_domain_hostname_even_with_a_pinned_ip() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        grund_tls::install_default();
        let certificate =
            rcgen::generate_simple_self_signed(vec!["probe.example.com".into()]).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    certificate.signing_key.serialize_der(),
                )
                .into(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let Ok(mut socket) = acceptor.accept(socket).await else {
                    continue;
                };
                let mut request = [0u8; 4096];
                if socket.read(&mut request).await.is_ok() {
                    let _ = socket
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await;
                }
            }
        });
        let root = reqwest::Certificate::from_der(certificate.cert.der().as_ref()).unwrap();
        let untrusted = pinned_client("probe.example.com", address).build().unwrap();
        assert!(https_probe(&untrusted, "probe.example.com").await.is_err());
        let trusted = pinned_client("probe.example.com", address)
            .tls_certs_merge([root.clone()])
            .build()
            .unwrap();
        assert!(https_probe(&trusted, "probe.example.com").await.is_ok());
        let wrong_name = pinned_client("wrong.example.com", address)
            .tls_certs_merge([root])
            .build()
            .unwrap();
        assert!(https_probe(&wrong_name, "wrong.example.com").await.is_err());
        server.abort();
    }
}
