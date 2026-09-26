//! `grund-net-lab`: grund-net's pieces as separate commands, for the
//! namespace lab (`crates/grund-net/lab/mesh.sh`) and for trying the mesh by
//! hand before grund agent and grund-server carry it.
//!
//! - `keygen`: a machine key seed and its endpoint id.
//! - `sign`: signs a membership list with a network key.
//! - `lighthouse`: the relay (HTTPS, with a stand-in app route beside it) and
//!   QUIC address discovery, admitting the keys given.
//! - `node`: a machine: its endpoint, and the mesh on a TUN device, with the
//!   signed list read from a file and re-read on SIGHUP. Writes its status as
//!   JSON to a file every second.
//! - `inject`: dials a member over the mesh's ALPN with any key and sends
//!   one hand-made IPv6 packet with the given source and destination, so the
//!   lab can check what the receiver's filter does with a spoofed source or a
//!   non-member, which a well-behaved mesh never sends.

use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, bail};
use axum::{Router, routing::get};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use grund_net::{
    NET_ALPN,
    endpoint::{self, Bind, NetConfig},
    key,
    membership::{MembershipList, SignedList},
    mesh::{Mesh, MeshConfig},
    relay::{self, AllowList, Relay},
};
use iroh::{EndpointId, RelayUrl, protocol::Router as IrohRouter};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tokio::sync::watch;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen,
    Sign {
        #[arg(long)]
        network_key: String,
        #[arg(long)]
        list: PathBuf,
    },
    Lighthouse {
        #[arg(long)]
        https: SocketAddr,
        #[arg(long)]
        qad: SocketAddr,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "allow")]
        allow: Vec<String>,
    },
    Node {
        #[arg(long)]
        key: String,
        #[arg(long)]
        relay: RelayUrl,
        #[arg(long)]
        relay_root: PathBuf,
        #[arg(long)]
        network_pub: String,
        #[arg(long)]
        list: PathBuf,
        #[arg(long, default_value = "grund0")]
        tun: String,
        #[arg(long)]
        bind: Option<SocketAddr>,
        #[arg(long)]
        status: PathBuf,
    },
    Inject {
        #[arg(long)]
        key: String,
        #[arg(long)]
        relay: RelayUrl,
        #[arg(long)]
        relay_root: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        src: std::net::Ipv6Addr,
        #[arg(long)]
        dst: std::net::Ipv6Addr,
        #[arg(long, default_value_t = 5)]
        count: u32,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    match Cli::parse().command {
        Command::Keygen => {
            let mut seed = [0u8; 32];
            getrandom_seed(&mut seed)?;
            let signing = SigningKey::from_bytes(&seed);
            println!(
                "{}",
                serde_json::json!({
                    "seed": hex::encode(seed),
                    "endpoint_id": key::endpoint_id(&seed).to_string(),
                    "public": hex::encode(signing.verifying_key().as_bytes()),
                })
            );
            Ok(())
        }
        Command::Sign { network_key, list } => {
            let list: MembershipList = serde_json::from_slice(&std::fs::read(&list)?)?;
            list.validate()?;
            let signed = SignedList::sign(&list, &SigningKey::from_bytes(&seed(&network_key)?));
            println!("{}", serde_json::to_string(&signed)?);
            Ok(())
        }
        Command::Lighthouse {
            https,
            qad,
            cert,
            key,
            allow,
        } => lighthouse(https, qad, cert, key, allow).await,
        Command::Node {
            key,
            relay,
            relay_root,
            network_pub,
            list,
            tun,
            bind,
            status,
        } => node(key, relay, relay_root, network_pub, list, tun, bind, status).await,
        Command::Inject {
            key,
            relay,
            relay_root,
            to,
            src,
            dst,
            count,
        } => inject(key, relay, relay_root, to, src, dst, count).await,
    }
}

async fn lighthouse(
    https: SocketAddr,
    qad: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    allow: Vec<String>,
) -> anyhow::Result<()> {
    let (cert, key) = (std::fs::read(cert)?, std::fs::read(key)?);
    let allowed = AllowList::default();
    allowed.set(
        allow
            .iter()
            .map(|s| EndpointId::from_str(s).context("an --allow endpoint id"))
            .collect::<anyhow::Result<Vec<_>>>()?,
    );
    let _qad = relay::spawn_address_discovery(qad, relay::tls_from_pem(&cert, &key)?).await?;
    let app = Router::new()
        .route("/health/live", get(|| async { "{\"status\":\"ok\"}" }))
        .merge(Relay::probe_routes());
    let listener = tokio::net::TcpListener::bind(https).await?;
    eprintln!(
        "{}",
        serde_json::json!({"event": "lighthouse", "https": https, "qad": qad})
    );
    relay::serve(
        listener,
        Some(Arc::new(relay::tls_from_pem(&cert, &key)?)),
        Relay::new(allowed),
        app,
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn node(
    key_hex: String,
    relay: RelayUrl,
    relay_root: PathBuf,
    network_pub: String,
    list_path: PathBuf,
    tun: String,
    bind: Option<SocketAddr>,
    status_path: PathBuf,
) -> anyhow::Result<()> {
    let roots = CertificateDer::pem_slice_iter(&std::fs::read(&relay_root)?)
        .collect::<Result<Vec<_>, _>>()
        .context("parse --relay-root")?;
    let network_key = VerifyingKey::from_bytes(&seed(&network_pub)?).context("--network-pub")?;
    let config = NetConfig {
        relays: vec![relay.clone()],
        bind: match bind {
            Some(addr) => Bind::Addrs(vec![addr]),
            None => Bind::Uplinks(0),
        },
        relay_roots: Some(roots),
        ..NetConfig::default()
    };
    let endpoint = endpoint::bind(
        key::secret_key(&seed(&key_hex)?),
        &config,
        vec![NET_ALPN.to_vec()],
    )
    .await?;
    eprintln!(
        "{}",
        serde_json::json!({"event": "node", "endpoint_id": endpoint.id().to_string(), "bound": endpoint.bound_sockets()})
    );
    let mesh = Mesh::new(
        endpoint.clone(),
        MeshConfig {
            tun_name: tun,
            relays: vec![relay],
        },
    );
    let _router = IrohRouter::builder(endpoint)
        .accept(NET_ALPN, mesh.clone())
        .spawn();

    let (tx, rx) = watch::channel(read_list(&list_path, &network_key).ok());
    tokio::spawn(async move {
        let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            return;
        };
        while hup.recv().await.is_some() {
            match read_list(&list_path, &network_key) {
                Ok(list) => {
                    let _ = tx.send(Some(list));
                }
                Err(e) => eprintln!(
                    "{}",
                    serde_json::json!({"event": "list_refused", "error": e.to_string()})
                ),
            }
        }
    });
    {
        let mesh = mesh.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Ok(json) = serde_json::to_vec(&mesh.status()) {
                    let tmp = status_path.with_extension("tmp");
                    if std::fs::write(&tmp, json).is_ok() {
                        let _ = std::fs::rename(&tmp, &status_path);
                    }
                }
            }
        });
    }
    mesh.run(rx).await
}

#[allow(clippy::too_many_arguments)]
async fn inject(
    key_hex: String,
    relay: RelayUrl,
    relay_root: PathBuf,
    to: String,
    src: std::net::Ipv6Addr,
    dst: std::net::Ipv6Addr,
    count: u32,
) -> anyhow::Result<()> {
    let roots = CertificateDer::pem_slice_iter(&std::fs::read(&relay_root)?)
        .collect::<Result<Vec<_>, _>>()?;
    let config = NetConfig {
        relays: vec![relay.clone()],
        relay_roots: Some(roots),
        ..NetConfig::default()
    };
    let endpoint = endpoint::bind(
        key::secret_key(&seed(&key_hex)?),
        &config,
        vec![NET_ALPN.to_vec()],
    )
    .await?;
    let target = EndpointId::from_str(&to)?;
    let outcome = match endpoint
        .connect(
            iroh::EndpointAddr::new(target).with_relay_url(relay),
            NET_ALPN,
        )
        .await
    {
        Ok(conn) => {
            let mut packet = vec![0u8; 48];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&8u16.to_be_bytes());
            packet[6] = 58;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
            packet[40] = 128;
            let mut framer = grund_net::frame::Framer::default();
            let mut sent = 0;
            for _ in 0..count {
                for d in framer.frame(&packet, conn.max_datagram_size().unwrap_or(1200)) {
                    if conn.send_datagram(d).is_ok() {
                        sent += 1;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            let closed = conn.close_reason().map(|r| r.to_string());
            serde_json::json!({"connected": true, "sent": sent, "closed_by_peer": closed})
        }
        Err(e) => serde_json::json!({"connected": false, "error": e.to_string()}),
    };
    println!("{outcome}");
    endpoint.close().await;
    Ok(())
}

fn read_list(path: &PathBuf, network_key: &VerifyingKey) -> anyhow::Result<MembershipList> {
    let signed: SignedList = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(signed.verify(network_key)?)
}

fn seed(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("hex")?;
    match <[u8; 32]>::try_from(bytes) {
        Ok(seed) => Ok(seed),
        Err(_) => bail!("expected 32 bytes of hex"),
    }
}

fn getrandom_seed(seed: &mut [u8; 32]) -> anyhow::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(seed)?;
    Ok(())
}
