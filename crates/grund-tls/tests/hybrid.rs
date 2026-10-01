use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use grund_tls::{Resolver, Served, kx};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, NamedGroup, ServerConfig, ServerConnection};

const NAME: &str = "hybrid.test";

struct Identity {
    cert_pem: String,
    key_pem: String,
    roots: rustls::RootCertStore,
}

fn identity() -> Identity {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![NAME.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    Identity {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        roots,
    }
}

fn grund_server(identity: &Identity) -> ServerConfig {
    let resolver = Resolver::default();
    resolver
        .set(Served::from_pem(identity.cert_pem.as_bytes(), identity.key_pem.as_bytes()).unwrap());
    grund_tls::server_config(resolver, &[]).unwrap()
}

fn server_on(provider: Arc<CryptoProvider>, identity: &Identity) -> ServerConfig {
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            CertificateDer::pem_slice_iter(identity.cert_pem.as_bytes())
                .map(Result::unwrap)
                .collect(),
            PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes()).unwrap(),
        )
        .unwrap()
}

fn provider_with(groups: &[&'static dyn rustls::crypto::SupportedKxGroup]) -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = groups.to_vec();
    Arc::new(provider)
}

fn client(provider: Arc<CryptoProvider>, identity: &Identity) -> ClientConfig {
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(identity.roots.clone())
        .with_no_client_auth()
}

struct Handshake {
    group: Option<NamedGroup>,
    client_flights: usize,
}

fn handshake(client: ClientConfig, server: ServerConfig) -> Handshake {
    let mut client =
        ClientConnection::new(Arc::new(client), ServerName::try_from(NAME).unwrap()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server)).unwrap();
    let mut client_flights = 0;
    while client.is_handshaking() || server.is_handshaking() {
        let mut flight = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut flight).unwrap();
        }
        if !flight.is_empty() {
            client_flights += 1;
        }
        server.read_tls(&mut flight.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut flight = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut flight).unwrap();
        }
        client.read_tls(&mut flight.as_slice()).unwrap();
        client.process_new_packets().unwrap();
    }
    let group = client.negotiated_key_exchange_group().map(|g| g.name());
    assert_eq!(
        group,
        server.negotiated_key_exchange_group().map(|g| g.name())
    );
    Handshake {
        group,
        client_flights,
    }
}

#[test]
fn grund_prefers_the_hybrid_group_first_then_x25519() {
    let names: Vec<NamedGroup> = grund_tls::provider()
        .kx_groups
        .iter()
        .map(|group| group.name())
        .collect();
    assert_eq!(
        names,
        [
            NamedGroup::X25519MLKEM768,
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1
        ]
    );
}

#[test]
fn grund_s_server_negotiates_x25519mlkem768_with_a_client_offering_only_it() {
    let identity = identity();
    let done = handshake(
        client(provider_with(&[kx::X25519MLKEM768]), &identity),
        grund_server(&identity),
    );
    assert_eq!(done.group, Some(NamedGroup::X25519MLKEM768));
}

#[test]
fn grund_s_client_and_server_negotiate_x25519mlkem768_in_one_round_trip() {
    let identity = identity();
    let done = handshake(
        client(grund_tls::provider(), &identity),
        grund_server(&identity),
    );
    assert_eq!(done.group, Some(NamedGroup::X25519MLKEM768));
    assert_eq!(done.client_flights, 2);
}

#[test]
fn a_hello_retry_shows_as_a_third_client_flight() {
    let identity = identity();
    let server = server_on(provider_with(&[kx::X25519MLKEM768]), &identity);
    let done = handshake(
        client(
            provider_with(&[rustls::crypto::ring::kx_group::X25519, kx::X25519MLKEM768]),
            &identity,
        ),
        server,
    );
    assert_eq!(done.group, Some(NamedGroup::X25519MLKEM768));
    assert_eq!(done.client_flights, 3);
}

#[test]
fn an_x25519_only_client_still_connects_to_grund_s_server() {
    let identity = identity();
    let done = handshake(
        client(
            provider_with(&[rustls::crypto::ring::kx_group::X25519]),
            &identity,
        ),
        grund_server(&identity),
    );
    assert_eq!(done.group, Some(NamedGroup::X25519));
}

#[test]
fn a_tls_1_2_client_still_connects_to_grund_s_server() {
    let identity = identity();
    let config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(identity.roots.clone())
            .with_no_client_auth();
    let done = handshake(config, grund_server(&identity));
    assert_eq!(done.group, Some(NamedGroup::X25519));
}

#[test]
fn grund_s_client_falls_back_to_x25519_without_a_retry_against_a_server_without_the_hybrid() {
    let identity = identity();
    let server = server_on(
        Arc::new(rustls::crypto::ring::default_provider()),
        &identity,
    );
    let done = handshake(client(grund_tls::provider(), &identity), server);
    assert_eq!(done.group, Some(NamedGroup::X25519));
    assert_eq!(done.client_flights, 2);
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(identity: &Identity) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "grund-tls-hybrid-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cert.pem"), &identity.cert_pem).unwrap();
        std::fs::write(dir.join("key.pem"), &identity.key_pem).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn openssl() -> Option<&'static str> {
    if std::env::var_os("GRUND_SKIP_OPENSSL_INTEROP").is_some() {
        eprintln!("GRUND_SKIP_OPENSSL_INTEROP is set: the OpenSSL interop check did not run");
        return None;
    }
    let listed = Command::new("openssl")
        .args(["list", "-kem-algorithms"])
        .output()
        .expect("the OpenSSL interop check needs openssl >= 3.5 on PATH (set GRUND_SKIP_OPENSSL_INTEROP to skip it)");
    let version = Command::new("openssl").arg("version").output().unwrap();
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("X25519MLKEM768"),
        "{} has no X25519MLKEM768; the interop check needs OpenSSL >= 3.5",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    Some("openssl")
}

#[test]
fn openssl_offering_only_x25519mlkem768_negotiates_it_with_grund_s_server() {
    let Some(openssl) = openssl() else { return };
    let identity = identity();
    let config = Arc::new(grund_server(&identity));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut server = ServerConnection::new(config).unwrap();
        while server.is_handshaking() {
            server.complete_io(&mut stream).unwrap();
        }
        let _ = server.complete_io(&mut stream);
        server.negotiated_key_exchange_group().map(|g| g.name())
    });

    let output = Command::new(openssl)
        .args([
            "s_client",
            "-connect",
            &address.to_string(),
            "-servername",
            NAME,
            "-groups",
            "X25519MLKEM768",
            "-tls1_3",
            "-brief",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said.contains("Negotiated TLS1.3 group: X25519MLKEM768"),
        "openssl s_client said:\n{said}"
    );
    assert_eq!(accepted.join().unwrap(), Some(NamedGroup::X25519MLKEM768));
}

#[test]
fn grund_s_client_negotiates_x25519mlkem768_with_an_openssl_server_offering_only_it() {
    let Some(openssl) = openssl() else { return };
    let identity = identity();
    let scratch = Scratch::new(&identity);
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut server = Command::new(openssl)
        .args([
            "s_server",
            "-accept",
            &format!("127.0.0.1:{port}"),
            "-cert",
            &scratch.path("cert.pem"),
            "-key",
            &scratch.path("key.pem"),
            "-groups",
            "X25519MLKEM768",
            "-tls1_3",
            "-naccept",
            "1",
            "-www",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match TcpStream::connect(address) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => panic!("openssl s_server did not listen: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut connection = ClientConnection::new(
        Arc::new(client(grund_tls::provider(), &identity)),
        ServerName::try_from(NAME).unwrap(),
    )
    .unwrap();
    let mut tls = rustls::Stream::new(&mut connection, &mut stream);
    tls.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut page = Vec::new();
    let _ = tls.read_to_end(&mut page);
    let group = connection.negotiated_key_exchange_group().map(|g| g.name());
    let _ = server.kill();
    let _ = server.wait();
    assert_eq!(group, Some(NamedGroup::X25519MLKEM768));
    assert!(
        String::from_utf8_lossy(&page).contains("X25519MLKEM768"),
        "openssl s_server reported:\n{}",
        String::from_utf8_lossy(&page)
    );
}
