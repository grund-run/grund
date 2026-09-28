use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use rustls::pki_types::pem::PemObject;

pub use super::free_port;
use super::random_hex;

pub const PEBBLE_VERSION: &str = "v2.10.1";

pub const SHORT_PROFILE_SECONDS: u64 = 30;

pub struct Pebble {
    pub directory: String,
    pub ca_file: PathBuf,
    pub tls_port: u16,
    pub http_port: u16,
    listen_port: u16,
    management_port: u16,
    dns_port: u16,
    work: PathBuf,
    bin: PathBuf,
    pebble: Option<Child>,
    challtestsrv: Option<Child>,
}

impl Drop for Pebble {
    fn drop(&mut self) {
        for child in [self.pebble.as_mut(), self.challtestsrv.as_mut()]
            .into_iter()
            .flatten()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

fn binaries() -> anyhow::Result<Option<PathBuf>> {
    let dir = std::env::var("GRUND_ACCEPT_PEBBLE_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/pebble"));
    let present = ["pebble", "pebble-challtestsrv"]
        .iter()
        .all(|name| dir.join(name).is_file());
    if present {
        return Ok(Some(dir));
    }
    anyhow::ensure!(
        std::env::var("GRUND_ACCEPT_REQUIRE_PEBBLE").is_err(),
        "GRUND_ACCEPT_REQUIRE_PEBBLE is set, but Pebble is not in {}: run \
         crates/grund/tests/pebble/fetch.sh",
        dir.display()
    );
    eprintln!(
        "skipped: needs Pebble {PEBBLE_VERSION} in {} (crates/grund/tests/pebble/fetch.sh)",
        dir.display()
    );
    Ok(None)
}

impl Pebble {
    pub fn prepare(tls_port: u16) -> anyhow::Result<Option<Self>> {
        let Some(bin) = binaries()? else {
            return Ok(None);
        };
        let work = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("pebble-{}", random_hex(6)));
        std::fs::create_dir_all(&work)?;
        let ca_key = rcgen::KeyPair::generate()?;
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key)?;
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate()?;
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
        let cert = params.signed_by(&key, &issuer)?;
        let ca_file = work.join("api-ca.pem");
        std::fs::write(&ca_file, ca.pem())?;
        std::fs::write(work.join("api.pem"), cert.pem())?;
        std::fs::write(work.join("api.key"), key.serialize_pem())?;
        let (listen_port, management_port, dns_port, http_port) =
            (free_port(), free_port(), free_port(), free_port());
        let config = serde_json::json!({
            "pebble": {
                "listenAddress": format!("127.0.0.1:{listen_port}"),
                "managementListenAddress": format!("127.0.0.1:{management_port}"),
                "certificate": work.join("api.pem"),
                "privateKey": work.join("api.key"),
                "httpPort": http_port,
                "tlsPort": tls_port,
                "ocspResponderURL": "",
                "externalAccountBindingRequired": false,
                "retryAfter": { "authz": 1, "order": 1 },
                "keyAlgorithm": "ecdsa",
                "profiles": {
                    "classic": { "description": "90 days", "validityPeriod": 7_776_000 },
                    "short": { "description": "seconds, to renew in a test", "validityPeriod": SHORT_PROFILE_SECONDS }
                }
            }
        });
        std::fs::write(
            work.join("pebble.json"),
            serde_json::to_vec_pretty(&config)?,
        )?;
        Ok(Some(Self {
            directory: format!("https://127.0.0.1:{listen_port}/dir"),
            ca_file,
            tls_port,
            http_port,
            listen_port,
            management_port,
            dns_port,
            work,
            bin,
            pebble: None,
            challtestsrv: None,
        }))
    }

    pub async fn start(tls_port: u16) -> anyhow::Result<Option<Self>> {
        let Some(mut pebble) = Self::prepare(tls_port)? else {
            return Ok(None);
        };
        pebble.run().await?;
        Ok(Some(pebble))
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        if self.challtestsrv.is_none() {
            let log = std::fs::File::create(self.work.join("challtestsrv.log"))?;
            self.challtestsrv = Some(
                Command::new(self.bin.join("pebble-challtestsrv"))
                    .args(["-defaultIPv4", "127.0.0.1", "-defaultIPv6", ""])
                    .args(["-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""])
                    .arg("-dnsserver")
                    .arg(format!("127.0.0.1:{}", self.dns_port))
                    .arg("-management")
                    .arg(format!("127.0.0.1:{}", free_port()))
                    .stdout(Stdio::from(log.try_clone()?))
                    .stderr(Stdio::from(log))
                    .spawn()
                    .context("spawn pebble-challtestsrv")?,
            );
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.work.join("pebble.log"))?;
        self.pebble = Some(
            Command::new(self.bin.join("pebble"))
                .arg("-config")
                .arg(self.work.join("pebble.json"))
                .arg("-dnsserver")
                .arg(format!("127.0.0.1:{}", self.dns_port))
                .env("PEBBLE_VA_NOSLEEP", "1")
                .env("PEBBLE_WFE_NONCEREJECT", "0")
                .env("PEBBLE_AUTHZREUSE", "0")
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()
                .context("spawn pebble")?,
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while std::net::TcpStream::connect(("127.0.0.1", self.listen_port)).is_err() {
            anyhow::ensure!(
                Instant::now() < deadline,
                "pebble never listened:\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.pebble.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.work.join("pebble.log")).unwrap_or_default()
    }

    pub fn issued_count(&self) -> usize {
        self.log().matches("Issued certificate serial").count()
    }

    pub async fn roots(&self) -> anyhow::Result<Arc<rustls::RootCertStore>> {
        let mut api =
            super::client::Origin::parse(&format!("https://localhost:{}", self.management_port))?;
        let mut trust = rustls::RootCertStore::empty();
        let api_pem = std::fs::read(&self.ca_file)?;
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&api_pem) {
            trust.add(cert?)?;
        }
        api.roots = Some(Arc::new(trust));
        let mut roots = rustls::RootCertStore::empty();
        let response = super::client::send(&api, "GET", "/roots/0", &[], None).await?;
        anyhow::ensure!(
            response.status == 200,
            "pebble /roots/0: {}",
            response.status
        );
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&response.body) {
            roots.add(cert?)?;
        }
        Ok(Arc::new(roots))
    }

    pub fn grund_settings(&self, domain: &str) -> Vec<(String, String)> {
        vec![
            ("GRUND_DOMAIN".into(), domain.into()),
            (
                "GRUND_PUBLIC_URL".into(),
                format!("https://{domain}:{}", self.tls_port),
            ),
            (
                "GRUND_TLS_LISTEN".into(),
                format!("127.0.0.1:{}", self.tls_port),
            ),
            ("GRUND_ACME_DIRECTORY".into(), self.directory.clone()),
            (
                "GRUND_ACME_CA_FILE".into(),
                self.ca_file.to_string_lossy().into_owned(),
            ),
            ("GRUND_ACME_RETRY_BASE".into(), "1".into()),
            ("GRUND_TLS_REFRESH_INTERVAL".into(), "1".into()),
        ]
    }
}

pub fn a_domain() -> String {
    format!("grund-{}.example.com", random_hex(4))
}
