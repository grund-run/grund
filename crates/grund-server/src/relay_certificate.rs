//! A `grund relay` on a host of its own, getting its certificate from its
//! instance (grund-docs design/traffic.md §5.7): `RelayTls::Instance`.
//!
//! ```text
//!   relay host                                      its instance
//!   ──────────                                      ────────────
//!   relay.key (Ed25519, 0600) ── EnrollRelay (once, one-time token) ──► grund_relays
//!   tls/pending-key.der (0600), its CSR ── RequestCertificate ────────► orders, under the lease
//!   Answers ◄── WatchChallenges: a key authorization ───────────────── grund_acme_challenges
//!      │     ── AnswerChallenge ──────────────────────────────────────► the CA is told to validate
//!      ▼
//!   :443 acme-tls/1 ◄──────────────────── the CA's validator
//!   Resolver ◄── GetCertificate: the chain ◄──────────────────────── issued
//!   tls/key.der, tls/chain.pem (0600): what is served, also across restarts
//! ```
//!
//! The relay's private keys never leave its host: the instance sees its
//! public key and its CSRs. It serves what it has on disk from its first
//! handshake, whether or not the instance or the CA answers, and renews when
//! the instance asks for a fresh CSR (the CA's ARI window), keeping the old
//! key until the new chain is installed.

use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::STANDARD};
use buffa::Message;
use ed25519_dalek::{Signer, SigningKey};
use grund_proto::grund::{
    certificates::v1::{
        self as proto, AnswerChallengeRequest, AnswerChallengeResponse, CertificateState,
        GetCertificateRequest, GetCertificateResponse, RequestCertificateRequest,
        RequestCertificateResponse, WatchChallengesRequest, WatchChallengesResponse,
    },
    relay::v1::{EnrollRelayRequest, EnrollRelayResponse},
};
use grund_tls::{Answers, KeyAndCsr, Resolver, Served};
use notmad::{Component, ComponentInfo, MadError};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::services::{agents::request_message, relays::enrollment_message};

/// The relay's enrollment: its id, host and instance.
pub const ENROLLMENT_FILE: &str = "relay.json";

/// The relay's Ed25519 key (its 32-byte seed).
pub const KEY_FILE: &str = "relay.key";

/// Where its certificate and keys are kept.
pub const TLS_DIR: &str = "tls";

/// How long one call to the instance may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// The longest the relay waits between tries when the instance does not
/// answer.
pub const MAX_RETRY: Duration = Duration::from_secs(60);

/// A Connect error the instance answered with: its code and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for Refused {}

/// Whether `error` is the instance answering `code`.
pub fn refused_with(error: &anyhow::Error, code: &str) -> bool {
    error
        .downcast_ref::<Refused>()
        .is_some_and(|refused| refused.code == code)
}

/// An HTTP client for the instance: the system's roots, or the Mozilla
/// roots built in when the host has none (the relay's image is `scratch`).
pub fn http_client(timeout: Option<Duration>) -> anyhow::Result<reqwest::Client> {
    grund_tls::install_default();
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .user_agent(concat!("grund-relay/", env!("CARGO_PKG_VERSION")));
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    let system_roots = std::env::var_os("SSL_CERT_FILE").is_some()
        || [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem",
        ]
        .iter()
        .any(|path| std::fs::metadata(path).is_ok_and(|m| m.len() > 0));
    if !system_roots {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder = builder.use_preconfigured_tls(grund_tls::client_config(roots)?);
    }
    builder
        .build()
        .context("build the HTTP client for the instance")
}

fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().context("a file in a directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let temporary = dir.join(format!(
        ".{}.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        Uuid::now_v7().simple()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn read_optional(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// The relay's identity with its instance: the key it enrolled and what the
/// instance bound it to.
#[derive(Clone)]
pub struct RelayKey {
    pub relay_id: Uuid,
    pub host: String,
    pub instance: String,
    key: SigningKey,
}

impl std::fmt::Debug for RelayKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayKey")
            .field("relay_id", &self.relay_id)
            .field("host", &self.host)
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

impl RelayKey {
    /// The enrollment kept in `dir`, if the relay enrolled before.
    pub fn load(dir: &Path) -> anyhow::Result<Option<Self>> {
        let Some(record) = read_optional(&dir.join(ENROLLMENT_FILE))? else {
            return Ok(None);
        };
        let record: serde_json::Value =
            serde_json::from_slice(&record).context("the relay's enrollment record")?;
        let seed = std::fs::read(dir.join(KEY_FILE))
            .with_context(|| format!("read {}", dir.join(KEY_FILE).display()))?;
        let seed = <[u8; 32]>::try_from(seed.as_slice())
            .map_err(|_| anyhow::anyhow!("{} is not a 32-byte key", KEY_FILE))?;
        Ok(Some(Self {
            relay_id: record["relay_id"]
                .as_str()
                .and_then(|id| Uuid::parse_str(id).ok())
                .context("the enrollment record's relay_id")?,
            host: record["host"]
                .as_str()
                .context("the enrollment record's host")?
                .to_string(),
            instance: record["instance"]
                .as_str()
                .context("the enrollment record's instance")?
                .to_string(),
            key: SigningKey::from_bytes(&seed),
        }))
    }

    /// Enrolls a new key with `instance`, using the one-time `token`, and
    /// keeps the result in `dir`. The token is not kept, nor logged.
    pub async fn enroll(
        dir: &Path,
        instance: &str,
        token: &str,
        http: &reqwest::Client,
    ) -> anyhow::Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("the operating system provides randomness");
        let key = SigningKey::from_bytes(&seed);
        let signed_at = chrono::Utc::now().timestamp();
        let proof = enrollment_message(
            instance,
            signed_at,
            &hex::encode(Sha256::digest(token.as_bytes())),
        );
        let request = EnrollRelayRequest {
            token: token.to_string(),
            relay_public_key: key.verifying_key().to_bytes().to_vec(),
            signed_at_unix: signed_at,
            signature: key.sign(&proof).to_bytes().to_vec(),
            ..Default::default()
        };
        let response: EnrollRelayResponse = unary(
            http,
            instance,
            "/grund.relay.v1.RelayEnrollmentService/EnrollRelay",
            &[],
            request.encode_to_vec(),
        )
        .await?;
        let relay_id = Uuid::parse_str(&response.relay_id).context("the relay id")?;
        write_private(&dir.join(KEY_FILE), &seed)?;
        write_private(
            &dir.join(ENROLLMENT_FILE),
            &serde_json::to_vec_pretty(&serde_json::json!({
                "relay_id": relay_id.to_string(),
                "host": response.host,
                "instance": instance,
            }))?,
        )?;
        Ok(Self {
            relay_id,
            host: response.host,
            instance: instance.to_string(),
            key,
        })
    }

    /// The headers that sign a request to `path` carrying `body`, as the
    /// instance checks them (grund.relay.v1).
    pub fn headers(&self, path: &str, body: &[u8]) -> Vec<(&'static str, String)> {
        let signed_at = chrono::Utc::now().timestamp();
        let signature = self.key.sign(&request_message(path, signed_at, body));
        vec![
            ("x-grund-relay", self.relay_id.to_string()),
            ("x-grund-signed-at", signed_at.to_string()),
            ("x-grund-signature", STANDARD.encode(signature.to_bytes())),
        ]
    }
}

async fn unary<Resp: Message>(
    http: &reqwest::Client,
    instance: &str,
    path: &str,
    headers: &[(&'static str, String)],
    body: Vec<u8>,
) -> anyhow::Result<Resp> {
    let mut request = http
        .post(format!("{instance}{path}"))
        .header("Content-Type", "application/proto")
        .header("Connect-Protocol-Version", "1");
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = request
        .body(body)
        .send()
        .await
        .with_context(|| format!("reach {instance}"))?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        return Err(Refused {
            code: error["code"].as_str().unwrap_or("unknown").to_string(),
            message: error["message"].as_str().unwrap_or("refused").to_string(),
        }
        .into());
    }
    Resp::decode_from_slice(&bytes)
        .with_context(|| format!("{path}: an answer that does not decode"))
}

/// Splits a Connect stream's body into its messages (RFC-style envelopes: a
/// flags byte, a 4-byte big-endian length, the message). The end-of-stream
/// envelope (flag 2) carries JSON with the stream's error, if any.
#[derive(Debug, Default)]
pub struct Envelopes {
    buffer: Vec<u8>,
}

/// One envelope's content.
#[derive(Debug, PartialEq, Eq)]
pub enum Envelope {
    Message(Vec<u8>),
    End(Option<Refused>),
}

/// The largest message a watch may carry.
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

impl Envelopes {
    /// Adds `bytes` and returns every whole envelope now available.
    pub fn push(&mut self, bytes: &[u8]) -> anyhow::Result<Vec<Envelope>> {
        self.buffer.extend_from_slice(bytes);
        let mut out = Vec::new();
        while self.buffer.len() >= 5 {
            let flags = self.buffer[0];
            let length = u32::from_be_bytes([
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
                self.buffer[4],
            ]) as usize;
            anyhow::ensure!(
                length <= MAX_ENVELOPE_BYTES,
                "a stream message of {length} bytes"
            );
            if self.buffer.len() < 5 + length {
                break;
            }
            let content: Vec<u8> = self.buffer.drain(..5 + length).skip(5).collect();
            anyhow::ensure!(flags & 1 == 0, "a compressed stream message");
            if flags & 2 == 2 {
                let end: serde_json::Value = serde_json::from_slice(&content).unwrap_or_default();
                let error = end.get("error").map(|error| Refused {
                    code: error["code"].as_str().unwrap_or("unknown").to_string(),
                    message: error["message"].as_str().unwrap_or("").to_string(),
                });
                out.push(Envelope::End(error));
            } else {
                out.push(Envelope::Message(content));
            }
        }
        Ok(out)
    }
}

/// The relay's calls to its instance, each signed by its key.
#[derive(Clone)]
pub struct Instance {
    http: reqwest::Client,
    watch_http: reqwest::Client,
    key: RelayKey,
}

impl Instance {
    pub fn new(key: RelayKey) -> anyhow::Result<Self> {
        Ok(Self {
            http: http_client(Some(CALL_TIMEOUT))?,
            watch_http: http_client(None)?,
            key,
        })
    }

    /// The relay's key and what it serves.
    pub fn key(&self) -> &RelayKey {
        &self.key
    }

    async fn call<Req: Message, Resp: Message>(
        &self,
        procedure: &str,
        request: &Req,
    ) -> anyhow::Result<Resp> {
        let path = format!("/grund.certificates.v1.CertificateService/{procedure}");
        let body = request.encode_to_vec();
        let headers = self.key.headers(&path, &body);
        unary(&self.http, &self.key.instance, &path, &headers, body).await
    }

    /// The relay's certificate as the instance has it; none before its first
    /// request.
    pub async fn get(&self) -> anyhow::Result<Option<proto::Certificate>> {
        match self
            .call::<_, GetCertificateResponse>("GetCertificate", &GetCertificateRequest::default())
            .await
        {
            Ok(response) => Ok(response.certificate.into_option()),
            Err(error) if refused_with(&error, "not_found") => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn request(&self, csr: &[u8]) -> anyhow::Result<proto::Certificate> {
        let response: RequestCertificateResponse = self
            .call(
                "RequestCertificate",
                &RequestCertificateRequest {
                    names: vec![self.key.host.clone()],
                    csr: csr.to_vec(),
                    ..Default::default()
                },
            )
            .await?;
        Ok(response.certificate.into_option().unwrap_or_default())
    }

    pub async fn answering(&self, token: &str) -> anyhow::Result<()> {
        let _: AnswerChallengeResponse = self
            .call(
                "AnswerChallenge",
                &AnswerChallengeRequest {
                    token: token.to_string(),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    /// Opens WatchChallenges; read it with [`Watch::next`].
    pub async fn watch(&self) -> anyhow::Result<Watch> {
        let path = "/grund.certificates.v1.CertificateService/WatchChallenges";
        let message = WatchChallengesRequest::default().encode_to_vec();
        let mut body = Vec::with_capacity(5 + message.len());
        body.push(0);
        body.extend_from_slice(&u32::try_from(message.len())?.to_be_bytes());
        body.extend_from_slice(&message);
        let mut request = self
            .watch_http
            .post(format!("{}{path}", self.key.instance))
            .header("Content-Type", "application/connect+proto")
            .header("Connect-Protocol-Version", "1")
            .header("Connect-Timeout-Ms", "40000");
        for (name, value) in self.key.headers(path, &body) {
            request = request.header(name, value);
        }
        let response = tokio::time::timeout(CALL_TIMEOUT, request.body(body).send())
            .await
            .context("the instance did not open the watch in time")?
            .with_context(|| format!("reach {}", self.key.instance))?;
        if !response.status().is_success() {
            let error: serde_json::Value = response.json().await.unwrap_or_default();
            return Err(Refused {
                code: error["code"].as_str().unwrap_or("unknown").to_string(),
                message: error["message"].as_str().unwrap_or("refused").to_string(),
            }
            .into());
        }
        Ok(Watch {
            response,
            envelopes: Envelopes::default(),
            ready: Default::default(),
        })
    }
}

/// An open WatchChallenges stream.
pub struct Watch {
    response: reqwest::Response,
    envelopes: Envelopes,
    ready: std::collections::VecDeque<Envelope>,
}

impl Watch {
    /// The next event, or none when the stream ended cleanly.
    pub async fn next(
        &mut self,
    ) -> anyhow::Result<Option<proto::__buffa::oneof::watch_challenges_response::Event>> {
        loop {
            match self.ready.pop_front() {
                Some(Envelope::Message(bytes)) => {
                    let message = WatchChallengesResponse::decode_from_slice(&bytes)
                        .context("a watch event that does not decode")?;
                    if let Some(event) = message.event {
                        return Ok(Some(event));
                    }
                    continue;
                }
                Some(Envelope::End(None)) => return Ok(None),
                Some(Envelope::End(Some(error))) => return Err(error.into()),
                None => {}
            }
            let chunk = tokio::time::timeout(Duration::from_secs(40), self.response.chunk())
                .await
                .context("the watch went silent")?
                .context("read the watch")?;
            match chunk {
                Some(bytes) => self.ready.extend(self.envelopes.push(&bytes)?),
                None => return Ok(None),
            }
        }
    }
}

/// What the relay serves, answered by the instance: the certificate in
/// `resolver`, and TLS-ALPN-01 answers in `answers` while an order waits.
#[derive(Debug, Clone, Default)]
pub struct InstanceTls {
    pub resolver: Resolver,
    pub answers: Answers,
}

impl InstanceTls {
    /// The TLS configuration for the relay's listener and its QUIC address
    /// discovery.
    pub fn server_config(&self) -> anyhow::Result<rustls::ServerConfig> {
        grund_tls::answering_server_config(
            self.resolver.clone(),
            self.answers.clone(),
            &[b"http/1.1"],
        )
    }
}

fn spki_of_leaf(chain_pem: &str) -> anyhow::Result<Vec<u8>> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .next()
        .context("the chain holds no certificate")?
        .context("parse the chain")?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der)
        .map_err(|error| anyhow::anyhow!("parse the certificate: {error}"))?;
    Ok(parsed.tbs_certificate.subject_pki.raw.to_vec())
}

fn spki_of_key(key_pkcs8_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    use x509_parser::prelude::FromDer;
    let made = KeyAndCsr::from_pkcs8(key_pkcs8_der, &["spki.invalid".to_string()])?;
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(made.csr_der())
            .map_err(|error| anyhow::anyhow!("parse a CSR: {error}"))?;
    Ok(csr.certification_request_info.subject_pki.raw.to_vec())
}

/// The relay's certificate files under `<data dir>/tls`, and what they
/// hold.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join(TLS_DIR),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Serves the certificate kept here, if there is one.
    pub fn load(&self, resolver: &Resolver) -> anyhow::Result<Option<String>> {
        let (Some(chain), Some(key)) = (
            read_optional(&self.path("chain.pem"))?,
            read_optional(&self.path("key.der"))?,
        ) else {
            return Ok(None);
        };
        let served = Served::from_pkcs8(&chain, &key).context("the relay's stored certificate")?;
        resolver.set(served);
        Ok(Some(String::from_utf8(chain).context("the stored chain")?))
    }

    /// The key and CSR waiting for a chain, made now if there is none.
    pub fn pending(&self, host: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        if let (Some(key), Some(csr)) = (
            read_optional(&self.path("pending-key.der"))?,
            read_optional(&self.path("pending.csr"))?,
        ) {
            return Ok((key, csr));
        }
        self.fresh(host)
    }

    /// A new key and CSR for `host`, replacing any waiting one.
    pub fn fresh(&self, host: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let made = KeyAndCsr::generate(&[host.to_string()])?;
        write_private(&self.path("pending-key.der"), made.key_pkcs8_der())?;
        write_private(&self.path("pending.csr"), made.csr_der())?;
        Ok((made.key_pkcs8_der().to_vec(), made.csr_der().to_vec()))
    }

    /// Serves `chain` with whichever kept key it is for (the waiting one, or
    /// the one served now), and keeps it. Refused when it is for neither.
    pub fn install(&self, chain: &str, resolver: &Resolver) -> anyhow::Result<()> {
        let leaf = spki_of_leaf(chain)?;
        let pending = read_optional(&self.path("pending-key.der"))?;
        let current = read_optional(&self.path("key.der"))?;
        let key = [pending.as_ref(), current.as_ref()]
            .into_iter()
            .flatten()
            .find(|key| spki_of_key(key).is_ok_and(|spki| spki == leaf))
            .cloned()
            .context("the instance's chain is for a key this relay does not have")?;
        let served = Served::from_pkcs8(chain.as_bytes(), &key)?;
        write_private(&self.path("key.der"), &key)?;
        write_private(&self.path("chain.pem"), chain.as_bytes())?;
        if pending.as_deref() == Some(&key[..]) {
            let _ = std::fs::remove_file(self.path("pending-key.der"));
            let _ = std::fs::remove_file(self.path("pending.csr"));
        }
        resolver.set(served);
        Ok(())
    }
}

/// Keeps the relay's certificate: asks for one, answers its challenges,
/// installs what is issued and renews when asked. A failure is logged and
/// tried again with backoff; what is served stays served.
pub struct CertificateClient {
    instance: Instance,
    tls: InstanceTls,
    store: Store,
}

impl CertificateClient {
    pub fn new(instance: Instance, tls: InstanceTls, data_dir: &Path) -> Self {
        Self {
            instance,
            tls,
            store: Store::new(data_dir),
        }
    }

    async fn reconcile(&self, installed: &mut Option<String>) -> anyhow::Result<()> {
        let host = self.instance.key().host.clone();
        let certificate = match self.instance.get().await? {
            Some(certificate) => certificate,
            None => {
                let (_, csr) = self.store.pending(&host)?;
                tracing::info!(%host, "relay: asking the instance for a certificate");
                self.instance.request(&csr).await?
            }
        };
        if !certificate.chain_pem.is_empty()
            && installed.as_deref() != Some(certificate.chain_pem.as_str())
        {
            match self
                .store
                .install(&certificate.chain_pem, &self.tls.resolver)
            {
                Ok(()) => {
                    tracing::info!(%host, version = certificate.version, "relay: serving the certificate from the instance");
                    *installed = Some(certificate.chain_pem.clone());
                }
                Err(error) => tracing::warn!(
                    error = format!("{error:#}"),
                    "relay: not serving the instance's chain"
                ),
            }
        }
        match certificate.state.as_known() {
            Some(CertificateState::CERTIFICATE_STATE_CSR_WANTED) => {
                let (_, csr) = self.store.fresh(&host)?;
                tracing::info!(%host, "relay: renewal is due; sending a CSR for a new key");
                self.instance.request(&csr).await?;
            }
            Some(CertificateState::CERTIFICATE_STATE_ISSUED) => {
                for name in self.tls.answers.names() {
                    self.tls.answers.remove(&name);
                }
            }
            _ => {}
        }
        self.watch().await
    }

    async fn watch(&self) -> anyhow::Result<()> {
        use proto::__buffa::oneof::watch_challenges_response::Event;
        let mut watch = self.instance.watch().await?;
        while let Some(event) = watch.next().await? {
            match event {
                Event::Challenge(challenge) => {
                    self.tls
                        .answers
                        .insert(&challenge.name, &challenge.key_authorization)?;
                    self.instance.answering(&challenge.token).await?;
                    tracing::info!(name = %challenge.name, "relay: answering a TLS-ALPN-01 challenge");
                }
                Event::CsrWanted(_) | Event::Issued(_) => return Ok(()),
            }
        }
        Ok(())
    }
}

impl Component for CertificateClient {
    fn info(&self) -> ComponentInfo {
        "grund-relay/certificate".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let mut installed = self.store.load(&self.tls.resolver)?;
        if installed.is_some() {
            tracing::info!("relay: serving the certificate kept on disk");
        }
        let mut retry = Duration::from_secs(1);
        loop {
            let done = tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                done = self.reconcile(&mut installed) => done,
            };
            let wait = match done {
                Ok(()) => {
                    retry = Duration::from_secs(1);
                    Duration::ZERO
                }
                Err(error) => {
                    tracing::warn!(
                        error = format!("{error:#}"),
                        retry_in_seconds = retry.as_secs(),
                        "relay: could not get its certificate from the instance; serving what it has"
                    );
                    let wait = retry.mul_f64(1.0 + crate::acme::unit_random() / 2.0);
                    retry = (retry * 2).min(MAX_RETRY);
                    wait
                }
            };
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                () = tokio::time::sleep(wait) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(flags: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![flags];
        out.extend_from_slice(&(content.len() as u32).to_be_bytes());
        out.extend_from_slice(content);
        out
    }

    #[test]
    fn a_stream_is_split_into_its_messages_however_it_arrives() {
        let mut bytes = envelope(0, b"one");
        bytes.extend(envelope(0, b""));
        bytes.extend(envelope(
            2,
            br#"{"error":{"code":"not_found","message":"gone"}}"#,
        ));
        let mut envelopes = Envelopes::default();
        let mut seen = Vec::new();
        for byte in &bytes {
            seen.extend(envelopes.push(std::slice::from_ref(byte)).unwrap());
        }
        assert_eq!(
            seen,
            vec![
                Envelope::Message(b"one".to_vec()),
                Envelope::Message(Vec::new()),
                Envelope::End(Some(Refused {
                    code: "not_found".into(),
                    message: "gone".into()
                })),
            ]
        );
        assert!(
            Envelopes::default()
                .push(&envelope(0, &vec![0; MAX_ENVELOPE_BYTES + 1]))
                .is_err()
        );
    }

    fn dir() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("grund-relay-store-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn issued_for(key_pkcs8_der: &[u8], host: &str) -> String {
        let key = rcgen::KeyPair::try_from(key_pkcs8_der).unwrap();
        rcgen::CertificateParams::new(vec![host.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem()
    }

    #[test]
    fn a_renewed_chain_is_served_with_the_new_key_and_the_old_one_until_then() {
        use std::os::unix::fs::PermissionsExt;
        let dir = dir();
        let store = Store::new(&dir);
        let resolver = Resolver::default();
        let (first_key, _) = store.pending("relay.example.com").unwrap();
        assert_eq!(
            store.pending("relay.example.com").unwrap().0,
            first_key,
            "a waiting key is kept"
        );
        store
            .install(&issued_for(&first_key, "relay.example.com"), &resolver)
            .unwrap();
        let first = resolver.current().unwrap();
        let (second_key, _) = store.fresh("relay.example.com").unwrap();
        assert_ne!(second_key, first_key);
        assert!(
            store
                .install(&issued_for(&first_key, "relay.example.com"), &resolver)
                .is_ok(),
            "the chain served now still installs while a new key waits"
        );
        store
            .install(&issued_for(&second_key, "relay.example.com"), &resolver)
            .unwrap();
        assert_ne!(
            resolver.current().unwrap().not_after,
            std::time::SystemTime::UNIX_EPOCH
        );
        assert!(!std::sync::Arc::ptr_eq(
            &first,
            &resolver.current().unwrap()
        ));
        let other = KeyAndCsr::generate(&["relay.example.com".to_string()]).unwrap();
        assert!(
            store
                .install(
                    &issued_for(other.key_pkcs8_der(), "relay.example.com"),
                    &resolver
                )
                .is_err(),
            "a chain for a key the relay never made is refused"
        );
        for name in ["key.der", "chain.pem"] {
            let mode = std::fs::metadata(dir.join(TLS_DIR).join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
        assert!(!dir.join(TLS_DIR).join("pending-key.der").exists());
        let again = Resolver::default();
        assert!(
            store.load(&again).unwrap().is_some(),
            "kept across a restart"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
