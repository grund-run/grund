//! `grund join`: registers this machine into a pool with a one-time token.
//!
//! The token and the instance's URL come from the command line (a customer's
//! machine, `grund join --url https://grund.example.com grund_join_…`) or from
//! fleet's metadata service (`grund join --mmds`, in a grund machine's guest:
//! MMDS V2 at 169.254.169.254, `{ grund: { url, enrollment_token }, fleet: {
//! machine_id } }`). Nothing else differs between the two.
//!
//! The machine key is written before the instance is asked, so a response
//! lost on the way back is not a stranded machine: running `grund join` again
//! with the same token and the same key gets the same answer (the instance
//! replays it). Once registered, `grund join` changes nothing and says so,
//! which is what lets fleet's guest supervise it with restarts.

use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use buffa::Message;
use ed25519_dalek::{Signer, SigningKey};
use grund_proto::grund::agent::v1::{
    EnrollMachineRequest, EnrollMachineResponse, ErrorReason, KeyPurpose, MachineFacts, Pool,
    PublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The file holding the machine key's 32-byte seed, as hex, owner-only.
pub const KEY_FILE: &str = "machine.key";

/// The file holding what the instance answered: the machine's identity and
/// the keys it pinned.
pub const RECORD_FILE: &str = "machine.json";

/// How long `join` keeps retrying an instance that is unavailable or
/// unreachable before giving up.
pub const RETRY_BUDGET: Duration = Duration::from_secs(120);

/// `grund join`.
#[derive(Clone, Debug, clap::Args)]
pub struct JoinArgs {
    /// The one-time setup code: grund_join_… (your organisation) or
    /// grund_reg_… (the management pool). Not needed with --mmds.
    pub token: Option<String>,

    /// The grund instance to register with, e.g. https://grund.example.com.
    /// Plain http only for a loopback address.
    #[arg(long, env = "GRUND_URL")]
    pub url: Option<String>,

    /// Read the URL and the setup code from fleet's metadata service (a grund
    /// machine's guest).
    #[arg(long)]
    pub mmds: bool,

    /// Where the metadata service answers.
    #[arg(
        long,
        env = "GRUND_MMDS_ADDRESS",
        default_value = "169.254.169.254",
        hide = true
    )]
    pub mmds_address: String,

    /// The name to ask for, when the setup code binds none.
    #[arg(long)]
    pub name: Option<String>,

    /// Where the machine keeps its key and identity.
    #[arg(
        long,
        env = "GRUND_AGENT_DATA_DIR",
        default_value = "/var/lib/grund/agent"
    )]
    pub data_dir: PathBuf,
}

/// What the instance answered, as kept on the machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub machine_id: String,
    pub name: String,
    /// `management` or `organisation`.
    pub pool: String,
    pub organisation_id: String,
    pub instance_url: String,
    pub instance_key: PinnedKey,
    pub trust_key: PinnedKey,
    pub heartbeat_interval_seconds: i32,
    pub registered_at_unix: i64,
}

/// A key of the instance, pinned at registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedKey {
    pub key_id: String,
    /// 32 bytes, lowercase hex.
    pub public_key: String,
    /// `instance`, `management` or `organisation`.
    pub purpose: String,
}

/// Where the setup code and the instance came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub url: String,
    pub token: String,
    pub fleet_machine_id: String,
}

/// Runs `grund join`.
pub async fn run(args: &JoinArgs) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if let Some(record) = read_record(&args.data_dir)? {
        println!(
            "already registered as {} ({}) with {}; nothing to do",
            record.name, record.machine_id, record.instance_url
        );
        return Ok(());
    }
    let http = http_client()?;
    let source = match (args.mmds, &args.token, &args.url) {
        (true, _, _) => from_mmds(&http, &args.mmds_address).await?,
        (false, Some(token), Some(url)) => Source {
            url: url.clone(),
            token: token.trim().to_string(),
            fleet_machine_id: String::new(),
        },
        (false, None, _) => bail!("give the setup code: grund join --url <instance> <code>"),
        (false, _, None) => bail!("give the instance: grund join --url <instance> <code>"),
    };
    let origin = origin(&source.url)?;
    let key = machine_key(&args.data_dir)?;
    let mut facts = facts();
    facts.fleet_machine_id = source.fleet_machine_id.clone();
    let request = enrollment_request(
        &origin,
        &source.token,
        &key,
        unix_now(),
        facts,
        args.name.as_deref().unwrap_or_default(),
    );
    let response = enroll(&http, &origin, &request).await?;
    let record = record(&origin, &response)?;
    write_record(&args.data_dir, &record)?;
    println!(
        "registered as {} ({}) in the {} pool of {}",
        record.name, record.machine_id, record.pool, record.instance_url
    );
    Ok(())
}

/// Where Linux systems keep their trusted certificate authorities.
pub const SYSTEM_ROOTS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// Whether this machine has a store of trusted certificate authorities: one
/// of [`SYSTEM_ROOTS`], or SSL_CERT_FILE.
pub fn has_system_roots() -> bool {
    std::env::var_os("SSL_CERT_FILE").is_some()
        || SYSTEM_ROOTS
            .iter()
            .any(|path| std::fs::metadata(path).is_ok_and(|m| m.len() > 0))
}

fn http_client() -> anyhow::Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .user_agent(concat!("grund-agent/", env!("CARGO_PKG_VERSION")));
    let builder = if has_system_roots() {
        builder
    } else {
        tracing::info!("no system certificate store; trusting the Mozilla roots built into grund");
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.use_preconfigured_tls(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    };
    builder.build().context("build the HTTP client")
}

/// The instance's origin (scheme, host, optional port), as the enrollment
/// proof signs it. Plain http only to a loopback address, as the contract
/// requires.
pub fn origin(url: &str) -> anyhow::Result<String> {
    let url = url.trim().trim_end_matches('/');
    let (scheme, authority) = url
        .split_once("://")
        .context("the instance URL needs a scheme, e.g. https://grund.example.com")?;
    anyhow::ensure!(
        !authority.is_empty() && !authority.contains('/') && !authority.contains('?'),
        "the instance URL must be an origin, with no path: {url}"
    );
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
        .map_or(authority, |(host, _)| host)
        .trim_start_matches('[')
        .trim_end_matches(']');
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match scheme {
        "https" => {}
        "http" if loopback => {}
        "http" => bail!("register over https; plain http is only for a loopback address"),
        other => bail!("the instance URL's scheme must be https, not {other}"),
    }
    Ok(format!("{scheme}://{authority}"))
}

/// The enrollment request, signed by the machine key over the instance's
/// origin, the time and the token's SHA-256 (grund-docs design/machines.md
/// §5.1).
pub fn enrollment_request(
    origin: &str,
    token: &str,
    key: &SigningKey,
    signed_at_unix: i64,
    facts: MachineFacts,
    requested_name: &str,
) -> EnrollMachineRequest {
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    let message = format!("grund-enroll-v1\n{origin}\n{signed_at_unix}\n{digest}");
    EnrollMachineRequest {
        token: token.to_string(),
        machine_public_key: key.verifying_key().to_bytes().to_vec(),
        signed_at_unix,
        signature: key.sign(message.as_bytes()).to_bytes().to_vec(),
        facts: buffa::MessageField::from(facts),
        requested_name: requested_name.to_string(),
        ..Default::default()
    }
}

async fn from_mmds(http: &reqwest::Client, address: &str) -> anyhow::Result<Source> {
    let base = format!("http://{address}");
    let session = http
        .put(format!("{base}/latest/api/token"))
        .header("X-metadata-token-ttl-seconds", "60")
        .send()
        .await
        .context("reach the metadata service")?
        .error_for_status()
        .context("open a metadata session")?
        .text()
        .await?;
    let document: serde_json::Value = http
        .get(format!("{base}/"))
        .header("X-metadata-token", session.trim())
        .header("Accept", "application/json")
        .send()
        .await
        .context("read the metadata")?
        .error_for_status()
        .context("read the metadata")?
        .json()
        .await
        .context("the metadata is not JSON")?;
    let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_string();
    let source = Source {
        url: text(&document["grund"]["url"]),
        token: text(&document["grund"]["enrollment_token"]),
        fleet_machine_id: text(&document["fleet"]["machine_id"]),
    };
    anyhow::ensure!(
        !source.url.is_empty() && !source.token.is_empty(),
        "the metadata has no grund assignment yet"
    );
    Ok(source)
}

async fn enroll(
    http: &reqwest::Client,
    origin: &str,
    request: &EnrollMachineRequest,
) -> anyhow::Result<EnrollMachineResponse> {
    let url = format!("{origin}/grund.agent.v1.MachineEnrollmentService/EnrollMachine");
    let body = request.encode_to_vec();
    let started = Instant::now();
    let mut wait = Duration::from_secs(1);
    loop {
        let attempt = http
            .post(&url)
            .header("Content-Type", "application/proto")
            .header("Connect-Protocol-Version", "1")
            .body(body.clone())
            .send()
            .await;
        let failure = match attempt {
            Ok(response) if response.status().is_success() => {
                let bytes = response.bytes().await?;
                return EnrollMachineResponse::decode_from_slice(&bytes)
                    .context("the instance answered something that is not a registration");
            }
            Ok(response) => {
                let error: serde_json::Value = response.json().await.unwrap_or_default();
                let code = error["code"].as_str().unwrap_or("unknown").to_string();
                let message = error["message"].as_str().unwrap_or_default().to_string();
                if code != "unavailable" {
                    let reason = reason(&error);
                    bail!(
                        "the instance refused to register this machine: {message} ({code}{reason})"
                    );
                }
                format!("the instance is unavailable: {message}")
            }
            Err(error) => format!("could not reach {origin}: {error}"),
        };
        if started.elapsed() + wait > RETRY_BUDGET {
            bail!(
                "{failure}; gave up after {} seconds",
                started.elapsed().as_secs()
            );
        }
        tracing::warn!("{failure}; retrying in {} ms", wait.as_millis());
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(Duration::from_secs(20)) + jitter();
    }
}

fn reason(error: &serde_json::Value) -> String {
    error["details"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|detail| detail["type"] == "grund.agent.v1.ErrorReason")
        .filter_map(|detail| detail["value"].as_str())
        .filter_map(|value| {
            STANDARD
                .decode(value)
                .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
                .ok()
        })
        .filter_map(|bytes| ErrorReason::decode_from_slice(&bytes).ok())
        .map(|reason| format!(", {}", reason.reason))
        .next()
        .unwrap_or_default()
}

fn jitter() -> Duration {
    let mut byte = [0u8; 1];
    getrandom::fill(&mut byte).expect("the operating system provides randomness");
    Duration::from_millis(u64::from(byte[0]) * 4)
}

fn pinned(key: Option<&PublicKey>) -> anyhow::Result<PinnedKey> {
    let key = key.context("the instance answered without a key to pin")?;
    anyhow::ensure!(key.public_key.len() == 32, "a pinned key is 32 bytes");
    Ok(PinnedKey {
        key_id: key.key_id.clone(),
        public_key: hex::encode(&key.public_key),
        purpose: match key.purpose.as_known() {
            Some(KeyPurpose::KEY_PURPOSE_INSTANCE) => "instance",
            Some(KeyPurpose::KEY_PURPOSE_MANAGEMENT) => "management",
            Some(KeyPurpose::KEY_PURPOSE_ORGANISATION) => "organisation",
            _ => bail!("the instance answered a key with no purpose"),
        }
        .to_string(),
    })
}

/// What the machine keeps of the instance's answer.
pub fn record(origin: &str, response: &EnrollMachineResponse) -> anyhow::Result<Record> {
    Ok(Record {
        machine_id: response.machine_id.clone(),
        name: response.machine_name.clone(),
        pool: match response.pool.as_known() {
            Some(Pool::POOL_MANAGEMENT) => "management",
            Some(Pool::POOL_ORGANISATION) => "organisation",
            _ => bail!("the instance answered no pool"),
        }
        .to_string(),
        organisation_id: response.organisation_id.clone(),
        instance_url: origin.to_string(),
        instance_key: pinned(response.instance_key.as_option())?,
        trust_key: pinned(response.trust_key.as_option())?,
        heartbeat_interval_seconds: response.heartbeat_interval_seconds,
        registered_at_unix: unix_now(),
    })
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn ensure_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))
}

/// The machine key: the one in `data_dir` if a registration was attempted
/// before, else a new one, written owner-only before anything is sent.
pub fn machine_key(data_dir: &Path) -> anyhow::Result<SigningKey> {
    let path = data_dir.join(KEY_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let seed: [u8; 32] = hex::decode(text.trim())
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .with_context(|| format!("{} is not a machine key", path.display()))?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure_dir(data_dir)?;
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("the operating system provides randomness");
            write_new(&path, &format!("{}\n", hex::encode(seed)))?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// The record of a registration, if this machine has one.
pub fn read_record(data_dir: &Path) -> anyhow::Result<Option<Record>> {
    let path = data_dir.join(RECORD_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            Ok(Some(serde_json::from_str(&text).with_context(|| {
                format!("{} is not a record", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn write_record(data_dir: &Path, record: &Record) -> anyhow::Result<()> {
    ensure_dir(data_dir)?;
    let path = data_dir.join(RECORD_FILE);
    let temporary = data_dir.join(format!(".{RECORD_FILE}.{}", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    write_new(&temporary, &serde_json::to_string_pretty(record)?)?;
    std::fs::rename(&temporary, &path).with_context(|| format!("write {}", path.display()))
}

fn write_new(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("write {}", path.display()))
}

/// What the machine says about itself. Informational: the instance
/// authorizes nothing from it.
pub fn facts() -> MachineFacts {
    let read = |path: &str| {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let memory_mib = read("/proc/meminfo")
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| {
            rest.trim()
                .trim_end_matches("kB")
                .trim()
                .parse::<i64>()
                .ok()
        })
        .map_or(0, |kib| kib / 1024);
    let os = read("/etc/os-release")
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|name| name.trim_matches('"').to_string())
        .unwrap_or_default();
    let cpu_model = read("/proc/cpuinfo")
        .lines()
        .find_map(|line| line.strip_prefix("model name"))
        .and_then(|rest| rest.split_once(':'))
        .map(|(_, name)| name.trim().to_string())
        .unwrap_or_default();
    MachineFacts {
        hostname: read("/proc/sys/kernel/hostname"),
        arch: std::env::consts::ARCH.to_string(),
        cpu_model,
        cpus: std::thread::available_parallelism().map_or(0, |n| n.get() as i32),
        memory_mib,
        disk_gib: 0,
        os,
        kernel: read("/proc/sys/kernel/osrelease"),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier};

    use super::*;

    #[test]
    fn an_origin_is_https_or_loopback_http_and_never_a_path() {
        assert_eq!(
            origin("https://grund.example.com/").unwrap(),
            "https://grund.example.com"
        );
        assert_eq!(
            origin("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(origin("http://[::1]:8080").unwrap(), "http://[::1]:8080");
        assert_eq!(origin("http://localhost").unwrap(), "http://localhost");
        for bad in [
            "http://grund.example.com",
            "http://10.0.0.5:8080",
            "https://grund.example.com/app",
            "ftp://grund.example.com",
            "grund.example.com",
        ] {
            assert!(origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_request_is_signed_over_origin_time_and_token_digest() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let request = enrollment_request(
            "https://grund.example.com",
            "grund_join_x",
            &key,
            1_790_000_000,
            MachineFacts::default(),
            "",
        );
        let digest = hex::encode(Sha256::digest(b"grund_join_x"));
        let message = format!("grund-enroll-v1\nhttps://grund.example.com\n1790000000\n{digest}");
        let signature = Signature::from_slice(&request.signature).unwrap();
        assert!(
            key.verifying_key()
                .verify(message.as_bytes(), &signature)
                .is_ok()
        );
        assert_eq!(
            request.machine_public_key,
            key.verifying_key().to_bytes().to_vec()
        );
    }

    #[test]
    fn the_machine_key_is_kept_owner_only_and_reused() {
        let dir = std::env::temp_dir().join(format!(
            "grund-agent-{}",
            unix_now() ^ i64::from(std::process::id())
        ));
        let first = machine_key(&dir).unwrap();
        let again = machine_key(&dir).unwrap();
        assert_eq!(first.to_bytes(), again.to_bytes());
        let mode = std::fs::metadata(dir.join(KEY_FILE)).unwrap().permissions();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_error_reason_is_read_from_the_connect_details() {
        let detail = ErrorReason {
            reason: "token_invalid".into(),
            ..Default::default()
        };
        let error = serde_json::json!({
            "code": "permission_denied",
            "details": [{"type": "grund.agent.v1.ErrorReason",
                         "value": base64::engine::general_purpose::STANDARD_NO_PAD.encode(detail.encode_to_vec())}],
        });
        assert_eq!(reason(&error), ", token_invalid");
    }
}
