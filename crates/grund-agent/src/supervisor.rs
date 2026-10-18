use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, bail, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use grund_domain::agent_updates::PublicBuild;
use grund_proto::grund::agent::v1::{
    BeginUpdateRequest, BeginUpdateResponse, PollUpdateRequest, PollUpdateResponse,
    ReportUpdateRequest, ReportUpdateResponse, SignedMachineUpdate,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    agent::Link,
    join::{self, Record},
};

const PACKAGES: &str = "https://git.kjuulh.io/api/packages/grund/generic/grund";
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const HEALTH_SECONDS: i64 = 120;
const SIGNATURE_PREFIX: &[u8] = b"grund-machine-update-v1\n";
const RUNTIME: &str = "/usr/local/lib/grund/agent";

/// The retained supervisor's machine-local settings. Candidates never replace it.
#[derive(Clone, Debug, clap::Args)]
pub struct SupervisorArgs {
    #[arg(
        long,
        env = "GRUND_AGENT_DATA_DIR",
        default_value = "/var/lib/grund/agent"
    )]
    pub data_dir: PathBuf,
    /// Print this executable's exact public identity without starting the supervisor.
    #[arg(long, hide = true)]
    pub identity: bool,
}

/// Machine-local following controls; only an explicit installer run enables following.
#[derive(Clone, Debug, clap::Args)]
pub struct FollowArgs {
    #[arg(
        long,
        env = "GRUND_AGENT_DATA_DIR",
        default_value = "/var/lib/grund/agent"
    )]
    pub data_dir: PathBuf,
    #[command(subcommand)]
    pub command: FollowCommand,
}

/// Local policy changes cannot enable a machine that has not been bootstrapped.
#[derive(Clone, Debug, clap::Subcommand)]
pub enum FollowCommand {
    Status,
    Pause,
    Resume,
}

/// An explicit local opt-in, never writable by the instance or a tenant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FollowPolicy {
    pub enabled: bool,
    pub paused: bool,
}

/// A completed control round from one particular agent process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub machine_id: String,
    pub registration_key: String,
    pub boot_id: Uuid,
    pub revision: String,
    pub ready: bool,
    pub observed_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Offer {
    kind: String,
    attempt_id: Uuid,
    machine_id: Uuid,
    registration_key: String,
    generation: u64,
    previous_revision: String,
    target: PublicBuild,
    expires_at_unix: i64,
    #[serde(default)]
    boot_id: Option<Uuid>,
    #[serde(default)]
    permit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Authorizing,
    Authorized,
    Candidate,
    Committed,
    RollingBack,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Journal {
    offer: Offer,
    phase: Phase,
    previous_sha256: String,
    candidate_sha256: String,
    previous_boot_id: Uuid,
    candidate_boot_id: Option<Uuid>,
    #[serde(default)]
    rollback_boot_id: Option<Uuid>,
    started_at_unix: i64,
    failure_code: String,
    restart_completed: bool,
    finalize: Option<KeptPermit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeptPermit {
    payload: Vec<u8>,
    signature: Vec<u8>,
    key_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Status {
    state: String,
    target_revision: Option<String>,
    failure_code: Option<String>,
    observed_at_unix: i64,
}

/// The exact public build identity; hosted private-only changes are not agent targets.
pub fn public_revision() -> &'static str {
    grund_domain::agent_updates::public_revision(env!("GRUND_BUILD_REVISION")).unwrap_or("unknown")
}

/// Durably publishes a successful control round without copying credentials or desired state.
pub fn record_health(data_dir: &Path, health: &Health) -> anyhow::Result<()> {
    if !data_dir.join("follow.json").is_file() {
        return Ok(());
    }
    atomic_json(&data_dir.join("update-health.json"), health)
}

/// Prints local policy and observed update state, or explicitly pauses/resumes an existing opt-in.
pub fn policy(args: &FollowArgs) -> anyhow::Result<()> {
    require_root()?;
    safe_directory(&args.data_dir)?;
    let path = args.data_dir.join("follow.json");
    let _lock = if matches!(args.command, FollowCommand::Status) {
        None
    } else {
        Some(lock()?)
    };
    let mut policy: FollowPolicy = read_json(&path)?.unwrap_or_default();
    if !matches!(args.command, FollowCommand::Status) {
        ensure!(
            policy.enabled,
            "following is not bootstrapped; rerun the verified installer explicitly"
        );
        policy.paused = matches!(args.command, FollowCommand::Pause);
        atomic_json(&path, &policy)?;
    }
    let status: Option<Status> = read_json(&args.data_dir.join("follow-status.json"))?;
    let journal: Option<Journal> = read_json(&args.data_dir.join("update-journal.json"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "enabled": policy.enabled, "paused": policy.paused,
            "status": status, "active_attempt": journal.as_ref().map(|j| j.offer.attempt_id),
            "phase": journal.as_ref().map(|j| j.phase),
        }))?
    );
    Ok(())
}

/// Runs independently of the replaceable agent and retries durable reports after lost acknowledgements.
pub async fn run(args: &SupervisorArgs) -> anyhow::Result<()> {
    if args.identity {
        println!("{}", serde_json::json!({"revision": public_revision()}));
        return Ok(());
    }
    require_root()?;
    safe_directory(&args.data_dir)?;
    safe_directory(Path::new(RUNTIME))?;
    grund_crypto::install_default();
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = interval.tick() => {
                if let Err(error) = pass(args).await {
                    tracing::warn!(error = %error, "machine following deferred; the durable attempt remains reserved");
                }
            }
        }
    }
}

async fn pass(args: &SupervisorArgs) -> anyhow::Result<()> {
    let _lock = match lock() {
        Ok(lock) => lock,
        Err(_) => return Ok(()),
    };
    let Some(record) = join::read_record(&args.data_dir)? else {
        return Ok(());
    };
    let link = Link::from_record(&record, &args.data_dir)?;
    let registration_key = hex::encode(
        join::machine_key(&args.data_dir)?
            .verifying_key()
            .to_bytes(),
    );
    let journal_path = args.data_dir.join("update-journal.json");
    if let Some(mut journal) = read_json::<Journal>(&journal_path)? {
        ensure!(
            journal.offer.machine_id.to_string() == record.machine_id
                && journal.offer.registration_key == registration_key,
            "registration changed during an unresolved update; manual recovery required"
        );
        return advance(args, &record, &link, &mut journal).await;
    }
    let policy: FollowPolicy = read_json(&args.data_dir.join("follow.json"))?.unwrap_or_default();
    if !policy.enabled || policy.paused {
        return Ok(());
    }
    let Some(health) = read_json::<Health>(&args.data_dir.join("update-health.json"))? else {
        return Ok(());
    };
    ensure!(
        healthy(
            &health,
            &record.machine_id,
            &registration_key,
            &health.revision
        ),
        "no fresh healthy agent boot"
    );
    let response: PollUpdateResponse = link
        .call_service(
            "MachineUpdateService",
            "PollUpdate",
            &PollUpdateRequest {
                following: true,
                architecture: std::env::consts::ARCH.to_string(),
                revision: health.revision.clone(),
                boot_id: health.boot_id.to_string(),
                ..Default::default()
            },
        )
        .await?;
    let Some(envelope) = response.offer.as_option() else {
        set_status(&args.data_dir, "waiting", None, None)?;
        return Ok(());
    };
    let offer = verify_envelope(&record, envelope)?;
    ensure!(
        offer.kind == "offer" && !offer.permit && offer.expires_at_unix > now(),
        "expired or invalid update offer"
    );
    ensure!(
        offer.machine_id.to_string() == record.machine_id
            && offer.registration_key == registration_key
            && offer.previous_revision == health.revision,
        "offer does not match this registration and running revision"
    );
    ensure!(
        binary_revision(&Path::new(RUNTIME).join("grund")).await? == health.revision,
        "running boot and previous executable identities differ"
    );
    let candidate = Path::new(RUNTIME).join("update-candidate");
    match download_candidate(&offer.target, &candidate).await {
        Ok(candidate_sha256) => {
            let previous = Path::new(RUNTIME).join("update-previous");
            remove_regular(&previous)?;
            fs::hard_link(Path::new(RUNTIME).join("grund"), &previous)
                .context("retain previous runtime")?;
            File::open(&previous)?.sync_all()?;
            sync_parent(&previous)?;
            let mut journal = Journal {
                previous_sha256: hash_file(&previous)?,
                candidate_sha256,
                previous_boot_id: health.boot_id,
                candidate_boot_id: None,
                rollback_boot_id: None,
                offer,
                phase: Phase::Authorizing,
                started_at_unix: now(),
                failure_code: String::new(),
                restart_completed: false,
                finalize: None,
            };
            atomic_json(&journal_path, &journal)?;
            advance(args, &record, &link, &mut journal).await
        }
        Err(_) => {
            remove_regular(&candidate)?;
            set_status(
                &args.data_dir,
                "unavailable",
                Some(&offer.target.revision),
                Some("artifact_unavailable"),
            )
        }
    }
}

async fn advance(
    args: &SupervisorArgs,
    record: &Record,
    link: &Link,
    journal: &mut Journal,
) -> anyhow::Result<()> {
    let path = args.data_dir.join("update-journal.json");
    if journal.phase == Phase::Authorizing {
        let policy: FollowPolicy =
            read_json(&args.data_dir.join("follow.json"))?.unwrap_or_default();
        if !policy.enabled || policy.paused {
            set_status(
                &args.data_dir,
                "paused",
                Some(&journal.offer.target.revision),
                None,
            )?;
            return Ok(());
        }
        let answer: BeginUpdateResponse = link
            .call_service(
                "MachineUpdateService",
                "BeginUpdate",
                &BeginUpdateRequest {
                    attempt_id: journal.offer.attempt_id.to_string(),
                    generation: journal.offer.generation,
                    boot_id: journal.previous_boot_id.to_string(),
                    ..Default::default()
                },
            )
            .await?;
        if !answer.authorized {
            return finish(&args.data_dir, journal, "offer_cancelled");
        }
        journal.phase = Phase::Authorized;
        journal.started_at_unix = now();
        atomic_json(&path, journal)?;
    }
    if journal.phase == Phase::Authorized {
        let runtime = Path::new(RUNTIME).join("grund");
        let actual = hash_file(&runtime).ok();
        if actual.as_deref() == Some(journal.previous_sha256.as_str()) {
            let candidate = Path::new(RUNTIME).join("update-candidate");
            if hash_file(&candidate).ok().as_deref() != Some(journal.candidate_sha256.as_str()) {
                return begin_rollback(args, link, journal, "verification").await;
            }
            fs::rename(&candidate, &runtime)?;
            sync_parent(&runtime)?;
        } else if actual.as_deref() != Some(journal.candidate_sha256.as_str()) {
            return begin_rollback(args, link, journal, "local_state").await;
        }
        journal.phase = Phase::Candidate;
        journal.restart_completed = false;
        atomic_json(&path, journal)?;
    }
    if journal.phase == Phase::Candidate {
        if !journal.restart_completed {
            if restart_agent().await.is_err() {
                return begin_rollback(args, link, journal, "restart").await;
            }
            journal.restart_completed = true;
            atomic_json(&path, journal)?;
        }
        if let Some(health) = matching_health(&args.data_dir, journal, false)? {
            journal.candidate_boot_id = Some(health.boot_id);
            atomic_json(&path, journal)?;
            let result = report(link, journal, "candidate_health", &health).await;
            if let Ok(answer) = result
                && answer.accepted
                && let Some(envelope) = answer.finalize.as_option()
            {
                let verified = verify_envelope(record, envelope)
                    .and_then(|permit| verify_finalize(&permit, &journal.offer, health.boot_id));
                if verified.is_ok() {
                    journal.phase = Phase::Committed;
                    journal.finalize = Some(KeptPermit {
                        payload: envelope.payload.to_vec(),
                        signature: envelope.signature.to_vec(),
                        key_id: envelope.key_id.clone(),
                    });
                    atomic_json(&path, journal)?;
                } else {
                    set_status(
                        &args.data_dir,
                        "candidate",
                        Some(&journal.offer.target.revision),
                        Some("verification"),
                    )?;
                }
            }
        }
        if journal.phase == Phase::Candidate && now() - journal.started_at_unix >= HEALTH_SECONDS {
            return begin_rollback(args, link, journal, "health").await;
        }
    }
    if journal.phase == Phase::Committed {
        let health = Health {
            machine_id: journal.offer.machine_id.to_string(),
            registration_key: journal.offer.registration_key.clone(),
            boot_id: journal
                .candidate_boot_id
                .context("committed update has no bound boot")?,
            revision: journal.offer.target.revision.clone(),
            ready: true,
            observed_at_unix: now(),
        };
        let answer = report(link, journal, "committed", &health).await?;
        ensure!(answer.accepted, "durable commit report was not accepted");
        finish(&args.data_dir, journal, "committed")?;
    } else if journal.phase == Phase::RollingBack {
        restore_previous(Path::new(RUNTIME), journal)?;
        if !journal.restart_completed {
            restart_agent().await?;
            journal.restart_completed = true;
            atomic_json(&path, journal)?;
        }
        if let Some(health) = matching_health(&args.data_dir, journal, true)? {
            journal.rollback_boot_id = Some(health.boot_id);
            journal.phase = Phase::RolledBack;
            atomic_json(&path, journal)?;
        } else {
            report_failure(link, journal).await;
        }
    }
    if journal.phase == Phase::RolledBack {
        let health = Health {
            machine_id: journal.offer.machine_id.to_string(),
            registration_key: journal.offer.registration_key.clone(),
            boot_id: journal
                .rollback_boot_id
                .context("verified rollback has no bound boot")?,
            revision: journal.offer.previous_revision.clone(),
            ready: true,
            observed_at_unix: now(),
        };
        let answer = report(link, journal, "rolled_back", &health).await?;
        ensure!(answer.accepted, "durable rollback report was not accepted");
        finish(&args.data_dir, journal, "rolled_back")?;
    }
    Ok(())
}

async fn begin_rollback(
    args: &SupervisorArgs,
    link: &Link,
    journal: &mut Journal,
    failure: &str,
) -> anyhow::Result<()> {
    journal.phase = Phase::RollingBack;
    journal.failure_code = failure.to_string();
    journal.restart_completed = false;
    atomic_json(&args.data_dir.join("update-journal.json"), journal)?;
    let mut policy: FollowPolicy =
        read_json(&args.data_dir.join("follow.json"))?.unwrap_or_default();
    policy.paused = true;
    atomic_json(&args.data_dir.join("follow.json"), &policy)?;
    report_failure(link, journal).await;
    restore_previous(Path::new(RUNTIME), journal)?;
    restart_agent().await?;
    journal.restart_completed = true;
    atomic_json(&args.data_dir.join("update-journal.json"), journal)?;
    set_status(
        &args.data_dir,
        "rolling_back",
        Some(&journal.offer.target.revision),
        Some(failure),
    )
}

fn restore_previous(directory: &Path, journal: &Journal) -> anyhow::Result<()> {
    let previous = directory.join("update-previous");
    ensure!(
        hash_file(&previous)? == journal.previous_sha256,
        "previous executable does not match durable journal"
    );
    let runtime = directory.join("grund");
    if hash_file(&runtime).ok().as_deref() != Some(journal.previous_sha256.as_str()) {
        let restored = directory.join("update-restored");
        remove_regular(&restored)?;
        fs::hard_link(&previous, &restored)?;
        fs::rename(&restored, &runtime)?;
        sync_parent(&runtime)?;
    }
    Ok(())
}

fn matching_health(
    data_dir: &Path,
    journal: &Journal,
    rollback: bool,
) -> anyhow::Result<Option<Health>> {
    let Some(health) = read_json::<Health>(&data_dir.join("update-health.json"))? else {
        return Ok(None);
    };
    let revision = if rollback {
        &journal.offer.previous_revision
    } else {
        &journal.offer.target.revision
    };
    Ok((healthy(
        &health,
        &journal.offer.machine_id.to_string(),
        &journal.offer.registration_key,
        revision,
    ) && health.boot_id != journal.previous_boot_id
        && (!rollback || Some(health.boot_id) != journal.candidate_boot_id))
        .then_some(health))
}

fn healthy(health: &Health, machine: &str, registration: &str, revision: &str) -> bool {
    health.ready
        && health.machine_id == machine
        && health.registration_key == registration
        && health.revision == revision
        && (0..=30).contains(&(now() - health.observed_at_unix))
}

async fn report(
    link: &Link,
    journal: &Journal,
    phase: &str,
    health: &Health,
) -> anyhow::Result<ReportUpdateResponse> {
    link.call_service(
        "MachineUpdateService",
        "ReportUpdate",
        &ReportUpdateRequest {
            attempt_id: journal.offer.attempt_id.to_string(),
            generation: journal.offer.generation,
            phase: phase.to_string(),
            boot_id: health.boot_id.to_string(),
            revision: health.revision.clone(),
            failure_code: journal.failure_code.clone(),
            ..Default::default()
        },
    )
    .await
}

async fn report_failure(link: &Link, journal: &Journal) {
    let health = Health {
        machine_id: journal.offer.machine_id.to_string(),
        registration_key: journal.offer.registration_key.clone(),
        boot_id: journal
            .candidate_boot_id
            .unwrap_or(journal.previous_boot_id),
        revision: journal.offer.target.revision.clone(),
        ready: false,
        observed_at_unix: now(),
    };
    let _ = report(link, journal, "failed", &health).await;
}

fn finish(data_dir: &Path, journal: &Journal, state: &str) -> anyhow::Result<()> {
    set_status(
        data_dir,
        state,
        Some(&journal.offer.target.revision),
        (!journal.failure_code.is_empty()).then_some(journal.failure_code.as_str()),
    )?;
    remove_regular(&data_dir.join("update-journal.json"))?;
    sync_parent(&data_dir.join("update-journal.json"))?;
    remove_regular(&Path::new(RUNTIME).join("update-previous"))?;
    remove_regular(&Path::new(RUNTIME).join("update-candidate"))?;
    sync_parent(&Path::new(RUNTIME).join("grund"))
}

fn verify_envelope(record: &Record, envelope: &SignedMachineUpdate) -> anyhow::Result<Offer> {
    ensure!(
        envelope.payload.len() <= 8192 && envelope.key_id == record.trust_key.key_id,
        "invalid update signing key or payload"
    );
    let bytes: [u8; 32] = hex::decode(&record.trust_key.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid pinned key"))?;
    let key = VerifyingKey::from_bytes(&bytes)?;
    let signature = Signature::from_slice(&envelope.signature)?;
    let mut message = Vec::with_capacity(SIGNATURE_PREFIX.len() + envelope.payload.len());
    message.extend_from_slice(SIGNATURE_PREFIX);
    message.extend_from_slice(&envelope.payload);
    key.verify_strict(&message, &signature)
        .context("update signature did not verify")?;
    let offer: Offer = serde_json::from_slice(&envelope.payload)?;
    PublicBuild::new(offer.target.revision.clone(), offer.target.package.clone())?;
    Ok(offer)
}

fn verify_finalize(permit: &Offer, offer: &Offer, boot: Uuid) -> anyhow::Result<()> {
    ensure!(
        permit.kind == "finalize"
            && permit.permit
            && permit.boot_id == Some(boot)
            && permit.expires_at_unix > now()
            && permit.attempt_id == offer.attempt_id
            && permit.machine_id == offer.machine_id
            && permit.registration_key == offer.registration_key
            && permit.generation == offer.generation
            && permit.previous_revision == offer.previous_revision
            && permit.target == offer.target,
        "finalize permit does not bind this candidate boot and attempt"
    );
    Ok(())
}

async fn restart_agent() -> anyhow::Result<()> {
    let status = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("systemctl")
            .args(["restart", "grund-agent.service"])
            .kill_on_drop(true)
            .status(),
    )
    .await
    .context("agent restart exceeded deadline")??;
    ensure!(status.success(), "agent restart failed");
    Ok(())
}

async fn download_candidate(build: &PublicBuild, destination: &Path) -> anyhow::Result<String> {
    PublicBuild::new(build.revision.clone(), build.package.clone())?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()?;
    let base = format!("{PACKAGES}/{}", build.package);
    let (file, digest) = if build.package.starts_with("main-") {
        ensure!(
            std::env::consts::ARCH == "x86_64",
            "public main packages do not support this architecture"
        );
        let digest = fetch_small(&client, &format!("{base}/grund.sha256")).await?;
        let digest = std::str::from_utf8(&digest)?.trim().to_string();
        validate_digest(&digest)?;
        ("grund".to_string(), digest)
    } else {
        let sums = fetch_small(&client, &format!("{base}/SHA256SUMS")).await?;
        let sums = std::str::from_utf8(&sums)?;
        let revision = fetch_small(&client, &format!("{base}/release.txt")).await?;
        ensure!(
            hex::encode(Sha256::digest(&revision)) == checksum(sums, "release.txt")?,
            "release identity checksum mismatch"
        );
        ensure!(
            std::str::from_utf8(&revision)? == format!("{}\n", build.revision),
            "public release names another revision"
        );
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => bail!("unsupported architecture"),
        };
        let file = format!("grund-linux-{arch}");
        let digest = checksum(sums, &file)?;
        (file, digest)
    };
    remove_regular(destination)?;
    let file_handle = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)?;
    let mut file_handle = tokio::fs::File::from_std(file_handle);
    let mut response = client
        .get(format!("{base}/{file}"))
        .send()
        .await?
        .error_for_status()?;
    ensure!(response.status().is_success(), "public package refused");
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= MAX_BINARY_BYTES),
        "public binary is too large"
    );
    let mut hash = Sha256::new();
    let mut total = 0u64;
    while let Some(chunk) = response.chunk().await? {
        total += chunk.len() as u64;
        ensure!(
            total <= MAX_BINARY_BYTES,
            "public binary exceeded size bound"
        );
        hash.update(&chunk);
        file_handle.write_all(&chunk).await?;
    }
    ensure!(
        total > 0 && hex::encode(hash.finalize()) == digest,
        "public binary checksum mismatch"
    );
    file_handle.sync_all().await?;
    drop(file_handle);
    ensure!(
        binary_revision(destination).await? == build.revision,
        "candidate reports another public revision"
    );
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    File::open(destination)?.sync_all()?;
    sync_parent(destination)?;
    Ok(digest)
}

async fn binary_revision(binary: &Path) -> anyhow::Result<String> {
    use tokio::io::AsyncReadExt;
    let mut command = tokio::process::Command::new(binary);
    command
        .args(["agent-supervisor", "--identity"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .context("candidate has no identity output")?
        .take(8193);
    let exchange = async {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await?;
        ensure!(
            bytes.len() <= 8192,
            "candidate identity exceeded size bound"
        );
        ensure!(
            child.wait().await?.success(),
            "candidate cannot report its exact public identity"
        );
        let identity: serde_json::Value = serde_json::from_slice(&bytes)?;
        Ok::<_, anyhow::Error>(
            identity["revision"]
                .as_str()
                .context("candidate has no exact public revision")?
                .to_string(),
        )
    };
    tokio::time::timeout(Duration::from_secs(15), exchange)
        .await
        .context("candidate identity timed out")?
}

async fn fetch_small(client: &reqwest::Client, url: &str) -> anyhow::Result<Vec<u8>> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    ensure!(
        response.status().is_success(),
        "public metadata unavailable"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 1024 * 1024,
            "public metadata exceeded size bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn checksum(sums: &str, name: &str) -> anyhow::Result<String> {
    let mut result = None;
    for line in sums.lines() {
        let mut fields = line.split_whitespace();
        let Some(digest) = fields.next() else {
            continue;
        };
        let Some(file) = fields.next() else {
            continue;
        };
        if file.strip_prefix('*').unwrap_or(file) == name {
            ensure!(
                result.is_none() && fields.next().is_none(),
                "ambiguous public checksum entry"
            );
            validate_digest(digest)?;
            result = Some(digest.to_string());
        }
    }
    result.context("public checksum entry missing")
}

fn validate_digest(digest: &str) -> anyhow::Result<()> {
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid public checksum"
    );
    Ok(())
}

fn hash_file(path: &Path) -> anyhow::Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn set_status(
    data_dir: &Path,
    state: &str,
    target: Option<&str>,
    failure: Option<&str>,
) -> anyhow::Result<()> {
    atomic_json(
        &data_dir.join("follow-status.json"),
        &Status {
            state: state.to_string(),
            target_revision: target.map(str::to_string),
            failure_code: failure.map(str::to_string),
            observed_at_unix: now(),
        },
    )
}

fn require_root() -> anyhow::Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "machine following controls require root; no changes made"
    );
    Ok(())
}

fn safe_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "machine following requires a root-owned, non-writable real directory"
    );
    Ok(())
}

pub(crate) fn lock() -> anyhow::Result<File> {
    let parent = Path::new("/var/lib/grund");
    safe_directory(parent)?;
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(parent.join(".update.lock"))?;
    file.try_lock()
        .context("another installation or machine update holds the local lock")?;
    Ok(file)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        file.metadata()?.len() <= 65536,
        "local update state exceeded size bound"
    );
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn atomic_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    let parent = path.parent().context("local state has no parent")?;
    let temporary = parent.join(format!(".update-{}.tmp", Uuid::now_v7()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_parent(path: &Path) -> anyhow::Result<()> {
    File::open(path.parent().context("path has no parent")?)?.sync_all()?;
    Ok(())
}

fn remove_regular(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file(),
                "refusing to remove non-regular update state"
            );
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_or_missing_checksums_never_authorize_a_candidate() {
        let digest = "a".repeat(64);
        assert!(checksum(&format!("{digest}  grund\n{digest}  grund\n"), "grund").is_err());
        assert!(checksum(&format!("{digest}  other\n"), "grund").is_err());
        assert_eq!(
            checksum(&format!("{digest}  grund\n"), "grund").unwrap(),
            digest
        );
        assert!(checksum("not-a-checksum  grund\n", "grund").is_err());
    }

    #[test]
    fn finalize_permits_bind_the_registration_attempt_generation_and_new_boot() {
        let offer = Offer {
            kind: "offer".into(),
            attempt_id: Uuid::now_v7(),
            machine_id: Uuid::now_v7(),
            registration_key: "a".repeat(64),
            generation: 7,
            previous_revision: "b".repeat(40),
            target: PublicBuild::new("c".repeat(40), format!("main-{}", "c".repeat(40))).unwrap(),
            expires_at_unix: now() + 60,
            boot_id: None,
            permit: false,
        };
        let boot = Uuid::now_v7();
        let mut permit = offer.clone();
        permit.kind = "finalize".into();
        permit.permit = true;
        permit.boot_id = Some(boot);
        assert!(verify_finalize(&permit, &offer, boot).is_ok());
        permit.generation += 1;
        assert!(verify_finalize(&permit, &offer, boot).is_err());
        permit.generation = offer.generation;
        assert!(verify_finalize(&permit, &offer, Uuid::now_v7()).is_err());
        permit.registration_key = "d".repeat(64);
        assert!(verify_finalize(&permit, &offer, boot).is_err());
    }

    #[test]
    fn stale_or_foreign_control_rounds_cannot_establish_health() {
        let mut health = Health {
            machine_id: "machine".into(),
            registration_key: "key".into(),
            boot_id: Uuid::now_v7(),
            revision: "revision".into(),
            ready: true,
            observed_at_unix: now(),
        };
        assert!(healthy(&health, "machine", "key", "revision"));
        assert!(!healthy(
            &health,
            "machine",
            "another-registration",
            "revision"
        ));
        health.observed_at_unix -= 31;
        assert!(!healthy(&health, "machine", "key", "revision"));
    }

    async fn a_lost_terminal_ack_preserves_the_original_verified_boot(phase: Phase) {
        use buffa::Message;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        grund_crypto::install_default();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let mut reports = Vec::new();
            for _ in 0..2 {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0u8; 4096];
                let (body_start, length) = loop {
                    let size = connection.read(&mut chunk).await.unwrap();
                    assert!(size != 0 && bytes.len() + size <= 65536);
                    bytes.extend_from_slice(&chunk[..size]);
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        break (end + 4, length);
                    }
                };
                while bytes.len() < body_start + length {
                    let size = connection.read(&mut chunk).await.unwrap();
                    assert!(size != 0 && bytes.len() + size <= 65536);
                    bytes.extend_from_slice(&chunk[..size]);
                }
                reports.push(
                    ReportUpdateRequest::decode_from_slice(&bytes[body_start..body_start + length])
                        .unwrap(),
                );
                connection.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
            }
            reports
        });
        let data_dir = std::env::temp_dir().join(format!("grund-update-{}", Uuid::now_v7()));
        let key = join::machine_key(&data_dir).unwrap();
        let pinned = join::PinnedKey {
            key_id: Uuid::now_v7().to_string(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            purpose: "organisation".into(),
        };
        let record = Record {
            machine_id: Uuid::now_v7().to_string(),
            name: "update-test".into(),
            pool: "organisation".into(),
            organisation_id: Uuid::now_v7().to_string(),
            instance_url: format!("http://{address}"),
            instance_key: pinned.clone(),
            trust_key: pinned,
            heartbeat_interval_seconds: 5,
            registered_at_unix: now(),
            network: None,
        };
        let link = Link::from_record(&record, &data_dir).unwrap();
        let mut journal = Journal {
            offer: Offer {
                kind: "offer".into(),
                attempt_id: Uuid::now_v7(),
                machine_id: record.machine_id.parse().unwrap(),
                registration_key: hex::encode(key.verifying_key().to_bytes()),
                generation: 1,
                previous_revision: "a".repeat(40),
                target: PublicBuild::main(&"b".repeat(40)).unwrap(),
                expires_at_unix: now() - 3600,
                boot_id: None,
                permit: false,
            },
            phase,
            previous_sha256: "c".repeat(64),
            candidate_sha256: "d".repeat(64),
            previous_boot_id: Uuid::now_v7(),
            candidate_boot_id: Some(Uuid::now_v7()),
            rollback_boot_id: Some(Uuid::now_v7()),
            started_at_unix: now() - 3600,
            failure_code: String::new(),
            restart_completed: true,
            finalize: None,
        };
        use ed25519_dalek::Signer;
        let mut permit = journal.offer.clone();
        permit.kind = "finalize".into();
        permit.boot_id = journal.candidate_boot_id;
        permit.permit = true;
        let payload = serde_json::to_vec(&permit).unwrap();
        let mut message = SIGNATURE_PREFIX.to_vec();
        message.extend_from_slice(&payload);
        journal.finalize = Some(KeptPermit {
            payload,
            signature: key.sign(&message).to_bytes().to_vec(),
            key_id: record.trust_key.key_id.clone(),
        });
        let path = data_dir.join("update-journal.json");
        atomic_json(&path, &journal).unwrap();
        let durable = fs::read(&path).unwrap();
        let args = SupervisorArgs {
            data_dir: data_dir.clone(),
            identity: false,
        };
        assert!(advance(&args, &record, &link, &mut journal).await.is_err());
        assert_eq!(journal.phase, phase);
        assert_eq!(fs::read(&path).unwrap(), durable);
        let mut recovered = read_json::<Journal>(&path).unwrap().unwrap();
        let current_boot = Uuid::now_v7();
        atomic_json(
            &data_dir.join("update-health.json"),
            &Health {
                machine_id: record.machine_id.clone(),
                registration_key: journal.offer.registration_key.clone(),
                boot_id: current_boot,
                revision: journal.offer.previous_revision.clone(),
                ready: true,
                observed_at_unix: now(),
            },
        )
        .unwrap();
        assert!(
            advance(&args, &record, &link, &mut recovered)
                .await
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), durable);
        let expected_boot = if phase == Phase::Committed {
            journal.candidate_boot_id.unwrap()
        } else {
            journal.rollback_boot_id.unwrap()
        };
        assert_ne!(expected_boot, current_boot);
        for report in tokio::time::timeout(Duration::from_secs(5), peer)
            .await
            .unwrap()
            .unwrap()
        {
            assert_eq!(report.boot_id, expected_boot.to_string());
            assert_eq!(
                report.phase,
                if phase == Phase::Committed {
                    "committed"
                } else {
                    "rolled_back"
                }
            );
        }
        fs::remove_dir_all(data_dir).unwrap();
    }

    #[tokio::test]
    async fn a_lost_commit_ack_never_rebinds_after_an_agent_reboot() {
        a_lost_terminal_ack_preserves_the_original_verified_boot(Phase::Committed).await;
    }

    #[tokio::test]
    async fn a_lost_rollback_ack_never_rebinds_after_an_agent_reboot() {
        a_lost_terminal_ack_preserves_the_original_verified_boot(Phase::RolledBack).await;
    }

    #[test]
    fn rollback_restores_only_verified_executable_bytes_and_preserves_machine_state() {
        let directory = std::env::temp_dir().join(format!("grund-rollback-{}", Uuid::now_v7()));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("update-previous"), b"known-good-executable").unwrap();
        fs::write(directory.join("grund"), b"unhealthy-candidate").unwrap();
        fs::write(
            directory.join("machine.json"),
            b"current-registration-must-survive",
        )
        .unwrap();
        let journal = Journal {
            offer: Offer {
                kind: "offer".into(),
                attempt_id: Uuid::now_v7(),
                machine_id: Uuid::now_v7(),
                registration_key: "a".repeat(64),
                generation: 1,
                previous_revision: "b".repeat(40),
                target: PublicBuild::main(&"c".repeat(40)).unwrap(),
                expires_at_unix: now() + 60,
                boot_id: None,
                permit: false,
            },
            phase: Phase::RollingBack,
            previous_sha256: hash_file(&directory.join("update-previous")).unwrap(),
            candidate_sha256: hash_file(&directory.join("grund")).unwrap(),
            previous_boot_id: Uuid::now_v7(),
            candidate_boot_id: Some(Uuid::now_v7()),
            started_at_unix: now(),
            failure_code: "health".into(),
            rollback_boot_id: None,
            restart_completed: false,
            finalize: None,
        };
        restore_previous(&directory, &journal).unwrap();
        assert_eq!(
            fs::read(directory.join("grund")).unwrap(),
            b"known-good-executable"
        );
        assert_eq!(
            fs::read(directory.join("machine.json")).unwrap(),
            b"current-registration-must-survive"
        );
        fs::write(directory.join("update-previous"), b"corrupt-previous").unwrap();
        assert!(restore_previous(&directory, &journal).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
