//! `grund agent`: the long-running half of the machine agent (grund-docs
//! design/machines.md §7b). After `grund join`, it keeps the machine
//! connected: a heartbeat with what the machine can do, the machine's desired
//! state when it changes, verified against the organisation key pinned at
//! registration, the VMs that state asks for, and a report of what runs.
//!
//! Every request is signed by the machine key (the control link over HTTPS,
//! until it moves onto iroh). A document is applied only if it verifies, is
//! for this machine and organisation, is newer than the last one applied, and
//! asks for no feature this agent does not know; otherwise the agent keeps
//! the last good one and reports why.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use buffa::Message;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use grund_proto::grund::agent::v1::{
    Capabilities, DesiredState, GetDesiredStateRequest, GetDesiredStateResponse,
    GetMachineJoinTokenRequest, GetMachineJoinTokenResponse, HeartbeatRequest, HeartbeatResponse,
    ReportStatusRequest, ReportStatusResponse, VmDesiredState, VmObserved, VmObservedState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    join::{self, Record},
    vm::{self, Artifact, VmImage, VmRuntime, VmSpec, VmState, VmStatus},
};

/// Features this agent knows how to apply.
pub const KNOWN_FEATURES: &[&str] = &["machines"];

/// The largest document the agent decodes (apps.md §15).
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The file keeping what the agent applied last.
pub const APPLIED_FILE: &str = "applied.json";

/// `grund agent`.
#[derive(Clone, Debug, clap::Args)]
pub struct AgentArgs {
    /// Where `grund join` kept the machine's key and identity.
    #[arg(
        long,
        env = "GRUND_AGENT_DATA_DIR",
        default_value = "/var/lib/grund/agent"
    )]
    pub data_dir: PathBuf,

    /// One round (heartbeat, desired state, VMs, report), then exit.
    #[arg(long, hide = true)]
    pub once: bool,

    /// Seconds between rounds, instead of what the instance asks for.
    #[arg(long, hide = true)]
    pub interval: Option<u64>,
}

/// What the agent applied last, kept across restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Applied {
    pub generation: u64,
    /// The document's payload, as verified, hex.
    pub payload: String,
}

/// Why a document was not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    TooLarge,
    BadSignature,
    Malformed,
    WrongMachine,
    Older,
    UnknownFeature(String),
    NoTrustKey,
    /// Signed by a key other than the one pinned.
    UnknownKey,
    /// The document applied last, again: nothing to do, and nothing to
    /// report.
    Same,
    /// The same generation as the one applied, with different content: the
    /// instance signed two documents it should not have, a bug or a
    /// compromise (apps.md §6.3).
    Equivocation,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::TooLarge => f.write_str("document larger than 1 MiB"),
            Refusal::BadSignature => f.write_str("document signature does not verify"),
            Refusal::Malformed => f.write_str("document does not decode"),
            Refusal::WrongMachine => f.write_str("document is for another machine or organisation"),
            Refusal::Older => f.write_str("document is not newer than the one applied"),
            Refusal::UnknownFeature(name) => write!(f, "document requires unknown feature {name}"),
            Refusal::NoTrustKey => f.write_str("this machine pinned no organisation key"),
            Refusal::UnknownKey => f.write_str("document is signed by a key this machine did not pin"),
            Refusal::Same => f.write_str("document is the one applied"),
            Refusal::Equivocation => f.write_str(
                "EQUIVOCATION: a second, different document for the generation already applied; the instance signed two",
            ),
        }
    }
}

/// Verifies and decodes a signed document against the pinned organisation
/// key, for this machine, newer than what was applied. The same generation
/// again is [`Refusal::Same`] with the same payload and
/// [`Refusal::Equivocation`] with a different one; only a lower generation
/// is [`Refusal::Older`].
pub fn verify(
    record: &Record,
    trust: &VerifyingKey,
    key_id: &str,
    payload: &[u8],
    signature: &[u8],
    applied: &Applied,
) -> Result<DesiredState, Refusal> {
    if payload.len() > MAX_DOCUMENT_BYTES {
        return Err(Refusal::TooLarge);
    }
    if key_id != record.trust_key.key_id {
        return Err(Refusal::UnknownKey);
    }
    let signature = Signature::from_slice(signature).map_err(|_| Refusal::BadSignature)?;
    let mut message = b"grund-desired-state-v1\n".to_vec();
    message.extend_from_slice(payload);
    trust
        .verify_strict(&message, &signature)
        .map_err(|_| Refusal::BadSignature)?;
    let state = DesiredState::decode_from_slice(payload).map_err(|_| Refusal::Malformed)?;
    if state.machine_id != record.machine_id || state.organisation_id != record.organisation_id {
        return Err(Refusal::WrongMachine);
    }
    if state.generation < applied.generation {
        return Err(Refusal::Older);
    }
    if state.generation == applied.generation && applied.generation > 0 {
        let same = hex::decode(&applied.payload)
            .is_ok_and(|kept| Sha256::digest(&kept) == Sha256::digest(payload));
        return Err(if same {
            Refusal::Same
        } else {
            Refusal::Equivocation
        });
    }
    if let Some(unknown) = state
        .required_features
        .iter()
        .find(|f| !KNOWN_FEATURES.contains(&f.as_str()))
    {
        return Err(Refusal::UnknownFeature(unknown.clone()));
    }
    Ok(state)
}

struct Link {
    http: reqwest::Client,
    origin: String,
    machine_id: String,
    key: SigningKey,
}

impl Link {
    async fn call<Req: Message, Resp: Message>(
        &self,
        procedure: &str,
        request: &Req,
    ) -> anyhow::Result<Resp> {
        let path = format!("/grund.agent.v1.AgentService/{procedure}");
        let body = request.encode_to_vec();
        let signed_at = unix_now();
        let message = format!(
            "grund-agent-request-v1\n{path}\n{signed_at}\n{}",
            hex::encode(Sha256::digest(&body))
        );
        let signature = STANDARD.encode(self.key.sign(message.as_bytes()).to_bytes());
        let response = self
            .http
            .post(format!("{}{path}", self.origin))
            .header("Content-Type", "application/proto")
            .header("Connect-Protocol-Version", "1")
            .header("x-grund-machine", &self.machine_id)
            .header("x-grund-signed-at", signed_at.to_string())
            .header("x-grund-signature", signature)
            .body(body)
            .send()
            .await
            .with_context(|| format!("reach {}", self.origin))?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            bail!(
                "{procedure}: {} ({})",
                error["message"].as_str().unwrap_or("refused"),
                error["code"].as_str().unwrap_or("unknown")
            );
        }
        Resp::decode_from_slice(&bytes)
            .with_context(|| format!("{procedure}: an answer that does not decode"))
    }
}

/// Runs `grund agent` with `runtime` for VMs.
pub async fn run<R: VmRuntime>(args: &AgentArgs, runtime: R) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let record = join::read_record(&args.data_dir)?
        .context("this machine is not registered; run grund join first")?;
    let key = join::machine_key(&args.data_dir)?;
    let trust = trust_key(&record);
    let link = Link {
        http: join::http_client()?,
        origin: record.instance_url.clone(),
        machine_id: record.machine_id.clone(),
        key,
    };
    let mut applied = read_applied(&args.data_dir)?;
    tracing::info!(machine = %record.machine_id, name = %record.name, "agent running");
    loop {
        let interval = match round(
            &link,
            &record,
            trust.as_ref(),
            &runtime,
            &args.data_dir,
            &mut applied,
        )
        .await
        {
            Ok(seconds) => args.interval.unwrap_or(seconds.max(1) as u64),
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "round failed; trying again");
                args.interval.unwrap_or(5)
            }
        };
        if args.once {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

async fn round<R: VmRuntime>(
    link: &Link,
    record: &Record,
    trust: Option<&VerifyingKey>,
    runtime: &R,
    data_dir: &Path,
    applied: &mut Applied,
) -> anyhow::Result<i32> {
    let capabilities = runtime.capabilities().await;
    let beat: HeartbeatResponse = link
        .call(
            "Heartbeat",
            &HeartbeatRequest {
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                capabilities: buffa::MessageField::from(Capabilities {
                    kvm: capabilities.kvm,
                    root: capabilities.root,
                    egress: capabilities.egress,
                    free_vcpus: capabilities.free_vcpus,
                    free_memory_mib: capabilities.free_memory_mib,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await?;
    let mut refusals = Vec::new();
    if beat.generation > applied.generation {
        let answer: GetDesiredStateResponse = link
            .call(
                "GetDesiredState",
                &GetDesiredStateRequest {
                    since_generation: applied.generation,
                    ..Default::default()
                },
            )
            .await?;
        if let Some(document) = answer.document.as_option() {
            match trust.ok_or(Refusal::NoTrustKey).and_then(|trust| {
                verify(
                    record,
                    trust,
                    &document.key_id,
                    &document.payload,
                    &document.signature,
                    applied,
                )
            }) {
                Ok(state) => {
                    *applied = Applied {
                        generation: state.generation,
                        payload: hex::encode(&document.payload),
                    };
                    write_applied(data_dir, applied)?;
                    tracing::info!(generation = state.generation, "applied a new desired state");
                }
                Err(Refusal::Same) => {}
                Err(Refusal::Equivocation) => {
                    tracing::error!(
                        generation = applied.generation,
                        "the instance signed two different documents for one generation; keeping the one applied"
                    );
                    refusals.push(Refusal::Equivocation.to_string());
                }
                Err(refusal) => {
                    tracing::warn!(%refusal, "refused a desired state; keeping the last good one");
                    refusals.push(refusal.to_string());
                }
            }
        }
    }
    let desired = current(applied);
    let observed = converge(link, record, runtime, desired.as_ref()).await?;
    let _: ReportStatusResponse = link
        .call(
            "ReportStatus",
            &ReportStatusRequest {
                applied_generation: applied.generation,
                machines: observed.iter().map(observed_message).collect(),
                refusals,
                ..Default::default()
            },
        )
        .await?;
    Ok(beat.heartbeat_interval_seconds)
}

fn current(applied: &Applied) -> Option<DesiredState> {
    let payload = hex::decode(&applied.payload).ok()?;
    DesiredState::decode_from_slice(&payload).ok()
}

async fn converge<R: VmRuntime>(
    link: &Link,
    record: &Record,
    runtime: &R,
    desired: Option<&DesiredState>,
) -> anyhow::Result<Vec<VmStatus>> {
    let observed = runtime.observe().await?;
    let empty = Vec::new();
    let wanted = desired.map_or(&empty, |d| &d.machines);
    for vm in wanted {
        let current = observed.iter().find(|o| o.id == vm.vm_id);
        let running = matches!(
            current.map(|c| &c.state),
            Some(VmState::Running | VmState::Starting)
        );
        match vm.state.as_known() {
            Some(VmDesiredState::VM_DESIRED_STATE_RUNNING) if !running => {
                let token: Option<GetMachineJoinTokenResponse> = link
                    .call(
                        "GetMachineJoinToken",
                        &GetMachineJoinTokenRequest {
                            vm_id: vm.vm_id.clone(),
                            ..Default::default()
                        },
                    )
                    .await
                    .ok();
                let (token, expires_at) = token.map_or((String::new(), String::new()), |t| {
                    let expires = t
                        .expires_at
                        .as_option()
                        .map(|ts| ts.seconds.to_string())
                        .unwrap_or_default();
                    (t.token, expires)
                });
                let spec = spec(
                    vm,
                    vm::metadata(&vm.vm_id, &record.instance_url, &token, &expires_at),
                );
                match runtime.ensure(&spec).await {
                    Ok(status) => {
                        tracing::info!(vm = %vm.vm_id, state = ?status.state, "ensured a VM")
                    }
                    Err(error) => {
                        tracing::warn!(vm = %vm.vm_id, error = %format!("{error:#}"), "could not start a VM")
                    }
                }
            }
            Some(VmDesiredState::VM_DESIRED_STATE_STOPPED) if running => {
                runtime.stop(&vm.vm_id).await?;
            }
            _ => {}
        }
    }
    for status in &observed {
        let still_wanted = wanted.iter().any(|vm| vm.vm_id == status.id);
        if !still_wanted && matches!(status.state, VmState::Running | VmState::Starting) {
            runtime.stop(&status.id).await?;
        }
    }
    runtime.observe().await
}

fn spec(vm: &grund_proto::grund::agent::v1::Vm, mmds: serde_json::Value) -> VmSpec {
    let artifact = |a: Option<&grund_proto::grund::agent::v1::Artifact>| Artifact {
        url: a.map(|a| a.url.clone()).unwrap_or_default(),
        sha256: a.map(|a| a.sha256.clone()).unwrap_or_default(),
    };
    let image = vm.image.as_option();
    VmSpec {
        id: vm.vm_id.clone(),
        vcpus: vm.vcpus,
        memory_mib: vm.memory_mib,
        disk_gib: vm.disk_gib,
        image: VmImage {
            kernel: artifact(image.and_then(|i| i.kernel.as_option())),
            rootfs: artifact(image.and_then(|i| i.rootfs.as_option())),
        },
        mmds,
    }
}

fn observed_message(status: &VmStatus) -> VmObserved {
    let (state, reason, exit_code) = match &status.state {
        VmState::Starting => (
            VmObservedState::VM_OBSERVED_STATE_STARTING,
            String::new(),
            0,
        ),
        VmState::Running => (VmObservedState::VM_OBSERVED_STATE_RUNNING, String::new(), 0),
        VmState::Stopped => (VmObservedState::VM_OBSERVED_STATE_STOPPED, String::new(), 0),
        VmState::Exited { code } => (
            VmObservedState::VM_OBSERVED_STATE_EXITED,
            String::new(),
            code.unwrap_or(0),
        ),
        VmState::Failed { reason } => {
            (VmObservedState::VM_OBSERVED_STATE_FAILED, reason.clone(), 0)
        }
    };
    VmObserved {
        vm_id: status.id.clone(),
        state: state.into(),
        reason,
        exit_code,
        ..Default::default()
    }
}

fn trust_key(record: &Record) -> Option<VerifyingKey> {
    if record.trust_key.purpose != "organisation" {
        return None;
    }
    let bytes: [u8; 32] = hex::decode(&record.trust_key.public_key)
        .ok()?
        .try_into()
        .ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn read_applied(data_dir: &Path) -> anyhow::Result<Applied> {
    match std::fs::read_to_string(data_dir.join(APPLIED_FILE)) {
        Ok(text) => Ok(serde_json::from_str(&text).unwrap_or_default()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Applied::default()),
        Err(error) => Err(error).context("read the applied desired state"),
    }
}

fn write_applied(data_dir: &Path, applied: &Applied) -> anyhow::Result<()> {
    let temporary = data_dir.join(format!(".{APPLIED_FILE}.{}", std::process::id()));
    std::fs::write(&temporary, serde_json::to_vec(applied)?)?;
    std::fs::rename(&temporary, data_dir.join(APPLIED_FILE))
        .context("write the applied desired state")
}

#[cfg(test)]
mod tests {
    use grund_proto::grund::agent::v1::Vm;

    use super::*;
    use crate::join::PinnedKey;

    fn record(key: &SigningKey) -> Record {
        Record {
            machine_id: "m-1".into(),
            name: "box".into(),
            pool: "organisation".into(),
            organisation_id: "o-1".into(),
            instance_url: "https://grund.example.com".into(),
            instance_key: PinnedKey {
                key_id: "i".into(),
                public_key: hex::encode([0u8; 32]),
                purpose: "instance".into(),
            },
            trust_key: PinnedKey {
                key_id: "k".into(),
                public_key: hex::encode(key.verifying_key().to_bytes()),
                purpose: "organisation".into(),
            },
            heartbeat_interval_seconds: 5,
            registered_at_unix: 0,
        }
    }

    fn signed(key: &SigningKey, state: &DesiredState) -> (Vec<u8>, Vec<u8>) {
        let payload = state.encode_to_vec();
        let mut message = b"grund-desired-state-v1\n".to_vec();
        message.extend_from_slice(&payload);
        (payload, key.sign(&message).to_bytes().to_vec())
    }

    fn state(generation: u64) -> DesiredState {
        DesiredState {
            machine_id: "m-1".into(),
            organisation_id: "o-1".into(),
            generation,
            required_features: vec!["machines".into()],
            machines: vec![Vm {
                vm_id: "vm-1".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn applied(generation: u64, payload: &[u8]) -> Applied {
        Applied {
            generation,
            payload: hex::encode(payload),
        }
    }

    #[test]
    fn a_document_applies_only_when_signed_for_this_machine_newer_and_understood() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let record = record(&key);
        let trust = key.verifying_key();
        let none = Applied::default();
        let (payload, signature) = signed(&key, &state(2));
        assert_eq!(
            verify(&record, &trust, "k", &payload, &signature, &none)
                .unwrap()
                .generation,
            2
        );
        assert_eq!(
            verify(&record, &trust, "other", &payload, &signature, &none),
            Err(Refusal::UnknownKey)
        );

        let stranger = SigningKey::from_bytes(&[6; 32]);
        let (bad, bad_signature) = signed(&stranger, &state(3));
        assert_eq!(
            verify(&record, &trust, "k", &bad, &bad_signature, &none),
            Err(Refusal::BadSignature)
        );

        let mut other = state(3);
        other.machine_id = "m-2".into();
        let (bad, bad_signature) = signed(&key, &other);
        assert_eq!(
            verify(&record, &trust, "k", &bad, &bad_signature, &none),
            Err(Refusal::WrongMachine)
        );

        let mut newer = state(3);
        newer.required_features.push("volumes".into());
        let (bad, bad_signature) = signed(&key, &newer);
        assert_eq!(
            verify(&record, &trust, "k", &bad, &bad_signature, &none),
            Err(Refusal::UnknownFeature("volumes".into()))
        );

        let (mut bad, bad_signature) = signed(&key, &state(3));
        bad[0] ^= 1;
        assert_eq!(
            verify(&record, &trust, "k", &bad, &bad_signature, &none),
            Err(Refusal::BadSignature)
        );
    }

    #[test]
    fn the_same_generation_again_is_nothing_or_an_equivocation_and_only_a_lower_one_is_older() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let record = record(&key);
        let trust = key.verifying_key();
        let (payload, signature) = signed(&key, &state(2));
        let kept = applied(2, &payload);
        assert_eq!(
            verify(&record, &trust, "k", &payload, &signature, &kept),
            Err(Refusal::Same)
        );

        let mut twin = state(2);
        twin.machines.clear();
        let (other, other_signature) = signed(&key, &twin);
        assert_eq!(
            verify(&record, &trust, "k", &other, &other_signature, &kept),
            Err(Refusal::Equivocation)
        );

        let (older, older_signature) = signed(&key, &state(1));
        assert_eq!(
            verify(&record, &trust, "k", &older, &older_signature, &kept),
            Err(Refusal::Older)
        );
    }
}
