//! Reads PID1-only boot context; the agent never creates or repairs it.
//!
//! `/run/grund/guest-boot.json` is a root-owned, single-link, regular 0600
//! file in a root-owned 0700 directory on tmpfs. PID1 creates it exclusively
//! after registration and before starting the agent, once per OS boot.
//! Its exact JSON schema is `{version:1, vm_id:UUID, os_boot_id:UUID,
//! machine_id:UUID, machine_public_key:hex32, instance_url:string,
//! instance_key:{key_id,public_key,purpose}, trust_key:{key_id,public_key,purpose},
//! replacement:null|{attempt_id:UUID,sequence:u64,document_generation:u64,
//! guest_machine_id:UUID,launch_nonce:UUID}}`. UUIDs are nonnil canonical
//! lowercase strings; replacement counters are positive and at most i64::MAX.
//! Unknown fields are refused. Only public registration data is retained;
//! enrollment tokens, metadata sessions and private keys are never serialized.
//! A missing, untrusted, stale or mismatched marker produces no evidence and
//! does not run a resource probe. A valid marker never implies positive limits.

use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    time::Duration,
};

use grund_proto::grund::agent::v1::{GuestBootEvidence, ResourceLimitProof};
use serde::Deserialize;

use crate::{
    join::{PinnedKey, Record},
    runtime::ContainerRuntime,
};

const MAX_CONTEXT: u64 = 16 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    version: u32,
    vm_id: String,
    os_boot_id: String,
    machine_id: String,
    machine_public_key: String,
    instance_url: String,
    instance_key: ContextKey,
    trust_key: ContextKey,
    replacement: Option<Replacement>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextKey {
    key_id: String,
    public_key: String,
    purpose: String,
}

impl ContextKey {
    fn matches(&self, key: &PinnedKey) -> bool {
        self.key_id == key.key_id
            && self.public_key == key.public_key
            && self.purpose == key.purpose
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    attempt_id: String,
    sequence: u64,
    document_generation: u64,
    guest_machine_id: String,
    launch_nonce: String,
}

fn valid_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

fn context(bytes: &[u8], os_boot_id: &str, record: &Record, public_key: &str) -> Option<Context> {
    if bytes.len() as u64 > MAX_CONTEXT {
        return None;
    }
    let context: Context = serde_json::from_slice(bytes).ok()?;
    if context.version != 1
        || !valid_uuid(&context.vm_id)
        || !valid_uuid(&context.os_boot_id)
        || context.os_boot_id != os_boot_id
        || !valid_uuid(&context.machine_id)
        || context.machine_id != record.machine_id
        || context.machine_public_key != public_key
        || context.instance_url != record.instance_url
        || !context.instance_key.matches(&record.instance_key)
        || !context.trust_key.matches(&record.trust_key)
    {
        return None;
    }
    if let Some(replacement) = &context.replacement
        && (!valid_uuid(&replacement.attempt_id)
            || !valid_uuid(&replacement.launch_nonce)
            || replacement.guest_machine_id != record.machine_id
            || replacement.sequence == 0
            || replacement.sequence > i64::MAX as u64
            || replacement.document_generation == 0
            || replacement.document_generation > i64::MAX as u64)
    {
        return None;
    }
    Some(context)
}

fn protected(metadata: &std::fs::Metadata, mode: u32, directory: bool) -> bool {
    metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.mode() & 0o7777 == mode
        && if directory {
            metadata.is_dir()
        } else {
            metadata.is_file() && metadata.nlink() == 1
        }
}

fn read_bounded(file: File, limit: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= limit).then_some(bytes)
}

fn read_marker() -> Option<Vec<u8>> {
    let run = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run")
        .ok()?;
    let metadata = run.metadata().ok()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return None;
    }
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    let run_result = unsafe { libc::fstatfs(run.as_raw_fd(), &mut filesystem) };
    #[allow(clippy::unnecessary_cast)]
    let run_magic = filesystem.f_type as i64;
    if run_result != 0 || run_magic != libc::TMPFS_MAGIC {
        return None;
    }
    let directory = open_at(&run, c"grund", libc::O_DIRECTORY)?;
    if !protected(&directory.metadata().ok()?, 0o700, true) {
        return None;
    }
    let file = open_at(&directory, c"guest-boot.json", 0)?;
    if !protected(&file.metadata().ok()?, 0o600, false) {
        return None;
    }
    let mut marker_filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    let marker_result = unsafe { libc::fstatfs(file.as_raw_fd(), &mut marker_filesystem) };
    #[allow(clippy::unnecessary_cast)]
    let marker_magic = marker_filesystem.f_type as i64;
    if marker_result != 0 || marker_magic != libc::TMPFS_MAGIC {
        return None;
    }
    read_bounded(file, MAX_CONTEXT)
}

fn open_at(directory: &File, name: &std::ffi::CStr, flags: libc::c_int) -> Option<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | flags,
        )
    };
    (fd >= 0).then(|| unsafe { File::from_raw_fd(fd) })
}

fn current_public_key() -> Option<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/var/lib/grund/agent/machine.key")
        .ok()?;
    if !protected(&file.metadata().ok()?, 0o600, false) {
        return None;
    }
    let seed = read_bounded(file, 128)?;
    let seed: [u8; 32] = hex::decode(std::str::from_utf8(&seed).ok()?.trim())
        .ok()?
        .try_into()
        .ok()?;
    Some(hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    ))
}

fn compose(context: Context, resources: ResourceLimitProof) -> GuestBootEvidence {
    let (attempt_id, sequence, launch_nonce) = context
        .replacement
        .map(|replacement| {
            (
                replacement.attempt_id,
                replacement.sequence,
                replacement.launch_nonce,
            )
        })
        .unwrap_or_default();
    GuestBootEvidence {
        version: 1,
        vm_id: context.vm_id,
        attempt_id,
        sequence,
        launch_nonce,
        os_boot_id: context.os_boot_id,
        resources: buffa::MessageField::from(resources),
        ..Default::default()
    }
}

fn resource_evidence(
    proof: Option<crate::runtime::ResourceLimitProof>,
    timed_out: bool,
) -> ResourceLimitProof {
    match proof {
        Some(proof) => ResourceLimitProof {
            cpu_verified: proof.cpu_verified,
            memory_verified: proof.memory_verified,
            attachment_verified: proof.attachment_verified,
            failure_code: proof
                .failure
                .map(|failure| failure.code().to_string())
                .unwrap_or_default(),
            ..Default::default()
        },
        None => ResourceLimitProof {
            failure_code: if timed_out {
                "RESOURCE_PROBE_TIMEOUT"
            } else {
                "RESOURCE_PROBE_UNSUPPORTED"
            }
            .to_string(),
            ..Default::default()
        },
    }
}

/// Composes current-OS PID1 launch context with a fresh bounded resource probe.
///
/// Physical hosts and legacy guest images without protected context return
/// `None` without probing. This never creates boot context, prepares a runtime,
/// enables controllers, enrolls a machine or substitutes agent boot identity.
/// The runtime probe owns cancellation-safe cleanup; unsupported and timed-out
/// probes report negative evidence rather than manufacturing readiness.
pub async fn evidence<C: ContainerRuntime>(
    runtime: &C,
    record: &Record,
) -> Option<GuestBootEvidence> {
    let bytes = read_marker()?;
    let os_boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let public_key = current_public_key()?;
    let context = context(&bytes, os_boot_id.trim(), record, &public_key)?;
    let resources = match tokio::time::timeout(PROBE_TIMEOUT, runtime.resource_limit_probe()).await
    {
        Ok(proof) => resource_evidence(proof, false),
        Err(_) => resource_evidence(None, true),
    };
    Some(compose(context, resources))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const BOOT: &str = "00000000-0000-4000-8000-000000000001";
    const MACHINE: &str = "00000000-0000-4000-8000-000000000002";
    const VM: &str = "00000000-0000-4000-8000-000000000003";
    const ATTEMPT: &str = "00000000-0000-4000-8000-000000000004";
    const NONCE: &str = "00000000-0000-4000-8000-000000000005";
    const OTHER: &str = "00000000-0000-4000-8000-000000000006";

    fn record() -> Record {
        let key = |purpose: &str| PinnedKey {
            key_id: purpose.to_string(),
            public_key: "a".repeat(64),
            purpose: purpose.to_string(),
        };
        Record {
            machine_id: MACHINE.to_string(),
            name: "guest".to_string(),
            pool: "organisation".to_string(),
            organisation_id: OTHER.to_string(),
            instance_url: "https://grund.example.com".to_string(),
            instance_key: key("instance"),
            trust_key: key("organisation"),
            heartbeat_interval_seconds: 5,
            registered_at_unix: 1,
            network: None,
        }
    }

    fn marker() -> Value {
        let record = record();
        json!({
            "version": 1, "vm_id": VM, "os_boot_id": BOOT, "machine_id": MACHINE,
            "machine_public_key": "b".repeat(64), "instance_url": record.instance_url,
            "instance_key": record.instance_key, "trust_key": record.trust_key,
            "replacement": {
                "attempt_id": ATTEMPT, "sequence": 3, "document_generation": 7,
                "guest_machine_id": MACHINE, "launch_nonce": NONCE,
            },
        })
    }

    fn accepted(marker: &Value, boot: &str, record: &Record, public_key: &str) -> bool {
        context(
            &serde_json::to_vec(marker).unwrap(),
            boot,
            record,
            public_key,
        )
        .is_some()
    }

    #[test]
    fn an_agent_restart_reuses_only_the_current_os_context() {
        let marker = marker();
        let record = record();
        let key = "b".repeat(64);
        assert!(accepted(&marker, BOOT, &record, &key));
        assert!(accepted(&marker, BOOT, &record, &key));
        assert!(!accepted(&marker, OTHER, &record, &key));
        assert!(context(b"", BOOT, &record, &key).is_none());
    }

    #[test]
    fn changed_registration_or_trust_cannot_inherit_a_launch_proof() {
        let marker = marker();
        let key = "b".repeat(64);
        let mut changed = record();
        changed.machine_id = OTHER.to_string();
        assert!(!accepted(&marker, BOOT, &changed, &key));
        let mut changed = record();
        changed.instance_key.public_key = "c".repeat(64);
        assert!(!accepted(&marker, BOOT, &changed, &key));
        let mut changed = record();
        changed.trust_key.key_id = "rotated".to_string();
        assert!(!accepted(&marker, BOOT, &changed, &key));
        let mut changed = record();
        changed.instance_url = "https://other.example.com".to_string();
        assert!(!accepted(&marker, BOOT, &changed, &key));
        assert!(!accepted(&marker, BOOT, &record(), &"c".repeat(64)));
    }

    #[test]
    fn replacement_identity_and_launch_fences_are_required_together() {
        for (field, value) in [
            ("guest_machine_id", json!(OTHER)),
            ("attempt_id", json!("")),
            ("launch_nonce", json!("")),
            ("sequence", json!(0)),
            ("document_generation", json!(0)),
            ("document_generation", json!(u64::MAX)),
        ] {
            let mut marker = marker();
            marker["replacement"][field] = value;
            assert!(!accepted(&marker, BOOT, &record(), &"b".repeat(64)));
        }
    }

    #[test]
    fn malformed_oversized_and_secret_bearing_context_is_not_trusted() {
        let record = record();
        let key = "b".repeat(64);
        assert!(context(b"{", BOOT, &record, &key).is_none());
        let mut oversized = marker();
        oversized["unexpected"] = json!("x".repeat(MAX_CONTEXT as usize));
        assert!(!accepted(&oversized, BOOT, &record, &key));
        let mut secret = marker();
        secret["enrollment_token"] = json!("secret");
        assert!(!accepted(&secret, BOOT, &record, &key));
        let mut secret = marker();
        secret["replacement"]["machine_key"] = json!("secret");
        assert!(!accepted(&secret, BOOT, &record, &key));
    }

    #[test]
    fn unsupported_partial_and_failed_probes_cannot_become_ready() {
        for timed_out in [false, true] {
            let unsupported = resource_evidence(None, timed_out);
            assert!(
                !unsupported.cpu_verified
                    && !unsupported.memory_verified
                    && !unsupported.attachment_verified
            );
            assert!(!unsupported.failure_code.is_empty());
        }
        let partial = resource_evidence(
            Some(crate::runtime::ResourceLimitProof {
                cpu_verified: true,
                memory_verified: false,
                attachment_verified: false,
                failure: Some(crate::runtime::ResourceLimitFailure::MemoryLimitUnverified),
            }),
            false,
        );
        assert!(!partial.memory_verified && !partial.attachment_verified);
        assert!(!partial.failure_code.is_empty());
        let cleanup_failed = resource_evidence(
            Some(crate::runtime::ResourceLimitProof {
                cpu_verified: true,
                memory_verified: true,
                attachment_verified: true,
                failure: Some(crate::runtime::ResourceLimitFailure::CleanupUnverified),
            }),
            false,
        );
        assert!(!cleanup_failed.failure_code.is_empty());
    }
}
