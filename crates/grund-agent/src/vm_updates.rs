use anyhow::{Context, ensure};
use grund_proto::grund::agent::v1 as wire;
use uuid::Uuid;

use crate::vm::{
    Artifact, VmImage, VmProcessIdentity, VmReplacementAction as Action,
    VmReplacementPhase as Phase, VmReplacementRequest as Request, VmReplacementStatus as Status,
    VmRuntime, VmSpec,
};

pub(crate) async fn apply<R: VmRuntime>(
    runtime: &R,
    spec: &VmSpec,
    update: &wire::VmUpdate,
    generation: u64,
) -> wire::VmObserved {
    if runtime.replacement_version() != 1 {
        return refused(spec, update, "VM_REPLACEMENT_UNSUPPORTED");
    }
    let request = match request(update, generation) {
        Ok(request) => request,
        Err(_) => return refused(spec, update, "VM_REPLACEMENT_REQUEST_INVALID"),
    };
    match runtime.replace(spec, &request).await {
        Ok(status) => match observed(spec, &request, status) {
            Ok(observed) => observed,
            Err(_) => refused(spec, update, "VM_REPLACEMENT_EVIDENCE_INVALID"),
        },
        Err(error) => {
            tracing::warn!(vm = %spec.id, error = %error, "guest update operation could not finish");
            refused(spec, update, "VM_REPLACEMENT_EXECUTION_FAILED")
        }
    }
}

fn request(update: &wire::VmUpdate, generation: u64) -> anyhow::Result<Request> {
    ensure!(
        update.version == 1 && update.sequence > 0 && generation > 0,
        "unsupported update fence"
    );
    for id in [
        &update.attempt_id,
        &update.guest_machine_id,
        &update.launch_nonce,
    ] {
        ensure!(!Uuid::parse_str(id)?.is_nil(), "empty update identity");
    }
    let action = match update.action.as_known() {
        Some(wire::VmUpdateAction::VM_UPDATE_ACTION_PREPARE) => Action::Prepare,
        Some(wire::VmUpdateAction::VM_UPDATE_ACTION_QUIESCE) => Action::Quiesce,
        Some(wire::VmUpdateAction::VM_UPDATE_ACTION_START_CANDIDATE) => Action::StartCandidate,
        Some(wire::VmUpdateAction::VM_UPDATE_ACTION_COMMIT) => Action::Commit,
        Some(wire::VmUpdateAction::VM_UPDATE_ACTION_ROLLBACK) => Action::Rollback,
        Some(wire::VmUpdateAction::VM_UPDATE_ACTION_RELEASE_OLD) => Action::ReleaseOld,
        _ => anyhow::bail!("unknown update operation"),
    };
    let bytes: &[u8] = update.registration_key.as_ref();
    let registration_key = bytes.try_into().context("invalid registered public key")?;
    let image = update.image.as_option().context("missing update image")?;
    let deadline = update
        .deadline
        .as_option()
        .context("missing update deadline")?;
    ensure!(
        (0..1_000_000_000).contains(&deadline.nanos),
        "invalid deadline precision"
    );
    let deadline_unix_ms = deadline
        .seconds
        .checked_mul(1000)
        .and_then(|seconds| seconds.checked_add(i64::from(deadline.nanos / 1_000_000)))
        .filter(|value| *value > 0)
        .context("update deadline overflow")?;
    Ok(Request {
        attempt_id: update.attempt_id.clone(),
        sequence: update.sequence,
        document_generation: generation,
        action,
        image: VmImage {
            kernel: artifact(image.kernel.as_option())?,
            rootfs: artifact(image.rootfs.as_option())?,
        },
        guest_machine_id: update.guest_machine_id.clone(),
        registration_key,
        launch_nonce: update.launch_nonce.clone(),
        deadline_unix_ms,
    })
}

fn artifact(value: Option<&wire::Artifact>) -> anyhow::Result<Artifact> {
    let value = value.context("missing image artifact")?;
    ensure!(
        value.sha256.len() == 64
            && value
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid image digest"
    );
    ensure!(
        !value.url.is_empty() && value.url.len() <= 2048,
        "invalid image location"
    );
    Ok(Artifact {
        url: value.url.clone(),
        sha256: value.sha256.clone(),
    })
}

fn process(value: &VmProcessIdentity) -> wire::VmProcessIdentity {
    wire::VmProcessIdentity {
        pid: value.pid,
        start_ticks: value.start_time_ticks,
        host_os_boot_id: value.boot_id.clone(),
        ..Default::default()
    }
}

fn phase(value: Phase) -> wire::VmUpdatePhase {
    match value {
        Phase::Preparing => wire::VmUpdatePhase::VM_UPDATE_PHASE_PREPARING,
        Phase::Prepared => wire::VmUpdatePhase::VM_UPDATE_PHASE_PREPARED,
        Phase::Quiescing => wire::VmUpdatePhase::VM_UPDATE_PHASE_QUIESCING,
        Phase::Quiesced => wire::VmUpdatePhase::VM_UPDATE_PHASE_QUIESCED,
        Phase::Installing => wire::VmUpdatePhase::VM_UPDATE_PHASE_INSTALLING,
        Phase::Starting => wire::VmUpdatePhase::VM_UPDATE_PHASE_STARTING,
        Phase::CandidateRunning => wire::VmUpdatePhase::VM_UPDATE_PHASE_CANDIDATE_RUNNING,
        Phase::Committed => wire::VmUpdatePhase::VM_UPDATE_PHASE_COMMITTED,
        Phase::RollingBack => wire::VmUpdatePhase::VM_UPDATE_PHASE_ROLLING_BACK,
        Phase::RolledBack => wire::VmUpdatePhase::VM_UPDATE_PHASE_ROLLED_BACK,
        Phase::Releasing => wire::VmUpdatePhase::VM_UPDATE_PHASE_RELEASING,
        Phase::Released => wire::VmUpdatePhase::VM_UPDATE_PHASE_RELEASED,
        Phase::Uncertain => wire::VmUpdatePhase::VM_UPDATE_PHASE_UNCERTAIN,
    }
}

fn observed(spec: &VmSpec, request: &Request, status: Status) -> anyhow::Result<wire::VmObserved> {
    ensure!(
        status.id == spec.id
            && status.attempt_id == request.attempt_id
            && status.sequence == request.sequence
            && status.document_generation == request.document_generation
            && status.launch_nonce == request.launch_nonce
            && status.requested_image == request.image,
        "replacement response changed its authorization"
    );
    let mut evidence = wire::VmUpdateObserved {
        version: 1,
        attempt_id: status.attempt_id,
        sequence: status.sequence,
        phase: phase(status.phase).into(),
        launch_nonce: status.launch_nonce,
        old_root_fenced: status.old_root_fenced,
        ..Default::default()
    };
    if let Some(previous) = status.previous_process.as_ref() {
        evidence.previous_process = process(previous).into();
    }
    if status.phase == Phase::Prepared {
        ensure!(
            status.previous_process.is_some()
                && status.running_process == status.previous_process
                && status.observed_image.as_ref() == Some(&spec.image),
            "prepared baseline is not observed"
        );
    }
    match status.phase {
        Phase::CandidateRunning => {
            ensure!(
                status.old_root_fenced
                    && status.running_process.is_some()
                    && status.running_process != status.previous_process
                    && status.observed_image.as_ref() == Some(&request.image),
                "candidate is not observed"
            );
            evidence.candidate_process =
                process(status.running_process.as_ref().expect("checked candidate")).into();
        }
        Phase::Committed | Phase::Releasing | Phase::Released => {
            ensure!(status.old_root_fenced, "committed baseline is not fenced");
            if let Some(running) = status.running_process.as_ref() {
                ensure!(
                    status.observed_image.as_ref() == Some(&request.image),
                    "committed image is not observed"
                );
                evidence.candidate_process = process(running).into();
            } else {
                ensure!(
                    status.observed_image.is_none(),
                    "stopped root claims an image"
                );
            }
        }
        Phase::Quiesced => {
            ensure!(
                status.old_root_fenced
                    && status.running_process.is_none()
                    && status.previous_process.is_some(),
                "quiesce is not physically observed"
            );
        }
        Phase::RolledBack => {
            ensure!(
                !status.old_root_fenced
                    && status.running_process.is_some()
                    && status.observed_image.as_ref() == Some(&spec.image),
                "baseline restoration is not observed"
            );
            evidence.previous_process =
                process(status.running_process.as_ref().expect("checked baseline")).into();
        }
        Phase::Uncertain => {
            evidence.reason = "VM_REPLACEMENT_UNCERTAIN".into();
        }
        _ => {}
    }
    let state = if status.phase == Phase::Uncertain {
        wire::VmObservedState::VM_OBSERVED_STATE_FAILED
    } else if status.running_process.is_some() && status.observed_image.is_some() {
        wire::VmObservedState::VM_OBSERVED_STATE_RUNNING
    } else if status.phase == Phase::Quiesced
        || matches!(status.phase, Phase::Committed | Phase::Released)
    {
        wire::VmObservedState::VM_OBSERVED_STATE_STOPPED
    } else {
        wire::VmObservedState::VM_OBSERVED_STATE_STARTING
    };
    let image = if status.phase == Phase::Prepared {
        Some(status.requested_image)
    } else {
        status.observed_image
    };
    if let Some(image) = image {
        evidence.kernel_sha256 = image.kernel.sha256;
        evidence.rootfs_sha256 = image.rootfs.sha256;
    }
    Ok(wire::VmObserved {
        vm_id: status.id,
        state: state.into(),
        reason: evidence.reason.clone(),
        update: evidence.into(),
        ..Default::default()
    })
}

fn refused(spec: &VmSpec, update: &wire::VmUpdate, reason: &str) -> wire::VmObserved {
    wire::VmObserved {
        vm_id: spec.id.clone(),
        state: wire::VmObservedState::VM_OBSERVED_STATE_FAILED.into(),
        reason: reason.into(),
        update: wire::VmUpdateObserved {
            version: 1,
            attempt_id: update.attempt_id.clone(),
            sequence: update.sequence,
            phase: wire::VmUpdatePhase::VM_UPDATE_PHASE_UNCERTAIN.into(),
            launch_nonce: update.launch_nonce.clone(),
            reason: reason.into(),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    }
}
