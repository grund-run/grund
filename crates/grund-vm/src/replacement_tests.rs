use super::*;
use crate::{Budget, Config, Network};
use grund_agent::vm::{Artifact, VmRuntime, VmState};

fn scratch() -> PathBuf {
    let path = std::env::temp_dir().join(format!("grund-vm-replacement-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&path).unwrap();
    path
}

fn runtime(path: &Path) -> Firecracker {
    Firecracker::new(Config {
        data_dir: path.into(),
        firecracker: "/not-launched".into(),
        jailer: None,
        network: Network::Isolated,
        budget: Budget {
            vcpus: 2,
            memory_mib: 1024,
            disk_gib: 4,
        },
    })
    .unwrap()
}

async fn run(runtime: &Firecracker, spec: &VmSpec, execution: &mut Journal) -> anyhow::Result<()> {
    let lease = execution_lock(runtime, &spec.id)?;
    super::run(runtime, spec, execution, &lease).await
}

fn spec() -> VmSpec {
    VmSpec {
        id: "vm-1".into(),
        vcpus: 1,
        memory_mib: 256,
        disk_gib: 1,
        image: VmImage {
            kernel: Artifact {
                url: "file:///absent-kernel".into(),
                sha256: RETAINED_KERNEL.into(),
            },
            rootfs: Artifact {
                url: "file:///absent-image".into(),
                sha256: "ab".repeat(32),
            },
        },
        mmds: grund_agent::vm::metadata("vm-1", "https://grund.example", "", ""),
    }
}

fn request() -> Request {
    Request {
        attempt_id: "attempt-1".into(),
        sequence: 1,
        document_generation: 10,
        action: Action::Prepare,
        image: spec().image,
        guest_machine_id: "guest-1".into(),
        registration_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        launch_nonce: "candidate-nonce-0123456789".into(),
        deadline_unix_ms: i64::MAX,
    }
}

fn journal() -> Journal {
    let request = request();
    Journal {
        version: JOURNAL_VERSION,
        operation_generation: request.document_generation,
        operation_nonces: vec![request.launch_nonce.clone()],
        status: Status {
            id: spec().id,
            attempt_id: request.attempt_id.clone(),
            sequence: request.sequence,
            document_generation: request.document_generation,
            phase: Phase::Prepared,
            requested_image: request.image.clone(),
            observed_image: Some(spec().image),
            launch_nonce: request.launch_nonce.clone(),
            previous_process: None,
            running_process: None,
            old_root_fenced: true,
            rollback_available: false,
            reason: None,
        },
        request,
        base_shape: Shape::of(&spec()),
        old_image: spec().image,
        old_disk: DiskIdentity {
            device: 1,
            inode: 2,
        },
        candidate_disk: None,
        old_process: None,
        candidate_process: None,
        used_nonces: Vec::new(),
        launch_pending: false,
        rollback_launch: false,
        launch_boot_id: String::new(),
        committed: false,
        committed_restart_nonce: None,
        release_accepted_running: false,
        pending_predecessor: None,
    }
}
fn committed_execution(runtime: &Firecracker) -> Journal {
    runtime.reserve(&spec().id, &Shape::of(&spec())).unwrap();
    std::fs::create_dir_all(journal_dir(runtime, &spec().id)).unwrap();
    let dir = runtime.dir(&spec().id);
    std::fs::write(dir.join("address"), "254").unwrap();
    std::fs::write(dir.join("rootfs.ext4"), b"confirmed candidate").unwrap();
    std::fs::write(dir.join("previous.ext4"), b"retained baseline").unwrap();
    let mut execution = journal();
    execution.committed = true;
    execution.status.phase = Phase::Committed;
    execution.request.action = Action::ReleaseOld;
    execution.request.image.rootfs.sha256 = "cd".repeat(32);
    execution.status.requested_image = execution.request.image.clone();
    execution.status.observed_image = None;
    let mut pinned = spec();
    pinned.image = execution.request.image.clone();
    atomic_json(&dir.join("spec.json"), &Shape::of(&pinned)).unwrap();
    let mut previous = process_identity(std::process::id()).unwrap().unwrap();
    previous.boot_id = "a-prior-host-boot".into();
    previous.uid = crate::jail::uid(254);
    let mut candidate = previous.clone();
    candidate.start_time_ticks += 1;
    execution.status.previous_process = Some(previous.clone());
    execution.old_process = Some(previous);
    execution.candidate_process = Some(candidate.clone());
    atomic_json(&dir.join("process.json"), &candidate).unwrap();
    std::fs::write(dir.join("firecracker.pid"), candidate.pid.to_string()).unwrap();
    execution.candidate_disk = Some(DiskIdentity::of(&dir.join("rootfs.ext4")).unwrap());
    execution.old_disk = DiskIdentity::of(&dir.join("previous.ext4")).unwrap();
    execution
        .used_nonces
        .push(execution.status.launch_nonce.clone());
    execution
}

fn identity() -> Identity {
    let pin = |purpose: &str| {
        json!({
            "key_id": format!("{purpose}-key"),
            "public_key": hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()),
            "purpose": purpose,
        })
    };
    Identity {
        key: format!("{}\n", hex::encode([7; 32])).into_bytes(),
        record: serde_json::to_vec(&json!({
            "machine_id": "guest-1", "name": "guest", "pool": "organisation",
            "organisation_id": "org-1", "instance_url": "https://grund.example",
            "instance_key": pin("instance"), "trust_key": pin("organisation"),
            "heartbeat_interval_seconds": 30, "registered_at_unix": 1,
        }))
        .unwrap(),
    }
}

#[test]
fn identity_preservation_requires_the_registered_private_key_and_all_pinned_keys() {
    let identity = identity();
    validate_identity(&identity.key, &identity.record, &request()).unwrap();
    let mut wrong = request();
    wrong.guest_machine_id = "another-machine".into();
    assert!(validate_identity(&identity.key, &identity.record, &wrong).is_err());
    wrong = request();
    wrong.registration_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    assert!(validate_identity(&identity.key, &identity.record, &wrong).is_err());
    let mut record: serde_json::Value = serde_json::from_slice(&identity.record).unwrap();
    record["trust_key"]["public_key"] = json!("00".repeat(32));
    assert!(
        validate_identity(
            &identity.key,
            &serde_json::to_vec(&record).unwrap(),
            &request()
        )
        .is_err()
    );
    record["trust_key"] = record["instance_key"].clone();
    assert!(
        validate_identity(
            &identity.key,
            &serde_json::to_vec(&record).unwrap(),
            &request()
        )
        .is_err()
    );
    assert!(validate_identity(&[b'a'; 129], &identity.record, &request()).is_err());
}

#[test]
fn stale_and_contradictory_actions_cannot_advance_the_execution_fence() {
    let mut journal = journal();
    assert!(!accept(&mut journal, &request()).unwrap());
    let mut conflicting = request();
    conflicting.action = Action::Quiesce;
    assert!(accept(&mut journal, &conflicting).is_err());
    conflicting.sequence = 2;
    assert!(accept(&mut journal, &conflicting).is_err());
    conflicting.document_generation = 11;
    conflicting.launch_nonce = "quiesce-authorization-nonce".into();
    accept(&mut journal, &conflicting).unwrap();
    assert!(accept(&mut journal, &request()).is_err());
    conflicting.sequence = 3;
    conflicting.document_generation = 12;
    conflicting.image.rootfs.sha256 = "cd".repeat(32);
    assert!(accept(&mut journal, &conflicting).is_err());
}

#[tokio::test]
async fn confirmation_never_allows_a_delayed_rollback() {
    let path = scratch();
    let runtime = runtime(&path);
    let mut journal = journal();
    std::fs::create_dir(runtime.dir(&spec().id)).unwrap();
    let previous = runtime.dir(&spec().id).join("previous.ext4");
    std::fs::write(&previous, b"retained for Core confirmation").unwrap();
    journal.status.phase = Phase::CandidateRunning;
    journal.status.rollback_available = true;
    journal.candidate_process = process_identity(std::process::id()).unwrap();
    journal.request.action = Action::Commit;
    run(&runtime, &spec(), &mut journal).await.unwrap();
    assert_eq!(journal.status.phase, Phase::Committed);
    assert!(!journal.status.rollback_available);
    assert_eq!(
        std::fs::read(&previous).unwrap(),
        b"retained for Core confirmation"
    );
    journal.request.action = Action::Rollback;
    journal.request.launch_nonce = "fresh-rollback-nonce-012345".into();
    assert!(run(&runtime, &spec(), &mut journal).await.is_err());
    assert_eq!(
        std::fs::read(&previous).unwrap(),
        b"retained for Core confirmation"
    );
    journal.status.phase = Phase::Released;
    let mut late = journal.request.clone();
    late.sequence += 1;
    late.document_generation += 1;
    assert!(accept(&mut journal, &late).is_err());
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn ordinary_shape_changes_and_unsupported_replacement_preserve_the_existing_disk() {
    let path = scratch();
    let runtime = runtime(&path);
    let original = spec();
    runtime
        .reserve(&original.id, &Shape::of(&original))
        .unwrap();
    let disk = runtime.dir(&original.id).join("rootfs.ext4");
    std::fs::write(&disk, b"existing guest bytes").unwrap();
    let mut changed = original.clone();
    changed.image.rootfs.sha256 = "cd".repeat(32);
    let observed = runtime.ensure(&changed).await.unwrap();
    assert!(matches!(observed.state, VmState::Failed { .. }));
    assert_eq!(std::fs::read(&disk).unwrap(), b"existing guest bytes");
    assert_eq!(runtime.replacement_version(), 0);
    assert!(runtime.replace(&original, &request()).await.is_err());
    assert_eq!(std::fs::read(&disk).unwrap(), b"existing guest bytes");
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn the_execution_journal_rejects_symlinks_and_torn_or_unknown_state() {
    let path = scratch();
    let runtime = runtime(&path);
    let dir = journal_dir(&runtime, &spec().id);
    std::fs::create_dir_all(&dir).unwrap();
    let target = path.join("elsewhere");
    std::fs::write(&target, b"untouched").unwrap();
    std::os::unix::fs::symlink(&target, journal_path(&runtime, &spec().id)).unwrap();
    assert!(load(&runtime, &spec().id).is_err());
    std::fs::remove_file(journal_path(&runtime, &spec().id)).unwrap();
    std::fs::write(journal_path(&runtime, &spec().id), b"{").unwrap();
    assert!(load(&runtime, &spec().id).is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"untouched");
    if crate::running_as_root() {
        let mut journal = journal();
        save(&runtime, &journal).unwrap();
        assert_eq!(
            load(&runtime, &spec().id).unwrap().unwrap().status.phase,
            Phase::Prepared
        );
        journal.version += 1;
        save(&runtime, &journal).unwrap();
        assert!(load(&runtime, &spec().id).is_err());
    }
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn a_reused_pid_cannot_authorize_signalling_another_process() {
    let mut child = tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let identity = process_identity(child.id().unwrap()).unwrap().unwrap();
    let mut stale = identity.clone();
    stale.start_time_ticks += 1;
    fence_identity(&stale).await.unwrap();
    assert!(child.try_wait().unwrap().is_none());
    fence_identity(&identity).await.unwrap();
    assert!(!child.wait().await.unwrap().success());
}

#[tokio::test]
async fn an_owned_replacement_blocks_normal_ensure_and_stop_without_touching_guest_bytes() {
    if !crate::running_as_root() {
        return;
    }
    let path = scratch();
    let runtime = runtime(&path);
    runtime.reserve(&spec().id, &Shape::of(&spec())).unwrap();
    let disk = runtime.dir(&spec().id).join("rootfs.ext4");
    std::fs::write(&disk, b"preserve old root").unwrap();
    std::fs::create_dir_all(journal_dir(&runtime, &spec().id)).unwrap();
    save(&runtime, &journal()).unwrap();
    assert!(runtime.ensure(&spec()).await.is_err());
    assert!(runtime.stop(&spec().id).await.is_err());
    assert_eq!(std::fs::read(disk).unwrap(), b"preserve old root");
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn offline_preservation_copies_only_identity_and_refuses_symlinked_seeds() {
    if !crate::running_as_root() || debugfs().is_none() {
        return;
    }
    let mkfs = crate::on_path(Path::new("mkfs.ext4"));
    if !mkfs.is_file() {
        return;
    }
    let path = scratch();
    let runtime = runtime(&path);
    let lease = execution_lock(&runtime, &spec().id).unwrap();
    let source = path.join("source.ext4");
    let target = path.join("target.ext4");
    for disk in [&source, &target] {
        let file = File::create(disk).unwrap();
        file.set_len(32 * 1024 * 1024).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(
            std::process::Command::new(&mkfs)
                .args(["-q", "-F"])
                .arg(disk)
                .status()
                .unwrap()
                .success()
        );
    }
    let expected = identity();
    write_identity(&source, &expected, &lease).await.unwrap();
    tool(&source, "mkdir /application-data", true, 8192, &lease)
        .await
        .unwrap();
    tool(
        &source,
        "mkdir /var/lib/grund/agent/applied-documents",
        true,
        8192,
        &lease,
    )
    .await
    .unwrap();
    let applied = path.join("applied-fixture");
    std::fs::write(
        &applied,
        b"desired application and volume state must stay behind",
    )
    .unwrap();
    tool(
        &source,
        &format!(
            "write {} /var/lib/grund/agent/applied.json",
            applied.display()
        ),
        true,
        8192,
        &lease,
    )
    .await
    .unwrap();
    let preserved = read_identity(&source, &request(), &lease).await.unwrap();
    write_identity(&target, &preserved, &lease).await.unwrap();
    assert_eq!(
        read_identity(&target, &request(), &lease)
            .await
            .unwrap()
            .record,
        expected.record
    );
    assert!(
        stat(&target, "/application-data", true, 0, &lease)
            .await
            .is_err()
    );
    assert!(
        stat(
            &target,
            "/var/lib/grund/agent/applied-documents",
            true,
            0,
            &lease
        )
        .await
        .is_err()
    );
    assert!(
        stat(
            &target,
            "/var/lib/grund/agent/applied.json",
            false,
            MAX_RECORD,
            &lease
        )
        .await
        .is_err()
    );
    tool(
        &source,
        "rm /var/lib/grund/agent/machine.key",
        true,
        8192,
        &lease,
    )
    .await
    .unwrap();
    tool(
        &source,
        "symlink /var/lib/grund/agent/machine.key /elsewhere",
        true,
        8192,
        &lease,
    )
    .await
    .unwrap();
    assert!(read_identity(&source, &request(), &lease).await.is_err());
    let blob = path.join("lease-output-fixture");
    File::create(&blob)
        .unwrap()
        .set_len(4 * 1024 * 1024)
        .unwrap();
    tool(
        &source,
        &format!("write {} /application-data/large", blob.display()),
        true,
        8192,
        &lease,
    )
    .await
    .unwrap();
    let mut command = guarded_tool(&debugfs().unwrap(), &lease).unwrap();
    let mut reader = command
        .args(["-w", "-R", "cat /application-data/large"])
        .arg(&source)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut first = [0u8; 1];
    tokio::time::timeout(
        Duration::from_secs(5),
        reader.stdout.as_mut().unwrap().read_exact(&mut first),
    )
    .await
    .unwrap()
    .unwrap();
    drop(command);
    drop(lease);
    assert!(reader.try_wait().unwrap().is_none());
    assert!(execution_lock(&runtime, &spec().id).is_err());
    reader.kill().await.unwrap();
    drop(execution_lock(&runtime, &spec().id).unwrap());
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn a_pid_file_alone_cannot_adopt_an_unrelated_live_process() {
    let path = scratch();
    let runtime = runtime(&path);
    runtime.reserve(&spec().id, &Shape::of(&spec())).unwrap();
    let dir = runtime.dir(&spec().id);
    std::fs::write(dir.join("firecracker.pid"), std::process::id().to_string()).unwrap();
    std::fs::write(dir.join("address"), "7").unwrap();
    std::fs::write(dir.join("rootfs.ext4"), b"unchanged baseline").unwrap();
    assert!(adopt_or_recorded(&runtime, &dir).await.is_err());
    assert!(!dir.join("process.json").exists());
    assert_eq!(
        std::fs::read(dir.join("rootfs.ext4")).unwrap(),
        b"unchanged baseline"
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn an_api_socket_must_belong_to_the_exact_observed_process() {
    let path = scratch();
    let runtime = runtime(&path);
    let dir = runtime.dir(&spec().id);
    let listener = tokio::net::UnixListener::bind(runtime.socket(&dir)).unwrap();
    let mut identity = process_identity(std::process::id()).unwrap().unwrap();
    identity.pid += 1;
    assert!(legacy_api_owner(&runtime, &dir, &identity).await.is_err());
    drop(listener);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn disk_ownership_depends_on_the_open_inode_not_equal_file_contents() {
    let path = scratch();
    let original = path.join("original");
    let another = path.join("another");
    let mut open = File::create(&original).unwrap();
    open.write_all(b"same bytes").unwrap();
    std::fs::write(&another, b"same bytes").unwrap();
    assert!(disk_is_open_by(std::process::id(), &DiskIdentity::of(&original).unwrap()).unwrap());
    assert!(!disk_is_open_by(std::process::id(), &DiskIdentity::of(&another).unwrap()).unwrap());
    drop(open);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn an_unidentified_launch_cannot_be_retried_or_rolled_back_into_a_second_root() {
    let path = scratch();
    let runtime = runtime(&path);
    runtime.reserve(&spec().id, &Shape::of(&spec())).unwrap();
    let disk = runtime.dir(&spec().id).join("rootfs.ext4");
    std::fs::write(&disk, b"preserved root").unwrap();
    std::fs::create_dir_all(journal_dir(&runtime, &spec().id)).unwrap();
    let mut journal = journal();
    journal.request.action = Action::StartCandidate;
    journal.status.phase = Phase::Starting;
    journal.launch_pending = true;
    journal
        .used_nonces
        .push(journal.request.launch_nonce.clone());
    run(&runtime, &spec(), &mut journal).await.unwrap();
    assert_eq!(journal.status.phase, Phase::Uncertain);
    assert_eq!(journal.used_nonces.len(), 1);
    journal.request.action = Action::Rollback;
    journal.request.launch_nonce = "fresh-rollback-nonce".into();
    assert!(run(&runtime, &spec(), &mut journal).await.is_err());
    assert_eq!(std::fs::read(&disk).unwrap(), b"preserved root");
    assert!(!runtime.dir(&spec().id).join("firecracker.pid").exists());
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn pre_quiesce_cancellation_preserves_the_live_baseline_and_removes_only_staging() {
    for phase in [Phase::Preparing, Phase::Prepared] {
        let path = scratch();
        let runtime = runtime(&path);
        runtime.reserve(&spec().id, &Shape::of(&spec())).unwrap();
        let dir = runtime.dir(&spec().id);
        let disk = dir.join("rootfs.ext4");
        let staged = dir.join("replacement.ext4");
        let partial = dir.join("replacement.partial");
        std::fs::write(&disk, b"baseline preserved").unwrap();
        std::fs::write(&staged, b"prepared target").unwrap();
        std::fs::write(&partial, b"partial staging").unwrap();
        let mut child = tokio::process::Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let baseline = process_identity(child.id().unwrap()).unwrap().unwrap();
        let mut journal = journal();
        journal.old_disk = DiskIdentity::of(&disk).unwrap();
        journal.candidate_disk = Some(DiskIdentity::of(&staged).unwrap());
        journal.old_process = Some(baseline.clone());
        journal.status.previous_process = Some(baseline.clone());
        journal.status.phase = phase;
        journal.request.action = Action::Rollback;
        journal.request.sequence = 2;
        validate_initial_operation(&journal.request).unwrap();
        run(&runtime, &spec(), &mut journal).await.unwrap();
        assert_eq!(journal.status.phase, Phase::RolledBack);
        assert_eq!(journal.status.running_process, Some(baseline.clone()));
        assert_eq!(journal.status.observed_image, Some(spec().image));
        assert!(!journal.status.old_root_fenced);
        assert!(journal.used_nonces.is_empty());
        assert!(!staged.exists() && !partial.exists());
        assert_eq!(
            process_identity(child.id().unwrap()).unwrap(),
            Some(baseline)
        );
        assert!(child.try_wait().unwrap().is_none());
        assert_eq!(std::fs::read(&disk).unwrap(), b"baseline preserved");
        child.kill().await.unwrap();
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn an_unknown_execution_cannot_resume_after_quiesce_or_skip_preparation() {
    for (action, sequence) in [
        (Action::Prepare, 0),
        (Action::Prepare, 2),
        (Action::Quiesce, 2),
        (Action::Rollback, 3),
        (Action::StartCandidate, 3),
        (Action::Commit, 4),
        (Action::ReleaseOld, 5),
    ] {
        let mut request = request();
        request.action = action;
        request.sequence = sequence;
        assert!(validate_initial_operation(&request).is_err());
    }
}

#[test]
fn a_consumed_nonce_requires_new_authorization_even_after_host_reboot() {
    let path = scratch();
    let runtime = runtime(&path);
    let mut journal = journal();
    journal.launch_pending = true;
    journal.launch_boot_id = "previous-host-boot".into();
    journal
        .used_nonces
        .push(journal.request.launch_nonce.clone());
    recover_launch(&runtime, &runtime.dir(&spec().id), &mut journal).unwrap();
    assert!(!journal.launch_pending);
    assert!(journal.status.old_root_fenced);
    assert_eq!(journal.status.phase, Phase::Uncertain);
    assert_eq!(journal.used_nonces.len(), 1);
    let mut next = journal.request.clone();
    next.sequence += 1;
    next.document_generation += 1;
    next.action = Action::StartCandidate;
    next.launch_nonce = "new-authorized-physical-launch".into();
    accept(&mut journal, &next).unwrap();
    next.sequence += 1;
    next.document_generation += 1;
    next.launch_nonce = journal.used_nonces[0].clone();
    assert!(accept(&mut journal, &next).is_err());
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn releasing_the_old_root_survives_a_crash_after_unlink_without_deleting_the_candidate() {
    let path = scratch();
    let runtime = runtime(&path);
    let mut execution = committed_execution(&runtime);
    let candidate = runtime.dir(&spec().id).join("rootfs.ext4");
    let previous = runtime.dir(&spec().id).join("previous.ext4");
    run(&runtime, &spec(), &mut execution).await.unwrap();
    assert!(!previous.exists());
    assert_eq!(std::fs::read(&candidate).unwrap(), b"confirmed candidate");
    let mut recovered = load(&runtime, &spec().id).unwrap().unwrap();
    assert_eq!(recovered.status.phase, Phase::Releasing);
    run(&runtime, &spec(), &mut recovered).await.unwrap();
    save(&runtime, &recovered).unwrap();
    assert_eq!(
        load(&runtime, &spec().id).unwrap().unwrap().status.phase,
        Phase::Released
    );
    run(&runtime, &spec(), &mut recovered).await.unwrap();
    assert_eq!(std::fs::read(candidate).unwrap(), b"confirmed candidate");
    recovered.request.action = Action::Rollback;
    assert!(run(&runtime, &spec(), &mut recovered).await.is_err());
    std::fs::remove_dir_all(path).unwrap();
}

#[cfg(target_arch = "x86_64")]
#[test]
fn a_non_dumpable_vmm_keeps_its_effective_uid_in_process_evidence() {
    if !crate::running_as_root() {
        return;
    }
    let mut ready = [0; 2];
    let mut release = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    assert_eq!(
        unsafe { libc::pipe2(release.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            libc::syscall(libc::SYS_close, ready[0]);
            libc::syscall(libc::SYS_close, release[1]);
            if libc::syscall(
                libc::SYS_setresuid,
                1_950_001_000u32,
                1_950_001_000u32,
                1_950_001_000u32,
            ) != 0
                || libc::syscall(libc::SYS_prctl, libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                || libc::syscall(libc::SYS_write, ready[1], b"x".as_ptr(), 1usize) != 1
            {
                libc::_exit(1);
            }
            let mut wait = libc::pollfd {
                fd: release[0],
                events: libc::POLLIN,
                revents: 0,
            };
            libc::syscall(
                libc::SYS_poll,
                std::ptr::from_mut(&mut wait),
                1usize,
                5000i32,
            );
            libc::_exit(0);
        }
    }
    unsafe {
        libc::close(ready[1]);
        libc::close(release[0]);
    }
    let ready_read = unsafe { OwnedFd::from_raw_fd(ready[0]) };
    let release_write = unsafe { OwnedFd::from_raw_fd(release[1]) };
    let mut byte = [0u8; 1];
    let ready_count = unsafe { libc::read(ready_read.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
    let observed = if ready_count == 1 {
        process_identity(u32::try_from(pid).unwrap())
    } else {
        Ok(None)
    };
    if ready_count == 1 {
        unsafe {
            libc::write(release_write.as_raw_fd(), b"x".as_ptr().cast(), 1);
        }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(ready_count, 1);
    assert_eq!(status, 0);
    assert_eq!(observed.unwrap().unwrap().uid, 1_950_001_000);
}

#[tokio::test]
async fn pre_spawn_setup_and_exec_errors_retire_the_intent_and_allow_a_retry() {
    let path = scratch();
    let runtime = runtime(&path);
    runtime.reserve(&spec().id, &Shape::of(&spec())).unwrap();
    let dir = runtime.dir(&spec().id);
    std::fs::write(dir.join("rootfs.ext4"), b"unchanged existing root").unwrap();
    std::fs::create_dir(dir.join("firecracker.log")).unwrap();
    assert!(runtime.launch(&spec().id, &dir).await.is_err());
    assert!(!dir.join("launch.intent").exists());
    check_launch_intent(&dir).unwrap();
    std::fs::remove_dir(dir.join("firecracker.log")).unwrap();
    let missing = dir.join("uninstalled-vmm");
    assert!(
        spawn_prepared(&dir, || tokio::process::Command::new(missing)
            .spawn()
            .map_err(|error| error.to_string()))
        .is_err()
    );
    assert!(!dir.join("launch.intent").exists());
    check_launch_intent(&dir).unwrap();
    std::fs::write(dir.join("process.json"), b"{}").unwrap();
    assert!(
        spawn_prepared(&dir, || tokio::process::Command::new(
            dir.join("uninstalled-vmm")
        )
        .spawn()
        .map_err(|error| error.to_string()))
        .is_err()
    );
    assert!(!dir.join("launch.intent").exists());
    std::fs::remove_file(dir.join("process.json")).unwrap();
    write_launch_intent(&dir).unwrap();
    assert!(dir.join("launch.intent").exists());
    assert!(check_launch_intent(&dir).is_err());
    assert!(
        spawn_prepared(&dir, || tokio::process::Command::new(
            dir.join("uninstalled-vmm")
        )
        .spawn()
        .map_err(|error| error.to_string()))
        .is_err()
    );
    assert!(dir.join("launch.intent").exists());
    assert_eq!(
        std::fs::read(dir.join("rootfs.ext4")).unwrap(),
        b"unchanged existing root"
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn successful_spawn_keeps_the_intent_until_process_identity_is_durable() {
    let path = scratch();
    let mut child = spawn_prepared(&path, || {
        tokio::process::Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| error.to_string())
    })
    .unwrap();
    assert!(path.join("launch.intent").exists());
    assert!(check_launch_intent(&path).is_err());
    child.kill().await.unwrap();
    assert!(path.join("launch.intent").exists());
    assert!(check_launch_intent(&path).is_err());
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn post_commit_recovery_reserves_one_nonce_without_copying_or_swapping_the_confirmed_root() {
    for phase in [Phase::Committed, Phase::Releasing, Phase::Released] {
        let path = scratch();
        let runtime = runtime(&path);
        let mut execution = committed_execution(&runtime);
        let dir = runtime.dir(&spec().id);
        execution.status.phase = phase;
        execution.release_accepted_running = phase == Phase::Released;
        execution.request.image.kernel.url =
            format!("file://{}", dir.join("missing-kernel").display());
        if phase != Phase::Committed {
            std::fs::remove_file(dir.join("previous.ext4")).unwrap();
        }
        let had_previous = dir.join("previous.ext4").exists();
        let confirmed = DiskIdentity::of(&dir.join("rootfs.ext4")).unwrap();
        let mut pinned = spec();
        pinned.image = execution.request.image.clone();
        validate_base_spec(&pinned, &execution).unwrap();
        let mut restart = execution.request.clone();
        restart.action = Action::StartCandidate;
        restart.sequence += 1;
        restart.document_generation += 1;
        restart.launch_nonce = "one-authorized-committed-restart".into();
        accept(&mut execution, &restart).unwrap();
        assert!(run(&runtime, &pinned, &mut execution).await.is_err());
        assert!(execution.committed);
        assert_eq!(execution.status.phase, Phase::Starting);
        assert_eq!(
            execution.committed_restart_nonce.as_deref(),
            Some(restart.launch_nonce.as_str())
        );
        assert!(confirmed.matches(&dir.join("rootfs.ext4")));
        assert_eq!(
            std::fs::read(dir.join("rootfs.ext4")).unwrap(),
            b"confirmed candidate"
        );
        assert_eq!(dir.join("previous.ext4").exists(), had_previous);
        assert!(!dir.join("replacement.ext4").exists());
        let mut recovered = load(&runtime, &spec().id).unwrap().unwrap();
        assert!(recovered.committed);
        assert!(owns(&runtime, &spec().id).unwrap());
        let mut second = recovered.request.clone();
        second.sequence += 1;
        second.document_generation += 1;
        second.launch_nonce = "forbidden-second-committed-restart".into();
        accept(&mut recovered, &second).unwrap();
        assert!(run(&runtime, &pinned, &mut recovered).await.is_err());
        recovered.request.action = Action::Rollback;
        assert!(run(&runtime, &pinned, &mut recovered).await.is_err());
        assert!(confirmed.matches(&dir.join("rootfs.ext4")));
        assert_eq!(dir.join("previous.ext4").exists(), had_previous);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[tokio::test]
async fn a_dead_committed_process_can_finalize_but_cannot_claim_health_or_enable_ordinary_restart()
{
    let path = scratch();
    let runtime = runtime(&path);
    let mut execution = committed_execution(&runtime);
    let current = process_identity(std::process::id()).unwrap().unwrap();
    execution.request.action = Action::Commit;
    run(&runtime, &spec(), &mut execution).await.unwrap();
    assert!(execution.committed);
    assert_eq!(execution.status.phase, Phase::Committed);
    execution.request.action = Action::ReleaseOld;
    run(&runtime, &spec(), &mut execution).await.unwrap();
    save(&runtime, &execution).unwrap();
    assert_eq!(execution.status.phase, Phase::Released);
    assert!(execution.status.old_root_fenced);
    assert!(
        execution.status.running_process.is_none() && execution.status.observed_image.is_none()
    );
    assert!(!execution.release_accepted_running);
    assert!(owns(&runtime, &spec().id).unwrap());
    assert!(!runtime.dir(&spec().id).join("firecracker.pid").exists());
    assert_eq!(process_identity(std::process::id()).unwrap(), Some(current));
    let mut pinned = spec();
    pinned.image = execution.request.image.clone();
    assert!(runtime.ensure(&pinned).await.is_err());
    assert!(runtime.stop(&spec().id).await.is_err());
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn committed_pin_confirmation_accepts_only_the_baseline_or_exact_target_with_frozen_resources() {
    let path = scratch();
    let runtime = runtime(&path);
    let mut execution = committed_execution(&runtime);
    let original = spec();
    let mut pinned = original.clone();
    pinned.image = execution.request.image.clone();
    validate_base_spec(&original, &execution).unwrap();
    for phase in [
        Phase::Committed,
        Phase::Releasing,
        Phase::Released,
        Phase::Starting,
        Phase::CandidateRunning,
        Phase::Uncertain,
    ] {
        execution.status.phase = phase;
        validate_base_spec(&pinned, &execution).unwrap();
        let mut changed = pinned.clone();
        changed.image.rootfs.sha256 = "ef".repeat(32);
        assert!(validate_base_spec(&changed, &execution).is_err());
        changed = pinned.clone();
        changed.memory_mib += 1;
        assert!(validate_base_spec(&changed, &execution).is_err());
        changed = pinned.clone();
        changed.id = "another-vm".into();
        assert!(validate_base_spec(&changed, &execution).is_err());
    }
    execution.committed = false;
    assert!(validate_base_spec(&pinned, &execution).is_err());
    validate_base_spec(&original, &execution).unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn older_committed_journals_recover_the_irreversible_latch_without_claiming_release_health() {
    let path = scratch();
    let runtime = runtime(&path);
    let execution = committed_execution(&runtime);
    let mut stored = serde_json::to_value(execution).unwrap();
    let fields = stored.as_object_mut().unwrap();
    fields.remove("committed");
    fields.remove("committed_restart_nonce");
    fields.remove("release_accepted_running");
    fields.remove("operation_generation");
    fields.remove("operation_nonces");
    atomic_json(&journal_path(&runtime, &spec().id), &stored).unwrap();
    let recovered = load(&runtime, &spec().id).unwrap().unwrap();
    assert!(recovered.committed);
    assert!(!recovered.release_accepted_running);
    assert!(recovered.committed_restart_nonce.is_none());
    assert!(owns(&runtime, &spec().id).unwrap());
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn committed_finalization_does_not_require_the_exited_candidate_pid_to_be_alive() {
    if !crate::running_as_root() {
        return;
    }
    let path = scratch();
    let runtime = runtime(&path);
    let mut execution = committed_execution(&runtime);
    let mut child = tokio::process::Command::new("sleep")
        .arg("30")
        .uid(crate::jail::uid(254))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let observed = process_identity(child.id().unwrap()).unwrap().unwrap();
    execution.candidate_process = Some(observed.clone());
    execution.status.running_process = Some(observed.clone());
    execution.status.observed_image = Some(execution.request.image.clone());
    let dir = runtime.dir(&spec().id);
    atomic_json(&dir.join("process.json"), &observed).unwrap();
    std::fs::write(dir.join("firecracker.pid"), observed.pid.to_string()).unwrap();
    child.kill().await.unwrap();
    execution.request.action = Action::Commit;
    run(&runtime, &spec(), &mut execution).await.unwrap();
    assert!(execution.committed);
    assert!(dir.join("previous.ext4").exists());
    assert!(execution.status.running_process.is_none());
    execution.request.action = Action::ReleaseOld;
    run(&runtime, &spec(), &mut execution).await.unwrap();
    assert_eq!(execution.status.phase, Phase::Released);
    assert!(!dir.join("previous.ext4").exists());
    assert!(!dir.join("firecracker.pid").exists());
    assert_eq!(
        std::fs::read(dir.join("rootfs.ext4")).unwrap(),
        b"confirmed candidate"
    );
    assert!(execution.status.old_root_fenced);
    assert!(
        execution.status.running_process.is_none() && execution.status.observed_image.is_none()
    );
    assert!(!execution.release_accepted_running);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn committed_finalization_refuses_a_changed_vm_address_without_retiring_either_root() {
    let path = scratch();
    let runtime = runtime(&path);
    let mut execution = committed_execution(&runtime);
    let dir = runtime.dir(&spec().id);
    std::fs::write(dir.join("address"), "253").unwrap();
    assert!(run(&runtime, &spec(), &mut execution).await.is_err());
    assert!(execution.committed);
    assert_eq!(execution.status.phase, Phase::Committed);
    assert_eq!(
        std::fs::read(dir.join("rootfs.ext4")).unwrap(),
        b"confirmed candidate"
    );
    assert_eq!(
        std::fs::read(dir.join("previous.ext4")).unwrap(),
        b"retained baseline"
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn ordered_quiesce_and_candidate_authorizations_use_distinct_unused_nonces() {
    let mut execution = journal();
    let prepared_nonce = execution.request.launch_nonce.clone();
    let mut quiesce = execution.request.clone();
    quiesce.action = Action::Quiesce;
    quiesce.sequence += 1;
    quiesce.document_generation += 1;
    assert!(accept(&mut execution, &quiesce).is_err());
    quiesce.launch_nonce = "quiesce-fresh-nonce-two".into();
    accept(&mut execution, &quiesce).unwrap();
    assert_eq!(execution.status.launch_nonce, quiesce.launch_nonce);
    execution.status.phase = Phase::Quiesced;
    let mut start = quiesce.clone();
    start.action = Action::StartCandidate;
    start.sequence += 1;
    start.document_generation += 1;
    start.launch_nonce = prepared_nonce.clone();
    assert!(accept(&mut execution, &start).is_err());
    start.launch_nonce = quiesce.launch_nonce.clone();
    assert!(accept(&mut execution, &start).is_err());
    start.launch_nonce = "candidate-fresh-nonce-three".into();
    accept(&mut execution, &start).unwrap();
    assert_eq!(
        execution.operation_nonces,
        vec![
            prepared_nonce,
            quiesce.launch_nonce,
            start.launch_nonce.clone()
        ]
    );
    let mut boot = spec();
    bind_boot_context(&mut boot, &execution).unwrap();
    assert_eq!(boot.mmds["vm"]["id"], spec().id);
    assert_eq!(boot.mmds["grund"]["url"], spec().mmds["grund"]["url"]);
    assert_eq!(
        boot.mmds["grund"]["replacement"]["launch_nonce"],
        start.launch_nonce
    );
    assert!(boot.mmds.get("vm_id").is_none());
    assert!(boot.mmds["grund"].get("vm_id").is_none());
    let mut without_context = boot.mmds.clone();
    without_context["grund"]
        .as_object_mut()
        .unwrap()
        .remove("replacement");
    assert_eq!(without_context, spec().mmds);
    execution.status.phase = Phase::CandidateRunning;
    execution.status.launch_nonce = start.launch_nonce.clone();
    execution.used_nonces.push(start.launch_nonce.clone());
    let mut commit = start.clone();
    commit.action = Action::Commit;
    commit.sequence += 1;
    commit.document_generation += 1;
    commit.launch_nonce = "unrelated-commit-nonce".into();
    assert!(accept(&mut execution, &commit).is_err());
    commit.launch_nonce = start.launch_nonce;
    accept(&mut execution, &commit).unwrap();
    execution.committed = true;
    execution.status.phase = Phase::Committed;
    let mut release = commit.clone();
    release.action = Action::ReleaseOld;
    release.sequence += 1;
    release.document_generation += 1;
    release.launch_nonce = "unrelated-release-nonce".into();
    assert!(accept(&mut execution, &release).is_err());
    release.launch_nonce = commit.launch_nonce;
    accept(&mut execution, &release).unwrap();
}

#[tokio::test]
async fn outer_document_replays_preserve_the_original_boot_authorization_and_running_process() {
    let path = scratch();
    let runtime = runtime(&path);
    runtime.reserve(&spec().id, &Shape::of(&spec())).unwrap();
    let mut child = tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let process = process_identity(child.id().unwrap()).unwrap().unwrap();
    let mut execution = journal();
    execution.request.action = Action::StartCandidate;
    execution.request.sequence = 3;
    execution.request.document_generation = 17;
    execution.request.deadline_unix_ms = now_ms().unwrap() - 1;
    execution.operation_generation = 17;
    execution.status.phase = Phase::CandidateRunning;
    execution.status.sequence = 3;
    execution.status.document_generation = 17;
    execution.status.running_process = Some(process.clone());
    execution.candidate_process = Some(process.clone());
    execution
        .used_nonces
        .push(execution.request.launch_nonce.clone());
    let mut before = spec();
    bind_boot_context(&mut before, &execution).unwrap();
    let nonces = execution.operation_nonces.clone();
    let mut refreshed = execution.request.clone();
    refreshed.document_generation = 19;
    validate_request(&spec(), &refreshed).unwrap();
    authorize_time(Some(&execution), &refreshed).unwrap();
    assert!(!accept(&mut execution, &refreshed).unwrap());
    run(&runtime, &spec(), &mut execution).await.unwrap();
    let mut after = spec();
    bind_boot_context(&mut after, &execution).unwrap();
    assert_eq!(before.mmds, after.mmds);
    assert_eq!(
        after.mmds["grund"]["replacement"]["document_generation"],
        17
    );
    assert_eq!(execution.status.document_generation, 19);
    assert_eq!(execution.status.sequence, 3);
    assert_eq!(execution.operation_generation, 17);
    assert_eq!(execution.operation_nonces, nonces);
    assert_eq!(
        process_identity(child.id().unwrap()).unwrap(),
        Some(process)
    );
    assert!(!runtime.dir(&spec().id).join("firecracker.pid").exists());
    let mut changed = refreshed.clone();
    changed.document_generation += 1;
    changed.deadline_unix_ms += 1;
    assert!(accept(&mut execution, &changed).is_err());
    changed = refreshed.clone();
    changed.document_generation += 1;
    changed.launch_nonce = "changed-replay-nonce".into();
    assert!(accept(&mut execution, &changed).is_err());
    changed = refreshed.clone();
    changed.document_generation += 1;
    changed.image.rootfs.url = "file:///changed-replay-source".into();
    assert!(accept(&mut execution, &changed).is_err());
    changed = refreshed;
    changed.document_generation = 18;
    assert!(accept(&mut execution, &changed).is_err());
    child.kill().await.unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn expired_authorizations_cannot_begin_or_resume_incomplete_destructive_operations() {
    let mut execution = journal();
    execution.request.deadline_unix_ms = now_ms().unwrap() - 1;
    validate_request(&spec(), &execution.request).unwrap();
    assert!(authorize_time(None, &execution.request).is_err());
    authorize_time(Some(&execution), &execution.request).unwrap();
    execution.status.phase = Phase::Preparing;
    assert!(authorize_time(Some(&execution), &execution.request).is_err());
    for action in [
        Action::Quiesce,
        Action::StartCandidate,
        Action::Commit,
        Action::Rollback,
    ] {
        let mut request = execution.request.clone();
        request.sequence += 1;
        request.document_generation += 1;
        request.action = action;
        request.launch_nonce = "new-expired-physical-authorization".into();
        validate_request(&spec(), &request).unwrap();
        assert!(authorize_time(Some(&execution), &request).is_err());
    }
    execution.status.phase = Phase::Starting;
    execution.request.action = Action::StartCandidate;
    execution.launch_pending = true;
    assert!(authorize_time(Some(&execution), &execution.request).is_err());
    assert!(execution.committed_restart_nonce.is_none());
}

#[tokio::test]
async fn irreversible_commit_and_release_cleanup_survive_the_authorization_deadline() {
    let path = scratch();
    let runtime = runtime(&path);
    let mut execution = committed_execution(&runtime);
    execution.request.action = Action::Commit;
    execution.request.deadline_unix_ms = now_ms().unwrap() - 1;
    let mut replay = execution.request.clone();
    replay.document_generation += 1;
    authorize_time(Some(&execution), &replay).unwrap();
    assert!(!accept(&mut execution, &replay).unwrap());
    run(&runtime, &spec(), &mut execution).await.unwrap();
    assert!(execution.committed);
    let mut release = replay;
    release.sequence += 1;
    release.document_generation += 1;
    release.action = Action::ReleaseOld;
    authorize_time(Some(&execution), &release).unwrap();
    accept(&mut execution, &release).unwrap();
    run(&runtime, &spec(), &mut execution).await.unwrap();
    save(&runtime, &execution).unwrap();
    assert_eq!(execution.status.phase, Phase::Released);
    assert!(execution.status.running_process.is_none());
    assert_eq!(
        std::fs::read(runtime.dir(&spec().id).join("rootfs.ext4")).unwrap(),
        b"confirmed candidate"
    );
    assert!(!runtime.dir(&spec().id).join("previous.ext4").exists());
    let mut late_restart = execution.request.clone();
    late_restart.sequence += 1;
    late_restart.document_generation += 1;
    late_restart.action = Action::StartCandidate;
    late_restart.launch_nonce = "expired-committed-restart".into();
    assert!(authorize_time(Some(&execution), &late_restart).is_err());
    assert!(execution.committed_restart_nonce.is_none());
    assert!(owns(&runtime, &spec().id).unwrap());
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn a_tool_keeps_the_cancelled_owners_lease_without_leaking_it_into_normal_children() {
    let path = scratch();
    let runtime = runtime(&path);
    let lease = execution_lock(&runtime, &spec().id).unwrap();
    assert!(unsafe { libc::fcntl(lease.0.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0);
    let mut command = guarded_tool(Path::new("sleep"), &lease).unwrap();
    let mut tool = command.arg("30").kill_on_drop(true).spawn().unwrap();
    assert!(unsafe { libc::fcntl(lease.0.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0);
    let mut ordinary = tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    drop(command);
    drop(lease);
    assert!(execution_lock(&runtime, &spec().id).is_err());
    tool.kill().await.unwrap();
    let next = execution_lock(&runtime, &spec().id).unwrap();
    assert!(ordinary.try_wait().unwrap().is_none());
    ordinary.kill().await.unwrap();
    drop(next);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
#[ignore = "subprocess fixture invoked by the parent-death lease regression"]
async fn execution_lease_parent_fixture() {
    let path =
        PathBuf::from(std::env::var_os("GRUND_VM_EXECUTION_LEASE_FIXTURE").expect("fixture path"));
    let runtime = runtime(&path);
    assert_eq!(unsafe { libc::close(libc::STDIN_FILENO) }, 0);
    let lease = execution_lock(&runtime, &spec().id).unwrap();
    assert_eq!(lease.0.as_raw_fd(), libc::STDIN_FILENO);
    let mut command = guarded_tool(Path::new("sleep"), &lease).unwrap();
    let mut tool = command
        .arg("30")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    drop(command);
    drop(lease);
    std::fs::write(path.join("lease-tool.pid"), tool.id().unwrap().to_string()).unwrap();
    tokio::time::sleep(Duration::from_secs(10)).await;
    tool.kill().await.unwrap();
}

#[tokio::test]
async fn losing_the_agent_process_kills_its_tool_and_releases_only_the_tools_inherited_lease() {
    let path = scratch();
    let runtime = runtime(&path);
    let mut parent = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "replacement::tests::execution_lease_parent_fixture",
            "--nocapture",
        ])
        .env("GRUND_VM_EXECUTION_LEASE_FIXTURE", &path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Some(pid) = std::fs::read_to_string(path.join("lease-tool.pid"))
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
        {
            break pid;
        }
        assert!(
            parent.try_wait().unwrap().is_none(),
            "lease fixture exited before spawning its tool"
        );
        assert!(
            tokio::time::Instant::now() < until,
            "lease fixture did not publish its tool"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let observed = process_identity(pid).unwrap().unwrap();
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(raw >= 0);
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    assert!(execution_lock(&runtime, &spec().id).is_err());
    parent.kill().await.unwrap();
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while !pidfd_exited(&pidfd).unwrap() && tokio::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let parent_death_stopped_tool = pidfd_exited(&pidfd).unwrap();
    if !parent_death_stopped_tool {
        fence_identity(&observed).await.unwrap();
    }
    assert!(
        parent_death_stopped_tool,
        "tool survived its actual parent process"
    );
    let next = execution_lock(&runtime, &spec().id).unwrap();
    drop(next);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn jail_association_uses_pinned_kernel_objects_and_refuses_replaced_paths() {
    let path = scratch();
    let executable = path.join("firecracker");
    let alias = path.join("same-executable");
    let other = path.join("different-executable");
    std::fs::write(&executable, b"same contents").unwrap();
    std::fs::hard_link(&executable, &alias).unwrap();
    std::fs::write(&other, b"same contents").unwrap();
    let held = File::open(&executable).unwrap();
    let observed = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
    assert!(same_kernel_object(&observed, &alias).unwrap());
    assert!(!same_kernel_object(&observed, &other).unwrap());
    let symlink = path.join("symlink");
    std::os::unix::fs::symlink(&executable, &symlink).unwrap();
    assert!(same_kernel_object(&observed, &symlink).is_err());
    std::fs::remove_file(&executable).unwrap();
    std::fs::write(&executable, b"same contents").unwrap();
    assert!(!same_kernel_object(&observed, &executable).unwrap());

    let root = path.join("root");
    std::fs::create_dir(&root).unwrap();
    let held_root = File::open(&root).unwrap();
    let observed_root = PathBuf::from(format!("/proc/self/fd/{}", held_root.as_raw_fd()));
    assert!(same_kernel_object(&observed_root, &root).unwrap());
    std::fs::rename(&root, path.join("previous-root")).unwrap();
    std::fs::create_dir(&root).unwrap();
    assert!(!same_kernel_object(&observed_root, &root).unwrap());
    drop((held, held_root));
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn a_cancelled_launch_fences_only_its_pinned_process() {
    use std::os::unix::process::ExitStatusExt;

    let mut candidate = tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut other = tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let launch = LaunchGuard::new(&mut candidate).unwrap();
    drop(launch);
    let stopped = tokio::time::timeout(Duration::from_secs(2), candidate.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stopped.signal(), Some(libc::SIGKILL));
    assert!(other.try_wait().unwrap().is_none());
    other.kill().await.unwrap();
}

#[tokio::test]
async fn a_configured_launch_survives_the_temporary_fence_handoff() {
    let mut candidate = tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    LaunchGuard::new(&mut candidate).unwrap().finish();
    assert!(candidate.try_wait().unwrap().is_none());
    candidate.kill().await.unwrap();
}

#[tokio::test]
async fn an_exited_child_cannot_arm_a_launch_fence() {
    let mut candidate = tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, candidate.id().unwrap(), 0) };
    assert!(raw >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    fence_pidfd(&fd).await.unwrap();
    assert!(LaunchGuard::new(&mut candidate).is_err());
    candidate.wait().await.unwrap();
}
