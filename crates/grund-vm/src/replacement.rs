//! Offline, locally fenced execution of an already authorized guest replacement.

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use grund_agent::{
    join::{PinnedKey, Record},
    vm::{
        VmImage, VmProcessIdentity, VmReplacementAction as Action, VmReplacementPhase as Phase,
        VmReplacementRequest as Request, VmReplacementStatus as Status, VmSpec,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Firecracker, Shape, api::Api};

/// The supported x86_64 kernel remains unchanged by root replacement.
pub const RETAINED_KERNEL: &str =
    "9204218e8bcca6ac23848d74f45df2eb19d7f31e8277840a7d145a0df8b078d2";
const JOURNAL_VERSION: u32 = 1;
const MAX_JOURNAL: u64 = 65536;
const MAX_RECORD: usize = 32768;
const IDENTITY_DIR: &str = "/var/lib/grund/agent";
const IDENTITY_FILES: [&str; 2] = ["machine.key", "machine.json"];
const MAX_OPERATION_NONCES: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DiskIdentity {
    device: u64,
    inode: u64,
}

impl DiskIdentity {
    fn of(path: &Path) -> anyhow::Result<Self> {
        let meta = std::fs::symlink_metadata(path)?;
        ensure!(
            meta.is_file() && meta.nlink() <= 3,
            "replacement disk is not a bounded regular file"
        );
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
        })
    }
    fn matches(&self, path: &Path) -> bool {
        Self::of(path).as_ref().is_ok_and(|got| got == self)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    request: Request,
    status: Status,
    base_shape: Shape,
    old_image: VmImage,
    old_disk: DiskIdentity,
    candidate_disk: Option<DiskIdentity>,
    old_process: Option<VmProcessIdentity>,
    candidate_process: Option<VmProcessIdentity>,
    used_nonces: Vec<String>,
    launch_pending: bool,
    rollback_launch: bool,
    launch_boot_id: String,
    pending_predecessor: Option<VmProcessIdentity>,
    #[serde(default)]
    committed: bool,
    #[serde(default)]
    committed_restart_nonce: Option<String>,
    #[serde(default)]
    release_accepted_running: bool,
    #[serde(default)]
    operation_generation: u64,
    #[serde(default)]
    operation_nonces: Vec<String>,
}

fn now_ms() -> anyhow::Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
fn journal_dir(runtime: &Firecracker, id: &str) -> PathBuf {
    runtime.inner.config.data_dir.join("replacements").join(id)
}
fn journal_path(runtime: &Firecracker, id: &str) -> PathBuf {
    journal_dir(runtime, id).join("execution.json")
}

fn protected_dir(path: &Path) -> anyhow::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "replacement requires root-owned non-writable directories"
    );
    Ok(())
}

fn protected_ancestry(path: &Path) -> anyhow::Result<()> {
    ensure!(
        path.is_absolute(),
        "replacement requires an absolute protected data directory"
    );
    for ancestor in path.ancestors() {
        protected_dir(ancestor)?;
    }
    Ok(())
}

fn secure_dir(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
        sync_dir(path.parent().context("directory parent")?)?;
    }
    protected_dir(path)
}

fn sync_dir(path: &Path) -> anyhow::Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn atomic_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let parent = path.parent().context("journal parent")?;
    let tmp = parent.join(format!(".{}.tmp", uuid::Uuid::now_v7()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        serde_json::to_writer(&mut file, value)?;
        ensure!(
            file.metadata()?.len() <= MAX_JOURNAL,
            "execution record exceeds its durable size bound"
        );
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0
            && meta.len() <= MAX_JOURNAL
            && meta.nlink() == 1,
        "unsafe execution journal"
    );
    Ok(Some(serde_json::from_reader(file)?))
}

fn load(runtime: &Firecracker, id: &str) -> anyhow::Result<Option<Journal>> {
    let mut journal: Option<Journal> = read_json(&journal_path(runtime, id))?;
    if let Some(journal) = &mut journal {
        ensure!(
            journal.version == JOURNAL_VERSION && journal.status.id == id,
            "unknown or mismatched execution journal"
        );
        journal.committed |= journal.committed_restart_nonce.is_some()
            || matches!(
                journal.status.phase,
                Phase::Committed | Phase::Releasing | Phase::Released
            );
        ensure!(
            !journal.committed || journal.status.phase != Phase::RolledBack,
            "committed execution has contradictory rollback state"
        );
        if journal.operation_generation == 0 {
            journal.operation_generation = journal.request.document_generation;
        }
        if journal.operation_nonces.is_empty() {
            for nonce in journal
                .used_nonces
                .iter()
                .chain([&journal.request.launch_nonce, &journal.status.launch_nonce])
            {
                if !journal.operation_nonces.contains(nonce) {
                    journal.operation_nonces.push(nonce.clone());
                }
            }
        }
        ensure!(
            journal.operation_nonces.len() <= MAX_OPERATION_NONCES,
            "operation nonce history exceeds the execution journal bound"
        );
    }
    Ok(journal)
}

fn save(runtime: &Firecracker, journal: &Journal) -> anyhow::Result<()> {
    atomic_json(&journal_path(runtime, &journal.status.id), journal)
}

pub(crate) struct ExecutionLock(File);

pub(crate) fn execution_lock(runtime: &Firecracker, id: &str) -> anyhow::Result<ExecutionLock> {
    let base = runtime.inner.config.data_dir.join("execution-locks");
    if !base.exists() {
        std::fs::DirBuilder::new().mode(0o700).create(&base)?;
    }
    let meta = std::fs::symlink_metadata(&base)?;
    ensure!(
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0,
        "unsafe VM lock directory"
    );
    let path = base.join(id);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o022 == 0,
        "unsafe VM execution lock"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "VM execution is already locked"
    );
    Ok(ExecutionLock(file))
}

pub(crate) fn owns(runtime: &Firecracker, id: &str) -> anyhow::Result<bool> {
    Ok(load(runtime, id)?.is_some_and(|journal| !terminal(&journal)))
}

fn terminal(journal: &Journal) -> bool {
    (journal.status.phase == Phase::RolledBack && !journal.committed)
        || (journal.status.phase == Phase::Released && journal.release_accepted_running)
}

fn debugfs() -> Option<PathBuf> {
    ["/usr/sbin/debugfs", "/sbin/debugfs"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| {
            std::fs::symlink_metadata(path).is_ok_and(|meta| {
                meta.is_file()
                    && meta.uid() == 0
                    && meta.mode() & 0o022 == 0
                    && meta.mode() & 0o111 != 0
            })
        })
}

pub(crate) fn version(runtime: &Firecracker) -> u32 {
    if !cfg!(target_arch = "x86_64")
        || !crate::running_as_root()
        || runtime.inner.jail.is_none()
        || debugfs().is_none()
    {
        return 0;
    }
    let jail = runtime.inner.jail.as_ref().expect("checked jail");
    for path in [&runtime.inner.config.firecracker, &jail.jailer] {
        if !std::fs::metadata(path).is_ok_and(|meta| {
            meta.is_file()
                && meta.uid() == 0
                && meta.mode() & 0o022 == 0
                && meta.mode() & 0o111 != 0
        }) {
            return 0;
        }
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
    if fd < 0 {
        return 0;
    }
    unsafe {
        libc::close(fd as i32);
    }
    let raw = unsafe {
        libc::memfd_create(
            c"grund-replacement-probe".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return 0;
    }
    let memfd = unsafe { OwnedFd::from_raw_fd(raw) };
    if unsafe {
        libc::fcntl(
            memfd.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    } != 0
    {
        return 0;
    }
    if protected_ancestry(&runtime.inner.config.data_dir).is_err() {
        return 0;
    }
    1
}

fn process_uid(pid: u32) -> anyhow::Result<Option<u32>> {
    let file = match File::open(format!("/proc/{pid}/status")) {
        Ok(file) => file,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let mut reader = BufReader::new(file);
    let mut line = String::with_capacity(128);
    for _ in 0..16 {
        match reader.read_line(&mut line) {
            Ok(0) => return Ok(None),
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        ensure!(line.len() <= 4096, "incomplete process ownership evidence");
        if let Some(ids) = line.strip_prefix("Uid:") {
            return Ok(Some(
                ids.split_whitespace()
                    .nth(1)
                    .context("missing effective process uid")?
                    .parse()?,
            ));
        }
        line.clear();
    }
    anyhow::bail!("process has no bounded uid evidence")
}

fn process_identity(pid: u32) -> anyhow::Result<Option<VmProcessIdentity>> {
    Ok(process_record(pid)?.and_then(|(identity, running)| running.then_some(identity)))
}

fn process_start_identity(pid: u32) -> anyhow::Result<Option<VmProcessIdentity>> {
    Ok(process_record(pid)?.map(|(identity, _)| identity))
}

fn process_record(pid: u32) -> anyhow::Result<Option<(VmProcessIdentity, bool)>> {
    let dir = PathBuf::from(format!("/proc/{pid}"));
    let stat = match std::fs::read_to_string(dir.join("stat")) {
        Ok(stat) => stat,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let Some(uid) = process_uid(pid)? else {
        return Ok(None);
    };
    let (_, fields) = stat.rsplit_once(')').context("invalid process stat")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    ensure!(fields.len() > 19, "incomplete process identity");
    let running = fields[0] != "Z" && fields[0] != "X";
    Ok(Some((
        VmProcessIdentity {
            pid,
            start_time_ticks: fields[19].parse()?,
            boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .into(),
            uid,
        },
        running,
    )))
}

fn same_kernel_object(observed: &Path, expected: &Path) -> anyhow::Result<bool> {
    let observed_file = File::open(observed)?;
    let observed = observed_file.metadata()?;
    let expected = std::fs::symlink_metadata(expected)?;
    ensure!(
        expected.is_file() || expected.is_dir(),
        "jail association is not a regular file or directory"
    );
    Ok(observed.dev() == expected.dev() && observed.ino() == expected.ino())
}

pub(crate) struct LaunchGuard {
    pub(crate) pid: u32,
    fd: OwnedFd,
    armed: bool,
}

impl LaunchGuard {
    pub(crate) fn new(child: &mut tokio::process::Child) -> anyhow::Result<Self> {
        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("the spawned VMM has already exited"))?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        ensure!(raw >= 0, "cannot pin the spawned VMM");
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        ensure!(
            child.try_wait()?.is_none(),
            "the spawned VMM already exited"
        );
        Ok(Self {
            pid,
            fd,
            armed: true,
        })
    }

    pub(crate) async fn fence(&mut self) -> anyhow::Result<()> {
        fence_pidfd(&self.fd).await?;
        self.armed = false;
        Ok(())
    }

    pub(crate) fn finish(mut self) {
        self.armed = false;
    }
}

impl Drop for LaunchGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = signal_pidfd(&self.fd);
        }
    }
}

pub(crate) fn finish_failed_launch(dir: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(dir.join("launch.intent")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    sync_dir(dir)
}

fn validate_process_owner(
    runtime: &Firecracker,
    dir: &Path,
    identity: &VmProcessIdentity,
) -> anyhow::Result<()> {
    let octet = crate::read_address(dir).context("VM has no reserved address")?;
    ensure!(
        identity.uid == crate::jail::uid(octet),
        "VMM process uid does not own this VM"
    );
    let exe = PathBuf::from(format!("/proc/{}/exe", identity.pid));
    let expected = runtime
        .inner
        .jail
        .as_ref()
        .context("replacement needs jailer")?
        .root(dir)
        .join("firecracker");
    ensure!(
        same_kernel_object(&exe, &expected)?,
        "VMM executable does not belong to this VM's jail"
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchIntent {
    boot_id: String,
    previous: Option<VmProcessIdentity>,
}

pub(crate) fn check_launch_intent(dir: &Path) -> anyhow::Result<()> {
    let Some(intent): Option<LaunchIntent> = read_json(&dir.join("launch.intent"))? else {
        return Ok(());
    };
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let current: Option<VmProcessIdentity> = read_json(&dir.join("process.json"))?;
    ensure!(
        boot_id.trim() != intent.boot_id || (current.is_some() && current != intent.previous),
        "unidentified VMM launch may still exist"
    );
    std::fs::remove_file(dir.join("launch.intent"))?;
    sync_dir(dir)
}

fn write_launch_intent(dir: &Path) -> anyhow::Result<()> {
    atomic_json(
        &dir.join("launch.intent"),
        &LaunchIntent {
            boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .into(),
            previous: read_json(&dir.join("process.json"))?,
        },
    )
}

pub(crate) fn spawn_prepared(
    dir: &Path,
    prepare: impl FnOnce() -> Result<tokio::process::Child, String>,
) -> Result<tokio::process::Child, String> {
    check_launch_intent(dir).map_err(|error| format!("launch fence: {error:#}"))?;
    match write_launch_intent(dir)
        .map_err(|error| format!("launch fence: {error:#}"))
        .and_then(|()| prepare())
    {
        Ok(child) => Ok(child),
        Err(error) => {
            let cleared = (|| {
                match std::fs::remove_file(dir.join("launch.intent")) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                File::open(dir)?.sync_all()
            })();
            cleared.map_err(|cleanup| {
                format!("{error}; unspawned launch receipt cleanup failed: {cleanup}")
            })?;
            Err(error)
        }
    }
}

pub(crate) fn record_process(runtime: &Firecracker, dir: &Path, pid: u32) -> anyhow::Result<()> {
    let identity = process_identity(pid)?.context("VMM exited before its identity was recorded")?;
    if runtime.inner.jail.is_some() {
        validate_process_owner(runtime, dir, &identity)?;
    }
    atomic_json(&dir.join("process.json"), &identity)?;
    std::fs::remove_file(dir.join("launch.intent"))?;
    sync_dir(dir)
}

fn sole_vm_process(uid: u32, expected_pid: u32) -> anyhow::Result<()> {
    let mut count = 0;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        count += 1;
        ensure!(
            count <= 65536,
            "process ownership scan exceeds safety bound"
        );
        let Some(owner) = process_uid(pid)? else {
            continue;
        };
        if owner == uid && pid != expected_pid {
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if raw < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            ensure!(raw >= 0, "cannot establish exclusive VMM process ownership");
            let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
            ensure!(pidfd_exited(&fd)?, "multiple processes use this VM's uid");
        }
    }
    Ok(())
}

fn disk_is_open_by(pid: u32, disk: &DiskIdentity) -> anyhow::Result<bool> {
    let mut count = 0;
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        let entry = entry?;
        count += 1;
        ensure!(count <= 1024, "VMM descriptor scan exceeds safety bound");
        if std::fs::metadata(entry.path()).is_ok_and(|meta| {
            meta.is_file() && meta.dev() == disk.device && meta.ino() == disk.inode
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn legacy_api_owner(
    runtime: &Firecracker,
    dir: &Path,
    identity: &VmProcessIdentity,
) -> anyhow::Result<()> {
    let socket = runtime.socket(dir);
    let exchange = async {
        let mut stream = tokio::net::UnixStream::connect(&socket).await?;
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = u32::try_from(std::mem::size_of::<libc::ucred>())?;
        ensure!(
            unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    std::ptr::from_mut(&mut peer).cast(),
                    &mut length,
                )
            } == 0,
            "cannot establish API socket peer identity"
        );
        ensure!(
            peer.pid == i32::try_from(identity.pid)? && peer.uid == identity.uid,
            "API socket is not owned by the expected VMM"
        );
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n")
            .await?;
        let mut raw = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            ensure!(
                raw.len() <= 8192,
                "legacy VMM API reply exceeds safety bound"
            );
            if let Some((status, body)) = crate::api::parse_reply(&raw) {
                ensure!(status == 200, "legacy VMM API observation refused");
                let info: serde_json::Value = serde_json::from_slice(&body)?;
                ensure!(
                    info["id"].as_str() == Some(crate::jail::id(dir).as_str())
                        && info["state"].as_str() == Some("Running"),
                    "API does not identify this running VM"
                );
                return anyhow::Ok(());
            }
            let n = stream.read(&mut buffer).await?;
            ensure!(n > 0, "legacy VMM API closed before identity observation");
            raw.extend_from_slice(&buffer[..n]);
        }
    };
    tokio::time::timeout(Duration::from_secs(2), exchange)
        .await
        .context("legacy VMM identity observation deadline")?
}

async fn adopt_or_recorded(
    runtime: &Firecracker,
    dir: &Path,
) -> anyhow::Result<Option<VmProcessIdentity>> {
    check_launch_intent(dir)?;
    if read_json::<VmProcessIdentity>(&dir.join("process.json"))?.is_some() {
        return recorded_process(runtime, dir);
    }
    let pid_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join("firecracker.pid"))?;
    let meta = pid_file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.mode() & 0o022 == 0
            && meta.nlink() == 1
            && meta.len() <= 32,
        "unsafe legacy VMM pid file"
    );
    let pid = crate::read_pid(dir).context("legacy VM has no valid pid")?;
    let before = process_identity(pid)?
        .context("legacy VM is not running; offline ownership cannot be adopted")?;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    ensure!(raw >= 0, "cannot pin legacy VMM process identity");
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    ensure!(
        process_identity(pid)?.as_ref() == Some(&before),
        "legacy VMM changed during adoption"
    );
    validate_process_owner(runtime, dir, &before)?;
    sole_vm_process(before.uid, pid)?;
    let jail = runtime
        .inner
        .jail
        .as_ref()
        .context("legacy VM is not jailed")?;
    let root = jail.root(dir);
    ensure!(
        same_kernel_object(&PathBuf::from(format!("/proc/{pid}/root")), &root)?
            && same_kernel_object(&PathBuf::from(format!("/proc/{pid}/cwd")), &root)?,
        "legacy VMM jail association does not match"
    );
    let executable = &runtime.inner.config.firecracker;
    protected_ancestry(executable.parent().context("host executable parent")?)?;
    let executable_meta = std::fs::metadata(executable)?;
    ensure!(
        executable_meta.is_file()
            && executable_meta.uid() == 0
            && executable_meta.mode() & 0o022 == 0,
        "host Firecracker executable is not trusted"
    );
    ensure!(
        crate::image::file_digest(executable).await?
            == crate::image::file_digest(&PathBuf::from(format!("/proc/{pid}/exe"))).await?,
        "legacy VMM executable differs from the configured runtime"
    );
    let args = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(
        args.len() <= 8192,
        "legacy VMM arguments exceed safety bound"
    );
    let args: Vec<_> = args
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    ensure!(
        args.windows(2)
            .any(|pair| pair == [b"--api-sock".as_slice(), b"fc.sock".as_slice()]),
        "legacy VMM arguments do not name its jailed API socket"
    );
    ensure!(
        !args
            .iter()
            .any(|arg| *arg == b"--config-file" || *arg == b"--no-api"),
        "legacy VMM uses an unsupported alternate launch path"
    );
    let disk = DiskIdentity::of(&dir.join("rootfs.ext4"))?;
    ensure!(
        disk.matches(&root.join("rootfs.ext4")) && disk_is_open_by(pid, &disk)?,
        "legacy VMM does not hold this VM's root disk"
    );
    if let Some(cgroups) = &runtime.inner.cgroups
        && cgroups.of(&crate::jail::id(dir)).exists()
    {
        let membership = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        let expected = format!("0::/{}/{}", cgroups.parent, crate::jail::id(dir));
        ensure!(
            membership.lines().any(|line| line == expected),
            "legacy VMM cgroup association does not match"
        );
    }
    legacy_api_owner(runtime, dir, &before).await?;
    sole_vm_process(before.uid, pid)?;
    ensure!(
        process_identity(pid)?.as_ref() == Some(&before) && disk_is_open_by(pid, &disk)?,
        "legacy VMM changed during adoption"
    );
    let mut state = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    ensure!(
        unsafe { libc::poll(&mut state, 1, 0) } == 0,
        "legacy VMM exited during adoption"
    );
    atomic_json(&dir.join("process.json"), &before)?;
    Ok(Some(before))
}

fn recorded_process(
    runtime: &Firecracker,
    dir: &Path,
) -> anyhow::Result<Option<VmProcessIdentity>> {
    check_launch_intent(dir)?;
    let identity: Option<VmProcessIdentity> = read_json(&dir.join("process.json"))?;
    if let Some(identity) = &identity {
        if process_identity(identity.pid)?.as_ref() == Some(identity) {
            validate_process_owner(runtime, dir, identity)?;
        } else if let Some(pid) = crate::read_pid(dir) {
            ensure!(
                process_identity(pid)?.is_none(),
                "PID ownership changed; refusing uncertainty"
            );
        }
    } else if let Some(pid) = crate::read_pid(dir) {
        ensure!(
            process_identity(pid)?.is_none(),
            "live legacy VMM has no durable process identity"
        );
    } else {
        anyhow::bail!("VM has no durable launch identity; refusing uncertain offline state");
    }
    Ok(identity)
}

fn pidfd_exited(fd: &OwnedFd) -> anyhow::Result<bool> {
    let mut state = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut state, 1, 0) };
    ensure!(ready >= 0, "cannot observe VMM thread-group exit");
    Ok(ready > 0 && state.revents & libc::POLLIN != 0)
}

fn same_process_start(identity: &VmProcessIdentity) -> anyhow::Result<bool> {
    let Some(current) = process_start_identity(identity.pid)? else {
        return Ok(false);
    };
    if current.start_time_ticks != identity.start_time_ticks || current.boot_id != identity.boot_id
    {
        return Ok(false);
    }
    ensure!(
        current.uid == identity.uid,
        "VMM process ownership changed; refusing uncertainty"
    );
    Ok(true)
}

async fn fence_identity(identity: &VmProcessIdentity) -> anyhow::Result<()> {
    if !same_process_start(identity)? {
        return Ok(());
    }
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.pid, 0) };
    if raw < 0 && !same_process_start(identity)? {
        return Ok(());
    }
    ensure!(raw >= 0, "cannot open VMM pidfd");
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    if !same_process_start(identity)? || pidfd_exited(&fd)? {
        return Ok(());
    }
    fence_pidfd(&fd).await
}

fn signal_pidfd(fd: &OwnedFd) -> anyhow::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    ensure!(
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
        "cannot physically fence VMM"
    );
    Ok(())
}

async fn fence_pidfd(fd: &OwnedFd) -> anyhow::Result<()> {
    signal_pidfd(fd)?;
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    while !pidfd_exited(fd)? {
        ensure!(
            tokio::time::Instant::now() < end,
            "VMM did not exit; replacement refused"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

pub(crate) async fn fence_process(runtime: &Firecracker, dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    check_launch_intent(dir)?;
    let identity = if runtime.inner.jail.is_none() {
        let identity: Option<VmProcessIdentity> = read_json(&dir.join("process.json"))?;
        if identity.is_none() {
            ensure!(
                crate::read_pid(dir).is_none_or(|pid| !crate::process_alive(pid)),
                "live VMM has no process-start identity"
            );
        }
        identity
    } else {
        adopt_or_recorded(runtime, dir).await?
    };
    if let Some(identity) = identity {
        if process_identity(identity.pid)?.as_ref() == Some(&identity) {
            let asked = Api::new(runtime.socket(dir))
                .put("/actions", &json!({"action_type": "SendCtrlAltDel"}))
                .await;
            if asked.is_ok() {
                let until = tokio::time::Instant::now() + crate::STOP_GRACE;
                while process_identity(identity.pid)?.as_ref() == Some(&identity)
                    && tokio::time::Instant::now() < until
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        fence_identity(&identity).await?;
    }
    Ok(())
}

fn validate_request(spec: &VmSpec, request: &Request) -> anyhow::Result<()> {
    ensure!(crate::valid_id(&spec.id), "invalid VM id");
    ensure!(
        spec.mmds["vm"]["id"].as_str() == Some(spec.id.as_str()) && spec.mmds["grund"].is_object(),
        "replacement requires canonical VM metadata"
    );
    for value in [
        &request.guest_machine_id,
        &request.attempt_id,
        &request.launch_nonce,
    ] {
        ensure!(
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
            "invalid bounded replacement identifier"
        );
    }
    ensure!(
        request.sequence > 0 && request.document_generation > 0,
        "replacement fences must be nonzero"
    );
    ensure!(
        request.image.kernel.sha256 == RETAINED_KERNEL
            && spec.image.kernel.sha256 == RETAINED_KERNEL,
        "replacement requires the retained x86_64 kernel"
    );
    ensure!(
        request.image.rootfs.sha256.len() == 64
            && request
                .image
                .rootfs
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid replacement image digest"
    );
    for artifact in [
        &spec.image.kernel,
        &spec.image.rootfs,
        &request.image.kernel,
        &request.image.rootfs,
    ] {
        ensure!(
            !artifact.url.is_empty() && artifact.url.len() <= 4096,
            "artifact URL exceeds journal boundary"
        );
    }
    let key = VerifyingKey::from_bytes(&request.registration_key)
        .context("invalid registered public key")?;
    ensure!(!key.is_weak(), "weak registered public key");
    Ok(())
}

fn same_operation(left: &Request, right: &Request) -> bool {
    left.attempt_id == right.attempt_id
        && left.sequence == right.sequence
        && left.action == right.action
        && left.image == right.image
        && left.guest_machine_id == right.guest_machine_id
        && left.registration_key == right.registration_key
        && left.launch_nonce == right.launch_nonce
        && left.deadline_unix_ms == right.deadline_unix_ms
}

fn validate_initial_operation(request: &Request) -> anyhow::Result<()> {
    ensure!(
        matches!(
            (request.action, request.sequence),
            (Action::Prepare, 1) | (Action::Rollback, 2)
        ),
        "new execution requires Prepare1 or pre-authorization Rollback2"
    );
    Ok(())
}

fn authorize_time(journal: Option<&Journal>, request: &Request) -> anyhow::Result<()> {
    if now_ms()? < request.deadline_unix_ms {
        return Ok(());
    }
    let prior = journal.context("replacement authorization expired before execution began")?;
    ensure!(
        prior.request.attempt_id == request.attempt_id,
        "replacement authorization expired for this attempt"
    );
    if prior.committed && matches!(request.action, Action::Commit | Action::ReleaseOld) {
        return Ok(());
    }
    ensure!(
        same_operation(&prior.request, request),
        "expired authorization cannot begin a new operation"
    );
    let completed = matches!(
        (request.action, prior.status.phase),
        (Action::Prepare, Phase::Prepared)
            | (Action::Quiesce, Phase::Quiesced)
            | (Action::StartCandidate, Phase::CandidateRunning)
            | (Action::Rollback, Phase::RolledBack)
            | (Action::ReleaseOld, Phase::Released)
    );
    ensure!(
        completed,
        "expired authorization cannot resume incomplete physical work"
    );
    Ok(())
}

fn accept(journal: &mut Journal, request: &Request) -> anyhow::Result<bool> {
    ensure!(
        journal.request.attempt_id == request.attempt_id,
        "replacement attempt already owns this VM"
    );
    ensure!(
        request.document_generation >= journal.request.document_generation
            && request.sequence >= journal.request.sequence,
        "stale replacement fence"
    );
    ensure!(
        journal.request.image.kernel.sha256 == request.image.kernel.sha256
            && journal.request.image.rootfs.sha256 == request.image.rootfs.sha256
            && journal.request.guest_machine_id == request.guest_machine_id
            && journal.request.registration_key == request.registration_key,
        "replacement identity or immutable image changed"
    );
    if request.sequence == journal.request.sequence {
        ensure!(
            same_operation(request, &journal.request),
            "contradictory replacement replay"
        );
        journal.request.document_generation = request.document_generation;
        journal.status.document_generation = request.document_generation;
        return Ok(false);
    }
    ensure!(
        request.document_generation > journal.request.document_generation,
        "new operation requires a new document generation"
    );
    ensure!(
        journal.status.phase != Phase::RolledBack,
        "replacement already rolled back"
    );
    ensure!(
        journal.status.phase != Phase::Released
            || (journal.committed && request.action == Action::StartCandidate)
            || (journal.committed
                && !journal.release_accepted_running
                && request.action == Action::ReleaseOld),
        "replacement already terminal"
    );
    let fresh_transition = !journal.committed
        && request.action == Action::Quiesce
        && journal.status.phase == Phase::Prepared
        || request.action == Action::StartCandidate
            && (journal.committed
                || journal.status.phase == Phase::Quiesced
                || (matches!(journal.status.phase, Phase::Starting | Phase::Uncertain)
                    && !journal.rollback_launch))
        || !journal.committed && request.action == Action::Rollback;
    if matches!(
        request.action,
        Action::Quiesce | Action::StartCandidate | Action::Rollback
    ) {
        ensure!(
            fresh_transition && request.launch_nonce != journal.status.launch_nonce,
            "operation requires its ordered fresh nonce transition"
        );
        ensure!(
            !journal.operation_nonces.contains(&request.launch_nonce)
                && !journal.used_nonces.contains(&request.launch_nonce),
            "operation nonce was already authorized or launched"
        );
    } else {
        ensure!(
            request.launch_nonce == journal.status.launch_nonce,
            "unrelated operation nonce changed"
        );
    }
    if !journal.operation_nonces.contains(&request.launch_nonce) {
        ensure!(
            journal.operation_nonces.len() < MAX_OPERATION_NONCES,
            "operation nonce history bound exceeded"
        );
        journal.operation_nonces.push(request.launch_nonce.clone());
    }
    if request.action == Action::Quiesce {
        journal.status.launch_nonce = request.launch_nonce.clone();
    }
    journal.operation_generation = request.document_generation;
    journal.request = request.clone();
    journal.status.requested_image = request.image.clone();
    journal.status.sequence = request.sequence;
    journal.status.document_generation = request.document_generation;
    Ok(true)
}

fn transition(journal: &mut Journal, phase: Phase) {
    journal.status.phase = phase;
    journal.status.reason = None;
}

pub(crate) async fn execute(
    runtime: &Firecracker,
    spec: &VmSpec,
    request: &Request,
) -> anyhow::Result<Status> {
    ensure!(
        version(runtime) == 1,
        "replacement version0: root x86_64 jailed runtime, pidfd and trusted debugfs required"
    );
    validate_request(spec, request)?;
    let lock = runtime.lock(&spec.id);
    let _held = lock.lock().await;
    let disk_lock = execution_lock(runtime, &spec.id)?;
    let dir = runtime.dir(&spec.id);
    protected_dir(&runtime.inner.config.data_dir.join("vms"))?;
    protected_dir(&dir)?;
    secure_dir(&runtime.inner.config.data_dir.join("replacements"))?;
    secure_dir(&journal_dir(runtime, &spec.id))?;
    let prior = load(runtime, &spec.id)?;
    authorize_time(prior.as_ref(), request)?;
    let mut journal = match prior {
        Some(mut journal) if journal.request.attempt_id == request.attempt_id => {
            accept(&mut journal, request)?;
            journal
        }
        prior => {
            if let Some(prior) = prior {
                ensure!(
                    terminal(&prior)
                        && request.document_generation > prior.request.document_generation,
                    "stale attempt or active replacement"
                );
                ensure!(
                    !prior.used_nonces.contains(&request.launch_nonce),
                    "launch nonce was already used"
                );
            }
            validate_initial_operation(request)?;
            let shape = crate::read_shape(&dir).context("VM has no recorded shape")?;
            ensure!(
                shape == Shape::of(spec),
                "base spec does not match the existing VM"
            );
            let old_process = adopt_or_recorded(runtime, &dir).await?;
            let running_process = match &old_process {
                Some(identity) => {
                    process_identity(identity.pid)?.filter(|current| current == identity)
                }
                None => None,
            };
            Journal {
                version: JOURNAL_VERSION,
                request: request.clone(),
                status: Status {
                    id: spec.id.clone(),
                    attempt_id: request.attempt_id.clone(),
                    sequence: request.sequence,
                    document_generation: request.document_generation,
                    phase: Phase::Preparing,
                    requested_image: request.image.clone(),
                    observed_image: running_process.as_ref().map(|_| spec.image.clone()),
                    launch_nonce: request.launch_nonce.clone(),
                    previous_process: old_process.clone(),
                    running_process,
                    old_root_fenced: false,
                    rollback_available: false,
                    reason: None,
                },
                base_shape: shape,
                old_image: spec.image.clone(),
                old_disk: DiskIdentity::of(&dir.join("rootfs.ext4"))?,
                candidate_disk: None,
                old_process,
                candidate_process: None,
                used_nonces: Vec::new(),
                launch_pending: false,
                rollback_launch: false,
                launch_boot_id: String::new(),
                pending_predecessor: None,
                committed: false,
                committed_restart_nonce: None,
                release_accepted_running: false,
                operation_generation: request.document_generation,
                operation_nonces: vec![request.launch_nonce.clone()],
            }
        }
    };
    recover_launch(runtime, &dir, &mut journal)?;
    validate_base_spec(spec, &journal)?;
    save(runtime, &journal)?;
    let result = run(runtime, spec, &mut journal, &disk_lock).await;
    if let Err(error) = result {
        journal.status.reason = Some(format!("{error:#}").chars().take(1024).collect());
        save(runtime, &journal)?;
        return Err(error);
    }
    refresh_running(&mut journal)?;
    save(runtime, &journal)?;
    Ok(journal.status)
}

fn refresh_running(journal: &mut Journal) -> anyhow::Result<()> {
    if let Some(identity) = &journal.status.running_process
        && process_identity(identity.pid)?.as_ref() != Some(identity)
    {
        journal.status.running_process = None;
        journal.status.observed_image = None;
        if journal.status.phase == Phase::CandidateRunning {
            transition(journal, Phase::Uncertain);
        }
        if journal.status.phase == Phase::Released {
            journal.release_accepted_running = false;
        }
        journal.status.reason =
            Some("the observed VMM no longer runs with its recorded identity".into());
    }
    Ok(())
}

fn validate_base_spec(spec: &VmSpec, journal: &Journal) -> anyhow::Result<()> {
    ensure!(
        spec.id == journal.status.id
            && journal.base_shape.vcpus == spec.vcpus
            && journal.base_shape.memory_mib == spec.memory_mib
            && journal.base_shape.disk_gib == spec.disk_gib,
        "replacement cannot change VM identity or resources"
    );
    let same_image = |image: &VmImage| {
        image
            .kernel
            .sha256
            .eq_ignore_ascii_case(&spec.image.kernel.sha256)
            && image
                .rootfs
                .sha256
                .eq_ignore_ascii_case(&spec.image.rootfs.sha256)
    };
    ensure!(
        same_image(&journal.old_image) || (journal.committed && same_image(&journal.request.image)),
        "VM image changed outside committed pin confirmation"
    );
    Ok(())
}

async fn run(
    runtime: &Firecracker,
    spec: &VmSpec,
    journal: &mut Journal,
    execution: &ExecutionLock,
) -> anyhow::Result<()> {
    let dir = runtime.dir(&spec.id);
    let staged = dir.join("replacement.ext4");
    let old = dir.join("previous.ext4");
    match journal.request.action {
        Action::Prepare => {
            if journal.status.phase == Phase::Prepared {
                return Ok(());
            }
            ensure!(
                journal.status.phase == Phase::Preparing,
                "Prepare is not valid in this phase"
            );
            let timeout =
                Duration::from_millis(u64::try_from(journal.request.deadline_unix_ms - now_ms()?)?);
            tokio::time::Instant::now()
                .checked_add(timeout)
                .context("authorization deadline exceeds runtime clock")?;
            tokio::time::timeout(timeout, async {
                let kernel = runtime
                    .inner
                    .images
                    .ensure(&journal.request.image.kernel)
                    .await?;
                let image = runtime
                    .inner
                    .images
                    .ensure(&journal.request.image.rootfs)
                    .await?;
                for artifact in [&kernel, &image] {
                    let metadata = std::fs::symlink_metadata(artifact)?;
                    ensure!(
                        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                        "verified artifact is not a protected regular file"
                    );
                }
                File::open(&kernel)?.sync_all()?;
                File::open(&image)?.sync_all()?;
                sync_dir(&runtime.inner.config.data_dir.join("images"))?;
                if staged.exists() {
                    std::fs::remove_file(&staged)?;
                }
                crate::copy_disk(&image, &staged, spec.disk_gib)?;
                std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))?;
                File::open(&staged)?.sync_all()?;
                sync_dir(&dir)?;
                anyhow::Ok(())
            })
            .await
            .context("replacement image staging deadline")??;
            journal.candidate_disk = Some(DiskIdentity::of(&staged)?);
            transition(journal, Phase::Prepared);
        }
        Action::Quiesce => {
            if journal.status.phase == Phase::Quiesced {
                return Ok(());
            }
            ensure!(
                matches!(journal.status.phase, Phase::Prepared | Phase::Quiescing),
                "Quiesce is not valid in this phase"
            );
            ensure!(
                journal.old_disk.matches(&dir.join("rootfs.ext4"))
                    && journal
                        .candidate_disk
                        .as_ref()
                        .is_some_and(|disk| disk.matches(&staged)),
                "root identity changed"
            );
            transition(journal, Phase::Quiescing);
            save(runtime, journal)?;
            let current = recorded_process(runtime, &dir)?;
            ensure!(current == journal.old_process, "old VMM identity changed");
            if let Some(identity) = &current {
                fence_identity(identity).await?;
            }
            sole_vm_process(
                crate::jail::uid(crate::read_address(&dir).context("VM address missing")?),
                0,
            )?;
            ensure!(
                current
                    .as_ref()
                    .is_none_or(|identity| process_identity(identity.pid)
                        .is_ok_and(|got| got.as_ref() != Some(identity))),
                "old VMM still runs"
            );
            File::open(dir.join("rootfs.ext4"))?.sync_all()?;
            journal.status.running_process = None;
            journal.status.observed_image = None;
            journal.status.old_root_fenced = true;
            transition(journal, Phase::Quiesced);
        }
        Action::StartCandidate => {
            if journal.committed {
                return restart_committed(runtime, spec, journal).await;
            }
            if journal.status.phase == Phase::CandidateRunning {
                return verify_running(journal, false);
            }
            if journal.launch_pending {
                return uncertain(
                    runtime,
                    journal,
                    "unidentified candidate launch may still exist; refusing another root",
                );
            }
            if matches!(journal.status.phase, Phase::Starting | Phase::Uncertain) {
                ensure!(
                    !journal.rollback_launch,
                    "rollback cannot resume candidate execution"
                );
                if journal.used_nonces.contains(&journal.request.launch_nonce) {
                    return uncertain(
                        runtime,
                        journal,
                        "candidate launch nonce consumed; a fresh authorized nonce is required",
                    );
                }
                if let Some(identity) = &journal.candidate_process {
                    fence_identity(identity).await?;
                }
                ensure!(
                    journal
                        .candidate_disk
                        .as_ref()
                        .is_some_and(|disk| disk.matches(&dir.join("rootfs.ext4"))),
                    "candidate root identity changed"
                );
                transition(journal, Phase::Installing);
                save(runtime, journal)?;
            }
            ensure!(
                matches!(journal.status.phase, Phase::Quiesced | Phase::Installing),
                "StartCandidate is not valid in this phase"
            );
            fence_old(runtime, &dir, journal).await?;
            if journal.status.phase == Phase::Quiesced {
                ensure!(
                    journal.old_disk.matches(&dir.join("rootfs.ext4")),
                    "old root changed"
                );
                ensure!(
                    journal
                        .candidate_disk
                        .as_ref()
                        .is_some_and(|disk| disk.matches(&staged)),
                    "staged root changed"
                );
                let identity =
                    read_identity(&dir.join("rootfs.ext4"), &journal.request, execution).await?;
                write_identity(&staged, &identity, execution).await?;
                File::open(&staged)?.sync_all()?;
                if old.exists() {
                    ensure!(journal.old_disk.matches(&old), "unexpected previous root");
                } else {
                    std::fs::hard_link(dir.join("rootfs.ext4"), &old)?;
                    sync_dir(&dir)?;
                }
                journal.status.rollback_available = true;
                transition(journal, Phase::Installing);
                save(runtime, journal)?;
            }
            let candidate = journal
                .candidate_disk
                .as_ref()
                .context("candidate identity missing")?;
            if !candidate.matches(&dir.join("rootfs.ext4")) {
                ensure!(
                    journal.old_disk.matches(&dir.join("rootfs.ext4"))
                        && candidate.matches(&staged)
                        && journal.old_disk.matches(&old),
                    "ambiguous root installation"
                );
                std::fs::rename(&staged, dir.join("rootfs.ext4"))?;
                sync_dir(&dir)?;
            }
            let mut candidate_spec = spec.clone();
            candidate_spec.image = journal.request.image.clone();
            launch(runtime, &candidate_spec, journal, false).await?;
        }
        Action::Commit => {
            if journal.status.phase == Phase::Committed {
                return finalize_committed(runtime, &dir, journal).await;
            }
            ensure!(
                journal.status.phase == Phase::CandidateRunning,
                "Commit requires a running candidate"
            );
            verify_running(journal, false)?;
            journal.status.rollback_available = false;
            journal.committed = true;
            transition(journal, Phase::Committed);
        }
        Action::ReleaseOld => {
            if journal.status.phase == Phase::Released && journal.release_accepted_running {
                return Ok(());
            }
            ensure!(
                journal.committed
                    && matches!(
                        journal.status.phase,
                        Phase::Committed
                            | Phase::Releasing
                            | Phase::Released
                            | Phase::CandidateRunning
                    ),
                "ReleaseOld requires matching committed execution"
            );
            finalize_committed(runtime, &dir, journal).await?;
            transition(journal, Phase::Releasing);
            save(runtime, journal)?;
            if old.exists() {
                ensure!(
                    journal.old_disk.matches(&old),
                    "previous root identity changed"
                );
                std::fs::remove_file(&old)?;
                sync_dir(&dir)?;
            }
            journal.status.rollback_available = false;
            journal.release_accepted_running = journal.status.running_process.is_some();
            transition(journal, Phase::Released);
        }
        Action::Rollback => {
            ensure!(!journal.committed, "committed target cannot be rolled back");
            if journal.status.phase == Phase::RolledBack {
                return Ok(());
            }
            ensure!(
                !matches!(
                    journal.status.phase,
                    Phase::Committed | Phase::Releasing | Phase::Released
                ),
                "confirmed candidate cannot be rolled back"
            );
            if matches!(journal.status.phase, Phase::Preparing | Phase::Prepared) {
                ensure!(
                    journal.old_disk.matches(&dir.join("rootfs.ext4")),
                    "baseline root changed before quiesce"
                );
                if journal.status.phase == Phase::Prepared {
                    ensure!(
                        journal
                            .candidate_disk
                            .as_ref()
                            .is_some_and(|disk| disk.matches(&staged)),
                        "prepared root identity changed"
                    );
                }
                verify_running(journal, true)?;
                if staged.exists() {
                    std::fs::remove_file(&staged)?;
                }
                let partial = dir.join("replacement.partial");
                if partial.exists() {
                    std::fs::remove_file(partial)?;
                }
                sync_dir(&dir)?;
                journal.status.running_process = journal.old_process.clone();
                journal.status.observed_image = Some(journal.old_image.clone());
                journal.status.launch_nonce = journal.request.launch_nonce.clone();
                journal.status.old_root_fenced = false;
                journal.status.rollback_available = false;
                transition(journal, Phase::RolledBack);
                return Ok(());
            }
            ensure!(
                !journal.used_nonces.contains(&journal.request.launch_nonce)
                    && journal.request.launch_nonce != journal.status.launch_nonce,
                "rollback requires a fresh authorized launch nonce"
            );
            ensure!(
                !journal.launch_pending,
                "unidentified rollback launch may still exist"
            );
            ensure!(
                matches!(
                    journal.status.phase,
                    Phase::Prepared
                        | Phase::Quiescing
                        | Phase::Quiesced
                        | Phase::Installing
                        | Phase::Starting
                        | Phase::CandidateRunning
                        | Phase::RollingBack
                        | Phase::Uncertain
                ),
                "Rollback is not valid in this phase"
            );
            transition(journal, Phase::RollingBack);
            save(runtime, journal)?;
            if let Some(identity) = &journal.candidate_process {
                fence_identity(identity).await?;
            }
            fence_old(runtime, &dir, journal).await?;
            journal.status.running_process = None;
            journal.status.observed_image = None;
            if !journal.old_disk.matches(&dir.join("rootfs.ext4")) {
                ensure!(journal.old_disk.matches(&old), "rollback root missing");
                std::fs::rename(&old, dir.join("rootfs.ext4"))?;
                sync_dir(&dir)?;
            }
            if old.exists() {
                ensure!(journal.old_disk.matches(&old), "unexpected rollback root");
                std::fs::remove_file(&old)?;
            }
            journal.status.old_root_fenced = true;
            if staged.exists() {
                ensure!(
                    journal
                        .candidate_disk
                        .as_ref()
                        .is_some_and(|disk| disk.matches(&staged)),
                    "unexpected staged disk"
                );
                std::fs::remove_file(&staged)?;
            }
            sync_dir(&dir)?;
            journal.status.rollback_available = false;
            let mut old_spec = spec.clone();
            old_spec.image = journal.old_image.clone();
            launch(runtime, &old_spec, journal, true).await?;
            journal.status.rollback_available = false;
        }
    }
    Ok(())
}

async fn restart_committed(
    runtime: &Firecracker,
    spec: &VmSpec,
    journal: &mut Journal,
) -> anyhow::Result<()> {
    if journal.status.phase == Phase::CandidateRunning
        && journal.request.launch_nonce == journal.status.launch_nonce
        && !journal.launch_pending
    {
        return verify_running(journal, false);
    }
    ensure!(
        journal.committed
            && matches!(
                journal.status.phase,
                Phase::Committed
                    | Phase::Releasing
                    | Phase::Released
                    | Phase::Starting
                    | Phase::Uncertain
                    | Phase::CandidateRunning
            ),
        "committed restart is not valid in this phase"
    );
    if journal.launch_pending || journal.used_nonces.contains(&journal.request.launch_nonce) {
        return uncertain(
            runtime,
            journal,
            "committed restart launch is ambiguous or its nonce was consumed; recovery stays paused",
        );
    }
    ensure!(
        journal.request.launch_nonce != journal.status.launch_nonce,
        "committed restart requires a fresh authorized nonce"
    );
    if let Some(reserved) = &journal.committed_restart_nonce {
        ensure!(
            reserved == &journal.request.launch_nonce,
            "the bounded committed restart was already reserved"
        );
    }
    let dir = runtime.dir(&spec.id);
    finalize_committed(runtime, &dir, journal).await?;
    journal.committed_restart_nonce = Some(journal.request.launch_nonce.clone());
    journal.release_accepted_running = false;
    transition(journal, Phase::Starting);
    save(runtime, journal)?;
    if let Some(identity) = &journal.candidate_process {
        fence_identity(identity).await?;
    }
    sole_vm_process(
        crate::jail::uid(crate::read_address(&dir).context("committed VM address missing")?),
        0,
    )?;
    ensure!(
        journal
            .candidate_disk
            .as_ref()
            .is_some_and(|disk| disk.matches(&dir.join("rootfs.ext4"))),
        "committed root changed before restart"
    );
    journal.status.running_process = None;
    journal.status.observed_image = None;
    journal.status.old_root_fenced = true;
    let mut committed_spec = spec.clone();
    committed_spec.image = journal.request.image.clone();
    launch(runtime, &committed_spec, journal, false).await
}

async fn finalize_committed(
    runtime: &Firecracker,
    dir: &Path,
    journal: &mut Journal,
) -> anyhow::Result<()> {
    ensure!(
        journal.committed,
        "execution has not irreversibly committed"
    );
    ensure!(
        !journal.launch_pending,
        "an unidentified launch prevents finalization"
    );
    check_launch_intent(dir)?;
    let candidate = journal
        .candidate_disk
        .as_ref()
        .context("committed root identity missing")?;
    ensure!(
        candidate != &journal.old_disk && candidate.matches(&dir.join("rootfs.ext4")),
        "confirmed root changed"
    );
    let mut shape = journal.base_shape.clone();
    shape.kernel_sha256 = journal.request.image.kernel.sha256.clone();
    shape.rootfs_sha256 = journal.request.image.rootfs.sha256.clone();
    ensure!(
        crate::read_shape(dir).as_ref() == Some(&shape),
        "committed shape changed"
    );
    let uid = crate::jail::uid(crate::read_address(dir).context("committed VM address missing")?);
    let recorded = journal
        .candidate_process
        .as_ref()
        .context("committed process witness missing")?;
    ensure!(recorded.uid == uid, "committed VMM ownership changed");
    let previous = journal
        .old_process
        .as_ref()
        .context("baseline process witness missing")?;
    ensure!(
        previous.uid == uid && previous != recorded,
        "baseline and committed process witnesses conflict"
    );
    fence_identity(previous).await?;
    let running = process_identity(recorded.pid)?.filter(|identity| identity == recorded);
    if let Some(identity) = &running {
        validate_process_owner(runtime, dir, identity)?;
        ensure!(
            disk_is_open_by(identity.pid, candidate)?,
            "committed VMM does not hold the confirmed root"
        );
        sole_vm_process(uid, identity.pid)?;
    } else {
        if same_process_start(recorded)? {
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, recorded.pid, 0) };
            ensure!(raw >= 0, "cannot prove committed VMM thread-group exit");
            let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
            ensure!(
                pidfd_exited(&pidfd)?,
                "committed VMM still has live threads"
            );
        }
        sole_vm_process(uid, 0)?;
        match std::fs::remove_file(dir.join("firecracker.pid")) {
            Ok(()) => sync_dir(dir)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    journal.status.observed_image = running.as_ref().map(|_| journal.request.image.clone());
    journal.status.running_process = running;
    journal.status.old_root_fenced = true;
    journal.status.rollback_available = false;
    Ok(())
}

async fn fence_old(runtime: &Firecracker, dir: &Path, journal: &Journal) -> anyhow::Result<()> {
    if let Some(identity) = &journal.old_process {
        if process_identity(identity.pid)?.as_ref() == Some(identity) {
            validate_process_owner(runtime, dir, identity)?;
        }
        fence_identity(identity).await?;
    }
    sole_vm_process(
        crate::jail::uid(crate::read_address(dir).context("VM address missing")?),
        0,
    )?;
    Ok(())
}

fn verify_running(journal: &Journal, old: bool) -> anyhow::Result<()> {
    let identity = if old {
        &journal.old_process
    } else {
        &journal.candidate_process
    };
    let identity = identity.as_ref().context("missing observed VMM identity")?;
    ensure!(
        process_identity(identity.pid)?.as_ref() == Some(identity),
        "observed VMM no longer runs"
    );
    Ok(())
}

fn uncertain(runtime: &Firecracker, journal: &mut Journal, reason: &str) -> anyhow::Result<()> {
    transition(journal, Phase::Uncertain);
    journal.status.reason = Some(reason.into());
    save(runtime, journal)
}

fn recover_launch(runtime: &Firecracker, dir: &Path, journal: &mut Journal) -> anyhow::Result<()> {
    if !journal.launch_pending {
        return Ok(());
    }
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    if boot_id.trim() != journal.launch_boot_id {
        journal.launch_pending = false;
        journal.status.running_process = None;
        journal.status.observed_image = None;
        journal.status.old_root_fenced = true;
        transition(journal, Phase::Uncertain);
        journal.status.reason = Some(
            "host reboot fenced the interrupted launch; a fresh authorized nonce is required"
                .into(),
        );
        return Ok(());
    }
    let process: Option<VmProcessIdentity> = read_json(&dir.join("process.json"))?;
    if let Some(identity) =
        process.filter(|identity| Some(identity) != journal.pending_predecessor.as_ref())
    {
        if process_identity(identity.pid)?.as_ref() == Some(&identity) {
            validate_process_owner(runtime, dir, &identity)?;
        }
        if journal.rollback_launch {
            journal.old_process = Some(identity.clone());
        } else {
            journal.candidate_process = Some(identity.clone());
        }
        journal.status.running_process =
            process_identity(identity.pid)?.filter(|current| current == &identity);
        journal.status.old_root_fenced = !journal.rollback_launch;
        journal.status.observed_image = None;
        journal.launch_pending = false;
        transition(journal, Phase::Uncertain);
        journal.status.reason =
            Some("interrupted launch identified; a fresh authorized nonce is required".into());
    }
    Ok(())
}

async fn launch(
    runtime: &Firecracker,
    spec: &VmSpec,
    journal: &mut Journal,
    rollback: bool,
) -> anyhow::Result<()> {
    ensure!(
        now_ms()? < journal.request.deadline_unix_ms,
        "launch authorization expired"
    );
    ensure!(
        !journal.used_nonces.contains(&journal.request.launch_nonce),
        "nonce already consumed"
    );
    let dir = runtime.dir(&spec.id);
    let kernel = runtime.inner.images.ensure(&spec.image.kernel).await?;
    atomic_json(&dir.join("spec.json"), &Shape::of(spec))?;
    let octet = crate::read_address(&dir).context("VM address missing")?;
    runtime
        .inner
        .jail
        .as_ref()
        .context("jailer missing")?
        .prepare(&dir, crate::jail::uid(octet), &kernel)?;
    ensure!(
        now_ms()? < journal.request.deadline_unix_ms,
        "launch authorization expired during preparation"
    );
    journal.status.running_process = None;
    journal.status.observed_image = None;
    ensure!(
        journal.used_nonces.len() < 8,
        "physical launch bound exceeded"
    );
    journal
        .used_nonces
        .push(journal.request.launch_nonce.clone());
    journal.launch_pending = true;
    journal.rollback_launch = rollback;
    if rollback {
        journal.status.old_root_fenced = false;
    }
    journal.launch_boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into();
    journal.pending_predecessor = read_json(&dir.join("process.json"))?;
    if !rollback {
        transition(journal, Phase::Starting);
    }
    save(runtime, journal)?;
    let mut launched = match runtime.launch(&spec.id, &dir).await {
        Ok(launched) => launched,
        Err(_) => {
            return uncertain(
                runtime,
                journal,
                "VMM launch failed or ambiguous; physical launch nonce consumed",
            );
        }
    };
    let pid = launched.pid;
    let identity = process_identity(pid)?.context("VMM exited before configuration")?;
    validate_process_owner(runtime, &dir, &identity)?;
    if rollback {
        journal.old_process = Some(identity.clone());
    } else {
        journal.candidate_process = Some(identity.clone());
    }
    journal.launch_pending = false;
    journal.status.running_process = Some(identity);
    journal.status.launch_nonce = journal.request.launch_nonce.clone();
    save(runtime, journal)?;
    let mut boot_spec = spec.clone();
    bind_boot_context(&mut boot_spec, journal)?;
    let api = Api::new(runtime.socket(&dir));
    let remaining = journal.request.deadline_unix_ms.saturating_sub(now_ms()?);
    if remaining <= 0 {
        return uncertain(
            runtime,
            journal,
            "launch authorization expired before InstanceStart; nonce consumed",
        );
    }
    if tokio::time::Instant::now()
        .checked_add(Duration::from_millis(u64::try_from(remaining)?))
        .is_none()
    {
        return uncertain(
            runtime,
            journal,
            "authorization deadline exceeds the local execution clock; nonce consumed",
        );
    }
    let configured =
        tokio::time::timeout(Duration::from_millis(u64::try_from(remaining)?), async {
            for (path, body) in crate::boot_sequence(
                &boot_spec,
                Path::new("vmlinux"),
                runtime.guest_network(&dir),
            ) {
                api.put(path, &body).await?;
            }
            api.put("/actions", &json!({"action_type": "InstanceStart"}))
                .await
        })
        .await;
    if !matches!(configured, Ok(Ok(()))) {
        launched.fence().await?;
        return uncertain(
            runtime,
            journal,
            "InstanceStart result is uncertain; nonce consumed",
        );
    }
    journal.launch_pending = false;
    journal.status.observed_image = Some(spec.image.clone());
    journal.status.old_root_fenced = !rollback;
    transition(
        journal,
        if rollback {
            Phase::RolledBack
        } else {
            Phase::CandidateRunning
        },
    );
    launched.finish();
    Ok(())
}

struct Identity {
    key: Vec<u8>,
    record: Vec<u8>,
}

fn validate_identity(key: &[u8], record: &[u8], request: &Request) -> anyhow::Result<()> {
    ensure!(
        key.len() <= 128 && record.len() <= MAX_RECORD,
        "identity exceeds preservation boundary"
    );
    let seed: [u8; 32] = hex::decode(std::str::from_utf8(key)?.trim())
        .map_err(|_| anyhow::anyhow!("malformed machine seed"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("malformed machine seed"))?;
    ensure!(
        SigningKey::from_bytes(&seed).verifying_key().to_bytes() == request.registration_key,
        "private identity does not match registered public key"
    );
    let record: Record = serde_json::from_slice(record).context("malformed machine record")?;
    ensure!(
        record.machine_id == request.guest_machine_id,
        "guest machine identity mismatch"
    );
    ensure!(
        matches!(record.pool.as_str(), "organisation" | "management")
            && record.pool == record.trust_key.purpose,
        "machine pool does not match pinned trust"
    );
    ensure!(
        !record.name.is_empty()
            && record.heartbeat_interval_seconds > 0
            && record.registered_at_unix > 0,
        "malformed machine registration"
    );
    let url = reqwest::Url::parse(&record.instance_url).context("malformed instance URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "invalid instance origin"
    );
    validate_pin(&record.instance_key, "instance")?;
    ensure!(
        matches!(
            record.trust_key.purpose.as_str(),
            "organisation" | "management"
        ),
        "invalid trust purpose"
    );
    validate_pin(&record.trust_key, &record.trust_key.purpose)?;
    if let Some(network) = &record.network {
        validate_pin(&network.key, "network")?;
    }
    Ok(())
}

fn validate_pin(pin: &PinnedKey, purpose: &str) -> anyhow::Result<()> {
    ensure!(
        !pin.key_id.is_empty()
            && pin.key_id.len() <= 128
            && pin.purpose == purpose
            && pin.public_key.len() == 64
            && pin
                .public_key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "malformed pinned trust key"
    );
    let bytes: [u8; 32] = hex::decode(&pin.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid pinned key length"))?;
    let key = VerifyingKey::from_bytes(&bytes).context("invalid pinned public key")?;
    ensure!(!key.is_weak(), "weak pinned public key");
    Ok(())
}

fn bind_boot_context(spec: &mut VmSpec, journal: &Journal) -> anyhow::Result<()> {
    let grund = spec
        .mmds
        .get_mut("grund")
        .and_then(serde_json::Value::as_object_mut)
        .context("missing canonical grund metadata")?;
    grund.insert(
        "replacement".into(),
        json!({
            "attempt_id": journal.request.attempt_id,
            "sequence": journal.request.sequence,
            "document_generation": journal.operation_generation,
            "guest_machine_id": journal.request.guest_machine_id,
            "launch_nonce": journal.request.launch_nonce,
        }),
    );
    Ok(())
}

fn guarded_tool(
    program: &Path,
    execution: &ExecutionLock,
) -> std::io::Result<tokio::process::Command> {
    let raw = unsafe { libc::fcntl(execution.0.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let inherited = unsafe { OwnedFd::from_raw_fd(raw) };
    let parent = unsafe { libc::getpid() };
    let mut command = tokio::process::Command::new(program);
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            let fd = inherited.as_raw_fd();
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

async fn tool(
    disk: &Path,
    command: &str,
    writable: bool,
    bound: usize,
    execution: &ExecutionLock,
) -> anyhow::Result<Vec<u8>> {
    let mut process = guarded_tool(
        &debugfs().context("trusted debugfs unavailable")?,
        execution,
    )?;
    if writable {
        process.arg("-w");
    }
    let mut child = process
        .args(["-R", command])
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child.stdout.take().context("debugfs stdout")?;
    let mut output = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        (&mut stdout)
            .take(u64::try_from(bound)? + 1)
            .read_to_end(&mut output)
            .await?;
        ensure!(
            output.len() <= bound,
            "offline ext4 output exceeds preservation boundary"
        );
        ensure!(
            child.wait().await?.success(),
            "offline ext4 operation failed"
        );
        anyhow::Ok(())
    })
    .await
    .context("offline ext4 deadline")?;
    result?;
    Ok(output)
}

async fn stat(
    disk: &Path,
    path: &str,
    directory: bool,
    max: usize,
    execution: &ExecutionLock,
) -> anyhow::Result<()> {
    let output = tool(disk, &format!("stat {path}"), false, 8192, execution).await?;
    let text = std::str::from_utf8(&output)?;
    ensure!(
        text.contains(if directory {
            "Type: directory"
        } else {
            "Type: regular"
        }),
        "identity path is absent, symlinked or not regular"
    );
    let uid = text
        .split("User:")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .context("missing identity owner")?
        .parse::<u32>()?;
    ensure!(uid == 0, "identity must be root owned");
    let mode = text
        .split("Mode:")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .context("missing identity mode")?;
    let mode = u32::from_str_radix(mode, 8)?;
    ensure!(
        mode & 0o022 == 0,
        "identity path is writable by an untrusted user"
    );
    if !directory {
        ensure!(mode & 0o077 == 0, "identity file is not owner-only");
        let size = text
            .split("Size:")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .context("missing identity size")?
            .parse::<usize>()?;
        let links = text
            .split("Links:")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .context("missing identity links")?
            .parse::<u32>()?;
        ensure!(
            size > 0 && size <= max && links == 1,
            "identity is unbounded or aliased"
        );
    }
    Ok(())
}

async fn identity_parents(disk: &Path, execution: &ExecutionLock) -> anyhow::Result<()> {
    for path in ["/", "/var", "/var/lib", "/var/lib/grund", IDENTITY_DIR] {
        stat(disk, path, true, 0, execution).await?;
    }
    Ok(())
}

async fn read_identity(
    disk: &Path,
    request: &Request,
    execution: &ExecutionLock,
) -> anyhow::Result<Identity> {
    let metadata = std::fs::symlink_metadata(disk)?;
    ensure!(
        metadata.is_file() && metadata.mode() & 0o077 == 0,
        "source identity disk is not private"
    );
    identity_parents(disk, execution).await?;
    stat(
        disk,
        "/var/lib/grund/agent/machine.key",
        false,
        128,
        execution,
    )
    .await?;
    stat(
        disk,
        "/var/lib/grund/agent/machine.json",
        false,
        MAX_RECORD,
        execution,
    )
    .await?;
    let key = tool(
        disk,
        "cat /var/lib/grund/agent/machine.key",
        false,
        128,
        execution,
    )
    .await?;
    let record = tool(
        disk,
        "cat /var/lib/grund/agent/machine.json",
        false,
        MAX_RECORD,
        execution,
    )
    .await?;
    validate_identity(&key, &record, request)?;
    Ok(Identity { key, record })
}

async fn write_identity(
    disk: &Path,
    identity: &Identity,
    execution: &ExecutionLock,
) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(disk)?;
    ensure!(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
        "staged identity disk is not root-private"
    );
    stat(disk, "/", true, 0, execution).await?;
    for path in ["/var", "/var/lib", "/var/lib/grund", IDENTITY_DIR] {
        tool(disk, &format!("mkdir {path}"), true, 8192, execution).await?;
        stat(disk, path, true, 0, execution).await?;
    }
    for (name, bytes) in IDENTITY_FILES
        .into_iter()
        .zip([identity.key.as_slice(), identity.record.as_slice()])
    {
        let path = format!("{IDENTITY_DIR}/{name}");
        let existing = tool(disk, &format!("stat {path}"), false, 8192, execution).await?;
        if !existing.is_empty() {
            stat(disk, &path, false, MAX_RECORD, execution).await?;
        }
        let fd = unsafe {
            libc::memfd_create(
                c"grund-identity".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        ensure!(fd >= 0, "anonymous identity buffer unavailable");
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        ensure!(
            unsafe {
                libc::fcntl(
                    file.as_raw_fd(),
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            } == 0,
            "cannot seal identity buffer"
        );
        tool(disk, &format!("rm {path}"), true, 8192, execution).await?;
        tool(
            disk,
            &format!(
                "write /proc/{}/fd/{} {path}",
                std::process::id(),
                file.as_raw_fd()
            ),
            true,
            8192,
            execution,
        )
        .await?;
        tool(
            disk,
            &format!("set_inode_field {path} mode 0100600"),
            true,
            8192,
            execution,
        )
        .await?;
        stat(disk, &path, false, bytes.len(), execution).await?;
        ensure!(
            tool(disk, &format!("cat {path}"), false, bytes.len(), execution).await? == bytes,
            "identity preservation readback mismatch"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "replacement_tests.rs"]
mod tests;
