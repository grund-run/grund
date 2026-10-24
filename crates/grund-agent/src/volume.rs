//! Agent-owned persistent volume directories, attached ext4 block volumes,
//! and locally authorized host binds. Ownership records live outside
//! container-writable directories; a missing source is never silently replaced.

use std::{
    collections::HashMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    sync::{LazyLock, Mutex},
};

use anyhow::{Context, ensure};
use grund_proto::grund::agent::v1::{DesiredState, VolumeMount};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::runtime::VolumeBind;

#[derive(Default)]
struct Activity {
    workers: usize,
    deleting: bool,
}

static ACTIVITIES: LazyLock<Mutex<HashMap<String, Activity>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Hold this across backup/restore work and its final desired-state recheck.
/// It prevents a signed tombstone from acknowledging an absent restore
/// destination while a worker is about to create it.
pub struct VolumeGuard {
    id: String,
}

pub fn guard(id: &str) -> anyhow::Result<VolumeGuard> {
    ensure!(valid_id(id), "invalid volume ID");
    let mut states = ACTIVITIES
        .lock()
        .map_err(|_| anyhow::anyhow!("volume activity lock poisoned"))?;
    let state = states.entry(id.into()).or_default();
    ensure!(!state.deleting, "volume {id} is being deleted");
    state.workers += 1;
    Ok(VolumeGuard { id: id.into() })
}

impl Drop for VolumeGuard {
    fn drop(&mut self) {
        if let Ok(mut states) = ACTIVITIES.lock()
            && let Some(state) = states.get_mut(&self.id)
        {
            state.workers -= 1;
            if state.workers == 0 && !state.deleting {
                states.remove(&self.id);
            }
        }
    }
}

pub fn active(id: &str) -> bool {
    ACTIVITIES.lock().map_or(true, |states| {
        states.get(id).is_some_and(|s| s.workers != 0)
    })
}

/// Atomically fence new workers and check whether existing ones drained.
pub fn begin_delete(id: &str) -> anyhow::Result<bool> {
    ensure!(valid_id(id), "invalid volume ID");
    let mut states = ACTIVITIES
        .lock()
        .map_err(|_| anyhow::anyhow!("volume activity lock poisoned"))?;
    let state = states.entry(id.into()).or_default();
    state.deleting = true;
    Ok(state.workers == 0)
}

/// A new signed document no longer carries these tombstones; drop finished
/// in-process fences. IDs never reuse a durable on-disk deleting marker.
pub fn retain_deletions(desired: Option<&DesiredState>) {
    if let Ok(mut states) = ACTIVITIES.lock() {
        states.retain(|id, state| {
            state.workers > 0
                || (state.deleting
                    && desired.is_some_and(|doc| {
                        doc.volume_deletions
                            .iter()
                            .any(|t| t.volume_id == id.as_str())
                    }))
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Owner {
    app_id: String,
    volume_id: String,
    device: u64,
    inode: u64,
    #[serde(default)]
    deleting: bool,
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

/// Open each directory component relative to an already-open parent, refusing
/// symlinks anywhere in the path. Never canonicalize untrusted source paths.
pub fn directory(path: &Path) -> anyhow::Result<File> {
    checked_directory(path, false)
}

fn host_directory(path: &Path) -> anyhow::Result<File> {
    checked_directory(path, true)
}

fn checked_directory(path: &Path, stable_parents: bool) -> anyhow::Result<File> {
    ensure!(
        path.is_absolute(),
        "{} is not an absolute directory",
        path.display()
    );
    let mut current = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                if stable_parents {
                    let parent = current.metadata()?;
                    ensure!(
                        parent.uid() == 0 && parent.mode() & 0o022 == 0,
                        "host path {} has an ancestor writable by a non-root user",
                        path.display()
                    );
                }
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(io::Error::last_os_error()).with_context(|| {
                        format!("open {} without following symlinks", path.display())
                    });
                }
                current = unsafe { File::from_raw_fd(fd) };
            }
            _ => anyhow::bail!("{} contains an unsafe path component", path.display()),
        }
    }
    Ok(current)
}

fn mkdir_child(parent: &File, name: &str) -> anyhow::Result<bool> {
    let name = CString::new(name)?;
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::AlreadyExists {
        Ok(false)
    } else {
        Err(error.into())
    }
}

fn managed_roots(data_dir: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    let data = directory(data_dir)?;
    let meta = data.metadata()?;
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.permissions().mode() & 0o022 == 0,
        "{} must be owned by the agent and not writable by other users",
        data_dir.display()
    );
    for name in ["volumes", "volume-owners"] {
        mkdir_child(&data, name)?;
        let path = data_dir.join(name);
        let fd = directory(&path)?;
        let meta = fd.metadata()?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.permissions().mode() & 0o077 == 0,
            "{} must be private to the machine agent",
            path.display()
        );
    }
    Ok((data_dir.join("volumes"), data_dir.join("volume-owners")))
}

fn owner_path(owners: &Path, id: &str) -> PathBuf {
    owners.join(format!("{id}.json"))
}

fn read_owner(owners: &Path, id: &str) -> anyhow::Result<Option<Owner>> {
    let path = owner_path(owners, id);
    let dir = directory(owners)?;
    let name = CString::new(format!("{id}.json"))?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(e).with_context(|| format!("open owner record {}", path.display()));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    ensure!(
        file.metadata()?.is_file(),
        "{} is not an owner record",
        path.display()
    );
    Ok(Some(serde_json::from_reader(file).with_context(|| {
        format!("read owner record {}", path.display())
    })?))
}

pub fn managed_path(data_dir: &Path, volume_id: &str) -> anyhow::Result<PathBuf> {
    ensure!(valid_id(volume_id), "invalid volume ID");
    Ok(data_dir.join("volumes").join(volume_id))
}

#[derive(Serialize, Deserialize)]
struct BlockOwner {
    app_id: String,
    volume_id: String,
    #[serde(default)]
    deleting: bool,
}

fn block_roots(data_dir: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    let data = directory(data_dir)?;
    let meta = data.metadata()?;
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.permissions().mode() & 0o022 == 0,
        "{} must be owned by the agent and not writable by other users",
        data_dir.display()
    );
    for name in ["block-volumes", "block-owners"] {
        mkdir_child(&data, name)?;
        let dir = directory(&data_dir.join(name))?;
        let meta = dir.metadata()?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.permissions().mode() & 0o077 == 0,
            "{name} must be private to the machine agent"
        );
    }
    Ok((
        data_dir.join("block-volumes"),
        data_dir.join("block-owners"),
    ))
}

fn read_block_owner(owners: &Path, id: &str) -> anyhow::Result<Option<BlockOwner>> {
    let dir = directory(owners)?;
    let name = CString::new(format!("{id}.json"))?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).context("open block volume ownership record");
    }
    let file = unsafe { File::from_raw_fd(fd) };
    ensure!(
        file.metadata()?.is_file(),
        "block owner record is not a file"
    );
    Ok(Some(serde_json::from_reader(file)?))
}

fn block_identity(app: &str, name: &str, id: &str) -> anyhow::Result<Uuid> {
    let app = Uuid::parse_str(app).context("block volume app ID is not a UUID")?;
    ensure!(!name.is_empty(), "block volume name is empty");
    ensure!(valid_id(id), "block volume ID is not a canonical UUID");
    let id = Uuid::parse_str(id)?;
    ensure!(
        Uuid::new_v5(&app, name.as_bytes()) == id,
        "block volume ID does not match its app-scoped immutable name"
    );
    Ok(id)
}

const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_MAGIC_OFFSET: usize = 56;
const EXT4_UUID_OFFSET: usize = 104;
fn ext4_uuid(file: &File) -> io::Result<Option<Uuid>> {
    use std::os::unix::fs::FileExt;
    let mut superblock = [0u8; EXT4_UUID_OFFSET + 16];
    match file.read_exact_at(&mut superblock, EXT4_SUPERBLOCK_OFFSET) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    if superblock[EXT4_MAGIC_OFFSET..EXT4_MAGIC_OFFSET + 2] != [0x53, 0xef] {
        return Ok(None);
    }
    Ok(Some(Uuid::from_bytes(
        superblock[EXT4_UUID_OFFSET..EXT4_UUID_OFFSET + 16]
            .try_into()
            .expect("fixed superblock offset"),
    )))
}

fn matches_ext4(file: &File, id: Uuid) -> io::Result<bool> {
    Ok(ext4_uuid(file)? == Some(id))
}

fn open_block_device(path: &Path) -> io::Result<Option<File>> {
    let device = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    Ok(device
        .metadata()?
        .file_type()
        .is_block_device()
        .then_some(device))
}

const MAX_BLOCK_DEVICES: usize = 1024;

fn find_block_device(id: Uuid) -> anyhow::Result<File> {
    let mut found = None;
    let mut examined = 0;
    for entry in fs::read_dir("/sys/class/block").context("list attached block devices")? {
        examined += 1;
        ensure!(
            examined <= MAX_BLOCK_DEVICES,
            "too many attached block devices to safely identify a volume"
        );
        let name = entry?.file_name();
        if name.as_bytes().is_empty()
            || !name
                .as_bytes()
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
        {
            continue;
        }
        let path = Path::new("/dev").join(&name);
        let device = match open_block_device(&path) {
            Ok(Some(device)) => device,
            Ok(None) | Err(_) => continue,
        };
        if matches_ext4(&device, id).unwrap_or(false) {
            ensure!(found.is_none(), "more than one device has this ext4 UUID");
            found = Some(device);
        }
    }
    found.context("matching ext4 block device is not attached")
}

fn mount_id(dir: &File) -> anyhow::Result<u64> {
    use rustix::fs::{AtFlags, StatxFlags, statx};

    let stat = statx(dir, c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .context("inspect volume mount identity")?;
    ensure!(
        stat.stx_mask & StatxFlags::MNT_ID.bits() != 0,
        "kernel did not report volume mount identity"
    );
    Ok(stat.stx_mnt_id)
}

fn check_block_mount(dir: &File, root: &File, device: &File) -> anyhow::Result<bool> {
    if mount_id(dir)? == mount_id(root)? {
        return Ok(false);
    }
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) } < 0 {
        return Err(io::Error::last_os_error()).context("inspect mounted filesystem");
    }
    let dev = device.metadata()?;
    let mounted = dir.metadata()?;
    ensure!(
        stat.f_type == 0xef53 && mounted.dev() == dev.rdev(),
        "mounted block filesystem does not match signed ext4 identity"
    );
    Ok(true)
}

fn block_source(data_dir: &Path, app: &str, name: &str, id: &str) -> anyhow::Result<PathBuf> {
    let expected = block_identity(app, name, id)?;
    let (root, owners) = block_roots(data_dir)?;
    let (managed_root, managed_owners) = managed_roots(data_dir)?;
    ensure!(
        read_owner(&managed_owners, id)?.is_none()
            && fs::symlink_metadata(managed_root.join(id))
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
        "block volume conflicts with an existing managed directory"
    );
    let parent = directory(&root)?;
    lock_directory(&parent, true)?;
    if let Some(record) = read_block_owner(&owners, id)? {
        ensure!(
            record.app_id == app && record.volume_id == id,
            "block volume belongs to another app"
        );
        ensure!(!record.deleting, "block volume is being deleted");
    } else {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(owner_path(&owners, id))
            .context("record block volume ownership")?;
        serde_json::to_writer(
            &mut file,
            &BlockOwner {
                app_id: app.into(),
                volume_id: id.into(),
                deleting: false,
            },
        )?;
        file.sync_all()?;
        directory(&owners)?.sync_all()?;
    }
    mkdir_child(&parent, id)?;
    parent.sync_all()?;
    let path = root.join(id);
    let device = find_block_device(expected)?;
    let dir = directory(&path).context("block mountpoint is missing or unsafe")?;
    if !check_block_mount(&dir, &parent, &device)? {
        let meta = dir.metadata()?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() }
                && meta.permissions().mode() & 0o077 == 0
                && fs::read_dir(&path)?.next().is_none(),
            "block mountpoint must be agent-owned, private and empty"
        );
        let device_fd = CString::new(format!("/proc/self/fd/{}", device.as_raw_fd()))?;
        let target = CString::new(path.as_os_str().as_bytes())?;
        if unsafe {
            libc::mount(
                device_fd.as_ptr(),
                target.as_ptr(),
                c"ext4".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error()).context("mount matching ext4 block device");
        }
        let mounted = directory(&path)?;
        ensure!(
            check_block_mount(&mounted, &parent, &device)?,
            "block device mount did not appear"
        );
    }
    Ok(path)
}

fn owner_matches(record: &Owner, app: &str, id: &str, dir: &File) -> anyhow::Result<()> {
    let meta = dir.metadata()?;
    ensure!(
        record.app_id == app && record.volume_id == id,
        "volume {id} belongs to another app or has a different identity"
    );
    ensure!(!record.deleting, "volume {id} is being deleted");
    ensure!(
        record.device == meta.dev() && record.inode == meta.ino(),
        "volume {id} directory was replaced; refusing to start instead of creating empty storage"
    );
    Ok(())
}

fn provision(data_dir: &Path, app: &str, id: &str) -> anyhow::Result<PathBuf> {
    ensure!(
        !app.is_empty() && valid_id(id),
        "volume has an invalid app or volume ID"
    );
    let (root, owners) = managed_roots(data_dir)?;
    let path = root.join(id);
    let record = read_owner(&owners, id)?;
    if record.is_none() {
        let parent = directory(&root)?;
        ensure!(
            mkdir_child(&parent, id)?,
            "volume {id} exists without trusted ownership metadata; refusing to use or replace it"
        );
        parent.sync_all()?;
        let dir = directory(&path)?;
        let meta = dir.metadata()?;
        let record = Owner {
            app_id: app.into(),
            volume_id: id.into(),
            device: meta.dev(),
            inode: meta.ino(),
            deleting: false,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(owner_path(&owners, id))
            .with_context(|| format!("record the owner of volume {id}"))?;
        serde_json::to_writer(&mut file, &record)?;
        file.sync_all()?;
        directory(&owners)?.sync_all()?;
        return Ok(path);
    }
    let dir = directory(&path).with_context(|| {
        format!("volume {id} directory is unavailable; restore it rather than replacing it")
    })?;
    owner_matches(&record.expect("checked above"), app, id, &dir)?;
    Ok(path)
}

/// Verify the signed mounts against the machine-local allowlist on every pass.
/// `source` is the absolute host path chosen for an existing volume, never
/// accepted for a managed volume.
pub fn prepare(
    data_dir: &Path,
    roots: &[PathBuf],
    app: &str,
    mounts: &[VolumeMount],
) -> anyhow::Result<Vec<VolumeBind>> {
    let mut binds = Vec::with_capacity(mounts.len());
    for mount in mounts {
        ensure!(
            !app.is_empty() && valid_id(&mount.volume_id),
            "invalid volume or app ID"
        );
        let destination = Path::new(&mount.path);
        ensure!(
            destination.is_absolute()
                && destination != Path::new("/")
                && destination
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
            "volume {} has an unsafe container path",
            mount.name
        );
        ensure!(
            !["/proc", "/dev", "/sys", "/etc/resolv.conf"]
                .iter()
                .any(|p| destination.starts_with(p)),
            "volume {} overlaps a container system mount",
            mount.name
        );
        ensure!(
            !binds
                .iter()
                .any(|v: &VolumeBind| overlaps(Path::new(&v.path), destination)),
            "overlapping writable container volume paths"
        );
        let source = if mount.block_device {
            ensure!(
                mount.source.is_empty(),
                "block volume cannot name a host path"
            );
            block_source(data_dir, app, &mount.name, &mount.volume_id)?
        } else if mount.source.is_empty() {
            provision(data_dir, app, &mount.volume_id)?
        } else {
            let source = Path::new(&mount.source);
            ensure!(
                source.is_absolute()
                    && source
                        .components()
                        .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
                "volume {} has an unsafe host path",
                mount.name
            );
            ensure!(
                roots
                    .iter()
                    .any(|root| source.starts_with(root) && source != root),
                "volume {} host path is not within an allowlisted root",
                mount.name
            );
            ensure!(
                !overlaps(source, data_dir),
                "volume {} host path overlaps the agent's storage",
                mount.name
            );
            host_directory(source).with_context(|| {
                format!(
                    "volume {} source is not a safe existing directory",
                    mount.name
                )
            })?;
            source.to_path_buf()
        };
        ensure!(
            !binds
                .iter()
                .any(|v: &VolumeBind| overlaps(Path::new(&v.source), &source)),
            "overlapping writable host directories"
        );
        let managed = mount.source.is_empty() && !mount.block_device;
        ensure!(
            !mount.copy_up || managed,
            "volume {} asks for a copy-up but is not a grund-managed directory",
            mount.name
        );
        binds.push(VolumeBind {
            volume_id: mount.volume_id.clone(),
            app_id: app.into(),
            name: mount.name.clone(),
            path: mount.path.clone(),
            source: source.display().to_string(),
            managed,
            block_device: mount.block_device,
            copy_up: mount.copy_up,
        });
    }
    Ok(binds)
}

pub fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Validate the volume identity before each runc task start (including reboot
/// restarts). Existing binds must still be allowed by local policy.
pub fn verify_bind(data_dir: &Path, roots: &[PathBuf], bind: &VolumeBind) -> anyhow::Result<File> {
    ensure!(
        valid_id(&bind.volume_id) && !bind.app_id.is_empty(),
        "invalid volume identity"
    );
    let path = Path::new(&bind.source);
    if bind.block_device {
        ensure!(
            path == data_dir.join("block-volumes").join(&bind.volume_id),
            "block volume source is not agent-controlled"
        );
        ensure!(!bind.managed, "block volume cannot be a managed directory");
        block_source(data_dir, &bind.app_id, &bind.name, &bind.volume_id)?;
        return directory(path);
    }
    if bind.managed {
        let (root, owners) = managed_roots(data_dir)?;
        ensure!(
            path == root.join(&bind.volume_id),
            "managed volume source is not agent-controlled"
        );
        let record = read_owner(&owners, &bind.volume_id)?
            .context("managed volume owner metadata is missing")?;
        let dir = directory(path)?;
        owner_matches(&record, &bind.app_id, &bind.volume_id, &dir)?;
        Ok(dir)
    } else {
        ensure!(
            roots
                .iter()
                .any(|root| path.starts_with(root) && path != root),
            "volume source is not allowed by machine policy"
        );
        ensure!(
            !overlaps(path, data_dir),
            "host path overlaps the agent's storage"
        );
        host_directory(path)
    }
}

fn lock_directory(dir: &File, exclusive: bool) -> anyhow::Result<()> {
    let mode = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    if unsafe { libc::flock(dir.as_raw_fd(), mode | libc::LOCK_NB) } < 0 {
        return Err(io::Error::last_os_error())
            .context("volume is busy with a backup, restore, or deletion");
    }
    Ok(())
}

/// A shared filesystem lock across an entire backup, including its final
/// signed-state check. The returned File owns the flock until dropped.
pub fn backup_guard(
    data_dir: &Path,
    roots: &[PathBuf],
    bind: &VolumeBind,
) -> anyhow::Result<(PathBuf, File)> {
    let dir = verify_bind(data_dir, roots, bind)?;
    lock_directory(&dir, false)?;
    let verified = verify_bind(data_dir, roots, bind)?;
    let old = dir.metadata()?;
    let new = verified.metadata()?;
    ensure!(
        old.dev() == new.dev() && old.ino() == new.ino(),
        "volume source changed while acquiring its backup lock"
    );
    Ok((PathBuf::from(&bind.source), dir))
}

/// A new managed target held exclusively for the entire restore. The caller
/// must also acquire [`guard`] before allocating this directory.
pub fn restore_guard(
    data_dir: &Path,
    app_id: &str,
    new_volume_id: &str,
) -> anyhow::Result<(PathBuf, File)> {
    let path = restore_target(data_dir, app_id, new_volume_id)?;
    let dir = directory(&path)?;
    lock_directory(&dir, true)?;
    let bind = VolumeBind {
        app_id: app_id.into(),
        volume_id: new_volume_id.into(),
        name: "restore".into(),
        path: "/restore".into(),
        source: path.display().to_string(),
        managed: true,
        block_device: false,
        copy_up: false,
    };
    let verified = verify_bind(data_dir, &[], &bind)?;
    let old = dir.metadata()?;
    let new = verified.metadata()?;
    ensure!(
        old.dev() == new.dev() && old.ino() == new.ino(),
        "restore target changed while acquiring its lock"
    );
    Ok((path, dir))
}

/// Backup can read only a currently permitted signed mount. Managed volumes
/// require matching owner metadata; existing host paths require the current
/// machine-local allowlist and no symlink in any component. The caller must
/// match the bind against the signed desired state and active machine lease.
pub fn backup_source(
    data_dir: &Path,
    roots: &[PathBuf],
    bind: &VolumeBind,
) -> anyhow::Result<PathBuf> {
    let dir = verify_bind(data_dir, roots, bind)?;
    ensure!(
        dir.metadata()?.is_dir(),
        "volume backup source is unavailable"
    );
    Ok(PathBuf::from(&bind.source))
}

/// Allocate a new, never-before-owned managed directory for a restore.
/// The caller must hold the restore lease and keep this ID detached until
/// completion; an existing or interrupted restore is never overwritten.
pub fn restore_target(
    data_dir: &Path,
    app_id: &str,
    new_volume_id: &str,
) -> anyhow::Result<PathBuf> {
    ensure!(
        valid_id(new_volume_id) && !app_id.is_empty(),
        "invalid restore identity"
    );
    let (_, owners) = managed_roots(data_dir)?;
    ensure!(
        read_owner(&owners, new_volume_id)?.is_none(),
        "restore destination already exists"
    );
    provision(data_dir, app_id, new_volume_id)
}

/// Grant a freshly provisioned managed directory to the image's numeric
/// identity. Never change ownership of populated data or existing host paths.
pub fn grant_access(
    dir: &File,
    bind: &VolumeBind,
    uid: u32,
    gid: u32,
    groups: &[u32],
) -> anyhow::Result<()> {
    let mut meta = dir.metadata()?;
    if bind.managed
        && meta.uid() == 0
        && meta.permissions().mode() & 0o777 == 0o700
        && uid != 0
        && fs::read_dir(&bind.source)?.next().is_none()
    {
        let result = unsafe { libc::fchown(dir.as_raw_fd(), uid, gid) };
        if result < 0 {
            return Err(io::Error::last_os_error())
                .context("grant a new managed directory to the image user");
        }
        dir.sync_all()?;
        meta = dir.metadata()?;
    }
    if uid != 0 && !bind.copy_up {
        let mode = meta.permissions().mode();
        let access = if meta.uid() == uid {
            (mode >> 6) & 7
        } else if meta.gid() == gid || groups.contains(&meta.gid()) {
            (mode >> 3) & 7
        } else {
            mode & 7
        };
        ensure!(
            access & 7 == 7,
            "volume {} is not writable and searchable by image user {uid}:{gid}; provision its permissions locally",
            bind.name
        );
    }
    Ok(())
}

/// A managed volume held exclusively while the image's files are staged
/// for it ([`copy_up_begin`]). They are copied into an agent-owned staging
/// directory, never into the volume, until [`CopyUp::install`] moves them in.
pub struct CopyUp {
    dir: File,
    owners: File,
    staging: PathBuf,
    volume: PathBuf,
    marker: CString,
}

/// What [`CopyUp::install`] moves into a volume, written beside the owner
/// record before the first move so an interrupted install is completed,
/// never undone, and refused if the volume holds anything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Manifest {
    names: Vec<String>,
    uid: u32,
    gid: u32,
    mode: u32,
    atime: (i64, i64),
    mtime: (i64, i64),
}

fn copy_up_marker(id: &str) -> anyhow::Result<CString> {
    Ok(CString::new(format!("{id}.copyup"))?)
}

fn read_marker(owners: &File, marker: &CString) -> anyhow::Result<Option<Manifest>> {
    let fd = unsafe {
        libc::openat(
            owners.as_raw_fd(),
            marker.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error.into())
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    Ok(Some(
        serde_json::from_reader(file).context("the copy-up manifest does not decode")?,
    ))
}

fn staging_root(data_dir: &Path, volumes: &Path) -> anyhow::Result<PathBuf> {
    let data = directory(data_dir)?;
    mkdir_child(&data, "volume-staging")?;
    let root = data_dir.join("volume-staging");
    let staging = directory(&root)?;
    let meta = staging.metadata()?;
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.permissions().mode() & 0o077 == 0,
        "{} must be owned by the agent and private",
        root.display()
    );
    ensure!(
        meta.dev() == directory(volumes)?.metadata()?.dev(),
        "volume staging and volumes must share one filesystem for an atomic install"
    );
    Ok(root)
}

fn names_in(path: &Path) -> anyhow::Result<std::collections::BTreeSet<String>> {
    fs::read_dir(path)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|name| anyhow::anyhow!("{name:?} is not UTF-8"))
        })
        .collect()
}

/// Locks managed volume `bind` (verified as `dir`) for its copy-up. An
/// install a crash interrupted is completed first, and nothing more is
/// copied. Otherwise `None` when the volume holds data, which is never
/// copied into, changed or removed; for an empty volume, a fresh staging
/// directory to copy the image's files into. Only that staging directory,
/// which the agent alone creates and never mounts, is ever deleted.
pub fn copy_up_begin(
    data_dir: &Path,
    bind: &VolumeBind,
    dir: File,
) -> anyhow::Result<Option<CopyUp>> {
    ensure!(
        bind.copy_up && bind.managed && !bind.block_device,
        "volume {} is not a grund-managed directory to copy into",
        bind.name
    );
    let (volumes, owners_path) = managed_roots(data_dir)?;
    let owners = directory(&owners_path)?;
    lock_directory(&dir, true)?;
    let staging = staging_root(data_dir, &volumes)?.join(&bind.volume_id);
    let copy = CopyUp {
        dir,
        owners,
        staging,
        volume: PathBuf::from(&bind.source),
        marker: copy_up_marker(&bind.volume_id)?,
    };
    if let Some(manifest) = read_marker(&copy.owners, &copy.marker)? {
        copy.roll_forward(&manifest)?;
        return Ok(None);
    }
    match fs::symlink_metadata(&copy.staging) {
        Ok(meta) => {
            ensure!(
                meta.is_dir(),
                "{} is not a staging directory",
                copy.staging.display()
            );
            fs::remove_dir_all(&copy.staging)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    if fs::read_dir(&copy.volume)?.next().is_some() {
        return Ok(None);
    }
    fs::DirBuilder::new().mode(0o700).create(&copy.staging)?;
    Ok(Some(copy))
}

impl CopyUp {
    /// Where to copy the image's files, the directory's own metadata
    /// included.
    pub fn staging(&self) -> &Path {
        &self.staging
    }

    /// The image had nothing to copy: removes the empty staging directory
    /// and leaves the volume as it was.
    pub fn abandon(self) -> anyhow::Result<()> {
        fs::remove_dir(&self.staging)?;
        Ok(())
    }

    /// Makes the staged files durable, records them, and moves each into
    /// the volume without replacing anything.
    pub fn install(self) -> anyhow::Result<()> {
        let staged = directory(&self.staging)?;
        if unsafe { libc::syncfs(staged.as_raw_fd()) } < 0 {
            return Err(io::Error::last_os_error()).context("make the staged copy durable");
        }
        let meta = staged.metadata()?;
        let manifest = Manifest {
            names: names_in(&self.staging)?.into_iter().collect(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode() & 0o7777,
            atime: (meta.atime(), meta.atime_nsec()),
            mtime: (meta.mtime(), meta.mtime_nsec()),
        };
        let fd = unsafe {
            libc::openat(
                self.owners.as_raw_fd(),
                self.marker.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("record the copy-up manifest");
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        serde_json::to_writer(&mut file, &manifest)?;
        file.sync_all()?;
        self.owners.sync_all()?;
        self.roll_forward(&manifest)
    }

    fn roll_forward(&self, manifest: &Manifest) -> anyhow::Result<()> {
        let staged = self.staging.exists();
        for name in &manifest.names {
            let from = self.staging.join(name);
            let to = self.volume.join(name);
            let in_staging = staged && fs::symlink_metadata(&from).is_ok();
            let in_volume = fs::symlink_metadata(&to).is_ok();
            match (in_staging, in_volume) {
                (true, false) => {
                    let (from_c, to_c) = (
                        CString::new(from.as_os_str().as_bytes())?,
                        CString::new(to.as_os_str().as_bytes())?,
                    );
                    if unsafe {
                        libc::renameat2(
                            libc::AT_FDCWD,
                            from_c.as_ptr(),
                            libc::AT_FDCWD,
                            to_c.as_ptr(),
                            libc::RENAME_NOREPLACE,
                        )
                    } < 0
                    {
                        return Err(io::Error::last_os_error())
                            .with_context(|| format!("move {name} into the volume"));
                    }
                }
                (false, true) => {}
                (true, true) => anyhow::bail!(
                    "the volume has a {name} the copy-up did not put there; leaving it and the staged copy alone"
                ),
                (false, false) => {
                    anyhow::bail!("the staged {name} is missing; leaving the volume alone")
                }
            }
        }
        let expected: std::collections::BTreeSet<&str> =
            manifest.names.iter().map(String::as_str).collect();
        if let Some(extra) = names_in(&self.volume)?
            .into_iter()
            .find(|name| !expected.contains(name.as_str()))
        {
            anyhow::bail!(
                "the volume has a {extra} the copy-up did not put there; refusing to finish it"
            );
        }
        let target = CString::new(self.volume.as_os_str().as_bytes())?;
        if unsafe { libc::chown(target.as_ptr(), manifest.uid, manifest.gid) } < 0
            || unsafe { libc::chmod(target.as_ptr(), manifest.mode) } < 0
        {
            return Err(io::Error::last_os_error())
                .context("give the volume the image directory's owner and mode");
        }
        let times = [
            libc::timespec {
                tv_sec: manifest.atime.0,
                tv_nsec: manifest.atime.1,
            },
            libc::timespec {
                tv_sec: manifest.mtime.0,
                tv_nsec: manifest.mtime.1,
            },
        ];
        if unsafe { libc::utimensat(libc::AT_FDCWD, target.as_ptr(), times.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error())
                .context("give the volume the image directory's times");
        }
        self.dir.sync_all()?;
        if staged {
            fs::remove_dir(&self.staging).context("remove the emptied staging directory")?;
        }
        if unsafe { libc::unlinkat(self.owners.as_raw_fd(), self.marker.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error()).context("mark the copy-up complete");
        }
        self.owners.sync_all()?;
        Ok(())
    }
}

/// Refuses to start a replica on a volume whose copy-up install was
/// interrupted; the next create completes it.
pub fn ensure_copied(data_dir: &Path, bind: &VolumeBind) -> anyhow::Result<()> {
    if !bind.copy_up {
        return Ok(());
    }
    let (_, owners_path) = managed_roots(data_dir)?;
    let owners = directory(&owners_path)?;
    ensure!(
        read_marker(&owners, &copy_up_marker(&bind.volume_id)?)?.is_none(),
        "volume {}'s copy of the image's files is not installed yet; the next create completes it",
        bind.name
    );
    Ok(())
}

fn release_block(root: &Path, id: &str) -> anyhow::Result<()> {
    let path = root.join(id);
    let dir = match directory(&path) {
        Ok(dir) => dir,
        Err(error) => match fs::symlink_metadata(&path) {
            Err(absent) if absent.kind() == io::ErrorKind::NotFound => return Ok(()),
            _ => return Err(error),
        },
    };
    let parent = directory(root)?;
    lock_directory(&parent, true)?;
    let mounted = mount_id(&dir)? != mount_id(&parent)?;
    if mounted {
        let expected = Uuid::parse_str(id)?;
        let device = find_block_device(expected)?;
        ensure!(
            check_block_mount(&dir, &parent, &device)?,
            "block filesystem is not mounted"
        );
    }
    drop(dir);
    if mounted {
        let target = CString::new(path.as_os_str().as_bytes())?;
        if unsafe { libc::umount2(target.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error()).context("unmount unused block volume");
        }
    }
    fs::remove_dir(&path).context("remove empty block mountpoint")?;
    parent.sync_all()?;
    Ok(())
}

pub fn has_block_owners(data_dir: &Path) -> bool {
    data_dir.join("block-owners").exists()
}

/// Release a block mount only after its signed writer and every runtime
/// container holding it are absent. Keep owner metadata for a future attach.
pub fn release_unused(
    data_dir: &Path,
    desired: Option<&DesiredState>,
    mounted: &[(String, VolumeBind)],
) -> anyhow::Result<()> {
    if !has_block_owners(data_dir) {
        return Ok(());
    }
    let (root, owners) = block_roots(data_dir)?;
    for (count, entry) in fs::read_dir(&owners)?.enumerate() {
        ensure!(
            count < MAX_BLOCK_DEVICES,
            "too many block volume owner records"
        );
        let name = entry?.file_name();
        let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
            continue;
        };
        if !valid_id(id)
            || mounted.iter().any(|(_, bind)| bind.volume_id == id)
            || desired.is_some_and(|state| {
                state.replicas.iter().any(|replica| {
                    replica
                        .volumes
                        .iter()
                        .any(|volume| volume.block_device && volume.volume_id == id)
                })
            })
        {
            continue;
        }
        let record = read_block_owner(&owners, id)?.context("block volume owner is missing")?;
        ensure!(
            record.volume_id == id && !record.app_id.is_empty(),
            "block volume owner record does not match its mountpoint"
        );
        release_block(&root, id)?;
    }
    Ok(())
}

fn delete_block(
    root: &Path,
    owners: &Path,
    app: &str,
    id: &str,
    mut record: BlockOwner,
) -> anyhow::Result<bool> {
    ensure!(
        record.app_id == app && record.volume_id == id,
        "refusing to delete another app's block volume"
    );
    if !record.deleting {
        record.deleting = true;
        let temp = owners.join(format!("{id}.deleting"));
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("discard interrupted block deletion marker"),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .context("record block volume deletion")?;
        serde_json::to_writer(&mut file, &record)?;
        file.sync_all()?;
        fs::rename(temp, owner_path(owners, id))?;
        directory(owners)?.sync_all()?;
    }
    release_block(root, id)?;
    Ok(true)
}

/// Erase only a managed directory with a matching owner record, or unmount a
/// matching block volume and remove its empty mountpoint. Never erase guest
/// block bytes. Durable deleting records prevent ID reuse after a tombstone.
pub fn delete_managed(data_dir: &Path, app: &str, id: &str) -> anyhow::Result<bool> {
    ensure!(
        valid_id(id) && !app.is_empty(),
        "invalid volume deletion identity"
    );
    let (block_root, block_owners) = block_roots(data_dir)?;
    if let Some(record) = read_block_owner(&block_owners, id)? {
        return delete_block(&block_root, &block_owners, app, id, record);
    }
    ensure!(
        fs::symlink_metadata(block_root.join(id))
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
        "unowned block mountpoint cannot be deleted as a directory volume"
    );
    let (root, owners) = managed_roots(data_dir)?;
    let path = root.join(id);
    let dir = match directory(&path) {
        Ok(dir) => Some(dir),
        Err(error) => match fs::symlink_metadata(&path) {
            Err(absent) if absent.kind() == io::ErrorKind::NotFound => None,
            _ => return Err(error),
        },
    };
    let Some(dir) = dir else {
        return match read_owner(&owners, id)? {
            None => Ok(true),
            Some(record) if record.app_id == app && record.volume_id == id && record.deleting => {
                Ok(true)
            }
            _ => anyhow::bail!(
                "volume {id} directory is missing but its ownership record has not been deleted"
            ),
        };
    };
    lock_directory(&dir, true)?;
    let Some(mut record) = read_owner(&owners, id)? else {
        anyhow::bail!("volume {id} exists without ownership metadata; refusing to erase it");
    };
    ensure!(
        record.app_id == app && record.volume_id == id,
        "refusing to delete another app's volume"
    );
    let meta = dir.metadata()?;
    ensure!(
        meta.dev() == record.device && meta.ino() == record.inode,
        "volume {id} directory was replaced; refusing to erase it"
    );
    if !record.deleting {
        owner_matches(&record, app, id, &dir)?;
        record.deleting = true;
        let temp = owners.join(format!("{id}.deleting"));
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("discard interrupted deletion marker"),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        serde_json::to_writer(&mut file, &record)?;
        file.sync_all()?;
        fs::rename(&temp, owner_path(&owners, id))?;
        directory(&owners)?.sync_all()?;
    }
    fs::remove_dir_all(&path)?;
    directory(&root)?.sync_all()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("grund-volume-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }
    fn mount(id: &str, source: &str) -> VolumeMount {
        VolumeMount {
            volume_id: id.into(),
            name: "data".into(),
            path: "/data".into(),
            source: source.into(),
            ..Default::default()
        }
    }
    const ID: &str = "11111111-1111-1111-1111-111111111111";

    fn copy_up_volume(name: &str) -> (PathBuf, VolumeBind) {
        let base = scratch(name);
        let bind = prepare(
            &base,
            &[],
            "app-a",
            &[VolumeMount {
                copy_up: true,
                ..mount(ID, "")
            }],
        )
        .unwrap()
        .remove(0);
        (base, bind)
    }

    fn begin(base: &Path, bind: &VolumeBind) -> anyhow::Result<Option<CopyUp>> {
        copy_up_begin(base, bind, verify_bind(base, &[], bind)?)
    }

    #[test]
    fn a_copy_up_stages_then_installs_into_an_empty_volume() {
        let (base, bind) = copy_up_volume("copy-up-fresh");
        let copy = begin(&base, &bind)
            .unwrap()
            .expect("an empty volume is copied into");
        fs::write(copy.staging().join("seed"), b"from the image").unwrap();
        fs::create_dir(copy.staging().join("conf")).unwrap();
        fs::set_permissions(copy.staging(), fs::Permissions::from_mode(0o750)).unwrap();
        let staging = copy.staging().to_path_buf();
        copy.install().unwrap();
        let volume = Path::new(&bind.source);
        assert_eq!(fs::read(volume.join("seed")).unwrap(), b"from the image");
        assert!(volume.join("conf").is_dir());
        assert_eq!(fs::metadata(volume).unwrap().mode() & 0o777, 0o750);
        assert!(!staging.exists());
        ensure_copied(&base, &bind).unwrap();
        assert!(begin(&base, &bind).unwrap().is_none());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_volume_with_data_is_never_copied_into_or_changed() {
        let (base, bind) = copy_up_volume("copy-up-data");
        fs::write(Path::new(&bind.source).join("user"), b"mine").unwrap();
        assert!(begin(&base, &bind).unwrap().is_none());
        assert_eq!(names_in(Path::new(&bind.source)).unwrap().len(), 1);
        assert_eq!(
            fs::read(Path::new(&bind.source).join("user")).unwrap(),
            b"mine"
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn leftover_staging_without_a_manifest_is_the_only_thing_removed() {
        let (base, bind) = copy_up_volume("copy-up-leftover");
        let copy = begin(&base, &bind).unwrap().unwrap();
        fs::write(copy.staging().join("half"), b"partial").unwrap();
        drop(copy);
        let again = begin(&base, &bind)
            .unwrap()
            .expect("still empty, so copied again");
        assert!(names_in(again.staging()).unwrap().is_empty());
        assert!(names_in(Path::new(&bind.source)).unwrap().is_empty());
        fs::remove_dir_all(base).unwrap();
    }

    fn interrupted(name: &str) -> (PathBuf, VolumeBind) {
        let (base, bind) = copy_up_volume(name);
        let copy = begin(&base, &bind).unwrap().unwrap();
        for file in ["a", "b"] {
            fs::write(copy.staging().join(file), file).unwrap();
        }
        let manifest = Manifest {
            names: vec!["a".into(), "b".into()],
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            mode: 0o755,
            atime: (0, 0),
            mtime: (0, 0),
        };
        let marker = base.join("volume-owners").join(format!("{ID}.copyup"));
        fs::write(&marker, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::rename(copy.staging().join("a"), Path::new(&bind.source).join("a")).unwrap();
        drop(copy);
        (base, bind)
    }

    #[test]
    fn an_interrupted_install_refuses_a_start_and_is_completed_not_undone() {
        let (base, bind) = interrupted("copy-up-resume");
        assert!(ensure_copied(&base, &bind).is_err());
        assert!(begin(&base, &bind).unwrap().is_none());
        assert_eq!(
            names_in(Path::new(&bind.source)).unwrap(),
            ["a".to_string(), "b".to_string()].into()
        );
        ensure_copied(&base, &bind).unwrap();
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn an_interrupted_install_next_to_foreign_content_is_left_alone() {
        let (base, bind) = interrupted("copy-up-tamper");
        fs::write(Path::new(&bind.source).join("foreign"), b"not ours").unwrap();
        assert!(begin(&base, &bind).is_err());
        assert_eq!(
            fs::read(Path::new(&bind.source).join("foreign")).unwrap(),
            b"not ours"
        );
        assert!(Path::new(&bind.source).join("a").exists());
        assert!(ensure_copied(&base, &bind).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_host_bind_or_block_volume_cannot_ask_for_a_copy_up() {
        let base = scratch("copy-up-bind");
        let host = scratch("copy-up-bind-host");
        fs::create_dir(host.join("sub")).unwrap();
        let refused = prepare(
            &base,
            &[host.clone()],
            "app-a",
            &[VolumeMount {
                copy_up: true,
                ..mount(ID, host.join("sub").to_str().unwrap())
            }],
        );
        assert!(refused.is_err());
        fs::remove_dir_all(base).unwrap();
        fs::remove_dir_all(host).unwrap();
    }
    #[test]
    fn mount_identity_distinguishes_the_proc_filesystem_from_the_root() {
        let root = File::open("/").unwrap();
        let same_root = File::open("/").unwrap();
        let proc = File::open("/proc").unwrap();
        assert_eq!(mount_id(&root).unwrap(), mount_id(&same_root).unwrap());
        assert_ne!(mount_id(&root).unwrap(), mount_id(&proc).unwrap());
    }

    #[test]
    fn managed_bytes_survive_restarts_and_replacement_is_refused() {
        let base = scratch("durable");
        let bind = prepare(&base, &[], "app-a", &[mount(ID, "")])
            .unwrap()
            .remove(0);
        fs::write(Path::new(&bind.source).join("message"), b"persisted").unwrap();
        let again = prepare(&base, &[], "app-a", &[mount(ID, "")]).unwrap();
        assert_eq!(
            fs::read(Path::new(&again[0].source).join("message")).unwrap(),
            b"persisted"
        );
        assert!(prepare(&base, &[], "app-b", &[mount(ID, "")]).is_err());
        let lost = base.join("lost");
        fs::rename(&bind.source, &lost).unwrap();
        assert!(prepare(&base, &[], "app-a", &[mount(ID, "")]).is_err());
        fs::create_dir(&bind.source).unwrap();
        assert!(verify_bind(&base, &[], &bind).is_err());
        fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn existing_paths_need_local_permission_stable_ancestors_and_no_symlink() {
        let base = scratch("policy");
        let data = base.join("data");
        fs::create_dir(&data).unwrap();
        let allowed = base.join("allowed");
        fs::create_dir(&allowed).unwrap();
        let photos = allowed.join("photos");
        fs::create_dir(&photos).unwrap();
        let source = photos.display().to_string();
        assert!(prepare(&data, &[], "app", &[mount(ID, &source)]).is_err());
        let unsafe_parent = prepare(
            &data,
            std::slice::from_ref(&allowed),
            "app",
            &[mount(ID, &source)],
        )
        .unwrap_err();
        assert!(
            format!("{unsafe_parent:#}").contains("ancestor writable by a non-root user"),
            "{unsafe_parent:#}"
        );
        let safe_source = "/usr/lib";
        let safe_roots = [PathBuf::from("/usr")];
        let safe = prepare(&data, &safe_roots, "app", &[mount(ID, safe_source)])
            .unwrap()
            .remove(0);
        verify_bind(&data, &safe_roots, &safe).unwrap();
        assert!(
            prepare(
                &data,
                std::slice::from_ref(&base),
                "app",
                &[mount(ID, &data.display().to_string())]
            )
            .is_err()
        );
        let mut nested = mount("22222222-2222-2222-2222-222222222222", safe_source);
        nested.path = "/other".into();
        assert!(prepare(&data, &safe_roots, "app", &[mount(ID, safe_source), nested]).is_err());
        fs::remove_dir(&photos).unwrap();
        std::os::unix::fs::symlink("/etc", &photos).unwrap();
        assert!(directory(&photos).is_err());
        assert!(prepare(&data, &[allowed], "app", &[mount(ID, &source)]).is_err());
        fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn deletion_requires_matching_owner_and_never_erases_host_data() {
        let base = scratch("delete");
        let bind = prepare(&base, &[], "app-a", &[mount(ID, "")])
            .unwrap()
            .remove(0);
        let file = Path::new(&bind.source).join("data");
        fs::write(&file, b"secret").unwrap();
        assert!(delete_managed(&base, "app-b", ID).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"secret");
        assert!(delete_managed(&base, "app-a", ID).unwrap());
        assert!(!file.exists());
        assert!(delete_managed(&base, "app-a", ID).unwrap());
        assert!(prepare(&base, &[], "app-a", &[mount(ID, "")]).is_err());
        fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn active_restore_fences_tombstone_ack_and_a_backup_flock_fences_erasure() {
        let base = scratch("active");
        let id = "33333333-3333-3333-3333-333333333333";
        let worker = guard(id).unwrap();
        assert!(active(id));
        assert!(!begin_delete(id).unwrap());
        assert!(
            guard(id).is_err(),
            "no new worker may begin after a signed tombstone"
        );
        drop(worker);
        assert!(!active(id));
        assert!(begin_delete(id).unwrap());
        assert!(
            delete_managed(&base, "app-a", id).unwrap(),
            "never-provisioned target has no data to erase"
        );
        if let Ok(mut states) = ACTIVITIES.lock() {
            states.remove(id);
        }
        let bind = prepare(&base, &[], "app-a", &[mount(id, "")])
            .unwrap()
            .remove(0);
        let file = Path::new(&bind.source).join("important");
        fs::write(&file, b"keep").unwrap();
        let (_, locked) = backup_guard(&base, &[], &bind).unwrap();
        assert!(delete_managed(&base, "app-a", id).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"keep");
        drop(locked);
        assert!(delete_managed(&base, "app-a", id).unwrap());
        if let Ok(mut states) = ACTIVITIES.lock() {
            states.remove(id);
        }
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn an_orphan_directory_is_not_acknowledged_or_erased() {
        let base = scratch("orphan");
        assert!(delete_managed(&base, "app-a", ID).unwrap());
        let path = managed_path(&base, ID).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("unowned"), b"do not erase").unwrap();
        assert!(delete_managed(&base, "app-a", ID).is_err());
        assert_eq!(fs::read(path.join("unowned")).unwrap(), b"do not erase");
        fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn block_identity_requires_ext4_magic_uuid_and_the_original_app_and_name() {
        let base = scratch("block-identity");
        let image = base.join("ext4-image");
        let app = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let new_owner = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let id = Uuid::new_v5(&app, b"data");
        let mut superblock = vec![0u8; 1024 + 120];
        superblock[1024 + 56..1024 + 58].copy_from_slice(&[0x53, 0xef]);
        superblock[1024 + 104..1024 + 120].copy_from_slice(id.as_bytes());
        fs::write(&image, &superblock).unwrap();
        assert!(matches_ext4(&File::open(&image).unwrap(), id).unwrap());
        assert!(
            open_block_device(&image).unwrap().is_none(),
            "a regular file cannot be attached storage"
        );
        let link = base.join("device-link");
        std::os::unix::fs::symlink(&image, &link).unwrap();
        assert!(
            open_block_device(&link).is_err(),
            "a symlink cannot designate a device"
        );

        let original = id.to_string();
        assert_eq!(
            block_identity(&app.to_string(), "data", &original).unwrap(),
            id
        );
        assert!(block_identity(&app.to_string(), "renamed", &original).is_err());
        assert!(block_identity(&new_owner.to_string(), "data", &original).is_err());
        let restored = Uuid::new_v5(&new_owner, b"data");
        assert!(!matches_ext4(&File::open(&image).unwrap(), restored).unwrap());

        superblock[1024 + 104..1024 + 120].copy_from_slice(restored.as_bytes());
        fs::write(&image, &superblock).unwrap();
        assert!(!matches_ext4(&File::open(&image).unwrap(), id).unwrap());
        superblock[1024 + 56] = 0;
        fs::write(&image, &superblock).unwrap();
        assert!(!matches_ext4(&File::open(&image).unwrap(), restored).unwrap());

        let mut signed = mount(&original, "/usr/lib");
        signed.block_device = true;
        assert!(prepare(&base, &[], &app.to_string(), &[signed]).is_err());
        assert!(!managed_path(&base, &original).unwrap().exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_previously_managed_directory_is_never_replaced_by_a_block_mount() {
        let base = scratch("no-block-fallback");
        let app = Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
        let id = Uuid::new_v5(&app, b"data").to_string();
        let old = prepare(&base, &[], &app.to_string(), &[mount(&id, "")])
            .unwrap()
            .remove(0);
        let bytes = Path::new(&old.source).join("important");
        fs::write(&bytes, b"existing data").unwrap();
        let mut signed = mount(&id, "");
        signed.block_device = true;
        let error = prepare(&base, &[], &app.to_string(), &[signed]).unwrap_err();
        assert!(format!("{error:#}").contains("conflicts with an existing managed directory"));
        assert_eq!(fs::read(&bytes).unwrap(), b"existing data");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn releasing_a_block_mount_never_erases_guest_bytes_or_transfers_its_owner() {
        let base = scratch("block-release");
        let app = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        let id = Uuid::new_v5(&app, b"data").to_string();
        let (root, owners) = block_roots(&base).unwrap();
        let path = root.join(&id);
        fs::create_dir(&path).unwrap();
        let bytes = path.join("important");
        fs::write(&bytes, b"do not erase").unwrap();
        fs::write(
            owner_path(&owners, &id),
            serde_json::to_vec(&BlockOwner {
                app_id: app.to_string(),
                volume_id: id.clone(),
                deleting: false,
            })
            .unwrap(),
        )
        .unwrap();
        let mut signed = mount(&id, "");
        signed.block_device = true;
        let desired = DesiredState {
            replicas: vec![grund_proto::grund::agent::v1::Replica {
                volumes: vec![signed],
                ..Default::default()
            }],
            ..Default::default()
        };
        release_unused(&base, Some(&desired), &[]).unwrap();
        assert_eq!(fs::read(&bytes).unwrap(), b"do not erase");
        let bind = VolumeBind {
            volume_id: id.clone(),
            app_id: app.to_string(),
            name: "data".into(),
            path: "/data".into(),
            source: path.display().to_string(),
            managed: false,
            block_device: true,
            copy_up: false,
        };
        release_unused(&base, None, &[("replica".into(), bind)]).unwrap();
        assert_eq!(fs::read(&bytes).unwrap(), b"do not erase");
        assert!(release_unused(&base, None, &[]).is_err());
        assert!(delete_managed(&base, "foreign-app", &id).is_err());
        assert_eq!(fs::read(&bytes).unwrap(), b"do not erase");
        fs::remove_file(&bytes).unwrap();
        release_unused(&base, None, &[]).unwrap();
        assert!(!path.exists());
        assert!(delete_managed(&base, &app.to_string(), &id).unwrap());
        assert!(block_source(&base, &app.to_string(), "data", &id).is_err());
        fs::remove_dir_all(base).unwrap();
    }
}
