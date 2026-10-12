//! Agent-owned persistent volume directories and locally authorized host binds.
//! Ownership records live outside container-writable directories, under a
//! root-owned sibling. A missing or changed directory is never recreated.

use std::{
    collections::HashMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    sync::{LazyLock, Mutex},
};

use anyhow::{Context, ensure};
use grund_proto::grund::agent::v1::{DesiredState, VolumeMount};
use serde::{Deserialize, Serialize};

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
        let source = if mount.source.is_empty() {
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
        binds.push(VolumeBind {
            volume_id: mount.volume_id.clone(),
            app_id: app.into(),
            name: mount.name.clone(),
            path: mount.path.clone(),
            source: source.display().to_string(),
            managed: mount.source.is_empty(),
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
    if uid != 0 {
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

/// Erase only a directory with a matching owner record, after its writer is
/// stopped. Leave the deleting record as a durable replay receipt until the
/// control plane removes the tombstone; this also prevents ID reuse.
pub fn delete_managed(data_dir: &Path, app: &str, id: &str) -> anyhow::Result<bool> {
    ensure!(
        valid_id(id) && !app.is_empty(),
        "invalid volume deletion identity"
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
}
