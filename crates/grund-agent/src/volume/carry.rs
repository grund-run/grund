use super::*;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    ffi::OsString,
    io::{Read, Write},
    time::Duration,
};

const MANIFEST: &str = "volume-carry-attestation.json";
const PENDING: &str = "volume-carry-attestation.pending.json";
const CONSUMED: &str = "volume-carry-attestation.consumed.json";
const MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Attestation {
    version: u32,
    machine_id: String,
    fleet_machine_id: String,
    placement: u64,
    boot_id: String,
    data_dir: PathBuf,
    device_mapping: DeviceMapping,
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DeviceMapping {
    original_device: u64,
    mounted_source_device: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    app_id: String,
    volume_id: String,
    old_device: u64,
    old_inode: u64,
    new_device: u64,
    new_inode: u64,
    content_sha256: String,
}

struct ContextBinding<'a> {
    machine_id: &'a str,
    fleet_machine_id: &'a str,
    placement: u64,
    boot_id: &'a str,
    data_dir: &'a Path,
}

fn open_child(parent: &File, name: &std::ffi::OsStr, flags: i32) -> io::Result<File> {
    let name = CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn private_directory(dir: &File, uid: u32, private: bool) -> anyhow::Result<()> {
    let meta = dir.metadata()?;
    ensure!(
        meta.is_dir()
            && meta.uid() == uid
            && meta.mode() & (if private { 0o077 } else { 0o022 }) == 0,
        "carry metadata parent must be trusted and not writable by containers"
    );
    Ok(())
}

fn trusted_directory(path: &Path) -> anyhow::Result<File> {
    ensure!(path.is_absolute(), "carry path must be absolute");
    let mut dir = File::open("/")?;
    private_directory(&dir, 0, false)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                dir = open_child(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                private_directory(&dir, 0, false)?;
            }
            _ => anyhow::bail!("unsafe carry path"),
        }
    }
    Ok(dir)
}

fn read_private<T: serde::de::DeserializeOwned>(
    dir: &File,
    name: &str,
    uid: u32,
) -> anyhow::Result<Option<T>> {
    let file = match open_child(dir, name.as_ref(), libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("open private carry metadata"),
    };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == uid
            && meta.mode() & 0o077 == 0
            && meta.nlink() == 1
            && meta.len() <= MAX_BYTES as u64,
        "carry metadata must be a bounded private regular file without hard links"
    );
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_BYTES,
        "carry metadata exceeds size bound"
    );
    Ok(Some(
        serde_json::from_slice(&bytes).context("decode private carry metadata")?,
    ))
}

fn names(dir: &File) -> anyhow::Result<Vec<OsString>> {
    let mut names = fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(names)
}

fn atomic_json<T: Serialize>(
    dir: &File,
    name: &str,
    value: &T,
    replace: bool,
) -> anyhow::Result<()> {
    let temporary = CString::new(format!(".carry-{}", Uuid::now_v7()))?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("create atomic carry metadata");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| {
        serde_json::to_writer(&mut file, value)?;
        file.flush()?;
        file.sync_all()?;
        let name = CString::new(name)?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                dir.as_raw_fd(),
                temporary.as_ptr(),
                dir.as_raw_fd(),
                name.as_ptr(),
                if replace { 0 } else { libc::RENAME_NOREPLACE },
            )
        } < 0
        {
            return Err(io::Error::last_os_error()).context("publish atomic carry metadata");
        }
        dir.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(dir.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}

fn unlink(dir: &File, name: &str) -> anyhow::Result<()> {
    let name = CString::new(name)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error.into());
        }
    }
    dir.sync_all()?;
    Ok(())
}

fn digest_node(
    parent: &File,
    name: &std::ffi::OsStr,
    relative: &mut Vec<u8>,
    hash: &mut Sha256,
    buffer: &mut [u8],
) -> anyhow::Result<()> {
    let name_c = CString::new(name.as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name_c.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        return Err(io::Error::last_os_error()).context("inspect carried content");
    }
    let stat = unsafe { stat.assume_init() };
    let kind = match stat.st_mode & libc::S_IFMT {
        libc::S_IFDIR => b'd',
        libc::S_IFREG => b'f',
        libc::S_IFLNK => b'l',
        _ => anyhow::bail!("unsupported node in carried volume"),
    };
    hash.update((relative.len() as u64).to_le_bytes());
    hash.update(relative.as_slice());
    hash.update([kind]);
    hash.update((stat.st_mode & 0o7777).to_le_bytes());
    hash.update(stat.st_uid.to_le_bytes());
    hash.update(stat.st_gid.to_le_bytes());
    if kind == b'l' {
        let size = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name_c.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        ensure!(
            size >= 0 && (size as usize) < buffer.len(),
            "cannot read carried symlink"
        );
        hash.update((size as u64).to_le_bytes());
        hash.update(&buffer[..size as usize]);
    } else {
        let mut node = open_child(
            parent,
            name,
            libc::O_RDONLY | if kind == b'd' { libc::O_DIRECTORY } else { 0 },
        )?;
        let meta = node.metadata()?;
        ensure!(
            meta.dev() == stat.st_dev && meta.ino() == stat.st_ino && meta.mode() == stat.st_mode,
            "carried content changed during inspection"
        );
        if kind == b'd' {
            for child in names(&node)? {
                let previous = relative.len();
                if previous != 0 {
                    relative.push(b'/');
                }
                relative.extend_from_slice(child.as_bytes());
                digest_node(&node, &child, relative, hash, buffer)?;
                relative.truncate(previous);
            }
        } else {
            hash.update(meta.len().to_le_bytes());
            let mut length = 0u64;
            loop {
                let read = node.read(buffer)?;
                if read == 0 {
                    break;
                }
                length += read as u64;
                hash.update(&buffer[..read]);
            }
            let after = node.metadata()?;
            ensure!(
                length == meta.len()
                    && after.len() == meta.len()
                    && after.mtime() == meta.mtime()
                    && after.mtime_nsec() == meta.mtime_nsec()
                    && after.ctime() == meta.ctime()
                    && after.ctime_nsec() == meta.ctime_nsec(),
                "carried file changed while hashing"
            );
        }
    }
    Ok(())
}

fn content_digest(dir: &File) -> anyhow::Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    digest_node(
        dir,
        std::ffi::OsStr::new("."),
        &mut Vec::new(),
        &mut hash,
        &mut buffer,
    )?;
    Ok(hex::encode(hash.finalize()))
}

fn validate_context(attestation: &Attestation, context: &ContextBinding<'_>) -> anyhow::Result<()> {
    ensure!(
        attestation.version == 1 && attestation.entries.len() <= 1024,
        "unsupported or oversized carry attestation"
    );
    ensure!(
        valid_id(&attestation.machine_id)
            && valid_id(&attestation.fleet_machine_id)
            && valid_id(&attestation.boot_id),
        "invalid carry context identity"
    );
    ensure!(
        attestation.machine_id == context.machine_id
            && attestation.fleet_machine_id == context.fleet_machine_id
            && attestation.placement == context.placement
            && attestation.placement > 0
            && attestation.boot_id == context.boot_id
            && attestation.data_dir == context.data_dir,
        "carry attestation does not match registered machine, live Fleet placement, boot or volume root"
    );
    ensure!(
        attestation.device_mapping.original_device != 0
            && attestation.device_mapping.mounted_source_device != 0,
        "carry lacks a verified device namespace mapping"
    );
    let mut ids = HashSet::with_capacity(attestation.entries.len());
    for entry in &attestation.entries {
        ensure!(
            valid_id(&entry.app_id) && valid_id(&entry.volume_id) && ids.insert(&entry.volume_id),
            "invalid or duplicate carry volume identity"
        );
        ensure!(
            entry.old_device == attestation.device_mapping.original_device
                && entry.old_inode != 0
                && entry.new_device != 0
                && entry.new_inode != 0,
            "carry entry conflicts with verified original device mapping"
        );
        ensure!(
            entry.content_sha256.len() == 64
                && entry
                    .content_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid carry content digest"
        );
    }
    Ok(())
}

fn validate_entries(
    attestation: &Attestation,
    data: &File,
    uid: u32,
    complete: bool,
    resuming: bool,
) -> anyhow::Result<Vec<Owner>> {
    let volumes = open_child(data, "volumes".as_ref(), libc::O_RDONLY | libc::O_DIRECTORY);
    let owners = open_child(
        data,
        "volume-owners".as_ref(),
        libc::O_RDONLY | libc::O_DIRECTORY,
    );
    if attestation.entries.is_empty()
        && volumes
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        && owners
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
    {
        return Ok(Vec::new());
    }
    let (volumes, owners) = (volumes?, owners?);
    private_directory(&volumes, uid, true)?;
    private_directory(&owners, uid, true)?;
    if !complete {
        let expected: HashSet<_> = attestation
            .entries
            .iter()
            .map(|entry| OsString::from(&entry.volume_id))
            .collect();
        let expected_owners: HashSet<_> = attestation
            .entries
            .iter()
            .map(|entry| OsString::from(format!("{}.json", entry.volume_id)))
            .collect();
        ensure!(
            names(&volumes)?.into_iter().collect::<HashSet<_>>() == expected
                && names(&owners)?
                    .into_iter()
                    .filter(|name| !name.as_bytes().starts_with(b".carry-"))
                    .collect::<HashSet<_>>()
                    == expected_owners,
            "carry inventory is incomplete or contains unrelated volumes"
        );
    }
    let mut validated = Vec::with_capacity(attestation.entries.len());
    for entry in &attestation.entries {
        let owner: Owner = read_private(&owners, &format!("{}.json", entry.volume_id), uid)?
            .context("carried owner is missing")?;
        ensure!(
            owner.app_id == entry.app_id && owner.volume_id == entry.volume_id && !owner.deleting,
            "carried owner is deleting or has a different app or volume identity"
        );
        let old = owner.device == entry.old_device && owner.inode == entry.old_inode;
        let new = owner.device == entry.new_device && owner.inode == entry.new_inode;
        ensure!(
            if complete {
                new
            } else {
                old || (resuming && new)
            },
            "carried owner does not match the recorded transition"
        );
        let target = open_child(
            &volumes,
            entry.volume_id.as_ref(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let meta = target.metadata()?;
        ensure!(
            meta.dev() == entry.new_device && meta.ino() == entry.new_inode,
            "carried target directory was replaced"
        );
        if !complete {
            ensure!(
                content_digest(&target)? == entry.content_sha256,
                "carried volume content differs from the verified copy"
            );
        }
        validated.push(owner);
    }
    Ok(validated)
}

fn consume_at(
    fleet: &File,
    data: &File,
    context: &ContextBinding<'_>,
    uid: u32,
    mut after_owner: impl FnMut(usize) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    private_directory(fleet, uid, false)?;
    private_directory(data, uid, false)?;
    ensure!(
        unsafe { libc::flock(fleet.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another carry consumer is active"
    );
    let manifest: Option<Attestation> = read_private(fleet, MANIFEST, uid)?;
    let pending: Option<Attestation> = read_private(fleet, PENDING, uid)?;
    let consumed: Option<Attestation> = read_private(fleet, CONSUMED, uid)?;
    if let Some(receipt) = consumed {
        if receipt.boot_id != context.boot_id {
            ensure!(
                manifest.is_none() && pending.is_none(),
                "stale carry receipt conflicts with a required handoff"
            );
            return Ok(());
        }
        validate_context(&receipt, context)?;
        ensure!(
            manifest.is_none() && pending.as_ref().is_none_or(|journal| *journal == receipt),
            "consumed carry cannot grant another handoff"
        );
        validate_entries(&receipt, data, uid, true, true)?;
        fleet.sync_all()?;
        if pending.is_some() {
            unlink(fleet, PENDING)?;
        }
        return Ok(());
    }
    let Some(attestation) = manifest else {
        ensure!(
            pending.is_none(),
            "required carry manifest is missing during consumption"
        );
        return Ok(());
    };
    validate_context(&attestation, context)?;
    ensure!(
        pending
            .as_ref()
            .is_none_or(|journal| *journal == attestation),
        "carry manifest changed during partial consumption"
    );
    let validated = validate_entries(&attestation, data, uid, false, pending.is_some())?;
    if pending.is_none() {
        atomic_json(fleet, PENDING, &attestation, false)?;
    }
    if !validated.is_empty() {
        let owners = open_child(
            data,
            "volume-owners".as_ref(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let volumes = open_child(data, "volumes".as_ref(), libc::O_RDONLY | libc::O_DIRECTORY)?;
        for (index, (entry, mut owner)) in attestation.entries.iter().zip(validated).enumerate() {
            let target = open_child(
                &volumes,
                entry.volume_id.as_ref(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            let meta = target.metadata()?;
            ensure!(
                meta.dev() == entry.new_device && meta.ino() == entry.new_inode,
                "carry target changed before owner update"
            );
            owner.device = entry.new_device;
            owner.inode = entry.new_inode;
            atomic_json(&owners, &format!("{}.json", entry.volume_id), &owner, true)?;
            after_owner(index)?;
        }
    }
    validate_entries(&attestation, data, uid, true, true)?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            fleet.as_raw_fd(),
            c"volume-carry-attestation.json".as_ptr(),
            fleet.as_raw_fd(),
            c"volume-carry-attestation.consumed.json".as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } < 0
    {
        return Err(io::Error::last_os_error()).context("consume carry attestation exactly once");
    }
    fleet.sync_all()?;
    unlink(fleet, PENDING)?;
    Ok(())
}

async fn bounded_response(
    mut response: reqwest::Response,
    maximum: usize,
) -> anyhow::Result<Vec<u8>> {
    response = response.error_for_status()?;
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= maximum as u64),
        "MMDS response exceeds bound"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= maximum,
            "MMDS response exceeds bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn live_fleet() -> anyhow::Result<(String, u64)> {
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(2))
        .build()?;
    let session = bounded_response(
        http.put("http://169.254.169.254/latest/api/token")
            .header("X-metadata-token-ttl-seconds", "60")
            .send()
            .await?,
        4096,
    )
    .await?;
    let session = std::str::from_utf8(&session)?.trim();
    ensure!(!session.is_empty(), "MMDS returned an empty session");
    let bytes = bounded_response(
        http.get("http://169.254.169.254/")
            .header("X-metadata-token", session)
            .header("Accept", "application/json")
            .send()
            .await?,
        MAX_BYTES,
    )
    .await?;
    let document: serde_json::Value = serde_json::from_slice(&bytes)?;
    let fleet = document.get("fleet").context("MMDS has no Fleet context")?;
    let id = fleet
        .get("machine_id")
        .and_then(|id| id.as_str())
        .context("MMDS lacks Fleet machine identity")?;
    let placement = fleet
        .get("placement")
        .and_then(|value| value.as_u64())
        .context("MMDS lacks Fleet placement")?;
    ensure!(
        valid_id(id) && placement > 0,
        "MMDS has invalid Fleet identity or placement"
    );
    Ok((id.into(), placement))
}

pub(super) async fn consume(data_dir: &Path, machine_id: &str) -> anyhow::Result<()> {
    let fleet_path = Path::new("/var/lib/fleet");
    let mut present = false;
    for name in [MANIFEST, PENDING, CONSUMED] {
        match fs::symlink_metadata(fleet_path.join(name)) {
            Ok(_) => present = true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect Fleet carry handoff"),
        }
    }
    if !present {
        return Ok(());
    }
    let fleet = trusted_directory(fleet_path)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot = boot.trim();
    let receipt: Option<Attestation> = read_private(&fleet, CONSUMED, 0)?;
    if receipt.is_some_and(|receipt| receipt.boot_id != boot)
        && read_private::<Attestation>(&fleet, MANIFEST, 0)?.is_none()
        && read_private::<Attestation>(&fleet, PENDING, 0)?.is_none()
    {
        return Ok(());
    }
    let (fleet_id, placement) = live_fleet()
        .await
        .context("verify live Fleet carry context")?;
    let data = trusted_directory(data_dir)?;
    consume_at(
        &fleet,
        &data,
        &ContextBinding {
            machine_id,
            fleet_machine_id: &fleet_id,
            placement,
            boot_id: boot,
            data_dir,
        },
        0,
        |_| Ok(()),
    )
    .context("consume verified Fleet volumes before starting workers")
}

#[cfg(test)]
mod tests;
