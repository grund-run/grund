//! Firecracker under its jailer, for bridged VMs: each VM runs as a uid of
//! its own, chrooted into its directory, so a guest that escapes into its
//! Firecracker process holds nothing but that VM.
//!
//! ```text
//!   <vm>/rootfs.ext4                          the disk, owned by the VM's uid
//!   <vm>/jail/firecracker/<id>/root/          the chroot: Firecracker's "/" and cwd
//!       firecracker                           copied in by the jailer
//!       dev/                                  kvm, net/tun, urandom, made by the jailer
//!       vmlinux                               a hard link to the verified kernel
//!       rootfs.ext4                           a hard link to the disk
//!       fc.sock                               the API
//! ```
//!
//! The uid is [`UID_BASE`] plus the VM's address on the bridge, so it is
//! unique on the machine for as long as the VM holds that address, and the
//! tap is created owned by it, so no other VM can open it. The kernel's
//! inode is shared by every VM using it and is never chowned, only made
//! readable. The jailer execs Firecracker in place, so the pid recorded is
//! Firecracker's.
//!
//! Not done yet: cgroup limits. Firecracker's own memory is bounded by the
//! guest's, and the VM's vCPUs by its configuration, but a runaway VMM is
//! not capped.

use std::{
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// The first of the uids VMs run as: above systemd's container and dynamic
/// user ranges, below 2^31.
pub const UID_BASE: u32 = 1_950_000_000;

/// The jailer and the Firecracker it runs.
#[derive(Debug, Clone)]
pub struct Jail {
    pub jailer: PathBuf,
    pub firecracker: PathBuf,
}

/// The uid (and gid) of the VM at `.octet`.
pub fn uid(octet: u8) -> u32 {
    UID_BASE + u32::from(octet)
}

/// The jailer's id for the VM in `dir`: the directory's name, its VM id.
pub fn id(dir: &Path) -> String {
    dir.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The chroot the jailer makes for the VM in `dir`.
pub fn root(dir: &Path) -> PathBuf {
    dir.join("jail/firecracker").join(id(dir)).join("root")
}

impl Jail {
    /// Makes the chroot ready for a launch as `uid`: an earlier run's
    /// leftovers removed (the jailer refuses device nodes that exist), the
    /// kernel and disk linked in, and the chroot and disk owned by the VM.
    pub fn prepare(&self, dir: &Path, uid: u32, kernel: &Path) -> io::Result<()> {
        let root = root(dir);
        std::fs::create_dir_all(&root)?;
        for stale in [
            "dev",
            "firecracker",
            "run",
            "fc.sock",
            "vmlinux",
            "rootfs.ext4",
        ] {
            let path = root.join(stale);
            if path.is_dir() {
                std::fs::remove_dir_all(&path)?;
            } else if path.symlink_metadata().is_ok() {
                std::fs::remove_file(&path)?;
            }
        }
        std::fs::set_permissions(kernel, std::fs::Permissions::from_mode(0o644))?;
        link(kernel, &root.join("vmlinux"))?;
        let disk = dir.join("rootfs.ext4");
        chown(&disk, uid)?;
        std::fs::set_permissions(&disk, std::fs::Permissions::from_mode(0o600))?;
        std::fs::hard_link(&disk, root.join("rootfs.ext4"))?;
        chown(&root, uid)
    }

    /// The jailer's arguments for the VM in `dir`.
    pub fn args(&self, dir: &Path, uid: u32) -> Vec<String> {
        vec![
            "--id".into(),
            id(dir),
            "--exec-file".into(),
            self.firecracker.display().to_string(),
            "--uid".into(),
            uid.to_string(),
            "--gid".into(),
            uid.to_string(),
            "--chroot-base-dir".into(),
            dir.join("jail").display().to_string(),
            "--resource-limit".into(),
            "no-file=1024".into(),
            "--".into(),
            "--api-sock".into(),
            "fc.sock".into(),
        ]
    }
}

fn link(from: &Path, to: &Path) -> io::Result<()> {
    match std::fs::hard_link(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            std::fs::copy(from, to).map(|_| ())
        }
        Err(error) => Err(error),
    }
}

fn chown(path: &Path, uid: u32) -> io::Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(uid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chroot_uid_and_command_are_the_vms_own() {
        let dir = Path::new("/var/lib/grund/agent/vm/vms/0190a1b2-c3d4");
        assert_eq!(
            root(dir),
            Path::new(
                "/var/lib/grund/agent/vm/vms/0190a1b2-c3d4/jail/firecracker/0190a1b2-c3d4/root"
            )
        );
        assert_eq!(uid(2), 1_950_000_002);
        assert!(uid(254) < 1 << 31);
        let jail = Jail {
            jailer: "/usr/local/bin/jailer".into(),
            firecracker: "/usr/local/bin/firecracker".into(),
        };
        let args = jail.args(dir, uid(7)).join(" ");
        assert!(
            args.starts_with("--id 0190a1b2-c3d4 --exec-file /usr/local/bin/firecracker --uid 1950000007 --gid 1950000007 --chroot-base-dir /var/lib/grund/agent/vm/vms/0190a1b2-c3d4/jail"),
            "{args}"
        );
        assert!(args.ends_with("-- --api-sock fc.sock"), "{args}");
    }
}
