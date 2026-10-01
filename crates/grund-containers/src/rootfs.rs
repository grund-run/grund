//! Reading a few files from a container's root filesystem before it runs:
//! the snapshot's mounts are mounted read-only on a scratch directory, the
//! files read, and the mounts undone. Only regular files under real
//! directories are read: a symlink in the image is never followed onto the
//! host.

use std::{
    ffi::CString,
    io,
    os::unix::ffi::OsStrExt,
    path::{Component, Path},
};

use crate::api::containerd::types::Mount;

/// Splits a containerd mount's options into `mount(2)` flags and the data
/// string the filesystem gets. Always adds `MS_RDONLY`.
pub fn flags_and_data(options: &[String]) -> (libc::c_ulong, String) {
    let mut flags = libc::MS_RDONLY;
    let mut data = Vec::new();
    for option in options {
        match option.as_str() {
            "ro" | "rw" => {}
            "bind" => flags |= libc::MS_BIND,
            "rbind" => flags |= libc::MS_BIND | libc::MS_REC,
            "nosuid" => flags |= libc::MS_NOSUID,
            "nodev" => flags |= libc::MS_NODEV,
            "noexec" => flags |= libc::MS_NOEXEC,
            other => data.push(other),
        }
    }
    (flags, data.join(","))
}

fn cstring(text: &str) -> io::Result<CString> {
    CString::new(text).map_err(io::Error::other)
}

fn mount_one(mount: &Mount, target: &Path) -> io::Result<()> {
    let (flags, data) = flags_and_data(&mount.options);
    let source = cstring(&mount.source)?;
    let kind = cstring(&mount.r#type)?;
    let to = CString::new(target.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let data = cstring(&data)?;
    let bind = flags & libc::MS_BIND != 0;
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            to.as_ptr(),
            kind.as_ptr(),
            flags,
            data.as_ptr().cast(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if bind {
        let remount = unsafe {
            libc::mount(
                std::ptr::null(),
                to.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                std::ptr::null(),
            )
        };
        if remount < 0 {
            let error = io::Error::last_os_error();
            unmount(target);
            return Err(error);
        }
    }
    Ok(())
}

fn unmount(target: &Path) {
    if let Ok(to) = CString::new(target.as_os_str().as_bytes()) {
        unsafe {
            libc::umount2(to.as_ptr(), libc::MNT_DETACH);
        }
    }
}

/// A regular file at `relative` under `root`, when every component on the
/// way is a real directory (no symlink) and the file is regular.
pub fn read_regular(root: &Path, relative: &str) -> Option<String> {
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            return None;
        };
        path.push(name);
        let meta = std::fs::symlink_metadata(&path).ok()?;
        if meta.file_type().is_symlink() {
            return None;
        }
    }
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > 4 * 1024 * 1024 {
        return None;
    }
    std::fs::read_to_string(&path).ok()
}

/// Mounts `mounts` (one, as containerd gives an active snapshot's) read-only
/// on `scratch`, reads each of `files` (relative paths), and unmounts.
pub fn read_files(
    mounts: &[Mount],
    scratch: &Path,
    files: &[&str],
) -> io::Result<Vec<Option<String>>> {
    let [mount] = mounts else {
        return Err(io::Error::other(format!(
            "expected one rootfs mount, containerd gave {}",
            mounts.len()
        )));
    };
    std::fs::create_dir_all(scratch)?;
    mount_one(mount, scratch)?;
    let read = files.iter().map(|f| read_regular(scratch, f)).collect();
    unmount(scratch);
    let _ = std::fs::remove_dir(scratch);
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_options_become_data_and_bind_options_flags() {
        let (flags, data) = flags_and_data(&[
            "index=off".into(),
            "workdir=/w".into(),
            "upperdir=/u".into(),
            "lowerdir=/l1:/l2".into(),
        ]);
        assert_eq!(flags, libc::MS_RDONLY);
        assert_eq!(data, "index=off,workdir=/w,upperdir=/u,lowerdir=/l1:/l2");
        let (flags, data) = flags_and_data(&["rbind".into(), "rw".into()]);
        assert_eq!(flags, libc::MS_RDONLY | libc::MS_BIND | libc::MS_REC);
        assert_eq!(data, "");
    }

    #[test]
    fn a_symlinked_passwd_is_not_followed_onto_the_host() {
        let root = std::env::temp_dir().join(format!(
            "grund-containers-rootfs-{}",
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/group"), "root:x:0:\n").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("etc/passwd")).unwrap();
        assert_eq!(
            read_regular(&root, "etc/group").as_deref(),
            Some("root:x:0:\n")
        );
        assert_eq!(read_regular(&root, "etc/passwd"), None);
        assert_eq!(read_regular(&root, "../etc/passwd"), None);
        std::fs::create_dir_all(root.join("via")).unwrap();
        std::os::unix::fs::symlink("/etc", root.join("via/etc")).unwrap();
        assert_eq!(read_regular(&root.join("via"), "etc/hostname"), None);
        std::fs::remove_dir_all(root).unwrap();
    }
}
