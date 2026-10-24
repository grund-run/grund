//! Reading a few files from a container's root filesystem before it runs,
//! and copying an image directory into a new volume: the snapshot's mounts
//! are mounted read-only on a scratch directory, the files read or copied,
//! and the mounts undone. A symlink in the image is never followed onto the
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

/// Mounts `mounts` read-only on `scratch` and copies the image's directory
/// `from` (absolute in the image) into the empty directory `into`, as
/// Docker's copy-up does: modes, owners and times kept, the directory's own
/// on `into` too, symlinks copied as symlinks. False, with nothing copied,
/// when `from` is absent or not a directory in the image. A symlink on the
/// way to `from`, or a device, FIFO or socket in it, is refused.
pub fn copy_tree(mounts: &[Mount], scratch: &Path, from: &str, into: &Path) -> io::Result<bool> {
    let [mount] = mounts else {
        return Err(io::Error::other(format!(
            "expected one rootfs mount, containerd gave {}",
            mounts.len()
        )));
    };
    std::fs::create_dir_all(scratch)?;
    mount_one(mount, scratch)?;
    let copied = image_directory(scratch, from).and_then(|source| match source {
        Some(source) => copy_directory(&source, into).map(|()| true),
        None => Ok(false),
    });
    unmount(scratch);
    let _ = std::fs::remove_dir(scratch);
    copied
}

fn image_directory(root: &Path, from: &str) -> io::Result<Option<std::path::PathBuf>> {
    let mut path = root.to_path_buf();
    for component in Path::new(from).components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                path.push(name);
                match std::fs::symlink_metadata(&path) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(io::Error::other(format!(
                            "{from} passes through a symlink in the image"
                        )));
                    }
                    Ok(meta) if !meta.is_dir() => return Ok(None),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
            _ => {
                return Err(io::Error::other(format!(
                    "{from} is not a plain absolute path"
                )));
            }
        }
    }
    Ok(Some(path))
}

fn copy_directory(source: &Path, into: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let from = entry.path();
        let to = into.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&from)?;
        let kind = meta.file_type();
        if kind.is_dir() {
            std::fs::create_dir(&to)?;
            copy_directory(&from, &to)?;
        } else if kind.is_file() {
            std::fs::copy(&from, &to)?;
        } else if kind.is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(&from)?, &to)?;
        } else {
            return Err(io::Error::other(format!(
                "{} is a device, FIFO or socket, which a volume copy does not take",
                from.display()
            )));
        }
        keep_metadata(&to, &meta)?;
    }
    keep_metadata(into, &std::fs::symlink_metadata(source)?)
}

fn keep_metadata(path: &Path, meta: &std::fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let to = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    if unsafe { libc::lchown(to.as_ptr(), meta.uid(), meta.gid()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if !meta.file_type().is_symlink()
        && unsafe { libc::chmod(to.as_ptr(), meta.mode() & 0o7777) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let times = [
        libc::timespec {
            tv_sec: meta.atime(),
            tv_nsec: meta.atime_nsec(),
        },
        libc::timespec {
            tv_sec: meta.mtime(),
            tv_nsec: meta.mtime_nsec(),
        },
    ];
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            to.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "grund-copy-up-{name}-{}",
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_image_directory_is_copied_with_its_modes_and_symlinks_kept() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let image = temp("image");
        let data = image.join("var/lib/app");
        std::fs::create_dir_all(data.join("nested")).unwrap();
        std::fs::write(data.join("nested/seed.txt"), "seed").unwrap();
        std::fs::set_permissions(
            data.join("nested/seed.txt"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        std::os::unix::fs::symlink("/etc/passwd", data.join("link")).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o750)).unwrap();
        let volume = temp("volume");
        let source = image_directory(&image, "/var/lib/app").unwrap().unwrap();
        copy_directory(&source, &volume).unwrap();
        assert_eq!(
            std::fs::read_to_string(volume.join("nested/seed.txt")).unwrap(),
            "seed"
        );
        assert_eq!(
            std::fs::metadata(volume.join("nested/seed.txt"))
                .unwrap()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(
            std::fs::read_link(volume.join("link")).unwrap(),
            Path::new("/etc/passwd")
        );
        assert_eq!(std::fs::metadata(&volume).unwrap().mode() & 0o777, 0o750);
        assert_eq!(
            std::fs::metadata(volume.join("nested/seed.txt"))
                .unwrap()
                .mtime(),
            std::fs::metadata(data.join("nested/seed.txt"))
                .unwrap()
                .mtime()
        );
        std::fs::remove_dir_all(image).unwrap();
        std::fs::remove_dir_all(volume).unwrap();
    }

    #[test]
    fn a_symlink_on_the_way_or_a_fifo_inside_is_refused_and_an_absent_path_copies_nothing() {
        let image = temp("refuse");
        std::fs::create_dir_all(image.join("real")).unwrap();
        std::os::unix::fs::symlink("/etc", image.join("via")).unwrap();
        assert!(image_directory(&image, "/via/ssl").is_err());
        assert_eq!(image_directory(&image, "/missing/dir").unwrap(), None);
        let fifo = CString::new(image.join("real/pipe").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let volume = temp("refuse-volume");
        assert!(copy_directory(&image.join("real"), &volume).is_err());
        std::fs::remove_dir_all(image).unwrap();
        std::fs::remove_dir_all(volume).unwrap();
    }

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
