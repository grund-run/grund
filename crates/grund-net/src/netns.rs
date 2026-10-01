//! Each container's own network namespace, made by the runtime rather than
//! runc so it can be entered by path: `<run dir>/netns/<id>`, a bind mount
//! of the namespace (as `ip netns add` makes them), with loopback up and no
//! other interface. The directory is a shared mount, so removing a
//! namespace's mount propagates to mount namespaces that copied it.
//!
//! The namespace is made on a thread of its own, which unshares its network
//! namespace, brings `lo` up, bind-mounts `/proc/thread-self/ns/net` and
//! ends; no other thread's namespace changes. Entering one ([`enter`]) is
//! for a thread that ends after it, too.

use std::{
    ffi::CString,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
};

/// `NSFS_MAGIC`: the filesystem a namespace file lives on.
pub const NSFS_MAGIC: i64 = 0x6e73_6673;

/// Where container `id`'s namespace is bound.
pub fn path(dir: &Path, id: &str) -> PathBuf {
    dir.join(id)
}

fn cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
}

fn check(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Whether `path` is a bound namespace (rather than the empty file it is
/// bound onto, which is what is left after a reboot or a crash).
pub fn is_namespace(path: &Path) -> bool {
    let Ok(c) = cstring(path) else {
        return false;
    };
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::statfs(c.as_ptr(), &mut stat) };
    #[allow(clippy::unnecessary_cast)]
    let kind = stat.f_type as i64;
    result == 0 && kind == NSFS_MAGIC
}

fn make_shared(dir: &Path) -> io::Result<()> {
    let c = cstring(dir)?;
    let none = c"none";
    let shared = unsafe {
        libc::mount(
            none.as_ptr(),
            c.as_ptr(),
            std::ptr::null(),
            libc::MS_SHARED | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if shared == 0 {
        return Ok(());
    }
    check(unsafe {
        libc::mount(
            c.as_ptr(),
            c.as_ptr(),
            none.as_ptr(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    })?;
    check(unsafe {
        libc::mount(
            none.as_ptr(),
            c.as_ptr(),
            std::ptr::null(),
            libc::MS_SHARED | libc::MS_REC,
            std::ptr::null(),
        )
    })
}

/// Brings `lo` up in the calling thread's network namespace.
pub fn loopback_up() -> io::Result<()> {
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { std::os::fd::OwnedFd::from_raw_fd(socket) };
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(b"lo\0") {
        *slot = *byte as libc::c_char;
    }
    check(unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut request) })?;
    unsafe {
        request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
    }
    check(unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS as _, &mut request) })
}

/// Makes sure container `id` has its namespace at [`path`], with loopback
/// up, and returns the path. One already bound is kept as it is.
pub fn ensure(dir: &Path, id: &str) -> io::Result<PathBuf> {
    let target = path(dir, id);
    if is_namespace(&target) {
        return Ok(target);
    }
    std::fs::create_dir_all(dir)?;
    make_shared(dir)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&target)?;
    let bind_to = target.clone();
    let made = std::thread::spawn(move || -> io::Result<()> {
        check(unsafe { libc::unshare(libc::CLONE_NEWNET) })?;
        loopback_up()?;
        let source = c"/proc/thread-self/ns/net";
        let to = cstring(&bind_to)?;
        check(unsafe {
            libc::mount(
                source.as_ptr(),
                to.as_ptr(),
                c"none".as_ptr(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        })
    })
    .join()
    .map_err(|_| io::Error::other("the namespace thread panicked"))?;
    if let Err(error) = made {
        let _ = std::fs::remove_file(&target);
        return Err(error);
    }
    Ok(target)
}

/// Unmounts and removes container `id`'s namespace. A missing one is fine.
pub fn remove(dir: &Path, id: &str) -> io::Result<()> {
    let target = path(dir, id);
    if !target.exists() {
        return Ok(());
    }
    let c = cstring(&target)?;
    let unmounted = unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
    if unmounted < 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOENT)) {
            return Err(error);
        }
    }
    match std::fs::remove_file(&target) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Moves the calling thread into the namespace at `path`. For a thread
/// that ends afterwards: it never moves back.
pub fn enter(path: &Path) -> io::Result<()> {
    let file = std::fs::File::open(path)?;
    check(unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) })
}
