use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    time::{Duration, Instant},
};

use grund_agent::runtime::{ResourceLimitFailure as Failure, ResourceLimitProof};

use crate::capabilities::CGROUP2_MAGIC;

const CPU_QUOTA: u64 = 10_000;
const CPU_PERIOD: u64 = 100_000;
const MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_READ: u64 = 4096;
const PROBE_DEADLINE: Duration = Duration::from_secs(2);
const CLEANUP_GRACE: Duration = Duration::from_secs(6);
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

pub(crate) fn probe() -> ResourceLimitProof {
    let mut proof = ResourceLimitProof::default();
    let deadline = Instant::now() + PROBE_DEADLINE;
    let parent = match delegation() {
        Ok(parent) => parent,
        Err(_) => {
            proof.failure = Some(Failure::BootDelegationUnavailable);
            return proof;
        }
    };
    if Instant::now() >= deadline {
        proof.failure = Some(Failure::ChildUnavailable);
        return proof;
    }
    let mut leaf = match OwnedLeaf::create(&parent) {
        Ok(leaf) => leaf,
        Err(failure) => {
            proof.failure = Some(failure);
            return proof;
        }
    };
    let result = verify(&leaf, &mut proof, deadline);
    proof.failure = result.err();
    if leaf.cleanup().is_err() {
        proof.failure = Some(Failure::CleanupUnverified);
    }
    proof
}

fn delegation() -> io::Result<File> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/sys/fs/cgroup")?;
    validate_delegation(&root, true)?;
    let parent = open_at(&root, c"grund", libc::O_RDONLY | libc::O_DIRECTORY)?;
    validate_delegation(&parent, false)?;
    if root.metadata()?.dev() != parent.metadata()?.dev()
        || !read_at(&parent, c"cgroup.procs")?.trim().is_empty()
    {
        return Err(io::Error::other("unusable app delegation"));
    }
    Ok(parent)
}

fn validate_delegation(dir: &File, hierarchy_mount: bool) -> io::Result<()> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::unnecessary_cast)]
    let magic = stat.f_type as i64;
    if magic != CGROUP2_MAGIC
        || !domain_type(dir, hierarchy_mount)?
        || !delegates_limits(&read_at(dir, c"cgroup.controllers")?)
        || !delegates_limits(&read_at(dir, c"cgroup.subtree_control")?)
    {
        return Err(io::Error::other("unusable app delegation"));
    }
    Ok(())
}

fn domain_type(dir: &File, hierarchy_mount: bool) -> io::Result<bool> {
    match read_at(dir, c"cgroup.type") {
        Ok(kind) => Ok(kind.trim() == "domain"),
        Err(error) if hierarchy_mount && error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

fn delegates_limits(text: &str) -> bool {
    let mut cpu = false;
    let mut memory = false;
    for controller in text.split_ascii_whitespace() {
        cpu |= controller == "cpu";
        memory |= controller == "memory";
    }
    cpu && memory
}

fn verify(
    leaf: &OwnedLeaf<'_>,
    proof: &mut ResourceLimitProof,
    deadline: Instant,
) -> Result<(), Failure> {
    probe_time_remaining(deadline)?;
    let dir = leaf.dir.as_ref().ok_or(Failure::LeafUnavailable)?;
    write_at(dir, c"cpu.max", b"10000 100000\n").map_err(|_| Failure::CpuLimitUnverified)?;
    probe_time_remaining(deadline)?;
    write_at(dir, c"memory.max", b"67108864\n").map_err(|_| Failure::MemoryLimitUnverified)?;
    verify_limits(dir)?;
    probe_time_remaining(deadline)?;
    if !read_at(dir, c"cgroup.procs")
        .map_err(|_| Failure::AttachmentUnverified)?
        .trim()
        .is_empty()
    {
        return Err(Failure::AttachmentUnverified);
    }
    probe_time_remaining(deadline)?;
    let mut child =
        OwnedChild::spawn(dir, deadline + CLEANUP_GRACE).map_err(|_| Failure::ChildUnavailable)?;
    let result = (|| {
        if Instant::now() >= deadline || !child.alive() {
            return Err(Failure::ChildUnavailable);
        }
        let membership = read_bounded(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(format!("/proc/{}/cgroup", child.pid))
                .map_err(|_| Failure::AttachmentUnverified)?,
        )
        .map_err(|_| Failure::AttachmentUnverified)?;
        probe_time_remaining(deadline)?;
        let expected = format!("/grund/{}", leaf.name.to_string_lossy());
        if !membership_matches(&membership, &expected)
            || !only_owned_member(
                &read_at(dir, c"cgroup.procs").map_err(|_| Failure::AttachmentUnverified)?,
                child.pid,
            )
        {
            return Err(Failure::AttachmentUnverified);
        }
        verify_limits(dir)?;
        if Instant::now() >= deadline || !child.alive() {
            return Err(Failure::AttachmentUnverified);
        }
        proof.cpu_verified = true;
        proof.memory_verified = true;
        proof.attachment_verified = true;
        Ok(())
    })();
    if child.cleanup().is_err() {
        return Err(Failure::CleanupUnverified);
    }
    result
}

fn probe_time_remaining(deadline: Instant) -> Result<(), Failure> {
    if Instant::now() >= deadline {
        return Err(Failure::ChildUnavailable);
    }
    Ok(())
}

fn verify_limits(dir: &File) -> Result<(), Failure> {
    if !read_at(dir, c"cpu.max").is_ok_and(|text| cpu_limit(&text) == Some((CPU_QUOTA, CPU_PERIOD)))
    {
        return Err(Failure::CpuLimitUnverified);
    }
    if !read_at(dir, c"memory.max")
        .is_ok_and(|text| finite_number(text.trim()) == Some(MEMORY_BYTES))
    {
        return Err(Failure::MemoryLimitUnverified);
    }
    Ok(())
}

fn finite_number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok().filter(|number| *number != 0)
}

fn cpu_limit(text: &str) -> Option<(u64, u64)> {
    let mut fields = text.split_ascii_whitespace();
    let quota = finite_number(fields.next()?)?;
    let period = finite_number(fields.next()?)?;
    fields.next().is_none().then_some((quota, period))
}

fn membership_matches(text: &str, expected: &str) -> bool {
    let mut unified = text.lines().filter_map(|line| line.strip_prefix("0::"));
    unified.next() == Some(expected) && unified.next().is_none()
}

fn only_owned_member(text: &str, pid: libc::pid_t) -> bool {
    let Ok(pid) = u64::try_from(pid) else {
        return false;
    };
    if pid == 0 {
        return false;
    }
    let mut members = text.split_ascii_whitespace();
    members.next().and_then(finite_number) == Some(pid) && members.next().is_none()
}

fn open_at(dir: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_bounded(file: File) -> io::Result<String> {
    let mut text = String::new();
    file.take(MAX_READ + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MAX_READ {
        return Err(io::Error::other("oversized kernel response"));
    }
    Ok(text)
}

fn read_at(dir: &File, name: &CStr) -> io::Result<String> {
    read_bounded(open_at(dir, name, libc::O_RDONLY)?)
}

fn write_at(dir: &File, name: &CStr, value: &[u8]) -> io::Result<()> {
    open_at(dir, name, libc::O_WRONLY)?.write_all(value)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

fn identity_at(dir: &File, name: &CStr) -> io::Result<FileIdentity> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(io::Error::other("owned leaf is not a directory"));
    }
    Ok(FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

struct OwnedLeaf<'a> {
    parent: &'a File,
    name: CString,
    identity: Option<FileIdentity>,
    dir: Option<File>,
    removed: bool,
}

impl<'a> OwnedLeaf<'a> {
    fn create(parent: &'a File) -> Result<Self, Failure> {
        let name = CString::new(format!(".resource-probe-{}", uuid::Uuid::new_v4()))
            .map_err(|_| Failure::LeafUnavailable)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(Failure::BootDelegationUnavailable);
        }
        let mut leaf = Self {
            parent,
            name,
            identity: None,
            dir: None,
            removed: false,
        };
        let setup = (|| {
            leaf.identity = Some(identity_at(parent, &leaf.name)?);
            let dir = open_at(parent, &leaf.name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let metadata = dir.metadata()?;
            if leaf.identity
                != Some(FileIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                })
            {
                return Err(io::Error::other("owned leaf changed"));
            }
            leaf.dir = Some(dir);
            Ok::<_, io::Error>(())
        })();
        if setup.is_err() {
            return Err(if leaf.cleanup().is_err() {
                Failure::CleanupUnverified
            } else {
                Failure::LeafUnavailable
            });
        }
        Ok(leaf)
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        if self.identity.is_none() || Some(identity_at(self.parent, &self.name)?) != self.identity {
            return Err(io::Error::other("owned leaf identity changed"));
        }
        if unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.removed = true;
        Ok(())
    }
}

impl Drop for OwnedLeaf<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct OwnedChild {
    pid: libc::pid_t,
    pidfd: File,
    reaped: bool,
    cleanup_deadline: Instant,
}

impl OwnedChild {
    fn spawn(cgroup: &File, cleanup_deadline: Instant) -> io::Result<Self> {
        child_cleanup_available()?;
        let parent = unsafe { libc::getpid() };
        let mut child_deadline: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut child_deadline) } != 0 {
            return Err(io::Error::last_os_error());
        }
        child_deadline.tv_sec = child_deadline
            .tv_sec
            .checked_add(5)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let mut pidfd: RawFd = -1;
        let mut args: libc::clone_args = unsafe { std::mem::zeroed() };
        args.flags = libc::CLONE_PIDFD as u64 | CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP;
        args.pidfd = (&raw mut pidfd) as u64;
        args.exit_signal = libc::SIGCHLD as u64;
        args.cgroup = cgroup.as_raw_fd() as u64;
        let pid = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &raw mut args,
                std::mem::size_of::<libc::clone_args>(),
            )
        };
        if pid == 0 {
            unsafe { child_wait(parent, &child_deadline) }
        }
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            pid: pid as libc::pid_t,
            pidfd: unsafe { File::from_raw_fd(pidfd) },
            reaped: false,
            cleanup_deadline,
        })
    }

    fn alive(&self) -> bool {
        let mut fd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&raw mut fd, 1, 0) == 0 }
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        let signal = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        let signal_error = (signal < 0).then(io::Error::last_os_error);
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let waited = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.pidfd.as_raw_fd() as libc::id_t,
                    &raw mut info,
                    libc::WEXITED | libc::WNOHANG,
                )
            };
            if waited == 0 && unsafe { info.si_pid() } == self.pid {
                self.reaped = true;
                return match signal_error {
                    Some(error) if error.raw_os_error() != Some(libc::ESRCH) => Err(error),
                    _ => Ok(()),
                };
            }
            if waited < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            let timeout = cleanup_poll_timeout(self.cleanup_deadline)?;
            let mut fd = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&raw mut fd, 1, timeout) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}

fn child_cleanup_available() -> io::Result<()> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let waited = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            libc::c_int::MAX as libc::id_t,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG,
        )
    };
    if waited != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
        return Err(io::Error::other("owned-child reaping unavailable"));
    }
    let signaled = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            -1,
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if signaled != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
        return Err(io::Error::other("owned-child signaling unavailable"));
    }
    Ok(())
}

fn cleanup_poll_timeout(deadline: Instant) -> io::Result<libc::c_int> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
    Ok(remaining.as_millis().clamp(1, 100) as libc::c_int)
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

unsafe fn child_wait(parent: libc::pid_t, deadline: &libc::timespec) -> ! {
    unsafe {
        if libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
            0,
            0,
            0,
        ) != 0
            || libc::syscall(libc::SYS_getppid) != libc::c_long::from(parent)
        {
            libc::syscall(libc::SYS_exit_group, 1);
        }
        libc::syscall(
            libc::SYS_clock_nanosleep,
            libc::CLOCK_MONOTONIC,
            libc::TIMER_ABSTIME,
            deadline as *const libc::timespec,
            std::ptr::null_mut::<libc::timespec>(),
        );
        libc::syscall(libc::SYS_exit_group, 0);
        libc::_exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

    struct Scratch {
        path: PathBuf,
        dir: File,
    }

    impl Scratch {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("grund-resource-probe-{}", uuid::Uuid::new_v4()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            let dir = File::open(&path).unwrap();
            Self { path, dir }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    #[test]
    fn cleanup_preflight_supports_pidfds_without_reaping_other_children() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 37"])
            .spawn()
            .unwrap();
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            let _ = child.wait();
            panic!("open owned test child pidfd: {error}");
        }
        let pidfd = unsafe { File::from_raw_fd(fd as RawFd) };
        let mut ready = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let exited = unsafe { libc::poll(&raw mut ready, 1, 5_000) };
        let preflight = child_cleanup_available();
        let status = child.wait().unwrap();
        assert_eq!(exited, 1);
        assert_ne!(ready.revents & libc::POLLIN, 0);
        assert_eq!(status.code(), Some(37));
        assert!(
            preflight.is_ok(),
            "pidfd cleanup unavailable: {preflight:?}"
        );
    }

    #[test]
    fn expired_deadlines_do_not_restart_probe_or_cleanup_waits() {
        let expired = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            probe_time_remaining(expired),
            Err(Failure::ChildUnavailable)
        );
        assert_eq!(
            cleanup_poll_timeout(expired).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            cleanup_poll_timeout(Instant::now() + Duration::from_secs(30)).unwrap(),
            100
        );
    }

    #[test]
    fn unlimited_zero_malformed_and_overflowed_limits_cannot_be_verified() {
        assert_eq!(cpu_limit("10000 100000\n"), Some((10_000, 100_000)));
        assert_eq!(finite_number("67108864"), Some(MEMORY_BYTES));
        for text in [
            "max 100000",
            "0 100000",
            "10000 0",
            "-1 100000",
            "+10000 100000",
            "18446744073709551616 100000",
            "10000 100000 trailing",
            "10000",
        ] {
            assert_eq!(cpu_limit(text), None, "{text}");
        }
        for text in ["max", "0", "-1", "+1", "1 2", "18446744073709551616"] {
            assert_eq!(finite_number(text), None, "{text}");
        }
    }

    #[test]
    fn controller_names_must_be_individually_delegated() {
        assert!(delegates_limits("cpuset cpu io memory\n"));
        assert!(!delegates_limits("cpuset memory\n"));
        assert!(!delegates_limits("cpu memory_recursiveprot\n"));
        assert!(!delegates_limits("+cpu +memory\n"));
    }

    #[test]
    fn missing_type_is_only_valid_at_the_hierarchy_mount() {
        let scratch = Scratch::new();
        assert!(domain_type(&scratch.dir, true).unwrap());
        assert!(domain_type(&scratch.dir, false).is_err());
        let kind = scratch.path.join("cgroup.type");
        fs::write(&kind, "domain\n").unwrap();
        assert!(domain_type(&scratch.dir, false).unwrap());
        fs::write(&kind, "threaded\n").unwrap();
        assert!(!domain_type(&scratch.dir, true).unwrap());
        assert!(!domain_type(&scratch.dir, false).unwrap());
    }

    #[test]
    fn attachment_requires_one_exact_unified_path_and_only_the_owned_pid() {
        let path = "/grund/.resource-probe-owned";
        assert!(membership_matches(
            "0::/grund/.resource-probe-owned\n",
            path
        ));
        for text in [
            "0::/grund/.resource-probe-owned/other\n",
            "0::/grund/.resource-probe-owned-more\n",
            "1:cpu:/grund/.resource-probe-owned\n",
            "0::/grund/.resource-probe-owned\n0::/elsewhere\n",
        ] {
            assert!(!membership_matches(text, path), "{text}");
        }
        assert!(only_owned_member("123\n", 123));
        for text in ["", "124\n", "123\n124\n", "123\n123\n", "+123\n"] {
            assert!(!only_owned_member(text, 123), "{text}");
        }
        assert!(!only_owned_member("", -1));
        assert!(!only_owned_member("0\n", 0));
    }

    #[test]
    fn a_probe_scope_removes_its_owned_leaf() {
        let scratch = Scratch::new();
        let path = {
            let leaf = OwnedLeaf::create(&scratch.dir).unwrap();
            let path = scratch.path.join(leaf.name.to_str().unwrap());
            assert!(path.try_exists().unwrap());
            path
        };
        assert!(!path.try_exists().unwrap());
    }

    #[test]
    fn cleanup_refuses_a_replacement_directory_at_the_owned_name() {
        let scratch = Scratch::new();
        let mut leaf = OwnedLeaf::create(&scratch.dir).unwrap();
        let path = scratch.path.join(leaf.name.to_str().unwrap());
        let moved = scratch.path.join("moved");
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(leaf.cleanup().is_err());
        assert!(path.is_dir());
        assert!(moved.is_dir());
    }

    #[test]
    fn cleanup_never_recursively_removes_unowned_contents() {
        let scratch = Scratch::new();
        let mut leaf = OwnedLeaf::create(&scratch.dir).unwrap();
        let path = scratch.path.join(leaf.name.to_str().unwrap());
        let foreign = path.join("foreign");
        fs::write(&foreign, b"retain").unwrap();
        assert!(leaf.cleanup().is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"retain");
        fs::remove_file(&foreign).unwrap();
        leaf.cleanup().unwrap();
        leaf.cleanup().unwrap();
        assert!(!path.try_exists().unwrap());
    }

    #[test]
    fn kernel_file_reads_refuse_symlinks_and_oversized_responses() {
        let scratch = Scratch::new();
        let data = scratch.path.join("data");
        fs::write(&data, "1".repeat(MAX_READ as usize + 1)).unwrap();
        std::os::unix::fs::symlink(&data, scratch.path.join("link")).unwrap();
        assert!(read_at(&scratch.dir, c"link").is_err());
        assert!(read_at(&scratch.dir, c"data").is_err());
    }
}
