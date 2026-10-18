//! PID 1 of a grund microVM (grund-vm): the whole of its init system.
//!
//! ```text
//!   boot     mount /proc /sys /dev /run /tmp, / read-write, Ctrl-Alt-Del to SIGINT,
//!            /etc/resolv.conf from the resolvers the kernel's ip= argument names,
//!            / grown online to fill its disk, up to 2 TiB (the image is small;
//!            grund-vm grows the disk file to the VM's size)
//!   context  fetch MMDSv2 once, including on an already registered root; PID1
//!            writes only public boot context to protected tmpfs before agent
//!            work, bound to the current registration and kernel boot UUID
//!   register grund join --mmds, again with backoff from 2 s to 60 s until
//!            /var/lib/grund/agent/machine.json exists: the machine is registered
//!   run      grund agent, restarted with the same backoff whenever it ends
//!   stop     on SIGINT or SIGTERM (a Ctrl-Alt-Del from the host): SIGTERM to the
//!            children, 5 s, sync, reboot; with reboot=k Firecracker then exits
//! ```
//!
//! It never exits: PID 1 exiting panics the kernel. It reaps every child,
//! so success is read from what grund join leaves on disk, not from an exit
//! status. The metadata address needs no route of its own: it is on-link in
//! grund-vm's isolated network, and behind the default route on a bridge.

use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const GRUND: &str = "/usr/local/bin/grund";
const REGISTERED: &str = "/var/lib/grund/agent/machine.json";
const MAX_BACKOFF: Duration = Duration::from_secs(60);

const BOOT_MARKER: &str = "/run/grund/guest-boot.json";
const MAX_METADATA: usize = 16 * 1024;
const MAX_HEADERS: usize = 4096;
const METADATA_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(serde::Deserialize)]
struct Metadata {
    grund: Assignment,
    vm: MetadataVm,
}

#[derive(serde::Deserialize)]
struct MetadataVm {
    id: String,
}

#[derive(serde::Deserialize)]
struct Assignment {
    #[serde(skip)]
    vm_id: String,
    url: String,
    replacement: Option<Replacement>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    attempt_id: String,
    sequence: u64,
    document_generation: u64,
    guest_machine_id: String,
    launch_nonce: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Registration {
    machine_id: String,
    instance_url: String,
    instance_key: PinnedKey,
    trust_key: PinnedKey,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PinnedKey {
    key_id: String,
    public_key: String,
    purpose: String,
}

#[derive(serde::Serialize)]
struct BootContext {
    version: u32,
    vm_id: String,
    os_boot_id: String,
    machine_id: String,
    machine_public_key: String,
    instance_url: String,
    instance_key: PinnedKey,
    trust_key: PinnedKey,
    replacement: Option<Replacement>,
}

fn valid_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

fn metadata_origin(value: &str) -> Option<&str> {
    let value = value.trim().trim_end_matches('/');
    let (scheme, authority) = value.split_once("://")?;
    if value.len() > 2048
        || authority.is_empty()
        || authority
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b'@' | b'?' | b'#' | b'/' | b'\\'))
    {
        return None;
    }
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(authority, |(host, _)| host)
        .trim_start_matches('[')
        .trim_end_matches(']');
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    (scheme == "https" || (scheme == "http" && loopback)).then_some(value)
}

fn parse_assignment(bytes: &[u8]) -> Option<Assignment> {
    if bytes.len() > MAX_METADATA {
        return None;
    }
    let metadata = serde_json::from_slice::<Metadata>(bytes).ok()?;
    let mut assignment = metadata.grund;
    assignment.vm_id = metadata.vm.id;
    if !valid_uuid(&assignment.vm_id) || metadata_origin(&assignment.url).is_none() {
        return None;
    }
    if let Some(replacement) = &assignment.replacement
        && (!valid_uuid(&replacement.attempt_id)
            || !valid_uuid(&replacement.guest_machine_id)
            || !valid_uuid(&replacement.launch_nonce)
            || replacement.sequence == 0
            || replacement.sequence > i64::MAX as u64
            || replacement.document_generation == 0
            || replacement.document_generation > i64::MAX as u64)
    {
        return None;
    }
    Some(assignment)
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "metadata deadline"))
}

fn response_length(headers: &[u8], max_body: usize) -> Option<usize> {
    let headers = std::str::from_utf8(headers).ok()?;
    let mut lines = headers.split("\r\n");
    let status = lines.next()?;
    if !matches!(
        status.split_whitespace().next(),
        Some("HTTP/1.0" | "HTTP/1.1")
    ) || status.split_whitespace().nth(1) != Some("200")
    {
        return None;
    }
    let mut length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return None;
            }
            length = Some(value.trim().parse::<usize>().ok()?);
        }
    }
    length.filter(|length| *length <= max_body)
}

fn metadata_request(request: &str, max_body: usize, deadline: Instant) -> io::Result<Vec<u8>> {
    let address = SocketAddr::from(([169, 254, 169, 254], 80));
    let mut stream = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(request.as_bytes())?;
    let mut bytes = Vec::new();
    let mut body = None;
    loop {
        if let Some((start, length)) = body
            && bytes.len() == start + length
        {
            bytes.copy_within(start.., 0);
            bytes.truncate(length);
            return Ok(bytes);
        }
        let limit = body.map_or(MAX_HEADERS, |(start, length)| start + length);
        if bytes.len() >= limit {
            return Err(io::Error::other("invalid metadata response"));
        }
        let mut buffer = [0; 1024];
        let capacity = buffer.len().min(limit - bytes.len());
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let count = stream.read(&mut buffer[..capacity])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "metadata response",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
        if body.is_none()
            && let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let start = end + 4;
            let length = response_length(&bytes[..start], max_body)
                .ok_or_else(|| io::Error::other("invalid metadata headers"))?;
            if bytes.len() > start + length {
                return Err(io::Error::other("invalid metadata length"));
            }
            body = Some((start, length));
        }
    }
}

fn fetch_boot_assignment() -> Option<Assignment> {
    let deadline = Instant::now() + METADATA_TIMEOUT;
    let token = metadata_request(
        "PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-metadata-token-ttl-seconds: 60\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        1024,
        deadline,
    ).ok()?;
    let token = std::str::from_utf8(&token).ok()?.trim();
    if token.is_empty() || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return None;
    }
    let bytes = metadata_request(
        &format!("GET / HTTP/1.1\r\nHost: 169.254.169.254\r\nX-metadata-token: {token}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"),
        MAX_METADATA,
        deadline,
    ).ok()?;
    parse_assignment(&bytes)
}

fn read_protected(path: &str, limit: u64) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::other("unprotected identity"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("oversized identity"));
    }
    Ok(bytes)
}

fn boot_context(
    assignment: Assignment,
    registration: Registration,
    public_key: String,
    os_boot_id: String,
) -> Option<BootContext> {
    if !valid_uuid(&os_boot_id)
        || !valid_uuid(&registration.machine_id)
        || assignment.url.trim().trim_end_matches('/') != registration.instance_url
        || assignment
            .replacement
            .as_ref()
            .is_some_and(|replacement| replacement.guest_machine_id != registration.machine_id)
    {
        return None;
    }
    Some(BootContext {
        version: 1,
        vm_id: assignment.vm_id,
        os_boot_id,
        machine_id: registration.machine_id,
        machine_public_key: public_key,
        instance_url: registration.instance_url,
        instance_key: registration.instance_key,
        trust_key: registration.trust_key,
        replacement: assignment.replacement,
    })
}

fn write_boot_context(assignment: Assignment) -> Option<()> {
    if std::process::id() != 1 {
        return None;
    }
    let registration =
        serde_json::from_slice(&read_protected(REGISTERED, MAX_METADATA as u64).ok()?).ok()?;
    let seed = read_protected("/var/lib/grund/agent/machine.key", 128).ok()?;
    let seed: [u8; 32] = hex::decode(std::str::from_utf8(&seed).ok()?.trim())
        .ok()?
        .try_into()
        .ok()?;
    let public_key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    let os_boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()?
        .trim()
        .to_string();
    let context = boot_context(assignment, registration, public_key, os_boot_id)?;
    let run = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open("/run")
        .ok()?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    let run_result = unsafe { libc::fstatfs(run.as_raw_fd(), &mut filesystem) };
    #[allow(clippy::unnecessary_cast)]
    let run_magic = filesystem.f_type as i64;
    if run_result != 0 || run_magic != libc::TMPFS_MAGIC {
        return None;
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create("/run/grund")
        .ok()?;
    let directory = std::fs::symlink_metadata("/run/grund").ok()?;
    if !directory.is_dir() || directory.uid() != 0 || directory.mode() & 0o777 != 0o700 {
        return None;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(BOOT_MARKER)
        .ok()?;
    let bytes = serde_json::to_vec(&context).ok()?;
    file.write_all(&bytes).ok()?;
    file.sync_all().ok()?;
    File::open("/run/grund").ok()?.sync_all().ok()?;
    Some(())
}
static STOP: AtomicBool = AtomicBool::new(false);

macro_rules! log {
    ($($arg:tt)*) => {{
        println!("grund-guest: {}", format!($($arg)*));
    }};
}

extern "C" fn on_stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn mount(source: &str, target: &str, fstype: &str, flags: libc::c_ulong) {
    let _ = std::fs::create_dir_all(target);
    let (source, target, fstype) = (cstr(source), cstr(target), cstr(fstype));
    unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
}

fn cstr(value: &str) -> CString {
    CString::new(value).unwrap_or_default()
}

fn boot() {
    mount("proc", "/proc", "proc", 0);
    mount("sysfs", "/sys", "sysfs", 0);
    mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0);
    if let Err(error) = prepare_app_cgroups() {
        log!("app cgroup delegation unavailable: {error}");
    }
    if !Path::new("/dev/null").exists() {
        mount("devtmpfs", "/dev", "devtmpfs", 0);
    }
    let root = cstr("/");
    let none = cstr("");
    unsafe {
        libc::mount(
            none.as_ptr(),
            root.as_ptr(),
            none.as_ptr(),
            libc::MS_REMOUNT,
            std::ptr::null(),
        )
    };
    mount("tmpfs", "/run", "tmpfs", 0);
    let _ = std::fs::set_permissions("/run", std::fs::Permissions::from_mode(0o755));
    mount("tmpfs", "/tmp", "tmpfs", 0);
    unsafe {
        libc::reboot(libc::LINUX_REBOOT_CMD_CAD_OFF);
        libc::signal(libc::SIGINT, on_stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_stop as *const () as libc::sighandler_t);
    }
    grow_root();
    if let Some(resolv) = std::fs::read_to_string("/proc/net/pnp")
        .ok()
        .as_deref()
        .and_then(resolv_conf)
    {
        let _ = std::fs::create_dir_all("/etc");
        let _ = std::fs::write("/etc/resolv.conf", resolv);
    }
}

fn prepare_app_cgroups() -> std::io::Result<()> {
    std::fs::write(
        "/sys/fs/cgroup/cgroup.subtree_control",
        "+cpu +memory +pids",
    )?;
    std::fs::create_dir_all("/sys/fs/cgroup/grund")?;
    std::fs::write(
        "/sys/fs/cgroup/grund/cgroup.subtree_control",
        "+cpu +memory +pids",
    )
}

const EXT4_IOC_RESIZE_FS: libc::c_ulong = 0x4008_6610;
const MAX_ROOT_BYTES: u64 = 2 << 40;

fn grow_root() {
    let sectors = std::fs::read_to_string("/sys/block/vda/size")
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok());
    let root = cstr("/");
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(root.as_ptr(), &mut stat) } != 0 {
        return;
    }
    let (Some(sectors), block) = (sectors, stat.f_frsize as u64) else {
        return;
    };
    let Some(target) = blocks_to_fill(sectors, block, stat.f_blocks as u64) else {
        return;
    };
    let fd = unsafe { libc::open(root.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        return;
    }
    let grown = unsafe { libc::ioctl(fd, EXT4_IOC_RESIZE_FS as _, &target) };
    unsafe { libc::close(fd) };
    if grown == 0 {
        log!("grew / to {} MiB", target * block / 1024 / 1024);
    } else {
        log!(
            "could not grow / to fill its disk: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn blocks_to_fill(sectors: u64, block: u64, current: u64) -> Option<u64> {
    if block == 0 {
        return None;
    }
    let target = (sectors * 512).min(MAX_ROOT_BYTES) / block;
    (target > current).then_some(target)
}

fn resolv_conf(pnp: &str) -> Option<String> {
    let lines: Vec<&str> = pnp
        .lines()
        .filter(|line| line.starts_with("nameserver ") && !line.ends_with(" 0.0.0.0"))
        .collect();
    (!lines.is_empty()).then(|| lines.join("\n") + "\n")
}

fn reap() {
    loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid <= 0 {
            return;
        }
    }
}

fn alive(child: &Child) -> bool {
    Path::new(&format!("/proc/{}", child.id())).exists()
        && std::fs::read_to_string(format!("/proc/{}/stat", child.id()))
            .map(|stat| {
                stat.rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().next())
                    .is_some_and(|state| state != "Z" && state != "X")
            })
            .unwrap_or(false)
}

fn spawn(args: &[&str]) -> Option<Child> {
    match Command::new(GRUND).args(args).stdin(Stdio::null()).spawn() {
        Ok(child) => Some(child),
        Err(error) => {
            log!("cannot start grund {}: {error}", args.join(" "));
            None
        }
    }
}

fn shutdown(children: &[Child]) -> ! {
    log!("stopping");
    for child in children.iter() {
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while children.iter().any(alive) && Instant::now() < deadline {
        reap();
        thread::sleep(Duration::from_millis(100));
    }
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn next_backoff(backoff: Duration) -> Duration {
    (backoff * 2).min(MAX_BACKOFF)
}

fn main() {
    boot();
    let mut boot_assignment = fetch_boot_assignment();
    log!("started");
    let mut children: Vec<Child> = Vec::new();
    let mut backoff = Duration::from_secs(2);
    let mut next_start = Instant::now();
    let mut agent_supported = true;
    loop {
        if STOP.load(Ordering::SeqCst) {
            shutdown(&children);
        }
        reap();
        children.retain(alive);
        let registered = Path::new(REGISTERED).exists();
        if registered
            && let Some(assignment) = boot_assignment.take()
            && write_boot_context(assignment).is_none()
        {
            log!("boot context unavailable; guest readiness proof disabled");
        }
        if children.is_empty() && Instant::now() >= next_start {
            if !Path::new(GRUND).exists() {
                log!("this image has no grund at {GRUND}; nothing to run");
                next_start = Instant::now() + MAX_BACKOFF;
            } else if !registered {
                log!("registering: grund join --mmds");
                children.extend(spawn(&["join", "--mmds"]));
                next_start = Instant::now() + backoff;
                backoff = next_backoff(backoff);
            } else if agent_supported {
                if Command::new(GRUND)
                    .args(["agent", "--help"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success())
                {
                    log!("registered; running grund agent");
                    children.extend(spawn(&["agent"]));
                    next_start = Instant::now() + backoff;
                    backoff = next_backoff(backoff);
                } else {
                    log!(
                        "registered; this grund has no agent yet, so there is nothing more to run"
                    );
                    agent_supported = false;
                }
            }
        }
        if registered && !children.is_empty() {
            backoff = Duration::from_secs(2);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VM: &str = "00000000-0000-4000-8000-000000000001";
    const MACHINE: &str = "00000000-0000-4000-8000-000000000002";
    const ATTEMPT: &str = "00000000-0000-4000-8000-000000000003";
    const NONCE: &str = "00000000-0000-4000-8000-000000000004";
    const BOOT: &str = "00000000-0000-4000-8000-000000000005";

    fn metadata() -> serde_json::Value {
        serde_json::json!({
            "grund": {
                "url": "https://grund.example.com",
                "enrollment_token": "secret-enrollment",
                "machine_key": "secret-private-key",
                "replacement": {
                    "attempt_id": ATTEMPT,
                    "sequence": 3,
                    "document_generation": 7,
                    "guest_machine_id": MACHINE,
                    "launch_nonce": NONCE,
                },
            },
            "vm": { "id": VM },
            "fleet": {"machine_id": "secret-provider-identity"},
        })
    }

    fn registration() -> Registration {
        let key = |purpose: &str| PinnedKey {
            key_id: purpose.to_string(),
            public_key: "a".repeat(64),
            purpose: purpose.to_string(),
        };
        Registration {
            machine_id: MACHINE.to_string(),
            instance_url: "https://grund.example.com".to_string(),
            instance_key: key("instance"),
            trust_key: key("organisation"),
        }
    }

    fn assignment(value: &serde_json::Value) -> Option<Assignment> {
        parse_assignment(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn metadata_secrets_cannot_cross_the_persisted_boot_boundary() {
        let context = boot_context(
            assignment(&metadata()).unwrap(),
            registration(),
            "b".repeat(64),
            BOOT.to_string(),
        )
        .unwrap();
        let bytes = serde_json::to_string(&context).unwrap();
        assert!(!bytes.contains("secret-"));
        assert!(!bytes.contains("enrollment_token"));
        assert!(!bytes.contains("machine_key"));
        let value: serde_json::Value = serde_json::from_str(&bytes).unwrap();
        assert_eq!(value["replacement"]["launch_nonce"], NONCE);
        assert_eq!(value["os_boot_id"], BOOT);
    }

    #[test]
    fn malformed_or_oversized_metadata_never_creates_a_context() {
        assert!(parse_assignment(b"{").is_none());
        assert!(parse_assignment(&vec![b' '; MAX_METADATA + 1]).is_none());
        for url in [
            "https://user:secret-password@grund.example.com",
            "https://grund.example.com?token=secret",
            "https://grund.example.com/#secret",
        ] {
            let mut credentialed = metadata();
            credentialed["grund"]["url"] = serde_json::json!(url);
            assert!(assignment(&credentialed).is_none());
        }
        let mut invalid = metadata();
        invalid["grund"]["replacement"]["sequence"] = serde_json::json!(0);
        assert!(assignment(&invalid).is_none());
        invalid = metadata();
        invalid["vm"]["id"] = serde_json::json!("not-a-vm");
        assert!(assignment(&invalid).is_none());
        invalid = metadata();
        invalid["grund"]["replacement"]["document_generation"] = serde_json::json!(u64::MAX);
        assert!(assignment(&invalid).is_none());
    }

    #[test]
    fn another_guest_or_instance_cannot_reuse_the_registered_identity() {
        let mut other_guest = metadata();
        other_guest["grund"]["replacement"]["guest_machine_id"] = serde_json::json!(VM);
        assert!(
            boot_context(
                assignment(&other_guest).unwrap(),
                registration(),
                "b".repeat(64),
                BOOT.to_string(),
            )
            .is_none()
        );
        let mut other_instance = metadata();
        other_instance["grund"]["url"] = serde_json::json!("https://other.example.com");
        assert!(
            boot_context(
                assignment(&other_instance).unwrap(),
                registration(),
                "b".repeat(64),
                BOOT.to_string(),
            )
            .is_none()
        );
        assert!(
            boot_context(
                assignment(&metadata()).unwrap(),
                registration(),
                "b".repeat(64),
                "agent-boot-id".to_string(),
            )
            .is_none()
        );
    }

    #[test]
    fn metadata_http_refuses_ambiguous_or_unbounded_bodies() {
        assert_eq!(
            response_length(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", 10),
            Some(10)
        );
        for headers in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n".as_slice(),
        ] {
            assert_eq!(response_length(headers, 10), None);
        }
    }

    #[test]
    fn the_kernels_nameservers_become_a_resolv_conf() {
        let pnp = "#PROTO: MANUAL\nnameserver 1.1.1.1\nnameserver 0.0.0.0\n";
        assert_eq!(resolv_conf(pnp).as_deref(), Some("nameserver 1.1.1.1\n"));
        assert_eq!(resolv_conf("#PROTO: MANUAL\n"), None);
    }

    #[test]
    fn the_root_grows_only_when_its_disk_is_larger() {
        let one_gib_in_sectors = 2 * 1024 * 1024;
        assert_eq!(
            blocks_to_fill(one_gib_in_sectors, 4096, 12_288),
            Some(262_144)
        );
        assert_eq!(blocks_to_fill(one_gib_in_sectors, 4096, 262_144), None);
        assert_eq!(blocks_to_fill(one_gib_in_sectors, 0, 1), None);
        let four_tib_in_sectors = 8 << 30;
        assert_eq!(
            blocks_to_fill(four_tib_in_sectors, 4096, 12_288),
            Some(512 << 20),
            "no further than the image's reserve allows"
        );
    }

    #[test]
    fn the_backoff_doubles_up_to_a_minute() {
        assert_eq!(next_backoff(Duration::from_secs(2)), Duration::from_secs(4));
        assert_eq!(next_backoff(Duration::from_secs(40)), MAX_BACKOFF);
    }
}
