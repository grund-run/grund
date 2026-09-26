//! PID 1 of a grund microVM (grund-vm): the whole of its init system.
//!
//! ```text
//!   boot     mount /proc /sys /dev /run /tmp, / read-write, Ctrl-Alt-Del to SIGINT,
//!            /etc/resolv.conf from the resolvers the kernel's ip= argument names
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
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const GRUND: &str = "/usr/local/bin/grund";
const REGISTERED: &str = "/var/lib/grund/agent/machine.json";
const MAX_BACKOFF: Duration = Duration::from_secs(60);

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
    mount("tmpfs", "/tmp", "tmpfs", 0);
    unsafe {
        libc::reboot(libc::LINUX_REBOOT_CMD_CAD_OFF);
        libc::signal(libc::SIGINT, on_stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_stop as *const () as libc::sighandler_t);
    }
    if let Some(resolv) = std::fs::read_to_string("/proc/net/pnp")
        .ok()
        .as_deref()
        .and_then(resolv_conf)
    {
        let _ = std::fs::create_dir_all("/etc");
        let _ = std::fs::write("/etc/resolv.conf", resolv);
    }
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

    #[test]
    fn the_kernels_nameservers_become_a_resolv_conf() {
        let pnp = "#PROTO: MANUAL\nnameserver 1.1.1.1\nnameserver 0.0.0.0\n";
        assert_eq!(resolv_conf(pnp).as_deref(), Some("nameserver 1.1.1.1\n"));
        assert_eq!(resolv_conf("#PROTO: MANUAL\n"), None);
    }

    #[test]
    fn the_backoff_doubles_up_to_a_minute() {
        assert_eq!(next_backoff(Duration::from_secs(2)), Duration::from_secs(4));
        assert_eq!(next_backoff(Duration::from_secs(40)), MAX_BACKOFF);
    }
}
