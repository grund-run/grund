//! The `grund0` TUN device (Linux).
//!
//! [`Tun::create`] opens the device, gives it the machine's address with the
//! network's /48 as its prefix (so the kernel routes every member's /64 to
//! it), sets the MTU to 1280 and brings it up. It needs `CAP_NET_ADMIN`, as
//! the agent has when it runs as root; a rootless machine uses service
//! forwards instead (network.md §6.6, not built).
//!
//! [`Tun::create_in`] makes a replica's own `grund0` inside its container's
//! network namespace (network.md §6.1): its address in the machine's /64 with
//! the network's /48 as prefix, default routes for IPv6 and IPv4 into the
//! device, and [`REPLICA_IPV4`] as its IPv4 source. The agent holds the
//! descriptor, so every packet the replica sends reaches the agent's mesh
//! and nothing is routed by the host. The device is persistent: it outlives
//! the agent, and a restarted agent opens it again by name; it goes when its
//! namespace does.

use std::{
    fs::{File, OpenOptions},
    io,
    net::Ipv6Addr,
    os::fd::{AsRawFd, OwnedFd, RawFd},
};

use anyhow::{Context, bail};
use tokio::io::unix::AsyncFd;

/// The MTU of `grund0`: the IPv6 minimum, which fits every path once split.
pub const MTU: u16 = 1280;

/// An open, configured TUN device.
#[derive(Debug)]
pub struct Tun {
    fd: AsyncFd<File>,
    name: String,
    ifindex: libc::c_int,
}

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;

/// A replica's IPv4 source address inside its namespace: link-local, so it
/// collides with nothing the host routes. The agent's egress stack
/// ([`crate::egress`]) translates its flows to host sockets; nothing sees it
/// on the wire.
pub const REPLICA_IPV4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(169, 254, 77, 2);

#[repr(C)]
struct In6Ifreq {
    addr: libc::in6_addr,
    prefixlen: u32,
    ifindex: libc::c_int,
}

impl Tun {
    /// Creates `name`, with `address/prefix_len`, MTU 1280, up.
    pub fn create(name: &str, address: Ipv6Addr, prefix_len: u8) -> anyhow::Result<Self> {
        let file = open_tun(name)?;
        set_nonblocking(file.as_raw_fd())?;
        let ifindex = configure(name, address, prefix_len)?;
        Ok(Self {
            fd: AsyncFd::new(file)?,
            name: name.to_string(),
            ifindex,
        })
    }

    /// Makes (or opens again) the persistent TUN `name` inside the network
    /// namespace bound at `netns`, with `address/prefix_len`, MTU 1280, up,
    /// and default routes for IPv6 and IPv4 through it with [`REPLICA_IPV4`]
    /// as IPv4 source. Runs on a thread of its own that enters the
    /// namespace and ends; the calling thread's namespace never changes.
    pub fn create_in(
        netns: &std::path::Path,
        name: &str,
        address: Ipv6Addr,
        prefix_len: u8,
    ) -> anyhow::Result<Self> {
        let (netns, name_owned) = (netns.to_path_buf(), name.to_string());
        let made = std::thread::spawn(move || -> anyhow::Result<(File, libc::c_int)> {
            crate::netns::enter(&netns)
                .with_context(|| format!("enter the network namespace {}", netns.display()))?;
            let file = open_tun(&name_owned)?;
            if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETPERSIST as _, 1 as libc::c_ulong) } < 0
            {
                return Err(io::Error::last_os_error()).context("TUNSETPERSIST");
            }
            let ifindex = configure(&name_owned, address, prefix_len)?;
            ignore_exists(add_ipv4(&name_owned, REPLICA_IPV4))?;
            ignore_exists(add_route6_default(ifindex))?;
            ignore_exists(add_route4_default(&name_owned))?;
            Ok((file, ifindex))
        })
        .join()
        .map_err(|_| anyhow::anyhow!("the TUN thread panicked"))??;
        let (file, ifindex) = made;
        set_nonblocking(file.as_raw_fd())?;
        Ok(Self {
            fd: AsyncFd::new(file)?,
            name: name.to_string(),
            ifindex,
        })
    }

    /// Gives the device another address, `address/prefix_len`: the stub
    /// resolver's `::53` beside the machine's `::1`. A TUN device has no
    /// neighbour discovery, so the address is usable at once, with no
    /// duplicate address detection to wait out.
    pub fn add_address(&self, address: Ipv6Addr, prefix_len: u8) -> anyhow::Result<()> {
        add_ipv6(self.ifindex, address, prefix_len)
    }

    /// The device's interface index.
    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    /// The device's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one packet.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|f| {
                raw(unsafe { libc::read(f.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) })
            }) {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes one packet.
    pub async fn write(&self, packet: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|f| {
                raw(unsafe { libc::write(f.as_raw_fd(), packet.as_ptr().cast(), packet.len()) })
            }) {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }
}

fn open_tun(name: &str) -> anyhow::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .context("open /dev/net/tun")?;
    let mut ifr = ifreq(name)?;
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifr).context("TUNSETIFF")?;
    Ok(file)
}

fn configure(name: &str, address: Ipv6Addr, prefix_len: u8) -> anyhow::Result<libc::c_int> {
    let inet = socket(libc::AF_INET)?;
    let mut ifr = ifreq(name)?;
    ifr.ifr_ifru.ifru_mtu = MTU as libc::c_int;
    ioctl(inet.as_raw_fd(), libc::SIOCSIFMTU, &mut ifr).context("SIOCSIFMTU")?;

    let mut ifr = ifreq(name)?;
    ioctl(inet.as_raw_fd(), libc::SIOCGIFINDEX, &mut ifr).context("SIOCGIFINDEX")?;
    let ifindex = unsafe { ifr.ifr_ifru.ifru_ifindex };

    ignore_exists(add_ipv6(ifindex, address, prefix_len))?;

    let mut ifr = ifreq(name)?;
    ioctl(inet.as_raw_fd(), libc::SIOCGIFFLAGS, &mut ifr).context("SIOCGIFFLAGS")?;
    unsafe { ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short };
    ioctl(inet.as_raw_fd(), libc::SIOCSIFFLAGS, &mut ifr).context("SIOCSIFFLAGS")?;
    Ok(ifindex)
}

fn ignore_exists(result: anyhow::Result<()>) -> anyhow::Result<()> {
    match result {
        Err(e)
            if e.downcast_ref::<io::Error>()
                .and_then(io::Error::raw_os_error)
                == Some(libc::EEXIST) =>
        {
            Ok(())
        }
        other => other,
    }
}

fn add_ipv4(name: &str, address: std::net::Ipv4Addr) -> anyhow::Result<()> {
    let inet = socket(libc::AF_INET)?;
    let sockaddr = |a: std::net::Ipv4Addr| {
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_addr.s_addr = u32::from(a).to_be();
        sa
    };
    let mut ifr = ifreq(name)?;
    unsafe {
        *(&mut ifr.ifr_ifru as *mut _ as *mut libc::sockaddr_in) = sockaddr(address);
    }
    ioctl(inet.as_raw_fd(), libc::SIOCSIFADDR, &mut ifr).context("SIOCSIFADDR (IPv4)")?;
    let mut ifr = ifreq(name)?;
    unsafe {
        *(&mut ifr.ifr_ifru as *mut _ as *mut libc::sockaddr_in) =
            sockaddr(std::net::Ipv4Addr::BROADCAST);
    }
    ioctl(inet.as_raw_fd(), libc::SIOCSIFNETMASK, &mut ifr).context("SIOCSIFNETMASK")
}

#[repr(C)]
struct In6Rtmsg {
    dst: libc::in6_addr,
    src: libc::in6_addr,
    gateway: libc::in6_addr,
    rtmsg_type: u32,
    dst_len: u16,
    src_len: u16,
    metric: u32,
    info: libc::c_ulong,
    flags: u32,
    ifindex: libc::c_int,
}

fn add_route6_default(ifindex: libc::c_int) -> anyhow::Result<()> {
    let inet6 = socket(libc::AF_INET6)?;
    let mut rt = In6Rtmsg {
        dst: libc::in6_addr { s6_addr: [0; 16] },
        src: libc::in6_addr { s6_addr: [0; 16] },
        gateway: libc::in6_addr { s6_addr: [0; 16] },
        rtmsg_type: 0,
        dst_len: 0,
        src_len: 0,
        metric: 1,
        info: 0,
        flags: libc::RTF_UP as u32,
        ifindex,
    };
    ioctl(inet6.as_raw_fd(), libc::SIOCADDRT, &mut rt).context("SIOCADDRT (IPv6 default)")
}

fn add_route4_default(name: &str) -> anyhow::Result<()> {
    let inet = socket(libc::AF_INET)?;
    let device = std::ffi::CString::new(name)?;
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    for field in [&mut rt.rt_dst, &mut rt.rt_genmask] {
        let sa = field as *mut libc::sockaddr as *mut libc::sockaddr_in;
        unsafe {
            (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
        }
    }
    rt.rt_flags = libc::RTF_UP;
    rt.rt_dev = device.as_ptr() as *mut libc::c_char;
    ioctl(inet.as_raw_fd(), libc::SIOCADDRT, &mut rt).context("SIOCADDRT (IPv4 default)")
}

fn ifreq(name: &str) -> anyhow::Result<libc::ifreq> {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    if name.is_empty() || name.len() >= ifr.ifr_name.len() {
        bail!("interface name {name:?} must be 1 to 15 bytes");
    }
    for (i, b) in name.bytes().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    Ok(ifr)
}

fn add_ipv6(ifindex: libc::c_int, address: Ipv6Addr, prefix_len: u8) -> anyhow::Result<()> {
    let inet6 = socket(libc::AF_INET6)?;
    let mut req = In6Ifreq {
        addr: libc::in6_addr {
            s6_addr: address.octets(),
        },
        prefixlen: prefix_len as u32,
        ifindex,
    };
    Ok(ioctl(inet6.as_raw_fd(), libc::SIOCSIFADDR, &mut req)?)
}

fn ioctl<T>(fd: RawFd, request: libc::c_ulong, arg: &mut T) -> io::Result<()> {
    if unsafe { libc::ioctl(fd, request as _, arg as *mut T) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn socket(family: libc::c_int) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) })
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn raw(n: isize) -> io::Result<usize> {
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
