//! The `grund0` TUN device (Linux).
//!
//! [`Tun::create`] opens the device, gives it the machine's address with the
//! network's /48 as its prefix (so the kernel routes every member's /64 to
//! it), sets the MTU to 1280 and brings it up. It needs `CAP_NET_ADMIN`, as
//! the agent has when it runs as root; a rootless machine uses service
//! forwards instead (network.md §6.6, not built).

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
}

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[repr(C)]
struct In6Ifreq {
    addr: libc::in6_addr,
    prefixlen: u32,
    ifindex: libc::c_int,
}

impl Tun {
    /// Creates `name`, with `address/prefix_len`, MTU 1280, up.
    pub fn create(name: &str, address: Ipv6Addr, prefix_len: u8) -> anyhow::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .context("open /dev/net/tun")?;
        let mut ifr = ifreq(name)?;
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifr).context("TUNSETIFF")?;
        set_nonblocking(file.as_raw_fd())?;

        let inet = socket(libc::AF_INET)?;
        let mut ifr = ifreq(name)?;
        ifr.ifr_ifru.ifru_mtu = MTU as libc::c_int;
        ioctl(inet.as_raw_fd(), libc::SIOCSIFMTU, &mut ifr).context("SIOCSIFMTU")?;

        let mut ifr = ifreq(name)?;
        ioctl(inet.as_raw_fd(), libc::SIOCGIFINDEX, &mut ifr).context("SIOCGIFINDEX")?;
        let ifindex = unsafe { ifr.ifr_ifru.ifru_ifindex };

        let inet6 = socket(libc::AF_INET6)?;
        let mut req = In6Ifreq {
            addr: libc::in6_addr {
                s6_addr: address.octets(),
            },
            prefixlen: prefix_len as u32,
            ifindex,
        };
        ioctl(inet6.as_raw_fd(), libc::SIOCSIFADDR, &mut req).context("SIOCSIFADDR (IPv6)")?;

        let mut ifr = ifreq(name)?;
        ioctl(inet.as_raw_fd(), libc::SIOCGIFFLAGS, &mut ifr).context("SIOCGIFFLAGS")?;
        unsafe { ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short };
        ioctl(inet.as_raw_fd(), libc::SIOCSIFFLAGS, &mut ifr).context("SIOCSIFFLAGS")?;

        Ok(Self {
            fd: AsyncFd::new(file)?,
            name: name.to_string(),
        })
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
