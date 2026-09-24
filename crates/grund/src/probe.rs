//! `grund probe`: a readiness check for container health checks.
//!
//! The image is `scratch`, with no shell and no curl, so compose cannot probe
//! it any other way. One plain HTTP/1.1 GET to a local address, bounded by a
//! timeout; anything but a 200 is a failure.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use anyhow::Context;

#[derive(clap::Args)]
pub struct ProbeArgs {
    /// Address of the instance to probe.
    #[arg(long, default_value = "127.0.0.1:8080")]
    address: SocketAddr,

    /// Path that must answer 200.
    #[arg(long, default_value = "/health/ready")]
    path: String,
}

pub fn run(args: &ProbeArgs) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&args.address, timeout)
        .with_context(|| format!("connect to {}", args.address))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: grund-probe\r\n\r\n",
        args.path, args.address
    )?;
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).context("read status line")?;
    // "HTTP/1.1 200"
    anyhow::ensure!(
        &head[9..12] == b"200",
        "{} answered {}",
        args.path,
        String::from_utf8_lossy(&head[9..12])
    );
    Ok(())
}
