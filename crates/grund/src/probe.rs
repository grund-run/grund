use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use anyhow::Context;

#[derive(clap::Args)]
pub struct ProbeArgs {
    #[arg(
        long,
        default_value = "127.0.0.1:8080",
        help = "Address of the instance to probe"
    )]
    address: SocketAddr,

    #[arg(
        long,
        default_value = "/health/ready",
        help = "Path that must answer 200"
    )]
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
    anyhow::ensure!(
        &head[9..12] == b"200",
        "{} answered {}",
        args.path,
        String::from_utf8_lossy(&head[9..12])
    );
    Ok(())
}
