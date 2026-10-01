//! IPv4-only apps on grund's IPv6 private network (grund-docs
//! design/network.md §6.6): many images listen on `0.0.0.0` only (nginx's
//! default, among others), which an IPv6 address never reaches. For such a
//! replica the agent listens on `[replica address]:port` inside the
//! replica's own network namespace and relays each connection to
//! `127.0.0.1:port` there, so the app is reachable by name and address, as
//! one listening on `[::]` is.
//!
//! A port is forwarded only when nothing holds it on IPv6: binding the
//! replica's own address fails while the app listens on `[::]`, and then
//! the app answers for itself. Binding a specific IPv6 address never
//! collides with an IPv4 listener. The app sees its clients as `127.0.0.1`,
//! as behind any proxy. The forward lives as long as the replica's network
//! (`apps` detaches it with the replica).

use std::{
    net::{Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use tokio::task::JoinHandle;

/// How long the relay's connection to the app inside the namespace may
/// take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// One forwarded port of one replica; dropping it stops listening.
#[derive(Debug)]
pub struct Forward {
    pub port: u16,
    task: JoinHandle<()>,
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Why a port was not forwarded.
#[derive(Debug, PartialEq, Eq)]
pub enum NotForwarded {
    /// Something already listens on the port over IPv6: the app itself.
    Taken,
    /// The namespace or the socket refused, with why.
    Failed(String),
}

/// Listens on `[address]:port` inside the namespace at `netns` and relays
/// each connection to `127.0.0.1:port` there.
pub async fn start(netns: PathBuf, address: Ipv6Addr, port: u16) -> Result<Forward, NotForwarded> {
    let bind_in = netns.clone();
    let listener = tokio::task::spawn_blocking(move || {
        std::thread::scope(|scope| {
            scope
                .spawn(move || -> std::io::Result<std::net::TcpListener> {
                    grund_net::netns::enter(&bind_in)?;
                    let listener = std::net::TcpListener::bind(SocketAddr::from((address, port)))?;
                    listener.set_nonblocking(true)?;
                    Ok(listener)
                })
                .join()
                .unwrap_or_else(|_| Err(std::io::Error::other("the bind thread panicked")))
        })
    })
    .await
    .map_err(|e| NotForwarded::Failed(e.to_string()))?
    .map_err(|e| match e.kind() {
        std::io::ErrorKind::AddrInUse => NotForwarded::Taken,
        _ => NotForwarded::Failed(e.to_string()),
    })?;
    let listener = tokio::net::TcpListener::from_std(listener)
        .map_err(|e| NotForwarded::Failed(e.to_string()))?;
    let task = tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let netns = netns.clone();
            tokio::spawn(async move {
                let Ok(mut app) = crate::probe::connect(netns, port, CONNECT_TIMEOUT).await else {
                    return;
                };
                let _ = client.set_nodelay(true);
                let _ = tokio::io::copy_bidirectional(&mut client, &mut app).await;
            });
        }
    });
    Ok(Forward { port, task })
}
