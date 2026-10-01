//! Readiness checks (grund-docs design/apps.md §8.1): a TCP connect, or an
//! HTTP/1.1 `GET` whose status must be 2xx or 3xx. A failure says why in a
//! few words, for the user.
//!
//! A replica with an address on the private network is checked there, from
//! the machine ([`run_at`]): the check takes the path its peers take, so
//! ready means reachable. A replica without one (a machine on no network) is
//! checked on `127.0.0.1` inside its own network namespace ([`run`]), from a
//! thread of its own that enters the namespace and ends, so no other
//! thread's namespace changes.

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::runtime::Probe;

/// Runs `probe` within `timeout`, from the network namespace at `netns`
/// (this thread's own when `None`).
pub async fn run(netns: Option<PathBuf>, probe: Probe, timeout: Duration) -> Result<(), String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("grund-probe".into())
        .spawn(move || {
            let result = match &netns {
                Some(path) => grund_net::netns::enter(path)
                    .map_err(|e| format!("cannot enter the container's network namespace: {e}")),
                None => Ok(()),
            }
            .and_then(|()| check(&probe, timeout));
            let _ = tx.send(result);
        })
        .map_err(|e| format!("cannot start a probe: {e}"))?;
    match tokio::time::timeout(timeout + Duration::from_secs(1), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("the probe ended without an answer".into()),
        Err(_) => Err(format!("no answer within {} ms", timeout.as_millis())),
    }
}

/// Opens a TCP connection to `127.0.0.1:port` inside the network namespace
/// at `netns`, for the gate (grund-docs design/traffic.md §7.4): a thread
/// enters the namespace, connects, and ends, and the socket stays in the
/// namespace it was made in. This is how the gate reaches a container whose
/// namespace has loopback only; with an address of its own, the runtime
/// connects to that from the host instead.
pub async fn connect(
    netns: PathBuf,
    port: u16,
    timeout: Duration,
) -> std::io::Result<tokio::net::TcpStream> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("grund-connect".into())
        .spawn(move || {
            let result = grund_net::netns::enter(&netns).and_then(|()| {
                let stream = TcpStream::connect_timeout(
                    &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                    timeout,
                )?;
                stream.set_nodelay(true)?;
                stream.set_nonblocking(true)?;
                Ok(stream)
            });
            let _ = tx.send(result);
        })?;
    let stream = tokio::time::timeout(timeout + Duration::from_secs(1), rx)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no connection in time"))?
        .map_err(|_| std::io::Error::other("the connecting thread ended without an answer"))??;
    tokio::net::TcpStream::from_std(stream)
}

/// Runs `probe` against `ip` within `timeout`, from this machine.
pub async fn run_at(ip: IpAddr, probe: Probe, timeout: Duration) -> Result<(), String> {
    let checked = tokio::task::spawn_blocking(move || check_at(ip, &probe, timeout));
    match tokio::time::timeout(timeout + Duration::from_secs(1), checked).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("the probe ended without an answer".into()),
        Err(_) => Err(format!("no answer within {} ms", timeout.as_millis())),
    }
}

/// The check itself on `127.0.0.1`, in the calling thread's namespace.
pub fn check(probe: &Probe, timeout: Duration) -> Result<(), String> {
    check_at(IpAddr::V4(Ipv4Addr::LOCALHOST), probe, timeout)
}

/// The check itself, against `ip`.
pub fn check_at(ip: IpAddr, probe: &Probe, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let port = match probe {
        Probe::Http { port, .. } | Probe::Tcp { port } => *port,
    };
    let address = SocketAddr::from((ip, port));
    let mut stream = TcpStream::connect_timeout(&address, timeout).map_err(|e| match e.kind() {
        std::io::ErrorKind::ConnectionRefused => format!("connection refused on port {port}"),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            format!("no answer on port {port} within {} ms", timeout.as_millis())
        }
        _ => format!("cannot connect to port {port}: {e}"),
    })?;
    let Probe::Http { path, .. } = probe else {
        return Ok(());
    };
    if !path.starts_with('/') || path.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(format!(
            "the check's path {path:?} is not an absolute URL path"
        ));
    }
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1));
    stream
        .set_write_timeout(Some(remaining))
        .and_then(|()| stream.set_read_timeout(Some(remaining)))
        .map_err(|e| format!("port {port}: {e}"))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: grund-agent\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("cannot send the request on port {port}: {e}"))?;
    let mut head = Vec::with_capacity(256);
    let mut buf = [0u8; 512];
    while !head.windows(2).any(|w| w == b"\r\n") {
        if head.len() > 8192 {
            return Err(format!("no HTTP status line on port {port}"));
        }
        match stream.read(&mut buf) {
            Ok(0) => {
                return Err(format!(
                    "port {port} closed the connection without an HTTP response"
                ));
            }
            Ok(n) => head.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(format!(
                    "no HTTP response on port {port} within {} ms",
                    timeout.as_millis()
                ));
            }
            Err(e) => return Err(format!("port {port}: {e}")),
        }
    }
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    status(&String::from_utf8_lossy(&head[..line_end]), port)
}

/// Whether an HTTP status line passes: 2xx and 3xx do.
pub fn status(line: &str, port: u16) -> Result<(), String> {
    let mut parts = line.split(' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().and_then(|c| c.parse::<u16>().ok());
    match code {
        Some(code) if version.starts_with("HTTP/") && (200..400).contains(&code) => Ok(()),
        Some(code) if version.starts_with("HTTP/") => Err(format!("status {code}")),
        _ => Err(format!("not an HTTP response on port {port}")),
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    fn serve_once(reply: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(reply);
        });
        port
    }

    #[test]
    fn status_lines_pass_on_2xx_and_3xx_only() {
        assert_eq!(status("HTTP/1.1 200 OK", 1), Ok(()));
        assert_eq!(status("HTTP/1.0 302 Found", 1), Ok(()));
        assert_eq!(status("HTTP/1.1 204", 1), Ok(()));
        assert_eq!(
            status("HTTP/1.1 502 Bad Gateway", 1),
            Err("status 502".into())
        );
        assert_eq!(
            status("HTTP/1.1 404 Not Found", 1),
            Err("status 404".into())
        );
        assert_eq!(
            status("SSH-2.0-OpenSSH", 22),
            Err("not an HTTP response on port 22".into())
        );
    }

    #[tokio::test]
    async fn an_http_check_reads_the_status_and_a_tcp_check_only_connects() {
        let ok = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let probe = Probe::Http {
            port: ok,
            path: "/healthz".into(),
        };
        assert_eq!(run(None, probe, Duration::from_secs(2)).await, Ok(()));
        let bad = serve_once(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        let probe = Probe::Http {
            port: bad,
            path: "/".into(),
        };
        assert_eq!(
            run(None, probe, Duration::from_secs(2)).await,
            Err("status 502".into())
        );
        let tcp = serve_once(b"");
        assert_eq!(
            run(None, Probe::Tcp { port: tcp }, Duration::from_secs(2)).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn a_closed_port_is_refused_and_a_silent_one_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(
            run(None, Probe::Tcp { port: closed }, Duration::from_secs(1)).await,
            Err(format!("connection refused on port {closed}"))
        );
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = silent.local_addr().unwrap().port();
        let probe = Probe::Http {
            port,
            path: "/".into(),
        };
        let error = run(None, probe, Duration::from_millis(200))
            .await
            .unwrap_err();
        assert_eq!(
            error,
            format!("no HTTP response on port {port} within 200 ms")
        );
        drop(silent);
    }

    #[tokio::test]
    async fn a_path_that_could_smuggle_a_header_is_refused() {
        let port = serve_once(b"HTTP/1.1 200 OK\r\n\r\n");
        let probe = Probe::Http {
            port,
            path: "/x HTTP/1.1\r\nX: y".into(),
        };
        let error = run(None, probe, Duration::from_secs(1)).await.unwrap_err();
        assert!(error.contains("not an absolute URL path"), "{error}");
    }
}
