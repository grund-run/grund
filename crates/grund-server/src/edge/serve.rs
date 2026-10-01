//! What an edge does with each connection (grund-docs design/traffic.md
//! §6.1, §6.2, §6.3, §13).
//!
//! On 443, for every TCP connection: rustls reads the whole ClientHello
//! however many segments carry it, and only then is the name known
//! (§6.2); the handshake finishes with that name's certificate; a machine
//! that runs the app is picked, an entry stream opened, the header sent and
//! the gate's answer awaited; then bytes are copied both ways. A refusal or
//! no answer is tried on the next machine: nothing reached an app. A
//! suspended address gets a fixed 451 page, and an address no machine takes
//! a 503, both without a stream. The edge never parses HTTP it passes on.
//!
//! Per source address: at most 256 open connections and 50 new handshakes a
//! second (§13). On 80: a 308 to https, path and query kept.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, atomic::Ordering::Relaxed},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Incoming, header};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use super::{
    machines::{Machine, Pool},
    routes::Routes,
};

/// How long a client has to finish its TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// What the edge allows one source address.
#[derive(Debug, Clone, Copy)]
pub struct PerAddress {
    pub connections: usize,
    pub handshakes_per_second: f64,
}

#[derive(Debug, Default)]
struct Bucket {
    tokens: f64,
    at: Option<Instant>,
}

/// Per-source limits, in this process.
#[derive(Debug)]
pub struct Admission {
    limits: PerAddress,
    open: Mutex<HashMap<IpAddr, usize>>,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

/// An admitted connection; its slot frees when dropped.
pub struct Admitted<'a> {
    admission: &'a Admission,
    ip: IpAddr,
}

impl Drop for Admitted<'_> {
    fn drop(&mut self) {
        let mut open = self.admission.open.lock().expect("admission lock");
        if let Some(n) = open.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                open.remove(&self.ip);
            }
        }
    }
}

impl Admission {
    pub fn new(limits: PerAddress) -> Self {
        Self {
            limits,
            open: Mutex::new(HashMap::new()),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Admits a new connection from `ip`, or refuses it.
    pub fn admit(&self, ip: IpAddr, now: Instant) -> Option<Admitted<'_>> {
        let mut open = self.open.lock().expect("admission lock");
        if open.get(&ip).is_some_and(|n| *n >= self.limits.connections) {
            return None;
        }
        {
            let mut buckets = self.buckets.lock().expect("admission lock");
            if buckets.len() > 100_000 {
                buckets.retain(|_, b| {
                    b.at.is_some_and(|at| now.duration_since(at) < Duration::from_secs(10))
                });
            }
            let bucket = buckets.entry(ip).or_default();
            let rate = self.limits.handshakes_per_second;
            let elapsed = bucket
                .at
                .map_or(1.0, |at| now.duration_since(at).as_secs_f64());
            bucket.tokens = (bucket.tokens + elapsed * rate).min(rate);
            bucket.at = Some(now);
            if bucket.tokens < 1.0 {
                return None;
            }
            bucket.tokens -= 1.0;
        }
        *open.entry(ip).or_insert(0) += 1;
        Some(Admitted {
            admission: self,
            ip,
        })
    }
}

type Counts = HashMap<(String, &'static str), (u64, u64, u64)>;

/// Entry bytes per address and path since the last report.
#[derive(Debug, Default)]
pub struct Meter {
    counts: Mutex<Counts>,
}

impl Meter {
    pub fn add(&self, name: &str, relayed: bool, bytes_in: u64, bytes_out: u64) {
        let path = if relayed { "relay" } else { "direct" };
        let mut counts = self.counts.lock().expect("meter lock");
        let entry = counts.entry((name.to_string(), path)).or_default();
        entry.0 += bytes_in;
        entry.1 += bytes_out;
        entry.2 += 1;
    }

    /// Everything counted, emptied.
    pub fn take(&self) -> Vec<(String, &'static str, u64, u64, u64)> {
        std::mem::take(&mut *self.counts.lock().expect("meter lock"))
            .into_iter()
            .map(|((name, path), (i, o, c))| (name, path, i, o, c))
            .collect()
    }
}

/// What every connection shares.
pub struct Edge {
    pub routes: Routes,
    pub pool: Pool,
    pub tls: Arc<rustls::ServerConfig>,
    pub host: String,
    pub admission: Admission,
    pub meter: Meter,
}

async fn page<I>(io: I, status: StatusCode, words: &'static str)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |_: Request<Incoming>| async move {
        let mut response = Response::new(Full::new(Bytes::from_static(words.as_bytes())));
        *response.status_mut() = status;
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        headers.insert(
            header::CONNECTION,
            header::HeaderValue::from_static("close"),
        );
        Ok::<_, std::convert::Infallible>(response)
    });
    let _ = tokio::time::timeout(
        Duration::from_secs(30),
        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(io), service),
    )
    .await;
}

/// Serves one TCP connection on 443.
pub async fn connection(edge: Arc<Edge>, tcp: TcpStream, peer: SocketAddr) {
    let Some(_admitted) = edge.admission.admit(peer.ip(), Instant::now()) else {
        return;
    };
    let _ = tcp.set_nodelay(true);
    let accepting = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp);
    let Ok(Ok(start)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting).await else {
        return;
    };
    let hello = start.client_hello();
    let Some(name) = hello
        .server_name()
        .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
    else {
        return;
    };
    let validator = hello
        .alpn()
        .is_some_and(|mut p| p.any(|p| p == grund_tls::ACME_TLS_ALPN));
    let route = edge.routes.current().get(&name);
    if route.is_none() && name != edge.host && !validator {
        return;
    }
    let Ok(Ok(tls)) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, start.into_stream(edge.tls.clone())).await
    else {
        return;
    };
    if validator {
        return;
    }
    let Some(route) = route else {
        page(tls, StatusCode::OK, "grund edge\n").await;
        return;
    };
    if route.suspended {
        page(
            tls,
            StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            "This address is suspended.\n",
        )
        .await;
        return;
    }
    let (_, session) = tls.get_ref();
    let header = grund_entry::Header {
        host: name.clone(),
        alpn: session
            .alpn_protocol()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .unwrap_or_else(|| "http/1.1".into()),
        client: peer.to_string(),
        tls: grund_entry::Tls {
            version: session
                .protocol_version()
                .map(|v| format!("{v:?}"))
                .unwrap_or_default(),
            cipher: session
                .negotiated_cipher_suite()
                .map(|c| format!("{:?}", c.suite()))
                .unwrap_or_default(),
        },
    };
    let Ok(header) = header.encode() else {
        return;
    };
    for machine in edge.pool.order(&name, &route.machines) {
        match hand_over(&edge.pool, &machine, &name, &header).await {
            Some((send, recv, relayed)) => {
                machine.streams.fetch_add(1, Relaxed);
                let mut client = tls;
                let mut stream = tokio::io::join(recv, send);
                let copied = tokio::io::copy_bidirectional(&mut client, &mut stream).await;
                machine.streams.fetch_sub(1, Relaxed);
                let (bytes_in, bytes_out) = copied.unwrap_or((0, 0));
                edge.meter.add(&name, relayed, bytes_in, bytes_out);
                return;
            }
            None => continue,
        }
    }
    page(
        tls,
        StatusCode::SERVICE_UNAVAILABLE,
        "No machine is serving this app right now. Try again in a moment.\n",
    )
    .await;
}

async fn hand_over(
    pool: &Pool,
    machine: &Machine,
    name: &str,
    header: &[u8],
) -> Option<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream, bool)> {
    let connection = match pool.connection(machine).await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::debug!(machine = %machine.endpoint_id, %error, "edge: machine unreachable");
            machine.eject_all();
            return None;
        }
    };
    let Ok((mut send, mut recv)) = Pool::open(&connection).await else {
        machine.eject_all();
        return None;
    };
    if send.write_all(header).await.is_err() {
        machine.eject_all();
        return None;
    }
    let answer = tokio::time::timeout(
        Pool::answer_timeout(&connection),
        grund_entry::read_answer(&mut recv),
    )
    .await;
    match answer {
        Ok(Ok(grund_entry::Answer::Accept { ready })) => {
            machine.accepted(name, ready);
            Some((send, recv, Machine::relayed(&connection)))
        }
        Ok(Ok(refusal)) => {
            tracing::debug!(machine = %machine.endpoint_id, %name, answer = refusal.word(), "edge: the gate refused");
            machine.eject(name);
            None
        }
        _ => {
            tracing::debug!(machine = %machine.endpoint_id, %name, "edge: the gate did not answer in time");
            machine.eject(name);
            None
        }
    }
}

/// Answers port 80: a 308 to the same address over https, path and query
/// kept. HTTP-01 for custom domains is not built, so every
/// `/.well-known/acme-challenge/` request is a 404.
pub async fn http(tcp: TcpStream) {
    let service = hyper::service::service_fn(|request: Request<Incoming>| async move {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.parse::<hyper::http::uri::Authority>().ok())
            .map(|a| a.host().to_ascii_lowercase());
        let path = request
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let mut response = Response::new(Full::new(Bytes::new()));
        match host {
            _ if path.starts_with("/.well-known/acme-challenge/") => {
                *response.status_mut() = StatusCode::NOT_FOUND;
            }
            Some(host) => {
                *response.status_mut() = StatusCode::PERMANENT_REDIRECT;
                if let Ok(location) =
                    header::HeaderValue::from_str(&format!("https://{host}{path}"))
                {
                    response.headers_mut().insert(header::LOCATION, location);
                }
            }
            None => *response.status_mut() = StatusCode::BAD_REQUEST,
        }
        Ok::<_, std::convert::Infallible>(response)
    });
    let _ = tokio::time::timeout(
        Duration::from_secs(30),
        hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(Duration::from_secs(10))
            .serve_connection(TokioIo::new(tcp), service),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_gets_its_connections_and_handshake_rate_and_no_more() {
        let admission = Admission::new(PerAddress {
            connections: 3,
            handshakes_per_second: 5.0,
        });
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let now = Instant::now();
        let held: Vec<_> = (0..3).filter_map(|_| admission.admit(ip, now)).collect();
        assert_eq!(held.len(), 3);
        assert!(
            admission.admit(ip, now).is_none(),
            "the fourth open connection"
        );
        assert!(
            admission
                .admit("203.0.113.10".parse().unwrap(), now)
                .is_some(),
            "another source"
        );
        drop(held);
        let burst = (0..10)
            .filter(|_| admission.admit(ip, now).is_some())
            .count();
        assert_eq!(burst, 2, "five handshakes a second, three spent");
        assert!(
            admission.admit(ip, now + Duration::from_secs(1)).is_some(),
            "refilled"
        );
    }

    #[test]
    fn the_meter_counts_by_address_and_path_and_empties() {
        let meter = Meter::default();
        meter.add("a.grund.run", true, 10, 100);
        meter.add("a.grund.run", true, 1, 1);
        meter.add("a.grund.run", false, 5, 5);
        let mut taken = meter.take();
        taken.sort();
        assert_eq!(
            taken,
            vec![
                ("a.grund.run".to_string(), "direct", 5, 5, 1),
                ("a.grund.run".to_string(), "relay", 11, 101, 2)
            ]
        );
        assert!(meter.take().is_empty());
    }
}
