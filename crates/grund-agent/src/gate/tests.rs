use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use grund_proto::grund::agent::v1::{Port, Replica, ReplicaState};
use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::*;

#[derive(Default)]
struct Backends {
    addrs: Mutex<HashMap<String, SocketAddr>>,
    stops: Mutex<HashMap<String, CancellationToken>>,
}

impl Dial for Backends {
    fn connect(
        &self,
        replica_id: String,
        _port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send + '_>> {
        let addr = self.addrs.lock().unwrap().get(&replica_id).copied();
        Box::pin(async move {
            match addr {
                Some(addr) => TcpStream::connect(addr).await,
                None => Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            }
        })
    }
}

impl Backends {
    async fn start(&self, id: &str) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = CancellationToken::new();
        self.addrs.lock().unwrap().insert(id.into(), addr);
        self.stops.lock().unwrap().insert(id.into(), stop.clone());
        let id = id.to_string();
        tokio::spawn(async move {
            loop {
                let (stream, _) = tokio::select! {
                    () = stop.cancelled() => return,
                    accepted = listener.accept() => accepted.unwrap(),
                };
                let (id, stop) = (id.clone(), stop.clone());
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                        let id = id.clone();
                        async move {
                            let wait = request
                                .uri()
                                .query()
                                .and_then(|q| q.strip_prefix("wait="))
                                .and_then(|ms| ms.parse().ok())
                                .unwrap_or(0);
                            tokio::time::sleep(Duration::from_millis(wait)).await;
                            let mut seen = format!("{id}\n");
                            for (name, value) in request.headers() {
                                seen.push_str(&format!(
                                    "{name}: {}\n",
                                    value.to_str().unwrap_or("?")
                                ));
                            }
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            seen.push_str(&format!("body: {}\n", body.len()));
                            Ok::<_, std::convert::Infallible>(Response::new(full(seen)))
                        }
                    });
                    let conn = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service);
                    tokio::select! {
                        () = stop.cancelled() => {}
                        _ = conn => {}
                    }
                });
            }
        });
        addr
    }

    fn kill(&self, id: &str) {
        if let Some(stop) = self.stops.lock().unwrap().remove(id) {
            stop.cancel();
        }
    }
}

fn replica(id: &str, app: &str, state: ReplicaState) -> Replica {
    Replica {
        replica_id: id.into(),
        app: app.into(),
        ports: vec![Port {
            name: "web".into(),
            port: 8080,
            protocol: "http".into(),
            public: true,
            ..Default::default()
        }],
        hostnames: vec![
            format!("{app}-kasper.grund.test"),
            format!("{app}.example.com"),
        ],
        state: state.into(),
        ..Default::default()
    }
}

fn document(replicas: Vec<Replica>) -> DesiredState {
    DesiredState {
        replicas,
        entry_keys: vec!["edgekey".into()],
        ..Default::default()
    }
}

fn ready(document: &DesiredState, ready: &[&str]) -> Vec<ReplicaEndpoint> {
    let mut endpoints = endpoints_from(Some(document), &[]);
    for e in &mut endpoints {
        e.ready = ready.contains(&e.replica_id.as_str());
    }
    endpoints
}

async fn connection(gate: &Gate, host: &str) -> hyper::client::conn::http1::SendRequest<Body> {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let gate = gate.clone();
    let host = host.to_string();
    tokio::spawn(async move {
        gate.serve(
            server,
            EntryClient {
                client: "203.0.113.7:4242".into(),
                host,
            },
        )
        .await
    });
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client))
        .await
        .unwrap();
    tokio::spawn(conn);
    sender
}

async fn get(
    sender: &mut hyper::client::conn::http1::SendRequest<Body>,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, String) {
    let mut request = Request::get(path).header("host", host);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = sender
        .send_request(request.body(empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn a_foreign_host_on_a_connection_gets_421_and_reaches_no_copy() {
    let backends = Arc::new(Backends::default());
    backends.start("a1").await;
    backends.start("b1").await;
    let gate = Gate::new(backends.clone(), Limits::default());
    let doc = document(vec![
        replica("a1", "photos", ReplicaState::REPLICA_STATE_RUNNING),
        replica("b1", "blog", ReplicaState::REPLICA_STATE_RUNNING),
    ]);
    gate.update(Some(&doc), &ready(&doc, &["a1", "b1"]), &[]);
    let mut photos = connection(&gate, "photos-kasper.grund.test").await;
    let (status, _, body) = get(&mut photos, "photos-kasper.grund.test", "/", &[]).await;
    assert_eq!((status, body.lines().next()), (StatusCode::OK, Some("a1")));
    let (status, _, body) = get(&mut photos, "photos.example.com", "/", &[]).await;
    assert_eq!(
        (status, body.lines().next()),
        (StatusCode::OK, Some("a1")),
        "a custom domain of the same app"
    );
    let (status, _, body) = get(&mut photos, "blog-kasper.grund.test", "/", &[]).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    assert!(!body.contains("b1") && !body.contains("a1"));
    assert_eq!(gate.stats().misdirected.load(Relaxed), 1);
}

#[tokio::test]
async fn forwarding_headers_from_the_client_are_replaced_and_hop_by_hop_ones_removed() {
    let backends = Arc::new(Backends::default());
    backends.start("a1").await;
    let gate = Gate::new(backends.clone(), Limits::default());
    let doc = document(vec![replica(
        "a1",
        "photos",
        ReplicaState::REPLICA_STATE_RUNNING,
    )]);
    gate.update(Some(&doc), &ready(&doc, &["a1"]), &[]);
    let mut sender = connection(&gate, "photos-kasper.grund.test").await;
    let (status, headers, body) = get(
        &mut sender,
        "photos-kasper.grund.test",
        "/",
        &[
            ("x-forwarded-for", "10.9.9.9"),
            ("forwarded", "for=10.9.9.9"),
            ("x-real-ip", "10.9.9.9"),
            ("x-forwarded-proto", "http"),
            ("connection", "x-secret"),
            ("x-secret", "hop"),
            ("x-request-id", "kept-1"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("10.9.9.9"), "{body}");
    assert!(body.contains("x-forwarded-for: 203.0.113.7\n"), "{body}");
    assert!(body.contains("x-forwarded-proto: https\n"));
    assert!(body.contains("x-forwarded-host: photos-kasper.grund.test\n"));
    assert!(
        body.contains("forwarded: for=203.0.113.7;proto=https;host=photos-kasper.grund.test\n")
    );
    assert!(!body.contains("x-secret"), "{body}");
    assert!(body.contains("x-request-id: kept-1\n"));
    assert_eq!(
        headers[header::STRICT_TRANSPORT_SECURITY],
        "max-age=31536000"
    );
    let (_, headers, body) = get(&mut sender, "photos.example.com", "/", &[]).await;
    assert!(
        !headers.contains_key(header::STRICT_TRANSPORT_SECURITY),
        "custom domains only if the app sets it"
    );
    assert!(body.contains("x-request-id: "));
}

#[tokio::test]
async fn a_killed_copy_costs_no_request_and_is_ejected_at_once() {
    let backends = Arc::new(Backends::default());
    backends.start("a1").await;
    backends.start("a2").await;
    let gate = Gate::new(backends.clone(), Limits::default());
    let doc = document(vec![
        replica("a1", "photos", ReplicaState::REPLICA_STATE_RUNNING),
        replica("a2", "photos", ReplicaState::REPLICA_STATE_RUNNING),
    ]);
    gate.update(Some(&doc), &ready(&doc, &["a1", "a2"]), &[]);
    let mut sender = connection(&gate, "photos-kasper.grund.test").await;
    for _ in 0..20 {
        get(&mut sender, "photos-kasper.grund.test", "/", &[]).await;
    }
    backends.kill("a1");
    backends.addrs.lock().unwrap().remove("a1");
    for _ in 0..50 {
        let (status, _, body) = get(&mut sender, "photos-kasper.grund.test", "/", &[]).await;
        assert_eq!((status, body.lines().next()), (StatusCode::OK, Some("a2")));
    }
    assert!(
        gate.stats().retried.load(Relaxed) <= 2,
        "a reset on the pooled connection and one refused connect, then ejected"
    );
    assert_eq!(gate.stats().failed.load(Relaxed), 0);
}

#[tokio::test]
async fn a_draining_copy_gets_nothing_new_unless_nothing_else_answers_and_reports_idle() {
    let backends = Arc::new(Backends::default());
    backends.start("old").await;
    backends.start("new").await;
    let gate = Gate::new(backends.clone(), Limits::default());
    let doc = document(vec![
        replica("old", "photos", ReplicaState::REPLICA_STATE_RUNNING),
        replica("new", "photos", ReplicaState::REPLICA_STATE_RUNNING),
    ]);
    gate.update(Some(&doc), &ready(&doc, &["old", "new"]), &[]);
    let mut sender = connection(&gate, "photos-kasper.grund.test").await;
    let slow = {
        let gate = gate.clone();
        tokio::spawn(async move {
            let mut sender = connection(&gate, "photos-kasper.grund.test").await;
            let mut seen = Vec::new();
            for _ in 0..8 {
                seen.push(
                    get(&mut sender, "photos-kasper.grund.test", "/?wait=300", &[])
                        .await
                        .2,
                );
            }
            seen
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let draining = document(vec![
        replica("old", "photos", ReplicaState::REPLICA_STATE_DRAINING),
        replica("new", "photos", ReplicaState::REPLICA_STATE_RUNNING),
    ]);
    gate.update(Some(&draining), &ready(&draining, &["old", "new"]), &[]);
    for _ in 0..20 {
        let (_, _, body) = get(&mut sender, "photos-kasper.grund.test", "/", &[]).await;
        assert_eq!(body.lines().next(), Some("new"));
    }
    slow.await.unwrap();
    assert_eq!(gate.idle(Some(&draining)), vec!["old".to_string()]);
    let only_old = document(vec![replica(
        "old",
        "photos",
        ReplicaState::REPLICA_STATE_DRAINING,
    )]);
    gate.update(Some(&only_old), &ready(&only_old, &["old"]), &[]);
    let (_, _, body) = get(&mut sender, "photos-kasper.grund.test", "/", &[]).await;
    assert_eq!(body.lines().next(), Some("old"), "the draining fallback");
    assert!(matches!(
        gate.admit("photos-kasper.grund.test"),
        grund_entry::Answer::Accept { ready: 0 }
    ));
}

#[tokio::test]
async fn with_no_ready_copy_here_a_ready_copy_elsewhere_serves_and_the_client_is_asked_to_reconnect()
 {
    let backends = Arc::new(Backends::default());
    let remote = Backends::default();
    let remote_addr = remote.start("r1").await;
    let gate = Gate::new(backends.clone(), Limits::default());
    let doc = document(vec![replica(
        "a1",
        "photos",
        ReplicaState::REPLICA_STATE_RUNNING,
    )]);
    let with_port = |port| RemoteCopy {
        replica_id: "r1".into(),
        app: "photos".into(),
        machine_id: "m2".into(),
        address: remote_addr.ip(),
        ports: vec![port],
        ready: true,
    };
    let mut doc_on_port = doc.clone();
    doc_on_port.replicas[0].ports[0].port = u32::from(remote_addr.port());
    gate.update(
        Some(&doc_on_port),
        &ready(&doc_on_port, &[]),
        &[with_port(remote_addr.port())],
    );
    assert_eq!(
        gate.admit("photos-kasper.grund.test"),
        grund_entry::Answer::NoReadyCopy
    );
    assert_eq!(
        gate.admit("blog-kasper.grund.test"),
        grund_entry::Answer::NotPlacedHere
    );
    let mut sender = connection(&gate, "photos-kasper.grund.test").await;
    let (status, headers, body) = get(&mut sender, "photos-kasper.grund.test", "/", &[]).await;
    assert_eq!((status, body.lines().next()), (StatusCode::OK, Some("r1")));
    assert_eq!(headers[header::CONNECTION], "close");
    gate.update(Some(&doc), &ready(&doc, &[]), &[]);
    let mut sender = connection(&gate, "photos-kasper.grund.test").await;
    let (status, _, _) = get(&mut sender, "photos-kasper.grund.test", "/", &[]).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_draining_gate_refuses_new_streams_and_lets_in_flight_requests_finish() {
    let backends = Arc::new(Backends::default());
    backends.start("a1").await;
    let gate = Gate::new(backends.clone(), Limits::default());
    let doc = document(vec![replica(
        "a1",
        "photos",
        ReplicaState::REPLICA_STATE_RUNNING,
    )]);
    gate.update(Some(&doc), &ready(&doc, &["a1"]), &[]);
    assert!(gate.is_entry_key("EDGEKEY") && !gate.is_entry_key("stranger"));
    let mut sender = connection(&gate, "photos-kasper.grund.test").await;
    let in_flight = tokio::spawn(async move {
        get(&mut sender, "photos-kasper.grund.test", "/?wait=500", &[])
            .await
            .0
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    gate.drain().await;
    assert_eq!(in_flight.await.unwrap(), StatusCode::OK);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(
        gate.admit("photos-kasper.grund.test"),
        grund_entry::Answer::Draining
    );
}

#[tokio::test]
async fn a_body_up_to_the_retry_buffer_is_retried_and_a_websocket_upgrade_passes_through() {
    let backends = Arc::new(Backends::default());
    backends.start("a2").await;
    let gate = Gate::new(backends.clone(), Limits::default());
    let doc = document(vec![
        replica("a1", "photos", ReplicaState::REPLICA_STATE_RUNNING),
        replica("a2", "photos", ReplicaState::REPLICA_STATE_RUNNING),
    ]);
    gate.update(Some(&doc), &ready(&doc, &["a1", "a2"]), &[]);
    let mut sender = connection(&gate, "photos-kasper.grund.test").await;
    for _ in 0..10 {
        let request = Request::post("/")
            .header("host", "photos-kasper.grund.test")
            .body(full(vec![7u8; 1000]))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("body: 1000"));
    }

    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    backends
        .addrs
        .lock()
        .unwrap()
        .insert("ws".into(), echo.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut head = vec![0u8; 4096];
        let n = stream.read(&mut head).await.unwrap();
        assert!(
            String::from_utf8_lossy(&head[..n])
                .to_ascii_lowercase()
                .contains("upgrade: websocket")
        );
        stream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(&buf).await.unwrap();
    });
    let ws_doc = document(vec![replica(
        "ws",
        "chat",
        ReplicaState::REPLICA_STATE_RUNNING,
    )]);
    gate.update(Some(&ws_doc), &ready(&ws_doc, &["ws"]), &[]);
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let serving = gate.clone();
    tokio::spawn(async move {
        serving
            .serve(
                server,
                EntryClient {
                    client: "203.0.113.7:1".into(),
                    host: "chat-kasper.grund.test".into(),
                },
            )
            .await
    });
    client
        .write_all(b"GET /ws HTTP/1.1\r\nhost: chat-kasper.grund.test\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n")
        .await
        .unwrap();
    let mut head = vec![0u8; 1024];
    let n = client.read(&mut head).await.unwrap();
    assert!(
        String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head[..n])
    );
    client.write_all(b"hello").await.unwrap();
    let mut echoed = [0u8; 5];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"hello");
}

#[test]
fn hosts_are_read_without_port_or_case_and_hop_by_hop_headers_named_in_connection_go() {
    let request = Request::get("/")
        .header("host", "Photos-Kasper.grund.test:443")
        .body(())
        .unwrap();
    assert_eq!(
        request_host(&request).as_deref(),
        Some("photos-kasper.grund.test")
    );
    let request = Request::get("https://blog.example.com/x").body(()).unwrap();
    assert_eq!(request_host(&request).as_deref(), Some("blog.example.com"));
    let mut headers = HeaderMap::new();
    headers.insert(
        "connection",
        HeaderValue::from_static("keep-alive, x-private"),
    );
    headers.insert("x-private", HeaderValue::from_static("1"));
    headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
    headers.insert("upgrade", HeaderValue::from_static("websocket"));
    headers.insert("x-kept", HeaderValue::from_static("1"));
    let mut kept = headers.clone();
    strip_hop_by_hop(&mut headers, false);
    assert_eq!(headers.len(), 1);
    strip_hop_by_hop(&mut kept, true);
    assert_eq!(kept["upgrade"], "websocket");
    assert_eq!(kept["connection"], "upgrade");
    let mut v6 = HeaderMap::new();
    set_forwarding(&mut v6, "[2001:db8::7]:443", "a.example.com");
    assert_eq!(v6["x-forwarded-for"], "2001:db8::7");
    assert_eq!(
        v6["forwarded"],
        "for=\"[2001:db8::7]\";proto=https;host=a.example.com"
    );
}
