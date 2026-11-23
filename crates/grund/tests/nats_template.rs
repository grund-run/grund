mod template_support;

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use grund_config::stack::TemplateSettings;
use grund_domain::app::templates;
use serde_json::{Value, json};
use template_support::{Fixture, Mount};
use uuid::Uuid;

#[test]
#[ignore = "requires Linux bridge access, Docker, and the catalogue's pinned NATS image already provisioned locally"]
fn jetstream_authenticates_and_keeps_file_messages_after_copy_recreation() {
    let settings = TemplateSettings {
        jetstream: true,
        ..TemplateSettings::default()
    };
    let template = templates::resolve("nats", Some(&settings)).expect("JetStream template exists");
    let mut fixture = Fixture::new(template, &[]);
    fixture.start(Some(Mount::Writable));
    fixture.wait_until_ready();
    assert_store_bounds(&fixture);
    assert_authentication_required(&fixture);

    let mut client = authenticated(&fixture);
    let created = client.request(
        "$JS.API.STREAM.CREATE.GRUND_ACCEPTANCE",
        &json!({
            "name": "GRUND_ACCEPTANCE",
            "subjects": ["grund.acceptance.events"],
            "storage": "file",
            "retention": "limits",
            "max_msgs": 100,
            "max_bytes": 1048576,
            "max_age": 3600000000000_u64,
            "max_msgs_per_subject": 100,
            "max_msg_size": 1024,
            "max_consumers": 1,
            "duplicate_window": 60000000000_u64
        })
        .to_string(),
    );
    assert_eq!(created["config"]["storage"], "file");
    let marker = Uuid::new_v4().simple().to_string();
    let published = client.request("grund.acceptance.events", &marker);
    assert_eq!(published["stream"], "GRUND_ACCEPTANCE");
    assert_eq!(published["seq"], 1);
    assert_message(&mut client, &marker);
    drop(client);

    fixture.remove_copy();
    fixture.start(Some(Mount::Writable));
    fixture.wait_until_ready();
    assert_store_bounds(&fixture);
    assert_authentication_required(&fixture);
    assert_message(&mut authenticated(&fixture), &marker);
}

#[test]
#[ignore = "requires Docker and the catalogue's pinned NATS image already provisioned locally"]
fn jetstream_refuses_a_missing_or_read_only_owned_volume() {
    let settings = TemplateSettings {
        jetstream: true,
        ..TemplateSettings::default()
    };
    for mount in [None, Some(Mount::ReadOnly)] {
        let template =
            templates::resolve("nats", Some(&settings)).expect("JetStream template exists");
        let mut fixture = Fixture::new(template, &[]);
        fixture.start(mount);
        fixture.assert_startup_refused();
    }
}

#[test]
#[ignore = "requires Docker and the catalogue's pinned NATS image already provisioned locally"]
fn jetstream_refuses_either_missing_store_bound() {
    let settings = TemplateSettings {
        jetstream: true,
        ..TemplateSettings::default()
    };
    for bound in ["NATS_MAX_MEM", "NATS_MAX_FILE"] {
        let template =
            templates::resolve("nats", Some(&settings)).expect("JetStream template exists");
        let mut fixture = Fixture::new(template, &[bound]);
        fixture.start(Some(Mount::Writable));
        fixture.assert_startup_refused();
    }
}

fn authenticated(fixture: &Fixture) -> Nats {
    Nats::connect(
        &fixture.address,
        Some(fixture.credential("NATS_AUTH_TOKEN")),
    )
    .unwrap_or_else(|error| {
        panic!(
            "authenticated NATS connection failed: {}",
            fixture.redact(&error)
        )
    })
}

fn assert_authentication_required(fixture: &Fixture) {
    for token in [None, Some("incorrect-generated-credential")] {
        match Nats::connect(&fixture.address, token) {
            Ok(_) => panic!("NATS accepted an absent or incorrect credential"),
            Err(error) => assert!(
                error.to_ascii_lowercase().contains("authorization"),
                "NATS must refuse authentication, not merely lose the connection: {}",
                fixture.redact(&error),
            ),
        }
    }
}

fn assert_store_bounds(fixture: &Fixture) {
    let monitor = fixture
        .template
        .ports
        .iter()
        .find(|(name, _, _)| *name == "monitor")
        .expect("NATS monitoring port")
        .1;
    let state: Value = serde_json::from_str(&fixture.http_get(monitor, "/jsz"))
        .expect("JetStream monitoring responds with JSON");
    let config = &state["config"];
    assert_eq!(
        config["max_memory"].as_u64(),
        Some(fixture.memory_mib * 1024 * 1024 / 2),
        "JetStream memory is bounded below its real container memory cap",
    );
    assert_eq!(config["max_storage"].as_u64(), Some(1024 * 1024 * 1024));
}

fn assert_message(client: &mut Nats, marker: &str) {
    let stored = client.request("$JS.API.STREAM.MSG.GET.GRUND_ACCEPTANCE", r#"{"seq":1}"#);
    assert_eq!(stored["message"]["subject"], "grund.acceptance.events");
    assert_eq!(stored["message"]["seq"], 1);
    use base64::{Engine, engine::general_purpose::STANDARD};
    let encoded = stored["message"]["data"]
        .as_str()
        .expect("stored message data");
    assert_eq!(
        STANDARD.decode(encoded).expect("base64 message data"),
        marker.as_bytes()
    );
}

struct Nats {
    reader: BufReader<TcpStream>,
}

impl Nats {
    fn connect(address: &str, token: Option<&str>) -> Result<Self, String> {
        let address: SocketAddr = format!("{address}:4222")
            .parse()
            .map_err(|_| "invalid bridge address")?;
        let socket = TcpStream::connect_timeout(&address, Duration::from_secs(3))
            .map_err(|error| error.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|error| error.to_string())?;
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .map_err(|error| error.to_string())?;
        let mut client = Self {
            reader: BufReader::new(socket),
        };
        if !client.line()?.starts_with("INFO ") {
            return Err("NATS did not send INFO".into());
        }
        let mut options =
            json!({"verbose": false, "pedantic": true, "lang": "rust", "version": "1"});
        if let Some(token) = token {
            options["auth_token"] = token.into();
        }
        write!(client.reader.get_mut(), "CONNECT {options}\r\nPING\r\n")
            .map_err(|error| error.to_string())?;
        loop {
            let line = client.line()?;
            if line == "PONG" {
                return Ok(client);
            }
            if let Some(error) = line.strip_prefix("-ERR ") {
                return Err(error.to_owned());
            }
            if line == "PING" {
                client
                    .reader
                    .get_mut()
                    .write_all(b"PONG\r\n")
                    .map_err(|error| error.to_string())?;
            }
        }
    }

    fn line(&mut self) -> Result<String, String> {
        let mut line = String::new();
        let read = self
            .reader
            .read_line(&mut line)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("NATS connection closed".into());
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    }

    fn request(&mut self, subject: &str, payload: &str) -> Value {
        let inbox = format!("_INBOX.{}", Uuid::new_v4().simple());
        write!(
            self.reader.get_mut(),
            "SUB {inbox} 1\r\nUNSUB 1 1\r\nPUB {subject} {inbox} {}\r\n{payload}\r\n",
            payload.len(),
        )
        .expect("send authenticated NATS request");
        loop {
            let line = self.line().expect("read NATS request response");
            if line == "PING" {
                self.reader
                    .get_mut()
                    .write_all(b"PONG\r\n")
                    .expect("answer NATS ping");
                continue;
            }
            if line.starts_with("MSG ") {
                let length: usize = line
                    .split_whitespace()
                    .last()
                    .unwrap()
                    .parse()
                    .expect("NATS message size");
                assert!(length <= 1024 * 1024, "NATS response is bounded");
                let mut body = vec![0; length + 2];
                self.reader
                    .read_exact(&mut body)
                    .expect("read complete NATS message");
                assert_eq!(&body[length..], b"\r\n");
                let response: Value =
                    serde_json::from_slice(&body[..length]).expect("JetStream JSON response");
                assert!(
                    response.get("error").is_none(),
                    "JetStream request failed: {response}"
                );
                return response;
            }
            assert!(!line.starts_with("-ERR"), "NATS rejected a request: {line}");
        }
    }
}
