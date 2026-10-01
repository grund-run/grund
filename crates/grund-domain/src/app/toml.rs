//! `grund.toml`, the file in a customer's repository that says what an app
//! runs (grund-docs design/apps.md §3.2, §3.3): the same model as the
//! dashboard and the API, in words a person writes. A key grund does not
//! know is refused rather than ignored, so a typo is never silently a
//! default.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::spec::{
    AppSettings, AppSpec, CheckKind, CheckSpec, EnvVar, PortSpec, Protocol, SecretEnv,
    SettingsInput, SpecError, StopSpec,
};

/// The largest file accepted.
pub const MAX_FILE_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    apps: indexmap::IndexMap<String, FileApp>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileApp {
    image: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    copies: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    machines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reschedule_after: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto_rollback: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ports: Vec<FilePort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resources: Option<FileResources>,
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    env: indexmap::IndexMap<String, String>,
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    secrets: indexmap::IndexMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    check: Option<FileCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stop: Option<FileStop>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    release: Option<FileRelease>,
    #[serde(default, skip_serializing)]
    volumes: Option<toml::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilePort {
    name: String,
    port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    public: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    memory: Option<Memory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cpu: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum Memory {
    Mib(u64),
    Text(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileCheck {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interval_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout_ms: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileStop {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grace: Option<u32>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileRelease {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_surge: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_unavailable: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min_ready: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ready_deadline: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    drain: Option<u32>,
}

/// One app as a `grund.toml` declares it.
#[derive(Debug, Clone, PartialEq)]
pub struct Declared {
    pub name: String,
    /// Validated, with defaults filled in.
    pub spec: AppSpec,
    /// The settings it declares, `None` for each key it leaves out.
    pub settings: SettingsInput,
}

fn refuse<T>(field: impl Into<String>, problem: impl Into<String>) -> Result<T, SpecError> {
    Err(SpecError {
        field: field.into(),
        problem: problem.into(),
    })
}

fn memory_mib(memory: &Memory) -> Result<u64, SpecError> {
    match memory {
        Memory::Mib(mib) => Ok(*mib),
        Memory::Text(text) => {
            let text = text.trim();
            let split = text
                .find(|c: char| !(c.is_ascii_digit() || c == '.'))
                .unwrap_or(text.len());
            let (number, unit) = text.split_at(split);
            let number: f64 = number.parse().map_err(|_| SpecError {
                field: "resources.memory".into(),
                problem: "write it as 512 MiB or 4 GiB".into(),
            })?;
            let factor = match unit.trim() {
                "" | "MiB" | "M" | "MB" => 1.0,
                "GiB" | "G" | "GB" => 1024.0,
                _ => return refuse("resources.memory", "write it as 512 MiB or 4 GiB"),
            };
            Ok((number * factor).round() as u64)
        }
    }
}

/// Parses a file and returns the one app it declares as `name`. Every other
/// app in the file is left for its own deploy.
pub fn parse_app(text: &str, name: &str) -> Result<Declared, SpecError> {
    if text.len() > MAX_FILE_BYTES {
        return refuse("grund.toml", "use at most 64 KiB");
    }
    let file: File = toml::from_str(text).map_err(|e| SpecError {
        field: "grund.toml".into(),
        problem: e.message().to_string(),
    })?;
    let Some(app) = file.apps.get(name) else {
        let known: Vec<&str> = file.apps.keys().map(String::as_str).collect();
        return refuse(
            "grund.toml",
            if known.is_empty() {
                format!("the file declares no apps; add an [apps.{name}] table")
            } else {
                format!(
                    "the file has no [apps.{name}]; it declares {}",
                    known.join(", ")
                )
            },
        );
    };
    if app.volumes.is_some() {
        return refuse(
            format!("apps.{name}.volumes"),
            "volumes are not supported yet",
        );
    }
    let mut ports = Vec::new();
    for (i, port) in app.ports.iter().enumerate() {
        let protocol = match port.protocol.as_deref() {
            None => Protocol::Http,
            Some(text) => Protocol::parse(text).ok_or_else(|| SpecError {
                field: format!("apps.{name}.ports[{i}].protocol"),
                problem: "use http, h2c or tcp".into(),
            })?,
        };
        ports.push(PortSpec {
            name: port.name.clone(),
            port: port.port,
            protocol,
            public: port.public,
        });
    }
    let (memory, cpu) = match &app.resources {
        None => (0, 0),
        Some(resources) => (
            resources
                .memory
                .as_ref()
                .map(memory_mib)
                .transpose()?
                .unwrap_or(0),
            match resources.cpu {
                None => 0,
                Some(cpu) if cpu > 0.0 && cpu <= 64.0 => (cpu * 1000.0).round() as u32,
                Some(_) => return refuse(format!("apps.{name}.resources.cpu"), "use 0.01 to 64"),
            },
        ),
    };
    let check = match &app.check {
        None => None,
        Some(check) => Some(CheckSpec {
            kind: match (&check.http, check.tcp) {
                (Some(path), None) => CheckKind::Http { path: path.clone() },
                (None, Some(_)) => CheckKind::Tcp,
                _ => {
                    return refuse(
                        format!("apps.{name}.check"),
                        "give exactly one of http = \"/path\" or tcp = <port>",
                    );
                }
            },
            port: check.tcp.or(check.port).unwrap_or(0),
            interval_ms: check.interval_ms.unwrap_or(0),
            timeout_ms: check.timeout_ms.unwrap_or(0),
        }),
    };
    let spec = AppSpec {
        image: app.image.clone(),
        command: app.command.clone(),
        ports,
        memory_mib: memory,
        cpu_millis: cpu,
        env: app
            .env
            .iter()
            .map(|(name, value)| EnvVar {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        secrets: app
            .secrets
            .iter()
            .map(|(env, secret)| SecretEnv {
                env: env.clone(),
                secret: secret.clone(),
            })
            .collect(),
        check,
        stop: app.stop.as_ref().map_or(
            StopSpec {
                signal: String::new(),
                grace_seconds: 0,
            },
            |stop| StopSpec {
                signal: stop.signal.clone().unwrap_or_default(),
                grace_seconds: stop.grace.unwrap_or(0),
            },
        ),
    }
    .validate()
    .map_err(|e| SpecError {
        field: format!("apps.{name}.{}", e.field),
        problem: e.problem,
    })?;
    let release = app.release.as_ref();
    let settings = SettingsInput {
        copies: app.copies,
        max_surge: release.and_then(|r| r.max_surge),
        max_unavailable: release.and_then(|r| r.max_unavailable),
        min_ready_seconds: release.and_then(|r| r.min_ready),
        ready_deadline_seconds: release.and_then(|r| r.ready_deadline),
        drain_seconds: release.and_then(|r| r.drain),
        machines: app.machines.clone(),
        reschedule_after_seconds: app.reschedule_after,
        auto_rollback: app.auto_rollback,
    };
    AppSettings::validate(settings.clone()).map_err(|e| SpecError {
        field: format!("apps.{name}.{}", e.field),
        problem: e.problem,
    })?;
    Ok(Declared {
        name: name.to_string(),
        spec,
        settings,
    })
}

/// The file that declares this app as it runs now, for "Copy as file".
/// Settings at their defaults are left out.
pub fn render(name: &str, spec: &AppSpec, settings: &AppSettings) -> String {
    let defaults = AppSettings::default();
    let rollout = &settings.rollout;
    let release = FileRelease {
        max_surge: (rollout.max_surge != defaults.rollout.max_surge).then_some(rollout.max_surge),
        max_unavailable: (rollout.max_unavailable != defaults.rollout.max_unavailable)
            .then_some(rollout.max_unavailable),
        min_ready: (rollout.min_ready_seconds != defaults.rollout.min_ready_seconds)
            .then_some(rollout.min_ready_seconds),
        ready_deadline: (rollout.ready_deadline_seconds != defaults.rollout.ready_deadline_seconds)
            .then_some(rollout.ready_deadline_seconds),
        drain: (rollout.drain_seconds != defaults.rollout.drain_seconds)
            .then_some(rollout.drain_seconds),
    };
    let release_set = release.max_surge.is_some()
        || release.max_unavailable.is_some()
        || release.min_ready.is_some()
        || release.ready_deadline.is_some()
        || release.drain.is_some();
    let app = FileApp {
        image: spec.image.clone(),
        command: spec.command.clone(),
        copies: (settings.copies != 1).then_some(settings.copies),
        machines: settings.machines.clone(),
        reschedule_after: (settings.reschedule_after_seconds != defaults.reschedule_after_seconds)
            .then_some(settings.reschedule_after_seconds),
        auto_rollback: (!settings.auto_rollback).then_some(false),
        ports: spec
            .ports
            .iter()
            .map(|p| FilePort {
                name: p.name.clone(),
                port: p.port,
                protocol: (p.protocol != Protocol::Http).then(|| p.protocol.as_str().to_string()),
                public: p.public,
            })
            .collect(),
        resources: (spec.memory_mib != 512 || spec.cpu_millis != 1000).then(|| FileResources {
            memory: Some(if spec.memory_mib.is_multiple_of(1024) {
                Memory::Text(format!("{} GiB", spec.memory_mib / 1024))
            } else {
                Memory::Text(format!("{} MiB", spec.memory_mib))
            }),
            cpu: Some(f64::from(spec.cpu_millis) / 1000.0),
        }),
        env: spec
            .env
            .iter()
            .map(|e| (e.name.clone(), e.value.clone()))
            .collect(),
        secrets: spec
            .secrets
            .iter()
            .map(|s| (s.env.clone(), s.secret.clone()))
            .collect(),
        check: spec.check.as_ref().map(|c| FileCheck {
            http: match &c.kind {
                CheckKind::Http { path } => Some(path.clone()),
                CheckKind::Tcp => None,
            },
            tcp: matches!(c.kind, CheckKind::Tcp).then_some(c.port),
            port: match c.kind {
                CheckKind::Http { .. } if spec.ports.first().map(|p| p.port) != Some(c.port) => {
                    Some(c.port)
                }
                _ => None,
            },
            interval_ms: (c.interval_ms != 2000).then_some(c.interval_ms),
            timeout_ms: (c.timeout_ms != 1000).then_some(c.timeout_ms),
        }),
        stop: (spec.stop != StopSpec::default()).then(|| FileStop {
            signal: (spec.stop.signal != "SIGTERM").then(|| spec.stop.signal.clone()),
            grace: (spec.stop.grace_seconds != 30).then_some(spec.stop.grace_seconds),
        }),
        release: release_set.then_some(release),
        volumes: None,
    };
    let mut apps = indexmap::IndexMap::new();
    apps.insert(name.to_string(), app);
    toml::to_string(&File { apps }).unwrap_or_default()
}

/// The names of the apps a file declares, in order, if it parses.
pub fn declared_names(text: &str) -> Vec<String> {
    toml::from_str::<BTreeMap<String, toml::Value>>(text)
        .ok()
        .and_then(|table| table.get("apps").cloned())
        .and_then(|apps| apps.as_table().map(|t| t.keys().cloned().collect()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOP: &str = r#"
[apps.shop]
image = "ghcr.io/acme/shop:2026-09-26.1"
command = ["./shop", "serve"]
copies = 2

[[apps.shop.ports]]
name = "http"
port = 8080
public = true

[apps.shop.resources]
memory = "1 GiB"
cpu = 0.5

[apps.shop.env]
DATABASE_URL = "postgres://shop@db.grund.internal:5432/shop"

[apps.shop.secrets]
DATABASE_PASSWORD = "db-password"

[apps.shop.check]
http = "/healthz"

[apps.db]
image = "postgres:17.6"

[[apps.db.ports]]
name = "postgres"
port = 5432
protocol = "tcp"
"#;

    #[test]
    fn the_designs_example_declares_the_app_it_names() {
        let shop = parse_app(SHOP, "shop").unwrap();
        assert_eq!(shop.spec.image, "ghcr.io/acme/shop:2026-09-26.1");
        assert_eq!(shop.spec.command, vec!["./shop", "serve"]);
        assert_eq!(shop.spec.memory_mib, 1024);
        assert_eq!(shop.spec.cpu_millis, 500);
        assert_eq!(shop.spec.ports[0].port, 8080);
        assert!(shop.spec.ports[0].public);
        assert_eq!(shop.spec.secrets[0].secret, "db-password");
        assert_eq!(shop.spec.check.as_ref().unwrap().port, 8080);
        assert_eq!(shop.settings.copies, Some(2));
        let db = parse_app(SHOP, "db").unwrap();
        assert_eq!(db.spec.ports[0].protocol, Protocol::Tcp);
        assert_eq!(declared_names(SHOP), vec!["shop", "db"]);
    }

    #[test]
    fn an_unknown_key_or_a_missing_app_is_refused() {
        let typo = "[apps.web]\nimage = \"nginx\"\ncopis = 2\n";
        assert!(
            parse_app(typo, "web")
                .unwrap_err()
                .problem
                .contains("copis")
        );
        let error = parse_app(SHOP, "web").unwrap_err();
        assert!(error.problem.contains("shop, db"), "{error}");
        let volumes = "[apps.db]\nimage = \"postgres\"\n[apps.db.volumes.data]\npath = \"/d\"\n";
        assert_eq!(
            parse_app(volumes, "db").unwrap_err().field,
            "apps.db.volumes"
        );
        let bad = "[apps.web]\nimage = \"nginx\"\n[apps.web.resources]\nmemory = \"lots\"\n";
        assert_eq!(parse_app(bad, "web").unwrap_err().field, "resources.memory");
    }

    #[test]
    fn a_rendered_file_parses_back_to_the_same_app() {
        let shop = parse_app(SHOP, "shop").unwrap();
        let settings = AppSettings::validate(shop.settings.clone()).unwrap();
        let text = render("shop", &shop.spec, &settings);
        let again = parse_app(&text, "shop").unwrap();
        assert_eq!(again.spec, shop.spec);
        assert_eq!(AppSettings::validate(again.settings).unwrap(), settings);
    }
}
