//! `grund.yaml`, the file in a customer's repository that says what an app
//! runs (grund-docs design/apps.md §3.2, §3.3): the same model as the
//! dashboard and the API, in words a person writes. A key grund does not
//! know is refused rather than ignored, so a typo is never silently a
//! default.
//!
//! The types below are the file's format. The JSON Schema every instance
//! serves at [`SCHEMA_PATH`] is generated from them ([`schema`]), so an
//! editor's completion and hover text are these docs, and the schema cannot
//! drift from what [`parse_app`] accepts.
//!
//! The YAML is read and written by [`crate::yaml`]: one document, YAML 1.2
//! booleans, unknown tags refused, aliases bounded.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings, json_schema};
use serde::{Deserialize, Serialize};

use super::spec::{
    AppSettings, AppSpec, CheckKind, CheckSpec, EnvVar, MachineKind, PlacementRules, PortSpec,
    Protocol, STOP_SIGNALS, SecretEnv, SettingsInput, SpecError, StopSpec,
};
use crate::yaml;

/// The largest file accepted.
pub const MAX_FILE_BYTES: usize = 64 * 1024;

/// The name the file goes by, in errors and downloads.
pub const FILE_NAME: &str = "grund.yaml";

/// Where every instance serves the file's JSON Schema.
pub const SCHEMA_PATH: &str = "/schema/grund.json";

/// A grund.yaml: the apps one repository declares. Each deploy names one of
/// them; the others are left for their own deploys.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(title = "grund.yaml")]
pub struct GrundFile {
    /// The apps, by name: lowercase letters, digits and dashes, at most 32
    /// characters, starting with a letter.
    #[serde(default)]
    pub apps: indexmap::IndexMap<String, FileApp>,
}

/// One app: what each copy runs, and how many copies run where.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileApp {
    /// The container image, as `docker pull` takes it, for example
    /// `ghcr.io/acme/shop:2026-09-26.1` or `nginx:1.27`. grund resolves the
    /// tag to a digest once, at deploy, and every copy runs that digest.
    pub image: String,
    /// Replaces the image's entrypoint and command, one argument per item.
    /// Leave it out to run what the image says.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub command: Vec<String>,
    /// How many copies run. Default 1, at most 20.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 20))]
    pub copies: Option<u32>,
    /// The machines the copies may run on, by name. Leave it out for any
    /// machine in the organisation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 50))]
    pub machines: Vec<String>,
    /// Which machines beyond their names, and how the copies spread over
    /// them. Leave it out for any machine, spread one copy per machine
    /// first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<FilePlacement>,
    /// Seconds a copy's machine may be unreachable before the copy is placed
    /// elsewhere. Default 120, 30 to 3600.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 30, max = 3600))]
    pub reschedule_after: Option<u32>,
    /// Go back to the release before when a rollout fails. Default true;
    /// false halts the app as it is until the next release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_rollback: Option<bool>,
    /// The ports the app listens on. At most 8, of which at most 2 public.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 8))]
    pub ports: Vec<FilePort>,
    /// What each copy reserves on its machine. Default 512 MiB and 1 CPU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<FileResources>,
    /// Environment variables, by name. A value is kept as written: `8080`,
    /// `1.50` and `true` are those strings. At most 128, 32 KiB in all.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    #[schemars(extend("additionalProperties" = {"type": ["string", "number", "boolean"]}))]
    pub env: indexmap::IndexMap<String, String>,
    /// Environment variables taken from the organisation's secrets: the
    /// variable's name, then the secret's. The value never appears in the
    /// file. At most 50.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub secrets: indexmap::IndexMap<String, String>,
    /// The ready check a new copy must pass before it takes traffic and
    /// before an older copy leaves. Leave it out to count a running copy as
    /// ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<FileCheck>,
    /// How a copy is stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<FileStop>,
    /// How a new release replaces the copies of the one before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<FileRelease>,
    /// Not supported yet; a file that declares volumes is refused.
    #[serde(default, skip_serializing)]
    #[schemars(skip)]
    pub volumes: Option<serde::de::IgnoredAny>,
}

/// A port the app listens on.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilePort {
    /// A name for the port, unique in the app, for example `http`.
    pub name: String,
    /// The port inside the container, 1 to 65535.
    #[schemars(range(min = 1))]
    pub port: u16,
    /// What the port speaks. Default `http`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<FileProtocol>,
    /// Serve the port at the app's public address. Default false: reachable
    /// only inside the organisation, at `<app>.grund.internal`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub public: bool,
}

/// What a port speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FileProtocol {
    /// HTTP/1.1, and HTTP/2 where the client asks for it.
    Http,
    /// HTTP/2 without TLS, for gRPC.
    H2c,
    /// Plain TCP.
    Tcp,
}

/// What each copy reserves.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileResources {
    /// Memory, as `512 MiB` or `4 GiB`, or a number of MiB. Default
    /// 512 MiB, 16 MiB to 256 GiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<Memory>,
    /// CPUs, for example 0.5 or 2. Default 1, 0.01 to 64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0.01, max = 64))]
    pub cpu: Option<f64>,
}

/// An amount of memory, in MiB or as text with a unit.
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Memory {
    Mib(u64),
    Text(String),
}

impl JsonSchema for Memory {
    fn schema_name() -> Cow<'static, str> {
        "Memory".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "anyOf": [
                {"type": "integer", "minimum": 16, "maximum": 262144},
                {"type": "string", "pattern": "^\\s*[0-9.]+\\s*(MiB|M|MB|GiB|G|GB)?\\s*$"}
            ]
        })
    }
}

/// A ready check: an HTTP path that answers 2xx or 3xx, or a TCP port that
/// accepts a connection. Give exactly one of `http` and `tcp`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileCheck {
    /// The path to ask, for example `/healthz`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<String>,
    /// The port to connect to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub tcp: Option<u16>,
    /// The port an `http` check asks. Default the app's first port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub port: Option<u16>,
    /// Milliseconds between checks. Default 2000, 500 to 60000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 500, max = 60000))]
    pub interval_ms: Option<u32>,
    /// Milliseconds one check may take, below the interval. Default 1000,
    /// 100 to 30000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 100, max = 30000))]
    pub timeout_ms: Option<u32>,
}

/// How a copy is stopped: the signal, then a kill after the grace period.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileStop {
    /// The signal sent first. Default SIGTERM; one of SIGTERM, SIGINT,
    /// SIGQUIT, SIGUSR1, SIGUSR2 or SIGHUP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("examples" = STOP_SIGNALS))]
    pub signal: Option<String>,
    /// Seconds between the signal and the kill. Default 30, at most 300.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 300))]
    pub grace: Option<u32>,
}

/// Where the copies run, beyond the machines' names. A copy on a machine
/// that stops matching moves to one that does, started before it stops.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilePlacement {
    /// Labels a machine must carry, each with this value, as set on the
    /// Machines page, for example `disk: ssd`. At most 16.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    #[schemars(extend("maxProperties" = 16))]
    pub labels: indexmap::IndexMap<String, String>,
    /// `own` for the organisation's own machines only, `hosted` for machines
    /// grund hosts only. Leave it out for either.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FileMachineKind>,
    /// A label key whose values are failure domains, for example `zone`:
    /// copies go to the value with the fewest copies first, then to the
    /// machine with the fewest. Machines without the label count as one
    /// domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spread_by: Option<String>,
    /// Other apps whose machines are preferred, after the spread. At most
    /// 10.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 10))]
    pub near: Vec<String>,
    /// Other apps whose machines are avoided, after the spread. At most 10.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 10))]
    pub apart: Vec<String>,
}

/// Which kind of machine.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileMachineKind {
    /// The organisation's own machines.
    Own,
    /// Machines grund hosts.
    Hosted,
}

/// How a release rolls out.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileRelease {
    /// Copies of the new release started beyond `copies` at once. Default
    /// 1, at most `copies`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_surge: Option<u32>,
    /// Copies that may be missing during the rollout. Default 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<u32>,
    /// Seconds a new copy must stay ready before it counts. Default 10, at
    /// most 600.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(max = 600))]
    pub min_ready: Option<u32>,
    /// Seconds the whole rollout may take before it fails. Default 300, 10
    /// to 1800.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 10, max = 1800))]
    pub ready_deadline: Option<u32>,
    /// Seconds an old copy keeps serving after traffic leaves it. Default
    /// 30, at most 300.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(max = 300))]
    pub drain: Option<u32>,
}

/// One app as a `grund.yaml` declares it.
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

fn read(text: &str) -> Result<GrundFile, SpecError> {
    yaml::from_str(text).map_err(|error| SpecError {
        field: if error.path.is_empty() {
            FILE_NAME.into()
        } else {
            error.path.clone()
        },
        problem: error.problem(),
    })
}

fn memory_mib(name: &str, memory: &Memory) -> Result<u64, SpecError> {
    let field = format!("apps.{name}.resources.memory");
    match memory {
        Memory::Mib(mib) => Ok(*mib),
        Memory::Text(text) => {
            let text = text.trim();
            let split = text
                .find(|c: char| !(c.is_ascii_digit() || c == '.'))
                .unwrap_or(text.len());
            let (number, unit) = text.split_at(split);
            let number: f64 = number.parse().map_err(|_| SpecError {
                field: field.clone(),
                problem: "write it as 512 MiB or 4 GiB".into(),
            })?;
            let factor = match unit.trim() {
                "" | "MiB" | "M" | "MB" => 1.0,
                "GiB" | "G" | "GB" => 1024.0,
                _ => return refuse(field, "write it as 512 MiB or 4 GiB"),
            };
            Ok((number * factor).round() as u64)
        }
    }
}

/// Parses a file and returns the one app it declares as `name`. Every other
/// app in the file is left for its own deploy. A file that does not parse
/// is refused with the line and column, and the field's path when serde
/// knew it (`apps.shop.copies`).
pub fn parse_app(text: &str, name: &str) -> Result<Declared, SpecError> {
    if text.len() > MAX_FILE_BYTES {
        return refuse(FILE_NAME, "use at most 64 KiB");
    }
    let file = read(text)?;
    let Some(app) = file.apps.get(name) else {
        let known: Vec<&str> = file.apps.keys().map(String::as_str).collect();
        return refuse(
            FILE_NAME,
            if known.is_empty() {
                format!("the file declares no apps; add {name} under apps:")
            } else {
                format!(
                    "the file declares no app {name} under apps:; it declares {}",
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
    let ports = app
        .ports
        .iter()
        .map(|port| PortSpec {
            name: port.name.clone(),
            port: port.port,
            protocol: match port.protocol {
                None | Some(FileProtocol::Http) => Protocol::Http,
                Some(FileProtocol::H2c) => Protocol::H2c,
                Some(FileProtocol::Tcp) => Protocol::Tcp,
            },
            public: port.public,
        })
        .collect();
    let (memory, cpu) = match &app.resources {
        None => (0, 0),
        Some(resources) => (
            resources
                .memory
                .as_ref()
                .map(|m| memory_mib(name, m))
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
                        "give exactly one of http: /path or tcp: <port>",
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
        ..placement_input(app.placement.as_ref())
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

fn placement_input(placement: Option<&FilePlacement>) -> SettingsInput {
    let Some(placement) = placement else {
        return SettingsInput::default();
    };
    SettingsInput {
        labels: placement
            .labels
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        kind: match placement.kind {
            Some(FileMachineKind::Own) => "own".into(),
            Some(FileMachineKind::Hosted) => "hosted".into(),
            None => String::new(),
        },
        spread_by: placement.spread_by.clone().unwrap_or_default(),
        near: placement.near.clone(),
        apart: placement.apart.clone(),
        ..SettingsInput::default()
    }
}

fn file_placement(rules: &PlacementRules) -> Option<FilePlacement> {
    (!rules.is_default()).then(|| FilePlacement {
        labels: rules
            .labels
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        kind: rules.kind.map(|kind| match kind {
            MachineKind::Own => FileMachineKind::Own,
            MachineKind::Hosted => FileMachineKind::Hosted,
        }),
        spread_by: rules.spread_by.clone(),
        near: rules.near.clone(),
        apart: rules.apart.clone(),
    })
}

fn file_app(spec: &AppSpec, settings: &AppSettings) -> FileApp {
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
    FileApp {
        image: spec.image.clone(),
        command: spec.command.clone(),
        copies: (settings.copies != 1).then_some(settings.copies),
        machines: settings.machines.clone(),
        placement: file_placement(&settings.placement),
        reschedule_after: (settings.reschedule_after_seconds != defaults.reschedule_after_seconds)
            .then_some(settings.reschedule_after_seconds),
        auto_rollback: (!settings.auto_rollback).then_some(false),
        ports: spec
            .ports
            .iter()
            .map(|p| FilePort {
                name: p.name.clone(),
                port: p.port,
                protocol: match p.protocol {
                    Protocol::Http => None,
                    Protocol::H2c => Some(FileProtocol::H2c),
                    Protocol::Tcp => Some(FileProtocol::Tcp),
                },
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
    }
}

/// The file that declares this app as it runs now, for the dashboard's
/// Copy and Download. Settings at their defaults are left out, keys come in
/// the order of the types above, and the first line points editors at
/// `schema_url` (the instance's [`SCHEMA_PATH`]).
pub fn render(name: &str, spec: &AppSpec, settings: &AppSettings, schema_url: &str) -> String {
    let mut apps = indexmap::IndexMap::new();
    apps.insert(name.to_string(), file_app(spec, settings));
    let body = yaml::to_string(&GrundFile { apps });
    format!(
        "# yaml-language-server: $schema={schema_url}\n\
         # {name}, as its newest release runs. Defaults are left out.\n\
         {body}"
    )
}

/// The names of the apps a file declares, in order, if it parses.
pub fn declared_names(text: &str) -> Vec<String> {
    read(text)
        .map(|file| file.apps.into_keys().collect())
        .unwrap_or_default()
}

/// The JSON Schema of a grund.yaml (draft 07, which every YAML editor
/// reads), as served at [`SCHEMA_PATH`].
pub fn schema() -> serde_json::Value {
    let mut settings = SchemaSettings::draft07();
    settings.meta_schema = Some("http://json-schema.org/draft-07/schema#".into());
    let schema = settings
        .into_generator()
        .into_root_schema_for::<GrundFile>();
    serde_json::to_value(schema).unwrap_or_default()
}

/// [`schema`] as the file the repository keeps (`schema/grund.json`):
/// pretty, with a final newline.
pub fn schema_text() -> String {
    let mut text = serde_json::to_string_pretty(&schema()).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOP: &str = r#"
apps:
  shop:
    image: ghcr.io/acme/shop:2026-09-26.1
    command: [./shop, serve]
    copies: 2
    ports:
      - name: http
        port: 8080
        public: true
    resources:
      memory: 1 GiB
      cpu: 0.5
    env:
      DATABASE_URL: postgres://shop@db.grund.internal:5432/shop
    secrets:
      DATABASE_PASSWORD: db-password
    check:
      http: /healthz
  db:
    image: postgres:17.6
    ports:
      - name: postgres
        port: 5432
        protocol: tcp
"#;

    fn schema_validator() -> jsonschema::Validator {
        jsonschema::draft7::new(&schema()).unwrap()
    }

    fn as_json(text: &str) -> serde_json::Value {
        serde_saphyr::from_str(text).unwrap()
    }

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
    fn an_unknown_key_is_refused_with_its_line_column_and_path() {
        let typo = "apps:\n  web:\n    image: nginx\n    copis: 2\n";
        let error = parse_app(typo, "web").unwrap_err();
        assert_eq!(error.field, "apps.web.copis");
        assert!(error.problem.starts_with("line 4, column 5: "), "{error}");
        assert!(error.problem.contains("unknown field `copis`"), "{error}");
        assert!(error.problem.contains("copies"), "{error}");
        let nested =
            "apps:\n  web:\n    image: nginx\n    ports:\n      - name: http\n        prot: 80\n";
        let error = parse_app(nested, "web").unwrap_err();
        assert_eq!(error.field, "apps.web.ports[0].prot");
        assert!(error.problem.starts_with("line 6, column 9: "), "{error}");
        let top = "apps: {}\nversion: 2\n";
        let error = parse_app(top, "web").unwrap_err();
        assert_eq!(error.field, "version");
        assert!(error.problem.starts_with("line 2, column 1: "), "{error}");
    }

    #[test]
    fn a_wrong_type_or_a_broken_file_names_where() {
        let cases = [
            (
                "apps:\n  web:\n    image: nginx\n    copies: lots\n",
                "apps.web.copies",
                "line 4, column 13: ",
            ),
            (
                "apps:\n  web:\n    image: nginx\n    ports:\n      - {name: h, port: 80, protocol: udp}\n",
                "apps.web.ports[0].protocol",
                "line 5, column 39: ",
            ),
            (
                "apps:\n  web:\n    image: nginx\n    ports:\n      - {name: h, port: 80, public: yes}\n",
                "apps.web.ports[0].public",
                "line 5, column 37: ",
            ),
            (
                "apps:\n  web:\n    image:\n",
                "apps.web.image",
                "line 3, column 10: ",
            ),
            (
                "apps:\n  web:\n    copies: 1\n",
                "apps.web",
                "line 3, column 5: ",
            ),
            (
                "apps:\n\tweb:\n    image: nginx\n",
                FILE_NAME,
                "line 2, column 2: ",
            ),
            ("apps: {}\n---\napps: {}\n", FILE_NAME, "line 2, column 1: "),
            ("- nginx\n", FILE_NAME, "line 1, column 1: "),
            (
                "apps:\n  web:\n    image: !!python/object nginx\n",
                "apps.web",
                "line 3, column 28: ",
            ),
        ];
        for (text, field, at) in cases {
            let error = parse_app(text, "web").unwrap_err();
            assert_eq!(error.field, field, "{text:?}: {error}");
            assert!(error.problem.starts_with(at), "{text:?}: {error}");
            assert!(!error.problem.contains("Option<"), "{text:?}: {error}");
        }
    }

    #[test]
    fn a_missing_app_volumes_and_bad_values_are_refused_by_field() {
        let error = parse_app(SHOP, "web").unwrap_err();
        assert!(error.problem.contains("shop, db"), "{error}");
        assert!(
            parse_app("apps: {}\n", "web")
                .unwrap_err()
                .problem
                .contains("declares no apps")
        );
        assert!(
            parse_app("", "web")
                .unwrap_err()
                .problem
                .contains("declares no apps")
        );
        let volumes = "apps:\n  db:\n    image: postgres\n    volumes:\n      data: {path: /d}\n";
        assert_eq!(
            parse_app(volumes, "db").unwrap_err().field,
            "apps.db.volumes"
        );
        let bad = "apps:\n  web:\n    image: nginx\n    resources:\n      memory: lots\n";
        assert_eq!(
            parse_app(bad, "web").unwrap_err().field,
            "apps.web.resources.memory"
        );
        let copies = "apps:\n  web:\n    image: nginx\n    copies: 21\n";
        assert_eq!(
            parse_app(copies, "web").unwrap_err().field,
            "apps.web.copies"
        );
        let big = format!("apps: {{}}\n#{}\n", "x".repeat(MAX_FILE_BYTES));
        assert!(
            parse_app(&big, "web")
                .unwrap_err()
                .problem
                .contains("64 KiB")
        );
    }

    #[test]
    fn an_env_value_is_kept_as_written() {
        let text = "apps:\n  web:\n    image: nginx\n    env:\n      PORT: 8080\n      RATE: 1.50\n      DEBUG: true\n      MODE: 0x1F\n";
        let web = parse_app(text, "web").unwrap();
        let values: Vec<&str> = web.spec.env.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(values, ["8080", "1.50", "true", "0x1F"]);
        assert!(schema_validator().is_valid(&as_json(text)));
    }

    #[test]
    fn anchors_are_read_and_an_alias_bomb_is_refused_quickly() {
        let shared = "apps:\n  a:\n    image: x\n    env: &env\n      MODE: live\n  b:\n    image: y\n    env:\n      <<: *env\n      NAME: b\n";
        let b = parse_app(shared, "b").unwrap();
        assert_eq!(b.spec.env.len(), 2);
        let mut bomb = String::from(
            "apps:\n  a:\n    image: x\n    volumes:\n      l0: &l0 [lol, lol, lol, lol, lol, lol, lol, lol, lol]\n",
        );
        for level in 1..10 {
            let prev = level - 1;
            let row = vec![format!("*l{prev}"); 9].join(", ");
            bomb.push_str(&format!("      l{level}: &l{level} [{row}]\n"));
        }
        let started = std::time::Instant::now();
        let error = parse_app(&bomb, "a").unwrap_err();
        assert!(error.problem.contains("alias"), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn placement_is_read_refused_by_field_and_written_back() {
        let text = "apps:\n  web:\n    image: nginx:1.27\n    copies: 3\n    placement:\n      labels:\n        disk: ssd\n      kind: own\n      spread_by: zone\n      near: [db]\n      apart: [batch]\n";
        let web = parse_app(text, "web").unwrap();
        let settings = AppSettings::validate(web.settings.clone()).unwrap();
        assert_eq!(settings.placement.spread_by.as_deref(), Some("zone"));
        assert_eq!(
            settings.placement.labels.get("disk").map(String::as_str),
            Some("ssd")
        );
        assert_eq!(settings.placement.kind, Some(MachineKind::Own));
        assert_eq!(settings.placement.near, vec!["db".to_string()]);
        let rendered = render(
            "web",
            &web.spec,
            &settings,
            "https://grund.example/schema/grund.json",
        );
        assert!(rendered.contains("placement:"), "{rendered}");
        let again = parse_app(&rendered, "web").unwrap();
        assert_eq!(AppSettings::validate(again.settings).unwrap(), settings);
        let bad = "apps:\n  web:\n    image: nginx:1.27\n    placement:\n      spread_by: Zone\n";
        assert_eq!(
            parse_app(bad, "web").unwrap_err().field,
            "apps.web.placement.spread_by"
        );
        let plain = parse_app("apps:\n  web:\n    image: nginx:1.27\n", "web").unwrap();
        let plain = AppSettings::validate(plain.settings).unwrap();
        assert!(!render("web", &web.spec, &plain, "x").contains("placement"));
    }

    #[test]
    fn a_rendered_file_parses_back_to_the_same_app() {
        let shop = parse_app(SHOP, "shop").unwrap();
        let settings = AppSettings::validate(shop.settings.clone()).unwrap();
        let text = render(
            "shop",
            &shop.spec,
            &settings,
            "https://grund.example/schema/grund.json",
        );
        let again = parse_app(&text, "shop").unwrap();
        assert_eq!(again.spec, shop.spec);
        assert_eq!(AppSettings::validate(again.settings).unwrap(), settings);
    }

    #[test]
    fn the_export_points_editors_at_the_schema_and_keeps_its_order() {
        let shop = parse_app(SHOP, "shop").unwrap();
        let settings = AppSettings::validate(shop.settings.clone()).unwrap();
        let text = render(
            "shop",
            &shop.spec,
            &settings,
            "https://grund.example/schema/grund.json",
        );
        assert_eq!(
            text.lines().next(),
            Some("# yaml-language-server: $schema=https://grund.example/schema/grund.json")
        );
        let keys: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("    ") && !l.starts_with("     ") && !l.starts_with("    -"))
            .filter_map(|l| l.trim().split(':').next())
            .collect();
        assert_eq!(
            keys,
            [
                "image",
                "command",
                "copies",
                "ports",
                "resources",
                "env",
                "secrets",
                "check"
            ]
        );
        assert_eq!(
            text,
            render(
                "shop",
                &shop.spec,
                &settings,
                "https://grund.example/schema/grund.json"
            )
        );
    }

    #[test]
    fn strings_yaml_would_read_as_something_else_survive_a_round_trip() {
        let awkward = [
            "yes",
            "no",
            "on",
            "off",
            "true",
            "null",
            "~",
            "",
            "8080",
            "0x1F",
            "1e3",
            "0777",
            "- item",
            "a: b",
            "#hash",
            "key: value # not a comment",
            "'quoted'",
            "\"double\"",
            "multi\nline\n",
            "trailing space ",
            " leading",
            "tab\there",
            "{flow}",
            "[list]",
            "*alias",
            "&anchor",
            "!tag",
            "%directive",
            "@at",
            "`tick`",
            "æøå ✓",
            "line one\n\nline three",
            "ends with newlines\n\n",
            &"long ".repeat(40),
        ];
        let mut spec = parse_app(SHOP, "shop").unwrap().spec;
        spec.env = awkward
            .iter()
            .enumerate()
            .map(|(i, value)| EnvVar {
                name: format!("V{i}"),
                value: value.to_string(),
            })
            .collect();
        spec.command = awkward.iter().map(|s| s.replace('\0', "")).collect();
        let spec = spec.validate().unwrap();
        let settings = AppSettings::default();
        let text = render(
            "shop",
            &spec,
            &settings,
            "https://grund.example/schema/grund.json",
        );
        let again = parse_app(&text, "shop").unwrap_or_else(|e| panic!("{e}\n{text}"));
        assert_eq!(again.spec, spec, "{text}");
    }

    #[test]
    fn every_example_and_the_export_validate_against_the_schema() {
        let validator = schema_validator();
        let shop = parse_app(SHOP, "shop").unwrap();
        let settings = AppSettings::validate(shop.settings.clone()).unwrap();
        let exported = render(
            "shop",
            &shop.spec,
            &settings,
            "https://grund.example/schema/grund.json",
        );
        for text in [SHOP, exported.as_str()] {
            let errors: Vec<String> = validator
                .iter_errors(&as_json(text))
                .map(|e| e.to_string())
                .collect();
            assert!(errors.is_empty(), "{errors:?}\n{text}");
        }
        for template in super::super::templates::CATALOGUE {
            let Some(spec) = template.spec(true) else {
                continue;
            };
            let spec = spec.validate().unwrap();
            let text = render(template.key, &spec, &AppSettings::default(), "x");
            assert!(validator.is_valid(&as_json(&text)), "{text}");
        }
        assert!(!validator.is_valid(&as_json("apps:\n  web:\n    image: nginx\n    copis: 2\n")));
        assert!(!validator.is_valid(&as_json("apps:\n  web:\n    copies: 2\n")));
    }

    #[test]
    fn the_schema_describes_the_fields_editors_show() {
        let schema = schema();
        let text = schema.to_string();
        assert_eq!(schema["$schema"], "http://json-schema.org/draft-07/schema#");
        assert_eq!(schema["title"], "grund.yaml");
        assert_eq!(schema["additionalProperties"], false);
        assert!(text.contains("How many copies run. Default 1, at most 20."));
        assert!(text.contains("\"h2c\""));
        assert!(!text.contains("volumes"));
    }

    #[test]
    fn the_schema_in_the_repository_is_the_one_the_types_make() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schema/grund.json");
        if std::env::var_os("GRUND_WRITE_SCHEMA").is_some() {
            std::fs::write(path, schema_text()).unwrap();
        }
        let kept = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            kept == schema_text(),
            "schema/grund.json is stale: run GRUND_WRITE_SCHEMA=1 cargo test -p grund-domain"
        );
    }
}
