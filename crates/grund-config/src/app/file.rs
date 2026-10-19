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
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Serialize};

use super::spec::{
    AppSettings, AppSpec, CheckKind, CheckSpec, EnvVar, MachineKind, PlacementRules, PortSpec,
    Protocol, STOP_SIGNALS, SecretEnv, SettingsInput, SpecError, StopSpec, VolumeSpec,
};
use crate::yaml;

/// The largest file accepted.
pub const MAX_FILE_BYTES: usize = 64 * 1024;

/// The name the file goes by, in errors and downloads.
pub const FILE_NAME: &str = "grund.yaml";

/// Where every instance serves the file's JSON Schema.
pub const SCHEMA_PATH: &str = "/schema/grund.json";

/// A grund.yaml declares either independently deployed apps or one stack.
#[derive(Debug, Default, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("oneOf" = [{"required": ["apps"], "not": {"required": ["stack"]}}, {"required": ["stack"], "not": {"required": ["apps"]}}]))]
#[schemars(title = "grund.yaml")]
pub struct GrundFile {
    /// The apps, by name: lowercase letters, digits and dashes, at most 32
    /// characters, starting with a letter.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub apps: indexmap::IndexMap<String, FileApp>,
    /// A coordinated deployment; cannot be combined with `apps`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<crate::stack::Definition>,
}

impl<'de> Deserialize<'de> for GrundFile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Document {
            #[serde(default, deserialize_with = "unique_optional_map")]
            apps: Option<indexmap::IndexMap<String, FileApp>>,
            #[serde(default, deserialize_with = "present_stack")]
            stack: Option<crate::stack::Definition>,
        }
        let document = Document::deserialize(deserializer)?;
        match (document.apps, document.stack) {
            (Some(apps), None) => Ok(Self { apps, stack: None }),
            (None, Some(stack)) => Ok(Self {
                apps: indexmap::IndexMap::new(),
                stack: Some(stack),
            }),
            (None, None) => Err(serde::de::Error::custom(
                "the file declares no apps or stack; declare exactly one of apps or stack",
            )),
            _ => Err(serde::de::Error::custom(
                "declare exactly one of apps or stack",
            )),
        }
    }
}

fn unique_optional_map<'de, D, T>(
    deserializer: D,
) -> Result<Option<indexmap::IndexMap<String, T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    unique_map(deserializer).map(Some)
}

fn present_stack<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::stack::Definition>, D::Error> {
    crate::stack::Definition::deserialize(deserializer).map(Some)
}

fn volume_path<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let path = String::deserialize(deserializer)?;
    if path.is_empty() {
        return Err(serde::de::Error::custom("a volume path cannot be empty"));
    }
    Ok(path)
}

/// One app: what each copy runs, and how many copies run where.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileApp {
    /// The container image, as `docker pull` takes it, for example
    /// `ghcr.io/acme/shop:2026-09-26.1` or `nginx:1.27`. grund resolves the
    /// tag to a digest once, at deploy, and every copy runs that digest.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[schemars(!default, !skip_serializing_if, length(min = 1))]
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
    #[serde(deserialize_with = "unique_map")]
    pub env: indexmap::IndexMap<String, String>,
    /// Environment variables taken from the organisation's secrets: the
    /// variable's name, then the secret's. The value never appears in the
    /// file. At most 50.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    #[serde(deserialize_with = "unique_map")]
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
    /// App-owned storage, by name. Omission only removes a mount from this
    /// release; it never deletes a volume. Volumes require exactly one copy.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    #[schemars(extend("propertyNames" = {"pattern": "^[a-z0-9]+(?:-[a-z0-9]+)*$", "maxLength": 32}))]
    #[serde(deserialize_with = "unique_map")]
    pub volumes: indexmap::IndexMap<String, FileVolume>,
}

pub(crate) fn unique_map<'de, D, T>(
    deserializer: D,
) -> Result<indexmap::IndexMap<String, T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct UniqueMap<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for UniqueMap<T> {
        type Value = indexmap::IndexMap<String, T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a mapping with distinct names")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut volumes = indexmap::IndexMap::new();
            while let Some((name, volume)) = map.next_entry::<String, T>()? {
                if volumes.contains_key(&name) {
                    return Err(serde::de::Error::custom(format!("duplicate name `{name}`")));
                }
                volumes.insert(name, volume);
            }
            Ok(volumes)
        }
    }

    deserializer.deserialize_map(UniqueMap(std::marker::PhantomData))
}

/// One volume mounted by this app. An omitted source uses an own-machine
/// managed directory unless size_gib requests hosted block storage.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileVolume {
    /// Absolute directory path in the container; paths must not overlap.
    #[schemars(length(min = 2, max = 4096))]
    #[schemars(extend("pattern" = "^/(?!\\.\\.?(/|$))[^/\\u0000-\\u001f]+(?:/(?!\\.\\.?(/|$))[^/\\u0000-\\u001f]+)*$"))]
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        deserialize_with = "volume_path"
    )]
    #[schemars(required)]
    pub path: String,
    /// Existing absolute host directory on an own machine, allowed by its
    /// local policy. Leave out for a managed or hosted volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("pattern" = "^/(?!\\.\\.?(/|$))[^/\\u0000-\\u001f]+(?:/(?!\\.\\.?(/|$))[^/\\u0000-\\u001f]+)*$", "maxLength" = 4096))]
    pub source: Option<String>,
    /// Hosted block volume capacity in GiB (1 to 4096). Leave out for an
    /// own-machine directory with no promised quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 4096))]
    pub size_gib: Option<u64>,
    /// `daily` opts into daily backups (requires a configured destination).
    /// Omitted or `off` means no scheduled backups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<FileBackup>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileBackup {
    Off,
    Daily,
}

/// A port the app listens on.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
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
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
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
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilePlacement {
    /// Labels a machine must carry, each with this value, as set on the
    /// Machines page, for example `disk: ssd`. At most 16.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    #[schemars(extend("maxProperties" = 16))]
    #[serde(deserialize_with = "unique_map")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileMachineKind {
    /// The organisation's own machines.
    Own,
    /// Machines grund hosts.
    Hosted,
}

/// How a release rolls out.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
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

pub(crate) fn read(text: &str) -> Result<GrundFile, SpecError> {
    if text.len() > crate::stack::MAX_FILE_BYTES {
        return refuse(FILE_NAME, "use at most 1 MiB");
    }
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
        if text.len() <= crate::stack::MAX_FILE_BYTES
            && read(text).is_ok_and(|file| file.stack.is_some())
        {
            return refuse(
                "stack",
                "this file declares a stack; use grund stack deploy",
            );
        }
        return refuse(FILE_NAME, "use at most 64 KiB");
    }
    let file = read(text)?;
    if file.stack.is_some() {
        return refuse(
            "stack",
            "this file declares a stack; use grund stack deploy",
        );
    }
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
    normalize(name, app)
}

pub(crate) fn normalize(name: &str, app: &FileApp) -> Result<Declared, SpecError> {
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
    let volumes = app
        .volumes
        .iter()
        .map(|(name, volume)| VolumeSpec {
            name: name.clone(),
            path: volume.path.clone(),
            source: volume.source.clone(),
            size_gib: volume.size_gib,
            backup: matches!(volume.backup, Some(FileBackup::Daily)),
        })
        .collect();
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
        volumes,
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
    if !spec.volumes.is_empty() && settings.copies.unwrap_or(1) != 1 {
        return refuse(
            format!("apps.{name}.copies"),
            "volumes require exactly one copy",
        );
    }
    let block_storage = spec.volumes.iter().any(|volume| volume.size_gib.is_some());
    if !spec.volumes.is_empty()
        && ((settings.kind == "hosted" && !block_storage)
            || (settings.kind == "own" && block_storage))
    {
        return refuse(
            format!("apps.{name}.placement.kind"),
            "hosted machines use sized block volumes; own machines use directories",
        );
    }
    Ok(Declared {
        name: name.to_string(),
        spec,
        settings,
    })
}

pub(crate) fn placement_input(placement: Option<&FilePlacement>) -> SettingsInput {
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

pub(crate) fn file_app(spec: &AppSpec, settings: &AppSettings) -> FileApp {
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
        volumes: spec
            .volumes
            .iter()
            .map(|v| {
                (
                    v.name.clone(),
                    FileVolume {
                        path: v.path.clone(),
                        source: v.source.clone(),
                        size_gib: v.size_gib,
                        backup: v.backup.then_some(FileBackup::Daily),
                    },
                )
            })
            .collect(),
    }
}

/// The file that declares this app as it runs now, for the dashboard's
/// Copy and Download. Settings at their defaults are left out, keys come in
/// the order of the types above, and the first line points editors at
/// `schema_url` (the instance's [`SCHEMA_PATH`]).
pub fn render(name: &str, spec: &AppSpec, settings: &AppSettings, schema_url: &str) -> String {
    let mut apps = indexmap::IndexMap::new();
    apps.insert(name.to_string(), file_app(spec, settings));
    let body = yaml::to_string(&GrundFile { apps, stack: None });
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
    fn own_machine_volumes_accept_managed_and_existing_directories_and_export() {
        let text = "apps:\n  photos:\n    image: example/photos:1\n    volumes:\n      data:\n        path: /data\n      media:\n        path: /var/media\n        source: /srv/photos\n        backup: daily\n";
        let photos = parse_app(text, "photos").unwrap();
        assert_eq!(
            photos.spec.volumes,
            vec![
                VolumeSpec {
                    name: "data".into(),
                    path: "/data".into(),
                    source: None,
                    size_gib: None,
                    backup: false,
                },
                VolumeSpec {
                    name: "media".into(),
                    path: "/var/media".into(),
                    source: Some("/srv/photos".into()),
                    size_gib: None,
                    backup: true,
                },
            ]
        );
        let exported = render(
            "photos",
            &photos.spec,
            &AppSettings::validate(photos.settings).unwrap(),
            "https://grund.example/schema/grund.json",
        );
        assert_eq!(parse_app(&exported, "photos").unwrap().spec, photos.spec);
        assert!(schema_validator().is_valid(&as_json(text)), "{text}");
        assert!(
            schema_validator().is_valid(&as_json(&exported)),
            "{exported}"
        );
        assert!(!exported.contains("backup: off"), "{exported}");
        let off = text.replace("backup: daily", "backup: off");
        assert!(!parse_app(&off, "photos").unwrap().spec.volumes[1].backup);
    }

    #[test]
    fn sized_volumes_roundtrip_and_refuse_out_of_range_capacity() {
        let prefix = "apps:\n  photos:\n    image: example/photos:1\n    volumes:\n      data:\n        path: /data\n        size_gib: ";
        for size in [1, 4096] {
            let file = format!("{prefix}{size}\n");
            let photos = parse_app(&file, "photos").unwrap();
            assert_eq!(photos.spec.volumes[0].size_gib, Some(size));
            let exported = render(
                "photos",
                &photos.spec,
                &AppSettings::validate(photos.settings).unwrap(),
                "https://grund.example/schema/grund.json",
            );
            assert_eq!(parse_app(&exported, "photos").unwrap().spec, photos.spec);
            assert!(schema_validator().is_valid(&as_json(&file)), "{file}");
            assert!(
                schema_validator().is_valid(&as_json(&exported)),
                "{exported}"
            );
        }
        for size in [0, 4097] {
            let file = format!("{prefix}{size}\n");
            assert_eq!(
                parse_app(&file, "photos").unwrap_err().field,
                "apps.photos.volumes[0].size_gib"
            );
            assert!(!schema_validator().is_valid(&as_json(&file)), "{file}");
        }
    }

    #[test]
    fn hosted_block_volumes_keep_placement_and_data_settings_through_file_edits() {
        let text = "apps:\n  database:\n    image: example/postgres:17\n    placement:\n      kind: hosted\n    volumes:\n      data:\n        path: /var/lib/postgresql/data\n        size_gib: 10\n        backup: daily\n";
        let declared = parse_app(text, "database").unwrap();
        let settings = AppSettings::validate(declared.settings).unwrap();
        let edited = render(
            "database",
            &declared.spec,
            &settings,
            "https://example.test",
        );
        let reparsed = parse_app(&edited, "database").unwrap();
        assert_eq!(reparsed.spec, declared.spec);
        assert_eq!(AppSettings::validate(reparsed.settings).unwrap(), settings);
        let wrong_target = text.replace("kind: hosted", "kind: own");
        assert_eq!(
            parse_app(&wrong_target, "database").unwrap_err().field,
            "apps.database.placement.kind"
        );
    }

    #[test]
    fn volume_files_refuse_invalid_paths_quota_duplicates_and_multiple_copies() {
        let prefix = "apps:\n  photos:\n    image: example/photos:1\n    volumes:\n";
        for (body, field) in [
            ("      x: {path: data}\n", "apps.photos.volumes[0].path"),
            ("      x: {path: /}\n", "apps.photos.volumes[0].path"),
            ("      x: {path: /a/../b}\n", "apps.photos.volumes[0].path"),
            ("      x: {path: /a//b}\n", "apps.photos.volumes[0].path"),
            ("      x: {path: /a/}\n", "apps.photos.volumes[0].path"),
            (
                "      x: {path: /data, source: relative}\n",
                "apps.photos.volumes[0].source",
            ),
            (
                "      x: {path: /data, source: /srv/../data}\n",
                "apps.photos.volumes[0].source",
            ),
            (
                "      x: {path: /data}\n      y: {path: /data/cache}\n",
                "apps.photos.volumes[1].path",
            ),
            (
                "      x: {path: /data, source: /srv/a}\n      y: {path: /other, source: /srv/a/b}\n",
                "apps.photos.volumes[1].source",
            ),
            (
                "      x: {path: /data}\n      X: {path: /other}\n",
                "apps.photos.volumes[1].name",
            ),
        ] {
            let file = format!("{prefix}{body}");
            assert_eq!(
                parse_app(&file, "photos").unwrap_err().field,
                field,
                "{file}"
            );
        }
        let duplicate = format!("{prefix}      x: {{path: /data}}\n      x: {{path: /other}}\n");
        assert!(parse_app(&duplicate, "photos").is_err(), "{duplicate}");
        for body in [
            "      x: {path: /data, size: 1 GiB}\n",
            "      x: {path: /data, backup: weekly}\n",
            "      x: {path: /data, backup: true}\n",
            "      x: [invalid]\n",
        ] {
            let file = format!("{prefix}{body}");
            assert!(parse_app(&file, "photos").is_err(), "{file}");
        }
        let many = format!("{prefix}      x: {{path: /data}}\n");
        let many = many.replace("    volumes:", "    copies: 2\n    volumes:");
        assert_eq!(
            parse_app(&many, "photos").unwrap_err().field,
            "apps.photos.copies"
        );
        let hosted = many.replace("copies: 2", "placement:\n      kind: hosted");
        assert_eq!(
            parse_app(&hosted, "photos").unwrap_err().field,
            "apps.photos.placement.kind"
        );
        assert!(!schema_validator().is_valid(&as_json(&format!(
            "{prefix}      x: {{path: /data, size: 1 GiB}}\n"
        ))));
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
            "apps:\n  a:\n    image: x\n    env:\n      l0: &l0 [lol, lol, lol, lol, lol, lol, lol, lol, lol]\n",
        );
        for level in 1..10 {
            let prev = level - 1;
            let row = vec![format!("*l{prev}"); 9].join(", ");
            bomb.push_str(&format!("      l{level}: &l{level} [{row}]\n"));
        }
        let started = std::time::Instant::now();
        let error = yaml::from_str::<serde_json::Value>(&bomb).unwrap_err();
        assert!(error.message.contains("alias"), "{error}");
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
        assert!(!validator.is_valid(&as_json("apps:\n  web:\n    image: nginx\n    copis: 2\n")));
        assert!(!validator.is_valid(&as_json("apps:\n  web:\n    copies: 2\n")));
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
            "schema/grund.json is stale: run GRUND_WRITE_SCHEMA=1 cargo test -p grund-config"
        );
    }
}
