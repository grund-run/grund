//! What one release runs, and the settings of an app that are not per
//! release (grund-docs design/apps.md §3.1, §3.4, §8.2, §15), each
//! validated with every default filled in: a value of these types that came
//! out of `validate` is within every limit.

use serde::{Deserialize, Serialize};

use crate::labels::Labels;

/// The most ports an app may declare.
pub const MAX_PORTS: usize = 8;
/// The most public ports an app may declare.
pub const MAX_PUBLIC_PORTS: usize = 2;
/// The most plain settings a release may carry.
pub const MAX_ENV: usize = 128;
/// Their total size, names and values together.
pub const MAX_ENV_BYTES: usize = 32 * 1024;
/// The most secrets an app may name.
pub const MAX_SECRETS: usize = 50;
/// The largest secret value.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
/// The most copies of one app.
pub const MAX_COPIES: u32 = 20;
/// The most apps an organisation may have.
pub const MAX_APPS_PER_ORGANISATION: i64 = 50;
/// The most arguments a command may have, and their total size.
pub const MAX_COMMAND_ARGS: usize = 64;
pub const MAX_COMMAND_BYTES: usize = 8 * 1024;
/// The longest image reference.
pub const MAX_IMAGE_REFERENCE: usize = 512;

/// The signals a release may stop its copies with.
pub const STOP_SIGNALS: &[&str] = &[
    "SIGTERM", "SIGINT", "SIGQUIT", "SIGUSR1", "SIGUSR2", "SIGHUP",
];

/// Why a spec or settings were refused: the field, and what is wrong with
/// it, in words for the person who wrote it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{field}: {problem}")]
pub struct SpecError {
    pub field: String,
    pub problem: String,
}

fn refuse<T>(field: impl Into<String>, problem: impl Into<String>) -> Result<T, SpecError> {
    Err(SpecError {
        field: field.into(),
        problem: problem.into(),
    })
}

/// An app's name: 1–32 of `a-z 0-9` with single hyphens between them. It is
/// in hostnames, so it never changes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppName(String);

impl AppName {
    pub fn parse(input: &str) -> Result<Self, SpecError> {
        let name = input.trim().to_ascii_lowercase();
        if !(1..=32).contains(&name.len()) {
            return refuse("name", "use 1 to 32 characters");
        }
        let grammar = name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !name.starts_with('-')
            && !name.ends_with('-')
            && !name.contains("--");
        if !grammar {
            return refuse(
                "name",
                "use only letters a–z, digits and single hyphens between them",
            );
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AppName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An OCI image reference, normalised: `docker.io/library/nginx:latest`
/// for `nginx`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImageReference {
    /// The registry's host, with a port when it has one: `docker.io`,
    /// `ghcr.io`, `localhost:5000`.
    pub registry: String,
    /// `library/nginx`, `acme/shop`.
    pub repository: String,
    /// Unset when only a digest was given.
    pub tag: Option<String>,
    /// `sha256:<64 lowercase hex>`, when the reference pins one.
    pub digest: Option<String>,
}

/// Whether `text` is `sha256:` and 64 lowercase hex digits.
pub fn is_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

impl ImageReference {
    /// Parses `[registry/]repository[:tag][@sha256:…]`. With neither a tag
    /// nor a digest, the tag is `latest`.
    pub fn parse(input: &str) -> Result<Self, SpecError> {
        let input = input.trim();
        if input.is_empty() {
            return refuse("image", "name an image, for example nginx:1.27");
        }
        if input.len() > MAX_IMAGE_REFERENCE {
            return refuse(
                "image",
                format!("use at most {MAX_IMAGE_REFERENCE} characters"),
            );
        }
        if input
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return refuse("image", "an image reference has no spaces");
        }
        let (name, digest) = match input.split_once('@') {
            Some((name, digest)) => {
                if !is_digest(digest) {
                    return refuse(
                        "image",
                        "a digest is sha256: and 64 lowercase hexadecimal digits",
                    );
                }
                (name, Some(digest.to_string()))
            }
            None => (input, None),
        };
        let (registry, rest) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_ascii_lowercase(), rest)
            }
            _ => ("docker.io".to_string(), name),
        };
        let (repository, tag) = match rest.rsplit_once(':') {
            Some((repository, tag)) if !tag.contains('/') => (repository, Some(tag.to_string())),
            _ => (rest, None),
        };
        let repository = if registry == "docker.io" && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository.to_string()
        };
        let component_ok = |c: &str| {
            !c.is_empty()
                && c.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                })
                && c.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        };
        if !repository.split('/').all(component_ok) {
            return refuse(
                "image",
                "a repository is lowercase letters, digits, '.', '_' and '-', separated by '/'",
            );
        }
        if let Some(tag) = &tag
            && (tag.is_empty()
                || tag.len() > 128
                || !tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
        {
            return refuse(
                "image",
                "a tag is at most 128 letters, digits, '.', '_' and '-'",
            );
        }
        let tag = match (&tag, &digest) {
            (None, None) => Some("latest".to_string()),
            _ => tag,
        };
        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// The reference with this digest pinned, for the runtime to fetch:
    /// `docker.io/library/nginx@sha256:…`.
    pub fn pinned(&self, digest: &str) -> String {
        format!("{}/{}@{digest}", self.registry, self.repository)
    }
}

impl std::fmt::Display for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(tag) = &self.tag {
            write!(f, ":{tag}")?;
        }
        if let Some(digest) = &self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

/// How a port is spoken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Http,
    H2c,
    Tcp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::H2c => "h2c",
            Protocol::Tcp => "tcp",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "http" => Some(Protocol::Http),
            "h2c" => Some(Protocol::H2c),
            "tcp" => Some(Protocol::Tcp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortSpec {
    pub name: String,
    pub port: u16,
    pub protocol: Protocol,
    pub public: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// A secret of the app, handed to it as an environment variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretEnv {
    pub env: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CheckKind {
    Http { path: String },
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckSpec {
    #[serde(flatten)]
    pub kind: CheckKind,
    pub port: u16,
    pub interval_ms: u32,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StopSpec {
    pub signal: String,
    pub grace_seconds: u32,
}

impl Default for StopSpec {
    fn default() -> Self {
        Self {
            signal: "SIGTERM".into(),
            grace_seconds: 30,
        }
    }
}

/// Everything one release runs. A value from [`AppSpec::validate`] has every
/// default filled in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppSpec {
    /// As the customer gave it; [`ImageReference::parse`] accepts it.
    pub image: String,
    pub command: Vec<String>,
    pub ports: Vec<PortSpec>,
    pub memory_mib: u64,
    pub cpu_millis: u32,
    pub env: Vec<EnvVar>,
    pub secrets: Vec<SecretEnv>,
    pub check: Option<CheckSpec>,
    pub stop: StopSpec,
}

fn env_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Whether `name` is a valid secret name: `[a-z0-9][a-z0-9-]{0,62}`.
pub fn secret_name_ok(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl AppSpec {
    /// The spec with every default filled in, or the first thing wrong with
    /// it. Zero and empty values mean "the default", as on the wire.
    pub fn validate(mut self) -> Result<Self, SpecError> {
        ImageReference::parse(&self.image)?;
        self.image = self.image.trim().to_string();
        if self.command.len() > MAX_COMMAND_ARGS
            || self.command.iter().map(String::len).sum::<usize>() > MAX_COMMAND_BYTES
        {
            return refuse(
                "command",
                format!("use at most {MAX_COMMAND_ARGS} arguments and {MAX_COMMAND_BYTES} bytes"),
            );
        }
        if self.command.iter().any(|a| a.contains('\0')) {
            return refuse("command", "an argument cannot contain a NUL byte");
        }
        if self.ports.len() > MAX_PORTS {
            return refuse("ports", format!("declare at most {MAX_PORTS} ports"));
        }
        if self.ports.iter().filter(|p| p.public).count() > MAX_PUBLIC_PORTS {
            return refuse(
                "ports",
                format!("at most {MAX_PUBLIC_PORTS} ports can be public"),
            );
        }
        for (i, port) in self.ports.iter().enumerate() {
            let name_ok = (1..=15).contains(&port.name.len())
                && port
                    .name
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_lowercase())
                && port
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !name_ok {
                return refuse(
                    format!("ports[{i}].name"),
                    "use 1 to 15 of a–z, 0–9 and '-', starting with a letter",
                );
            }
            if port.port == 0 {
                return refuse(format!("ports[{i}].port"), "use 1 to 65535");
            }
            if self.ports[..i]
                .iter()
                .any(|p| p.name == port.name || p.port == port.port)
            {
                return refuse(
                    format!("ports[{i}]"),
                    "each port needs its own name and number",
                );
            }
        }
        if self.memory_mib == 0 {
            self.memory_mib = 512;
        }
        if !(16..=262_144).contains(&self.memory_mib) {
            return refuse("resources.memory_mib", "use 16 to 262144 MiB");
        }
        if self.cpu_millis == 0 {
            self.cpu_millis = 1000;
        }
        if !(10..=64_000).contains(&self.cpu_millis) {
            return refuse("resources.cpu_millis", "use 10 to 64000 (0.01 to 64 CPUs)");
        }
        if self.env.len() > MAX_ENV
            || self
                .env
                .iter()
                .map(|e| e.name.len() + e.value.len())
                .sum::<usize>()
                > MAX_ENV_BYTES
        {
            return refuse(
                "env",
                format!("use at most {MAX_ENV} variables and 32 KiB together"),
            );
        }
        for (i, var) in self.env.iter().enumerate() {
            if !env_name_ok(&var.name) {
                return refuse(
                    format!("env[{i}].name"),
                    "a variable is letters, digits and '_', not starting with a digit",
                );
            }
            if var.value.contains('\0') {
                return refuse(
                    format!("env[{i}].value"),
                    "a value cannot contain a NUL byte",
                );
            }
            if self.env[..i].iter().any(|e| e.name == var.name) {
                return refuse(format!("env[{i}].name"), "each variable once");
            }
        }
        if self.secrets.len() > MAX_SECRETS {
            return refuse("secrets", format!("name at most {MAX_SECRETS} secrets"));
        }
        for (i, secret) in self.secrets.iter().enumerate() {
            if !env_name_ok(&secret.env) {
                return refuse(
                    format!("secrets[{i}].env"),
                    "a variable is letters, digits and '_', not starting with a digit",
                );
            }
            if !secret_name_ok(&secret.secret) {
                return refuse(
                    format!("secrets[{i}].secret"),
                    "a secret's name is a–z, 0–9 and '-', at most 63",
                );
            }
            if self.env.iter().any(|e| e.name == secret.env)
                || self.secrets[..i].iter().any(|s| s.env == secret.env)
            {
                return refuse(format!("secrets[{i}].env"), "each variable once");
            }
        }
        if let Some(check) = &mut self.check {
            if check.port == 0 {
                match self.ports.first() {
                    Some(port) => check.port = port.port,
                    None => {
                        return refuse(
                            "check.port",
                            "a check needs a port: declare one, or name it",
                        );
                    }
                }
            }
            if !self.ports.iter().any(|p| p.port == check.port) {
                return refuse("check.port", "check one of the app's ports");
            }
            if let CheckKind::Http { path } = &check.kind
                && (!path.starts_with('/')
                    || path.len() > 512
                    || path
                        .bytes()
                        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control()))
            {
                return refuse(
                    "check.http_path",
                    "a path starts with '/', has no spaces, and is at most 512 bytes",
                );
            }
            if check.interval_ms == 0 {
                check.interval_ms = 2000;
            }
            if check.timeout_ms == 0 {
                check.timeout_ms = 1000.min(check.interval_ms.saturating_sub(1)).max(100);
            }
            if !(500..=60_000).contains(&check.interval_ms) {
                return refuse("check.interval_ms", "use 500 to 60000");
            }
            if !(100..=30_000).contains(&check.timeout_ms) || check.timeout_ms >= check.interval_ms
            {
                return refuse("check.timeout_ms", "use 100 to 30000, below the interval");
            }
        }
        if self.stop.signal.is_empty() {
            self.stop.signal = "SIGTERM".into();
        }
        self.stop.signal = self.stop.signal.to_ascii_uppercase();
        if !self.stop.signal.starts_with("SIG") {
            self.stop.signal = format!("SIG{}", self.stop.signal);
        }
        if !STOP_SIGNALS.contains(&self.stop.signal.as_str()) {
            return refuse(
                "stop.signal",
                format!("use one of {}", STOP_SIGNALS.join(", ")),
            );
        }
        if self.stop.grace_seconds == 0 {
            self.stop.grace_seconds = 30;
        }
        if self.stop.grace_seconds > 300 {
            return refuse("stop.grace_seconds", "use at most 300");
        }
        Ok(self)
    }
}

/// How a rollout replaces copies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutSettings {
    pub max_surge: u32,
    pub max_unavailable: u32,
    pub min_ready_seconds: u32,
    pub ready_deadline_seconds: u32,
    pub drain_seconds: u32,
}

impl Default for RolloutSettings {
    fn default() -> Self {
        Self {
            max_surge: 1,
            max_unavailable: 0,
            min_ready_seconds: 10,
            ready_deadline_seconds: 300,
            drain_seconds: 30,
        }
    }
}

/// Which machines an app's copies run on, beyond their names
/// (grund-docs design/apps.md §5.2, §5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineKind {
    /// The organisation's own machines, joined by their owner.
    Own,
    /// Machines grund leases to the organisation.
    Hosted,
}

impl MachineKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MachineKind::Own => "own",
            MachineKind::Hosted => "hosted",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "own" => Some(MachineKind::Own),
            "hosted" => Some(MachineKind::Hosted),
            _ => None,
        }
    }
}

/// The most other apps one app may name in `near` and in `apart`.
pub const MAX_RELATED_APPS: usize = 10;

/// An app's placement rules besides machine names (apps.md §5.6). The
/// default places anywhere, spread over machines.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRules {
    /// Labels a machine must carry, every one with this value.
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
    /// Only own machines, or only hosted ones; `None`: either.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MachineKind>,
    /// A label key whose values are failure domains (`zone`): copies go to
    /// the value with the fewest of them first, then to the machine with
    /// the fewest. Machines without the key share one domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spread_by: Option<String>,
    /// Other apps of the organisation whose machines are preferred, after
    /// the spread.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub near: Vec<String>,
    /// Other apps of the organisation whose machines are avoided, after the
    /// spread.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apart: Vec<String>,
}

impl PlacementRules {
    pub fn is_default(&self) -> bool {
        *self == PlacementRules::default()
    }
}

/// What is not per release. A value from [`AppSettings::validate`] has every
/// default filled in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSettings {
    pub copies: u32,
    pub rollout: RolloutSettings,
    /// Machine names the copies may run on; empty: any.
    pub machines: Vec<String>,
    pub reschedule_after_seconds: u32,
    pub auto_rollback: bool,
    #[serde(default, skip_serializing_if = "PlacementRules::is_default")]
    pub placement: PlacementRules,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            copies: 1,
            rollout: RolloutSettings::default(),
            machines: Vec::new(),
            reschedule_after_seconds: 120,
            auto_rollback: true,
            placement: PlacementRules::default(),
        }
    }
}

/// Settings as asked for, with `None` meaning "the default".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsInput {
    pub copies: Option<u32>,
    pub max_surge: Option<u32>,
    pub max_unavailable: Option<u32>,
    pub min_ready_seconds: Option<u32>,
    pub ready_deadline_seconds: Option<u32>,
    pub drain_seconds: Option<u32>,
    pub machines: Vec<String>,
    pub reschedule_after_seconds: Option<u32>,
    pub auto_rollback: Option<bool>,
    /// Label pairs as given, checked by `validate`.
    pub labels: Vec<(String, String)>,
    /// `own`, `hosted`, or empty for either.
    pub kind: String,
    pub spread_by: String,
    pub near: Vec<String>,
    pub apart: Vec<String>,
}

impl AppSettings {
    /// The settings with every default filled in, or the first thing wrong.
    pub fn validate(input: SettingsInput) -> Result<Self, SpecError> {
        let defaults = AppSettings::default();
        let copies = input.copies.filter(|c| *c > 0).unwrap_or(defaults.copies);
        if copies > MAX_COPIES {
            return refuse("copies", format!("use 1 to {MAX_COPIES}"));
        }
        let rollout = RolloutSettings {
            max_surge: input.max_surge.unwrap_or(defaults.rollout.max_surge),
            max_unavailable: input
                .max_unavailable
                .unwrap_or(defaults.rollout.max_unavailable),
            min_ready_seconds: input
                .min_ready_seconds
                .unwrap_or(defaults.rollout.min_ready_seconds),
            ready_deadline_seconds: input
                .ready_deadline_seconds
                .filter(|s| *s > 0)
                .unwrap_or(defaults.rollout.ready_deadline_seconds),
            drain_seconds: input
                .drain_seconds
                .unwrap_or(defaults.rollout.drain_seconds),
        };
        if rollout.max_surge > copies {
            return refuse("rollout.max_surge", "use at most the number of copies");
        }
        if rollout.max_unavailable >= copies.max(1) && rollout.max_unavailable > 0 {
            return refuse(
                "rollout.max_unavailable",
                "use fewer than the number of copies",
            );
        }
        if rollout.max_surge == 0 && rollout.max_unavailable == 0 {
            return refuse(
                "rollout",
                "max_surge and max_unavailable cannot both be 0: nothing could be replaced",
            );
        }
        if rollout.min_ready_seconds > 600 {
            return refuse("rollout.min_ready_seconds", "use at most 600");
        }
        if !(10..=1800).contains(&rollout.ready_deadline_seconds) {
            return refuse("rollout.ready_deadline_seconds", "use 10 to 1800");
        }
        if rollout.drain_seconds > 300 {
            return refuse("rollout.drain_seconds", "use at most 300");
        }
        let reschedule_after_seconds = input
            .reschedule_after_seconds
            .filter(|s| *s > 0)
            .unwrap_or(defaults.reschedule_after_seconds);
        if !(30..=3600).contains(&reschedule_after_seconds) {
            return refuse("reschedule_after_seconds", "use 30 to 3600");
        }
        let mut machines = Vec::new();
        for (i, name) in input.machines.iter().enumerate() {
            let name = crate::names::MachineName::parse(name).map_err(|e| SpecError {
                field: format!("machines[{i}]"),
                problem: e.to_string(),
            })?;
            if !machines.contains(&name.as_str().to_string()) {
                machines.push(name.as_str().to_string());
            }
        }
        if machines.len() > 50 {
            return refuse("machines", "name at most 50 machines");
        }
        let placement = PlacementRules::validate(&input)?;
        Ok(Self {
            copies,
            rollout,
            machines,
            reschedule_after_seconds,
            auto_rollback: input.auto_rollback.unwrap_or(true),
            placement,
        })
    }

    /// These settings with `copies` replaced, validated again.
    pub fn with_copies(&self, copies: u32) -> Result<Self, SpecError> {
        if !(1..=MAX_COPIES).contains(&copies) {
            return refuse("copies", format!("use 1 to {MAX_COPIES}"));
        }
        let mut input = self.as_input();
        input.copies = Some(copies);
        if input.max_surge.is_some_and(|s| s > copies) {
            input.max_surge = Some(copies.min(self.rollout.max_surge.max(1)));
        }
        if input.max_unavailable.is_some_and(|u| u >= copies) {
            input.max_unavailable = Some(copies - 1);
        }
        Self::validate(input)
    }

    /// The input that validates to these settings.
    pub fn as_input(&self) -> SettingsInput {
        SettingsInput {
            copies: Some(self.copies),
            max_surge: Some(self.rollout.max_surge),
            max_unavailable: Some(self.rollout.max_unavailable),
            min_ready_seconds: Some(self.rollout.min_ready_seconds),
            ready_deadline_seconds: Some(self.rollout.ready_deadline_seconds),
            drain_seconds: Some(self.rollout.drain_seconds),
            machines: self.machines.clone(),
            reschedule_after_seconds: Some(self.reschedule_after_seconds),
            auto_rollback: Some(self.auto_rollback),
            labels: self
                .placement
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            kind: self
                .placement
                .kind
                .map(|k| k.as_str().to_string())
                .unwrap_or_default(),
            spread_by: self.placement.spread_by.clone().unwrap_or_default(),
            near: self.placement.near.clone(),
            apart: self.placement.apart.clone(),
        }
    }
}

impl PlacementRules {
    fn validate(input: &SettingsInput) -> Result<Self, SpecError> {
        let labels =
            crate::labels::labels(input.labels.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .map_err(|e| SpecError {
                    field: "placement.labels".into(),
                    problem: e.to_string(),
                })?;
        let kind = match input.kind.trim() {
            "" => None,
            text => Some(MachineKind::parse(text).ok_or_else(|| SpecError {
                field: "placement.kind".into(),
                problem: "use own or hosted".into(),
            })?),
        };
        let spread_by = match input.spread_by.trim() {
            "" => None,
            text => Some(crate::labels::label_key(text).map_err(|e| SpecError {
                field: "placement.spread_by".into(),
                problem: e.to_string(),
            })?),
        };
        let related = |field: &str, names: &[String]| -> Result<Vec<String>, SpecError> {
            let mut out: Vec<String> = Vec::new();
            for (i, name) in names.iter().enumerate() {
                let name = AppName::parse(name).map_err(|e| SpecError {
                    field: format!("placement.{field}[{i}]"),
                    problem: e.problem,
                })?;
                if !out.iter().any(|n| n == name.as_str()) {
                    out.push(name.as_str().to_string());
                }
            }
            if out.len() > MAX_RELATED_APPS {
                return refuse(
                    format!("placement.{field}"),
                    format!("name at most {MAX_RELATED_APPS} apps"),
                );
            }
            Ok(out)
        };
        let near = related("near", &input.near)?;
        let apart = related("apart", &input.apart)?;
        if let Some(both) = near.iter().find(|n| apart.contains(n)) {
            return refuse(
                "placement.apart",
                format!("{both} is also in near; name it in one of them"),
            );
        }
        Ok(Self {
            labels,
            kind,
            spread_by,
            near,
            apart,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> AppSpec {
        AppSpec {
            image: "nginx".into(),
            command: Vec::new(),
            ports: vec![PortSpec {
                name: "http".into(),
                port: 8080,
                protocol: Protocol::Http,
                public: true,
            }],
            memory_mib: 0,
            cpu_millis: 0,
            env: Vec::new(),
            secrets: Vec::new(),
            check: Some(CheckSpec {
                kind: CheckKind::Http {
                    path: "/healthz".into(),
                },
                port: 0,
                interval_ms: 0,
                timeout_ms: 0,
            }),
            stop: StopSpec {
                signal: String::new(),
                grace_seconds: 0,
            },
        }
    }

    #[test]
    fn an_image_reference_is_normalised_as_docker_does() {
        let r = ImageReference::parse("nginx").unwrap();
        assert_eq!(r.to_string(), "docker.io/library/nginx:latest");
        let r = ImageReference::parse("ghcr.io/acme/shop:2026-09-26.1").unwrap();
        assert_eq!(
            (r.registry.as_str(), r.repository.as_str(), r.tag.as_deref()),
            ("ghcr.io", "acme/shop", Some("2026-09-26.1"))
        );
        let r = ImageReference::parse("localhost:5000/app").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.tag.as_deref(), Some("latest"));
        let digest = format!("sha256:{}", "a".repeat(64));
        let r = ImageReference::parse(&format!("traefik/whoami@{digest}")).unwrap();
        assert_eq!(r.tag, None);
        assert_eq!(r.digest.as_deref(), Some(digest.as_str()));
        assert_eq!(
            r.pinned(&digest),
            format!("docker.io/traefik/whoami@{digest}")
        );
    }

    #[test]
    fn a_malformed_image_reference_is_refused() {
        for bad in [
            "",
            "Nginx",
            "nginx@sha256:abc",
            "nginx:bad tag",
            "a//b",
            "nginx:",
            "-x/y",
        ] {
            assert!(ImageReference::parse(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn a_spec_gets_every_default() {
        let spec = spec().validate().unwrap();
        assert_eq!(spec.memory_mib, 512);
        assert_eq!(spec.cpu_millis, 1000);
        assert_eq!(spec.stop, StopSpec::default());
        let check = spec.check.unwrap();
        assert_eq!(
            (check.port, check.interval_ms, check.timeout_ms),
            (8080, 2000, 1000)
        );
    }

    #[test]
    fn a_spec_beyond_a_limit_is_refused_naming_the_field() {
        let field = |spec: AppSpec| spec.validate().unwrap_err().field;
        let mut s = spec();
        s.ports.push(s.ports[0].clone());
        assert_eq!(field(s), "ports[1]");
        let mut s = spec();
        s.memory_mib = 1 << 30;
        assert_eq!(field(s), "resources.memory_mib");
        let mut s = spec();
        s.env = vec![EnvVar {
            name: "1X".into(),
            value: "v".into(),
        }];
        assert_eq!(field(s), "env[0].name");
        let mut s = spec();
        s.env = (0..=MAX_ENV)
            .map(|i| EnvVar {
                name: format!("V{i}"),
                value: String::new(),
            })
            .collect();
        assert_eq!(field(s), "env");
        let mut s = spec();
        s.secrets = vec![SecretEnv {
            env: "PASSWORD".into(),
            secret: "Not OK".into(),
        }];
        assert_eq!(field(s), "secrets[0].secret");
        let mut s = spec();
        s.check.as_mut().unwrap().port = 9;
        assert_eq!(field(s), "check.port");
        let mut s = spec();
        s.ports.clear();
        assert_eq!(field(s), "check.port");
        let mut s = spec();
        s.stop.signal = "SIGKILL".into();
        assert_eq!(field(s), "stop.signal");
        let mut s = spec();
        s.stop.grace_seconds = 301;
        assert_eq!(field(s), "stop.grace_seconds");
        let mut s = spec();
        s.check.as_mut().unwrap().kind = CheckKind::Http {
            path: "healthz".into(),
        };
        assert_eq!(field(s), "check.http_path");
    }

    #[test]
    fn a_stop_signal_may_be_given_without_its_prefix() {
        let mut s = spec();
        s.stop.signal = "quit".into();
        assert_eq!(s.validate().unwrap().stop.signal, "SIGQUIT");
    }

    #[test]
    fn settings_default_to_the_designs_numbers() {
        let settings = AppSettings::validate(SettingsInput::default()).unwrap();
        assert_eq!(settings, AppSettings::default());
        assert_eq!(settings.rollout.max_surge, 1);
        assert_eq!(settings.rollout.max_unavailable, 0);
        assert_eq!(settings.reschedule_after_seconds, 120);
    }

    #[test]
    fn settings_that_could_never_replace_a_copy_are_refused() {
        let input = SettingsInput {
            copies: Some(2),
            max_surge: Some(0),
            max_unavailable: Some(0),
            ..Default::default()
        };
        assert_eq!(AppSettings::validate(input).unwrap_err().field, "rollout");
        let input = SettingsInput {
            copies: Some(21),
            ..Default::default()
        };
        assert_eq!(AppSettings::validate(input).unwrap_err().field, "copies");
        let input = SettingsInput {
            reschedule_after_seconds: Some(10),
            ..Default::default()
        };
        assert_eq!(
            AppSettings::validate(input).unwrap_err().field,
            "reschedule_after_seconds"
        );
    }

    #[test]
    fn scaling_keeps_the_rollout_settings_valid() {
        let settings = AppSettings::validate(SettingsInput {
            copies: Some(3),
            max_surge: Some(3),
            max_unavailable: Some(2),
            ..Default::default()
        })
        .unwrap();
        let scaled = settings.with_copies(1).unwrap();
        assert_eq!(scaled.copies, 1);
        assert_eq!(scaled.rollout.max_surge, 1);
        assert_eq!(scaled.rollout.max_unavailable, 0);
        assert!(settings.with_copies(0).is_err());
    }

    #[test]
    fn app_names_follow_the_slug_grammar() {
        assert_eq!(AppName::parse(" Shop ").unwrap().as_str(), "shop");
        for bad in ["", "-a", "a-", "a--b", "a_b", &"a".repeat(33)] {
            assert!(AppName::parse(bad).is_err(), "{bad} was accepted");
        }
    }
}
