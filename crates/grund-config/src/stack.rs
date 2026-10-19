//! Stack files reuse the ordinary app model and validators, with coordinated placement.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io::Write;

use indexmap::IndexMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::app::file::{
    self, FileApp, FileCheck, FilePlacement, FilePort, FileProtocol, FileResources, Memory,
};
use crate::app::spec::{AppSettings, AppSpec, Protocol, SpecError};

/// The largest raw stack file or serialized expanded stack, in bytes.
pub const MAX_FILE_BYTES: usize = 1024 * 1024;
/// The maximum services in one coordinated deployment.
pub const MAX_SERVICES: usize = 10;

/// The complete desired stack, before catalogue and image resolution.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    /// Organisation-scoped identity, starting with a lowercase letter, at most 32 characters.
    #[schemars(length(min = 1, max = 32))]
    #[schemars(extend("pattern" = "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", "not" = {"const": "machines"}))]
    pub name: String,
    /// Candidate machine names; omitted means any eligible organisation machine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 50))]
    pub machines: Vec<String>,
    /// Only kind and labels are allowed: stacks always place together.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_placement"
    )]
    #[schemars(with = "Option<HardPlacement>")]
    pub placement: Option<FilePlacement>,
    /// The single public HTTP or h2c endpoint; omitted means private.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<PublicTarget>,
    /// Services in declaration order. Duplicate names are refused.
    #[serde(deserialize_with = "file::unique_map")]
    #[schemars(extend("minProperties" = 1, "maxProperties" = 10, "propertyNames" = {"pattern": "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", "maxLength": 32}))]
    pub services: IndexMap<String, Service>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct HardPlacement {
    #[serde(default, deserialize_with = "file::unique_map")]
    #[schemars(extend("maxProperties" = 16))]
    labels: IndexMap<String, String>,
    #[schemars(extend("not" = {"const": "hosted"}))]
    kind: Option<crate::app::file::FileMachineKind>,
}

fn optional_placement<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<FilePlacement>, D::Error> {
    let placement = HardPlacement::deserialize(deserializer)?;
    Ok(Some(FilePlacement {
        labels: placement.labels,
        kind: placement.kind,
        ..FilePlacement::default()
    }))
}

/// One selected service port exposed at the stack address.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicTarget {
    pub service: String,
    pub port: String,
}

/// The replacement policy, independent of ordinary app rolling settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Restart {
    Rolling,
    Exclusive,
}

/// A service reuses the app-file fields, plus dependency and catalogue selection.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Service {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// An existing volume in this retained template service's app, mounted at its canonical path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_volume: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<Restart>,
    #[serde(flatten)]
    pub app: FileApp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceInput {
    template: Option<String>,
    data_volume: Option<String>,
    image: Option<String>,
    command: Option<Vec<String>>,
    #[serde(default, deserialize_with = "optional_env")]
    env: Option<IndexMap<String, String>>,
    #[serde(default, deserialize_with = "optional_env")]
    secrets: Option<IndexMap<String, String>>,
    check: Option<FileCheck>,
    #[serde(default)]
    depends_on: Vec<String>,
    restart: Option<Restart>,
    #[serde(default)]
    ports: Option<Vec<PrivatePort>>,
    #[serde(default, rename = "machines", deserialize_with = "forbidden")]
    _machines: (),
    #[serde(default, rename = "placement", deserialize_with = "forbidden")]
    _placement: (),
    #[serde(default, rename = "reschedule_after", deserialize_with = "forbidden")]
    _reschedule_after: (),
    #[serde(default, rename = "auto_rollback", deserialize_with = "forbidden")]
    _auto_rollback: (),
    #[serde(flatten)]
    app: FileApp,
}

fn optional_env<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<IndexMap<String, String>>, D::Error> {
    file::unique_map(deserializer).map(Some)
}

fn forbidden<'de, D: serde::Deserializer<'de>>(_: D) -> Result<(), D::Error> {
    Err(serde::de::Error::custom(
        "this field is controlled by the stack",
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivatePort {
    name: String,
    port: u16,
    protocol: Option<FileProtocol>,
}

impl<'de> Deserialize<'de> for Service {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let input = ServiceInput::deserialize(deserializer)?;
        if input.template.is_some()
            && (input.image.is_some()
                || input.command.is_some()
                || input.env.is_some()
                || input.secrets.is_some()
                || input.check.is_some()
                || input.ports.is_some())
        {
            return Err(serde::de::Error::custom(
                "template image, command, ports, env, secrets and readiness come from the catalogue",
            ));
        }
        let mut app = input.app;
        app.image = input.image.unwrap_or_default();
        app.command = input.command.unwrap_or_default();
        app.env = input.env.unwrap_or_default();
        app.secrets = input.secrets.unwrap_or_default();
        app.check = input.check;
        app.ports = input
            .ports
            .unwrap_or_default()
            .into_iter()
            .map(|port| FilePort {
                name: port.name,
                port: port.port,
                protocol: port.protocol,
                public: false,
            })
            .collect();
        Ok(Self {
            template: input.template,
            data_volume: input.data_volume,
            depends_on: input.depends_on,
            restart: input.restart,
            app,
        })
    }
}

impl JsonSchema for Service {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "StackService".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut value = serde_json::to_value(FileApp::json_schema(generator)).unwrap_or_default();
        if let Some(properties) = value
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
        {
            for field in ["machines", "placement", "reschedule_after", "auto_rollback"] {
                properties.remove(field);
            }
            properties.insert(
                "template".into(),
                serde_json::json!({"type": "string", "minLength": 1}),
            );
            properties.insert(
                "data_volume".into(),
                serde_json::json!({"type": "string", "minLength": 1, "maxLength": 32, "pattern": "^[a-z0-9]+(?:-[a-z0-9]+)*$"}),
            );
            properties.insert("depends_on".into(), serde_json::json!({"type": "array", "maxItems": 9, "uniqueItems": true, "items": {"type": "string"}}));
            properties.insert(
                "restart".into(),
                serde_json::json!({"type": "string", "enum": ["rolling", "exclusive"]}),
            );
            properties.insert("ports".into(), serde_json::json!({"type": "array", "maxItems": 8, "items": {"type": "object", "additionalProperties": false, "required": ["name", "port"], "properties": {"name": {"type": "string"}, "port": {"type": "integer", "minimum": 1, "maximum": 65535}, "protocol": {"type": "string", "enum": ["http", "h2c", "tcp"]}}}}));
        }
        let object = value.as_object_mut().expect("an app schema is an object");
        object.remove("required");
        object.insert("oneOf".into(), serde_json::json!([
            {"required": ["image"], "not": {"required": ["template"]}, "properties": {"data_volume": false, "volumes": {"additionalProperties": {"required": ["path"]}}}},
            {"required": ["template"], "not": {"required": ["image"]}, "properties": {
                "copies": {"const": 1}, "command": false, "ports": false, "env": false, "secrets": false, "check": false,
                "volumes": {
                    "type": "object", "additionalProperties": false,
                    "properties": {
                        "data": {
                            "type": "object", "additionalProperties": false,
                            "properties": {"backup": {"type": "string", "enum": ["off", "daily"]}}
                        }
                    }
                }
            }}
        ]));
        object.insert("allOf".into(), serde_json::json!([
            {"if": {"properties": {"restart": {"const": "exclusive"}}, "required": ["restart"]}, "then": {"properties": {"copies": {"const": 1}, "release": {"not": {"anyOf": [{"required": ["max_surge"]}, {"required": ["max_unavailable"]}]}}}}},
            {"properties": {"release": {"properties": {"max_surge": {"minimum": 1}}}}}
        ]));
        let mut volume = serde_json::to_value(crate::app::file::FileVolume::json_schema(generator))
            .expect("volume schemas serialize");
        volume
            .as_object_mut()
            .expect("volume schema is an object")
            .remove("required");
        object.get_mut("properties").and_then(serde_json::Value::as_object_mut).expect("app properties exist").insert("volumes".into(), serde_json::json!({"type": "object", "propertyNames": {"pattern": "^[a-z0-9]+(?:-[a-z0-9]+)*$", "maxLength": 32}, "additionalProperties": volume}));
        schemars::Schema::try_from(value).expect("the service schema is an object")
    }
}

/// An environment value obtained from a sibling, never a literal or expanded secret.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRef {
    pub env: String,
    pub service: String,
    pub output: String,
}

fn refuse<T>(field: impl Into<String>, problem: impl Into<String>) -> Result<T, SpecError> {
    Err(SpecError {
        field: field.into(),
        problem: problem.into(),
    })
}

fn name(name: &str, field: &str) -> Result<(), SpecError> {
    let parsed = crate::app::spec::AppName::parse(name).map_err(|error| SpecError {
        field: field.into(),
        problem: error.problem,
    })?;
    if parsed.as_str() != name || !name.as_bytes().first().is_some_and(u8::is_ascii_lowercase) {
        return refuse(
            field,
            "start with a lowercase letter; use lowercase letters, digits and single hyphens, at most 32 characters",
        );
    }
    Ok(())
}

fn reference(env: &str, value: &str, field: &str) -> Result<Option<ConnectionRef>, SpecError> {
    if value.starts_with("$${{") || !value.contains("${{") {
        return Ok(None);
    }
    let Some(expression) = value
        .strip_prefix("${{")
        .and_then(|value| value.strip_suffix("}}"))
    else {
        return refuse(
            field,
            "a connection reference must be the complete value, such as ${{ postgres.url }}",
        );
    };
    let Some((service, output)) = expression.trim().split_once('.') else {
        return refuse(
            field,
            "use ${{ service.url }}, ${{ service.host }} or ${{ service.port }}",
        );
    };
    name(service, field)?;
    if !matches!(
        output,
        "url" | "host" | "port" | "access_key_id" | "secret_access_key" | "region"
    ) {
        return refuse(
            field,
            "the connection output must be url, host, port, access_key_id, secret_access_key or region",
        );
    }
    Ok(Some(ConnectionRef {
        env: env.into(),
        service: service.into(),
        output: output.into(),
    }))
}

impl Service {
    /// Resolves the default from the expanded catalogue spec, not the template name.
    pub fn restart(&self, spec: &AppSpec) -> Restart {
        self.restart.unwrap_or(if spec.volumes.is_empty() {
            Restart::Rolling
        } else {
            Restart::Exclusive
        })
    }

    fn validate(&self, field: &str) -> Result<(), SpecError> {
        if self.app.image.is_empty() == self.template.is_none() {
            return refuse(field, "give exactly one of image or template");
        }
        if self
            .template
            .as_ref()
            .is_some_and(|key| key.trim().is_empty())
        {
            return refuse(format!("{field}.template"), "name a catalogue template");
        }
        if let Some(volume) = &self.data_volume
            && (self.template.is_none()
                || crate::app::spec::AppName::parse(volume)
                    .map_or(true, |name| name.as_str() != volume))
        {
            return refuse(
                format!("{field}.data_volume"),
                "select an app-owned volume name only for a stateful template",
            );
        }
        if !self.app.machines.is_empty()
            || self.app.placement.is_some()
            || self.app.reschedule_after.is_some()
            || self.app.auto_rollback.is_some()
        {
            return refuse(
                field,
                "placement, rescheduling and rollback are controlled by the stack",
            );
        }
        if self.app.ports.iter().any(|port| port.public) {
            return refuse(
                format!("{field}.ports"),
                "use stack.public instead of service public ports",
            );
        }
        if self.app.copies == Some(0) {
            return refuse(format!("{field}.copies"), "use 1 to 20 copies");
        }
        if self.template.is_some() {
            if !self.app.image.is_empty()
                || !self.app.command.is_empty()
                || !self.app.ports.is_empty()
                || !self.app.env.is_empty()
                || !self.app.secrets.is_empty()
                || self.app.check.is_some()
            {
                return refuse(
                    field,
                    "template command, ports, env, secrets and readiness come from the catalogue",
                );
            }
            if self.app.copies.is_some_and(|copies| copies != 1) {
                return refuse(
                    format!("{field}.copies"),
                    "template services require exactly one copy",
                );
            }
            for (key, volume) in &self.app.volumes {
                if key != "data"
                    || !volume.path.is_empty()
                    || volume.source.is_some()
                    || volume.size_gib.is_some()
                {
                    return refuse(
                        format!("{field}.volumes.{key}"),
                        "templates allow only volumes.data.backup as a policy overlay",
                    );
                }
            }
        }
        let owns_volumes = self.template.is_none() && !self.app.volumes.is_empty();
        if owns_volumes && self.restart == Some(Restart::Rolling) {
            return refuse(
                format!("{field}.restart"),
                "volume owners require exclusive restart",
            );
        }
        if self.restart == Some(Restart::Exclusive) || owns_volumes {
            if self.app.copies.is_some_and(|copies| copies != 1) {
                return refuse(
                    format!("{field}.copies"),
                    "exclusive restart requires exactly one copy",
                );
            }
            if self.app.release.as_ref().is_some_and(|release| {
                release.max_surge.is_some() || release.max_unavailable.is_some()
            }) {
                return refuse(
                    format!("{field}.release"),
                    "exclusive restart does not accept max_surge or max_unavailable",
                );
            }
        }
        Ok(())
    }
}

impl Definition {
    /// Checks the complete graph and raw declarations without looking up catalogue entries.
    pub fn validate(&self) -> Result<(), SpecError> {
        name(&self.name, "stack.name")?;
        if self.name == "machines" {
            return refuse("stack.name", "machines is reserved for machine DNS names");
        }
        if self.services.is_empty() || self.services.len() > MAX_SERVICES {
            return refuse("stack.services", "declare between 1 and 10 services");
        }
        if self
            .placement
            .as_ref()
            .is_some_and(|placement| placement.kind == Some(file::FileMachineKind::Hosted))
        {
            return refuse(
                "stack.placement.kind",
                "stacks run on one existing machine; hosted machine rental for stacks isn't available yet",
            );
        }
        if self.placement.as_ref().is_some_and(|placement| {
            placement.spread_by.is_some()
                || !placement.near.is_empty()
                || !placement.apart.is_empty()
        }) {
            return refuse(
                "stack.placement",
                "only kind and labels are allowed for co-located stacks",
            );
        }
        let mut placement = file::placement_input(self.placement.as_ref());
        placement.machines = self.machines.clone();
        AppSettings::validate(placement).map_err(|error| SpecError {
            field: format!("stack.{}", error.field),
            problem: error.problem,
        })?;
        for (service_name, service) in &self.services {
            let field = format!("stack.services.{service_name}");
            name(service_name, &field)?;
            service.validate(&field)?;
            let mut dependencies = BTreeSet::new();
            for dependency in &service.depends_on {
                if dependency == service_name
                    || !self.services.contains_key(dependency)
                    || !dependencies.insert(dependency)
                {
                    return refuse(
                        format!("{field}.depends_on"),
                        "name distinct sibling services, never the service itself",
                    );
                }
            }
            for (env, value) in &service.app.env {
                if let Some(reference) = reference(env, value, &format!("{field}.env.{env}"))?
                    && (!self.services.contains_key(&reference.service)
                        || !service.depends_on.contains(&reference.service))
                {
                    return refuse(
                        format!("{field}.env.{env}"),
                        "connection references require an existing sibling and an explicit depends_on entry",
                    );
                }
            }
            if service.template.is_none() {
                self.service(service_name, None)?;
            }
        }
        let mut ready = BTreeSet::new();
        loop {
            let previous = ready.len();
            for (service_name, service) in &self.services {
                if service
                    .depends_on
                    .iter()
                    .all(|dependency| ready.contains(dependency))
                {
                    ready.insert(service_name.clone());
                }
            }
            if ready.len() == self.services.len() {
                break;
            }
            if ready.len() == previous {
                return refuse("stack.services", "dependency graph contains a cycle");
            }
        }
        if let Some(public) = &self.public {
            let Some(service) = self.services.get(&public.service) else {
                return refuse("stack.public.service", "name a declared service");
            };
            if service.template.is_none() {
                let (spec, _, _) = self.service(&public.service, None)?;
                self.validate_public(&public.service, &spec)?;
            } else if public.port.is_empty() {
                return refuse("stack.public.port", "name an HTTP or h2c port");
            }
        }
        validate_expanded(self)
    }

    fn validate_public(&self, service: &str, spec: &AppSpec) -> Result<(), SpecError> {
        if let Some(public) = &self.public
            && public.service == service
            && !spec.ports.iter().any(|port| {
                port.name == public.port && matches!(port.protocol, Protocol::Http | Protocol::H2c)
            })
        {
            return refuse("stack.public.port", "select a declared HTTP or h2c port");
        }
        Ok(())
    }

    /// Expands one service with a server-supplied catalogue spec and applies existing app validation.
    /// Connection references are returned separately and removed from literal environment values.
    pub fn service(
        &self,
        service_name: &str,
        template_spec: Option<AppSpec>,
    ) -> Result<(AppSpec, AppSettings, Vec<ConnectionRef>), SpecError> {
        let field = format!("stack.services.{service_name}");
        let Some(service) = self.services.get(service_name) else {
            return refuse(field, "service is not declared");
        };
        service.validate(&field)?;
        let app = match (&service.template, template_spec) {
            (None, None) => Cow::Borrowed(&service.app),
            (Some(_), Some(spec)) => {
                let spec = spec.validate()?;
                let mut app = file::file_app(&spec, &AppSettings::default());
                if let Some(resources) = &service.app.resources {
                    let target = app.resources.get_or_insert_with(|| FileResources {
                        memory: Some(Memory::Mib(spec.memory_mib)),
                        cpu: Some(f64::from(spec.cpu_millis) / 1000.0),
                    });
                    if resources.memory.is_some() {
                        target.memory = resources.memory.clone();
                    }
                    if resources.cpu.is_some() {
                        target.cpu = resources.cpu;
                    }
                }
                app.copies = service.app.copies;
                if let Some(stop) = &service.app.stop {
                    app.stop = Some(crate::app::file::FileStop {
                        signal: stop
                            .signal
                            .clone()
                            .or_else(|| Some(spec.stop.signal.clone())),
                        grace: stop.grace.or(Some(spec.stop.grace_seconds)),
                    });
                }
                app.release = service.app.release.clone();
                for (key, overlay) in &service.app.volumes {
                    let Some(volume) = app.volumes.get_mut(key) else {
                        return refuse(
                            format!("{field}.volumes.{key}"),
                            "the catalogue template has no data volume",
                        );
                    };
                    if let Some(backup) = overlay.backup {
                        volume.backup = Some(backup);
                    }
                }
                if let Some(selected) = &service.data_volume {
                    let Some(volume) = app.volumes.shift_remove("data") else {
                        return refuse(
                            format!("{field}.data_volume"),
                            "the catalogue template has no data volume",
                        );
                    };
                    app.volumes.insert(selected.clone(), volume);
                }
                for port in &mut app.ports {
                    port.public = false;
                }
                Cow::Owned(app)
            }
            (Some(_), None) => {
                return refuse(
                    format!("{field}.template"),
                    "the server must resolve an enabled catalogue template",
                );
            }
            (None, Some(_)) => {
                return refuse(field, "an image service cannot receive a catalogue spec");
            }
        };
        let declared = file::normalize(service_name, &app).map_err(|error| SpecError {
            field: error
                .field
                .replacen(&format!("apps.{service_name}"), &field, 1),
            problem: error.problem,
        })?;
        let mut input = declared.settings;
        let placement = file::placement_input(self.placement.as_ref());
        input.machines = self.machines.clone();
        input.labels = placement.labels;
        input.kind = placement.kind;
        input.auto_rollback = Some(false);
        let settings = AppSettings::validate(input).map_err(|error| SpecError {
            field: format!("{field}.{}", error.field),
            problem: error.problem,
        })?;
        let mut spec = declared.spec;
        let restart = service.restart(&spec);
        if !spec.volumes.is_empty() && restart != Restart::Exclusive {
            return refuse(
                format!("{field}.restart"),
                "volume owners require exclusive restart",
            );
        }
        if restart == Restart::Exclusive {
            if settings.copies != 1 {
                return refuse(
                    format!("{field}.copies"),
                    "exclusive restart requires exactly one copy",
                );
            }
            if app.release.as_ref().is_some_and(|release| {
                release.max_surge.is_some() || release.max_unavailable.is_some()
            }) {
                return refuse(
                    format!("{field}.release"),
                    "exclusive restart does not accept max_surge or max_unavailable",
                );
            }
        }
        if restart == Restart::Rolling && settings.rollout.max_surge == 0 {
            return refuse(
                format!("{field}.release.max_surge"),
                "rolling stack services require max_surge of at least 1",
            );
        }
        let mut references = Vec::new();
        for env in &mut spec.env {
            if let Some(reference) =
                reference(&env.name, &env.value, &format!("{field}.env.{}", env.name))?
            {
                if !self.services.contains_key(&reference.service)
                    || !service.depends_on.contains(&reference.service)
                {
                    return refuse(
                        format!("{field}.env.{}", env.name),
                        "connection references require an existing sibling and an explicit depends_on entry",
                    );
                }
                references.push(reference);
            } else if env.value.starts_with("$${{") {
                env.value.remove(0);
            }
        }
        spec.env
            .retain(|env| !references.iter().any(|reference| reference.env == env.name));
        self.validate_public(service_name, &spec)?;
        for port in &mut spec.ports {
            port.public = self
                .public
                .as_ref()
                .is_some_and(|public| public.service == service_name && public.port == port.name);
        }
        validate_expanded(&(&spec, &settings, &references))?;
        Ok((spec, settings, references))
    }
}

/// Refuses expanded serializations larger than 1 MiB, without allocating a serialized copy.
/// Call this on the complete expanded bundle after resolving every catalogue service.
pub fn validate_expanded<T: Serialize + ?Sized>(value: &T) -> Result<(), SpecError> {
    struct Limit(usize);
    impl Write for Limit {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            if self.0 > MAX_FILE_BYTES {
                return Err(std::io::Error::other("expanded stack exceeds 1 MiB"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Limit(0), value).map_err(|error| SpecError {
        field: "stack".into(),
        problem: error.to_string(),
    })
}

/// Parses exactly one stack document; ordinary app files retain their own 64 KiB limit.
pub fn parse(text: &str) -> Result<Definition, SpecError> {
    if text.len() > MAX_FILE_BYTES {
        return refuse(file::FILE_NAME, "use at most 1 MiB");
    }
    let file = file::read(text)?;
    let Some(definition) = file.stack else {
        return refuse("stack", "this file declares apps; use grund app deploy");
    };
    definition.validate()?;
    Ok(definition)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = "stack:\n  name: demo\n  services:\n    web:\n      image: nginx\n";

    #[test]
    fn stack_and_app_files_remain_distinct_and_may_not_be_mixed() {
        assert!(parse(SIMPLE).is_ok());
        let error = file::parse_app(SIMPLE, "web").unwrap_err();
        assert!(error.problem.contains("grund stack deploy"));
        assert!(parse(&format!("apps: {{}}\n{SIMPLE}")).is_err());
        assert!(file::parse_app("apps:\n  web:\n    image: nginx\n", "web").is_ok());
        assert!(parse("apps:\n  web:\n    image: nginx\n").is_err());
    }

    #[test]
    fn raw_stack_limit_is_one_mebibyte_while_app_limit_remains_64_kibibytes() {
        let mut stack = SIMPLE.to_string();
        stack.push('#');
        stack.extend(std::iter::repeat_n('x', MAX_FILE_BYTES - stack.len()));
        assert_eq!(stack.len(), MAX_FILE_BYTES);
        assert!(parse(&stack).is_ok());
        stack.push('x');
        assert!(parse(&stack).is_err());
        let mut app = "apps:\n  web:\n    image: nginx\n#".to_string();
        app.extend(std::iter::repeat_n('x', file::MAX_FILE_BYTES - app.len()));
        assert!(file::parse_app(&app, "web").is_ok());
        app.push('x');
        assert!(file::parse_app(&app, "web").is_err());
        assert!(validate_expanded(&"x".repeat(MAX_FILE_BYTES)).is_err());
    }

    #[test]
    fn stack_placement_never_requests_hosted_machine_rental() {
        for (placement, accepted) in [
            ("", true),
            ("  placement: {kind: own}\n", true),
            ("  placement: {kind: hosted}\n", false),
        ] {
            let text = format!(
                "stack:\n  name: demo\n{placement}  services:\n    web:\n      image: nginx\n"
            );
            assert_eq!(parse(&text).is_ok(), accepted);
        }
    }

    #[test]
    fn dependencies_must_be_explicit_and_acyclic_and_references_are_typed() {
        let text = "stack:\n  name: demo\n  services:\n    db:\n      image: redis\n    web:\n      image: nginx\n      depends_on: [db]\n      env:\n        DB_HOST: ${{ db.host }}\n        PLAIN: value\n";
        let definition = parse(text).unwrap();
        let (spec, settings, references) = definition.service("web", None).unwrap();
        assert!(!settings.auto_rollback);
        assert_eq!(spec.env.len(), 1);
        assert_eq!(spec.env[0].name, "PLAIN");
        assert_eq!(
            references,
            vec![ConnectionRef {
                env: "DB_HOST".into(),
                service: "db".into(),
                output: "host".into()
            }]
        );
        assert!(parse(&text.replace("      depends_on: [db]\n", "")).is_err());
        assert!(
            parse(&text.replace(
                "      image: redis\n",
                "      image: redis\n      depends_on: [web]\n"
            ))
            .is_err()
        );
        assert!(parse(&text.replace("${{ db.host }}", "prefix-${{ db.host }}")).is_err());
    }

    #[test]
    fn escaped_connection_openers_remain_literal_without_a_sibling_binding() {
        let text = SIMPLE.replace(
            "      image: nginx",
            "      image: nginx\n      env:\n        LITERAL: '$${{ missing.url }}'",
        );
        let definition = parse(&text).unwrap();
        let (spec, _, references) = definition.service("web", None).unwrap();
        assert!(references.is_empty());
        assert_eq!(spec.env[0].value, "${{ missing.url }}");
    }

    #[test]
    fn strict_rolling_rejects_a_policy_that_cannot_start_a_successor() {
        let text = SIMPLE.replace(
            "      image: nginx",
            "      image: nginx\n      copies: 2\n      release: {max_surge: 0, max_unavailable: 1}",
        );
        let error = parse(&text).unwrap_err();
        assert_eq!(error.field, "stack.services.web.release.max_surge");
    }

    #[test]
    fn duplicate_and_unknown_keys_and_service_public_flags_are_refused() {
        for text in [
            SIMPLE.replace("      image: nginx", "      image: nginx\n      unknown: true"),
            SIMPLE.replace("      image: nginx", "      image: nginx\n      image: redis"),
            SIMPLE.replace("      image: nginx", "      image: nginx\n      env:\n        KEY: one\n        KEY: two"),
            SIMPLE.replace("      image: nginx", "      image: nginx\n      volumes:\n        data: {path: /data}\n        data: {path: /other}"),
            SIMPLE.replace("      image: nginx", "      image: nginx\n    web:\n      image: redis"),
            SIMPLE.replace("      image: nginx", "      image: nginx\n      ports: [{name: http, port: 80, public: false}]"),
            SIMPLE.replace("      image: nginx", "      image: nginx\n      machines: []"),
        ] {
            assert!(parse(&text).is_err(), "{text}");
        }
    }

    #[test]
    fn public_targets_and_exclusive_copy_bounds_are_checked_before_effects() {
        assert!(parse(&SIMPLE.replace("name: demo", "name: machines")).is_err());
        assert!(
            parse(&SIMPLE.replace(
                "  services:",
                "  public: {service: web, port: missing}\n  services:"
            ))
            .is_err()
        );
        assert!(
            parse(&SIMPLE.replace(
                "      image: nginx",
                "      image: nginx\n      copies: 2\n      restart: exclusive"
            ))
            .is_err()
        );
        assert!(
            parse(&SIMPLE.replace(
                "      image: nginx",
                "      image: nginx\n      restart: exclusive\n      release: {max_surge: 1}"
            ))
            .is_err()
        );
        let mut definition = parse(SIMPLE).unwrap();
        let service = definition.services["web"].clone();
        for index in 0..MAX_SERVICES {
            definition
                .services
                .insert(format!("service-{index}"), service.clone());
        }
        assert!(definition.validate().is_err());
    }

    #[test]
    fn only_the_selected_service_port_is_public() {
        let mut definition = parse(
            "stack:\n  name: frontend\n  public: {service: web, port: http}\n  services:\n    web:\n      image: nginx\n      ports:\n        - {name: http, port: 80, protocol: http}\n        - {name: admin, port: 8081, protocol: http}\n    backend:\n      image: nginx\n      ports:\n        - {name: http, port: 8080, protocol: http}\n",
        )
        .unwrap();
        let public_ports = |definition: &Definition, service: &str| {
            definition
                .service(service, None)
                .unwrap()
                .0
                .ports
                .into_iter()
                .filter(|port| port.public)
                .map(|port| port.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(public_ports(&definition, "web"), ["http"]);
        assert!(public_ports(&definition, "backend").is_empty());
        definition.public = Some(PublicTarget {
            service: "backend".into(),
            port: "http".into(),
        });
        assert!(public_ports(&definition, "web").is_empty());
        assert_eq!(public_ports(&definition, "backend"), ["http"]);
        definition.public = None;
        assert!(public_ports(&definition, "web").is_empty());
        assert!(public_ports(&definition, "backend").is_empty());
    }

    #[test]
    fn templates_require_catalogue_expansion_and_only_allow_backup_policy_overlays() {
        let text = SIMPLE.replace(
            "      image: nginx",
            "      template: postgres\n      volumes:\n        data:\n          backup: daily",
        );
        let definition = parse(&text).unwrap();
        assert!(definition.service("web", None).is_err());
        assert!(
            parse(&text.replace("backup: daily", "backup: daily\n          path: /changed"))
                .is_err()
        );
        assert!(
            parse(&text.replace(
                "template: postgres",
                "template: postgres\n      env: {PASSWORD: no}"
            ))
            .is_err()
        );
        assert!(
            parse(&text.replace(
                "template: postgres",
                "template: postgres\n      image: postgres"
            ))
            .is_err()
        );
        assert_eq!(
            parse(&crate::yaml::to_string(&file::GrundFile {
                apps: IndexMap::new(),
                stack: Some(definition.clone())
            }))
            .unwrap(),
            definition
        );
        let catalogue = file::parse_app("apps:\n  db:\n    image: postgres\n    resources: {memory: 1 GiB, cpu: 0.5}\n    volumes:\n      data: {path: /var/lib/postgresql/data}\n    ports: [{name: postgres, port: 5432, protocol: tcp}]\n    check: {tcp: 5432}\n", "db").unwrap().spec;
        let definition = parse(&text.replace(
            "template: postgres",
            "template: postgres\n      resources: {cpu: 0.25}",
        ))
        .unwrap();
        let (spec, settings, _) = definition.service("web", Some(catalogue)).unwrap();
        assert_eq!(spec.memory_mib, 1024);
        assert_eq!(spec.cpu_millis, 250);
        assert!(spec.volumes[0].backup);
        assert_eq!(spec.volumes[0].path, "/var/lib/postgresql/data");
        assert_eq!(settings.copies, 1);
        assert_eq!(
            definition.services["web"].restart(&spec),
            Restart::Exclusive
        );
        let definition = parse(&SIMPLE.replace("image: nginx", "template: nginx")).unwrap();
        let catalogue = file::parse_app("apps:\n  web:\n    image: nginx\n", "web")
            .unwrap()
            .spec;
        let (spec, _, _) = definition.service("web", Some(catalogue)).unwrap();
        assert_eq!(definition.services["web"].restart(&spec), Restart::Rolling);
    }

    #[test]
    fn a_template_data_volume_selection_preserves_the_canonical_mount_and_single_writer() {
        let definition = parse(
            "stack:\n  name: recovery\n  services:\n    storage:\n      template: seaweedfs\n      data_volume: data-restored\n      volumes:\n        data: {backup: daily}\n",
        ).unwrap();
        let catalogue = file::parse_app(
            "apps:\n  storage:\n    image: storage\n    volumes:\n      data: {path: /data}\n",
            "storage",
        )
        .unwrap()
        .spec;
        let (spec, settings, _) = definition.service("storage", Some(catalogue)).unwrap();
        assert_eq!(spec.volumes[0].name, "data-restored");
        assert_eq!(spec.volumes[0].path, "/data");
        assert!(spec.volumes[0].source.is_none());
        assert!(spec.volumes[0].backup);
        assert_eq!(settings.copies, 1);
        assert_eq!(
            definition.services["storage"].restart(&spec),
            Restart::Exclusive
        );
        for replacement in [
            "/other",
            "other/data",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(
                parse(
                    &crate::yaml::to_string(&file::GrundFile {
                        apps: IndexMap::new(),
                        stack: Some(definition.clone()),
                    })
                    .replace("data-restored", replacement)
                )
                .is_err()
            );
        }
        assert!(
            parse(&SIMPLE.replace(
                "image: nginx",
                "image: nginx\n      data_volume: data-restored"
            ))
            .is_err()
        );
        let no_storage = parse("stack:\n  name: recovery\n  services:\n    storage:\n      template: nats\n      data_volume: data-restored\n").unwrap();
        let catalogue = file::parse_app("apps:\n  storage:\n    image: nats\n", "storage")
            .unwrap()
            .spec;
        assert!(no_storage.service("storage", Some(catalogue)).is_err());
    }
}
