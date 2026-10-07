//! JSON Schemas for the CLI's JSON, generated from the protobuf descriptors
//! compiled into the binary (`grund_proto::FILE_DESCRIPTOR_SET`, with the
//! proto comments as descriptions), so they cannot drift from what the
//! instance sends. The mapping is protobuf JSON's: lowerCamelCase field
//! names, enums by name, 64-bit integers as decimal strings, bytes as
//! base64, Timestamp as RFC 3339. A field left at its default may be
//! absent.

use std::collections::{BTreeMap, BTreeSet};

use buffa::Message;
use buffa_descriptor::generated::descriptor::{
    DescriptorProto, FileDescriptorSet,
    field_descriptor_proto::{Label, Type},
};
use serde_json::{Map, Value, json};

#[derive(Debug, Clone)]
enum Kind {
    Scalar(Type),
    Message(String),
    Enum(String),
}

#[derive(Debug, Clone)]
struct Field {
    name: String,
    json_name: String,
    kind: Kind,
    repeated: bool,
    comment: String,
}

#[derive(Debug, Clone, Default)]
struct MessageType {
    comment: String,
    fields: Vec<Field>,
    map_entry: bool,
}

#[derive(Debug, Clone, Default)]
struct EnumType {
    comment: String,
    values: Vec<String>,
}

/// One procedure of a service.
#[derive(Debug, Clone)]
pub struct Procedure {
    /// `package.Service/Method`.
    pub rpc: String,
    pub input: String,
    pub output: String,
    pub comment: String,
}

/// Every message, enum and procedure of grund's protocol.
#[derive(Debug, Default)]
pub struct Registry {
    messages: BTreeMap<String, MessageType>,
    enums: BTreeMap<String, EnumType>,
    procedures: Vec<Procedure>,
}

fn clean(comment: Option<&String>) -> String {
    comment
        .map(|c| {
            c.lines()
                .map(str::trim)
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_string()
        })
        .unwrap_or_default()
}

impl Registry {
    /// The registry of the descriptors compiled into this binary.
    pub fn compiled() -> Self {
        Self::from_bytes(grund_proto::FILE_DESCRIPTOR_SET)
    }

    /// The registry of a serialised `FileDescriptorSet`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let set = FileDescriptorSet::decode_from_slice(bytes).unwrap_or_default();
        let mut registry = Registry::default();
        for file in &set.file {
            let package = file.package.clone().unwrap_or_default();
            let mut comments: BTreeMap<Vec<i32>, String> = BTreeMap::new();
            if let Some(info) = file.source_code_info.as_option() {
                for location in &info.location {
                    let text = clean(location.leading_comments.as_ref());
                    let text = if text.is_empty() {
                        clean(location.trailing_comments.as_ref())
                    } else {
                        text
                    };
                    if !text.is_empty() {
                        comments.insert(location.path.clone(), text);
                    }
                }
            }
            for (i, message) in file.message_type.iter().enumerate() {
                registry.add_message(&package, message, vec![4, i as i32], &comments);
            }
            for (i, e) in file.enum_type.iter().enumerate() {
                let name = format!("{package}.{}", e.name.clone().unwrap_or_default());
                registry.enums.insert(
                    name,
                    EnumType {
                        comment: comments
                            .get(&vec![5, i as i32])
                            .cloned()
                            .unwrap_or_default(),
                        values: e.value.iter().filter_map(|v| v.name.clone()).collect(),
                    },
                );
            }
            for (i, service) in file.service.iter().enumerate() {
                let service_name =
                    format!("{package}.{}", service.name.clone().unwrap_or_default());
                for (j, method) in service.method.iter().enumerate() {
                    registry.procedures.push(Procedure {
                        rpc: format!("{service_name}/{}", method.name.clone().unwrap_or_default()),
                        input: method
                            .input_type
                            .clone()
                            .unwrap_or_default()
                            .trim_start_matches('.')
                            .to_string(),
                        output: method
                            .output_type
                            .clone()
                            .unwrap_or_default()
                            .trim_start_matches('.')
                            .to_string(),
                        comment: comments
                            .get(&vec![6, i as i32, 2, j as i32])
                            .cloned()
                            .unwrap_or_default(),
                    });
                }
            }
        }
        registry
    }

    fn add_message(
        &mut self,
        scope: &str,
        message: &DescriptorProto,
        path: Vec<i32>,
        comments: &BTreeMap<Vec<i32>, String>,
    ) {
        let name = format!("{scope}.{}", message.name.clone().unwrap_or_default());
        for (i, nested) in message.nested_type.iter().enumerate() {
            let mut nested_path = path.clone();
            nested_path.extend([3, i as i32]);
            self.add_message(&name, nested, nested_path, comments);
        }
        for (i, e) in message.enum_type.iter().enumerate() {
            let mut enum_path = path.clone();
            enum_path.extend([4, i as i32]);
            self.enums.insert(
                format!("{name}.{}", e.name.clone().unwrap_or_default()),
                EnumType {
                    comment: comments.get(&enum_path).cloned().unwrap_or_default(),
                    values: e.value.iter().filter_map(|v| v.name.clone()).collect(),
                },
            );
        }
        let fields = message
            .field
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let mut field_path = path.clone();
                field_path.extend([2, i as i32]);
                let type_name = f
                    .type_name
                    .clone()
                    .unwrap_or_default()
                    .trim_start_matches('.')
                    .to_string();
                let kind = match f.r#type {
                    Some(Type::TYPE_MESSAGE) | Some(Type::TYPE_GROUP) => Kind::Message(type_name),
                    Some(Type::TYPE_ENUM) => Kind::Enum(type_name),
                    Some(other) => Kind::Scalar(other),
                    None => Kind::Scalar(Type::TYPE_STRING),
                };
                let name = f.name.clone().unwrap_or_default();
                Field {
                    json_name: f.json_name.clone().unwrap_or_else(|| name.clone()),
                    name,
                    kind,
                    repeated: f.label == Some(Label::LABEL_REPEATED),
                    comment: comments.get(&field_path).cloned().unwrap_or_default(),
                }
            })
            .collect();
        self.messages.insert(
            name,
            MessageType {
                comment: comments.get(&path).cloned().unwrap_or_default(),
                fields,
                map_entry: message
                    .options
                    .as_option()
                    .and_then(|o| o.map_entry)
                    .unwrap_or(false),
            },
        );
    }

    /// Every procedure, in descriptor order.
    pub fn procedures(&self) -> &[Procedure] {
        &self.procedures
    }

    /// Whether a message of that full name exists.
    pub fn has_message(&self, name: &str) -> bool {
        self.messages.contains_key(name)
    }

    /// A message's own comment.
    pub fn message_comment(&self, name: &str) -> String {
        self.messages
            .get(name)
            .map(|m| m.comment.clone())
            .unwrap_or_default()
    }

    fn well_known(name: &str) -> Option<Value> {
        Some(match name {
            "google.protobuf.Timestamp" => json!({"type": "string", "format": "date-time"}),
            "google.protobuf.Duration" => {
                json!({"type": "string", "pattern": "^-?[0-9]+(\\.[0-9]+)?s$"})
            }
            "google.protobuf.Struct" => json!({"type": "object"}),
            "google.protobuf.Value" => json!({}),
            "google.protobuf.ListValue" => json!({"type": "array"}),
            "google.protobuf.Empty" => json!({"type": "object", "additionalProperties": false}),
            "google.protobuf.StringValue" => json!({"type": "string"}),
            "google.protobuf.BoolValue" => json!({"type": "boolean"}),
            "google.protobuf.Int32Value" | "google.protobuf.UInt32Value" => {
                json!({"type": "integer"})
            }
            _ => return None,
        })
    }

    fn scalar(kind: Type) -> Value {
        match kind {
            Type::TYPE_DOUBLE | Type::TYPE_FLOAT => json!({"type": "number"}),
            Type::TYPE_INT64
            | Type::TYPE_UINT64
            | Type::TYPE_SINT64
            | Type::TYPE_FIXED64
            | Type::TYPE_SFIXED64 => {
                json!({"type": ["string", "integer"], "pattern": "^-?[0-9]+$"})
            }
            Type::TYPE_INT32
            | Type::TYPE_UINT32
            | Type::TYPE_SINT32
            | Type::TYPE_FIXED32
            | Type::TYPE_SFIXED32 => {
                json!({"type": "integer"})
            }
            Type::TYPE_BOOL => json!({"type": "boolean"}),
            Type::TYPE_BYTES => json!({"type": "string", "contentEncoding": "base64"}),
            _ => json!({"type": "string"}),
        }
    }

    fn single(&self, kind: &Kind, defs: &mut BTreeSet<String>) -> Value {
        match kind {
            Kind::Scalar(t) => Self::scalar(*t),
            Kind::Enum(name) => {
                let e = self.enums.get(name).cloned().unwrap_or_default();
                let mut schema = json!({"type": "string", "enum": e.values});
                if !e.comment.is_empty() {
                    schema["description"] = json!(e.comment);
                }
                schema
            }
            Kind::Message(name) => {
                if let Some(schema) = Self::well_known(name) {
                    return schema;
                }
                defs.insert(name.clone());
                json!({"$ref": format!("#/$defs/{name}")})
            }
        }
    }

    fn field_schema(&self, field: &Field, defs: &mut BTreeSet<String>) -> Value {
        let mut schema = match &field.kind {
            Kind::Message(name)
                if field.repeated && self.messages.get(name).is_some_and(|m| m.map_entry) =>
            {
                let entry = &self.messages[name];
                let value = entry
                    .fields
                    .iter()
                    .find(|f| f.name == "value")
                    .map(|f| self.single(&f.kind, defs))
                    .unwrap_or_default();
                json!({"type": "object", "additionalProperties": value})
            }
            kind if field.repeated => json!({"type": "array", "items": self.single(kind, defs)}),
            kind => self.single(kind, defs),
        };
        if !field.comment.is_empty() && schema.get("$ref").is_none() {
            schema["description"] = json!(field.comment);
        } else if !field.comment.is_empty() {
            schema = json!({"allOf": [schema], "description": field.comment});
        }
        schema
    }

    fn message_schema(&self, name: &str, defs: &mut BTreeSet<String>) -> Value {
        let Some(message) = self.messages.get(name) else {
            return json!({});
        };
        let mut properties = Map::new();
        for field in &message.fields {
            properties.insert(field.json_name.clone(), self.field_schema(field, defs));
        }
        let mut schema = json!({
            "type": "object",
            "title": name,
            "properties": properties,
            "additionalProperties": false,
        });
        if !message.comment.is_empty() {
            schema["description"] = json!(message.comment);
        }
        schema
    }

    /// Every message `names` reach, by full name, each as a JSON Schema
    /// whose message fields are `$ref`s to `#/$defs/<full name>`.
    pub fn definitions(&self, names: &[&str]) -> BTreeMap<String, Value> {
        let mut pending: BTreeSet<String> = names.iter().map(|n| n.to_string()).collect();
        let mut done = BTreeMap::new();
        while let Some(name) = pending.pop_first() {
            if done.contains_key(&name) || Self::well_known(&name).is_some() {
                continue;
            }
            let mut found = BTreeSet::new();
            let schema = self.message_schema(&name, &mut found);
            done.insert(name, schema);
            pending.extend(found.into_iter().filter(|f| !done.contains_key(f)));
        }
        done
    }

    /// A standalone JSON Schema (draft 2020-12) for the message `name`.
    pub fn schema(&self, name: &str) -> Value {
        let defs: Map<String, Value> = self.definitions(&[name]).into_iter().collect();
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": format!("#/$defs/{name}"),
            "$defs": defs,
        })
    }

    /// Whether `value` is the protobuf JSON of the message `name`: every
    /// key a field of it, every value of the field's type. Absent fields
    /// are fine. The error names the JSON pointer that is not.
    pub fn conforms(&self, value: &Value, name: &str) -> Result<(), String> {
        self.check_message(value, name, "")
    }

    fn check_message(&self, value: &Value, name: &str, at: &str) -> Result<(), String> {
        if let Some(schema) = Self::well_known(name) {
            return match (schema["type"].as_str(), value) {
                (Some("string"), Value::String(_))
                | (Some("object"), Value::Object(_))
                | (Some("array"), Value::Array(_))
                | (None, _) => Ok(()),
                (Some("boolean"), Value::Bool(_)) | (Some("integer"), Value::Number(_)) => Ok(()),
                _ => Err(format!("{at}: not a {name}")),
            };
        }
        let message = self
            .messages
            .get(name)
            .ok_or_else(|| format!("{at}: {name} is not a known message"))?;
        let Value::Object(object) = value else {
            return Err(format!("{at}: {name} must be an object"));
        };
        for (key, item) in object {
            let path = format!("{at}/{key}");
            let field = message
                .fields
                .iter()
                .find(|f| &f.json_name == key || &f.name == key)
                .ok_or_else(|| format!("{path}: {name} has no field {key}"))?;
            if item.is_null() {
                continue;
            }
            if field.repeated {
                if let Kind::Message(entry) = &field.kind
                    && self.messages.get(entry).is_some_and(|m| m.map_entry)
                {
                    let Value::Object(map) = item else {
                        return Err(format!("{path}: a map must be an object"));
                    };
                    let value_field = self.messages[entry]
                        .fields
                        .iter()
                        .find(|f| f.name == "value")
                        .cloned();
                    for (k, v) in map {
                        if let Some(value_field) = &value_field {
                            self.check_single(v, &value_field.kind, &format!("{path}/{k}"))?;
                        }
                    }
                    continue;
                }
                let Value::Array(items) = item else {
                    return Err(format!("{path}: must be an array"));
                };
                for (i, element) in items.iter().enumerate() {
                    self.check_single(element, &field.kind, &format!("{path}/{i}"))?;
                }
            } else {
                self.check_single(item, &field.kind, &path)?;
            }
        }
        Ok(())
    }

    fn check_single(&self, value: &Value, kind: &Kind, at: &str) -> Result<(), String> {
        let ok = match kind {
            Kind::Message(name) => return self.check_message(value, name, at),
            Kind::Enum(name) => match value {
                Value::String(v) => self.enums.get(name).is_some_and(|e| e.values.contains(v)),
                Value::Number(_) => true,
                _ => false,
            },
            Kind::Scalar(t) => match (t, value) {
                (Type::TYPE_BOOL, Value::Bool(_)) => true,
                (Type::TYPE_STRING | Type::TYPE_BYTES, Value::String(_)) => true,
                (Type::TYPE_DOUBLE | Type::TYPE_FLOAT, Value::Number(_) | Value::String(_)) => true,
                (
                    Type::TYPE_INT64
                    | Type::TYPE_UINT64
                    | Type::TYPE_SINT64
                    | Type::TYPE_FIXED64
                    | Type::TYPE_SFIXED64,
                    Value::String(s),
                ) => s.parse::<i128>().is_ok(),
                (
                    Type::TYPE_INT64
                    | Type::TYPE_UINT64
                    | Type::TYPE_SINT64
                    | Type::TYPE_FIXED64
                    | Type::TYPE_SFIXED64,
                    Value::Number(n),
                ) => n.is_i64() || n.is_u64(),
                (_, Value::Number(n)) => n.is_i64() || n.is_u64(),
                _ => false,
            },
        };
        if ok {
            Ok(())
        } else {
            Err(format!("{at}: {value} is not of the field's type"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_the_cli_prints_is_in_the_compiled_descriptors() {
        let registry = Registry::compiled();
        for leaf in crate::meta::LEAVES {
            if !leaf.output.is_empty() {
                assert!(
                    registry.has_message(leaf.output),
                    "{}: {}",
                    leaf.path,
                    leaf.output
                );
            }
        }
    }

    #[test]
    fn a_schema_uses_json_names_and_carries_the_proto_comments() {
        let schema = Registry::compiled().schema("grund.app.v1.App");
        let app = &schema["$defs"]["grund.app.v1.App"];
        assert!(app["properties"]["currentRelease"].is_object());
        assert!(
            app["properties"]["currentRelease"]["description"]
                .as_str()
                .unwrap()
                .contains("release")
        );
        assert_eq!(app["additionalProperties"], json!(false));
        assert!(schema["$defs"]["grund.app.v1.RolloutStatus"].is_object());
        assert_eq!(
            schema["$defs"]["grund.app.v1.Replica"]["properties"]["placedAt"]["format"],
            "date-time"
        );
    }

    #[test]
    fn conformance_refuses_an_unknown_field_and_a_wrong_type() {
        let registry = Registry::compiled();
        let good = json!({"app": "web", "health": "live", "copiesWanted": 2, "copiesReady": 2,
            "rollout": {"state": "ROLLOUT_STATE_SUCCEEDED", "toRelease": 3}});
        registry.conforms(&good, "grund.cli.v1.AppStatus").unwrap();
        let unknown = json!({"app": "web", "colour": "blue"});
        assert!(
            registry
                .conforms(&unknown, "grund.cli.v1.AppStatus")
                .unwrap_err()
                .contains("/colour")
        );
        let wrong = json!({"rollout": {"state": "ROLLING"}});
        assert!(registry.conforms(&wrong, "grund.cli.v1.AppStatus").is_err());
    }

    #[test]
    fn the_descriptors_name_the_new_services() {
        let registry = Registry::compiled();
        let rpcs: Vec<&str> = registry
            .procedures()
            .iter()
            .map(|p| p.rpc.as_str())
            .collect();
        assert!(rpcs.contains(&"grund.token.v1.TokenService/CreateToken"));
        assert!(rpcs.contains(&"grund.login.v1.DeviceLoginService/PollDeviceLogin"));
    }
}
