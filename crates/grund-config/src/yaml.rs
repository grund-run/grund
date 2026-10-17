//! How grund reads and writes the YAML people keep: an app's `grund.yaml`
//! and a machine's `/etc/grund/policy.yaml`. One set of rules for both,
//! with serde-saphyr (pure Rust, `forbid(unsafe_code)`):
//!
//! - one document; a second `---` is refused;
//! - YAML 1.2 booleans only: `yes`, `no`, `on` and `off` are strings, and a
//!   boolean field refuses them rather than guessing;
//! - a tag grund does not know (`!!python/object`) is refused, never acted on;
//! - anchors and aliases work, and `<<` merges, but an alias may stand in
//!   for at most [`MAX_ALIAS_REPLAY`] nodes across the file, and the file
//!   for at most [`MAX_NODES`], so an alias bomb is refused in milliseconds;
//! - every error names the line, the column and, when serde knew it, the
//!   field's path (`apps.shop.ports[0].port`).

use serde::{Serialize, de::DeserializeOwned};
use serde_saphyr::MessageFormatter;

/// The most YAML nodes aliases may replay across one file. A real file with
/// anchors replays a few hundred; an alias bomb, billions.
pub const MAX_ALIAS_REPLAY: usize = 10_000;

/// The most nodes one file may have.
pub const MAX_NODES: usize = 50_000;

/// The deepest nesting accepted.
pub const MAX_DEPTH: usize = 32;

/// Why a YAML file was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.problem())]
pub struct YamlError {
    /// The field's path, as `apps.shop.copies`; empty when the file as a
    /// whole is wrong (it does not parse, or is not a mapping).
    pub path: String,
    /// 1-based, when known.
    pub line: Option<u64>,
    pub column: Option<u64>,
    /// In words for the person who wrote the file, without the position.
    pub message: String,
}

impl YamlError {
    /// `line 4, column 5: unknown field ...`.
    pub fn problem(&self) -> String {
        match (self.line, self.column) {
            (Some(line), Some(column)) => {
                format!("line {line}, column {column}: {}", self.message)
            }
            _ => self.message.clone(),
        }
    }
}

fn options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        reject_unsupported_tags: true,
        with_snippet: false,
        budget: serde_saphyr::budget! {
            max_documents: 1,
            max_depth: MAX_DEPTH,
            max_anchors: 256,
            max_aliases: 1024,
            max_nodes: MAX_NODES,
        },
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: MAX_ALIAS_REPLAY,
        },
    }
}

/// Reads `text` as a `T`. An empty file is an empty mapping.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, YamlError> {
    let mut path = String::new();
    serde_saphyr::with_deserializer_from_str_with_options(text, options(), |de| {
        serde_path_to_error::deserialize::<_, T>(de).map_err(|e| {
            path = e.path().to_string();
            e.into_inner()
        })
    })
    .map_err(|error| {
        let location = error.location();
        YamlError {
            path: if path == "." { String::new() } else { path },
            line: location.map(|at| at.line()),
            column: location.map(|at| at.column()),
            message: serde_saphyr::UserMessageFormatter
                .format_message(error.without_snippet())
                .into_owned(),
        }
    })
}

/// Writes `value` as block YAML: two-space indents, list items under their
/// key, a string quoted whenever YAML would read it as something else, and
/// a line break kept as a `|` block. Long strings are never folded.
pub fn to_string<T: Serialize>(value: &T) -> String {
    let options = serde_saphyr::ser_options! {
        folded_wrap_chars: usize::MAX,
        min_fold_chars: usize::MAX,
    };
    serde_saphyr::to_string_with_options(value, options).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Settings {
        on: bool,
        name: String,
    }

    #[test]
    fn an_error_names_its_line_column_and_path() {
        let error = from_str::<Settings>("on: true\nnaem: x\n").unwrap_err();
        assert_eq!(error.path, "naem");
        assert_eq!((error.line, error.column), (Some(2), Some(1)));
        assert!(error.message.contains("unknown field `naem`"), "{error}");
        assert!(
            error.to_string().starts_with("line 2, column 1: "),
            "{error}"
        );
    }

    #[test]
    fn yes_is_not_a_boolean_and_a_strange_tag_is_refused() {
        assert!(from_str::<Settings>("on: yes\nname: x\n").is_err());
        assert!(from_str::<Settings>("on: true\nname: !!python/object x\n").is_err());
        assert_eq!(
            from_str::<Settings>("on: true\nname: yes\n").unwrap().name,
            "yes"
        );
    }
}
