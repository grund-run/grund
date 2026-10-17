//! Machine labels (grund-docs design/apps.md §5.6): `key=value` pairs a
//! machine's owner sets, never the machine, so a machine cannot claim a
//! place it was not given. Apps select machines by them and spread their
//! copies over the values of one key.

use std::collections::BTreeMap;

/// The most labels one machine carries, and one app may require.
pub const MAX_LABELS: usize = 16;
/// The longest key and the longest value.
pub const MAX_LABEL_CHARS: usize = 63;

/// Labels, sorted by key.
pub type Labels = BTreeMap<String, String>;

/// Why a label was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    #[error(
        "a label key is 1 to 63 lowercase letters, digits, '.', '-', '_' or '/', starting and ending with a letter or digit"
    )]
    Key,
    #[error("a label value is at most 63 letters, digits, '.', '-' or '_'")]
    Value,
    #[error("use at most 16 labels")]
    TooMany,
}

/// The key, if it is one.
pub fn label_key(input: &str) -> Result<String, LabelError> {
    let key = input.trim();
    let edge = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    let ok = (1..=MAX_LABEL_CHARS).contains(&key.len())
        && key.chars().next().is_some_and(edge)
        && key.chars().last().is_some_and(edge)
        && key
            .chars()
            .all(|c| edge(c) || matches!(c, '.' | '-' | '_' | '/'));
    if ok {
        Ok(key.to_string())
    } else {
        Err(LabelError::Key)
    }
}

/// The value, if it is one. Empty is a value.
pub fn label_value(input: &str) -> Result<String, LabelError> {
    let value = input.trim();
    let ok = value.len() <= MAX_LABEL_CHARS
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if ok {
        Ok(value.to_string())
    } else {
        Err(LabelError::Value)
    }
}

/// Labels from pairs, each checked; a key given twice keeps its last value.
pub fn labels<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Labels, LabelError> {
    let mut out = Labels::new();
    for (key, value) in pairs {
        out.insert(label_key(key)?, label_value(value)?);
    }
    if out.len() > MAX_LABELS {
        return Err(LabelError::TooMany);
    }
    Ok(out)
}

/// `key=value` lines or comma-separated pairs, as a person types them on a
/// page. Blank entries are skipped; an entry without `=` is a key with an
/// empty value.
pub fn parse_labels(text: &str) -> Result<Labels, LabelError> {
    let pairs: Vec<(&str, &str)> = text
        .split([',', '\n'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.split_once('=').unwrap_or((entry, "")))
        .collect();
    labels(pairs)
}

/// Labels as `key=value, key=value`.
pub fn labels_text(labels: &Labels) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_values_follow_the_documented_alphabet() {
        assert_eq!(label_key("zone"), Ok("zone".into()));
        assert_eq!(label_key("grund.sh/rack-2"), Ok("grund.sh/rack-2".into()));
        assert_eq!(label_key("Zone"), Err(LabelError::Key));
        assert_eq!(label_key("-zone"), Err(LabelError::Key));
        assert_eq!(label_key(""), Err(LabelError::Key));
        assert_eq!(label_key(&"a".repeat(64)), Err(LabelError::Key));
        assert_eq!(label_value("eu-1.A_b"), Ok("eu-1.A_b".into()));
        assert_eq!(label_value(""), Ok(String::new()));
        assert_eq!(label_value("a b"), Err(LabelError::Value));
    }

    #[test]
    fn typed_labels_parse_from_lines_or_commas_and_refuse_too_many() {
        let parsed = parse_labels("zone=a, disk=ssd\ngpu\n\n").unwrap();
        assert_eq!(labels_text(&parsed), "disk=ssd, gpu=, zone=a");
        let many: String = (0..17).map(|i| format!("k{i}=v,")).collect();
        assert_eq!(parse_labels(&many), Err(LabelError::TooMany));
    }
}
