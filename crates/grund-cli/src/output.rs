//! Printing a command's result: protobuf JSON as the instance sent it
//! (`--output json`), the same as YAML, or text for a person (a table for
//! a list, the fields otherwise).

use std::io::{IsTerminal, Write};

use serde_json::Value;

use crate::error::CliError;

/// How results are printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// For people: tables and fields.
    Text,
    /// One JSON document on stdout; errors as JSON on stderr.
    Json,
    /// The JSON document as YAML.
    Yaml,
}

/// How a result reads as text.
#[derive(Debug, Clone, Copy)]
pub enum Text {
    /// The fields, as YAML.
    Fields,
    /// A table of the array at a JSON pointer, one column per (header,
    /// pointer into a row).
    Table(&'static str, &'static [(&'static str, &'static str)]),
    /// The string at a JSON pointer, alone.
    Line(&'static str),
    /// The value as indented JSON (a JSON Schema).
    Json,
    /// Text made for it ([`Output::with_text`]).
    Own,
}

/// What a command produced.
#[derive(Debug, Clone)]
pub struct Output {
    pub value: Value,
    pub text: Text,
    /// For [`Text::Own`].
    pub own: String,
}

impl Output {
    /// A result shown as its fields.
    pub fn fields(value: Value) -> Self {
        Output {
            value,
            text: Text::Fields,
            own: String::new(),
        }
    }

    /// A result whose text is `text`, written for it.
    pub fn with_text(value: Value, text: String) -> Self {
        Output {
            value,
            text: Text::Own,
            own: text,
        }
    }

    /// A result shown as indented JSON in every format but YAML.
    pub fn json(value: Value) -> Self {
        Output {
            value,
            text: Text::Json,
            own: String::new(),
        }
    }

    /// A result shown as a table.
    pub fn table(
        value: Value,
        rows: &'static str,
        columns: &'static [(&'static str, &'static str)],
    ) -> Self {
        Output {
            value,
            text: Text::Table(rows, columns),
            own: String::new(),
        }
    }

    /// A result shown as the one string at `pointer`.
    pub fn line(value: Value, pointer: &'static str) -> Self {
        Output {
            value,
            text: Text::Line(pointer),
            own: String::new(),
        }
    }

    /// The result in `format`, ending in a newline.
    pub fn render(&self, format: Format) -> String {
        match format {
            Format::Json => format!(
                "{}\n",
                serde_json::to_string_pretty(&self.value).unwrap_or_default()
            ),
            Format::Yaml => yaml(&self.value),
            Format::Text => match self.text {
                Text::Fields => yaml(&self.value),
                Text::Own => self.own.clone(),
                Text::Json => format!(
                    "{}\n",
                    serde_json::to_string_pretty(&self.value).unwrap_or_default()
                ),
                Text::Line(pointer) => {
                    format!(
                        "{}\n",
                        cell(self.value.pointer(pointer).unwrap_or(&Value::Null))
                    )
                }
                Text::Table(rows, columns) => table(
                    self.value
                        .pointer(rows)
                        .and_then(Value::as_array)
                        .map(Vec::as_slice)
                        .unwrap_or_default(),
                    columns,
                ),
            },
        }
    }
}

fn yaml(value: &Value) -> String {
    match value {
        Value::Object(map) if map.is_empty() => String::new(),
        _ => {
            let text = grund_domain::yaml::to_string(value);
            if text.ends_with('\n') {
                text
            } else {
                format!("{text}\n")
            }
        }
    }
}

/// A JSON value as one table cell.
pub fn cell(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Array(items) => items.iter().map(cell).collect::<Vec<_>>().join(","),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k}={}", cell(v)))
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

fn table(rows: &[Value], columns: &[(&str, &str)]) -> String {
    let mut lines: Vec<Vec<String>> = vec![columns.iter().map(|(h, _)| (*h).to_string()).collect()];
    for row in rows {
        lines.push(
            columns
                .iter()
                .map(|(_, pointer)| cell(row.pointer(pointer).unwrap_or(&Value::Null)))
                .collect(),
        );
    }
    let widths: Vec<usize> = (0..columns.len())
        .map(|i| {
            lines
                .iter()
                .map(|l| l[i].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut text = String::new();
    for line in lines {
        let mut out = String::new();
        for (i, value) in line.iter().enumerate() {
            if i + 1 == line.len() {
                out.push_str(value);
            } else {
                out.push_str(&format!("{value:<width$}  ", width = widths[i]));
            }
        }
        text.push_str(out.trim_end());
        text.push('\n');
    }
    text
}

/// Prints `output` on stdout.
pub fn print(output: &Output, format: Format) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(output.render(format).as_bytes());
    let _ = stdout.flush();
}

/// Prints `error` on stderr: JSON for `--output json` or `yaml`, text
/// otherwise.
pub fn print_error(error: &CliError, format: Format) {
    let text = match format {
        Format::Text => format!("{}\n", error.text()),
        Format::Json | Format::Yaml => format!("{}\n", error.json()),
    };
    let _ = std::io::stderr().lock().write_all(text.as_bytes());
}

/// A progress line on stderr, for people only: nothing with JSON or YAML
/// output, or when stderr is not a terminal.
pub fn progress(format: Format, line: &str) {
    if format == Format::Text && std::io::stderr().is_terminal() {
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_list_reads_as_a_table_and_as_json_unchanged() {
        let value = json!({"apps": [
            {"name": "web", "currentRelease": 3, "settings": {"copies": 2}},
            {"name": "worker", "settings": {"copies": 1}},
        ]});
        let output = Output::table(
            value.clone(),
            "/apps",
            &[
                ("NAME", "/name"),
                ("RELEASE", "/currentRelease"),
                ("COPIES", "/settings/copies"),
            ],
        );
        assert_eq!(
            output.render(Format::Text),
            "NAME    RELEASE  COPIES\nweb     3        2\nworker           1\n"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&output.render(Format::Json)).unwrap(),
            value
        );
    }
}
