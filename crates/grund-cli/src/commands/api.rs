//! `grund api`: any procedure of the instance's API, with the context's
//! credential (grund-docs design/cli-redesign.md §12). It grants nothing
//! the API does not already allow; the procedures it knows are the
//! descriptors compiled into this binary.

use std::io::Read;

use clap::Args;
use serde_json::{Map, Value, json};

use crate::{
    context::{Ctx, Global},
    error::{CliError, CliResult},
    output::Output,
    schema::Registry,
};

/// `grund api`.
#[derive(Debug, Args)]
pub struct ApiArgs {
    #[command(flatten)]
    pub global: Global,
    #[arg(
        value_name = "PROCEDURE",
        help = "package.Service/Method, or Service/Method when that names one; list prints them all"
    )]
    pub procedure: String,
    #[arg(
        short = 'f',
        long = "field",
        value_name = "KEY=VALUE",
        help = "A request field; VALUE is JSON when it parses as JSON, else a string. {org} is the organisation"
    )]
    pub fields: Vec<String>,
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with = "fields",
        help = "The request as protobuf JSON, from FILE or - for stdin"
    )]
    pub input: Option<String>,
}

fn resolve(registry: &Registry, name: &str) -> CliResult<String> {
    let name = name.trim_start_matches('/');
    let found: Vec<&str> = registry
        .procedures()
        .iter()
        .map(|p| p.rpc.as_str())
        .filter(|rpc| *rpc == name || rpc.ends_with(&format!(".{name}")))
        .collect();
    match found.as_slice() {
        [one] => Ok(one.to_string()),
        [] => Err(CliError::usage(format!("no procedure {name}"))
            .hint("grund api list")
            .field("procedure")),
        many => Err(CliError::usage(format!(
            "{name} names {} procedures: {}",
            many.len(),
            many.join(", ")
        ))
        .field("procedure")),
    }
}

fn field(text: &str) -> CliResult<(String, Value)> {
    let (key, value) = text
        .split_once('=')
        .ok_or_else(|| CliError::usage(format!("{text} is not KEY=VALUE")).field("field"))?;
    let value = serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()));
    Ok((key.to_string(), value))
}

fn uses_org(value: &Value) -> bool {
    match value {
        Value::String(s) => s == "{org}",
        Value::Array(items) => items.iter().any(uses_org),
        Value::Object(map) => map.values().any(uses_org),
        _ => false,
    }
}

fn fill_org(value: &mut Value, org: &str) {
    match value {
        Value::String(s) if s == "{org}" => *s = org.to_string(),
        Value::Array(items) => items.iter_mut().for_each(|v| fill_org(v, org)),
        Value::Object(map) => map.values_mut().for_each(|v| fill_org(v, org)),
        _ => {}
    }
}

/// Runs `grund api`.
pub async fn run(ctx: &Ctx, args: ApiArgs) -> CliResult<Output> {
    let registry = Registry::compiled();
    if args.procedure == "list" {
        let procedures: Vec<Value> = registry
            .procedures()
            .iter()
            .map(|p| {
                json!({
                    "rpc": p.rpc,
                    "input": p.input,
                    "output": p.output,
                    "description": p.comment.lines().next().unwrap_or_default(),
                })
            })
            .collect();
        return Ok(Output::table(
            json!({"procedures": procedures}),
            "/procedures",
            &[("PROCEDURE", "/rpc"), ("DESCRIPTION", "/description")],
        ));
    }
    let rpc = resolve(&registry, &args.procedure)?;
    let mut request = match &args.input {
        Some(path) => {
            let text = if path == "-" {
                ctx.read_stdin("Request JSON")?
            } else {
                let mut text = String::new();
                std::fs::File::open(path)
                    .and_then(|mut f| f.read_to_string(&mut text))
                    .map_err(|e| {
                        CliError::usage(format!("cannot read {path}: {e}")).field("input")
                    })?;
                text
            };
            serde_json::from_str(&text).map_err(|e| {
                CliError::usage(format!("the request is not JSON: {e}")).field("input")
            })?
        }
        None => {
            let mut object = Map::new();
            for text in &args.fields {
                let (key, value) = field(text)?;
                object.insert(key, value);
            }
            Value::Object(object)
        }
    };
    let api = ctx.api()?;
    if uses_org(&request) {
        let org = ctx.org(&api).await?;
        fill_org(&mut request, &org);
    }
    let answer = api.call(&rpc, request).await?;
    Ok(Output::json(answer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_name_resolves_only_when_it_names_one_procedure() {
        let registry = Registry::compiled();
        assert_eq!(
            resolve(&registry, "AppService/GetApp").unwrap(),
            "grund.app.v1.AppService/GetApp"
        );
        assert_eq!(
            resolve(&registry, "grund.app.v1.AppService/GetApp").unwrap(),
            "grund.app.v1.AppService/GetApp"
        );
        assert!(resolve(&registry, "NoService/Nothing").is_err());
    }

    #[test]
    fn a_field_value_is_json_when_it_parses_and_org_is_filled_anywhere() {
        assert_eq!(field("copies=3").unwrap(), ("copies".into(), json!(3)));
        assert_eq!(field("name=web").unwrap(), ("name".into(), json!("web")));
        assert_eq!(field("labels={\"a\":\"b\"}").unwrap().1, json!({"a": "b"}));
        assert!(field("nonsense").is_err());
        let mut request = json!({"organisation": "{org}", "names": ["{org}", "x"]});
        assert!(uses_org(&request));
        fill_org(&mut request, "acme");
        assert_eq!(
            request,
            json!({"organisation": "acme", "names": ["acme", "x"]})
        );
    }
}
