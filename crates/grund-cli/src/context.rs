//! What every client command runs with: where the instance is, which
//! credential to present, which organisation to act on, how to print, and
//! whether anyone can be asked.

use std::io::{IsTerminal, Read, Write};

use serde_json::{Value, json};

use crate::{
    api::Api,
    credentials::{self, Credentials},
    error::{CliError, CliResult, Code},
    output::Format,
};

/// The flags every client command takes, anywhere on its command line.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct Global {
    #[arg(
        long,
        global = true,
        hide = true,
        env = "GRUND_INSTANCE",
        value_name = "URL",
        help = "The instance, such as https://grund.example.com. Default: the one grund auth login signed in to last"
    )]
    pub instance: Option<String>,

    #[arg(
        long,
        global = true,
        env = "GRUND_CONTEXT",
        value_name = "NAME",
        help = "The context: an instance, its credential and organisation. Default: grund context use"
    )]
    pub context: Option<String>,

    #[arg(
        long,
        global = true,
        env = "GRUND_ORG",
        value_name = "SLUG",
        help = "The organisation. Default: grund org use, else the token's, else the only one"
    )]
    pub org: Option<String>,

    #[arg(
        short = 'o',
        long,
        global = true,
        env = "GRUND_OUTPUT",
        value_enum,
        value_name = "FORMAT",
        help = "text (default), json or yaml. JSON goes to stdout, errors as JSON to stderr"
    )]
    pub output: Option<Format>,

    #[arg(long, global = true, help = "The same as --output json")]
    pub json: bool,
}

impl Global {
    /// The same client target options for standalone and embedding parser roots.
    pub fn target_arguments() -> [clap::Arg; 3] {
        let command = <Self as clap::Args>::augment_args(clap::Command::new("grund"));
        ["instance", "context", "org"].map(|name| {
            command
                .get_arguments()
                .find(|argument| argument.get_id().as_str() == name)
                .expect("Global defines every target option")
                .clone()
        })
    }
}

/// Where the credential came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Environment,
    File,
}

/// A credential and what it is.
#[derive(Debug, Clone)]
pub struct Credential {
    pub secret: String,
    pub source: Source,
}

impl Credential {
    /// `session` for a `grund auth login` session, `token` for a personal access
    /// token.
    pub fn kind(&self) -> &'static str {
        if self.secret.starts_with("grund_cli_") {
            "session"
        } else {
            "token"
        }
    }
}

/// A command's surroundings.
pub struct Ctx {
    pub global: Global,
    pub format: Format,
    /// Text a tool call hands in place of stdin (`grund mcp`).
    pub stdin: Option<String>,
    /// Whether a person can be asked to confirm.
    pub interactive: bool,
}

impl Ctx {
    /// The context for `global`, asking on the terminal when there is one.
    pub fn new(global: Global) -> Self {
        let format = if global.json {
            Format::Json
        } else {
            global.output.unwrap_or(Format::Text)
        };
        let interactive = format == Format::Text
            && std::io::stdin().is_terminal()
            && std::io::stderr().is_terminal()
            && std::env::var_os("CI").is_none()
            && std::env::var_os("GRUND_NO_INPUT").is_none();
        Ctx {
            global,
            format,
            stdin: None,
            interactive,
        }
    }

    /// The CLI's file's path.
    pub fn credentials_path(&self) -> CliResult<std::path::PathBuf> {
        credentials::path()
    }

    /// The CLI's file, migrated from the older credentials file if need be.
    pub fn credentials(&self) -> CliResult<Credentials> {
        credentials::load()
    }

    /// The context commands act in: --context or GRUND_CONTEXT, else the
    /// file's current one. `None` when the file has none.
    pub fn context(&self) -> CliResult<Option<credentials::Context>> {
        let file = self.credentials()?;
        if let Some(name) = self.global.context.as_deref().filter(|n| !n.is_empty()) {
            return file.context(name).cloned().map(Some).ok_or_else(|| {
                CliError::new(Code::NotFound, format!("no context {name}"))
                    .hint("grund context list")
                    .field("context")
            });
        }
        Ok(file.context(&file.current).cloned())
    }

    /// The instance: --instance or GRUND_INSTANCE, else the context's.
    pub fn instance(&self) -> CliResult<String> {
        if let Some(instance) = self.global.instance.as_deref().filter(|i| !i.is_empty()) {
            return credentials::origin(instance);
        }
        match self.context()? {
            Some(context) => Ok(context.url),
            None => Err(CliError::new(Code::NotSignedIn, "no instance is chosen")
                .hint("run grund auth login <instance>, or set GRUND_INSTANCE and GRUND_TOKEN")),
        }
    }

    fn context_for(&self, instance: &str) -> CliResult<Option<credentials::Context>> {
        if let Some(context) = self.context()?.filter(|c| c.url == instance) {
            return Ok(Some(context));
        }
        Ok(self.credentials()?.for_instance(instance).cloned())
    }

    /// The credential for `instance`: GRUND_TOKEN, else the context's.
    pub fn credential(&self, instance: &str) -> CliResult<Credential> {
        if let Ok(secret) = std::env::var("GRUND_TOKEN") {
            let secret = secret.trim().to_string();
            if !secret.is_empty() {
                return Ok(Credential {
                    secret,
                    source: Source::Environment,
                });
            }
        }
        self.context_for(instance)?
            .map(|c| Credential {
                secret: c.credential,
                source: Source::File,
            })
            .ok_or_else(|| {
                CliError::new(Code::NotSignedIn, format!("not signed in to {instance}")).hint(
                    format!("run grund auth login {instance}, or set GRUND_TOKEN"),
                )
            })
    }

    /// A client for the instance with its credential.
    pub fn api(&self) -> CliResult<Api> {
        let instance = self.instance()?;
        let credential = self.credential(&instance)?;
        Api::new(&instance, Some(credential.secret))
    }

    /// The organisation to act on: --org or GRUND_ORG, else the context's,
    /// else the token's own, else the account's only one.
    pub async fn org(&self, api: &Api) -> CliResult<String> {
        if let Some(org) = self.global.org.as_deref().filter(|o| !o.is_empty()) {
            return Ok(org.trim().to_ascii_lowercase());
        }
        let instance = api.origin().to_string();
        let credential = self.credential(&instance)?;
        if credential.source == Source::File
            && let Some(context) = self.context_for(&instance)?
            && !context.organisation.is_empty()
        {
            return Ok(context.organisation);
        }
        if credential.kind() == "token" {
            let current = api
                .call("grund.token.v1.TokenService/GetCurrentToken", json!({}))
                .await?;
            if let Some(org) = current["organisation"].as_str().filter(|o| !o.is_empty()) {
                return Ok(org.to_string());
            }
        }
        let viewer = api
            .call("grund.account.v1.AccountService/GetViewer", json!({}))
            .await?;
        let slugs: Vec<String> = viewer["viewer"]["memberships"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| m["organisationSlug"].as_str().map(str::to_string))
            .collect();
        match slugs.as_slice() {
            [only] => Ok(only.clone()),
            [] => Err(CliError::new(
                Code::OrganisationRequired,
                "the account is in no organisation",
            )
            .hint("make one with grund org create <slug>")),
            many => Err(CliError::new(
                Code::OrganisationRequired,
                format!(
                    "the account is in {} organisations: {}",
                    many.len(),
                    many.join(", ")
                ),
            )
            .hint("pass --org <slug>, or run grund org use <slug>")),
        }
    }

    /// All of stdin, or the text a tool call handed in.
    pub fn read_stdin(&self, what: &str) -> CliResult<String> {
        if let Some(text) = &self.stdin {
            return Ok(text.clone());
        }
        let mut stdin = std::io::stdin();
        if stdin.is_terminal() {
            let _ = write!(std::io::stderr(), "{what} (end with Ctrl-D): ");
            let _ = std::io::stderr().flush();
        }
        let mut text = String::new();
        stdin.read_to_string(&mut text)?;
        if stdin.is_terminal() {
            let _ = writeln!(std::io::stderr());
        }
        Ok(text)
    }

    /// Goes ahead with a destructive change: with --yes, or after a person
    /// typed y; refused when nobody can be asked.
    pub fn confirm(&self, yes: bool, question: &str) -> CliResult<()> {
        if yes {
            return Ok(());
        }
        if !self.interactive {
            return Err(CliError::new(
                Code::ConfirmationRequired,
                format!("{question} needs --yes when nobody can be asked"),
            )
            .hint("add --yes, or run it in a terminal")
            .field("yes"));
        }
        let _ = write!(std::io::stderr(), "{question}? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if matches!(answer.trim(), "y" | "Y" | "yes") {
            Ok(())
        } else {
            Err(CliError::new(
                Code::ConfirmationRequired,
                "not confirmed; nothing changed",
            ))
        }
    }
}

/// A JSON object with `key` set when `value` is not empty.
pub fn set_if(object: &mut Value, key: &str, value: impl Into<Value>) {
    let value = value.into();
    let empty = match &value {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    };
    if !empty {
        object[key] = value;
    }
}
