//! `grund context`: the named contexts in the config file, each an
//! instance, its credential and an organisation (grund-docs
//! design/cli-redesign.md §8). Only `remove` reaches an instance, to end
//! the session it forgets.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::{
    api::Api,
    commands::{Noun, done},
    context::Ctx,
    credentials::Context,
    error::{CliError, CliResult, Code},
    output::Output,
};

/// `grund context`.
pub type ContextsCommand = Noun<ContextsAction>;

/// What `grund context` does.
#[derive(Debug, Subcommand)]
pub enum ContextsAction {
    #[command(about = "Every context, and which is current")]
    List,
    #[command(about = "Make a context current")]
    Use {
        #[arg(value_name = "NAME")]
        name: String,
    },
    #[command(about = "One context: its instance, account, organisation and credential kind")]
    Show {
        #[arg(value_name = "NAME", help = "Default: the current context")]
        name: Option<String>,
    },
    #[command(about = "Rename a context")]
    Rename {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(value_name = "NEW")]
        new: String,
    },
    #[command(about = "Forget a context and its credential, ending its session at the instance")]
    Remove {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long, help = "Do not ask; needed when nobody can be asked")]
        yes: bool,
    },
}

const CONTEXTS: &[(&str, &str)] = &[
    ("NAME", "/name"),
    ("INSTANCE", "/instance"),
    ("ORG", "/organisation"),
    ("USER", "/username"),
    ("CREDENTIAL", "/credential"),
];

fn shown(context: &Context, current: &str) -> Value {
    let mut value = json!({
        "name": context.name,
        "instance": context.url,
        "credential": context.kind(),
    });
    crate::context::set_if(&mut value, "username", context.username.clone());
    crate::context::set_if(&mut value, "organisation", context.organisation.clone());
    if context.name == current {
        value["current"] = json!(true);
    }
    value
}

fn missing(name: &str) -> CliError {
    CliError::new(Code::NotFound, format!("no context {name}"))
        .hint("grund context list")
        .field("name")
}

fn valid(name: &str) -> CliResult<String> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Err(CliError::usage(
            "a context name is 1 to 64 letters, digits, dots, colons, dashes or underscores",
        )
        .field("new"));
    }
    Ok(name.to_string())
}

/// Runs a `grund context` verb.
pub async fn run(ctx: &Ctx, action: ContextsAction) -> CliResult<Output> {
    let path = ctx.credentials_path()?;
    let mut file = ctx.credentials()?;
    match action {
        ContextsAction::List => {
            let contexts: Vec<Value> = file
                .contexts
                .iter()
                .map(|c| shown(c, &file.current))
                .collect();
            let mut value = json!({"contexts": contexts});
            crate::context::set_if(&mut value, "current", file.current.clone());
            Ok(Output::table(value, "/contexts", CONTEXTS))
        }
        ContextsAction::Use { name } => {
            if file.context(&name).is_none() {
                return Err(missing(&name));
            }
            file.current = name.clone();
            file.save(&path)?;
            Ok(done(format!("{name} is the current context.")))
        }
        ContextsAction::Show { name } => {
            let name = match name.or_else(|| ctx.global.context.clone()) {
                Some(name) => name,
                None if !file.current.is_empty() => file.current.clone(),
                None => {
                    return Err(CliError::new(Code::NotSignedIn, "no context is current")
                        .hint("run grund auth login <instance>"));
                }
            };
            let context = file.context(&name).ok_or_else(|| missing(&name))?;
            Ok(Output::fields(shown(context, &file.current)))
        }
        ContextsAction::Rename { name, new } => {
            let new = valid(&new)?;
            if file.context(&new).is_some() {
                return Err(
                    CliError::new(Code::Conflict, format!("a context is called {new}"))
                        .field("new"),
                );
            }
            let context = file.context_mut(&name).ok_or_else(|| missing(&name))?;
            context.name = new.clone();
            if file.current == name {
                file.current = new.clone();
            }
            file.save(&path)?;
            Ok(done(format!("Renamed context {name} to {new}.")))
        }
        ContextsAction::Remove { name, yes } => {
            let context = file.context(&name).cloned().ok_or_else(|| missing(&name))?;
            ctx.confirm(
                yes,
                &format!(
                    "Forget context {name} and its credential for {}",
                    context.url
                ),
            )?;
            let mut revoked = false;
            if context.kind() == "session" {
                let api = Api::new(&context.url, Some(context.credential.clone()))?;
                match api
                    .call("grund.account.v1.AccountService/ListSessions", json!({}))
                    .await
                {
                    Ok(sessions) => {
                        if let Some(id) = sessions["sessions"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|s| s["current"].as_bool() == Some(true))
                            .and_then(|s| s["sessionId"].as_str())
                        {
                            api.call(
                                "grund.account.v1.AccountService/RevokeSession",
                                json!({"sessionId": id}),
                            )
                            .await?;
                            revoked = true;
                        }
                    }
                    Err(error)
                        if matches!(error.code, Code::Unauthenticated | Code::Unavailable) => {}
                    Err(error) => return Err(error),
                }
            }
            file.remove(&name);
            file.save(&path)?;
            Ok(done(if revoked {
                format!("Forgot context {name}; its session is revoked.")
            } else if context.kind() == "token" {
                format!(
                    "Forgot context {name}. Its token stays live until it expires or is revoked."
                )
            } else {
                format!("Forgot context {name}.")
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_context_name_is_a_short_word_of_safe_characters() {
        assert_eq!(valid(" home-lab ").unwrap(), "home-lab");
        assert_eq!(
            valid("grund.example.com:8443").unwrap(),
            "grund.example.com:8443"
        );
        assert!(valid("").is_err());
        assert!(valid("two words").is_err());
        assert!(valid(&"x".repeat(65)).is_err());
    }

    #[test]
    fn a_shown_context_names_its_credential_kind_never_the_secret() {
        let context = Context {
            name: "home".into(),
            url: "https://grund.example.com".into(),
            credential: "grund_cli_secret".into(),
            username: "kasper".into(),
            organisation: "acme".into(),
        };
        let value = shown(&context, "home");
        assert_eq!(value["credential"], "session");
        assert_eq!(value["current"], true);
        assert!(!value.to_string().contains("grund_cli_secret"));
    }
}
