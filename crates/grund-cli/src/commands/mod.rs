//! The client command tree: nouns, then verbs. Each verb is one function
//! returning an [`Output`], which [`crate::run`] prints.

pub mod apps;
pub mod auth;
pub mod domains;
pub mod machines;
pub mod members;
pub mod orgs;
pub mod registries;
pub mod selfdesc;
pub mod tokens;

use clap::{Args, Subcommand};

use crate::{
    context::{Ctx, Global},
    error::CliResult,
    output::Output,
};

/// The first word of every client command, so a refused command line can
/// be told apart from an operator's.
pub const CLIENT_NOUNS: &[&str] = &[
    "login",
    "logout",
    "whoami",
    "orgs",
    "apps",
    "machines",
    "domains",
    "members",
    "invitations",
    "tokens",
    "registries",
    "describe",
    "schema",
    "skill",
    "mcp",
];

/// A client command.
#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Sign in to an instance: in the browser, or with a token from stdin")]
    Login(auth::LoginArgs),
    #[command(about = "Sign out of the instance and forget its credential")]
    Logout(auth::LogoutArgs),
    #[command(about = "Who the credential is, on which instance, and the default organisation")]
    Whoami(auth::WhoamiArgs),
    #[command(about = "Organisations: list, show, choose the default, create, rename, delete")]
    Orgs(orgs::OrgsCommand),
    #[command(
        about = "Apps: list, status, deploy from grund.yaml or flags, change a setting, roll back, delete. Operators: grund operator apps suspend|lift"
    )]
    Apps(Box<apps::AppsCommand>),
    #[command(about = "Machines: list, add with a setup code, labels, out of service, remove")]
    Machines(machines::MachinesCommand),
    #[command(about = "Custom domains: add, verify, bind to an app, unbind, remove")]
    Domains(domains::DomainsCommand),
    #[command(about = "Members of the organisation: list, invite, change a role, remove")]
    Members(members::MembersCommand),
    #[command(about = "Invitations not accepted yet: list, revoke")]
    Invitations(members::InvitationsCommand),
    #[command(about = "Personal access tokens for CI and agents: list, create, revoke")]
    Tokens(tokens::TokensCommand),
    #[command(about = "Logins to private container registries: list, set, remove")]
    Registries(registries::RegistriesCommand),
    #[command(
        about = "The whole command tree as JSON: arguments, types, defaults, examples, output schemas, error codes"
    )]
    Describe(selfdesc::DescribeArgs),
    #[command(about = "JSON Schemas: grund.yaml, a command's output, the error")]
    Schema(selfdesc::SchemaArgs),
    #[command(about = "A SKILL.md for coding agents: print it, or install it")]
    Skill(selfdesc::SkillCommand),
    #[command(about = "Serve the client commands as MCP tools over stdio")]
    Mcp(selfdesc::McpArgs),
}

/// A noun's flags and its verb.
#[derive(Debug, Args)]
pub struct Noun<A: Subcommand> {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub action: A,
}

impl Command {
    /// The global flags given with it.
    pub fn global(&self) -> &Global {
        match self {
            Command::Login(a) => &a.global,
            Command::Logout(a) => &a.global,
            Command::Whoami(a) => &a.global,
            Command::Orgs(c) => &c.global,
            Command::Apps(c) => &c.global,
            Command::Machines(c) => &c.global,
            Command::Domains(c) => &c.global,
            Command::Members(c) => &c.global,
            Command::Invitations(c) => &c.global,
            Command::Tokens(c) => &c.global,
            Command::Registries(c) => &c.global,
            Command::Describe(a) => &a.global,
            Command::Schema(a) => &a.global,
            Command::Skill(c) => &c.global,
            Command::Mcp(a) => &a.global,
        }
    }
}

/// Runs `command`. `None`: it printed what it had to say itself (`grund
/// mcp`, `grund skill`).
pub async fn execute(
    command: Command,
    ctx: &Ctx,
    root: &clap::Command,
    revision: &'static str,
) -> CliResult<Option<Output>> {
    let output = match command {
        Command::Login(args) => auth::login(ctx, args, revision).await?,
        Command::Logout(args) => auth::logout(ctx, args).await?,
        Command::Whoami(args) => auth::whoami(ctx, args).await?,
        Command::Orgs(command) => orgs::run(ctx, command.action).await?,
        Command::Apps(command) => apps::run(ctx, command.action).await?,
        Command::Machines(command) => machines::run(ctx, command.action).await?,
        Command::Domains(command) => domains::run(ctx, command.action).await?,
        Command::Members(command) => members::run_members(ctx, command.action).await?,
        Command::Invitations(command) => members::run_invitations(ctx, command.action).await?,
        Command::Tokens(command) => tokens::run(ctx, command.action).await?,
        Command::Registries(command) => registries::run(ctx, command.action).await?,
        Command::Describe(args) => selfdesc::describe(root, args)?,
        Command::Schema(args) => selfdesc::schema(root, args)?,
        Command::Skill(command) => return selfdesc::skill(ctx, root, command),
        Command::Mcp(_) => {
            Box::pin(crate::mcp::serve(root.clone(), revision)).await?;
            return Ok(None);
        }
    };
    Ok(Some(output))
}

/// `grund.cli.v1.DryRun`: the calls a command would make and what they
/// would change. Nothing was sent.
pub fn dry_run(calls: &[(String, serde_json::Value)], changes: Vec<serde_json::Value>) -> Output {
    let mut value = serde_json::json!({
        "dryRun": true,
        "calls": calls
            .iter()
            .map(|(rpc, request)| serde_json::json!({"rpc": rpc, "request": request}))
            .collect::<Vec<_>>(),
    });
    if !changes.is_empty() {
        value["changes"] = serde_json::Value::Array(changes);
    }
    Output::table(
        value,
        "/changes",
        &[
            ("CHANGE", "/path"),
            ("BEFORE", "/before"),
            ("AFTER", "/after"),
        ],
    )
}

/// `grund.cli.v1.Done`: a command whose answer is empty.
pub fn done(message: impl Into<String>) -> Output {
    Output::line(serde_json::json!({"message": message.into()}), "/message")
}

/// `grund.cli.v1.Change`s from `before` to `after`, as JSON pointers under
/// `prefix`: objects field by field, anything else whole.
pub fn changes(
    prefix: &str,
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> Vec<serde_json::Value> {
    use serde_json::Value;
    let mut found = Vec::new();
    match (before, after) {
        (Value::Object(old), Value::Object(new)) => {
            let mut keys: Vec<&String> = old.keys().chain(new.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let path = format!("{prefix}/{}", key.replace('~', "~0").replace('/', "~1"));
                found.extend(changes(
                    &path,
                    old.get(key).unwrap_or(&Value::Null),
                    new.get(key).unwrap_or(&Value::Null),
                ));
            }
        }
        (old, new) if old != new => {
            let mut change = serde_json::json!({"path": prefix});
            if !old.is_null() {
                change["before"] = old.clone();
            }
            if !new.is_null() {
                change["after"] = new.clone();
            }
            found.push(change);
        }
        _ => {}
    }
    found
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn changes_name_each_field_that_differs_by_its_pointer() {
        let before =
            json!({"image": "nginx:1.26", "env": [{"name": "A", "value": "1"}], "ports": []});
        let after =
            json!({"image": "nginx:1.27", "env": [{"name": "A", "value": "1"}], "command": ["x"]});
        assert_eq!(
            changes("/spec", &before, &after),
            vec![
                json!({"path": "/spec/command", "after": ["x"]}),
                json!({"path": "/spec/image", "before": "nginx:1.26", "after": "nginx:1.27"}),
                json!({"path": "/spec/ports", "before": []}),
            ]
        );
    }
}
