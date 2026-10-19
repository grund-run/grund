//! The client command tree: nouns, then verbs. Each verb is one function
//! returning an [`Output`], which [`crate::run`] prints.

pub mod app_telemetry;
pub mod apps;
pub mod auth;
pub mod domains;
pub mod machines;
pub mod members;
pub mod notifications;
pub mod orgs;
pub mod registries;
pub mod selfdesc;
pub mod stacks;
pub mod system;
pub mod system_update;
pub mod tokens;
pub mod volumes;

use clap::{Args, Subcommand};

use crate::{
    context::{Ctx, Global},
    error::CliResult,
    output::Output,
};

/// The first word of every client command, so a refused command line can
/// be told apart from an operator's.
pub const CLIENT_NOUNS: &[&str] = &[
    "install",
    "uninstall",
    "update",
    "auth",
    "org",
    "app",
    "stack",
    "volume",
    "machine",
    "domain",
    "member",
    "notification",
    "registry",
    "describe",
    "schema",
    "skill",
    "mcp",
];

/// A client command.
#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(
        about = "Install the self-hosted dashboard or connect this machine; requires Linux and root"
    )]
    Install(system::InstallArgs),
    #[command(about = "Stop and remove managed services, keeping configuration, identity and data")]
    Uninstall(system::UninstallArgs),
    #[command(
        about = "Update grund on this computer, or back up and update the self-hosted server"
    )]
    Update(system_update::UpdateArgs),
    #[command(about = "Sign in and access tokens")]
    Auth(auth::AuthCommand),
    #[command(about = "Organisations and the default one")]
    Org(orgs::OrgsCommand),
    #[command(about = "Deploy, inspect and change apps")]
    App(Box<apps::AppsCommand>),
    #[command(about = "Apps deployed together")]
    Stack(Box<stacks::StacksCommand>),
    #[command(about = "Storage that outlives a release")]
    Volume(volumes::VolumesCommand),
    #[command(about = "Your machines and grund machines")]
    Machine(machines::MachinesCommand),
    #[command(about = "Your own web addresses")]
    Domain(domains::DomainsCommand),
    #[command(about = "Who is in the organisation")]
    Member(members::MembersCommand),
    #[command(about = "What needs your attention")]
    Notification(notifications::NotificationsCommand),
    #[command(about = "Private image registry logins")]
    Registry(registries::RegistriesCommand),
    #[command(about = "Every command as JSON")]
    Describe(selfdesc::DescribeArgs),
    #[command(about = "JSON Schemas for grund.yaml and output")]
    Schema(selfdesc::SchemaArgs),
    #[command(about = "SKILL.md for coding agents")]
    Skill(selfdesc::SkillCommand),
    #[command(about = "Serve commands as MCP tools")]
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
            Command::Install(a) => &a.global,
            Command::Uninstall(a) => &a.global,
            Command::Update(a) => &a.global,
            Command::Auth(c) => &c.global,
            Command::Org(c) => &c.global,
            Command::App(c) => &c.global,
            Command::Stack(c) => &c.global,
            Command::Volume(c) => &c.global,
            Command::Machine(c) => &c.global,
            Command::Domain(c) => &c.global,
            Command::Member(c) => &c.global,
            Command::Notification(c) => &c.global,
            Command::Registry(c) => &c.global,
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
        Command::Install(args) => system::install(ctx, args).await?,
        Command::Uninstall(args) => system::uninstall(ctx, args).await?,
        Command::Update(args) => system_update::update(ctx, args).await?,
        Command::Auth(command) => match command.action {
            auth::AuthAction::Login(args) => auth::login(ctx, args, revision).await?,
            auth::AuthAction::Logout => auth::logout(ctx).await?,
            auth::AuthAction::Status => auth::status(ctx).await?,
            auth::AuthAction::Token { action } => tokens::run(ctx, action).await?,
        },
        Command::Org(command) => orgs::run(ctx, command.action).await?,
        Command::App(command) => match command.action {
            apps::AppsAction::Logs(args) if args.options.follow => {
                let api = ctx.api()?;
                let org = ctx.org(&api).await?;
                app_telemetry::follow(ctx, &api, &org, args).await?;
                return Ok(None);
            }
            action => apps::run(ctx, action).await?,
        },
        Command::Stack(command) => match command.action {
            stacks::StacksAction::Logs {
                stack,
                service,
                options,
            } if options.follow => {
                stacks::follow(ctx, &stack, &service, options).await?;
                return Ok(None);
            }
            action => stacks::run(ctx, action).await?,
        },
        Command::Volume(command) => volumes::run(ctx, command.action).await?,
        Command::Machine(command) => machines::run(ctx, command.action).await?,
        Command::Domain(command) => domains::run(ctx, command).await?,
        Command::Member(command) => members::run_members(ctx, command.action).await?,
        Command::Notification(command) => notifications::run(ctx, command).await?,
        Command::Registry(command) => registries::run(ctx, command.action).await?,
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
