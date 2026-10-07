//! `grund registries`: logins to private container registries, over
//! `grund.registry.v1.RegistryService`.

use clap::Subcommand;
use serde_json::json;

use crate::{
    commands::{Noun, done, dry_run},
    context::Ctx,
    error::{CliError, CliResult},
    output::Output,
};

const SERVICE: &str = "grund.registry.v1.RegistryService";

/// `grund registries`.
pub type RegistriesCommand = Noun<RegistriesAction>;

/// What `grund registries` does.
#[derive(Debug, Subcommand)]
pub enum RegistriesAction {
    #[command(about = "The organisation's registry logins: hosts and usernames, never passwords")]
    List,
    #[command(about = "Set the login for a host, the password or access token read from stdin")]
    Set {
        #[arg(
            value_name = "HOST",
            help = "As image references name it: ghcr.io, registry.example.com:5000"
        )]
        host: String,
        #[arg(long, value_name = "NAME")]
        username: String,
        #[arg(
            long,
            help = "Show the request (the password redacted) instead of sending it"
        )]
        dry_run: bool,
    },
    #[command(about = "Remove the login for a host")]
    Remove {
        #[arg(value_name = "HOST")]
        host: String,
        #[arg(long, help = "Do not ask; needed when nobody can be asked")]
        yes: bool,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
}

const LOGINS: &[(&str, &str)] = &[
    ("HOST", "/host"),
    ("USERNAME", "/username"),
    ("VERSION", "/version"),
    ("BY", "/updatedBy"),
    ("UPDATED", "/updatedAt"),
];

/// Runs a `grund registries` verb.
pub async fn run(ctx: &Ctx, action: RegistriesAction) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    match action {
        RegistriesAction::List => {
            let answer = api
                .call(
                    &format!("{SERVICE}/ListRegistryLogins"),
                    json!({"organisation": org}),
                )
                .await?;
            Ok(Output::table(answer, "/logins", LOGINS))
        }
        RegistriesAction::Set {
            host,
            username,
            dry_run: preview,
        } => {
            let password = ctx.read_stdin("The password or access token")?;
            let password = password.trim_end_matches(['\n', '\r']).to_string();
            if password.is_empty() {
                return Err(
                    CliError::usage("stdin is empty: give the password on stdin").field("stdin"),
                );
            }
            let request = json!({"organisation": org, "host": host, "username": username, "password": password});
            if preview {
                let mut shown = request.clone();
                shown["password"] = json!("<redacted>");
                return Ok(dry_run(
                    &[(format!("{SERVICE}/SetRegistryLogin"), shown)],
                    vec![],
                ));
            }
            Ok(Output::fields(
                api.call(&format!("{SERVICE}/SetRegistryLogin"), request)
                    .await?,
            ))
        }
        RegistriesAction::Remove {
            host,
            yes,
            dry_run: preview,
        } => {
            let request = json!({"organisation": org, "host": host});
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/RemoveRegistryLogin"), request)],
                    vec![],
                ));
            }
            ctx.confirm(yes, &format!("Remove the login for {host}"))?;
            api.call(&format!("{SERVICE}/RemoveRegistryLogin"), request)
                .await?;
            Ok(done(format!("Removed the login for {host}.")))
        }
    }
}
