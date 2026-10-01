//! `grund apps`: the operator's side of an app address (grund-docs
//! design/traffic.md §6.1, app-domains.md §5), run against the instance's
//! database like `grund migrate`.
//!
//! - `suspend <organisation>/<app> --reason <why>`: the edges answer the
//!   app's address with a fixed 451 page and open no stream, from their next
//!   route table (within seconds). Its copies and data are untouched.
//! - `lift <organisation>/<app>`: ends the suspension.

use clap::{Args, Subcommand};

use crate::config::DatabaseArgs;

/// `grund apps`.
#[derive(Debug, Clone, Args)]
pub struct AppsCommand {
    #[command(flatten)]
    pub database: DatabaseArgs,

    #[command(subcommand)]
    pub action: AppsAction,
}

/// What `grund apps` does.
#[derive(Debug, Clone, Subcommand)]
pub enum AppsAction {
    #[command(about = "Suspend ORGANISATION/APP's address: the edges answer it with a 451 page")]
    Suspend {
        app: String,
        #[arg(long)]
        reason: String,
    },
    #[command(about = "Lift ORGANISATION/APP's suspension")]
    Lift { app: String },
}

fn find(app: &str) -> anyhow::Result<(String, String)> {
    let (organisation, name) = app.split_once('/').ok_or_else(|| {
        anyhow::anyhow!("name the app as <organisation>/<app>, like kjuulh/photos")
    })?;
    Ok((
        organisation.trim().to_ascii_lowercase(),
        name.trim().to_ascii_lowercase(),
    ))
}

/// Runs `grund apps`.
pub async fn run(command: AppsCommand) -> anyhow::Result<()> {
    command.database.validate()?;
    let pool = crate::db::connect(&command.database).await?;
    let (target, suspend) = match &command.action {
        AppsAction::Suspend { app, reason } => {
            let reason = reason.trim();
            anyhow::ensure!(
                (1..=500).contains(&reason.len()),
                "--reason says why, in at most 500 bytes"
            );
            (app.clone(), Some(reason.to_string()))
        }
        AppsAction::Lift { app } => (app.clone(), None),
    };
    let (organisation, name) = find(&target)?;
    let app_id = grund_store::entry::app_by_slug(&pool, &organisation, &name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no live app {name} in the organisation {organisation}"))?;
    match suspend {
        Some(reason) => {
            grund_store::entry::suspend(&pool, app_id, &reason).await?;
            eprintln!(
                "Suspended {organisation}/{name}: the edges answer its address with 451 from their next route table."
            );
        }
        None => {
            if grund_store::entry::lift(&pool, app_id).await? {
                eprintln!("Lifted the suspension of {organisation}/{name}.");
            } else {
                eprintln!("{organisation}/{name} was not suspended.");
            }
        }
    }
    Ok(())
}
