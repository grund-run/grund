//! `grund relays`: the operator's side of relay enrollment (grund-docs
//! design/traffic.md §5.7), run against the instance's database like `grund
//! migrate`, for example `docker compose exec grund grund relays token
//! relay.example.com`.
//!
//! - `token <host>` mints a one-time token that enrolls one `grund relay`
//!   for `host` within an hour. The host must be in the instance's
//!   GRUND_RELAYS when the relay enrolls. Only the token's SHA-256 is
//!   stored; the token is printed once, to stdout.
//! - `revoke <host>` revokes the relay enrolled for `host`, and any unused
//!   token for it. It loses the certificate service and the access check
//!   from its next call.
//! - `list` prints every relay, active and revoked.

use clap::{Args, Subcommand};

use crate::{config::DatabaseArgs, services::relays::Role};

/// `grund relays`.
#[derive(Debug, Clone, Args)]
pub struct RelaysCommand {
    #[command(flatten)]
    pub database: DatabaseArgs,

    #[command(subcommand)]
    pub action: RelaysAction,
}

/// What `grund relays` does.
#[derive(Debug, Clone, Subcommand)]
pub enum RelaysAction {
    #[command(
        about = "Mint a one-time token that enrolls one grund relay for HOST, valid for an hour"
    )]
    Token { host: String },
    #[command(about = "Revoke the relay enrolled for HOST")]
    Revoke { host: String },
    #[command(about = "List every relay, active and revoked")]
    List,
}

/// `grund edges`: the same for `grund edge` nodes (traffic.md §6.7), whose
/// hosts must be in GRUND_EDGES. A revoked edge's key leaves every
/// machine's entry keys with the machine's next document.
#[derive(Debug, Clone, Args)]
pub struct EdgesCommand {
    #[command(flatten)]
    pub database: DatabaseArgs,

    #[command(subcommand)]
    pub action: EdgesAction,
}

/// What `grund edges` does.
#[derive(Debug, Clone, Subcommand)]
pub enum EdgesAction {
    #[command(
        about = "Mint a one-time token that enrolls one grund edge for HOST, valid for an hour"
    )]
    Token { host: String },
    #[command(about = "Revoke the edge enrolled for HOST")]
    Revoke { host: String },
    #[command(about = "List every edge, active and revoked")]
    List,
}

/// Runs `grund relays`.
pub async fn run(command: RelaysCommand) -> anyhow::Result<()> {
    let action = match command.action {
        RelaysAction::Token { host } => Action::Token(host),
        RelaysAction::Revoke { host } => Action::Revoke(host),
        RelaysAction::List => Action::List,
    };
    run_as(Role::Relay, &command.database, action).await
}

/// Runs `grund edges`.
pub async fn run_edges(command: EdgesCommand) -> anyhow::Result<()> {
    let action = match command.action {
        EdgesAction::Token { host } => Action::Token(host),
        EdgesAction::Revoke { host } => Action::Revoke(host),
        EdgesAction::List => Action::List,
    };
    run_as(Role::Edge, &command.database, action).await
}

enum Action {
    Token(String),
    Revoke(String),
    List,
}

async fn run_as(role: Role, database: &DatabaseArgs, action: Action) -> anyhow::Result<()> {
    database.validate()?;
    let pool = crate::db::connect(database).await?;
    let word = role.as_str();
    match action {
        Action::Token(host) => {
            let token = crate::services::relays::mint_role_token(&pool, role, &host).await?;
            eprintln!(
                "A one-time token for a grund {word} at {}, valid for {} minutes. Give it to the \
                 {word} as GRUND_{}_ENROLLMENT_TOKEN; the host must be in {}.",
                crate::services::relays::parse_host(&host)?,
                crate::services::relays::TOKEN_TTL.as_secs() / 60,
                word.to_ascii_uppercase(),
                role.setting()
            );
            println!("{token}");
        }
        Action::Revoke(host) => {
            let host = crate::services::relays::parse_host(&host)?;
            match grund_store::relays::revoke_host(&pool, word, &host).await? {
                0 => eprintln!(
                    "No {word} is enrolled for {host}; its unused tokens, if any, are gone."
                ),
                _ => eprintln!("Revoked the {word} for {host}."),
            }
        }
        Action::List => {
            for relay in grund_store::relays::list(&pool, word).await? {
                println!(
                    "{}\t{}\t{}\tenrolled {}{}",
                    relay.relay_id,
                    relay.host,
                    relay.state,
                    relay.enrolled_at.to_rfc3339(),
                    relay
                        .revoked_at
                        .map(|at| format!(", revoked {}", at.to_rfc3339()))
                        .unwrap_or_default()
                );
            }
        }
    }
    Ok(())
}
