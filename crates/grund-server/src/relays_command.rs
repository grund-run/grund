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

use crate::config::DatabaseArgs;

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

/// Runs `grund relays`.
pub async fn run(command: RelaysCommand) -> anyhow::Result<()> {
    command.database.validate()?;
    let pool = crate::db::connect(&command.database).await?;
    match command.action {
        RelaysAction::Token { host } => {
            let token = crate::services::relays::mint_token(&pool, &host).await?;
            eprintln!(
                "A one-time token for a grund relay at {}, valid for {} minutes. Give it to the \
                 relay as GRUND_RELAY_ENROLLMENT_TOKEN; the host must be in GRUND_RELAYS.",
                crate::services::relays::parse_host(&host)?,
                crate::services::relays::TOKEN_TTL.as_secs() / 60
            );
            println!("{token}");
        }
        RelaysAction::Revoke { host } => {
            let host = crate::services::relays::parse_host(&host)?;
            match grund_store::relays::revoke_host(&pool, &host).await? {
                0 => eprintln!(
                    "No relay is enrolled for {host}; its unused tokens, if any, are gone."
                ),
                _ => eprintln!("Revoked the relay for {host}."),
            }
        }
        RelaysAction::List => {
            for relay in grund_store::relays::list(&pool).await? {
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
