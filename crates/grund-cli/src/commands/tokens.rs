//! `grund tokens`: personal access tokens, over
//! `grund.token.v1.TokenService`. Needs a person's session (`grund login`):
//! a token never makes or revokes tokens.

use clap::Subcommand;
use serde_json::json;

use crate::{
    commands::{Noun, done, dry_run},
    context::Ctx,
    error::{CliError, CliResult, Code},
    output::Output,
};

const SERVICE: &str = "grund.token.v1.TokenService";

/// `grund tokens`.
pub type TokensCommand = Noun<TokensAction>;

/// What `grund tokens` does.
#[derive(Debug, Subcommand)]
pub enum TokensAction {
    #[command(
        about = "Live tokens: all of the organisation's for owners and admins, your own otherwise"
    )]
    List,
    #[command(about = "Make a token. Its secret is printed once (secret in the JSON)")]
    Create {
        #[arg(
            long,
            value_name = "NAME",
            help = "Such as the CI job that uses it; 1 to 64 characters"
        )]
        name: String,
        #[arg(long, value_name = "DAYS", value_parser = ["7", "30", "90", "365"], default_value = "30")]
        days: String,
        #[arg(
            long,
            value_parser = ["deploy", "full"],
            default_value = "deploy",
            help = "deploy: create, deploy and change apps. full: everything your role allows in the organisation, but never tokens, the account, or creating, renaming or deleting organisations"
        )]
        scope: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Revoke a token at once")]
    Revoke {
        #[arg(
            value_name = "TOKEN",
            help = "Its id, or its name when only one live token has it"
        )]
        token: String,
        #[arg(long, help = "Do not ask; needed when nobody can be asked")]
        yes: bool,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
}

const TOKENS: &[(&str, &str)] = &[
    ("NAME", "/name"),
    ("SCOPE", "/scope"),
    ("BY", "/createdBy"),
    ("EXPIRES", "/expiresAt"),
    ("LAST USED", "/lastUsedAt"),
    ("ID", "/tokenId"),
];

/// Runs a `grund tokens` verb.
pub async fn run(ctx: &Ctx, action: TokensAction) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    match action {
        TokensAction::List => {
            let answer = api
                .call(
                    &format!("{SERVICE}/ListTokens"),
                    json!({"organisation": org}),
                )
                .await?;
            Ok(Output::table(answer, "/tokens", TOKENS))
        }
        TokensAction::Create {
            name,
            days,
            scope,
            dry_run: preview,
        } => {
            let request = json!({
                "organisation": org,
                "name": name,
                "lifetimeDays": days.parse::<u32>().unwrap_or(30),
                "scope": if scope == "full" { "TOKEN_SCOPE_FULL" } else { "TOKEN_SCOPE_DEPLOY" },
            });
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/CreateToken"), request)],
                    vec![],
                ));
            }
            let answer = api.call(&format!("{SERVICE}/CreateToken"), request).await?;
            Ok(Output::line(answer, "/secret"))
        }
        TokensAction::Revoke {
            token,
            yes,
            dry_run: preview,
        } => {
            let list = api
                .call(
                    &format!("{SERVICE}/ListTokens"),
                    json!({"organisation": org}),
                )
                .await?;
            let tokens = list["tokens"].as_array().cloned().unwrap_or_default();
            let by_id = tokens.iter().find(|t| t["tokenId"] == json!(token));
            let by_name: Vec<_> = tokens
                .iter()
                .filter(|t| t["name"] == json!(token))
                .collect();
            let found = match (by_id, by_name.as_slice()) {
                (Some(found), _) => found.clone(),
                (None, [found]) => (*found).clone(),
                (None, []) => {
                    return Err(
                        CliError::new(Code::NotFound, format!("no live token {token}"))
                            .hint("grund tokens list"),
                    );
                }
                (None, _) => {
                    return Err(CliError::usage(format!(
                        "{} live tokens are named {token}; give the id",
                        by_name.len()
                    ))
                    .field("token"));
                }
            };
            let request = json!({"organisation": org, "tokenId": found["tokenId"]});
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/RevokeToken"), request)],
                    vec![],
                ));
            }
            ctx.confirm(
                yes,
                &format!(
                    "Revoke the token {}",
                    found["name"].as_str().unwrap_or_default()
                ),
            )?;
            api.call(&format!("{SERVICE}/RevokeToken"), request).await?;
            Ok(done(format!("Revoked {token}.")))
        }
    }
}
