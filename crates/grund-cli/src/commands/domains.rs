//! `grund domains`: the organisation's custom domains, over
//! `grund.domain.v1.DomainService`.

use clap::Subcommand;
use serde_json::json;

use crate::{
    commands::{Noun, done, dry_run},
    context::Ctx,
    error::CliResult,
    output::Output,
};

const SERVICE: &str = "grund.domain.v1.DomainService";

/// `grund domains`.
pub type DomainsCommand = Noun<DomainsAction>;

/// What `grund domains` does.
#[derive(Debug, Subcommand)]
pub enum DomainsAction {
    #[command(about = "The organisation's domains and their status")]
    List,
    #[command(about = "One domain: its TXT record, the app it is bound to, its certificate")]
    Get {
        #[arg(value_name = "DOMAIN")]
        domain: String,
    },
    #[command(about = "Add a domain; the answer names the TXT record that proves it is yours")]
    Add {
        #[arg(value_name = "DOMAIN")]
        domain: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Look the TXT record up now")]
    Verify {
        #[arg(value_name = "DOMAIN")]
        domain: String,
    },
    #[command(about = "Serve an app on a verified domain; its certificate follows within minutes")]
    Bind {
        #[arg(value_name = "DOMAIN")]
        domain: String,
        #[arg(value_name = "APP", help = "An app with a public http or h2c port")]
        app: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Stop serving the domain's app on it")]
    Unbind {
        #[arg(value_name = "DOMAIN")]
        domain: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(
        about = "Remove a domain; a verified one is held for a cool-down before another organisation can add it"
    )]
    Remove {
        #[arg(value_name = "DOMAIN")]
        domain: String,
        #[arg(long, help = "Do not ask; needed when nobody can be asked")]
        yes: bool,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
}

const DOMAINS: &[(&str, &str)] = &[
    ("DOMAIN", "/name"),
    ("STATUS", "/status"),
    ("APP", "/app"),
    ("PROBLEM", "/problem"),
];

/// Runs a `grund domains` verb.
pub async fn run(ctx: &Ctx, action: DomainsAction) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    let call = |method: &str| format!("{SERVICE}/{method}");
    match action {
        DomainsAction::List => {
            let answer = api
                .call(&call("ListDomains"), json!({"organisation": org}))
                .await?;
            Ok(Output::table(answer, "/domains", DOMAINS))
        }
        DomainsAction::Get { domain } => Ok(Output::fields(
            api.call(
                &call("GetDomain"),
                json!({"organisation": org, "name": domain}),
            )
            .await?,
        )),
        DomainsAction::Add {
            domain,
            dry_run: preview,
        } => {
            let request = json!({"organisation": org, "name": domain});
            if preview {
                return Ok(dry_run(&[(call("AddDomain"), request)], vec![]));
            }
            Ok(Output::fields(api.call(&call("AddDomain"), request).await?))
        }
        DomainsAction::Verify { domain } => Ok(Output::fields(
            api.call(
                &call("VerifyDomain"),
                json!({"organisation": org, "name": domain}),
            )
            .await?,
        )),
        DomainsAction::Bind {
            domain,
            app,
            dry_run: preview,
        } => {
            let request = json!({"organisation": org, "name": domain, "app": app});
            if preview {
                return Ok(dry_run(&[(call("BindDomain"), request)], vec![]));
            }
            Ok(Output::fields(
                api.call(&call("BindDomain"), request).await?,
            ))
        }
        DomainsAction::Unbind {
            domain,
            dry_run: preview,
        } => {
            let request = json!({"organisation": org, "name": domain});
            if preview {
                return Ok(dry_run(&[(call("UnbindDomain"), request)], vec![]));
            }
            Ok(Output::fields(
                api.call(&call("UnbindDomain"), request).await?,
            ))
        }
        DomainsAction::Remove {
            domain,
            yes,
            dry_run: preview,
        } => {
            let request = json!({"organisation": org, "name": domain});
            if preview {
                return Ok(dry_run(&[(call("RemoveDomain"), request)], vec![]));
            }
            ctx.confirm(yes, &format!("Remove the domain {domain}"))?;
            api.call(&call("RemoveDomain"), request).await?;
            Ok(done(format!("Removed {domain}.")))
        }
    }
}
