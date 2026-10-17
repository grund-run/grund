//! `grund domains`: the organisation's custom domains, over
//! `grund.domain.v1.DomainService`.

use std::fmt::Write;

use clap::Subcommand;
use serde_json::{Value, json};

use crate::{
    commands::{Noun, done, dry_run},
    context::Ctx,
    error::CliResult,
    output::{Format, Output},
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
    #[command(about = "Check domain setup and retry now")]
    Check {
        #[arg(value_name = "DOMAIN")]
        domain: String,
    },
    #[command(
        about = "Bind a verified domain to an app; in custom-only mode, bind before publishing its HTTP port"
    )]
    Bind {
        #[arg(value_name = "DOMAIN")]
        domain: String,
        #[arg(
            value_name = "APP",
            help = "An existing app (private apps can be bound in custom-only mode)"
        )]
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

fn listed(answer: Value) -> Output {
    let summary = Output::table(answer, "/domains", DOMAINS);
    let mut text = summary.render(Format::Text);
    if let Some(domains) = summary.value["domains"].as_array() {
        for domain in domains {
            let _ = writeln!(text, "\n{}", domain["name"].as_str().unwrap_or_default());
            let _ = writeln!(
                text,
                "  Failed certificate attempts: {}",
                domain["certificateAttempts"].as_i64().unwrap_or(0)
            );
            let _ = writeln!(
                text,
                "  Next certificate attempt: {}",
                domain["certificateNextAttemptAt"]
                    .as_str()
                    .unwrap_or("not scheduled")
            );
            if let Some(steps) = domain["setupSteps"].as_array() {
                for step in steps {
                    let state = step["state"].as_str().unwrap_or("STEP_STATE_UNSPECIFIED");
                    let state = state.strip_prefix("STEP_STATE_").unwrap_or(state);
                    let _ = writeln!(
                        text,
                        "  {}: {}",
                        step["name"].as_str().unwrap_or_default(),
                        state.to_ascii_lowercase()
                    );
                    if let Some(detail) = step["detail"].as_str().filter(|s| !s.is_empty()) {
                        let _ = writeln!(text, "    {detail}");
                    }
                    let _ = writeln!(
                        text,
                        "    Last check: {}",
                        step["checkedAt"].as_str().unwrap_or("not checked")
                    );
                    let _ = writeln!(
                        text,
                        "    Next retry: {}",
                        step["nextRetryAt"].as_str().unwrap_or("not scheduled")
                    );
                }
            }
        }
    }
    Output::with_text(summary.value, text)
}

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
            Ok(listed(answer))
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
        DomainsAction::Check { domain } => Ok(Output::fields(
            api.call(
                &call("CheckDomain"),
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
