//! `grund domains`: the organisation's custom domains, over
//! `grund.domain.v1.DomainService`.

use std::fmt::Write;

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::{
    commands::{done, dry_run},
    context::{Ctx, Global},
    error::CliResult,
    output::Output,
};

const SERVICE: &str = "grund.domain.v1.DomainService";

/// `grund domains` lists domains unless a verb is given.
#[derive(Debug, Args)]
pub struct DomainsCommand {
    #[command(flatten)]
    pub global: Global,
    #[arg(
        long,
        global = true,
        help = "Include setup steps, diagnostics, timestamps and retry counts in text output"
    )]
    pub details: bool,
    #[command(subcommand)]
    pub action: Option<DomainsAction>,
}

/// What `grund domains` does.
#[derive(Debug, Subcommand)]
pub enum DomainsAction {
    #[command(about = "The organisation's domains and their status")]
    List,
    #[command(about = "One domain's status and the records still needed")]
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
    #[command(about = "Use a verified parent domain for this organisation's app addresses")]
    AppDomain {
        #[arg(value_name = "DOMAIN")]
        domain: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Replace an app's address under its organisation's app domain")]
    Subdomain {
        #[arg(value_name = "APP")]
        app: String,
        #[arg(
            value_name = "LABEL",
            help = "One lowercase DNS label; omitted uses the app's name"
        )]
        label: Option<String>,
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

fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or_default()
}

fn steps(domain: &Value) -> impl Iterator<Item = &Value> {
    domain["setupSteps"].as_array().into_iter().flatten()
}

fn write_domain(text: &mut String, domain: &Value, details: bool) {
    let summary = field(domain, "setupSummary");
    let _ = writeln!(
        text,
        "{}: {}",
        field(domain, "name"),
        if summary.is_empty() {
            "Status not available"
        } else {
            summary
        }
    );
    let mut routing = false;
    if let Some(records) = domain["requiredRecords"].as_array() {
        for record in records {
            let kind = field(record, "type");
            let name = field(record, "name");
            let value = field(record, "value");
            let _ = writeln!(text, "  {kind}  {name}  {value}");
            routing |= kind == "CNAME";
        }
    }
    if routing {
        let _ = writeln!(
            text,
            "  For a root domain, use ALIAS/ANAME or CNAME flattening if your DNS provider supports it."
        );
    }
    if details {
        write_details(text, domain);
    }
}

fn write_details(text: &mut String, domain: &Value) {
    let _ = writeln!(text, "  Details:");
    for (label, key) in [
        ("Stored status", "status"),
        ("App", "app"),
        ("Parent domain", "parentDomain"),
        ("Managed app", "managedAppName"),
        ("Problem", "problem"),
        ("Verification record name", "verificationRecordName"),
        ("Verification record value", "verificationRecordValue"),
        ("Added", "addedAt"),
        ("Verified", "verifiedAt"),
        ("Bound", "boundAt"),
        ("Certificate expires", "certificateExpiresAt"),
        ("Next certificate attempt", "certificateNextAttemptAt"),
    ] {
        let value = field(domain, key);
        if !value.is_empty() {
            let _ = writeln!(text, "    {label}: {value}");
        }
    }
    let _ = writeln!(
        text,
        "    Failed certificate attempts: {}",
        domain["certificateAttempts"].as_i64().unwrap_or(0)
    );
    for step in steps(domain) {
        let state = field(step, "state");
        let state = state.strip_prefix("STEP_STATE_").unwrap_or(state);
        let _ = writeln!(
            text,
            "    {}: {}",
            field(step, "name"),
            state.to_ascii_lowercase()
        );
        let detail = field(step, "detail");
        if !detail.is_empty() {
            let _ = writeln!(text, "      {detail}");
        }
        let _ = writeln!(
            text,
            "      Last check: {}",
            step["checkedAt"].as_str().unwrap_or("not checked")
        );
        let _ = writeln!(
            text,
            "      Next retry: {}",
            step["nextRetryAt"].as_str().unwrap_or("not scheduled")
        );
    }
}

fn presented(answer: Value, details: bool) -> Output {
    let mut text = String::new();
    if let Some(domains) = answer["domains"].as_array() {
        for domain in domains {
            if !text.is_empty() {
                text.push('\n');
            }
            write_domain(&mut text, domain, details);
        }
    } else if answer["domain"].is_object() {
        write_domain(&mut text, &answer["domain"], details);
    }
    if text.is_empty() {
        text.push_str("No domains.\n");
    }
    Output::with_text(answer, text)
}

/// Runs `grund domains` or one of its verbs.
pub async fn run(ctx: &Ctx, command: DomainsCommand) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    let call = |method: &str| format!("{SERVICE}/{method}");
    let details = command.details;
    match command.action.unwrap_or(DomainsAction::List) {
        DomainsAction::List => {
            let answer = api
                .call(&call("ListDomains"), json!({"organisation": org}))
                .await?;
            Ok(presented(answer, details))
        }
        DomainsAction::Get { domain } => Ok(presented(
            api.call(
                &call("GetDomain"),
                json!({"organisation": org, "name": domain}),
            )
            .await?,
            details,
        )),
        DomainsAction::Add {
            domain,
            dry_run: preview,
        } => {
            let request = json!({"organisation": org, "name": domain});
            if preview {
                return Ok(dry_run(&[(call("AddDomain"), request)], vec![]));
            }
            Ok(presented(
                api.call(&call("AddDomain"), request).await?,
                details,
            ))
        }
        DomainsAction::Verify { domain } => Ok(presented(
            api.call(
                &call("VerifyDomain"),
                json!({"organisation": org, "name": domain}),
            )
            .await?,
            details,
        )),
        DomainsAction::Check { domain } => Ok(presented(
            api.call(
                &call("CheckDomain"),
                json!({"organisation": org, "name": domain}),
            )
            .await?,
            details,
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
            Ok(presented(
                api.call(&call("BindDomain"), request).await?,
                details,
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
            Ok(presented(
                api.call(&call("UnbindDomain"), request).await?,
                details,
            ))
        }
        DomainsAction::AppDomain {
            domain,
            dry_run: preview,
        } => {
            let request = json!({"organisation": org, "name": domain});
            if preview {
                return Ok(dry_run(&[(call("ConfigureAppDomain"), request)], vec![]));
            }
            Ok(presented(
                api.call(&call("ConfigureAppDomain"), request).await?,
                details,
            ))
        }
        DomainsAction::Subdomain {
            app,
            label,
            dry_run: preview,
        } => {
            let request =
                json!({"organisation": org, "app": app, "subdomain": label.unwrap_or_default()});
            if preview {
                return Ok(dry_run(&[(call("SetAppSubdomain"), request)], vec![]));
            }
            Ok(presented(
                api.call(&call("SetAppSubdomain"), request).await?,
                details,
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
