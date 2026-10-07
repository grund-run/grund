//! `grund machines`: the organisation's machines, over
//! `grund.machine.v1.MachineService`. A machine is named by its name or
//! its id.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::{
    api::Api,
    commands::{Noun, changes, done, dry_run},
    context::Ctx,
    error::{CliError, CliResult, Code},
    output::Output,
};

const SERVICE: &str = "grund.machine.v1.MachineService";

/// `grund machines`.
pub type MachinesCommand = Noun<MachinesAction>;

/// What `grund machines` does.
#[derive(Debug, Subcommand)]
pub enum MachinesAction {
    #[command(about = "The organisation's machines: own and leased, connected or not")]
    List,
    #[command(about = "One machine: facts, capabilities, labels, whether it is connected")]
    Get {
        #[arg(value_name = "MACHINE", help = "Its name or id")]
        machine: String,
    },
    #[command(
        about = "Mint a one-time setup code for a new machine and print the command that installs and joins it"
    )]
    Add {
        #[arg(
            value_name = "NAME",
            help = "The machine's name in the organisation; empty lets it choose"
        )]
        name: Option<String>,
        #[arg(
            long,
            value_name = "SECONDS",
            help = "How long the code works, at most 900. Default: 600"
        )]
        ttl: Option<u32>,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Show a machine's labels, or replace them with KEY=VALUE pairs")]
    Labels {
        #[arg(value_name = "MACHINE")]
        machine: String,
        #[arg(value_name = "KEY=VALUE")]
        labels: Vec<String>,
        #[arg(long, help = "Remove every label")]
        clear: bool,
        #[arg(long, help = "Show the request and what changes instead of sending it")]
        dry_run: bool,
    },
    #[command(
        name = "out-of-service",
        about = "Take a machine out of service: nothing new lands on it and its copies move to other machines"
    )]
    OutOfService {
        #[arg(value_name = "MACHINE")]
        machine: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(name = "in-service", about = "Put a machine back in service")]
    InService {
        #[arg(value_name = "MACHINE")]
        machine: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(
        about = "Revoke an own machine: it can no longer reach the instance. Take it out of service first"
    )]
    Remove {
        #[arg(value_name = "MACHINE")]
        machine: String,
        #[arg(long, help = "Do not ask; needed when nobody can be asked")]
        yes: bool,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
}

const MACHINES: &[(&str, &str)] = &[
    ("NAME", "/name"),
    ("ID", "/machineId"),
    ("CONNECTED", "/connected"),
    ("STATE", "/state"),
    ("OUT OF SERVICE", "/outOfServiceSince"),
    ("LABELS", "/labels"),
];

async fn find(api: &Api, org: &str, machine: &str) -> CliResult<Value> {
    let answer = api
        .call(
            &format!("{SERVICE}/ListMachines"),
            json!({"organisation": org}),
        )
        .await?;
    answer["machines"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|m| m["name"] == json!(machine) || m["machineId"] == json!(machine))
        .cloned()
        .ok_or_else(|| {
            CliError::new(Code::NotFound, format!("no machine {machine} in {org}"))
                .hint("grund machines list")
        })
}

/// Runs a `grund machines` verb.
pub async fn run(ctx: &Ctx, action: MachinesAction) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    match action {
        MachinesAction::List => {
            let answer = api
                .call(
                    &format!("{SERVICE}/ListMachines"),
                    json!({"organisation": org}),
                )
                .await?;
            Ok(Output::table(answer, "/machines", MACHINES))
        }
        MachinesAction::Get { machine } => {
            let found = find(&api, &org, &machine).await?;
            let answer = api
                .call(
                    &format!("{SERVICE}/GetMachine"),
                    json!({"organisation": org, "machineId": found["machineId"]}),
                )
                .await?;
            Ok(Output::fields(answer))
        }
        MachinesAction::Add {
            name,
            ttl,
            dry_run: preview,
        } => {
            let mut request = json!({"organisation": org, "name": name.unwrap_or_default()});
            if let Some(ttl) = ttl {
                request["ttlSeconds"] = json!(ttl);
            }
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/CreateJoinToken"), request)],
                    vec![],
                ));
            }
            let mut answer = api
                .call(&format!("{SERVICE}/CreateJoinToken"), request)
                .await?;
            let token = answer["token"].as_str().unwrap_or_default().to_string();
            answer["joinCommand"] = json!(format!("grund join --url {} {token}", api.origin()));
            let shown = if answer["installCommand"]
                .as_str()
                .is_some_and(|c| !c.is_empty())
            {
                "/installCommand"
            } else {
                "/joinCommand"
            };
            Ok(Output::line(answer, shown))
        }
        MachinesAction::Labels {
            machine,
            labels,
            clear,
            dry_run: preview,
        } => {
            let found = find(&api, &org, &machine).await?;
            if labels.is_empty() && !clear {
                return Ok(Output::fields(json!({"machine": found})));
            }
            let mut map = serde_json::Map::new();
            for pair in &labels {
                let (k, v) = pair
                    .split_once('=')
                    .filter(|(k, _)| !k.is_empty())
                    .ok_or_else(|| {
                        CliError::usage(format!("{pair} is not KEY=VALUE")).field("labels")
                    })?;
                map.insert(k.to_string(), json!(v));
            }
            let request = json!({
                "organisation": org,
                "machineId": found["machineId"],
                "labels": Value::Object(map.clone()),
            });
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/SetMachineLabels"), request)],
                    changes("/labels", &found["labels"], &Value::Object(map)),
                ));
            }
            let answer = api
                .call(&format!("{SERVICE}/SetMachineLabels"), request)
                .await?;
            Ok(Output::fields(answer))
        }
        MachinesAction::OutOfService {
            machine,
            dry_run: preview,
        } => in_service(&api, &org, &machine, false, preview).await,
        MachinesAction::InService {
            machine,
            dry_run: preview,
        } => in_service(&api, &org, &machine, true, preview).await,
        MachinesAction::Remove {
            machine,
            yes,
            dry_run: preview,
        } => {
            let found = find(&api, &org, &machine).await?;
            let request = json!({"organisation": org, "machineId": found["machineId"]});
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/RevokeMachine"), request)],
                    vec![],
                ));
            }
            ctx.confirm(
                yes,
                &format!("Revoke the machine {machine}; it can no longer reach the instance"),
            )?;
            api.call(&format!("{SERVICE}/RevokeMachine"), request)
                .await?;
            Ok(done(format!("Revoked {machine}.")))
        }
    }
}

async fn in_service(
    api: &Api,
    org: &str,
    machine: &str,
    in_service: bool,
    preview: bool,
) -> CliResult<Output> {
    let found = find(api, org, machine).await?;
    let request =
        json!({"organisation": org, "machineId": found["machineId"], "inService": in_service});
    if preview {
        return Ok(dry_run(
            &[(format!("{SERVICE}/SetMachineInService"), request)],
            vec![],
        ));
    }
    let answer = api
        .call(&format!("{SERVICE}/SetMachineInService"), request)
        .await?;
    Ok(Output::fields(answer))
}
