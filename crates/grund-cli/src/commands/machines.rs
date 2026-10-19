//! `grund machine`: the organisation's machines, over
//! `grund.machine.v1.MachineService`. A machine is named by its name or
//! its id.

use chrono::{DateTime, Utc};
use clap::Subcommand;
use serde_json::{Value, json};

use crate::{
    api::Api,
    commands::{Noun, changes, done, dry_run},
    context::Ctx,
    error::{CliError, CliResult, Code},
    output::{Format, Output},
};

const SERVICE: &str = "grund.machine.v1.MachineService";
const HOSTED: &str = "grund.machine.v1.HostedMachineService";

/// `grund machine`.
pub type MachinesCommand = Noun<MachinesAction>;

/// What `grund machine` does.
#[derive(Debug, Subcommand)]
pub enum MachinesAction {
    #[command(
        about = "List machines, app counts, reservations, and reported host usage",
        long_about = "List the organisation's machines, connected or not, with app and instance counts, reserved versus total CPU, RAM and disk, and measured usage for the whole machine. Reservations are not actual usage. Missing reports are shown as Not reported; usage samples older than 30 seconds are Stale. JSON and YAML retain the complete API response."
    )]
    List,
    #[command(about = "Show hosted sizes, capacity and this organisation's aggregate allowance")]
    Offers,
    #[command(
        about = "Show a machine's details, workloads, reservations, and reported host usage",
        long_about = "Show every field returned for one machine, including its capabilities, labels, connection state, app and instance counts, reservations, workloads with desired and observed state, and available host telemetry with its sample time. Reservations are not actual usage; absent telemetry is not zero."
    )]
    Show {
        #[arg(value_name = "MACHINE", help = "Its name or id")]
        machine: String,
    },
    #[command(about = "Add your own machine, or claim hosted capacity with --hosted --size")]
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
        #[arg(
            long,
            conflicts_with = "ttl",
            requires = "size",
            help = "Claim a hosted machine instead of making a setup code"
        )]
        hosted: bool,
        #[arg(
            long,
            requires = "hosted",
            help = "Hosted size from grund machine offers"
        )]
        size: Option<String>,
        #[arg(
            long,
            requires = "hosted",
            help = "Hosted region; omit when the size has only one"
        )]
        region: Option<String>,
        #[arg(
            long,
            requires = "hosted",
            help = "Reuse this key to resume the same hosted request"
        )]
        idempotency_key: Option<String>,
        #[arg(
            long,
            requires = "hosted",
            help = "Purchased rental UUID; its size must match"
        )]
        rental_id: Option<String>,
    },
    #[command(about = "Show a machine's labels, or replace them with KEY=VALUE pairs")]
    Label {
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
        about = "Drain a machine: nothing new lands on it and its copies move to other machines"
    )]
    Drain {
        #[arg(value_name = "MACHINE")]
        machine: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Put a drained machine back in service")]
    Undrain {
        #[arg(value_name = "MACHINE")]
        machine: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Remove a machine from the organisation")]
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
    ("APPS", "/apps"),
    ("INSTANCES", "/instances"),
    ("CPU RESERVED/ALLOCATABLE", "/cpu"),
    ("RAM RESERVED/ALLOCATABLE", "/memory"),
    ("DISK RESERVED/TOTAL", "/disk"),
    ("HOST CPU USED", "/hostCpu"),
    ("HOST RAM USED", "/hostMemory"),
    ("HOST DISK USED/TOTAL", "/hostDisk"),
    ("USAGE SAMPLE", "/usage"),
    ("OUT OF SERVICE", "/outOfServiceSince"),
    ("LABELS", "/labels"),
];

fn number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn cpu(value: Option<u64>) -> String {
    value.map_or_else(
        || "Not reported".to_string(),
        |millis| format!("{}.{:03} cores", millis / 1000, millis % 1000),
    )
}

fn memory(value: Option<u64>) -> String {
    value.map_or_else(|| "Not reported".to_string(), |mib| format!("{mib} MiB"))
}

fn disk(value: Option<u64>) -> String {
    value.map_or_else(|| "Not reported".to_string(), |gib| format!("{gib} GiB"))
}

fn bytes(value: Option<u64>) -> String {
    value.map_or_else(
        || "Not reported".to_string(),
        |bytes| format!("{:.2} GiB", bytes as f64 / 1_073_741_824.0),
    )
}

fn machine_list(answer: Value) -> Output {
    let now = Utc::now();
    let rows = answer["machines"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|machine| {
            let activity = &machine["activity"];
            let capabilities = &machine["capabilities"];
            let usage = &capabilities["usage"];
            let reserved = |field: &str| {
                activity
                    .is_object()
                    .then(|| number(&activity[field]).unwrap_or(0))
            };
            let total = |field: &str| {
                let allocatable = capabilities["resourcesAllocatable"].as_bool().unwrap_or(false);
                let reported = number(&capabilities[field])
                    .filter(|value| *value > 0 || (allocatable && field != "diskGib"))
                    .or_else(|| {
                        if field == "cpuMillis" {
                            number(&machine["facts"]["cpus"]).and_then(|cpus| cpus.checked_mul(1000))
                        } else {
                            number(&machine["facts"][field])
                        }.filter(|value| *value > 0)
                    });
                reported.map(|value| {
                    if allocatable {
                        value
                    } else {
                        value.saturating_sub(match field {
                            "cpuMillis" => 250,
                            "memoryMib" => 256,
                            _ => 0,
                        })
                    }
                })
            };
            let disk_reserved = if activity["diskUnbounded"].as_bool().unwrap_or(false) {
                format!("{} + unbounded", disk(reserved("diskGib")))
            } else {
                disk(reserved("diskGib"))
            };
            let sample = if !usage.is_object() {
                "Not reported"
            } else {
                match usage["sampledAt"]
                    .as_str()
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                {
                    Some(sampled) if sampled > now => "Clock ahead",
                    Some(sampled)
                        if now.signed_duration_since(sampled) > chrono::Duration::seconds(30) =>
                    {
                        "Stale"
                    }
                    Some(_) => "Current",
                    None => "Unknown sample time",
                }
            };
            json!({
                "name": machine["name"],
                "machineId": machine["machineId"],
                "connected": if machine["connected"].as_bool().unwrap_or(false) { "yes" } else { "no" },
                "state": machine["state"],
                "apps": reserved("apps").map_or_else(|| "Not reported".to_string(), |n| n.to_string()),
                "instances": reserved("instances").map_or_else(|| "Not reported".to_string(), |n| n.to_string()),
                "cpu": format!("{} / {}", cpu(reserved("cpuMillis")), cpu(total("cpuMillis"))),
                "memory": format!("{} / {}", memory(reserved("memoryMib")), memory(total("memoryMib"))),
                "disk": format!("{disk_reserved} / {}", disk(total("diskGib"))),
                "hostCpu": cpu(number(&usage["cpuMillis"])),
                "hostMemory": bytes(number(&usage["memoryUsedBytes"])),
                "hostDisk": format!("{} / {}", bytes(number(&usage["diskUsedBytes"])), bytes(number(&usage["diskTotalBytes"]))),
                "usage": sample,
                "outOfServiceSince": machine["outOfServiceSince"],
                "labels": machine["labels"],
            })
        })
        .collect::<Vec<_>>();
    let text = Output::table(json!({"machines": rows}), "/machines", MACHINES).render(Format::Text);
    Output::with_text(answer, text)
}

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
                .hint("grund machine list")
        })
}

/// Runs a `grund machine` verb.
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
            Ok(if ctx.format == Format::Text {
                machine_list(answer)
            } else {
                Output::fields(answer)
            })
        }
        MachinesAction::Show { machine } => {
            let found = find(&api, &org, &machine).await?;
            let answer = api
                .call(
                    &format!("{SERVICE}/GetMachine"),
                    json!({"organisation": org, "machineId": found["machineId"]}),
                )
                .await?;
            Ok(Output::fields(answer))
        }
        MachinesAction::Offers => {
            let answer = api
                .call(
                    &format!("{HOSTED}/ListHostedOffers"),
                    json!({"organisation": org}),
                )
                .await?;
            let table = Output::table(
                answer.clone(),
                "/offers",
                &[
                    ("SIZE", "/size"),
                    ("REGION", "/region"),
                    ("VCPU", "/vcpus"),
                    ("RAM MIB", "/memoryMib"),
                    ("READY CAPACITY", "/available"),
                ],
            )
            .render(Format::Text);
            let allowance = &answer["allowance"];
            let usage = &answer["usage"];
            let source = match allowance["source"].as_str() {
                Some("billing_pending") => "Billing pending",
                Some("waiting_for_billing") => "Waiting for billing",
                Some("allowance_disabled") => {
                    "Hosted machines are turned off for this organisation"
                }
                Some("needs_plan") => "Needs a plan",
                Some("rental") => "Purchased rental allowance",
                _ => "Not available",
            };
            let waiting = match answer["waitingReason"].as_str() {
                Some("trial_capacity_full") => "Hosted capacity for trial organisations is full.\n",
                _ => "",
            };
            let text = format!(
                "{source}\nMachines: {} / {}; vCPU: {} / {}; RAM: {} / {} MiB\n{waiting}{table}",
                number(&usage["machines"]).unwrap_or_default(),
                number(&allowance["maxMachines"]).unwrap_or_default(),
                number(&usage["vcpus"]).unwrap_or_default(),
                number(&allowance["maxVcpus"]).unwrap_or_default(),
                number(&usage["memoryMib"]).unwrap_or_default(),
                number(&allowance["maxMemoryMib"]).unwrap_or_default()
            );
            Ok(Output::with_text(answer, text))
        }
        MachinesAction::Add {
            name,
            ttl,
            hosted,
            size,
            region,
            idempotency_key,
            rental_id,
            dry_run: preview,
        } => {
            if hosted {
                let name = name.ok_or_else(|| {
                    CliError::usage("A hosted machine needs a name").field("name")
                })?;
                let request = json!({
                    "organisation": org, "name": name, "size": size.unwrap_or_default(),
                    "region": region.unwrap_or_default(),
                    "idempotencyKey": idempotency_key.unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
                    "rentalId": rental_id.unwrap_or_default(),
                });
                let procedure = format!("{HOSTED}/CreateHostedMachine");
                if preview {
                    return Ok(dry_run(&[(procedure, request)], vec![]));
                }
                return api.call(&procedure, request).await.map(Output::fields);
            }
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
        MachinesAction::Label {
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
                    &[(format!("{SERVICE}/SetMachineLabel"), request)],
                    changes("/labels", &found["labels"], &Value::Object(map)),
                ));
            }
            let answer = api
                .call(&format!("{SERVICE}/SetMachineLabel"), request)
                .await?;
            Ok(Output::fields(answer))
        }
        MachinesAction::Drain {
            machine,
            dry_run: preview,
        } => in_service(&api, &org, &machine, false, preview).await,
        MachinesAction::Undrain {
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
            let hosted = found["hosted"].as_bool().unwrap_or(false);
            let procedure = if hosted {
                format!("{HOSTED}/RemoveHostedMachine")
            } else {
                format!("{SERVICE}/RevokeMachine")
            };
            if preview {
                return Ok(dry_run(&[(procedure, request)], vec![]));
            }
            ctx.confirm(
                yes,
                &if hosted { format!("Give back hosted machine {machine} after its apps and stored data leave safely") } else { format!("Remove machine {machine} from the organisation") },
            )?;
            api.call(&procedure, request).await?;
            Ok(done(if hosted {
                format!("Return requested for {machine}.")
            } else {
                format!("Removed {machine}.")
            }))
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
            &[(format!("{SERVICE}/SetMachineUndrain"), request)],
            vec![],
        ));
    }
    let answer = api
        .call(&format!("{SERVICE}/SetMachineUndrain"), request)
        .await?;
    Ok(Output::fields(answer))
}
