//! Operator inventory and changes over the instance's Connect API.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::{
    api::Api,
    commands::{Noun, dry_run},
    context::Ctx,
    error::CliResult,
    output::{self, Output},
};

const SERVICE: &str = "grund.operator.v1.OperatorService";
const POOL: &str = "grund.machine.v1.ManagementPoolService";

const HOSTS: &[(&str, &str)] = &[
    ("ID", "/id"),
    ("NAME", "/name"),
    ("STATE", "/state"),
    ("REGION", "/region"),
    ("PROVIDER", "/provider"),
    ("VCPUS", "/capacity/vcpus"),
    ("USED", "/allocated/vcpus"),
    ("RAM MiB", "/capacity/memoryMib"),
    ("USED MiB", "/allocated/memoryMib"),
    ("MACHINES", "/machineCount"),
    ("REACHABLE", "/reachable"),
    ("REASON", "/cordonReason"),
];
const FLEET: &[(&str, &str)] = &[
    ("ID", "/id"),
    ("HOST", "/hostId"),
    ("STATE", "/state"),
    ("SIZE", "/size"),
    ("REGION", "/region"),
    ("ASSIGNED", "/assigned"),
    ("REASON", "/reason"),
];
const POOLS: &[(&str, &str)] = &[
    ("ID", "/id"),
    ("NAME", "/name"),
    ("SIZE", "/size"),
    ("REGION", "/region"),
    ("DESIRED", "/desired"),
    ("WARM", "/warm"),
    ("READY", "/ready"),
    ("REASON", "/unschedulableReason"),
];
const FAILURES: &[(&str, &str)] = &[
    ("MACHINE", "/machineId"),
    ("HOST", "/hostId"),
    ("STATE", "/state"),
    ("REASON", "/reason"),
    ("UPDATED", "/updatedAt"),
];
const MACHINES: &[(&str, &str)] = &[
    ("ID", "/machineId"),
    ("NAME", "/name"),
    ("STATE", "/state"),
    ("ORGANISATION", "/lease/organisation"),
    ("PROVIDER ID", "/providerMachineId"),
];
const LEASES: &[(&str, &str)] = &[
    ("MACHINE", "/machineId"),
    ("NAME", "/name"),
    ("LEASE", "/lease/leaseId"),
    ("ORGANISATION", "/lease/organisation"),
    ("LEASED AT", "/lease/leasedAt"),
];
const ENTITLEMENTS: &[(&str, &str)] = &[("ORGANISATION", "/organisation"), ("ENABLED", "/enabled")];

/// Host inventory, maintenance, and failures.
pub type HostsCommand = Noun<HostsAction>;

/// Host operations.
#[derive(Debug, Subcommand)]
pub enum HostsAction {
    #[command(about = "List hosts, capacity, allocation, and availability")]
    List {
        #[arg(long)]
        page_size: Option<i32>,
        #[arg(long)]
        page_token: Option<String>,
    },
    #[command(about = "List fleet machines on a host, or across hosts")]
    Machines {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        page_size: Option<i32>,
        #[arg(long)]
        page_token: Option<String>,
    },
    #[command(about = "List failed fleet machine operations")]
    Failures {
        #[arg(long)]
        page_size: Option<i32>,
        #[arg(long)]
        page_token: Option<String>,
    },
    #[command(about = "Stop scheduling on a host")]
    Cordon {
        host: String,
        #[arg(long, value_name = "REASON")]
        reason: String,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Resume scheduling on a host")]
    Uncordon {
        host: String,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Evacuate a host")]
    Drain {
        host: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

/// Management pool inventory and direct operations.
pub type PoolCommand = Noun<PoolAction>;

/// Management pool operations.
#[derive(Debug, Subcommand)]
pub enum PoolAction {
    #[command(about = "List hosted pool capacity and available machines")]
    List {
        #[arg(long)]
        page_size: Option<i32>,
        #[arg(long)]
        page_token: Option<String>,
    },
    #[command(about = "List management pool machines")]
    Machines,
    #[command(about = "Show one management pool machine")]
    Get { machine: String },
    #[command(about = "Ask the capacity provider for a new pool machine")]
    Provision {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        size: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Lease a pool machine to an organisation")]
    Lease {
        machine: String,
        organisation: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "End a pool machine's lease and return it for wiping")]
    End {
        machine: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Permanently revoke a pool machine")]
    Revoke {
        machine: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Retry wiping and rebuilding a returning pool machine")]
    Rebuild {
        machine: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Mint a one-time token for a manually enrolled pool machine")]
    Register {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        ttl: Option<i32>,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Mint a one-time token to re-enrol a wiped pool machine")]
    Reregister {
        machine: String,
        #[arg(long)]
        ttl: Option<i32>,
        #[arg(long)]
        dry_run: bool,
    },
}

/// Current pool leases.
pub type LeasesCommand = Noun<LeasesAction>;

/// Lease operations.
#[derive(Debug, Subcommand)]
pub enum LeasesAction {
    #[command(about = "List machines currently leased to organisations")]
    List,
    #[command(about = "End a lease and return the machine for wiping")]
    End {
        machine: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

/// Hosted access for organisations.
pub type EntitlementsCommand = Noun<EntitlementsAction>;

/// Hosted access operations.
#[derive(Debug, Subcommand)]
pub enum EntitlementsAction {
    #[command(about = "List organisations' hosted access")]
    List,
    #[command(about = "Allow an organisation to create hosted machines")]
    Grant {
        organisation: String,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Remove an organisation's hosted access")]
    Revoke {
        organisation: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

fn pagination(page_size: Option<i32>, page_token: Option<String>) -> Value {
    let mut request = json!({});
    if let Some(size) = page_size {
        request["pageSize"] = json!(size);
    }
    if let Some(token) = page_token {
        request["pageToken"] = json!(token);
    }
    request
}

async fn change(
    ctx: &Ctx,
    api: &Api,
    service: &str,
    method: &str,
    request: Value,
    preview: bool,
    confirmation: Option<(bool, String)>,
) -> CliResult<Output> {
    let rpc = format!("{service}/{method}");
    if preview {
        return Ok(dry_run(&[(rpc, request)], vec![]));
    }
    if let Some((yes, question)) = confirmation {
        ctx.confirm(yes, &question)?;
    }
    Ok(Output::fields(api.call(&rpc, request).await?))
}

/// Runs host inventory and maintenance commands with a CLI credential.
pub async fn hosts(ctx: &Ctx, action: HostsAction) -> CliResult<Output> {
    let api = ctx.api()?;
    match action {
        HostsAction::List {
            page_size,
            page_token,
        } => Ok(Output::table(
            api.call(
                &format!("{SERVICE}/ListHosts"),
                pagination(page_size, page_token),
            )
            .await?,
            "/hosts",
            HOSTS,
        )),
        HostsAction::Machines {
            host,
            page_size,
            page_token,
        } => {
            let mut request = pagination(page_size, page_token);
            if let Some(host) = host {
                request["hostId"] = json!(host);
            }
            Ok(Output::table(
                api.call(&format!("{SERVICE}/ListFleetMachines"), request)
                    .await?,
                "/machines",
                FLEET,
            ))
        }
        HostsAction::Failures {
            page_size,
            page_token,
        } => Ok(Output::table(
            api.call(
                &format!("{SERVICE}/ListFailures"),
                pagination(page_size, page_token),
            )
            .await?,
            "/failures",
            FAILURES,
        )),
        HostsAction::Cordon {
            host,
            reason,
            dry_run,
        } => {
            change(
                ctx,
                &api,
                SERVICE,
                "CordonHost",
                json!({"hostId": host, "reason": reason}),
                dry_run,
                None,
            )
            .await
        }
        HostsAction::Uncordon { host, dry_run } => {
            change(
                ctx,
                &api,
                SERVICE,
                "UncordonHost",
                json!({"hostId": host}),
                dry_run,
                None,
            )
            .await
        }
        HostsAction::Drain { host, yes, dry_run } => {
            change(
                ctx,
                &api,
                SERVICE,
                "DrainHost",
                json!({"hostId": host}),
                dry_run,
                Some((yes, format!("Drain host {host}"))),
            )
            .await
        }
    }
}

/// Runs pool inventory and direct machine operations.
pub async fn pool(ctx: &Ctx, action: PoolAction) -> CliResult<Output> {
    let api = ctx.api()?;
    match action {
        PoolAction::List { page_size, page_token } => Ok(Output::table(
            api.call(&format!("{SERVICE}/ListPools"), pagination(page_size, page_token)).await?,
            "/pools", POOLS,
        )),
        PoolAction::Machines => Ok(Output::table(api.call(&format!("{POOL}/ListPoolMachines"), json!({})).await?, "/machines", MACHINES)),
        PoolAction::Get { machine } => Ok(Output::fields(api.call(&format!("{POOL}/GetPoolMachine"), json!({"machineId": machine})).await?)),
        PoolAction::Provision { name, size, dry_run } => change(ctx, &api, POOL, "ProvisionPoolMachine", json!({"name": name.unwrap_or_default(), "size": size.unwrap_or_default()}), dry_run, None).await,
        PoolAction::Lease { machine, organisation, name, dry_run } => change(ctx, &api, POOL, "LeaseMachine", json!({"machineId": machine, "organisation": organisation, "name": name.unwrap_or_default()}), dry_run, None).await,
        PoolAction::End { machine, yes, dry_run } => end_lease(ctx, &api, machine, yes, dry_run).await,
        PoolAction::Revoke { machine, yes, dry_run } => change(ctx, &api, POOL, "RevokePoolMachine", json!({"machineId": machine}), dry_run, Some((yes, format!("Permanently revoke pool machine {machine}")))).await,
        PoolAction::Rebuild { machine, yes, dry_run } => change(ctx, &api, POOL, "RebuildPoolMachine", json!({"machineId": machine}), dry_run, Some((yes, format!("Wipe and rebuild pool machine {machine}")))).await,
        PoolAction::Register { name, ttl, dry_run } => {
            let mut request = json!({"name": name.unwrap_or_default()});
            if let Some(ttl) = ttl { request["ttlSeconds"] = json!(ttl); }
            change(ctx, &api, POOL, "CreateRegistrationToken", request, dry_run, None).await
        }
        PoolAction::Reregister { machine, ttl, dry_run } => {
            let mut request = json!({"machineId": machine});
            if let Some(ttl) = ttl { request["ttlSeconds"] = json!(ttl); }
            change(ctx, &api, POOL, "CreateReregistrationToken", request, dry_run, None).await
        }
    }
}

async fn end_lease(
    ctx: &Ctx,
    api: &Api,
    machine: String,
    yes: bool,
    preview: bool,
) -> CliResult<Output> {
    change(
        ctx,
        api,
        POOL,
        "EndLease",
        json!({"machineId": machine}),
        preview,
        Some((yes, format!("End the lease of pool machine {machine}"))),
    )
    .await
}

/// Lists or ends leases from the management pool.
pub async fn leases(ctx: &Ctx, action: LeasesAction) -> CliResult<Output> {
    let api = ctx.api()?;
    match action {
        LeasesAction::List => Ok(Output::table(
            api.call(
                &format!("{POOL}/ListPoolMachines"),
                json!({"state": "MACHINE_STATE_LEASED"}),
            )
            .await?,
            "/machines",
            LEASES,
        )),
        LeasesAction::End {
            machine,
            yes,
            dry_run,
        } => end_lease(ctx, &api, machine, yes, dry_run).await,
    }
}

/// Lists or changes an organisation's hosted entitlement.
pub async fn entitlements(ctx: &Ctx, action: EntitlementsAction) -> CliResult<Output> {
    let api = ctx.api()?;
    match action {
        EntitlementsAction::List => Ok(Output::table(
            api.call(&format!("{SERVICE}/ListEntitlements"), json!({}))
                .await?,
            "/organisations",
            ENTITLEMENTS,
        )),
        EntitlementsAction::Grant {
            organisation,
            dry_run,
        } => {
            change(
                ctx,
                &api,
                SERVICE,
                "SetHostedEntitlement",
                json!({"organisation": organisation, "enabled": true}),
                dry_run,
                None,
            )
            .await
        }
        EntitlementsAction::Revoke {
            organisation,
            yes,
            dry_run,
        } => {
            change(
                ctx,
                &api,
                SERVICE,
                "SetHostedEntitlement",
                json!({"organisation": organisation, "enabled": false}),
                dry_run,
                Some((yes, format!("Revoke hosted access for {organisation}"))),
            )
            .await
        }
    }
}

/// Runs an operator client command, printing JSON errors with the same rules as client commands.
pub async fn run(global: crate::context::Global, action: OperatorClientAction) -> i32 {
    let ctx = Ctx::new(global);
    let result = match action {
        OperatorClientAction::Hosts(action) => hosts(&ctx, action).await,
        OperatorClientAction::Pool(action) => pool(&ctx, action).await,
        OperatorClientAction::Leases(action) => leases(&ctx, action).await,
        OperatorClientAction::Entitlements(action) => entitlements(&ctx, action).await,
    };
    match result {
        Ok(answer) => {
            output::print(&answer, ctx.format);
            0
        }
        Err(error) => {
            output::print_error(&error, ctx.format);
            error.code.exit_status()
        }
    }
}

/// The Connect-backed operator noun, excluding database-only `operator apps`.
#[derive(Debug)]
pub enum OperatorClientAction {
    Hosts(HostsAction),
    Pool(PoolAction),
    Leases(LeasesAction),
    Entitlements(EntitlementsAction),
}
