//! App-owned, own-machine volumes over `grund.volume.v1.VolumeService`.
//! A volume's identity survives releases and machine detachment. Deleting
//! an app stops its volumes immediately; managed data is erased after the
//! recovery window, never customer-owned host paths.

use clap::Subcommand;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    api::Api,
    commands::{Noun, done, dry_run},
    context::Ctx,
    error::{CliError, CliResult, Code},
    output::Output,
};

const SERVICE: &str = "grund.volume.v1.VolumeService";

pub type VolumesCommand = Noun<VolumesAction>;

#[derive(Debug, Subcommand)]
pub enum BackupsAction {
    #[command(
        about = "Show the S3 destination and latest successful verification (never credentials)"
    )]
    Status,
    #[command(
        about = "Set an app volume's S3-compatible destination; read the secret access key from stdin"
    )]
    Set {
        #[arg(long, required = true)]
        endpoint: String,
        #[arg(long, required = true)]
        bucket: String,
        #[arg(long, required = true)]
        access_key_id: String,
        #[arg(long, help = "Reuse this key for a safe retry")]
        idempotency_key: Option<String>,
        #[arg(
            long,
            help = "Show a redacted request without reading the secret or changing anything"
        )]
        dry_run: bool,
    },
    #[command(about = "List only completed and verified recovery points")]
    Points,
    #[command(
        about = "Export the repository password to a new private file for independent recovery"
    )]
    ExportKey {
        #[arg(long, required = true, value_name = "PATH")]
        file: std::path::PathBuf,
        #[arg(long, help = "Do not ask; needed when nobody can be asked")]
        yes: bool,
        #[arg(
            long,
            help = "Show the redacted request without reading or writing the key"
        )]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum VolumesAction {
    #[command(about = "List an app's volumes, including detached ones")]
    List { app: String },
    #[command(about = "Show a volume and its current attachment and measured usage")]
    Show { app: String, volume: String },
    #[command(about = "Create an app-owned own-machine directory or a sized hosted block volume")]
    Create {
        app: String,
        name: String,
        #[arg(long, required = true)]
        path: String,
        #[arg(
            long,
            help = "Existing absolute host directory; requires the machine owner's local allowlist"
        )]
        source: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=4096), help = "Hosted block volume capacity in GiB (1 to 4096); omit for an own-machine directory")]
        size_gib: Option<u64>,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
        #[arg(
            long,
            help = "Request daily backup; not protected until an S3 destination and verified recovery point exist"
        )]
        backup: bool,
        #[arg(long, help = "Reuse this key to retry the same creation safely")]
        idempotency_key: Option<String>,
    },
    #[command(
        about = "Attach a detached app volume to an eligible machine after fencing the former writer"
    )]
    Attach {
        app: String,
        volume: String,
        machine: String,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Detach an app volume; the app waits rather than moving automatically")]
    Detach {
        app: String,
        volume: String,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "S3 destination and verified recovery points for one app volume")]
    Backups {
        app: String,
        volume: String,
        #[command(subcommand)]
        action: BackupsAction,
    },
    #[command(
        about = "Restore one verified backup recovery point into a NEW app-owned managed directory"
    )]
    Restore {
        app: String,
        volume: String,
        snapshot: String,
        #[arg(
            long,
            required = true,
            help = "New volume name, distinct from the source"
        )]
        name: String,
        #[arg(long, required = true, help = "Container path of the new volume")]
        path: String,
        #[arg(long, required = true, help = "Target own-machine id")]
        machine: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(
        about = "Accept losing a hosted volume's bytes; replacement uses a NEW volume name and ID"
    )]
    AcceptEmpty {
        app: String,
        volume: String,
        #[arg(long, help = "Do not ask for confirmation")]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Restore the SAME pending-deletion volume before its purge deadline")]
    RestoreDeleted {
        app: String,
        volume: String,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(
        about = "Stop an unused volume now; recoverable until its configured deadline (seven days by default)"
    )]
    Delete {
        app: String,
        volume: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
    #[command(
        about = "Permanently purge an already deleted volume now, without waiting seven days"
    )]
    PurgeNow {
        app: String,
        volume: String,
        #[arg(long, required = true, help = "Audit reason (1-512 bytes)")]
        reason: String,
        #[arg(long, help = "Do not ask for confirmation")]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

const VOLUMES: &[(&str, &str)] = &[
    ("NAME", "/name"),
    ("ID", "/volumeId"),
    ("PATH", "/path"),
    ("SIZE GiB (0=directory)", "/sizeGib"),
    ("STATE", "/status"),
    ("MACHINE", "/machineId"),
    ("MEASURED BYTES", "/measuredBytes"),
    ("RESTORABLE UNTIL", "/purgeAfter"),
    ("LOST HOST", "/lostHostName"),
    ("LOST AT", "/lostAt"),
    ("COMPLETED SNAPSHOT", "/lostSnapshotId"),
];

const POINTS: &[(&str, &str)] = &[
    ("SNAPSHOT", "/snapshotId"),
    ("COMPLETED", "/completedAt"),
    ("RESTORE VERIFIED", "/verifiedAt"),
];

async fn find(api: &Api, org: &str, app: &str, volume: &str) -> CliResult<Value> {
    let answer = api
        .call(
            &format!("{SERVICE}/ListVolumes"),
            json!({"organisation": org, "app": app}),
        )
        .await?;
    answer["volumes"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| row["name"] == volume || row["volumeId"] == volume)
        .cloned()
        .ok_or_else(|| {
            CliError::new(Code::NotFound, format!("no volume {volume} in {org}/{app}"))
                .hint(format!("grund volumes list {app}"))
        })
}

pub async fn run(ctx: &Ctx, action: VolumesAction) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    match action {
        VolumesAction::List { app } => {
            let answer = api
                .call(
                    &format!("{SERVICE}/ListVolumes"),
                    json!({"organisation": org, "app": app}),
                )
                .await?;
            Ok(Output::table(answer, "/volumes", VOLUMES))
        }
        VolumesAction::Show { app, volume } => {
            let row = find(&api, &org, &app, &volume).await?;
            let answer = api
                .call(
                    &format!("{SERVICE}/GetVolumeStatus"),
                    json!({"organisation": org, "app": app, "volumeId": row["volumeId"]}),
                )
                .await?;
            Ok(Output::fields(answer["volume"].clone()))
        }
        VolumesAction::Create {
            app,
            name,
            path,
            backup,
            idempotency_key,
            source,
            size_gib,
            dry_run: preview,
        } => {
            let request = json!({
                "organisation": org,
                "app": app,
                "name": name,
                "path": path,
                "source": source.unwrap_or_default(),
                "idempotencyKey": idempotency_key.unwrap_or_else(|| Uuid::now_v7().to_string()),
                "sizeGib": size_gib.unwrap_or_default(),
                "backup": backup,
            });
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/CreateVolume"), request)],
                    vec![],
                ));
            }
            let answer = api
                .call(&format!("{SERVICE}/CreateVolume"), request)
                .await?;
            Ok(Output::fields(answer["volume"].clone()))
        }
        VolumesAction::Attach {
            app,
            volume,
            machine,
            dry_run: preview,
        } => {
            let row = find(&api, &org, &app, &volume).await?;
            let request = json!({
                "organisation": org,
                "app": app,
                "volumeId": row["volumeId"],
                "machineId": machine,
                "expectedVersion": row["version"],
            });
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/AttachVolume"), request)],
                    vec![],
                ));
            }
            let answer = api
                .call(&format!("{SERVICE}/AttachVolume"), request)
                .await?;
            Ok(Output::fields(answer["volume"].clone()))
        }
        VolumesAction::Detach {
            app,
            volume,
            dry_run: preview,
        } => {
            let row = find(&api, &org, &app, &volume).await?;
            let request = json!({
                "organisation": org,
                "app": app,
                "volumeId": row["volumeId"],
                "expectedVersion": row["version"],
            });
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/DetachVolume"), request)],
                    vec![],
                ));
            }
            let answer = api
                .call(&format!("{SERVICE}/DetachVolume"), request)
                .await?;
            Ok(Output::fields(answer["volume"].clone()))
        }
        VolumesAction::Backups {
            app,
            volume,
            action,
        } => {
            let row = find(&api, &org, &app, &volume).await?;
            let id = &row["volumeId"];
            match action {
                BackupsAction::Status => {
                    let answer = api
                        .call(
                            &format!("{SERVICE}/GetBackupDestination"),
                            json!({"organisation": org, "app": app, "volumeId": id}),
                        )
                        .await?;
                    Ok(Output::fields(answer["destination"].clone()))
                }
                BackupsAction::Set {
                    endpoint,
                    bucket,
                    access_key_id,
                    idempotency_key,
                    dry_run: preview,
                } => {
                    let current = api
                        .call(
                            &format!("{SERVICE}/GetBackupDestination"),
                            json!({"organisation": org, "app": app, "volumeId": id}),
                        )
                        .await?;
                    let mut request = json!({
                        "organisation": org,
                        "app": app,
                        "volumeId": id,
                        "expectedVersion": current["destination"]["version"],
                        "idempotencyKey": idempotency_key.unwrap_or_else(|| Uuid::now_v7().to_string()),
                        "endpoint": endpoint,
                        "bucket": bucket,
                        "accessKeyId": access_key_id,
                    });
                    if preview {
                        request["secretAccessKey"] = json!("<read from stdin; redacted>");
                        return Ok(dry_run(
                            &[(format!("{SERVICE}/SetBackupDestination"), request)],
                            vec![],
                        ));
                    }
                    let secret = ctx.read_stdin("S3 secret access key")?;
                    let secret = secret.trim_end_matches(['\r', '\n']);
                    if secret.is_empty() {
                        return Err(CliError::usage(
                            "the S3 secret access key on stdin is empty",
                        ));
                    }
                    request["secretAccessKey"] = json!(secret);
                    let answer = api
                        .call(&format!("{SERVICE}/SetBackupDestination"), request)
                        .await?;
                    Ok(Output::fields(answer["destination"].clone()))
                }
                BackupsAction::Points => {
                    let answer = api
                        .call(
                            &format!("{SERVICE}/ListRecoveryPoints"),
                            json!({"organisation": org, "app": app, "volumeId": id}),
                        )
                        .await?;
                    Ok(Output::table(answer, "/points", POINTS))
                }
                BackupsAction::ExportKey {
                    file,
                    yes,
                    dry_run: preview,
                } => {
                    if preview {
                        return Ok(dry_run(
                            &[(
                                format!("{SERVICE}/ExportBackupKey"),
                                json!({"organisation": org, "app": app, "volumeId": id}),
                            )],
                            vec![
                                json!({"path": file.display().to_string(), "before": "absent", "after": "private key file (mode 0600)"}),
                            ],
                        ));
                    }
                    ctx.confirm(
                        yes,
                        &format!(
                            "Export {app}/{volume}'s backup decryption password to {}",
                            file.display()
                        ),
                    )?;
                    let answer = api
                        .call(
                            &format!("{SERVICE}/ExportBackupKey"),
                            json!({"organisation": org, "app": app, "volumeId": id}),
                        )
                        .await?;
                    let key = answer["repositoryPassword"].as_str().ok_or_else(|| {
                        CliError::new(Code::Failed, "the instance returned no backup key")
                    })?;
                    use std::{io::Write, os::unix::fs::OpenOptionsExt};
                    let mut out = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&file)?;
                    out.write_all(key.as_bytes())?;
                    out.sync_all()?;
                    Ok(done(format!(
                        "Saved the backup key to {} (mode 0600).",
                        file.display()
                    )))
                }
            }
        }
        VolumesAction::Restore {
            app,
            volume,
            snapshot,
            name,
            path,
            machine,
            yes,
            dry_run: preview,
        } => {
            let source = find(&api, &org, &app, &volume).await?;
            let request = json!({
                "organisation": org,
                "app": app,
                "sourceVolumeId": source["volumeId"],
                "snapshotId": snapshot,
                "newVolumeName": name,
                "targetContainerPath": path,
                "targetMachineId": machine,
                "confirmNewVolume": true,
                "expectedVersion": source["version"],
                "idempotencyKey": Uuid::now_v7().to_string(),
            });
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/RestoreRecoveryPoint"), request)],
                    vec![],
                ));
            }
            ctx.confirm(
                yes,
                &format!(
                    "Restore verified point {snapshot} for {app}/{volume} to a NEW app-owned volume {name} on machine {machine}; the source remains untouched"
                ),
            )?;
            let answer = api
                .call(&format!("{SERVICE}/RestoreRecoveryPoint"), request)
                .await?;
            Ok(Output::fields(answer))
        }
        VolumesAction::AcceptEmpty {
            app,
            volume,
            yes,
            dry_run: preview,
        } => {
            let row = find(&api, &org, &app, &volume).await?;
            if row["status"] != "lost" {
                return Err(CliError::new(
                    Code::Failed,
                    "only a declared lost hosted volume can be accepted empty",
                ));
            }
            let name = row["name"].as_str().unwrap_or_default();
            let request = json!({
                "organisation": org, "app": app,
                "volumeId": row["volumeId"],
                "expectedVersion": row["version"],
                "confirmVolumeName": name,
            });
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/AcceptEmptyLostVolume"), request)],
                    vec![],
                ));
            }
            ctx.confirm(
                yes,
                &format!("Accept that {app}/{name} on lost host {} cannot supply its old bytes; create a NEW app-owned volume and redeploy explicitly", row["lostHostName"].as_str().unwrap_or("unknown")),
            )?;
            let answer = api
                .call(&format!("{SERVICE}/AcceptEmptyLostVolume"), request)
                .await?;
            Ok(Output::fields(answer["volume"].clone()))
        }
        VolumesAction::RestoreDeleted {
            app,
            volume,
            dry_run: preview,
        } => {
            let row = find(&api, &org, &app, &volume).await?;
            let request = json!({
                "organisation": org,
                "app": app,
                "volumeId": row["volumeId"],
                "expectedVersion": row["version"],
            });
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/RestoreVolume"), request)],
                    vec![],
                ));
            }
            let answer = api
                .call(&format!("{SERVICE}/RestoreVolume"), request)
                .await?;
            Ok(Output::fields(answer["volume"].clone()))
        }
        VolumesAction::PurgeNow {
            app,
            volume,
            reason,
            yes,
            dry_run: preview,
        } => {
            let row = find(&api, &org, &app, &volume).await?;
            if row["status"] != "pending_deletion"
                && !(row["status"] == "lost" && !row["purgeAfter"].is_null())
            {
                return Err(CliError::new(
                    Code::Failed,
                    "only an already deleted volume pending purge can be purged now",
                ));
            }
            let request = json!({
                "organisation": org,
                "app": app,
                "volumeId": row["volumeId"],
                "expectedVersion": row["version"],
                "reason": reason,
            });
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/PurgeVolumeNow"), request)],
                    vec![],
                ));
            }
            ctx.confirm(
                yes,
                &if row["lostHostName"].as_str().is_some_and(|host| !host.is_empty()) {
                    format!("Permanently abandon {app}/{volume} on lost host {}; this records loss, not physical erasure", row["lostHostName"].as_str().unwrap_or_default())
                } else {
                    format!("Permanently purge {app}/{volume} now; managed data is erased only after physical confirmation")
                },
            )?;
            let answer = api
                .call(&format!("{SERVICE}/PurgeVolumeNow"), request)
                .await?;
            Ok(Output::fields(answer["volume"].clone()))
        }
        VolumesAction::Delete {
            app,
            volume,
            yes,
            dry_run: preview,
        } => {
            let row = find(&api, &org, &app, &volume).await?;
            let request = json!({
                "organisation": org,
                "app": app,
                "volumeId": row["volumeId"],
                "expectedVersion": row["version"],
            });
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/DeleteVolume"), request)],
                    vec![],
                ));
            }
            let effect = if row["source"].as_str().is_some_and(|path| !path.is_empty()) {
                "its access is removed now; your original host files remain untouched"
            } else {
                "it stops now; its managed directory and data remain restorable until the configured deadline (seven days by default)"
            };
            ctx.confirm(yes, &format!("Delete {app}/{volume}; {effect}"))?;
            let answer = api
                .call(&format!("{SERVICE}/DeleteVolume"), request)
                .await?;
            Ok(Output::fields(answer["volume"].clone()))
        }
    }
}
