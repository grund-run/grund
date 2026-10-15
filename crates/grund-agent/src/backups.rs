//! Encrypted off-machine volume snapshots. The caller authorizes each work item
//! against the current signed document, placement and local volume owner record
//! before handing paths to this module. No work or secret is persisted here.

use std::os::unix::process::CommandExt;
use std::sync::Arc;
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::LazyLock,
    time::Duration,
};

use crate::{agent::Link, apps::Shared, policy::Policy, runtime::VolumeBind};
use anyhow::{Context, ensure};
use grund_proto::grund::agent::v1::{BackupOperation, BackupWork};
use grund_proto::grund::agent::v1::{
    GetBackupWorkRequest, GetBackupWorkResponse, ReportBackupResultRequest,
    ReportBackupResultResponse,
};
use serde_json::Value;
use tokio::{io::AsyncReadExt, process::Command};

const MAX_OUTPUT: usize = 512 * 1024;
const EXECUTION_LIMIT: Duration = Duration::from_secs(6 * 60 * 60);
const RESTIC: &str = "/usr/local/bin/restic";
static RESTIC_BINARY: LazyLock<OsString> =
    LazyLock::new(|| std::env::var_os("GRUND_RESTIC_BIN").unwrap_or_else(|| RESTIC.into()));

struct PrivateRun {
    dir: PathBuf,
}

impl PrivateRun {
    fn new(data_dir: &Path, attempt: &str, password: &str) -> anyhow::Result<Self> {
        ensure!(
            crate::volume::valid_id(attempt),
            "invalid backup attempt identity"
        );
        let parent = data_dir.join("backup-runs");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        if let Err(error) = builder.create(&parent) {
            ensure!(
                error.kind() == std::io::ErrorKind::AlreadyExists,
                "cannot create private backup directory"
            );
        }
        let root = crate::volume::directory(&parent)?;
        ensure!(
            root.metadata()?.permissions().mode() & 0o077 == 0,
            "backup runtime directory must be private"
        );
        let dir = parent.join(attempt);
        match fs::symlink_metadata(&dir) {
            Ok(_) => {
                let stale = crate::volume::directory(&dir)?;
                ensure!(
                    stale.metadata()?.permissions().mode() & 0o077 == 0,
                    "stale backup directory is not private"
                );
                fs::remove_dir_all(&dir)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&dir)
            .context("backup attempt directory already exists or cannot be created")?;
        let run = Self { dir };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(run.dir.join("password"))?;
        use std::io::Write;
        file.write_all(password.as_bytes())?;
        file.sync_all()?;
        Ok(run)
    }
}

impl Drop for PrivateRun {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn repository(work: &BackupWork) -> anyhow::Result<String> {
    ensure!(
        work.endpoint.starts_with("https://")
            || work.endpoint.starts_with("http://127.0.0.1:")
            || work.endpoint.starts_with("http://localhost:"),
        "backup endpoint must use TLS (except loopback tests)"
    );
    ensure!(
        !work.endpoint.contains(['@', '?', '#', '\n', '\r', ' ']),
        "invalid backup endpoint"
    );
    ensure!(
        !work.bucket.is_empty()
            && work
                .bucket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'),
        "invalid backup bucket"
    );
    ensure!(
        !work.repo_prefix.is_empty()
            && work
                .repo_prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'/' || b == b'_'),
        "invalid backup repository prefix"
    );
    Ok(format!(
        "s3:{}/{}/{}",
        work.endpoint.trim_end_matches('/'),
        work.bucket,
        work.repo_prefix
    ))
}

struct Restic<'a> {
    work: &'a BackupWork,
    private: &'a PrivateRun,
    repository: String,
}

impl Restic<'_> {
    async fn call_status(&self, args: &[&str]) -> anyhow::Result<(i32, Vec<u8>)> {
        let binary = &*RESTIC_BINARY;
        ensure!(
            Path::new(binary).is_absolute(),
            "restic executable path must be absolute"
        );
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("RESTIC_REPOSITORY", &self.repository)
            .env("RESTIC_PASSWORD_FILE", self.private.dir.join("password"))
            .env("AWS_ACCESS_KEY_ID", &self.work.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &self.work.secret_access_key)
            .env("AWS_DEFAULT_REGION", "us-east-1")
            .env("RESTIC_CACHE_DIR", self.private.dir.join("cache"))
            .env("HOME", &self.private.dir)
            .arg("--no-cache")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if !self.work.session_token.is_empty() {
            command.env("AWS_SESSION_TOKEN", &self.work.session_token);
        }
        let parent = unsafe { libc::getpid() };
        unsafe {
            command.as_std_mut().pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "backup agent exited before restic started",
                    ));
                }
                Ok(())
            });
        }
        let mut child = command.spawn().context("restic executable unavailable")?;
        let mut stdout = child
            .stdout
            .take()
            .context("restic output pipe unavailable")?;
        let result = tokio::time::timeout(EXECUTION_LIMIT, async {
            let mut chunk = [0u8; 8192];
            let mut collected = Vec::new();
            loop {
                let n = stdout.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                ensure!(
                    collected.len() + n <= MAX_OUTPUT,
                    "restic output exceeded the bounded summary size"
                );
                collected.extend_from_slice(&chunk[..n]);
            }
            let status = child.wait().await?;
            Ok::<_, anyhow::Error>((status.code().unwrap_or(-1), collected))
        })
        .await;
        match result {
            Ok(Ok(out)) => Ok(out),
            Ok(Err(error)) => {
                let _ = child.kill().await;
                Err(error)
            }
            Err(_) => {
                let _ = child.kill().await;
                anyhow::bail!("restic operation timed out")
            }
        }
    }

    async fn call(&self, args: &[&str]) -> anyhow::Result<Vec<u8>> {
        let (status, output) = self.call_status(args).await?;
        ensure!(status == 0, "restic operation failed ({status})");
        Ok(output)
    }

    async fn verify_restore(
        &self,
        snapshot: &str,
        source_root: &Path,
        target: &Path,
    ) -> anyhow::Result<()> {
        ensure!(
            target != source_root
                && !target.starts_with(source_root)
                && !source_root.starts_with(target),
            "restore must use a separate directory"
        );
        let root = source_root.to_str().context("managed path is not UTF-8")?;
        let selection = format!("{snapshot}:{root}");
        self.call(&[
            "restore",
            &selection,
            "--target",
            target.to_str().context("restore path is not UTF-8")?,
        ])
        .await?;
        inspect_tree(target)?;
        Ok(())
    }
}

fn snapshot_id(text: &[u8]) -> anyhow::Result<String> {
    let mut result = None;
    for line in text.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let message: Value = serde_json::from_slice(line).context("restic emitted invalid JSON")?;
        if message["message_type"] == "summary" {
            let id = message["snapshot_id"]
                .as_str()
                .context("restic summary omitted snapshot ID")?;
            ensure!(
                id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()),
                "invalid restic snapshot ID"
            );
            result = Some(id.to_ascii_lowercase());
        }
    }
    result.context("restic returned no completed snapshot")
}

fn exact_snapshot(id: &str) -> anyhow::Result<()> {
    ensure!(
        id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid exact snapshot ID"
    );
    Ok(())
}

fn inspect_tree(root: &Path) -> anyhow::Result<()> {
    let mut queue = vec![root.to_owned()];
    let mut files = 0usize;
    while let Some(dir) = queue.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            ensure!(
                ty.is_file() || ty.is_dir(),
                "backup contains symlinks or special files; refusing to attach"
            );
            files += 1;
            ensure!(files <= 1_000_000, "backup exceeds safe traversal limit");
            if ty.is_dir() {
                queue.push(entry.path());
            } else {
                let _ = fs::File::open(entry.path())?.metadata()?;
            }
        }
    }
    Ok(())
}

/// Execute one machine-authorized work item. `source` has already passed
/// `volume::backup_source` against its signed mount. `destination` must be a
/// fresh managed volume allocated with `volume::restore_target`, or `None`
/// for backup/probe/prune. Returns an exact ID only for a verified backup.
/// A failed or interrupted restore is never attached; its directory needs
/// explicit managed-volume cleanup before a different attempt is allocated.
pub async fn perform(
    work: &BackupWork,
    data_dir: &Path,
    source: Option<&Path>,
    destination: Option<&Path>,
) -> anyhow::Result<Option<String>> {
    let private = PrivateRun::new(data_dir, &work.attempt_id, &work.repository_password)?;
    let repository = repository(work)?;
    let restic = Restic {
        work,
        private: &private,
        repository,
    };
    let source_id = if work.source_volume_id.is_empty() {
        &work.volume_id
    } else {
        &work.source_volume_id
    };
    let original_root = if work.source_path.is_empty() {
        crate::volume::managed_path(data_dir, source_id)?
    } else {
        let path = PathBuf::from(&work.source_path);
        ensure!(
            path.is_absolute()
                && path != Path::new("/")
                && path
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
            "backup source selector is not an absolute safe directory"
        );
        path
    };
    match work.operation.as_known() {
        Some(BackupOperation::BACKUP_OPERATION_BACKUP) => {
            let source =
                source.context("backup requires a signed, policy-allowed volume source")?;
            ensure!(
                source == original_root,
                "backup source does not match the signed volume"
            );
            let (status, _) = restic.call_status(&["cat", "config"]).await?;
            if status == 10 {
                restic.call(&["init"]).await?;
            } else {
                ensure!(
                    status == 0,
                    "repository unavailable; refusing to initialize it"
                );
            }
            let output = restic
                .call(&[
                    "backup",
                    "--json",
                    "--quiet",
                    "--one-file-system",
                    "--",
                    source.to_str().context("volume path is not UTF-8")?,
                ])
                .await?;
            let id = snapshot_id(&output)?;
            restic.call(&["check", "--read-data"]).await?;
            let probe = private.dir.join("probe");
            fs::create_dir(&probe)?;
            restic.verify_restore(&id, &original_root, &probe).await?;
            Ok(Some(id))
        }
        Some(BackupOperation::BACKUP_OPERATION_PROBE) => {
            exact_snapshot(&work.snapshot_id)?;
            restic.call(&["check", "--read-data"]).await?;
            let probe = private.dir.join("probe");
            fs::create_dir(&probe)?;
            restic
                .verify_restore(&work.snapshot_id, &original_root, &probe)
                .await?;
            Ok(Some(work.snapshot_id.clone()))
        }
        Some(BackupOperation::BACKUP_OPERATION_RESTORE) => {
            exact_snapshot(&work.snapshot_id)?;
            let destination =
                destination.context("restore requires a fresh app-owned destination")?;
            ensure!(
                destination != original_root,
                "restore must not overwrite the source volume"
            );
            ensure!(
                fs::read_dir(destination)?.next().is_none(),
                "restore destination is not empty"
            );
            restic.call(&["check", "--read-data"]).await?;
            restic
                .verify_restore(&work.snapshot_id, &original_root, destination)
                .await?;
            Ok(Some(work.snapshot_id.clone()))
        }
        Some(BackupOperation::BACKUP_OPERATION_PRUNE) => {
            exact_snapshot(&work.snapshot_id)?;
            restic
                .call(&["forget", &work.snapshot_id, "--prune"])
                .await?;
            Ok(Some(work.snapshot_id.clone()))
        }
        _ => anyhow::bail!("unsupported backup work operation"),
    }
}

fn signed_source(
    desired: &grund_proto::grund::agent::v1::DesiredState,
    work: &BackupWork,
    data_dir: &Path,
) -> anyhow::Result<VolumeBind> {
    let mount = desired
        .replicas
        .iter()
        .filter(|replica| replica.app_id == work.app_id)
        .flat_map(|replica| &replica.volumes)
        .find(|volume| volume.volume_id == work.volume_id && volume.source == work.source_path)
        .context("volume source not attached in current signed document")?;
    ensure!(
        !mount.block_device,
        "block volume backup must be performed by the block storage provider"
    );
    let managed = mount.source.is_empty();
    Ok(VolumeBind {
        volume_id: mount.volume_id.clone(),
        app_id: work.app_id.clone(),
        name: mount.name.clone(),
        path: mount.path.clone(),
        source: if managed {
            crate::volume::managed_path(data_dir, &mount.volume_id)?
                .display()
                .to_string()
        } else {
            mount.source.clone()
        },
        managed,
        block_device: false,
    })
}

/// Run one bounded attempt at a time. The server leases work to the machine
/// key; local signed desired state and owner policy independently authorize
/// the source before restic reads a byte. No secret is logged or cached.
pub async fn run(
    link: Link,
    shared: Arc<Shared>,
    policy: Policy,
    volume_root: PathBuf,
    machine_id: String,
) {
    loop {
        let response: anyhow::Result<GetBackupWorkResponse> = link
            .call(
                "GetBackupWork",
                &GetBackupWorkRequest {
                    machine_id: machine_id.clone(),
                    ..Default::default()
                },
            )
            .await;
        match response {
            Ok(response) => {
                if let Some(work) = response.work.as_option() {
                    let mut failure_stage = "source";
                    let attempt = async {
                        let desired = shared
                            .desired
                            .lock()
                            .expect("signed desired lock")
                            .clone()
                            .context("no applied signed machine document")?;
                        ensure!(
                            desired.machine_id == machine_id
                                && desired.organisation_id == work.organisation_id,
                            "work owner differs from signed document"
                        );
                        ensure!(
                            !desired
                                .volume_deletions
                                .iter()
                                .any(|d| d.volume_id == work.volume_id
                                    || d.volume_id == work.destination_volume_id),
                            "volume is pending deletion"
                        );
                        let is_backup = work.operation.as_known()
                            == Some(BackupOperation::BACKUP_OPERATION_BACKUP);
                        let is_restore = work.operation.as_known()
                            == Some(BackupOperation::BACKUP_OPERATION_RESTORE);
                        failure_stage = "permission";
                        let activity = if is_backup {
                            Some(crate::volume::guard(&work.volume_id)?)
                        } else if is_restore {
                            Some(crate::volume::guard(&work.destination_volume_id)?)
                        } else {
                            None
                        };
                        let (source, source_lock) = if is_backup {
                            let bind = signed_source(&desired, work, &volume_root)?;
                            let (path, file) = crate::volume::backup_guard(
                                &volume_root,
                                &policy.volume_roots,
                                &bind,
                            )?;
                            (Some(path), Some(file))
                        } else {
                            (None, None)
                        };
                        let (destination, target_lock) = if is_restore {
                            let (path, file) = crate::volume::restore_guard(
                                &volume_root,
                                &work.app_id,
                                &work.destination_volume_id,
                            )?;
                            (Some(path), Some(file))
                        } else {
                            (None, None)
                        };
                        failure_stage = "unavailable";
                        let result = perform(
                            work,
                            &volume_root,
                            source.as_deref(),
                            destination.as_deref(),
                        )
                        .await?;
                        failure_stage = "integrity";
                        let current = shared
                            .desired
                            .lock()
                            .expect("signed desired lock")
                            .clone()
                            .context("signed document withdrawn while processing backup")?;
                        ensure!(
                            current.machine_id == machine_id
                                && current.organisation_id == work.organisation_id,
                            "machine's signed owner changed"
                        );
                        ensure!(
                            !current
                                .volume_deletions
                                .iter()
                                .any(|d| d.volume_id == work.volume_id
                                    || d.volume_id == work.destination_volume_id),
                            "volume deletion requested while processing backup"
                        );
                        if is_backup {
                            let bind = signed_source(&current, work, &volume_root)?;
                            ensure!(
                                crate::volume::backup_source(
                                    &volume_root,
                                    &policy.volume_roots,
                                    &bind
                                )?
                                .as_path()
                                    == source.as_deref().expect("backup source exists"),
                                "backup source changed during attempt"
                            );
                        }
                        if let Some(path) = destination.as_ref() {
                            let bind = VolumeBind {
                                volume_id: work.destination_volume_id.clone(),
                                app_id: work.app_id.clone(),
                                name: "restore".into(),
                                path: "/restore".into(),
                                source: path.display().to_string(),
                                managed: true,
                                block_device: false,
                            };
                            crate::volume::verify_bind(&volume_root, &[], &bind)?;
                        }
                        Ok::<_, anyhow::Error>((
                            result,
                            activity,
                            source_lock,
                            target_lock,
                            source.map(|path| path.display().to_string()),
                        ))
                    };
                    let result =
                        tokio::time::timeout(Duration::from_secs(6 * 60 * 60), attempt).await;
                    let mut held_guards = None;
                    let mut source_path = String::new();
                    let (success, snapshot_id, failure_class) = match result {
                        Ok(Ok((Some(id), activity, source_lock, target_lock, source))) => {
                            held_guards = Some((activity, source_lock, target_lock));
                            source_path = source.unwrap_or_default();
                            (true, id, String::new())
                        }
                        Ok(Ok((None, activity, source_lock, target_lock, _))) => {
                            held_guards = Some((activity, source_lock, target_lock));
                            (false, String::new(), "integrity".into())
                        }
                        Ok(Err(_)) => (false, String::new(), failure_stage.into()),
                        Err(_) => (false, String::new(), "timeout".into()),
                    };
                    let outcome: anyhow::Result<ReportBackupResultResponse> = link
                        .call(
                            "ReportBackupResult",
                            &ReportBackupResultRequest {
                                machine_id: machine_id.clone(),
                                attempt_id: work.attempt_id.clone(),
                                placement_generation: work.placement_generation,
                                success,
                                snapshot_id,
                                failure_class,
                                source_path,
                                ..Default::default()
                            },
                        )
                        .await;
                    if !matches!(
                        outcome,
                        Ok(ReportBackupResultResponse { accepted: true, .. })
                    ) {
                        tracing::warn!(
                            "backup result not acknowledged; lease remains retryable without a false recovery point"
                        );
                    }
                    drop(held_guards);
                }
            }
            Err(_) => tracing::warn!("backup work unavailable; durable attempts remain pending"),
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_completed_point_needs_the_exact_cryptographic_snapshot_id() {
        let line = br#"{"message_type":"summary","snapshot_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        assert_eq!(snapshot_id(line).unwrap(), "a".repeat(64));
        assert!(snapshot_id(br#"{"message_type":"summary","snapshot_id":"latest"}"#).is_err());
        assert!(snapshot_id(br#"{"message_type":"status"}"#).is_err());
    }

    #[test]
    fn a_killed_agent_can_retry_the_same_backup_attempt_without_reusing_its_password() {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("scratch")
            });
        let root = target.join(format!("backup-agent-restart-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let attempt = "11111111-1111-1111-1111-111111111111";
        let interrupted = PrivateRun::new(&root, attempt, "old-password").unwrap();
        std::mem::forget(interrupted);
        let retried = PrivateRun::new(&root, attempt, "new-password").unwrap();
        assert_eq!(
            fs::read(retried.dir.join("password")).unwrap(),
            b"new-password"
        );
        drop(retried);
        assert!(!root.join("backup-runs").join(attempt).exists());
        fs::remove_dir_all(root).unwrap();
    }
}
