//! Durable local-machine enrollment after the real owner claims an installation.

use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, ensure};
use ed25519_dalek::SigningKey;
use grund_config::names::MachineName;
use grund_domain::machine::{LocalMachineBootstrap, MachineFacts, MachineKey};
use grund_proto::grund::agent::v1::{EnrollMachineResponse, Pool};
use tokio::{io::AsyncReadExt, process::Command};
use uuid::Uuid;

use crate::join;

/// Privileged installation intent, retained for crash and lost-reply recovery.
pub const BOOTSTRAP_FILE: &str = "local-bootstrap.json";

const LOCAL_ORIGIN: &str = "http://localhost:8080";
const MAX_BYTES: u64 = 65536;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Persists the normal machine key and local registration intent before server setup.
pub fn prepare(data_dir: &Path) -> anyhow::Result<LocalMachineBootstrap> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "local machine setup requires root"
    );
    prepare_owned(data_dir, 0)
}

fn prepare_owned(data_dir: &Path, owner: u32) -> anyhow::Result<LocalMachineBootstrap> {
    if let Some(bootstrap) = read_pending(data_dir, owner)? {
        if let Some(record) = join::read_record(data_dir)? {
            ensure!(
                record.machine_id == bootstrap.machine_id.to_string(),
                "local setup intent does not match the registered machine; identity left unchanged"
            );
        }
        return Ok(bootstrap);
    }
    ensure!(
        join::read_record(data_dir)?.is_none(),
        "this machine is already registered; local setup cannot replace its identity"
    );
    if !data_dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(data_dir)?;
    }
    trusted_directory(data_dir, owner)?;
    let key_path = data_dir.join(join::KEY_FILE);
    read_private(&key_path, owner)?;
    let key = join::machine_key(data_dir)?;
    read_private(&key_path, owner)?.context("machine key was not persisted")?;
    File::open(data_dir)?.sync_all()?;
    let facts = join::facts();
    let machine_id = Uuid::now_v7();
    let name = MachineName::suggest(&facts.hostname).unwrap_or_else(|| {
        MachineName::parse(&format!("m-{}", &machine_id.simple().to_string()[24..]))
            .expect("m- and hex digits make a machine name")
    });
    let bootstrap = LocalMachineBootstrap {
        machine_id,
        name,
        key: MachineKey::from_bytes(&key.verifying_key().to_bytes())
            .expect("an Ed25519 public key is 32 bytes"),
        facts: MachineFacts {
            hostname: facts.hostname,
            arch: facts.arch,
            cpu_model: facts.cpu_model,
            cpus: facts.cpus,
            memory_mib: facts.memory_mib,
            disk_gib: join::disk_gib(data_dir),
            os: facts.os,
            kernel: facts.kernel,
            agent_version: facts.agent_version,
            fleet_machine_id: facts.fleet_machine_id,
        },
    };
    persist_intent(data_dir, &bootstrap)?;
    read_pending(data_dir, owner)?.context("local setup intent was not persisted")
}

fn trusted_directory(data_dir: &Path, owner: u32) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(data_dir)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0,
        "local setup requires a root-owned real data directory without group or other write access"
    );
    let absolute = if data_dir.is_absolute() {
        data_dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(data_dir)
    };
    for ancestor in absolute.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor)?;
        let protected_sticky_directory = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        ensure!(
            metadata.is_dir()
                && (metadata.uid() == 0 || metadata.uid() == owner)
                && (metadata.mode() & 0o022 == 0 || protected_sticky_directory),
            "local setup data directory has an untrusted ancestor"
        );
    }
    Ok(())
}

fn read_private(path: &Path, owner: u32) -> anyhow::Result<Option<Vec<u8>>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read trusted local setup state"),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == owner
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1
            && metadata.len() <= MAX_BYTES,
        "local setup state must be a private root-owned regular file within the size bound"
    );
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "local setup state exceeded its size bound"
    );
    Ok(Some(bytes))
}

fn read_pending(data_dir: &Path, owner: u32) -> anyhow::Result<Option<LocalMachineBootstrap>> {
    match fs::symlink_metadata(data_dir.join(BOOTSTRAP_FILE)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => trusted_directory(data_dir, owner)?,
    }
    let Some(bytes) = read_private(&data_dir.join(BOOTSTRAP_FILE), owner)? else {
        return Ok(None);
    };
    let bootstrap: LocalMachineBootstrap =
        serde_json::from_slice(&bytes).context("invalid local machine setup intent")?;
    ensure!(
        !bootstrap.machine_id.is_nil(),
        "local setup machine ID is invalid"
    );
    ensure!(
        MachineName::parse(bootstrap.name.as_str())? == bootstrap.name,
        "local setup machine name is invalid"
    );
    let seed = read_private(&data_dir.join(join::KEY_FILE), owner)?
        .context("local setup machine key is missing; refusing to generate another identity")?;
    let seed: [u8; 32] = hex::decode(std::str::from_utf8(&seed)?.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid local setup machine key"))?;
    let key = SigningKey::from_bytes(&seed);
    ensure!(
        bootstrap.key.as_hex() == hex::encode(key.verifying_key().to_bytes()),
        "local setup intent has a different machine key; identity left unchanged"
    );
    Ok(Some(bootstrap))
}

fn persist_intent(data_dir: &Path, bootstrap: &LocalMachineBootstrap) -> anyhow::Result<()> {
    let temporary = data_dir.join(format!(".local-bootstrap-{}", Uuid::now_v7()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, bootstrap)?;
        file.sync_all()?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &temporary,
            rustix::fs::CWD,
            data_dir.join(BOOTSTRAP_FILE),
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        Ok::<_, anyhow::Error>(())
    })();
    let _ = fs::remove_file(&temporary);
    result?;
    File::open(data_dir)?.sync_all()?;
    Ok(())
}

/// Waits for the real owner's committed enrollment, then safely keeps its normal record.
pub async fn complete_pending(data_dir: &Path) -> anyhow::Result<()> {
    let already_registered = join::read_record(data_dir)?.is_some();
    complete_with(
        data_dir,
        0,
        local_response,
        crate::supervisor::lock,
        POLL_INTERVAL,
    )
    .await?;
    if !already_registered && join::read_record(data_dir)?.is_some() {
        let result = tokio::time::timeout(
            COMMAND_TIMEOUT,
            Command::new("systemctl")
                .args(["start", "--no-block", "grund-agent-updater.service"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await;
        match result {
            Ok(Ok(status)) if status.success() => {}
            _ => tracing::warn!(
                "machine registered but retained updater service could not be started"
            ),
        }
    }
    Ok(())
}

async fn complete_with<F, Fut, L>(
    data_dir: &Path,
    owner: u32,
    mut fetch: F,
    mut lock: L,
    interval: Duration,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<Option<EnrollMachineResponse>>>,
    L: FnMut() -> anyhow::Result<File>,
{
    if join::read_record(data_dir)?.is_some() {
        return Ok(());
    }
    let Some(bootstrap) = read_pending(data_dir, owner)? else {
        return Ok(());
    };
    loop {
        if join::read_record(data_dir)?.is_some() {
            return Ok(());
        }
        let Some(response) = fetch().await? else {
            tokio::time::sleep(interval).await;
            continue;
        };
        let _lock = match lock() {
            Ok(lock) => lock,
            Err(error)
                if matches!(
                    error.downcast_ref::<std::fs::TryLockError>(),
                    Some(std::fs::TryLockError::WouldBlock)
                ) =>
            {
                tokio::time::sleep(interval).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        if join::read_record(data_dir)?.is_some() {
            return Ok(());
        }
        ensure!(
            read_pending(data_dir, owner)?.as_ref() == Some(&bootstrap),
            "local setup intent changed while waiting; no record written"
        );
        let record = validated_record(&bootstrap, &response)?;
        join::write_record(data_dir, &record)?;
        return Ok(());
    }
}

fn validated_record(
    bootstrap: &LocalMachineBootstrap,
    response: &EnrollMachineResponse,
) -> anyhow::Result<join::Record> {
    ensure!(
        response.machine_id == bootstrap.machine_id.to_string()
            && response.machine_name == bootstrap.name.as_str(),
        "local instance returned a foreign machine identity"
    );
    ensure!(
        response.pool.as_known() == Some(Pool::POOL_ORGANISATION)
            && Uuid::parse_str(&response.organisation_id).is_ok_and(|id| !id.is_nil()),
        "local machine must belong to the real owner's organisation pool"
    );
    let record = join::record(LOCAL_ORIGIN, response)?;
    ensure!(
        record.instance_key.purpose == "instance"
            && record.trust_key.purpose == "organisation"
            && record.network.is_some(),
        "local instance returned incomplete organisation enrollment keys"
    );
    Ok(record)
}

async fn local_response() -> anyhow::Result<Option<EnrollMachineResponse>> {
    let mut command = Command::new("docker");
    command
        .args([
            "compose",
            "--env-file",
            "/opt/grund/.env",
            "--project-directory",
            "/opt/grund",
            "exec",
            "-T",
            "grund",
            "/grund",
            "local-machine",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GRUND_")
            || key.as_encoded_bytes().starts_with(b"COMPOSE_")
        {
            command.env_remove(key);
        }
    }
    let mut child = command
        .spawn()
        .context("run privileged local machine lookup; setup remains pending")?;
    let stdout = child
        .stdout
        .take()
        .context("capture local machine lookup")?;
    let output = async {
        let mut bytes = Vec::new();
        stdout.take(MAX_BYTES + 1).read_to_end(&mut bytes).await?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "local machine lookup exceeded its size bound"
        );
        let status = child.wait().await?;
        decode_lookup(status.code().unwrap_or(-1), &bytes)
    };
    match tokio::time::timeout(COMMAND_TIMEOUT, output).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!("local machine lookup timed out; waiting for the owner installation");
            Ok(None)
        }
    }
}

fn decode_lookup(status: i32, bytes: &[u8]) -> anyhow::Result<Option<EnrollMachineResponse>> {
    ensure!(
        status != 78,
        "local instance refused its configured machine identity; setup remains pending"
    );
    if status != 0 {
        tracing::warn!("local instance unavailable; waiting for the owner installation");
        return Ok(None);
    }
    serde_json::from_slice(bytes).context("invalid local machine lookup response")
}

#[cfg(test)]
mod tests {
    #[test]
    fn preparing_an_already_registered_machine_without_intent_preserves_every_identity_byte() {
        let fixture = Fixture::new();
        let bootstrap = fixture.prepare();
        let record = join::record(LOCAL_ORIGIN, &response(&bootstrap)).unwrap();
        join::write_record(&fixture.data, &record).unwrap();
        fs::remove_file(fixture.data.join(BOOTSTRAP_FILE)).unwrap();
        let before_record = fs::read(fixture.data.join(join::RECORD_FILE)).unwrap();
        let before_key = fs::read(fixture.data.join(join::KEY_FILE)).unwrap();
        assert!(prepare_owned(&fixture.data, fixture.owner).is_err());
        assert_eq!(
            fs::read(fixture.data.join(join::RECORD_FILE)).unwrap(),
            before_record
        );
        assert_eq!(
            fs::read(fixture.data.join(join::KEY_FILE)).unwrap(),
            before_key
        );
        assert!(!fixture.data.join(BOOTSTRAP_FILE).exists());
    }

    #[test]
    fn a_writable_parent_cannot_redirect_privileged_bootstrap_state() {
        let fixture = Fixture::new();
        fixture.prepare();
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_pending(&fixture.data, fixture.owner).is_err());
    }

    #[test]
    fn a_temporary_lookup_failure_is_pending_but_refusal_or_malformed_success_is_terminal() {
        assert!(decode_lookup(1, b"").unwrap().is_none());
        assert!(decode_lookup(0, b"null").unwrap().is_none());
        assert!(decode_lookup(78, b"").is_err());
        assert!(decode_lookup(0, b"not json").is_err());
    }

    #[test]
    fn privileged_enrollment_uses_the_normal_protobuf_json_contract() {
        let fixture = Fixture::new();
        let bootstrap = fixture.prepare();
        let response = response(&bootstrap);
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded = decode_lookup(0, &bytes).unwrap().unwrap();
        assert_eq!(
            validated_record(&bootstrap, &decoded).unwrap().machine_id,
            bootstrap.machine_id.to_string()
        );
    }

    use std::{cell::Cell, fs, os::unix::fs::PermissionsExt};

    use grund_proto::grund::agent::v1::{KeyPurpose, Network, Pool, PublicKey};

    use super::*;

    struct Fixture {
        root: std::path::PathBuf,
        data: std::path::PathBuf,
        owner: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("grund-local-{}", Uuid::now_v7()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                data: root.join("agent"),
                root,
                owner: rustix::process::geteuid().as_raw(),
            }
        }

        fn prepare(&self) -> LocalMachineBootstrap {
            prepare_owned(&self.data, self.owner).unwrap()
        }

        fn lock(&self) -> anyhow::Result<File> {
            let file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(self.root.join("update.lock"))?;
            file.try_lock()?;
            Ok(file)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn response(bootstrap: &LocalMachineBootstrap) -> EnrollMachineResponse {
        let public = |purpose: KeyPurpose| PublicKey {
            key_id: Uuid::now_v7().to_string(),
            public_key: vec![7; 32],
            purpose: purpose.into(),
            ..Default::default()
        };
        EnrollMachineResponse {
            machine_id: bootstrap.machine_id.to_string(),
            machine_name: bootstrap.name.to_string(),
            pool: Pool::POOL_ORGANISATION.into(),
            organisation_id: Uuid::now_v7().to_string(),
            instance_key: Some(public(KeyPurpose::KEY_PURPOSE_INSTANCE)).into(),
            trust_key: Some(public(KeyPurpose::KEY_PURPOSE_ORGANISATION)).into(),
            heartbeat_interval_seconds: 30,
            network: Some(Network {
                network_id: Uuid::now_v7().to_string(),
                key: Some(public(KeyPurpose::KEY_PURPOSE_NETWORK)).into(),
                prefix: "fd00::".into(),
                slot: 1,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    #[test]
    fn preparing_after_a_crash_reuses_the_durable_identity_and_real_facts() {
        let fixture = Fixture::new();
        let first = fixture.prepare();
        let key = fs::read(fixture.data.join(join::KEY_FILE)).unwrap();
        assert_eq!(fixture.prepare(), first);
        assert_eq!(fs::read(fixture.data.join(join::KEY_FILE)).unwrap(), key);
        assert_eq!(first.facts.arch, std::env::consts::ARCH);
        assert_eq!(first.facts.hostname, join::facts().hostname);
        assert_eq!(first.facts.disk_gib, join::disk_gib(&fixture.data));
        for name in [join::KEY_FILE, BOOTSTRAP_FILE] {
            assert_eq!(
                fs::metadata(fixture.data.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(join::read_record(&fixture.data).unwrap().is_none());
    }

    #[test]
    fn lost_descriptor_write_reuses_the_already_persisted_normal_key() {
        let fixture = Fixture::new();
        let key = join::machine_key(&fixture.data).unwrap();
        assert_eq!(
            fixture.prepare().key.as_hex(),
            hex::encode(key.verifying_key().to_bytes())
        );
    }

    #[test]
    fn an_existing_descriptor_cannot_repair_or_replace_a_missing_or_changed_key() {
        let fixture = Fixture::new();
        fixture.prepare();
        fs::write(fixture.data.join(join::KEY_FILE), hex::encode([19; 32])).unwrap();
        assert!(prepare_owned(&fixture.data, fixture.owner).is_err());
        fs::remove_file(fixture.data.join(join::KEY_FILE)).unwrap();
        assert!(prepare_owned(&fixture.data, fixture.owner).is_err());
        assert!(!fixture.data.join(join::KEY_FILE).exists());
    }

    #[test]
    fn untrusted_or_symlinked_intent_is_refused_before_a_server_can_be_called() {
        let fixture = Fixture::new();
        fixture.prepare();
        let path = fixture.data.join(BOOTSTRAP_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_pending(&fixture.data, fixture.owner).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(fixture.root.join("foreign"), &path).unwrap();
        assert!(read_pending(&fixture.data, fixture.owner).is_err());
    }

    #[tokio::test]
    async fn installer_lock_contention_waits_without_changing_the_pending_identity() {
        let fixture = Fixture::new();
        let bootstrap = fixture.prepare();
        let held = std::cell::RefCell::new(Some(fixture.lock().unwrap()));
        let first = Cell::new(true);
        let ready = response(&bootstrap);
        complete_with(
            &fixture.data,
            fixture.owner,
            || {
                if first.replace(false) {
                    assert!(join::read_record(&fixture.data).unwrap().is_none());
                } else {
                    held.borrow_mut().take();
                }
                let ready = ready.clone();
                async move { Ok(Some(ready)) }
            },
            || fixture.lock(),
            Duration::ZERO,
        )
        .await
        .unwrap();
        let record = join::read_record(&fixture.data).unwrap().unwrap();
        assert_eq!(record.machine_id, bootstrap.machine_id.to_string());
        assert_eq!(fixture.prepare(), bootstrap);
    }

    #[tokio::test]
    async fn owner_pending_waits_without_an_update_lock_then_persists_normal_enrollment() {
        let fixture = Fixture::new();
        let bootstrap = fixture.prepare();
        let ready = response(&bootstrap);
        let calls = Cell::new(0);
        complete_with(
            &fixture.data,
            fixture.owner,
            || {
                let count = calls.get();
                calls.set(count + 1);
                assert!(fixture.lock().is_ok());
                assert!(join::read_record(&fixture.data).unwrap().is_none());
                let answer = (count > 0).then(|| ready.clone());
                async move { Ok(answer) }
            },
            || fixture.lock(),
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert_eq!(calls.get(), 2);
        let registered = join::read_record(&fixture.data).unwrap().unwrap();
        assert_eq!(registered.machine_id, bootstrap.machine_id.to_string());
        assert_eq!(registered.instance_url, LOCAL_ORIGIN);
        assert_eq!(registered.pool, "organisation");
        assert!(registered.network.is_some());
        assert_eq!(fixture.prepare(), bootstrap);
    }

    #[tokio::test]
    async fn lost_reply_can_be_retried_without_resetting_identity_or_update_journals() {
        let fixture = Fixture::new();
        let bootstrap = fixture.prepare();
        fs::write(fixture.data.join("update-journal.json"), b"retained").unwrap();
        let failed = complete_with(
            &fixture.data,
            fixture.owner,
            || async { anyhow::bail!("reply lost") },
            || fixture.lock(),
            Duration::ZERO,
        )
        .await;
        assert!(failed.is_err());
        assert_eq!(fixture.prepare(), bootstrap);
        let ready = response(&bootstrap);
        complete_with(
            &fixture.data,
            fixture.owner,
            || {
                let ready = ready.clone();
                async move { Ok(Some(ready)) }
            },
            || fixture.lock(),
            Duration::ZERO,
        )
        .await
        .unwrap();
        let record = fs::read(fixture.data.join(join::RECORD_FILE)).unwrap();
        complete_with(
            &fixture.data,
            fixture.owner,
            || async { panic!("already registered") },
            || panic!("already registered"),
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert_eq!(
            fs::read(fixture.data.join(join::RECORD_FILE)).unwrap(),
            record
        );
        assert_eq!(
            fs::read(fixture.data.join("update-journal.json")).unwrap(),
            b"retained"
        );
    }

    #[tokio::test]
    async fn foreign_identity_pool_or_changed_local_key_never_becomes_a_record() {
        for scenario in 0..3 {
            let fixture = Fixture::new();
            let bootstrap = fixture.prepare();
            let mut ready = response(&bootstrap);
            if scenario == 0 {
                ready.machine_id = Uuid::now_v7().to_string();
            }
            if scenario == 1 {
                ready.pool = Pool::POOL_MANAGEMENT.into();
            }
            let result = complete_with(
                &fixture.data,
                fixture.owner,
                || {
                    if scenario == 2 {
                        fs::write(fixture.data.join(join::KEY_FILE), hex::encode([11; 32]))
                            .unwrap();
                    }
                    let ready = ready.clone();
                    async move { Ok(Some(ready)) }
                },
                || fixture.lock(),
                Duration::ZERO,
            )
            .await;
            assert!(result.is_err());
            assert!(join::read_record(&fixture.data).unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn a_registration_winning_the_lock_is_never_overwritten() {
        let fixture = Fixture::new();
        let bootstrap = fixture.prepare();
        let ready = response(&bootstrap);
        let mut winner = join::record(LOCAL_ORIGIN, &ready).unwrap();
        winner.machine_id = Uuid::now_v7().to_string();
        complete_with(
            &fixture.data,
            fixture.owner,
            || {
                join::write_record(&fixture.data, &winner).unwrap();
                let ready = ready.clone();
                async move { Ok(Some(ready)) }
            },
            || fixture.lock(),
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert_eq!(
            join::read_record(&fixture.data).unwrap(),
            Some(winner.clone())
        );
        assert!(prepare_owned(&fixture.data, fixture.owner).is_err());
        assert_eq!(join::read_record(&fixture.data).unwrap(), Some(winner));
    }

    #[tokio::test]
    async fn an_unmanaged_agent_does_not_poll_or_create_state() {
        let fixture = Fixture::new();
        complete_with(
            &fixture.data,
            fixture.owner,
            || async { panic!("unmanaged") },
            || panic!("unmanaged"),
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert!(!fixture.data.exists());
    }

    #[tokio::test]
    async fn an_unmanaged_unregistered_directory_needs_no_privileged_bootstrap_permissions() {
        let fixture = Fixture::new();
        fs::create_dir(&fixture.data).unwrap();
        fs::set_permissions(&fixture.data, fs::Permissions::from_mode(0o777)).unwrap();
        complete_with(
            &fixture.data,
            0,
            || async { panic!("unmanaged") },
            || panic!("unmanaged"),
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert!(fs::read_dir(&fixture.data).unwrap().next().is_none());
    }
}
