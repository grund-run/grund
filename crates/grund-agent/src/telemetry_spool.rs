use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use buffa::Message;
use grund_proto::grund::agent::v1::ExportTelemetryRequest;
use serde::{Deserialize, Serialize};

pub(super) const MAX_BATCH: usize = 256 * 1024;
const MAX_METADATA: usize = 1024 * 1024;
const MAX_FILES: usize = 1024;
const QUOTA: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Cursor {
    pub device: u64,
    pub inode: u64,
    #[serde(default)]
    pub resetting: bool,
    pub offset: u64,
    pub skipping: bool,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Identity {
    pub organisation: String,
    pub machine: String,
    pub app: String,
    pub release: u32,
    pub instance: String,
    pub secrets: Vec<(String, u32)>,
}

impl Identity {
    pub(crate) fn from_document(
        document: &grund_proto::grund::agent::v1::DesiredState,
        replica: &grund_proto::grund::agent::v1::Replica,
    ) -> Self {
        Self {
            organisation: document.organisation_id.clone(),
            machine: document.machine_id.clone(),
            app: replica.app_id.clone(),
            release: replica.release,
            instance: replica.replica_id.clone(),
            secrets: replica
                .secrets
                .iter()
                .map(|s| (s.name.clone(), s.version))
                .collect(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct State {
    cursors: BTreeMap<String, Cursor>,
    dropped: u64,
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    identities: BTreeMap<String, Identity>,
    #[serde(default)]
    capture_loss: BTreeMap<String, (String, u64)>,
    #[serde(default)]
    capture_dropped_bytes: u64,
    #[serde(default)]
    shutdown_loss_events: u64,
    #[serde(default)]
    rejected_batch_attempts: u64,
    #[serde(default)]
    expired_window_batch_attempts: u64,
    #[serde(default)]
    pending_rejection: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Metadata {
    updates: BTreeMap<String, Cursor>,
    records: u64,
    #[serde(default)]
    revision: u64,
}

pub(super) struct Spool {
    root: PathBuf,
    state: State,
    files: BTreeMap<String, (u64, u64)>,
    bytes: u64,
}

fn bounded(path: &Path, maximum: usize) -> anyhow::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "telemetry entry is not a regular file"
    );
    anyhow::ensure!(
        file.metadata()?.len() <= maximum as u64,
        "telemetry entry exceeds its bound"
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= maximum, "telemetry entry exceeds its bound");
    Ok(bytes)
}

fn atomic(root: &Path, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let temporary = root.join(".writing");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, root.join(name))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn decode(bytes: &[u8]) -> anyhow::Result<(Metadata, ExportTelemetryRequest)> {
    anyhow::ensure!(bytes.len() >= 4, "incomplete telemetry batch");
    let length = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
    anyhow::ensure!(
        length <= MAX_METADATA && length + 4 <= bytes.len(),
        "invalid telemetry metadata"
    );
    let metadata = serde_json::from_slice(&bytes[4..4 + length])?;
    let payload = &bytes[4 + length..];
    anyhow::ensure!(
        payload.len() <= MAX_BATCH,
        "telemetry batch exceeds its bound"
    );
    let request = ExportTelemetryRequest::decode_from_slice(payload)?;
    Ok((metadata, request))
}

impl Spool {
    pub(super) fn open(root: PathBuf, scope: &str) -> anyhow::Result<Self> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&root)?.take(MAX_FILES + 4) {
            entries.push(entry?);
        }
        anyhow::ensure!(
            entries.len() < MAX_FILES + 4,
            "telemetry spool directory exceeds its entry bound"
        );
        for entry in &entries {
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid telemetry entry name"))?;
            anyhow::ensure!(
                entry.file_type()?.is_file(),
                "telemetry entry is not a regular file"
            );
            anyhow::ensure!(
                matches!(name, "scope" | "state" | ".writing") || name.ends_with(".batch"),
                "unknown telemetry spool entry"
            );
        }
        let same_scope =
            bounded(&root.join("scope"), 128).is_ok_and(|bytes| bytes == scope.as_bytes());
        if !same_scope {
            for entry in &entries {
                anyhow::ensure!(
                    entry.file_type()?.is_file(),
                    "unexpected telemetry spool directory"
                );
                std::fs::remove_file(entry.path())?;
            }
            atomic(&root, "scope", scope.as_bytes())?;
            entries.clear();
        }
        for entry in &entries {
            if entry.file_name() == ".writing" {
                std::fs::remove_file(entry.path())?;
            }
        }
        let state = bounded(&root.join("state"), MAX_METADATA)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let mut spool = Self {
            root,
            state,
            files: BTreeMap::new(),
            bytes: 0,
        };
        let mut batches: Vec<_> = entries
            .into_iter()
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                name.ends_with(".batch").then_some((name, entry.path()))
            })
            .collect();
        batches.sort_by(|a, b| a.0.cmp(&b.0));
        let mut retained = std::collections::VecDeque::new();
        let mut retained_bytes = 0u64;
        for (name, path) in batches {
            if spool.state.pending_rejection.as_deref() == name.strip_suffix(".batch") {
                std::fs::remove_file(&path)?;
                File::open(&spool.root)?.sync_all()?;
                continue;
            }
            let size = std::fs::symlink_metadata(&path)?.len();
            retained_bytes = retained_bytes.saturating_add(size);
            retained.push_back((name, path, size));
            while retained_bytes + 2 * MAX_METADATA as u64 + 4096 > QUOTA {
                let Some((_, path, size)) = retained.pop_front() else {
                    break;
                };
                std::fs::remove_file(path)?;
                retained_bytes -= size;
                spool.drop_records(1);
            }
        }
        for (name, path, _) in retained {
            let parsed = bounded(&path, MAX_BATCH + MAX_METADATA + 4)
                .and_then(|bytes| decode(&bytes).map(|value| (bytes.len() as u64, value)));
            match parsed {
                Ok((size, (metadata, request)))
                    if name == format!("{}.batch", request.batch_id)
                        && uuid::Uuid::parse_str(&request.batch_id).is_ok() =>
                {
                    if metadata.revision > spool.state.revision {
                        spool.state.cursors.extend(metadata.updates);
                        spool.state.revision = metadata.revision;
                    }
                    spool.files.insert(name, (size, metadata.records));
                    spool.bytes += size;
                }
                _ => {
                    std::fs::remove_file(path)?;
                    spool.state.dropped = spool.state.dropped.saturating_add(1);
                }
            }
        }
        spool.finish_rejection()?;
        spool.enforce(0)?;
        spool.checkpoint()?;
        Ok(spool)
    }

    pub(super) fn cursor(&self, key: &str) -> Cursor {
        self.state.cursors.get(key).cloned().unwrap_or_default()
    }

    pub(super) fn dropped(&self) -> u64 {
        self.state.dropped
    }

    pub(super) fn drop_records(&mut self, count: u64) {
        self.state.dropped = self.state.dropped.saturating_add(count);
    }

    fn checkpoint(&self) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(&self.state)?;
        anyhow::ensure!(
            bytes.len() <= MAX_METADATA,
            "telemetry cursor state exceeds its bound"
        );
        atomic(&self.root, "state", &bytes)
    }

    fn enforce(&mut self, incoming: u64) -> anyhow::Result<()> {
        while self.bytes + incoming + 2 * MAX_METADATA as u64 + 4096 > QUOTA
            || self.files.len() >= MAX_FILES - 1
        {
            let Some((name, (bytes, records))) =
                self.files.first_key_value().map(|(n, s)| (n.clone(), *s))
            else {
                anyhow::bail!("telemetry batch cannot fit the machine spool quota");
            };
            std::fs::remove_file(self.root.join(&name))?;
            self.files.remove(&name);
            self.bytes -= bytes;
            self.drop_records(records);
        }
        Ok(())
    }

    pub(super) fn push(
        &mut self,
        request: &ExportTelemetryRequest,
        updates: BTreeMap<String, Cursor>,
        records: u64,
    ) -> anyhow::Result<()> {
        self.finish_rejection()?;
        let payload = request.encode_to_vec();
        anyhow::ensure!(
            payload.len() <= MAX_BATCH,
            "telemetry payload exceeds its bound"
        );
        let revision = self.state.revision.saturating_add(1);
        let metadata = Metadata {
            updates,
            records,
            revision,
        };
        let metadata_bytes = serde_json::to_vec(&metadata)?;
        anyhow::ensure!(
            metadata_bytes.len() <= MAX_METADATA,
            "telemetry cursor update exceeds its bound"
        );
        let mut bytes = Vec::with_capacity(4 + metadata_bytes.len() + payload.len());
        bytes.extend_from_slice(&(metadata_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&metadata_bytes);
        bytes.extend_from_slice(&payload);
        self.enforce(bytes.len() as u64)?;
        let name = format!("{}.batch", request.batch_id);
        atomic(&self.root, &name, &bytes)?;
        self.files.insert(name, (bytes.len() as u64, records));
        self.bytes += bytes.len() as u64;
        self.state.cursors.extend(metadata.updates);
        self.state.revision = revision;
        self.checkpoint()
    }

    pub(super) fn next(&mut self) -> anyhow::Result<Option<ExportTelemetryRequest>> {
        self.finish_rejection()?;
        self.files
            .first_key_value()
            .map(|(name, _)| {
                decode(&bounded(
                    &self.root.join(name),
                    MAX_BATCH + MAX_METADATA + 4,
                )?)
                .map(|(_, request)| request)
            })
            .transpose()
    }

    pub(super) fn acknowledge(&mut self, batch_id: &str) -> anyhow::Result<()> {
        let name = format!("{batch_id}.batch");
        if let Some((bytes, _)) = self.files.get(&name).copied() {
            self.checkpoint()?;
            match std::fs::remove_file(self.root.join(&name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            File::open(&self.root)?.sync_all()?;
            self.files.remove(&name);
            self.bytes -= bytes;
        }
        Ok(())
    }

    pub(super) fn reject(&mut self, batch_id: &str, expired_window: bool) -> anyhow::Result<()> {
        self.finish_rejection()?;
        if let Some((_, records)) = self.files.get(&format!("{batch_id}.batch")).copied() {
            self.drop_records(records);
            self.state.pending_rejection = Some(batch_id.into());
        }
        self.rejection_attempt(expired_window)?;
        self.finish_rejection()
    }

    pub(super) fn rejection_attempt(&mut self, expired_window: bool) -> anyhow::Result<()> {
        self.state.rejected_batch_attempts = self.state.rejected_batch_attempts.saturating_add(1);
        if expired_window {
            self.state.expired_window_batch_attempts =
                self.state.expired_window_batch_attempts.saturating_add(1);
        }
        self.checkpoint()
    }

    fn finish_rejection(&mut self) -> anyhow::Result<()> {
        if let Some(id) = self.state.pending_rejection.clone() {
            self.acknowledge(&id)?;
            self.state.pending_rejection = None;
            self.checkpoint()?;
        }
        Ok(())
    }

    pub(super) fn rejected_batch_attempts(&self) -> u64 {
        self.state.rejected_batch_attempts
    }

    pub(super) fn expired_window_batch_attempts(&self) -> u64 {
        self.state.expired_window_batch_attempts
    }

    pub(super) fn advance(&mut self, updates: BTreeMap<String, Cursor>) -> anyhow::Result<()> {
        self.state.cursors.extend(updates);
        self.state.revision = self.state.revision.saturating_add(1);
        self.checkpoint()
    }

    pub(crate) fn identities(&self) -> BTreeMap<String, Identity> {
        self.state.identities.clone()
    }

    pub(crate) fn remember(
        &mut self,
        identities: impl IntoIterator<Item = Identity>,
    ) -> anyhow::Result<()> {
        let mut changed = false;
        for identity in identities {
            if self.state.identities.get(&identity.instance) != Some(&identity) {
                self.state
                    .identities
                    .insert(identity.instance.clone(), identity);
                changed = true;
            }
        }
        if changed {
            self.advance(BTreeMap::new())?;
        }
        Ok(())
    }

    pub(crate) fn capture_loss(
        &mut self,
        instance: &str,
        epoch: String,
        bytes: u64,
    ) -> anyhow::Result<()> {
        let previous = self.state.capture_loss.get(instance);
        if previous.is_some_and(|(old, seen)| old == &epoch && *seen >= bytes) {
            return Ok(());
        }
        let delta = previous
            .filter(|(old, _)| old == &epoch)
            .map_or(bytes, |(_, old)| bytes.saturating_sub(*old));
        self.state.capture_dropped_bytes = self.state.capture_dropped_bytes.saturating_add(delta);
        self.state
            .capture_loss
            .insert(instance.into(), (epoch, bytes));
        self.advance(BTreeMap::new())
    }

    pub(crate) fn capture_dropped_bytes(&self) -> u64 {
        self.state.capture_dropped_bytes
    }
    pub(crate) fn shutdown_loss_events(&self) -> u64 {
        self.state.shutdown_loss_events
    }
    pub(crate) fn shutdown_loss(&mut self, events: u64) -> anyhow::Result<()> {
        self.state.shutdown_loss_events = self.state.shutdown_loss_events.saturating_add(events);
        self.advance(BTreeMap::new())
    }
    pub(crate) fn retain_instances(
        &mut self,
        keep: &std::collections::BTreeSet<String>,
    ) -> anyhow::Result<()> {
        let before = self.state.identities.len();
        self.state.identities.retain(|id, _| keep.contains(id));
        self.state.capture_loss.retain(|id, _| keep.contains(id));
        self.state.cursors.retain(|key, _| {
            key.rsplit_once(':')
                .is_some_and(|(id, _)| keep.contains(id))
        });
        if before != self.state.identities.len() {
            self.advance(BTreeMap::new())?;
        }
        Ok(())
    }

    pub(super) fn retain_cursors(&mut self, wanted: &std::collections::BTreeSet<String>) {
        let identities = &self.state.identities;
        self.state.cursors.retain(|key, _| {
            wanted.contains(key)
                || key
                    .rsplit_once(':')
                    .is_some_and(|(id, _)| identities.contains_key(id))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(size: usize) -> ExportTelemetryRequest {
        ExportTelemetryRequest {
            batch_id: uuid::Uuid::now_v7().to_string(),
            logs_otlp: vec![42; size],
            ..Default::default()
        }
    }

    #[test]
    fn restart_replays_the_same_batch_and_acknowledges_its_offsets() {
        let root = std::env::temp_dir().join(format!("grund-spool-{}", uuid::Uuid::now_v7()));
        let request = request(10);
        let cursor = Cursor {
            inode: 7,
            offset: 99,
            ..Default::default()
        };
        {
            let mut spool = Spool::open(root.clone(), "scope-a").unwrap();
            spool
                .push(
                    &request,
                    BTreeMap::from([("stream".into(), cursor.clone())]),
                    1,
                )
                .unwrap();
        }
        let mut spool = Spool::open(root.clone(), "scope-a").unwrap();
        assert_eq!(spool.next().unwrap().unwrap().batch_id, request.batch_id);
        assert_eq!(spool.cursor("stream"), cursor);
        spool.acknowledge(&request.batch_id).unwrap();
        drop(spool);
        let mut spool = Spool::open(root.clone(), "scope-a").unwrap();
        assert!(spool.next().unwrap().is_none());
        assert_eq!(spool.cursor("stream"), cursor);
        drop(spool);
        let mut spool = Spool::open(root.clone(), "scope-b").unwrap();
        assert!(spool.next().unwrap().is_none());
        assert_eq!(spool.cursor("stream"), Cursor::default());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn quota_evicts_oldest_batches_and_reports_loss_after_restart() {
        let root = std::env::temp_dir().join(format!("grund-spool-{}", uuid::Uuid::now_v7()));
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        let first = request(240 * 1024);
        spool.push(&first, BTreeMap::new(), 1).unwrap();
        for _ in 0..100 {
            spool
                .push(&request(240 * 1024), BTreeMap::new(), 1)
                .unwrap();
        }
        assert!(spool.bytes + MAX_METADATA as u64 + 4096 <= QUOTA);
        assert!(spool.dropped() > 0);
        assert_ne!(spool.next().unwrap().unwrap().batch_id, first.batch_id);
        drop(spool);
        let spool = Spool::open(root.clone(), "scope").unwrap();
        assert!(spool.dropped() > 0);
        assert!(spool.bytes + MAX_METADATA as u64 + 4096 <= QUOTA);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cursor_reset_checkpoint_is_not_rewound_by_older_pending_batches() {
        let root = std::env::temp_dir().join(format!("grund-reset-{}", uuid::Uuid::now_v7()));
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        let request = request(10);
        spool
            .push(
                &request,
                BTreeMap::from([(
                    "stream".into(),
                    Cursor {
                        inode: 9,
                        offset: 200,
                        ..Default::default()
                    },
                )]),
                1,
            )
            .unwrap();
        let reset = Cursor {
            inode: 9,
            offset: 0,
            ..Default::default()
        };
        spool
            .advance(BTreeMap::from([("stream".into(), reset.clone())]))
            .unwrap();
        drop(spool);
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        assert_eq!(spool.cursor("stream"), reset);
        assert_eq!(spool.next().unwrap().unwrap().batch_id, request.batch_id);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_discards_oversized_batches_without_loading_their_payload() {
        let root =
            std::env::temp_dir().join(format!("grund-bounded-replay-{}", uuid::Uuid::now_v7()));
        let spool = Spool::open(root.clone(), "scope").unwrap();
        drop(spool);
        let oversized = root.join(format!("{}.batch", uuid::Uuid::now_v7()));
        File::create(&oversized)
            .unwrap()
            .set_len(QUOTA + 1)
            .unwrap();
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        assert!(spool.next().unwrap().is_none());
        assert!(!oversized.exists());
        assert!(spool.dropped() > 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capture_byte_losses_and_shutdown_loss_events_survive_restart_without_double_counting() {
        let root =
            std::env::temp_dir().join(format!("grund-loss-counters-{}", uuid::Uuid::now_v7()));
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        let epoch = uuid::Uuid::now_v7().to_string();
        spool.capture_loss("instance", epoch.clone(), 100).unwrap();
        spool.shutdown_loss(1).unwrap();
        drop(spool);
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        spool.capture_loss("instance", epoch.clone(), 100).unwrap();
        assert_eq!(spool.capture_dropped_bytes(), 100);
        spool.capture_loss("instance", epoch.clone(), 150).unwrap();
        spool.capture_loss("instance", epoch.clone(), 50).unwrap();
        spool.capture_loss("instance", epoch, 150).unwrap();
        spool
            .capture_loss("instance", uuid::Uuid::now_v7().to_string(), 20)
            .unwrap();
        assert_eq!(spool.capture_dropped_bytes(), 170);
        assert_eq!(spool.shutdown_loss_events(), 1);
        assert_eq!(spool.dropped(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn permanent_refusals_drop_records_not_offsets_and_persist_both_attempt_counters() {
        let root = std::env::temp_dir().join(format!("grund-rejections-{}", uuid::Uuid::now_v7()));
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        let stale = request(10);
        let cursor = Cursor {
            offset: 90,
            inode: 2,
            ..Default::default()
        };
        spool
            .push(
                &stale,
                BTreeMap::from([("stream".into(), cursor.clone())]),
                3,
            )
            .unwrap();
        spool.reject(&stale.batch_id, true).unwrap();
        let generic = request(10);
        spool.push(&generic, BTreeMap::new(), 2).unwrap();
        spool.reject(&generic.batch_id, false).unwrap();
        let accepted = request(10);
        spool.push(&accepted, BTreeMap::new(), 7).unwrap();
        spool.acknowledge(&accepted.batch_id).unwrap();
        drop(spool);
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        assert!(spool.next().unwrap().is_none());
        assert_eq!(spool.cursor("stream"), cursor);
        assert_eq!(spool.dropped(), 5);
        assert_eq!(spool.rejected_batch_attempts(), 2);
        assert_eq!(spool.expired_window_batch_attempts(), 1);
        drop(spool);
        let spool = Spool::open(root.clone(), "other-scope").unwrap();
        assert_eq!(spool.rejected_batch_attempts(), 0);
        assert_eq!(spool.expired_window_batch_attempts(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_crash_after_rejection_checkpoint_never_replays_or_counts_the_loss_twice() {
        for removed_before_crash in [false, true] {
            let root = std::env::temp_dir()
                .join(format!("grund-rejection-crash-{}", uuid::Uuid::now_v7()));
            let mut spool = Spool::open(root.clone(), "scope").unwrap();
            let rejected = request(10);
            let cursor = Cursor {
                offset: 50,
                inode: 8,
                ..Default::default()
            };
            spool
                .push(
                    &rejected,
                    BTreeMap::from([("stream".into(), cursor.clone())]),
                    4,
                )
                .unwrap();
            spool.state.rejected_batch_attempts = 1;
            spool.state.expired_window_batch_attempts = 1;
            spool.state.dropped = 4;
            spool.state.pending_rejection = Some(rejected.batch_id.clone());
            spool.checkpoint().unwrap();
            if removed_before_crash {
                std::fs::remove_file(root.join(format!("{}.batch", rejected.batch_id))).unwrap();
            }
            drop(spool);
            for _ in 0..2 {
                let mut spool = Spool::open(root.clone(), "scope").unwrap();
                assert!(spool.next().unwrap().is_none());
                assert_eq!(spool.cursor("stream"), cursor);
                assert_eq!(spool.dropped(), 4);
                assert_eq!(spool.rejected_batch_attempts(), 1);
                assert_eq!(spool.expired_window_batch_attempts(), 1);
                assert!(spool.state.pending_rejection.is_none());
            }
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn old_spool_state_upgrades_without_inventing_rejection_attempts() {
        let root =
            std::env::temp_dir().join(format!("grund-rejection-upgrade-{}", uuid::Uuid::now_v7()));
        let spool = Spool::open(root.clone(), "scope").unwrap();
        drop(spool);
        atomic(&root, "state", br#"{"cursors":{},"dropped":9}"#).unwrap();
        let spool = Spool::open(root.clone(), "scope").unwrap();
        assert_eq!(spool.dropped(), 9);
        assert_eq!(spool.rejected_batch_attempts(), 0);
        assert_eq!(spool.expired_window_batch_attempts(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retryable_refusal_attempts_are_durable_without_dropping_the_pending_batch() {
        let root =
            std::env::temp_dir().join(format!("grund-retry-counters-{}", uuid::Uuid::now_v7()));
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        let batch = request(10);
        spool.push(&batch, BTreeMap::new(), 3).unwrap();
        for _ in 0..2 {
            spool.rejection_attempt(false).unwrap();
        }
        drop(spool);
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        assert_eq!(spool.next().unwrap().unwrap().batch_id, batch.batch_id);
        assert_eq!(spool.rejected_batch_attempts(), 2);
        assert_eq!(spool.expired_window_batch_attempts(), 0);
        assert_eq!(spool.dropped(), 0);
        spool.reject(&batch.batch_id, true).unwrap();
        drop(spool);
        let mut spool = Spool::open(root.clone(), "scope").unwrap();
        assert!(spool.next().unwrap().is_none());
        assert_eq!(spool.rejected_batch_attempts(), 3);
        assert_eq!(spool.expired_window_batch_attempts(), 1);
        assert_eq!(spool.dropped(), 3);
        std::fs::remove_dir_all(root).unwrap();
    }
}
