-- 0029_app_volumes.sql: app-owned own-machine storage (storage.md §1, §3).
-- grund_volumes is a version-guarded projection of grund-volume events, not
-- the source of truth; mire owns es_* independently. Cleanup rows are the
-- durable outbox until a machine acknowledges physical managed-dir erasure.
CREATE TABLE grund_volumes (
    organisation_id UUID NOT NULL,
    app_id UUID NOT NULL,
    volume_id UUID NOT NULL,
    name TEXT COLLATE "C" NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    path TEXT NOT NULL,
    source TEXT,
    backup BOOLEAN NOT NULL DEFAULT false,
    machine_id UUID,
    status TEXT NOT NULL CHECK (status IN ('requested','available','attached','deleting','deleted')),
    measured_bytes BIGINT CHECK (measured_bytes >= 0),
    measured_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    stream_version BIGINT NOT NULL,
    PRIMARY KEY (organisation_id, volume_id),
    UNIQUE (app_id, name),
    CHECK (source IS NULL OR source LIKE '/%'),
    CHECK ((measured_bytes IS NULL) = (measured_at IS NULL))
);
CREATE INDEX grund_volumes_app_idx ON grund_volumes (organisation_id, app_id, name);
CREATE INDEX grund_volumes_machine_idx ON grund_volumes (organisation_id, machine_id, volume_id)
    WHERE machine_id IS NOT NULL AND status IN ('attached','deleting');

CREATE TABLE grund_volume_cleanup (
    organisation_id UUID NOT NULL,
    volume_id UUID NOT NULL,
    app_id UUID NOT NULL,
    machine_id UUID NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    acknowledged_at TIMESTAMPTZ,
    stream_version BIGINT NOT NULL,
    PRIMARY KEY (organisation_id, volume_id)
);
CREATE INDEX grund_volume_cleanup_pending_idx ON grund_volume_cleanup (organisation_id, machine_id, volume_id)
    WHERE acknowledged_at IS NULL;

-- A receipt is claimed in the same Work transaction as its effect. The
-- unique key serializes concurrent retries, and the hash rejects reusing a
-- key with a different operation or request.
CREATE TABLE grund_volume_idempotency (
    organisation_id UUID NOT NULL,
    app_id UUID NOT NULL,
    idempotency_key TEXT COLLATE "C" NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    operation TEXT NOT NULL,
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    result_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organisation_id, app_id, idempotency_key)
);

-- Customer-owned backup repository credentials are AES-GCM sealed under the
-- instance secret and AAD-bound to the exact organisation/app/volume/version.
-- Never put them in mire events, machine documents or URLs.
CREATE TABLE grund_volume_backup_configs (
    organisation_id UUID NOT NULL,
    app_id UUID NOT NULL,
    volume_id UUID NOT NULL,
    endpoint TEXT NOT NULL,
    bucket TEXT NOT NULL,
    repo_prefix TEXT NOT NULL,
    sealed_access_key BYTEA NOT NULL,
    sealed_secret BYTEA NOT NULL,
    sealed_password BYTEA NOT NULL,
    sealed_session BYTEA,
    version BIGINT NOT NULL CHECK (version > 0),
    next_due_at TIMESTAMPTZ NOT NULL,
    last_success_at TIMESTAMPTZ,
    last_verified_at TIMESTAMPTZ,
    last_probe_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organisation_id, volume_id),
    FOREIGN KEY (organisation_id, volume_id) REFERENCES grund_volumes (organisation_id, volume_id)
);
CREATE INDEX grund_volume_backup_configs_due_idx ON grund_volume_backup_configs (next_due_at, organisation_id, volume_id);

-- A leased attempt is committed before an agent receives it. Stale machine
-- placement generations cannot complete work for a subsequent writer.
CREATE TABLE grund_volume_backup_attempts (
    organisation_id UUID NOT NULL,
    app_id UUID NOT NULL,
    volume_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    machine_id UUID NOT NULL,
    placement_generation BIGINT NOT NULL CHECK (placement_generation >= 0),
    operation TEXT NOT NULL CHECK (operation IN ('backup','restore','probe','prune')),
    source_volume_id UUID NOT NULL,
    destination_volume_id UUID,
    snapshot_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending','leased','completed','failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    leased_until TIMESTAMPTZ,
    failure_class TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (organisation_id, attempt_id),
    FOREIGN KEY (organisation_id, volume_id) REFERENCES grund_volumes (organisation_id, volume_id)
);
CREATE INDEX grund_volume_backup_attempts_due_idx ON grund_volume_backup_attempts (next_attempt_at, organisation_id, attempt_id)
    WHERE status IN ('pending','leased');
CREATE INDEX grund_volume_backup_attempts_machine_idx ON grund_volume_backup_attempts (organisation_id, machine_id, status);
CREATE UNIQUE INDEX grund_volume_backup_attempts_active_idx ON grund_volume_backup_attempts (organisation_id, volume_id, operation)
    WHERE status IN ('pending','leased');

-- Only verified snapshots are exposed as recovery points.
CREATE TABLE grund_volume_backup_points (
    organisation_id UUID NOT NULL,
    app_id UUID NOT NULL,
    volume_id UUID NOT NULL,
    snapshot_id TEXT COLLATE "C" NOT NULL,
    archived_path TEXT NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organisation_id, volume_id, snapshot_id),
    FOREIGN KEY (organisation_id, volume_id) REFERENCES grund_volumes (organisation_id, volume_id)
);
CREATE INDEX grund_volume_backup_points_latest_idx ON grund_volume_backup_points (organisation_id, app_id, volume_id, verified_at DESC);
