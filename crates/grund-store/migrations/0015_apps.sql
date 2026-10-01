-- 0015_apps.sql: apps, their releases and replicas (grund-docs
-- design/apps.md §10.2). grund_apps, grund_releases, grund_replicas and
-- grund_app_activity are the read model of the grund-app streams, written
-- in the transaction that records the events. grund_replica_status is what
-- machines report, overwritten. grund_app_secrets holds sealed values,
-- never events.

CREATE TABLE grund_apps (
    app_id          UUID        PRIMARY KEY,
    organisation_id UUID        NOT NULL,
    name            TEXT COLLATE "C" NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$'),
    settings        JSONB       NOT NULL,
    current_release INTEGER     CHECK (current_release > 0),
    -- The rollout in progress, or the last one: id, from, to, state, reason,
    -- started_at, ended_at.
    rollout         JSONB,
    halted          BOOLEAN     NOT NULL DEFAULT false,
    created_by      UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    deleted_at      TIMESTAMPTZ,
    -- Written by the reconciler, not from events: slots it could not place
    -- on its last pass, and why.
    waiting         JSONB       NOT NULL DEFAULT '[]',
    reconciled_at   TIMESTAMPTZ,
    stream_version  BIGINT      NOT NULL
);
CREATE UNIQUE INDEX grund_apps_name_idx ON grund_apps (organisation_id, name) WHERE deleted_at IS NULL;
CREATE INDEX grund_apps_live_idx ON grund_apps (organisation_id) WHERE deleted_at IS NULL;

CREATE TABLE grund_releases (
    app_id          UUID        NOT NULL,
    number          INTEGER     NOT NULL CHECK (number > 0),
    spec            JSONB       NOT NULL,
    image_digest    TEXT COLLATE "C" NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    platforms       JSONB       NOT NULL DEFAULT '[]',
    secret_versions JSONB       NOT NULL DEFAULT '[]',
    source          TEXT        NOT NULL CHECK (source IN ('dashboard', 'api', 'file', 'rollback')),
    rollback_of     INTEGER,
    note            TEXT        NOT NULL DEFAULT '' CHECK (octet_length(note) <= 200),
    created_by      UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    outcome         TEXT        CHECK (outcome IN ('rolling_out', 'live', 'replaced', 'failed', 'superseded')),
    reason          TEXT        CHECK (octet_length(reason) <= 1000),
    ended_at        TIMESTAMPTZ,
    PRIMARY KEY (app_id, number)
);

-- Every replica placed and not yet removed.
CREATE TABLE grund_replicas (
    replica_id      UUID        PRIMARY KEY,
    app_id          UUID        NOT NULL,
    organisation_id UUID        NOT NULL,
    machine_id      UUID        NOT NULL,
    slot            INTEGER     NOT NULL CHECK (slot >= 0),
    release         INTEGER     NOT NULL CHECK (release > 0),
    placement       BIGINT      NOT NULL CHECK (placement >= 0),
    state           TEXT        NOT NULL CHECK (state IN ('running', 'draining')),
    placed_at       TIMESTAMPTZ NOT NULL,
    draining_since  TIMESTAMPTZ
);
CREATE INDEX grund_replicas_app_idx ON grund_replicas (app_id);
CREATE INDEX grund_replicas_machine_idx ON grund_replicas (machine_id);

-- What a replica's machine last said about it. Not history: overwritten on
-- every report, and kept a while after the replica is gone so its last
-- words show in the activity.
CREATE TABLE grund_replica_status (
    replica_id     UUID        PRIMARY KEY,
    machine_id     UUID        NOT NULL,
    state          TEXT        NOT NULL
                   CHECK (state IN ('pulling', 'starting', 'running', 'exited', 'failed', 'refused', 'stopping')),
    ready          BOOLEAN     NOT NULL,
    ready_since    TIMESTAMPTZ,
    ever_ready     BOOLEAN     NOT NULL DEFAULT false,
    restarts       INTEGER     NOT NULL DEFAULT 0 CHECK (restarts >= 0),
    last_exit_code INTEGER     NOT NULL DEFAULT 0,
    reason         TEXT        NOT NULL DEFAULT '' CHECK (octet_length(reason) <= 500),
    observed_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX grund_replica_status_machine_idx ON grund_replica_status (machine_id);

-- The app's history as the dashboard shows it: one row per event, in
-- stream order.
CREATE TABLE grund_app_activity (
    app_id     UUID        NOT NULL,
    version    BIGINT      NOT NULL,
    at         TIMESTAMPTZ NOT NULL,
    kind       TEXT        NOT NULL,
    detail     JSONB       NOT NULL DEFAULT '{}',
    PRIMARY KEY (app_id, version)
);

-- Secret values, sealed with a key derived from GRUND_SECRET_KEY
-- (AES-256-GCM, the app and name and version as associated data). A new
-- value is a new version; versions are never overwritten.
CREATE TABLE grund_app_secrets (
    app_id          UUID        NOT NULL,
    organisation_id UUID        NOT NULL,
    name            TEXT COLLATE "C" NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    version         INTEGER     NOT NULL CHECK (version > 0),
    sealed          BYTEA       NOT NULL CHECK (octet_length(sealed) <= 65600),
    created_by      UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (app_id, name, version)
);
