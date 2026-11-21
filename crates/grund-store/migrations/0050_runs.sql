-- One-off stack executions (approved design sections 1, 3 and 5).
-- Mire owns grund-run audit streams; these version-guarded rows are rebuildable.
-- Argument bodies alone are erasable. Receipts deliberately contain only metadata.
CREATE TABLE grund_runs (
    organisation_id UUID NOT NULL,
    run_id UUID NOT NULL,
    stack_id UUID NOT NULL,
    service TEXT COLLATE "C" NOT NULL,
    app_id UUID NOT NULL,
    release INTEGER NOT NULL CHECK (release > 0),
    machine_id UUID NOT NULL,
    state JSONB NOT NULL CHECK (jsonb_typeof(state) = 'object'),
    outstanding BOOLEAN NOT NULL,
    deadline TIMESTAMPTZ NOT NULL,
    args_expire_at TIMESTAMPTZ,
    stream_version BIGINT NOT NULL CHECK (stream_version > 0),
    log_bytes_received BIGINT NOT NULL DEFAULT 0 CHECK (log_bytes_received BETWEEN 0 AND 10485760),
    dropped_records BIGINT NOT NULL DEFAULT 0 CHECK (dropped_records >= 0),
    PRIMARY KEY (organisation_id, run_id)
);
CREATE UNIQUE INDEX grund_runs_service_fence_idx ON grund_runs (organisation_id, stack_id, service) WHERE outstanding;
CREATE INDEX grund_runs_machine_idx ON grund_runs (organisation_id, machine_id) WHERE outstanding;
CREATE INDEX grund_runs_page_idx ON grund_runs (organisation_id, stack_id, run_id);
CREATE INDEX grund_runs_expiry_idx ON grund_runs (organisation_id, args_expire_at) WHERE args_expire_at IS NOT NULL;
CREATE TABLE grund_run_payloads (
    organisation_id UUID NOT NULL,
    run_id UUID NOT NULL,
    args JSONB NOT NULL CHECK (jsonb_typeof(args) = 'array' AND jsonb_array_length(args) BETWEEN 1 AND 128 AND octet_length(args::text) <= 200000),
    PRIMARY KEY (organisation_id, run_id),
    FOREIGN KEY (organisation_id, run_id) REFERENCES grund_runs (organisation_id, run_id)
);
CREATE TABLE grund_run_requests (
    organisation_id UUID NOT NULL,
    caller_id UUID NOT NULL,
    method TEXT COLLATE "C" NOT NULL CHECK (method IN ('create', 'cancel')),
    request_key TEXT COLLATE "C" NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128),
    fingerprint BYTEA NOT NULL CHECK (octet_length(fingerprint) = 32),
    run_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + interval '24 hours',
    PRIMARY KEY (organisation_id, caller_id, method, request_key)
);
CREATE INDEX grund_run_requests_expiry_idx ON grund_run_requests (organisation_id, expires_at);

-- Durable pins prevent future release/secret GC from erasing an outstanding input.
CREATE TABLE grund_run_inputs (
    organisation_id UUID NOT NULL,
    run_id UUID NOT NULL,
    app_id UUID NOT NULL,
    release INTEGER NOT NULL,
    secret_versions JSONB NOT NULL CHECK (jsonb_typeof(secret_versions) = 'array'),
    PRIMARY KEY (organisation_id, run_id),
    FOREIGN KEY (app_id, release) REFERENCES grund_releases(app_id, number)
);
CREATE TABLE grund_run_secret_pins (
    organisation_id UUID NOT NULL,
    run_id UUID NOT NULL,
    app_id UUID NOT NULL,
    name TEXT COLLATE "C" NOT NULL,
    version INTEGER NOT NULL,
    PRIMARY KEY (organisation_id, run_id, name),
    FOREIGN KEY (organisation_id, run_id) REFERENCES grund_run_inputs(organisation_id, run_id) ON DELETE CASCADE,
    FOREIGN KEY (app_id, name, version) REFERENCES grund_app_secrets(app_id, name, version)
);

-- Ordinary app readers cannot address this namespace: run output is stored under
-- app_id=run_id, never under the backing application's identity. Wire identities
-- are still validated against the real app, release and machine before rewriting.
ALTER TABLE grund_app_telemetry_instances ADD COLUMN run_id UUID;
CREATE INDEX grund_app_telemetry_instances_run_idx ON grund_app_telemetry_instances (organisation_id, run_id) WHERE run_id IS NOT NULL;
