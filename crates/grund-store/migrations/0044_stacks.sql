-- Stacks own app identities and coordinate whole-bundle changes without replacing
-- existing app, machine or volume event streams. Mire continues to own es_*.
-- These rows are version-fenced projections or disposable reconciliation evidence;
-- credentials remain encrypted in grund_app_secrets, never in stack definitions.
CREATE TABLE grund_stacks (
    organisation_id UUID NOT NULL REFERENCES grund_organisations(organisation_id),
    stack_id UUID NOT NULL,
    name TEXT COLLATE "C" NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,31}$'),
    state JSONB NOT NULL CHECK (jsonb_typeof(state) = 'object'),
    status TEXT NOT NULL CHECK (status IN ('waiting','deploying','ready','degraded','rolling_back','halted','deleting','deleted')),
    machine_id UUID REFERENCES grund_machines(machine_id),
    reserved_memory_mib BIGINT NOT NULL DEFAULT 0 CHECK (reserved_memory_mib >= 0),
    reserved_cpu_millis BIGINT NOT NULL DEFAULT 0 CHECK (reserved_cpu_millis >= 0),
    stream_version BIGINT NOT NULL CHECK (stream_version > 0),
    PRIMARY KEY (organisation_id, stack_id),
    UNIQUE (organisation_id, name)
);
CREATE INDEX grund_stacks_work_idx ON grund_stacks (organisation_id, stack_id) WHERE status <> 'deleted';
CREATE INDEX grund_stacks_machine_idx ON grund_stacks (organisation_id, machine_id) WHERE machine_id IS NOT NULL;

CREATE TABLE grund_stack_members (
    organisation_id UUID NOT NULL,
    stack_id UUID NOT NULL,
    service TEXT COLLATE "C" NOT NULL CHECK (service ~ '^[a-z][a-z0-9-]{0,31}$'),
    app_id UUID NOT NULL REFERENCES grund_apps(app_id),
    app_name TEXT COLLATE "C" NOT NULL,
    exclusive BOOLEAN NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    stopping BOOLEAN NOT NULL DEFAULT FALSE,
    operation_id UUID,
    required_generation BIGINT NOT NULL DEFAULT 0 CHECK (required_generation >= 0),
    PRIMARY KEY (organisation_id, stack_id, service),
    UNIQUE (organisation_id, app_id),
    FOREIGN KEY (organisation_id, stack_id) REFERENCES grund_stacks(organisation_id, stack_id)
);
CREATE INDEX grund_stack_members_app_idx ON grund_stack_members (organisation_id, app_id);

CREATE TABLE grund_stack_receipts (
    organisation_id UUID NOT NULL,
    stack_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    replica_id UUID NOT NULL,
    machine_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organisation_id, stack_id, operation_id, replica_id),
    FOREIGN KEY (organisation_id, stack_id) REFERENCES grund_stacks(organisation_id, stack_id)
);

CREATE TABLE grund_stack_requests (
    organisation_id UUID NOT NULL REFERENCES grund_organisations(organisation_id),
    method TEXT COLLATE "C" NOT NULL,
    request_key TEXT COLLATE "C" NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128),
    fingerprint BYTEA NOT NULL CHECK (octet_length(fingerprint) = 32),
    response JSONB NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + interval '24 hours',
    PRIMARY KEY (organisation_id, method, request_key)
);
CREATE INDEX grund_stack_requests_expiry_idx ON grund_stack_requests (organisation_id, expires_at);
