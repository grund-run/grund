-- Machine following has one event-sourced rollout slot (updates design §3).
-- These version-guarded rows are rebuildable read models, not rollout truth;
-- mire owns es_* and the singleton stream. Heartbeats are disposable evidence.
-- Migration holds/closed UUIDv7 watermarks and pending provider releases are
-- projected from that same singleton; routing-pause expiry never unlocks them.
CREATE TABLE grund_agent_updates (
    rollout_id UUID PRIMARY KEY,
    initialized BOOLEAN NOT NULL DEFAULT FALSE,
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0),
    target JSONB CHECK (target IS NULL OR jsonb_typeof(target) = 'object'),
    paused BOOLEAN NOT NULL DEFAULT FALSE,
    active JSONB CHECK (active IS NULL OR jsonb_typeof(active) = 'object'),
    last_completed JSONB CHECK (last_completed IS NULL OR jsonb_typeof(last_completed) = 'object'),
    attempt_sequence BIGINT NOT NULL DEFAULT 0 CHECK (attempt_sequence >= 0),
    migration_holds JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(migration_holds) = 'object'),
    closed_migrations JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(closed_migrations) = 'object'),
    pending_provider_release JSONB CHECK (pending_provider_release IS NULL OR jsonb_typeof(pending_provider_release) = 'object'),
    stream_version BIGINT NOT NULL CHECK (stream_version > 0)
);


-- Terminal attempts retain lost-acknowledgment receipts after later machines finish.
CREATE TABLE grund_agent_update_completed_attempts (
    attempt_id UUID PRIMARY KEY,
    attempt JSONB NOT NULL CHECK (jsonb_typeof(attempt) = 'object' AND attempt->>'phase' IN ('succeeded', 'rolled_back')),
    stream_version BIGINT NOT NULL CHECK (stream_version > 0)
);
CREATE TABLE grund_agent_update_observations (
    machine_id UUID PRIMARY KEY,
    registration_key TEXT COLLATE "C" NOT NULL CHECK (registration_key ~ '^[0-9a-f]{64}$'),
    boot_id UUID NOT NULL,
    revision TEXT COLLATE "C" NOT NULL CHECK (revision ~ '^[0-9a-f]{40}$'),
    ready BOOLEAN NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL
);