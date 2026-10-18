-- Customer app telemetry is disposable SQL data, not domain events.
-- Logical payload quotas exclude PostgreSQL tuple, index and vacuum overhead.
-- Retained placement identities permit bounded replay after replicas stop.
CREATE TABLE grund_app_telemetry_usage (
    organisation_id UUID PRIMARY KEY,
    log_bytes BIGINT NOT NULL DEFAULT 0 CHECK (log_bytes >= 0),
    receipts INTEGER NOT NULL DEFAULT 0 CHECK (receipts BETWEEN 0 AND 8388608),
    metric_bytes BIGINT NOT NULL DEFAULT 0 CHECK (metric_bytes >= 0),
    cursor BIGINT NOT NULL DEFAULT 0 CHECK (cursor >= 0)
);
CREATE TABLE grund_app_telemetry_instances (
    organisation_id UUID NOT NULL,
    instance_id UUID NOT NULL,
    app_id UUID NOT NULL,
    machine_id UUID NOT NULL,
    release INTEGER NOT NULL CHECK (release > 0),
    placed_at TIMESTAMPTZ NOT NULL,
    stopped_at TIMESTAMPTZ,
    PRIMARY KEY (organisation_id, instance_id)
);
CREATE INDEX grund_app_telemetry_instances_machine_idx ON grund_app_telemetry_instances (organisation_id, machine_id);
CREATE INDEX grund_app_telemetry_instances_expiry_idx ON grund_app_telemetry_instances (organisation_id, stopped_at) WHERE stopped_at IS NOT NULL;
INSERT INTO grund_app_telemetry_instances (organisation_id, instance_id, app_id, machine_id, release, placed_at)
SELECT organisation_id, replica_id, app_id, machine_id, release, placed_at FROM grund_replicas;
CREATE FUNCTION grund_record_telemetry_instance() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO grund_app_telemetry_instances (organisation_id, instance_id, app_id, machine_id, release, placed_at)
        VALUES (NEW.organisation_id, NEW.replica_id, NEW.app_id, NEW.machine_id, NEW.release, NEW.placed_at)
        ON CONFLICT DO NOTHING;
        RETURN NEW;
    END IF;
    UPDATE grund_app_telemetry_instances SET stopped_at = clock_timestamp()
    WHERE organisation_id = OLD.organisation_id AND instance_id = OLD.replica_id;
    RETURN OLD;
END;
$$;
CREATE TRIGGER grund_replicas_telemetry_identity AFTER INSERT OR DELETE ON grund_replicas
FOR EACH ROW EXECUTE FUNCTION grund_record_telemetry_instance();
CREATE TABLE grund_app_telemetry_batches (
    organisation_id UUID NOT NULL,
    machine_id UUID NOT NULL,
    batch_id UUID NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    accepted_logs INTEGER NOT NULL,
    accepted_samples INTEGER NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organisation_id, machine_id, batch_id)
);
CREATE INDEX grund_app_telemetry_batches_expiry_idx ON grund_app_telemetry_batches (organisation_id, received_at);
CREATE TABLE grund_app_logs (
    organisation_id UUID NOT NULL,
    cursor BIGINT NOT NULL,
    app_id UUID NOT NULL,
    instance_id UUID NOT NULL,
    machine_id UUID NOT NULL,
    release INTEGER NOT NULL CHECK (release > 0),
    observed_at TIMESTAMPTZ NOT NULL,
    stream TEXT NOT NULL CHECK (stream IN ('stdout', 'stderr', 'combined')),
    body TEXT NOT NULL CHECK (octet_length(body) <= 8192),
    truncated BOOLEAN NOT NULL,
    payload_bytes BIGINT NOT NULL CHECK (payload_bytes BETWEEN 128 AND 8320),
    PRIMARY KEY (organisation_id, cursor)
);
CREATE INDEX grund_app_logs_app_idx ON grund_app_logs (organisation_id, app_id, cursor);
CREATE INDEX grund_app_logs_expiry_idx ON grund_app_logs (organisation_id, observed_at, cursor);
CREATE TABLE grund_app_metrics (
    organisation_id UUID NOT NULL,
    cursor BIGINT NOT NULL,
    app_id UUID NOT NULL,
    instance_id UUID NOT NULL,
    machine_id UUID NOT NULL,
    release INTEGER NOT NULL CHECK (release > 0),
    observed_at TIMESTAMPTZ NOT NULL,
    cpu_millis DOUBLE PRECISION CHECK (cpu_millis >= 0 AND cpu_millis < 'Infinity'::float8),
    memory_bytes BIGINT CHECK (memory_bytes >= 0),
    reserved_cpu_millis INTEGER NOT NULL CHECK (reserved_cpu_millis >= 0),
    reserved_memory_bytes BIGINT NOT NULL CHECK (reserved_memory_bytes >= 0),
    payload_bytes BIGINT NOT NULL DEFAULT 128 CHECK (payload_bytes = 128),
    PRIMARY KEY (organisation_id, cursor)
);
CREATE INDEX grund_app_metrics_app_idx ON grund_app_metrics (organisation_id, app_id, observed_at);
CREATE INDEX grund_app_metrics_expiry_idx ON grund_app_metrics (organisation_id, observed_at, cursor);
CREATE TABLE grund_app_telemetry_losses (
    organisation_id UUID NOT NULL,
    app_id UUID NOT NULL,
    dropped_records BIGINT NOT NULL DEFAULT 0 CHECK (dropped_records >= 0),
    PRIMARY KEY (organisation_id, app_id)
);
