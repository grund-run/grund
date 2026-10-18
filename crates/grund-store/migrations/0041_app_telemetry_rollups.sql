-- The approved app-observation capacity revision keeps weighted minute/day and
-- ten-minute/week history while charging every metric row and log envelope 384 bytes.
-- Existing 0040 payload accounting is replaced, not retained as a second quota.
ALTER TABLE grund_app_logs DROP CONSTRAINT grund_app_logs_payload_bytes_check;
UPDATE grund_app_logs SET payload_bytes = octet_length(body)::bigint + 384;
ALTER TABLE grund_app_logs ADD CONSTRAINT grund_app_logs_payload_bytes_check
    CHECK (payload_bytes = octet_length(body)::bigint + 384);
ALTER TABLE grund_app_metrics DROP CONSTRAINT grund_app_metrics_payload_bytes_check;
ALTER TABLE grund_app_metrics ALTER COLUMN payload_bytes SET DEFAULT 384;
UPDATE grund_app_metrics SET payload_bytes = 384;
ALTER TABLE grund_app_metrics ADD CONSTRAINT grund_app_metrics_payload_bytes_check
    CHECK (payload_bytes = 384);
CREATE TABLE grund_app_metric_rollups (
    organisation_id UUID NOT NULL,
    app_id UUID NOT NULL,
    instance_id UUID NOT NULL,
    machine_id UUID NOT NULL,
    release INTEGER NOT NULL CHECK (release > 0),
    observed_at TIMESTAMPTZ NOT NULL,
    bucket_seconds INTEGER NOT NULL CHECK (bucket_seconds IN (60, 600)),
    coverage_mask BIGINT NOT NULL CHECK (coverage_mask > 0 AND coverage_mask < (1::bigint << (bucket_seconds / 10))),
    cpu_sum DOUBLE PRECISION NOT NULL CHECK (cpu_sum >= 0 AND cpu_sum < 'Infinity'::float8),
    cpu_count BIGINT NOT NULL CHECK (cpu_count >= 0),
    memory_sum NUMERIC NOT NULL CHECK (memory_sum >= 0 AND memory_sum < 'Infinity'::numeric),
    memory_count BIGINT NOT NULL CHECK (memory_count >= 0),
    memory_max_bytes BIGINT CHECK (memory_max_bytes >= 0),
    samples BIGINT NOT NULL CHECK (samples > 0),
    reserved_cpu_millis INTEGER NOT NULL CHECK (reserved_cpu_millis >= 0),
    reserved_memory_bytes BIGINT NOT NULL CHECK (reserved_memory_bytes >= 0),
    payload_bytes BIGINT NOT NULL DEFAULT 384 CHECK (payload_bytes = 384),
    PRIMARY KEY (organisation_id, instance_id, bucket_seconds, observed_at),
    CHECK (cpu_count <= samples AND memory_count <= samples),
    CHECK ((memory_count = 0) = (memory_max_bytes IS NULL)),
    CHECK (cpu_count > 0 OR cpu_sum = 0),
    CHECK (memory_count > 0 OR memory_sum = 0),
    CHECK (observed_at = date_bin(make_interval(secs => bucket_seconds), observed_at,
                                 timestamptz '1970-01-01 00:00:00+00'))
);
CREATE INDEX grund_app_metric_rollups_app_idx
    ON grund_app_metric_rollups (organisation_id, app_id, observed_at);
CREATE INDEX grund_app_metric_rollups_expiry_idx
    ON grund_app_metric_rollups (organisation_id, observed_at, instance_id, bucket_seconds);
CREATE INDEX grund_app_metric_rollups_minute_idx
    ON grund_app_metric_rollups (organisation_id, observed_at, instance_id)
    WHERE bucket_seconds = 60;
INSERT INTO grund_app_telemetry_usage (organisation_id, cursor, log_bytes, metric_bytes)
SELECT organisation_id, max(cursor), sum(log_bytes)::bigint, sum(metric_bytes)::bigint
FROM (
    SELECT organisation_id, cursor, 0::bigint AS log_bytes, 0::bigint AS metric_bytes
    FROM grund_app_telemetry_usage
    UNION ALL
    SELECT organisation_id, max(cursor), sum(payload_bytes)::bigint, 0::bigint
    FROM grund_app_logs GROUP BY organisation_id
    UNION ALL
    SELECT organisation_id, max(cursor), 0::bigint, sum(payload_bytes)::bigint
    FROM grund_app_metrics GROUP BY organisation_id
) accounting
GROUP BY organisation_id
ON CONFLICT (organisation_id) DO UPDATE
SET cursor = EXCLUDED.cursor, log_bytes = EXCLUDED.log_bytes, metric_bytes = EXCLUDED.metric_bytes;

-- Presence outages describe disconnection from the instance, not app shutdown.
-- A checkpoint starts on the first observed write; never infer pre-migration history.
ALTER TABLE grund_machine_presence ADD COLUMN telemetry_organisation_id UUID;
ALTER TABLE grund_app_telemetry_instances ADD COLUMN metric_coverage_lost_before TIMESTAMPTZ;
CREATE TABLE grund_app_telemetry_outages (
    organisation_id UUID NOT NULL,
    machine_id UUID NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organisation_id, machine_id, started_at),
    CHECK (ended_at > started_at)
);
CREATE INDEX grund_app_telemetry_outages_expiry_idx
ON grund_app_telemetry_outages (organisation_id, ended_at, machine_id, started_at);
CREATE INDEX grund_app_telemetry_instances_app_idx
ON grund_app_telemetry_instances (organisation_id, app_id, placed_at, instance_id);
CREATE FUNCTION grund_record_telemetry_outage() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    owner UUID;
    gap_start TIMESTAMPTZ;
BEGIN
    SELECT pool_organisation_id INTO owner FROM grund_machines WHERE machine_id = NEW.machine_id;
    NEW.telemetry_organisation_id := owner;
    IF TG_OP = 'UPDATE' AND owner IS NOT NULL AND OLD.telemetry_organisation_id = owner
       AND NEW.last_seen_at > OLD.last_seen_at + interval '30 seconds' THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('telemetry-outages:' || owner::text, 0));
        gap_start := greatest(OLD.last_seen_at + interval '30 seconds', statement_timestamp() - interval '7 days');
        IF NEW.last_seen_at > gap_start THEN
            INSERT INTO grund_app_telemetry_outages (organisation_id, machine_id, started_at, ended_at)
            VALUES (owner, NEW.machine_id, gap_start, NEW.last_seen_at)
            ON CONFLICT (organisation_id, machine_id, started_at) DO UPDATE
            SET ended_at = greatest(grund_app_telemetry_outages.ended_at, EXCLUDED.ended_at);
        END IF;
        DELETE FROM grund_app_telemetry_outages WHERE organisation_id = owner
          AND (ended_at <= statement_timestamp() - interval '7 days'
            OR (machine_id, started_at) IN (
                SELECT machine_id, started_at FROM grund_app_telemetry_outages
                WHERE organisation_id = owner ORDER BY ended_at DESC, machine_id, started_at DESC OFFSET 1024));
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER grund_machine_presence_telemetry_outage BEFORE INSERT OR UPDATE OF last_seen_at
ON grund_machine_presence FOR EACH ROW EXECUTE FUNCTION grund_record_telemetry_outage();
CREATE FUNCTION grund_reset_telemetry_presence_owner() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.pool_organisation_id IS DISTINCT FROM OLD.pool_organisation_id THEN
        UPDATE grund_machine_presence SET telemetry_organisation_id = NULL WHERE machine_id = NEW.machine_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER grund_machines_telemetry_owner AFTER UPDATE OF pool_organisation_id
ON grund_machines FOR EACH ROW EXECUTE FUNCTION grund_reset_telemetry_presence_owner();
-- A quota/expiry deletion must not resurrect an offline label over received data.
-- Only the store's transaction-local compaction pass preserves received coverage.
CREATE FUNCTION grund_note_metric_coverage_loss() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('grund.telemetry_compacting', true) = 'on' THEN
        RETURN NULL;
    END IF;
    IF TG_TABLE_NAME = 'grund_app_metrics' THEN
        UPDATE grund_app_telemetry_instances i
        SET metric_coverage_lost_before = greatest(i.metric_coverage_lost_before, d.coverage_end)
        FROM (SELECT organisation_id, instance_id, max(observed_at + interval '10 seconds') AS coverage_end
              FROM deleted_metrics GROUP BY organisation_id, instance_id) d
        WHERE i.organisation_id = d.organisation_id AND i.instance_id = d.instance_id
          AND (i.metric_coverage_lost_before IS NULL OR i.metric_coverage_lost_before < d.coverage_end);
    ELSE
        UPDATE grund_app_telemetry_instances i
        SET metric_coverage_lost_before = greatest(i.metric_coverage_lost_before, d.coverage_end)
        FROM (SELECT organisation_id, instance_id, max(observed_at + make_interval(secs => bucket_seconds)) AS coverage_end
              FROM deleted_metrics GROUP BY organisation_id, instance_id) d
        WHERE i.organisation_id = d.organisation_id AND i.instance_id = d.instance_id
          AND (i.metric_coverage_lost_before IS NULL OR i.metric_coverage_lost_before < d.coverage_end);
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER grund_app_metrics_coverage_loss AFTER DELETE ON grund_app_metrics
REFERENCING OLD TABLE AS deleted_metrics
FOR EACH STATEMENT EXECUTE FUNCTION grund_note_metric_coverage_loss();
CREATE TRIGGER grund_app_metric_rollups_coverage_loss AFTER DELETE ON grund_app_metric_rollups
REFERENCING OLD TABLE AS deleted_metrics
FOR EACH STATEMENT EXECUTE FUNCTION grund_note_metric_coverage_loss();
