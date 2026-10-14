-- A management machine becomes returning before Fleet detaches its hosted
-- volumes. Preserve the former lessee from the LeaseEnded event for that
-- direction only; pool_organisation_id is intentionally cleared immediately.
-- The public migrator precedes mire's on a fresh install. Existing deployments
-- already have es_events; only those can have returning machines to backfill.
ALTER TABLE grund_machines ADD COLUMN returning_organisation_id UUID;
DO $$
BEGIN
    IF to_regclass('es_events') IS NOT NULL THEN
        EXECUTE $backfill$
            WITH ended AS (
                SELECT m.machine_id, (e.data->>'organisation_id')::uuid AS organisation_id
                FROM grund_machines m
                JOIN LATERAL (
                    SELECT data FROM es_events
                    WHERE stream_id = 'grund-machine-' || m.machine_id::text
                      AND data->>'type' = 'lease_ended'
                    ORDER BY stream_version DESC LIMIT 1
                ) e ON true
                WHERE m.pool = 'management' AND m.state = 'returning'
            )
            UPDATE grund_machines m SET returning_organisation_id = ended.organisation_id
            FROM ended WHERE m.machine_id = ended.machine_id
        $backfill$;
    END IF;
END $$;
ALTER TABLE grund_machines ADD CONSTRAINT grund_machines_returning_organisation_check
    CHECK (state = 'returning' OR returning_organisation_id IS NULL);
