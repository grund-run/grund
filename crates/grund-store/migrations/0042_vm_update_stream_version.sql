-- Own-VM replacement pins are derived from the shared agent-updates stream.
-- Fence every VM update event so older replay cannot overwrite a newer attempt.
-- Mire owns the event history; this column is only a rebuildable projection guard.
ALTER TABLE grund_vms ADD COLUMN update_stream_version BIGINT NOT NULL DEFAULT 0;

-- A cancelled staged VM preserves its actual outcome in the existing receipt.
ALTER TABLE grund_agent_update_completed_attempts
    DROP CONSTRAINT grund_agent_update_completed_attempts_attempt_check,
    ADD CONSTRAINT grund_agent_update_completed_attempts_attempt_check
    CHECK (jsonb_typeof(attempt) = 'object' AND attempt->>'phase' IN ('succeeded', 'rolled_back', 'cancelled'));
