-- A fleet host can warn grund before pausing a hosted machine. The pause is
-- durable across grund restarts and expires if fleet cannot clear it after a
-- failed migration; it affects entry routing, not the running app copies.
CREATE TABLE grund_machine_migration_pauses (
    machine_id UUID PRIMARY KEY REFERENCES grund_machines(machine_id) ON DELETE CASCADE,
    migration_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + interval '120 seconds'
);
