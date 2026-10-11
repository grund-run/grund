-- A fleet restore reports the VM started before its agent has reconnected and
-- verified its copy. Keep the migration pause until a post-restore heartbeat and
-- ready replica report, with a short expiry if either signal never arrives
-- (traffic.md migration failover, hosted run 2026-10-11).
ALTER TABLE grund_machine_migration_pauses
    ADD COLUMN clear_requested_at TIMESTAMPTZ,
    ADD COLUMN recovery_heartbeat_at TIMESTAMPTZ;
