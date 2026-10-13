-- 0030_volume_delete_window.sql: keep app-owned bytes and backup recovery points
-- for the configurable app/volume recovery window before durable final purge.
-- An expired app stops reserving its name only when its purge is recorded.
ALTER TABLE grund_apps ADD COLUMN purge_after TIMESTAMPTZ;
ALTER TABLE grund_volumes ADD COLUMN purge_after TIMESTAMPTZ;
ALTER TABLE grund_volumes DROP CONSTRAINT grund_volumes_status_check;
ALTER TABLE grund_volumes ADD CONSTRAINT grund_volumes_status_check
    CHECK (status IN ('requested','available','attached','pending_deletion','deleting','deleted'));
CREATE INDEX grund_volumes_purge_due_idx ON grund_volumes (purge_after, organisation_id, volume_id)
    WHERE status = 'pending_deletion';
CREATE INDEX grund_apps_purge_due_idx ON grund_apps (purge_after, organisation_id, app_id)
    WHERE deleted_at IS NOT NULL AND purge_after IS NOT NULL;
DROP INDEX grund_apps_name_idx;
CREATE UNIQUE INDEX grund_apps_name_idx ON grund_apps (organisation_id, name)
    WHERE deleted_at IS NULL OR purge_after IS NOT NULL;
