-- App-owned hosted blocks reserve a stable machine drive slot until the host
-- acknowledges detachment. The generic projection is still rebuilt from events.
ALTER TABLE grund_volumes ADD COLUMN size_gib BIGINT CHECK (size_gib BETWEEN 1 AND 4096);
ALTER TABLE grund_volumes ADD COLUMN slot INTEGER CHECK (slot BETWEEN 1 AND 4);
ALTER TABLE grund_volumes ADD COLUMN detachment_pending BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE grund_volumes ADD CONSTRAINT grund_volumes_backend_slot_check
    CHECK (slot IS NULL OR (size_gib IS NOT NULL AND machine_id IS NOT NULL));
ALTER TABLE grund_volumes DROP CONSTRAINT grund_volumes_status_check;
ALTER TABLE grund_volumes ADD CONSTRAINT grund_volumes_status_check
    CHECK (status IN ('requested','available','awaiting_backend','attached',
                     'detaching_backend','pending_deletion','deleting','deleted'));
CREATE UNIQUE INDEX grund_volumes_backend_machine_slot_idx
    ON grund_volumes (machine_id, slot) WHERE slot IS NOT NULL AND status <> 'deleted';
