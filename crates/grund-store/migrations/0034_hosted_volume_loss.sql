-- Operator-declared hosted host loss (storage design §9) is irreversible for
-- the original volume identity. The read model is rebuilt from grund-volume events;
-- neither retiring a lost host nor abandoning its bytes is an erasure receipt.
ALTER TABLE grund_volumes DROP CONSTRAINT grund_volumes_status_check;
ALTER TABLE grund_volumes ADD CONSTRAINT grund_volumes_status_check
    CHECK (status IN ('requested','available','awaiting_backend','attached',
                     'detaching_backend','pending_deletion','deleting','deleted','lost'));
ALTER TABLE grund_volumes ADD COLUMN lost_host_id UUID;
ALTER TABLE grund_volumes ADD COLUMN lost_host_name TEXT;
ALTER TABLE grund_volumes ADD COLUMN lost_at TIMESTAMPTZ;
ALTER TABLE grund_volumes ADD COLUMN lost_snapshot_id TEXT;
ALTER TABLE grund_volumes ADD COLUMN empty_replacement_accepted BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE grund_volumes ADD CONSTRAINT grund_volumes_loss_pair_check
    CHECK ((lost_host_id IS NULL) = (lost_host_name IS NULL) AND
           (lost_host_id IS NULL) = (lost_at IS NULL));
