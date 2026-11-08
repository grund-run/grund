-- Fence financial outbox delivery by destination epoch (Billing destination
-- epoch fence, Public grund: configuration, store and sender). Legacy NULL
-- origins remain unknown, never inferred from the current destination. Retain
-- superseded facts intact; already scrubbed delivered history is unrecoverable.
CREATE TABLE grund_billing_epochs (
    epoch        UUID PRIMARY KEY CHECK (epoch <> '00000000-0000-0000-0000-000000000000'),
    url          TEXT NOT NULL CHECK (url <> '' AND position('@' in url) = 0),
    mode         TEXT NOT NULL CHECK (mode IN ('sandbox', 'live')),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    retired_at   TIMESTAMPTZ
);

-- The permanent singleton is also the admission lock. Activations take UPDATE,
-- short producer/claim/completion transactions take SHARE, never across HTTP.
CREATE TABLE grund_billing_destination (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    epoch     UUID REFERENCES grund_billing_epochs (epoch)
);
INSERT INTO grund_billing_destination (singleton) VALUES (TRUE);

ALTER TABLE grund_outbox ADD COLUMN billing_epoch UUID;
ALTER TABLE grund_outbox ADD COLUMN superseded_at TIMESTAMPTZ;
ALTER TABLE grund_outbox ADD CONSTRAINT grund_outbox_billing_scope_check CHECK (
    (billing_epoch IS NULL AND superseded_at IS NULL)
    OR kind IN ('billing.organisation', 'billing.machine_count', 'billing.machine_change')
);
ALTER TABLE grund_outbox ADD CONSTRAINT grund_outbox_billing_epoch_check CHECK (
    billing_epoch IS NULL OR billing_epoch <> '00000000-0000-0000-0000-000000000000'
);

DROP INDEX grund_outbox_pending_idx;
CREATE INDEX grund_outbox_pending_idx ON grund_outbox (next_attempt_at, created_at)
    WHERE delivered_at IS NULL AND superseded_at IS NULL;
CREATE INDEX grund_outbox_billing_epoch_idx ON grund_outbox (billing_epoch, next_attempt_at, created_at)
    WHERE delivered_at IS NULL AND superseded_at IS NULL
      AND kind IN ('billing.organisation', 'billing.machine_count', 'billing.machine_change');
