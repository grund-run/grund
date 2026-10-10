-- Hosted machines belong to an explicitly entitled organisation. The request row
-- bridges a provider's asynchronous registration to the customer's lease and
-- preserves a visible Joining state until the registered machine is ready.
-- Provider identifiers and enrollment tokens are never returned to customers.
CREATE TABLE grund_hosted_entitlements (
    organisation_id UUID PRIMARY KEY REFERENCES grund_organisations (organisation_id),
    enabled BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE grund_hosted_orders (
    organisation_id UUID NOT NULL REFERENCES grund_organisations (organisation_id),
    order_id UUID NOT NULL,
    name TEXT COLLATE "C" NOT NULL,
    size TEXT COLLATE "C" NOT NULL CHECK (char_length(size) BETWEEN 1 AND 100),
    region TEXT COLLATE "C" NOT NULL CHECK (char_length(region) BETWEEN 1 AND 100),
    idempotency_key TEXT COLLATE "C" CHECK (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 128),
    token_id UUID UNIQUE REFERENCES grund_machine_tokens (token_id),
    machine_id UUID,
    status TEXT NOT NULL CHECK (status IN ('joining', 'active', 'removed', 'failed', 'refused')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + interval '30 seconds',
    leased_until TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    released_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    rebuild_requested_at TIMESTAMPTZ,
    PRIMARY KEY (organisation_id, order_id),
    CHECK (status <> 'active' OR machine_id IS NOT NULL),
    CHECK (status NOT IN ('removed', 'failed') OR cancelled_at IS NOT NULL)
);
CREATE UNIQUE INDEX grund_hosted_orders_active_name_idx
    ON grund_hosted_orders (organisation_id, name) WHERE status IN ('joining', 'active');
CREATE UNIQUE INDEX grund_hosted_orders_machine_idx
    ON grund_hosted_orders (machine_id) WHERE status IN ('joining', 'active') AND machine_id IS NOT NULL;
CREATE INDEX grund_hosted_orders_pending_idx
    ON grund_hosted_orders (next_attempt_at, order_id) WHERE status = 'joining';
CREATE INDEX grund_hosted_orders_release_idx
    ON grund_hosted_orders (created_at, order_id) WHERE status IN ('removed', 'failed') AND machine_id IS NULL AND released_at IS NULL;
CREATE UNIQUE INDEX grund_hosted_orders_idempotency_idx
    ON grund_hosted_orders (organisation_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX grund_hosted_orders_rebuild_idx
    ON grund_hosted_orders (next_attempt_at, order_id)
    WHERE status = 'removed' AND machine_id IS NOT NULL AND rebuild_requested_at IS NULL;

-- Keep operator-issued lease IDs so old VMs never reveal their physical host
-- after a lease ends and the management machine is rented again.
CREATE TABLE grund_hosted_manual_leases (
    organisation_id UUID NOT NULL REFERENCES grund_organisations (organisation_id),
    lease_id UUID NOT NULL,
    machine_id UUID NOT NULL,
    leased_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organisation_id, lease_id)
);
CREATE INDEX grund_hosted_manual_leases_machine_idx
    ON grund_hosted_manual_leases (organisation_id, machine_id, leased_at DESC);

INSERT INTO grund_hosted_manual_leases (organisation_id, lease_id, machine_id, leased_at)
SELECT lessee_organisation_id, lease_id, machine_id, leased_at
FROM grund_machines
WHERE pool = 'management' AND lease_id IS NOT NULL
  AND lessee_organisation_id IS NOT NULL AND leased_at IS NOT NULL;

ALTER TABLE grund_machine_tokens ADD COLUMN hosted_size TEXT COLLATE "C",
    ADD COLUMN hosted_region TEXT COLLATE "C";
ALTER TABLE grund_machines ADD COLUMN hosted_size TEXT COLLATE "C",
    ADD COLUMN hosted_region TEXT COLLATE "C";
