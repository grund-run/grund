-- Private networks (grund-docs design/network.md §5, §6; machines.md §4):
-- one per organisation for now, made on first use. grund is the only
-- authority on membership: it signs each version of the list with the
-- network's key, and a machine accepts a list only with a newer epoch.

-- A network key is per organisation, like the desired-state key.
ALTER TABLE grund_keys DROP CONSTRAINT grund_keys_purpose_check;
ALTER TABLE grund_keys DROP CONSTRAINT grund_keys_check;
ALTER TABLE grund_keys ADD CONSTRAINT grund_keys_purpose_check
    CHECK (purpose IN ('instance', 'management', 'organisation', 'network'));
ALTER TABLE grund_keys ADD CONSTRAINT grund_keys_check
    CHECK ((purpose IN ('organisation', 'network')) = (organisation_id IS NOT NULL));
CREATE UNIQUE INDEX grund_keys_current_network_idx ON grund_keys (organisation_id)
    WHERE retired_at IS NULL AND purpose = 'network';

-- The newest signed list is stored as sent, so every machine that asks for an
-- epoch gets the same bytes. Epoch 0 means no list has been signed yet.
CREATE TABLE grund_networks (
    network_id      UUID        PRIMARY KEY,
    organisation_id UUID        NOT NULL UNIQUE REFERENCES grund_organisations (organisation_id) ON DELETE CASCADE,
    -- The /48's first address, fdXX:XXXX:XXXX:: (RFC 4193: a random 40-bit
    -- global id), unique so two networks never share addresses.
    prefix          TEXT        NOT NULL UNIQUE,
    key_id          UUID        NOT NULL REFERENCES grund_keys (key_id),
    epoch           BIGINT      NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    body            BYTEA,
    signature       BYTEA,
    issued_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- A slot is a member's /64. A freed slot stays held for 24 hours before
-- another machine may get it (network.md §6.1), so caches and connections
-- that still know the old machine never reach a new one at its address. The
-- row keeps the last holder, so a machine that comes back within the hold
-- gets its own slot again.
CREATE TABLE grund_network_slots (
    network_id  UUID        NOT NULL REFERENCES grund_networks (network_id) ON DELETE CASCADE,
    slot        INTEGER     NOT NULL CHECK (slot BETWEEN 1 AND 65535),
    machine_id  UUID        NOT NULL,
    endpoint_id TEXT        NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL,
    freed_at    TIMESTAMPTZ,
    PRIMARY KEY (network_id, slot)
);
CREATE UNIQUE INDEX grund_network_slots_member_idx ON grund_network_slots (network_id, machine_id)
    WHERE freed_at IS NULL;
