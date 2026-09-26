-- 0006_machines.sql: machines, the management pool, leases, registration
-- tokens and the instance's keys (grund-docs design/machines.md).

-- Enrollment calls are counted per client address.
ALTER TABLE grund_throttle DROP CONSTRAINT grund_throttle_scope_check;
ALTER TABLE grund_throttle ADD CONSTRAINT grund_throttle_scope_check CHECK (scope IN (
    'login_failure', 'login_address', 'mail_email', 'mail_address', 'enroll_address'));

-- The instance's Ed25519 keys. Only the public half is stored: the private
-- half is derived from GRUND_SECRET_KEY and the key id at every start, and
-- checked against this row, so no private key sits in the database or its
-- backups. One current key per purpose, and per organisation.
CREATE TABLE grund_keys (
    key_id          UUID        PRIMARY KEY,
    purpose         TEXT        NOT NULL CHECK (purpose IN ('instance', 'management', 'organisation')),
    organisation_id UUID,
    public_key      BYTEA       NOT NULL CHECK (octet_length(public_key) = 32),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    retired_at      TIMESTAMPTZ,
    CHECK ((purpose = 'organisation') = (organisation_id IS NOT NULL))
);
CREATE UNIQUE INDEX grund_keys_current_idx ON grund_keys (purpose)
    WHERE retired_at IS NULL AND purpose IN ('instance', 'management');
CREATE UNIQUE INDEX grund_keys_current_organisation_idx ON grund_keys (organisation_id)
    WHERE retired_at IS NULL AND purpose = 'organisation';

-- The read model of the grund-machine streams. pool_organisation_id and
-- pool_name are the organisation whose pool the machine is in now (its own
-- organisation while active, the lessee while leased) and its name there:
-- names are unique within a pool.
CREATE TABLE grund_machines (
    machine_id             UUID        PRIMARY KEY,
    pool                   TEXT        NOT NULL CHECK (pool IN ('management', 'organisation')),
    home_organisation_id   UUID,
    name                   TEXT COLLATE "C" NOT NULL,
    state                  TEXT        NOT NULL
                           CHECK (state IN ('available', 'leased', 'returning', 'active', 'revoked')),
    public_key             TEXT COLLATE "C" CHECK (public_key ~ '^[0-9a-f]{64}$'),
    lease_id               UUID,
    lessee_organisation_id UUID,
    lease_name             TEXT COLLATE "C",
    leased_at              TIMESTAMPTZ,
    pool_organisation_id   UUID,
    pool_name              TEXT COLLATE "C",
    facts                  JSONB       NOT NULL DEFAULT '{}',
    minted_by              TEXT        NOT NULL,
    registered_at          TIMESTAMPTZ NOT NULL,
    key_registered_at      TIMESTAMPTZ NOT NULL,
    revoked_at             TIMESTAMPTZ,
    stream_version         BIGINT      NOT NULL,
    CHECK ((pool = 'organisation') = (home_organisation_id IS NOT NULL)),
    CHECK ((state = 'revoked') = (public_key IS NULL))
);
CREATE UNIQUE INDEX grund_machines_pool_name_idx ON grund_machines (pool_organisation_id, pool_name)
    WHERE pool_organisation_id IS NOT NULL;
CREATE UNIQUE INDEX grund_machines_management_name_idx ON grund_machines (name)
    WHERE pool = 'management' AND state <> 'revoked';
CREATE UNIQUE INDEX grund_machines_key_idx ON grund_machines (public_key)
    WHERE public_key IS NOT NULL;
CREATE INDEX grund_machines_management_idx ON grund_machines (state, registered_at)
    WHERE pool = 'management';

-- One-time registration tokens. Only the SHA-256 of a token is kept. A
-- consumed token remembers the key and machine it registered, so the same
-- machine repeating the call gets the same answer (at most five times).
CREATE TABLE grund_machine_tokens (
    token_id            UUID        PRIMARY KEY,
    token_digest        BYTEA       NOT NULL CHECK (octet_length(token_digest) = 32),
    kind                TEXT        NOT NULL CHECK (kind IN ('management', 'organisation')),
    organisation_id     UUID,
    machine_id          UUID,
    name                TEXT COLLATE "C",
    minted_by           TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at          TIMESTAMPTZ NOT NULL,
    consumed_at         TIMESTAMPTZ,
    consumed_key        TEXT COLLATE "C",
    consumed_machine_id UUID,
    replays             INTEGER     NOT NULL DEFAULT 0 CHECK (replays >= 0),
    CHECK (expires_at > created_at),
    CHECK ((kind = 'organisation') = (organisation_id IS NOT NULL)),
    CHECK (machine_id IS NULL OR kind = 'management'),
    CHECK ((consumed_at IS NULL) = (consumed_key IS NULL))
);
CREATE UNIQUE INDEX grund_machine_tokens_digest_idx ON grund_machine_tokens (token_digest);
CREATE INDEX grund_machine_tokens_open_idx ON grund_machine_tokens (kind, organisation_id, expires_at)
    WHERE consumed_at IS NULL;
