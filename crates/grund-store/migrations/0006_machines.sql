-- 0006_machines.sql: machines and how they enroll (grund/fleet
-- docs/design/enrollment-contract.md). A machine belongs to an organisation,
-- the customer's own hardware and grund machines alike.

-- The read model of the grund-machine aggregate. public_key is the Ed25519
-- key the machine proved at enrollment, as base64url without padding (32
-- bytes, 43 characters), the form the API shows; it is unique, so one key is
-- one machine. A name is unique among an organisation's machines that are
-- not revoked.
CREATE TABLE grund_machines (
    machine_id       UUID        PRIMARY KEY,
    organisation_id  UUID        NOT NULL,
    name             TEXT        NOT NULL
                     CHECK (name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$' AND char_length(name) <= 63),
    public_key       TEXT        NOT NULL UNIQUE CHECK (char_length(public_key) = 43),
    minted_by        TEXT        NOT NULL CHECK (char_length(minted_by) <= 128),
    facts            JSONB       NOT NULL,
    enrolled_at      TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ,
    stream_version   BIGINT      NOT NULL
);
CREATE INDEX grund_machines_organisation_idx ON grund_machines (organisation_id, enrolled_at);
CREATE UNIQUE INDEX grund_machines_live_name_idx ON grund_machines (organisation_id, name)
    WHERE revoked_at IS NULL;

-- One-time enrollment tokens. Only the token's SHA-256 is kept. A token is
-- bound at minting to its organisation, optionally a machine name, and who
-- minted it. Enrolling consumes it and records the machine and key, so a
-- replay with the same key while the token would still be valid returns
-- the same machine (the contract's §3.3). uses counts every call naming the
-- token, replays included, for its limit of 5.
CREATE TABLE grund_enrollment_tokens (
    token_digest     BYTEA       PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    organisation_id  UUID        NOT NULL,
    machine_name     TEXT        CHECK (char_length(machine_name) <= 63),
    minted_by        TEXT        NOT NULL CHECK (char_length(minted_by) <= 128),
    created_at       TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    consumed_at      TIMESTAMPTZ,
    machine_id       UUID,
    public_key       TEXT        CHECK (char_length(public_key) = 43),
    uses             INTEGER     NOT NULL DEFAULT 0 CHECK (uses >= 0),
    CHECK ((consumed_at IS NULL) = (machine_id IS NULL) AND (machine_id IS NULL) = (public_key IS NULL))
);
CREATE INDEX grund_enrollment_tokens_open_idx ON grund_enrollment_tokens (organisation_id, expires_at)
    WHERE consumed_at IS NULL;
CREATE INDEX grund_enrollment_tokens_expiry_idx ON grund_enrollment_tokens (expires_at);

-- Enrollment calls are counted per client address.
ALTER TABLE grund_throttle DROP CONSTRAINT grund_throttle_scope_check;
ALTER TABLE grund_throttle ADD CONSTRAINT grund_throttle_scope_check CHECK (scope IN (
    'login_failure', 'login_address', 'mail_email', 'mail_address', 'enroll_address'));
