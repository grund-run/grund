-- Certificates for terminators on other hosts, and the relays that ask for
-- them (grund-docs design/traffic.md §5.7, "the CSR flow"). The first
-- terminator is `grund relay` on a host of its own; a machine's gate and the
-- edge come later on the same rows.
--
-- The rule of 0010 holds: the instance drives every order, and the key is
-- made where TLS terminates. A remote terminator's row holds its CSR and
-- never a key; the instance's own row holds its sealed key and never a CSR.

-- Who a certificate belongs to. Every row so far is the instance's own
-- (its domain, its relays); custom domains (M3) will be an organisation's,
-- and every lookup made for a caller filters on it. The subject stays the
-- primary key: it already names the terminator (`instance`,
-- `relay:<host>`), so it is unique across owners.
ALTER TABLE grund_certificates
    ADD COLUMN owner TEXT COLLATE "C" NOT NULL DEFAULT 'instance'
        CHECK (owner = 'instance' OR owner ~ '^organisation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    -- Where the key lives: here, sealed (the instance's own domain), or with
    -- a terminator elsewhere, which sent `csr`.
    ADD COLUMN terminator TEXT NOT NULL DEFAULT 'instance' CHECK (terminator IN ('instance', 'remote')),
    ADD COLUMN csr BYTEA CHECK (octet_length(csr) BETWEEN 1 AND 4096),
    -- The CSR was issued once. Renewal wants a fresh key, so a spent CSR is
    -- never ordered again; the terminator is asked for a new one.
    ADD COLUMN csr_spent BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT grund_certificates_key_or_csr CHECK (
        (terminator = 'instance' AND csr IS NULL AND NOT csr_spent)
        OR (terminator = 'remote' AND sealed_key IS NULL AND csr IS NOT NULL)
    );

CREATE INDEX grund_certificates_owner_idx ON grund_certificates (owner, subject);

-- A challenge now names the subject it is for, so a terminator is handed
-- only its own, and the instance's listener answers only the instance's.
-- `answering_at` is set when a remote terminator says it answers: the CA is
-- told to validate only after that. Rows before this migration are the
-- instance's (they expire within 15 minutes anyway).
ALTER TABLE grund_acme_challenges
    ADD COLUMN subject TEXT COLLATE "C" NOT NULL DEFAULT 'instance',
    ADD COLUMN answering_at TIMESTAMPTZ;
ALTER TABLE grund_acme_challenges ALTER COLUMN subject DROP DEFAULT;
CREATE INDEX grund_acme_challenges_subject_idx ON grund_acme_challenges (subject, expires_at);

-- `grund relay`s enrolled with this instance, each under an Ed25519 key it
-- made itself. Nothing else identifies a relay: its calls are signed by this
-- key, and the host it may serve (and ask a certificate for) is the one its
-- token was minted for. One active relay per host; enrolling a host again
-- revokes the relay it had. Revoking is one row, and a revoked relay loses
-- the certificate API and the access check alike.
--
-- Plain tables, not an event stream, like 0010: a relay's identity is one
-- key and one host, nothing downstream folds its history, and revocation is
-- terminal.
CREATE TABLE grund_relays (
    relay_id    UUID        PRIMARY KEY,
    host        TEXT COLLATE "C" NOT NULL CHECK (host ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'),
    public_key  BYTEA       NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    state       TEXT        NOT NULL CHECK (state IN ('active', 'revoked')),
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    revoked_at  TIMESTAMPTZ,
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX grund_relays_host_idx ON grund_relays (host) WHERE state = 'active';

-- One-time enrollment tokens, minted by an operator for one host. Only the
-- SHA-256 of a token is stored. A consumed token keeps the key it enrolled,
-- so repeating the call with the same key answers the same, and any other
-- key is refused.
CREATE TABLE grund_relay_tokens (
    token_digest BYTEA       PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    host         TEXT COLLATE "C" NOT NULL CHECK (host ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'),
    expires_at   TIMESTAMPTZ NOT NULL,
    relay_id     UUID REFERENCES grund_relays (relay_id),
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((relay_id IS NULL) = (consumed_at IS NULL))
);
CREATE INDEX grund_relay_tokens_expiry_idx ON grund_relay_tokens (expires_at) WHERE consumed_at IS NULL;
