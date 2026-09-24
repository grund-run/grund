-- 0001_accounts.sql: accounts, organisations, sessions and the mail outbox.
-- The design is docs/design/auth.md.
--
-- This file owns grund_* tables; mire's own migrator owns es_* (the event
-- log). Two kinds of table live here:
--
-- * Read models of the grund-account and grund-organisation streams:
--   grund_accounts, grund_organisations, grund_memberships. The events are
--   the truth. These are written in the same transaction as the events by
--   grund_store::projections, guarded by stream_version so replays never move
--   a row backwards, and can be rebuilt from the log. The unique index on
--   username only refuses a conflicting write; it is not the record.
-- * Plain tables that are the truth for what they hold, deleted from freely:
--   addresses, password hashes and provider subjects (never in the event log,
--   so they can be erased), sessions, email-link tokens, rate-limit counters
--   and the outbox.
--
-- Secrets are never stored: sessions and email links as SHA-256 digests,
-- rate-limit keys as HMAC digests, passwords as Argon2id PHC strings.

CREATE TABLE grund_accounts (
    account_id        UUID        PRIMARY KEY,
    username          TEXT COLLATE "C" NOT NULL
                      CHECK (username ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(username) BETWEEN 3 AND 32),
    organisation_id   UUID        NOT NULL,
    email_verified_at TIMESTAMPTZ,
    registered_at     TIMESTAMPTZ NOT NULL,
    stream_version    BIGINT      NOT NULL CHECK (stream_version >= 1)
);
CREATE UNIQUE INDEX grund_accounts_username_idx ON grund_accounts (username);

CREATE TABLE grund_organisations (
    organisation_id UUID        PRIMARY KEY,
    slug            TEXT COLLATE "C" NOT NULL
                    CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(slug) BETWEEN 3 AND 32),
    kind            TEXT        NOT NULL CHECK (kind IN ('personal')),
    created_at      TIMESTAMPTZ NOT NULL,
    stream_version  BIGINT      NOT NULL CHECK (stream_version >= 1)
);
CREATE UNIQUE INDEX grund_organisations_slug_idx ON grund_organisations (slug);

-- The organisation leads the key: later resources are found through it.
CREATE TABLE grund_memberships (
    organisation_id UUID   NOT NULL,
    account_id      UUID   NOT NULL,
    role            TEXT   NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    stream_version  BIGINT NOT NULL CHECK (stream_version >= 1),
    PRIMARY KEY (organisation_id, account_id)
);
CREATE INDEX grund_memberships_account_idx ON grund_memberships (account_id, organisation_id);

CREATE TABLE grund_account_emails (
    account_id       UUID        PRIMARY KEY,
    email            TEXT        NOT NULL CHECK (octet_length(email) BETWEEN 3 AND 254),
    email_normalized TEXT COLLATE "C" NOT NULL CHECK (email_normalized = lower(email_normalized)),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX grund_account_emails_normalized_idx ON grund_account_emails (email_normalized);

CREATE TABLE grund_passwords (
    account_id UUID        PRIMARY KEY,
    phc        TEXT        NOT NULL CHECK (phc LIKE '$argon2id$%'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Linked social identities. The subject is the provider's stable id for the
-- person; one identity per provider per account.
CREATE TABLE grund_identities (
    identity_id UUID        PRIMARY KEY,
    provider    TEXT        NOT NULL CHECK (provider IN ('github', 'google', 'oidc')),
    subject     TEXT COLLATE "C" NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
    account_id  UUID        NOT NULL,
    linked_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX grund_identities_subject_idx ON grund_identities (provider, subject);
CREATE UNIQUE INDEX grund_identities_account_idx ON grund_identities (account_id, provider);

-- Expiry is enforced on every read; the sweeper only reclaims space.
CREATE TABLE grund_sessions (
    session_id     UUID        PRIMARY KEY,
    token_digest   BYTEA       NOT NULL CHECK (octet_length(token_digest) = 32),
    account_id     UUID        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at     TIMESTAMPTZ NOT NULL,
    user_agent     TEXT        NOT NULL DEFAULT '' CHECK (char_length(user_agent) <= 256),
    client_address TEXT        NOT NULL DEFAULT '' CHECK (char_length(client_address) <= 64),
    revoked_at     TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);
CREATE UNIQUE INDEX grund_sessions_token_idx ON grund_sessions (token_digest);
CREATE INDEX grund_sessions_account_idx ON grund_sessions (account_id, created_at) WHERE revoked_at IS NULL;
CREATE INDEX grund_sessions_expiry_idx ON grund_sessions (expires_at);

-- Links sent by mail. Bound to the address they were sent to, so a link for
-- an address the account no longer has proves nothing.
CREATE TABLE grund_email_tokens (
    token_digest     BYTEA       PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    purpose          TEXT        NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
    account_id       UUID        NOT NULL,
    email_normalized TEXT COLLATE "C" NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at       TIMESTAMPTZ NOT NULL,
    used_at          TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);
CREATE INDEX grund_email_tokens_account_idx ON grund_email_tokens (account_id, purpose) WHERE used_at IS NULL;
CREATE INDEX grund_email_tokens_expiry_idx ON grund_email_tokens (expires_at);

-- Fixed-window counters. The key is an HMAC of the counted value (an account
-- name, an address), never the value.
CREATE TABLE grund_throttle (
    scope        TEXT        NOT NULL
                 CHECK (scope IN ('login_failure', 'login_address', 'mail_email', 'mail_address')),
    key_digest   BYTEA       NOT NULL CHECK (octet_length(key_digest) = 32),
    window_start TIMESTAMPTZ NOT NULL,
    hits         INTEGER     NOT NULL CHECK (hits >= 0),
    PRIMARY KEY (scope, key_digest)
);
CREATE INDEX grund_throttle_window_idx ON grund_throttle (window_start);

-- Work to do after commit: mail, and resolving reset requests. The id derives
-- from what caused the row, so a retried cause never queues twice. Delivered
-- rows are scrubbed of recipient and payload at once, and deleted after a
-- retention window.
CREATE TABLE grund_outbox (
    outbox_id       UUID        PRIMARY KEY,
    kind            TEXT        NOT NULL CHECK (kind IN (
                        'mail.verify_email', 'mail.password_reset', 'mail.signup_existing',
                        'auth.password_reset_requested')),
    recipient       TEXT        NOT NULL DEFAULT '' CHECK (octet_length(recipient) <= 254),
    payload         JSONB       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(payload) = 'object'),
    attempts        INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_error      TEXT        CHECK (char_length(last_error) <= 200),
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX grund_outbox_pending_idx ON grund_outbox (next_attempt_at, created_at) WHERE delivered_at IS NULL;
CREATE INDEX grund_outbox_delivered_idx ON grund_outbox (delivered_at) WHERE delivered_at IS NOT NULL;
