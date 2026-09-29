-- The owner's setup link (grund-docs design/auth.md §5): the only way the
-- first account of a `single` instance is created. `grund setup-link` mints
-- one on the instance's machine while no account exists; opening it creates
-- the owner, with no mail.
--
-- The token is never stored: `token_digest` is HMAC-SHA256 under a subkey of
-- GRUND_SECRET_KEY, so a row is useless without the instance key and a link
-- works only where it was minted. Minting deletes every unused row first, so
-- at most one link is live. A used row is kept, with the account it made, as
-- the record of how the instance got its owner.
--
-- A plain table, not an event stream: the account's own `Registered` event
-- (method `setup_link`) is the history. No tenant column: a setup link is the
-- instance's, before any organisation exists.

CREATE TABLE grund_setup_links (
    token_digest BYTEA       PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    account_id   UUID,
    CHECK (expires_at > created_at),
    CHECK ((used_at IS NULL) = (account_id IS NULL))
);
