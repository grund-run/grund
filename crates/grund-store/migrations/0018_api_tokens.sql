-- Personal access tokens for the Connect API (grund-docs design/auth.md §6):
-- how CI deploys without a dashboard session.
--
-- A token is `grund_pat_` plus 32 random bytes in base62. Only its SHA-256
-- is stored, so a copy of this table holds nothing a caller can present.
-- Each token is scoped to one organisation and acts as the account that
-- made it, with that account's role in the organisation at the time of each
-- call: leaving the organisation, or losing the role, takes the token's
-- power with it. Expiry is enforced on every read; the sweeper only
-- reclaims rows a day after they ended.
--
-- A plain table, not an event stream, for the reason sessions are one
-- (auth.md §1): only current state matters, and rows are deleted.

CREATE TABLE grund_api_tokens (
    organisation_id UUID        NOT NULL,
    token_id        UUID        NOT NULL,
    token_digest    BYTEA       NOT NULL CHECK (octet_length(token_digest) = 32),
    account_id      UUID        NOT NULL,
    name            TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    PRIMARY KEY (organisation_id, token_id),
    CHECK (expires_at > created_at)
);
CREATE UNIQUE INDEX grund_api_tokens_digest_idx ON grund_api_tokens (token_digest);
CREATE INDEX grund_api_tokens_live_idx ON grund_api_tokens (organisation_id, created_at)
    WHERE revoked_at IS NULL;
CREATE INDEX grund_api_tokens_expiry_idx ON grund_api_tokens (expires_at);
