-- 0002_social_flows.sql: social sign-in flows (docs/design/auth.md §5).
--
-- One row per attempt, found by the SHA-256 of the random token in the
-- browser's grund_oauth cookie. A row moves forward through its stages by
-- conditional updates only, each of which also checks expiry, so a flow is
-- single-use and a replayed callback or form finds nothing to act on.
--
--   authorizing      waiting for the provider's callback (state, PKCE, nonce)
--   choose_username  a verified identity with no account: pick a username
--   link             a verified identity whose address has an account: prove
--                    ownership with that account's password
--   done             used
--
-- The PKCE verifier and nonce are held for at most ten minutes and are only
-- useful with a code the provider issues to this client. The identity's
-- subject and address sit here until the flow completes or expires.

CREATE TABLE grund_social_flows (
    flow_digest    BYTEA       PRIMARY KEY CHECK (octet_length(flow_digest) = 32),
    provider       TEXT        NOT NULL CHECK (provider IN ('github', 'google', 'oidc')),
    stage          TEXT        NOT NULL CHECK (stage IN ('authorizing', 'choose_username', 'link', 'done')),
    state          TEXT        NOT NULL CHECK (char_length(state) BETWEEN 32 AND 64),
    pkce_verifier  TEXT        NOT NULL CHECK (char_length(pkce_verifier) BETWEEN 43 AND 128),
    nonce          TEXT        NOT NULL CHECK (char_length(nonce) BETWEEN 32 AND 64),
    subject        TEXT        CHECK (char_length(subject) BETWEEN 1 AND 255),
    email          TEXT        CHECK (octet_length(email) BETWEEN 3 AND 254),
    suggested_name TEXT        CHECK (char_length(suggested_name) <= 64),
    account_id     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at     TIMESTAMPTZ NOT NULL,
    CHECK ((stage IN ('authorizing', 'done')) OR (subject IS NOT NULL AND email IS NOT NULL)),
    CHECK ((stage <> 'link') OR account_id IS NOT NULL)
);
CREATE INDEX grund_social_flows_expiry_idx ON grund_social_flows (expires_at);
