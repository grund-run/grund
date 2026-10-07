-- 0022_cli.sql: what the grund CLI needs (grund-docs design/cli.md §2,
-- design/auth.md §6).
--
-- 1. A token's scope. Every token made before this is 'deploy', the set CI
--    had; 'full' is chosen when a token is made, never by default.
-- 2. A session's kind. 'cli' sessions come from `grund login` and are
--    presented as `Authorization: Bearer grund_cli_…`; 'browser' sessions
--    only as the dashboard's cookie. Each is refused the other way.
-- 3. Device logins: `grund login` asks for one, a signed-in person approves
--    it in the browser, and the CLI's next poll turns it into a 'cli'
--    session, once. Only the device code's SHA-256 is stored; the session's
--    secret is made at that poll and never stored. Expiry is enforced on
--    every read; the sweeper only reclaims space.

ALTER TABLE grund_api_tokens
    ADD COLUMN scope TEXT NOT NULL DEFAULT 'deploy' CHECK (scope IN ('deploy', 'full'));

ALTER TABLE grund_sessions
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'browser' CHECK (kind IN ('browser', 'cli'));

CREATE TABLE grund_device_logins (
    login_id           UUID        PRIMARY KEY,
    device_code_digest BYTEA       NOT NULL CHECK (octet_length(device_code_digest) = 32),
    user_code          TEXT        NOT NULL COLLATE "C" CHECK (user_code ~ '^[BCDFGHJKLMNPQRSTVWXZ]{8}$'),
    client             TEXT        NOT NULL CHECK (char_length(client) BETWEEN 1 AND 100),
    host               TEXT        NOT NULL CHECK (char_length(host) BETWEEN 1 AND 100),
    client_address     TEXT        NOT NULL DEFAULT '' CHECK (char_length(client_address) <= 64),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at         TIMESTAMPTZ NOT NULL,
    approved_by        UUID,
    approved_at        TIMESTAMPTZ,
    denied_at          TIMESTAMPTZ,
    used_at            TIMESTAMPTZ,
    session_id         UUID,
    last_polled_at     TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CHECK (approved_at IS NULL OR denied_at IS NULL),
    CHECK (used_at IS NULL OR approved_at IS NOT NULL)
);
CREATE UNIQUE INDEX grund_device_logins_digest_idx ON grund_device_logins (device_code_digest);
CREATE UNIQUE INDEX grund_device_logins_user_code_idx ON grund_device_logins (user_code)
    WHERE used_at IS NULL AND denied_at IS NULL;
CREATE INDEX grund_device_logins_expiry_idx ON grund_device_logins (expires_at);
