-- Custom domains (grund-docs website/design/app-domains.md §3,
-- design/traffic.md §5.3): a name an organisation adds, proves with a TXT
-- record at _grund.<name> holding the token grund generated, and binds to
-- one of its apps. Event-sourced (stream category grund-custom-domain);
-- this is the read model, written in the transaction that records each
-- event and guarded by stream_version.
--
-- Who holds a name is decided here, by grund_domains_claimed_idx: one
-- verified (or bound) row per name across every organisation. Two
-- organisations verifying the same name at once cannot both commit.
--
-- A removed row stays, with removed_at: a name that was verified and is
-- removed cools down (GRUND_DOMAIN_COOLDOWN, 7 days by default) before
-- another organisation can verify it; the organisation that released it
-- may take it back at once.

CREATE TABLE grund_domains (
    domain_id       UUID        PRIMARY KEY,
    organisation_id UUID        NOT NULL,
    name            TEXT COLLATE "C" NOT NULL
                    CHECK (name ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'),
    token           TEXT COLLATE "C" NOT NULL CHECK (token ~ '^grund-verify-[A-Za-z0-9]{43}$'),
    state           TEXT        NOT NULL CHECK (state IN ('pending', 'verified', 'bound', 'removed')),
    app_id          UUID,
    added_by        UUID        NOT NULL,
    added_at        TIMESTAMPTZ NOT NULL,
    verified_at     TIMESTAMPTZ,
    bound_at        TIMESTAMPTZ,
    removed_at      TIMESTAMPTZ,
    -- Written by the verification check, not from events: when the TXT
    -- record was last looked for and, if it was not found, a stable code
    -- for why (no_record, wrong_value, lookup_failed).
    checked_at      TIMESTAMPTZ,
    check_error     TEXT CHECK (char_length(check_error) <= 64),
    stream_version  BIGINT      NOT NULL,
    CHECK ((state = 'bound') = (app_id IS NOT NULL)),
    CHECK ((state = 'removed') = (removed_at IS NOT NULL)),
    CHECK (state IN ('pending', 'removed') OR verified_at IS NOT NULL)
);
CREATE UNIQUE INDEX grund_domains_name_idx ON grund_domains (organisation_id, name) WHERE state <> 'removed';
CREATE UNIQUE INDEX grund_domains_claimed_idx ON grund_domains (name) WHERE state IN ('verified', 'bound');
CREATE INDEX grund_domains_released_idx ON grund_domains (name, removed_at) WHERE state = 'removed' AND verified_at IS NOT NULL;
CREATE INDEX grund_domains_app_idx ON grund_domains (app_id) WHERE state = 'bound';
CREATE INDEX grund_domains_added_idx ON grund_domains (organisation_id, added_at);

-- A custom domain's certificate is the organisation's (owner
-- organisation:<id>, already allowed by 0014) and its key is held here,
-- sealed, like the instance's own (terminator 'instance'): the edges that
-- serve the name are given the key, because every edge node must serve it
-- and one key per node would multiply orders (traffic.md §5.3). Its
-- subject is domain:<domain id>; it exists while the domain is bound.
