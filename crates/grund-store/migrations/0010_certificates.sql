-- Certificates the instance orders by ACME (grund-docs design/traffic.md §5,
-- "the certificates part"). The instance drives every order; the key is made
-- where TLS terminates and only a CSR travels. The first subject is the
-- instance's own domain, where the instance is also the terminator, so its
-- key is kept here, sealed with a subkey of GRUND_SECRET_KEY. Subjects whose
-- key lives elsewhere (the relay, a gate, the edge) are not built yet; they
-- will keep no key here at all.
--
-- These are plain tables, not an event stream: they are operational state
-- that a new order can always rebuild, and nothing downstream folds them.
-- There is no tenant: every row is the instance's own. Custom domains (M3)
-- will need an organisation leading their keys.

-- One ACME account per directory URL. `credentials` is instant-acme's
-- AccountCredentials JSON (the account key included), sealed.
CREATE TABLE grund_acme_accounts (
    directory   TEXT COLLATE "C" PRIMARY KEY CHECK (directory ~ '^https?://'),
    credentials BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- What should be served, what is, and when to act next. One replica acts at
-- a time: it claims the row with SKIP LOCKED and holds `leased_until`, and
-- writes back only while `leased_by` is still its own. Every replica reads
-- `version` to notice a new chain.
CREATE TABLE grund_certificates (
    subject         TEXT COLLATE "C" PRIMARY KEY CHECK (subject ~ '^[a-z][a-z0-9:._-]{0,127}$'),
    names           TEXT[]      NOT NULL CHECK (cardinality(names) BETWEEN 1 AND 100),
    directory       TEXT COLLATE "C" NOT NULL,
    profile         TEXT        NOT NULL CHECK (char_length(profile) BETWEEN 1 AND 64),
    challenge       TEXT        NOT NULL CHECK (challenge IN ('tls-alpn-01', 'http-01')),
    chain_pem       TEXT,
    sealed_key      BYTEA,
    not_before      TIMESTAMPTZ,
    not_after       TIMESTAMPTZ,
    -- When the next order starts: a point in the CA's ARI window, or two
    -- thirds of the lifetime when the CA offers no ARI.
    renew_at        TIMESTAMPTZ,
    -- When to ask the CA's ARI again (its Retry-After); NULL without ARI.
    ari_check_at    TIMESTAMPTZ,
    version         BIGINT      NOT NULL DEFAULT 0 CHECK (version >= 0),
    attempts        INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    leased_by       UUID,
    leased_until    TIMESTAMPTZ,
    -- A stable code, never the CA's text (that goes to the log).
    last_error      TEXT CHECK (char_length(last_error) <= 64),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((chain_pem IS NULL) = (version = 0)),
    CHECK ((chain_pem IS NULL) = (not_after IS NULL)),
    CHECK ((leased_by IS NULL) = (leased_until IS NULL))
);

-- Every order placed, so an order interrupted by a crash or a lost lease is
-- resumed by URL instead of placed again (Let's Encrypt allows 300 new orders
-- per account per 3 hours), and so what was ordered can be counted. The key
-- behind the order's CSR is kept sealed until the order ends, then dropped.
CREATE TABLE grund_acme_orders (
    order_id    UUID        PRIMARY KEY,
    subject     TEXT COLLATE "C" NOT NULL REFERENCES grund_certificates (subject) ON DELETE CASCADE,
    url         TEXT        NOT NULL CHECK (url ~ '^https?://'),
    sealed_key  BYTEA,
    status      TEXT        NOT NULL CHECK (status IN ('pending', 'valid', 'invalid', 'abandoned')),
    error       TEXT CHECK (char_length(error) <= 64),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    finished_at TIMESTAMPTZ,
    CHECK ((status = 'pending') = (finished_at IS NULL)),
    CHECK (status = 'pending' OR sealed_key IS NULL)
);
CREATE UNIQUE INDEX grund_acme_orders_pending_idx ON grund_acme_orders (subject) WHERE status = 'pending';
CREATE INDEX grund_acme_orders_subject_idx ON grund_acme_orders (subject, created_at);

-- Challenges waiting for a validator. The validator may reach any replica, so
-- each one answers from here. A key authorization is public by design (the
-- validator fetches it from anyone who asks), so it is stored as is.
CREATE TABLE grund_acme_challenges (
    kind              TEXT        NOT NULL CHECK (kind IN ('tls-alpn-01', 'http-01')),
    name              TEXT COLLATE "C" NOT NULL CHECK (char_length(name) BETWEEN 1 AND 253),
    token             TEXT COLLATE "C" NOT NULL CHECK (token ~ '^[A-Za-z0-9_-]{1,128}$'),
    key_authorization TEXT        NOT NULL CHECK (char_length(key_authorization) <= 256),
    expires_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (kind, name, token)
);
CREATE INDEX grund_acme_challenges_token_idx ON grund_acme_challenges (token) WHERE kind = 'http-01';
