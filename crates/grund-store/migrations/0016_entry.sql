-- The traffic path (grund-docs design/traffic.md §6, §7, §17 items 1-3, 5):
-- edges enrolled like relays, draining copies the gate reports idle,
-- suspended apps, and the entry bytes each edge meters.

-- `grund edge` enrolls exactly as `grund relay` does (0014): a one-time
-- token minted for one host, then its own Ed25519 key, which is also its
-- iroh key and so the entry key machines accept streams from. One table for
-- both, told apart by role; one active terminator per role and host.
ALTER TABLE grund_relays
    ADD COLUMN role TEXT NOT NULL DEFAULT 'relay' CHECK (role IN ('relay', 'edge'));
DROP INDEX grund_relays_host_idx;
CREATE UNIQUE INDEX grund_relays_host_idx ON grund_relays (role, host) WHERE state = 'active';

ALTER TABLE grund_relay_tokens
    ADD COLUMN role TEXT NOT NULL DEFAULT 'relay' CHECK (role IN ('relay', 'edge'));

-- A draining replica with nothing in flight through its machine's gate: the
-- reconciler may stop it before its drain ends (apps.md §12.3).
ALTER TABLE grund_replica_status
    ADD COLUMN idle BOOLEAN NOT NULL DEFAULT false;

-- An app the operator suspended (app-domains.md §5): its address is
-- answered with a fixed 451 page at the edge, and no stream is opened. Its
-- copies and data are untouched. Not an event of the app's stream: the
-- operator's decision about the instance, not the customer's about the app.
CREATE TABLE grund_app_suspensions (
    app_id       UUID        PRIMARY KEY,
    reason       TEXT        NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 500),
    suspended_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Entry bytes per address, path and UTC day, as edges report them
-- (traffic.md §6.4: relayed entry bytes count against the relay
-- allowance). Each report is counted once, by its id.
CREATE TABLE grund_entry_usage (
    day         DATE        NOT NULL,
    name        TEXT COLLATE "C" NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 253),
    path        TEXT        NOT NULL CHECK (path IN ('direct', 'relay')),
    bytes_in    BIGINT      NOT NULL DEFAULT 0 CHECK (bytes_in >= 0),
    bytes_out   BIGINT      NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
    connections BIGINT      NOT NULL DEFAULT 0 CHECK (connections >= 0),
    PRIMARY KEY (day, name, path)
);

CREATE TABLE grund_entry_usage_reports (
    report_id   UUID        PRIMARY KEY,
    edge_id     UUID        NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX grund_entry_usage_reports_received_idx ON grund_entry_usage_reports (received_at);
