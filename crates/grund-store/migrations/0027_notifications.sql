-- Per-account notifications project committed invitation, organisation and operator facts
-- (grund-docs/design/notifications.md, sections 1 and 2). The source ledger keeps
-- collapse idempotent while rows are retained; no invitation token or event payload
-- is copied into this read model. Mire continues to own es_*.
CREATE TABLE grund_notifications (
    account_id       UUID        NOT NULL,
    id               UUID        NOT NULL,
    organisation_id  UUID,
    source_kind      TEXT COLLATE "C" NOT NULL,
    source_id        UUID        NOT NULL,
    kind             TEXT COLLATE "C" NOT NULL CHECK (kind IN (
        'invitation.received', 'release.failed', 'release.rolled_back',
        'machine.out_of_service', 'machine.disconnected',
        'domain.certificate_issued', 'domain.certificate_failing',
        'hosted_machine.ready', 'hosted_machine.failed',
        'operator.host_unreachable', 'operator.migration_timeout',
        'operator.migration_failed', 'operator.lease_failed')),
    resource_name    TEXT        NOT NULL CHECK (char_length(resource_name) BETWEEN 1 AND 253),
    href             TEXT        NOT NULL CHECK (
        char_length(href) BETWEEN 1 AND 512 AND left(href, 1) = '/'
        AND left(href, 2) <> '//' AND position('?' in href) = 0
        AND position('#' in href) = 0 AND position(chr(92) in href) = 0
        AND href !~ '[[:space:]]'),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    read_at          TIMESTAMPTZ,
    repeat_count     INTEGER     NOT NULL DEFAULT 1 CHECK (repeat_count BETWEEN 1 AND 2147483647),
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, source_kind, source_id)
);
CREATE INDEX grund_notifications_order_idx
    ON grund_notifications (account_id, created_at DESC, id DESC);
CREATE INDEX grund_notifications_unread_idx
    ON grund_notifications (account_id, created_at DESC, id DESC)
    WHERE read_at IS NULL;
CREATE INDEX grund_notifications_expiry_idx ON grund_notifications (created_at, account_id, id);

-- Source keys remain after a visible row is removed by the 1,000-item cap.
-- Their own 90-day retention and 10,000-key account cap bound replay
-- idempotence without letting repeated operator events grow storage forever.
CREATE TABLE grund_notification_sources (
    account_id       UUID        NOT NULL,
    source_kind      TEXT COLLATE "C" NOT NULL,
    source_id        UUID        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_id, source_kind, source_id)
);
CREATE INDEX grund_notification_sources_order_idx
    ON grund_notification_sources (account_id, created_at DESC, source_id DESC);
CREATE INDEX grund_notification_sources_expiry_idx
    ON grund_notification_sources (created_at, account_id, source_kind, source_id);

-- Verification-time fanout and dashboard pending-invitation reads both find
-- an invitation sent before the account verified its address through this index.
CREATE INDEX grund_invitations_address_pending_idx
    ON grund_invitations (email_normalized, expires_at, invitation_id)
    WHERE accepted_at IS NULL AND withdrawn_at IS NULL;
