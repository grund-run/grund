-- Operator ownership interventions need durable history alongside membership.
-- This append-only projection is rebuilt from grund-organisation events;
-- mire owns the authoritative es_* event log. Mail commits with the event.
CREATE TABLE grund_operator_ownership_audit (
    organisation_id       UUID        NOT NULL,
    stream_version        BIGINT      NOT NULL CHECK (stream_version >= 1),
    operator_organisation UUID        NOT NULL,
    actor                 UUID        NOT NULL,
    target                UUID        NOT NULL,
    old_role              TEXT        CHECK (old_role IN ('owner', 'admin', 'member')),
    new_role              TEXT        CHECK (new_role IN ('owner', 'admin', 'member')),
    reason                TEXT        NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 2000),
    occurred_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organisation_id, stream_version),
    CHECK (organisation_id <> operator_organisation),
    CHECK (old_role IS DISTINCT FROM new_role),
    CHECK (old_role IS NOT DISTINCT FROM 'owner' OR new_role IS NOT DISTINCT FROM 'owner')
);

ALTER TABLE grund_outbox DROP CONSTRAINT grund_outbox_kind_check;
ALTER TABLE grund_outbox ADD CONSTRAINT grund_outbox_kind_check CHECK (kind IN (
    'mail.verify_email', 'mail.password_reset', 'mail.signup_existing',
    'auth.password_reset_requested', 'insights.account', 'mail.invitation',
    'mail.ownership_changed',
    'billing.organisation', 'billing.machine_count', 'billing.machine_change'));
