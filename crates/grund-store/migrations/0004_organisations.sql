-- 0004_organisations.sql: organisations people share (grund-docs
-- design/organisations.md): more than one member, invitations, and the
-- single-organisation mode of a self-hosted instance.

-- Kinds are provenance only: personal (made at sign-up), shared (made later),
-- instance (the one organisation of a single-organisation instance).
ALTER TABLE grund_organisations DROP CONSTRAINT grund_organisations_kind_check;
ALTER TABLE grund_organisations ADD CONSTRAINT grund_organisations_kind_check
    CHECK (kind IN ('personal', 'shared', 'instance'));

-- When the member joined. Null for memberships projected before this column.
ALTER TABLE grund_memberships ADD COLUMN joined_at TIMESTAMPTZ;

-- The one organisation of a single-organisation instance. The row can exist
-- only once, so of two racing first sign-ups exactly one commits.
CREATE TABLE grund_instance (
    singleton       BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    organisation_id UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Invitations by mail. The organisation stream decides (InvitationIssued,
-- InvitationWithdrawn, InvitationAccepted); this table holds what events do
-- not: the address and the link's SHA-256. Written in the same transaction
-- as the event.
CREATE TABLE grund_invitations (
    invitation_id    UUID        PRIMARY KEY,
    organisation_id  UUID        NOT NULL,
    token_digest     BYTEA       NOT NULL CHECK (octet_length(token_digest) = 32),
    email            TEXT        NOT NULL CHECK (octet_length(email) BETWEEN 3 AND 254),
    email_normalized TEXT COLLATE "C" NOT NULL CHECK (email_normalized = lower(email_normalized)),
    role             TEXT        NOT NULL CHECK (role IN ('admin', 'member')),
    invited_by       UUID        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at       TIMESTAMPTZ NOT NULL,
    accepted_at      TIMESTAMPTZ,
    withdrawn_at     TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);
CREATE UNIQUE INDEX grund_invitations_token_idx ON grund_invitations (token_digest);
CREATE INDEX grund_invitations_pending_idx ON grund_invitations (organisation_id, created_at)
    WHERE accepted_at IS NULL AND withdrawn_at IS NULL;

-- Which organisation `/` opens for an account: the one it used last.
CREATE TABLE grund_account_preferences (
    account_id           UUID        PRIMARY KEY,
    last_organisation_id UUID,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE grund_outbox DROP CONSTRAINT grund_outbox_kind_check;
ALTER TABLE grund_outbox ADD CONSTRAINT grund_outbox_kind_check CHECK (kind IN (
    'mail.verify_email', 'mail.password_reset', 'mail.signup_existing',
    'auth.password_reset_requested', 'insights.account', 'mail.invitation'));
