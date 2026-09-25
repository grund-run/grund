-- 0005_organisation_lifecycle.sql: renaming and deleting organisations
-- (grund-docs design/organisations.md), and telling a billing service about
-- them (design/billing.md).

-- A slug an organisation used before a rename. It stays taken, so old links
-- (and later application hostnames) never reach another organisation, and
-- members are redirected from it to the current slug.
CREATE TABLE grund_organisation_aliases (
    slug            TEXT COLLATE "C" PRIMARY KEY
                    CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(slug) BETWEEN 3 AND 32),
    organisation_id UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX grund_organisation_aliases_organisation_idx ON grund_organisation_aliases (organisation_id);

-- A deleted organisation keeps its row, and with it its slug: nobody else
-- can take the name. It has no members, so nothing reaches it.
ALTER TABLE grund_organisations ADD COLUMN deleted_at TIMESTAMPTZ;

-- A deletion waiting on billing (the organisation-deletion saga), and the
-- reason the last one did not happen, for the settings page.
ALTER TABLE grund_organisations ADD COLUMN deletion_requested_at TIMESTAMPTZ;
ALTER TABLE grund_organisations ADD COLUMN deletion_request_id UUID;
ALTER TABLE grund_organisations ADD COLUMN deletion_refusal TEXT
    CHECK (char_length(deletion_refusal) <= 500);

ALTER TABLE grund_outbox DROP CONSTRAINT grund_outbox_kind_check;
ALTER TABLE grund_outbox ADD CONSTRAINT grund_outbox_kind_check CHECK (kind IN (
    'mail.verify_email', 'mail.password_reset', 'mail.signup_existing',
    'auth.password_reset_requested', 'insights.account', 'mail.invitation',
    'billing.organisation'));
