-- Machine lifecycle changes and one hourly own-machine count are sent through
-- the existing durable outbox. Without billing configured neither is queued.
ALTER TABLE grund_outbox DROP CONSTRAINT grund_outbox_kind_check;
ALTER TABLE grund_outbox ADD CONSTRAINT grund_outbox_kind_check CHECK (kind IN (
    'mail.verify_email', 'mail.password_reset', 'mail.signup_existing',
    'auth.password_reset_requested', 'insights.account', 'mail.invitation',
    'billing.organisation', 'billing.machine_count', 'billing.machine_change'));
