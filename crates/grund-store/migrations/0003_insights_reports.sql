-- A new outbox kind: an account reported to grund insights once its address
-- is confirmed. Only queued when the instance is configured to report
-- (GRUND_INSIGHTS_URL and GRUND_INSIGHTS_TOKEN); an instance without them
-- never writes such a row. The address travels in `recipient` and the rest
-- in `payload`, and both are scrubbed on delivery like mail.

ALTER TABLE grund_outbox DROP CONSTRAINT grund_outbox_kind_check;
ALTER TABLE grund_outbox ADD CONSTRAINT grund_outbox_kind_check CHECK (kind IN (
    'mail.verify_email', 'mail.password_reset', 'mail.signup_existing',
    'auth.password_reset_requested', 'insights.account'));
