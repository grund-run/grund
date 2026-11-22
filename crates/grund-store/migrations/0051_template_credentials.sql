-- Persistent messaging and analytics templates use the same encrypted,
-- version-pinned credential provenance as the existing data templates.
ALTER TABLE grund_template_credentials
    DROP CONSTRAINT grund_template_credentials_template_check;
ALTER TABLE grund_template_credentials
    ADD CONSTRAINT grund_template_credentials_template_check
    CHECK (template IN ('postgres', 'redis', 'seaweedfs', 'nats', 'clickhouse'));
