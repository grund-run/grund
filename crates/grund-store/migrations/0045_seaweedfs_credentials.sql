-- SeaweedFS replaces the disabled MinIO catalogue entry and uses the same
-- generated-credential provenance and audited disclosure as PostgreSQL/Redis.
ALTER TABLE grund_template_credentials
    DROP CONSTRAINT grund_template_credentials_template_check;
ALTER TABLE grund_template_credentials
    ADD CONSTRAINT grund_template_credentials_template_check
    CHECK (template IN ('postgres', 'redis', 'seaweedfs'));
