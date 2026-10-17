-- Organisation app-domain namespaces (grund-docs website/design/app-domains.md):
-- generated hostnames retain their parent and managed-app provenance after
-- unbinding or removal, so explicit allocation opt-outs survive future defaults.
-- Hierarchy decisions serialize in the service; these constraints remain the
-- final boundary for one enabled parent and one live assignment per app/parent.
-- The existing global claimed-name index and projection subscription stay intact;
-- existing rows are ordinary custom domains and need no historical replay.

ALTER TABLE grund_domains
    ADD COLUMN is_app_domain BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN parent_domain_id UUID,
    ADD COLUMN parent_domain TEXT COLLATE "C",
    ADD COLUMN managed_app_id UUID,
    ADD COLUMN assignment_disabled BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT grund_domains_provenance_check CHECK (
        (parent_domain_id IS NULL AND parent_domain IS NULL AND managed_app_id IS NULL)
        OR (parent_domain_id IS NOT NULL AND parent_domain IS NOT NULL AND managed_app_id IS NOT NULL)
    ),
    ADD CONSTRAINT grund_domains_parent_role_check CHECK (
        NOT is_app_domain OR (parent_domain_id IS NULL AND verified_at IS NOT NULL)
    ),
    ADD CONSTRAINT grund_domains_generated_name_check CHECK (
        parent_domain_id IS NULL OR (
            parent_domain_id <> domain_id
            AND parent_domain ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'
            AND right(name, length(parent_domain) + 1) = '.' || parent_domain
            AND left(name, length(name) - length(parent_domain) - 1)
                ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
        )
    ),
    ADD CONSTRAINT grund_domains_managed_binding_check CHECK (
        managed_app_id IS NULL OR state <> 'bound' OR app_id = managed_app_id
    ),
    ADD CONSTRAINT grund_domains_allocation_preference_check CHECK (
        NOT assignment_disabled OR managed_app_id IS NOT NULL
    );

CREATE UNIQUE INDEX grund_domains_app_domain_idx
    ON grund_domains (organisation_id)
    WHERE is_app_domain AND state <> 'removed';
CREATE UNIQUE INDEX grund_domains_managed_assignment_idx
    ON grund_domains (organisation_id, parent_domain_id, managed_app_id)
    WHERE parent_domain_id IS NOT NULL AND state <> 'removed';
CREATE INDEX grund_domains_managed_history_idx
    ON grund_domains (organisation_id, managed_app_id, added_at DESC, domain_id DESC)
    WHERE managed_app_id IS NOT NULL;
