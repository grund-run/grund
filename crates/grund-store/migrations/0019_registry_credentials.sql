-- Registry credentials (grund-docs design/apps.md §6.5): an organisation's
-- login to a private image registry, one per registry host. grund uses it
-- to resolve a tag to a digest when a release is made, and hands it to the
-- agent of a machine that pulls an image of one of the organisation's
-- replicas placed on it, from that host.
--
-- The password (or registry token) is sealed with AES-256-GCM under a
-- subkey of GRUND_SECRET_KEY, bound to the organisation, the host, the
-- username and the version, so a row copied to another organisation or
-- host does not open. The username is not secret and is shown on the
-- dashboard. Setting a host's credential again replaces it and bumps its
-- version.
--
-- A plain table, not an event stream: a credential is a secret, and
-- secrets never enter the event log (apps.md §10.1). Removing a row
-- removes the credential for good.

CREATE TABLE grund_registry_credentials (
    organisation_id UUID        NOT NULL,
    host            TEXT COLLATE "C" NOT NULL
                    CHECK (host ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$'
                           AND char_length(host) <= 261),
    username        TEXT        NOT NULL CHECK (char_length(username) BETWEEN 1 AND 256),
    sealed_password BYTEA       NOT NULL CHECK (octet_length(sealed_password) BETWEEN 29 AND 8220),
    version         INTEGER     NOT NULL CHECK (version > 0),
    updated_by      UUID        NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organisation_id, host)
);
