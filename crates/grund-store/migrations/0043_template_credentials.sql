-- Template credentials alone are readable by an authorised owner/admin action.
-- Pin provenance to the generated version so replacing it keeps user input write-only.
-- Reveal audit contains identity and time, never credential material.
CREATE TABLE grund_template_credentials (
    organisation_id UUID NOT NULL,
    app_id UUID NOT NULL,
    name TEXT COLLATE "C" NOT NULL,
    version INTEGER NOT NULL,
    template TEXT COLLATE "C" NOT NULL CHECK (template IN ('postgres', 'redis')),
    PRIMARY KEY (organisation_id, app_id, name, version),
    FOREIGN KEY (app_id, name, version) REFERENCES grund_app_secrets (app_id, name, version) ON DELETE CASCADE
);
CREATE TABLE grund_template_credential_reveals (
    organisation_id UUID NOT NULL,
    reveal_id UUID NOT NULL,
    app_id UUID NOT NULL,
    actor UUID NOT NULL,
    name TEXT COLLATE "C" NOT NULL,
    version INTEGER NOT NULL,
    revealed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organisation_id, reveal_id)
);
CREATE INDEX grund_template_credential_reveals_rate_idx
    ON grund_template_credential_reveals (organisation_id, actor, revealed_at DESC);
