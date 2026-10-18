-- Explicit app image discovery (grund-docs design/updates.md section 4).
-- This tenant-scoped cache is disposable; immutable ReleaseCreated payloads,
-- not a receipt table or Forest ownership, retain apply request identity.
CREATE TABLE grund_app_update_checks (
    organisation_id UUID NOT NULL,
    app_id UUID NOT NULL REFERENCES grund_apps(app_id) ON DELETE CASCADE,
    base_release INTEGER NOT NULL CHECK (base_release > 0),
    base_digest TEXT COLLATE "C" NOT NULL CHECK (base_digest ~ '^sha256:[0-9a-f]{64}$'),
    checked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    observation JSONB NOT NULL CHECK (
        jsonb_typeof(observation) = 'object'
        AND observation->>'state' IN ('current', 'available', 'pinned', 'error')
        AND observation ?& ARRAY['state', 'candidates', 'reason', 'base_release', 'current_digest', 'current_image', 'checked_at']
        AND jsonb_typeof(observation->'candidates') = 'array'
        AND jsonb_array_length(observation->'candidates') <= 8
        AND octet_length(observation::text) <= 32768
        AND observation->>'reason' IN ('current', 'update_available', 'image_pinned', 'image_unresolved')
    ),
    PRIMARY KEY (organisation_id, app_id)
);
