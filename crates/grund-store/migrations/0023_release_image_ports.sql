-- Image ports belong to the immutable release's resolved image. NULL marks an
-- older release awaiting a one-time registry inspection outside the GET path;
-- [] records a verified image that declares no TCP ports.
ALTER TABLE grund_releases ADD COLUMN exposed_ports JSONB
    CHECK (exposed_ports IS NULL OR jsonb_typeof(exposed_ports) = 'array');
