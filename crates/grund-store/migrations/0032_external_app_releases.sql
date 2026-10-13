-- External forest releases need one durable app owner and a replay receipt, co-committed
-- with the grund-app ReleaseCreated event (grund-docs design/forest.md §3).
-- Mire owns es_*; these are its rebuildable app release projections. A token's
-- nullable app list preserves the rights of tokens made before app scoping.
ALTER TABLE grund_api_tokens ADD COLUMN apps TEXT[];
ALTER TABLE grund_api_tokens ADD CONSTRAINT grund_api_tokens_apps_check
    CHECK (apps IS NULL OR (cardinality(apps) BETWEEN 1 AND 64 AND array_position(apps, NULL) IS NULL));

CREATE TABLE grund_app_external_owners (
    organisation_id UUID NOT NULL,
    app_id UUID NOT NULL,
    forest_organisation TEXT COLLATE "C" NOT NULL,
    destination TEXT COLLATE "C" NOT NULL,
    project TEXT COLLATE "C" NOT NULL,
    stream_version BIGINT NOT NULL,
    PRIMARY KEY (organisation_id, app_id),
    CHECK (char_length(forest_organisation) BETWEEN 1 AND 128),
    CHECK (char_length(destination) BETWEEN 1 AND 128),
    CHECK (char_length(project) BETWEEN 1 AND 128)
);

CREATE TABLE grund_app_external_releases (
    organisation_id UUID NOT NULL,
    forest_organisation TEXT COLLATE "C" NOT NULL,
    destination TEXT COLLATE "C" NOT NULL,
    intent_id UUID NOT NULL,
    app_name TEXT COLLATE "C" NOT NULL,
    app_id UUID NOT NULL,
    artifact_id UUID NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    release_number INTEGER NOT NULL CHECK (release_number > 0),
    stream_version BIGINT NOT NULL,
    PRIMARY KEY (organisation_id, forest_organisation, destination, intent_id, app_name),
    FOREIGN KEY (organisation_id, app_id) REFERENCES grund_app_external_owners (organisation_id, app_id),
    CHECK (char_length(forest_organisation) BETWEEN 1 AND 128),
    CHECK (char_length(destination) BETWEEN 1 AND 128),
    CHECK (char_length(app_name) BETWEEN 1 AND 32)
);
