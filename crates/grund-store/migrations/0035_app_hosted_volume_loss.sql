-- Keep owner-visible app loss history in the version-guarded grund-app read
-- model, rebuilt from the HostedVolumeLost aggregate event (storage design §9).
ALTER TABLE grund_apps ADD COLUMN lost_volumes JSONB NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(lost_volumes) = 'array');
