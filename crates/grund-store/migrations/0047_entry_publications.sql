CREATE TABLE grund_entry_publications (
    singleton     BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    rules_version INTEGER NOT NULL,
    app_domain    TEXT
);
