-- Placement on machines (grund-docs design/apps.md §5.6, §5.7): the labels
-- a machine's owner gives it, and whether it is out of service (cordoned).
-- Both are set by the organisation whose pool the machine is in, as the
-- machine stream's labels_set, cordoned and uncordoned events, and cleared
-- when a lease ends, so the next lessee inherits neither.
-- labels is a JSON object of key to value, at most 16; cordoned_at is NULL
-- while the machine is in service.
ALTER TABLE grund_machines
    ADD COLUMN labels JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(labels) = 'object'),
    ADD COLUMN cordoned_at TIMESTAMPTZ;
