-- The ports a machine accepts from the other members of its private network
-- (grund-docs design/network.md §11.4): everything else is closed. Declared
-- by the organisation whose pool the machine is in, as the machine stream's
-- ports_declared event, and carried to every member in the signed
-- membership list. A JSON array of {"transport": "tcp"|"udp", "port": n},
-- sorted, at most 64; empty (the default) means nothing is open.
ALTER TABLE grund_machines
    ADD COLUMN network_ports JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(network_ports) = 'array');
