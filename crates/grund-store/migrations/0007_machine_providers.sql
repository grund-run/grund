-- 0007_machine_providers.sql: the capacity provider's id for a machine grund
-- asked a provider for (grund-docs design/machines.md; the contract is
-- proto/grund/capacity/v1). A token minted for a provisioning call records
-- the id the provider answered; the machine that registers with it carries
-- it from then on. Both come from grund's own call, never from the machine.
ALTER TABLE grund_machine_tokens ADD COLUMN provider_machine_id TEXT
    CHECK (provider_machine_id IS NULL OR octet_length(provider_machine_id) BETWEEN 1 AND 200);
ALTER TABLE grund_machines ADD COLUMN provider_machine_id TEXT
    CHECK (provider_machine_id IS NULL OR octet_length(provider_machine_id) BETWEEN 1 AND 200);
