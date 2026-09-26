-- 0008_agents.sql: the control link's state (grund-docs design/machines.md
-- §7b): what each machine's agent last said, the VMs an organisation runs on
-- its own devices, and each machine's newest signed desired state.

-- What the agent said last. A heartbeat every few seconds is not history, so
-- it is a plain row, overwritten.
CREATE TABLE grund_machine_presence (
    machine_id         UUID        PRIMARY KEY,
    last_seen_at       TIMESTAMPTZ NOT NULL,
    agent_version      TEXT        NOT NULL DEFAULT '' CHECK (octet_length(agent_version) <= 64),
    capabilities       JSONB       NOT NULL DEFAULT '{}',
    applied_generation BIGINT      NOT NULL DEFAULT 0 CHECK (applied_generation >= 0),
    refusals           JSONB       NOT NULL DEFAULT '[]',
    reported_at        TIMESTAMPTZ
);

-- VMs an organisation runs on one of its own machines. machine_id is the
-- machine the VM registered as, once it did.
CREATE TABLE grund_vms (
    vm_id           UUID        PRIMARY KEY,
    organisation_id UUID        NOT NULL,
    host_machine_id UUID        NOT NULL,
    name            TEXT COLLATE "C" NOT NULL,
    vcpus           INTEGER     NOT NULL CHECK (vcpus BETWEEN 1 AND 64),
    memory_mib      INTEGER     NOT NULL CHECK (memory_mib BETWEEN 128 AND 262144),
    disk_gib        INTEGER     NOT NULL CHECK (disk_gib BETWEEN 1 AND 4096),
    kernel_url      TEXT        NOT NULL,
    kernel_sha256   TEXT COLLATE "C" NOT NULL CHECK (kernel_sha256 ~ '^[0-9a-f]{64}$'),
    rootfs_url      TEXT        NOT NULL,
    rootfs_sha256   TEXT COLLATE "C" NOT NULL CHECK (rootfs_sha256 ~ '^[0-9a-f]{64}$'),
    state           TEXT        NOT NULL CHECK (state IN ('running', 'stopped')),
    observed_state  TEXT        CHECK (observed_state IN ('starting', 'running', 'stopped', 'exited', 'failed')),
    observed_reason TEXT        CHECK (octet_length(observed_reason) <= 500),
    machine_id      UUID,
    created_by      UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX grund_vms_name_idx ON grund_vms (organisation_id, name) WHERE state = 'running';
CREATE INDEX grund_vms_host_idx ON grund_vms (host_machine_id);

-- Each machine's newest desired state, as signed. The generation only grows;
-- 0 is the row a first change locks before it signs generation 1.
CREATE TABLE grund_machine_documents (
    machine_id UUID        PRIMARY KEY,
    generation BIGINT      NOT NULL CHECK (generation >= 0),
    key_id     UUID        NOT NULL,
    payload    BYTEA       NOT NULL CHECK (octet_length(payload) <= 1048576),
    signature  BYTEA       NOT NULL CHECK (octet_length(signature) = 64),
    issued_at  TIMESTAMPTZ NOT NULL
);

-- A join token minted for a VM: the machine that registers with it is that
-- VM.
ALTER TABLE grund_machine_tokens ADD COLUMN vm_id UUID;
