-- Recovery records retain the exact released reservation, including NULL
-- uncapped budget. No foreign-key cascade or operator-provided free text.
CREATE TABLE bandwidth_recovery_audit (
    reservation_id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL,
    mapping_id TEXT NOT NULL,
    mapping_revision INTEGER NOT NULL,
    request_id TEXT,
    rate_bytes_per_second INTEGER,
    reserved_at INTEGER NOT NULL,
    recovered_at INTEGER NOT NULL DEFAULT(unixepoch()),
    confirmation TEXT NOT NULL CHECK(confirmation='offline_all_tunnels_stopped')
) STRICT;
