-- Persistent, conservative same-database bandwidth admission. No expiry:
-- unknown workers must not silently release capacity. No cascade from a
-- deleted mapping; deleting desired metadata is not proof of process exit.
CREATE TABLE bandwidth_reservations (
    id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    mapping_id TEXT NOT NULL,
    mapping_revision INTEGER NOT NULL CHECK(mapping_revision>=1),
    request_id TEXT,
    rate_bytes_per_second INTEGER CHECK(rate_bytes_per_second BETWEEN 1 AND 125000000),
    created_at INTEGER NOT NULL DEFAULT(unixepoch())
) STRICT;
CREATE INDEX bandwidth_reservations_tenant ON bandwidth_reservations(tenant_id);
