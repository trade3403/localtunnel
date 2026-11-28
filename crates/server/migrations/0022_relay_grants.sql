-- One initial, non-executable authorization preview per allocation.
-- Retain evidence and occupied resources even after expiry or revocation.
CREATE TABLE relay_grants (
    id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
    allocation_id TEXT NOT NULL UNIQUE REFERENCES relay_allocations(id),
    mapping_id TEXT NOT NULL REFERENCES mappings(id),
    mapping_revision INTEGER NOT NULL CHECK(mapping_revision>=1),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    node_generation INTEGER NOT NULL CHECK(node_generation>=1),
    generation INTEGER NOT NULL CHECK(generation>=2),
    policy_revision INTEGER NOT NULL CHECK(policy_revision>=1),
    device_revision INTEGER NOT NULL CHECK(device_revision>=1),
    entitlement_revision INTEGER NOT NULL CHECK(entitlement_revision>=1),
    issued_at INTEGER NOT NULL CHECK(issued_at>0),
    expires_at INTEGER NOT NULL CHECK(expires_at=issued_at+15),
    revoked_at INTEGER
) STRICT;
CREATE TRIGGER relay_grant_no_cancel BEFORE UPDATE OF state,live_mapping_id ON relay_allocations
WHEN EXISTS(SELECT 1 FROM relay_grants g WHERE g.allocation_id=OLD.id) AND
    (NEW.state<>OLD.state OR NEW.live_mapping_id IS NOT OLD.live_mapping_id)
BEGIN SELECT RAISE(ABORT,'granted allocation requires reconciliation'); END;
CREATE TRIGGER relay_grant_validate BEFORE INSERT ON relay_grants
WHEN NOT EXISTS(SELECT 1 FROM relay_allocations a WHERE a.id=NEW.allocation_id AND a.state='reserved'
    AND a.live_mapping_id=NEW.mapping_id AND a.mapping_revision=NEW.mapping_revision AND a.node_id=NEW.node_id
    AND a.node_generation=NEW.node_generation AND NEW.generation=a.generation+1)
BEGIN SELECT RAISE(ABORT,'invalid grant binding'); END;
