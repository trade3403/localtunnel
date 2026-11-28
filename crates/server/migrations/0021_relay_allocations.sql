-- A reservation is desired metadata, NEVER a data-plane authorization.
CREATE TABLE relay_allocations (
    id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32),
    owner_id TEXT NOT NULL REFERENCES users(id),
    request_key TEXT NOT NULL CHECK(length(request_key)=32),
    request_digest BLOB NOT NULL CHECK(length(request_digest)=32),
    mapping_id TEXT NOT NULL UNIQUE,
    live_mapping_id TEXT UNIQUE REFERENCES mappings(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    mapping_revision INTEGER NOT NULL CHECK(mapping_revision>=1),
    generation INTEGER NOT NULL CHECK(generation>=1),
    node_generation INTEGER NOT NULL CHECK(node_generation>=1),
    bind_port INTEGER NOT NULL CHECK(bind_port BETWEEN 20000 AND 29999),
    state TEXT NOT NULL CHECK(state IN ('reserved','cancelled')),
    created_at INTEGER NOT NULL DEFAULT(unixepoch()),
    UNIQUE(owner_id,request_key),
    CHECK((state='reserved' AND live_mapping_id IS NOT NULL AND live_mapping_id=mapping_id) OR (state='cancelled' AND live_mapping_id IS NULL))
) STRICT;
CREATE UNIQUE INDEX relay_allocations_port ON relay_allocations(node_id,bind_port) WHERE state='reserved';
-- Fail closed even if a future legacy caller forgets the HTTP gate.
CREATE TRIGGER relay_allocation_no_legacy_runtime BEFORE INSERT ON runtime_requests
WHEN EXISTS(SELECT 1 FROM relay_allocations WHERE live_mapping_id=NEW.mapping_id)
BEGIN SELECT RAISE(ABORT,'scheduled mapping cannot use legacy runtime'); END;
CREATE TRIGGER relay_allocation_no_legacy_update BEFORE UPDATE ON mappings
WHEN EXISTS(SELECT 1 FROM relay_allocations WHERE live_mapping_id=OLD.id)
BEGIN SELECT RAISE(ABORT,'scheduled mapping is immutable'); END;
CREATE TRIGGER relay_allocation_validate BEFORE INSERT ON relay_allocations
WHEN NEW.state<>'reserved' OR NOT EXISTS(SELECT 1 FROM mappings m WHERE m.id=NEW.live_mapping_id AND m.owner_id=NEW.owner_id AND m.node_id=NEW.node_id AND m.bind_port=NEW.bind_port AND m.revision=NEW.mapping_revision AND m.enabled=0)
BEGIN SELECT RAISE(ABORT,'invalid scheduled mapping binding'); END;
