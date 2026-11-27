-- Explicit tenant opt-in and one-shot relay claim. No automatic release.
CREATE TABLE relay_tcp_intents (
    grant_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_grants(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    relay_port INTEGER NOT NULL CHECK(relay_port BETWEEN 30000 AND 59999),
    bind_port INTEGER NOT NULL CHECK(bind_port BETWEEN 20000 AND 29999),
    created_at INTEGER NOT NULL CHECK(created_at>0),
    claimed_at INTEGER CHECK(claimed_at>=created_at),
    UNIQUE(node_id,relay_port)
) STRICT;
CREATE TRIGGER relay_tcp_intent_validate BEFORE INSERT ON relay_tcp_intents
WHEN NEW.claimed_at IS NOT NULL OR NOT EXISTS(
    SELECT 1 FROM relay_grants g JOIN relay_allocations a ON a.id=g.allocation_id
    JOIN mappings m ON m.id=g.mapping_id
    WHERE g.id=NEW.grant_id AND g.node_id=NEW.node_id AND a.node_id=NEW.node_id
    AND a.generation=g.generation AND a.state='reserved' AND a.live_mapping_id=m.id
    AND m.protocol='tcp' AND m.enabled=0 AND m.bind_port=NEW.bind_port
    AND g.revoked_at IS NULL AND g.issued_at<=NEW.created_at AND g.expires_at>NEW.created_at)
BEGIN SELECT RAISE(ABORT,'invalid TCP intent binding'); END;
CREATE TRIGGER relay_tcp_intent_one_shot BEFORE UPDATE ON relay_tcp_intents
WHEN NEW.grant_id<>OLD.grant_id OR NEW.node_id<>OLD.node_id OR NEW.relay_port<>OLD.relay_port
    OR NEW.bind_port<>OLD.bind_port OR NEW.created_at<>OLD.created_at
    OR OLD.claimed_at IS NOT NULL OR NEW.claimed_at IS NULL
BEGIN SELECT RAISE(ABORT,'TCP intent is immutable after claim'); END;
CREATE TRIGGER relay_tcp_intent_no_delete BEFORE DELETE ON relay_tcp_intents
BEGIN SELECT RAISE(ABORT,'TCP intent requires reconciliation'); END;
