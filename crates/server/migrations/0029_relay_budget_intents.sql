-- Non-executable finite-budget claim ledger.
CREATE TABLE relay_budget_intents (
 grant_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_budget_grants(id),
 node_id TEXT NOT NULL REFERENCES nodes(id),
 relay_port INTEGER NOT NULL CHECK(relay_port BETWEEN 30000 AND 59999),
 bind_port INTEGER NOT NULL CHECK(bind_port BETWEEN 20000 AND 29999),
 created_at INTEGER NOT NULL CHECK(created_at>0),
 claimed_at INTEGER CHECK(claimed_at>=created_at),
 UNIQUE(node_id,relay_port)
) STRICT;
CREATE TRIGGER relay_budget_intent_validate BEFORE INSERT ON relay_budget_intents
WHEN NEW.claimed_at IS NOT NULL OR NOT EXISTS(
 SELECT 1 FROM relay_budget_grants g JOIN relay_budget_previews b ON b.allocation_id=g.allocation_id
 JOIN relay_allocations a ON a.id=b.allocation_id AND a.generation=2 AND a.state='reserved'
 JOIN mappings m ON m.id=a.live_mapping_id AND m.revision=b.mapping_revision
 WHERE g.id=NEW.grant_id AND b.node_id=NEW.node_id AND a.node_id=b.node_id
 AND a.node_generation=b.node_generation AND a.mapping_revision=b.mapping_revision
 AND m.protocol='tcp' AND m.enabled=0 AND m.bind_port=NEW.bind_port AND a.bind_port=NEW.bind_port
 AND g.revoked_at IS NULL AND g.issued_at<=NEW.created_at AND g.expires_at>NEW.created_at)
BEGIN SELECT RAISE(ABORT,'invalid budget intent binding'); END;
CREATE TRIGGER relay_budget_intent_one_shot BEFORE UPDATE ON relay_budget_intents
WHEN NEW.grant_id<>OLD.grant_id OR NEW.node_id<>OLD.node_id OR NEW.relay_port<>OLD.relay_port
 OR NEW.bind_port<>OLD.bind_port OR NEW.created_at<>OLD.created_at OR OLD.claimed_at IS NOT NULL
 OR NEW.claimed_at IS NULL OR NOT EXISTS(SELECT 1 FROM relay_budget_grants g
 WHERE g.id=OLD.grant_id AND g.revoked_at IS NULL AND NEW.claimed_at>=g.issued_at AND NEW.claimed_at<g.expires_at)
BEGIN SELECT RAISE(ABORT,'budget intent immutable or expired'); END;
CREATE TRIGGER relay_budget_intent_no_delete BEFORE DELETE ON relay_budget_intents
BEGIN SELECT RAISE(ABORT,'budget intent requires reconciliation'); END;
CREATE TRIGGER relay_budget_transport_exclusive BEFORE INSERT ON relay_budget_intents
WHEN EXISTS(SELECT 1 FROM relay_tcp_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
 OR EXISTS(SELECT 1 FROM relay_udp_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
 OR EXISTS(SELECT 1 FROM relay_http_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
 OR EXISTS(SELECT 1 FROM relay_https_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
BEGIN SELECT RAISE(ABORT,'transport port reserved'); END;
CREATE TRIGGER relay_tcp_budget_transport_exclusive BEFORE INSERT ON relay_tcp_intents
WHEN EXISTS(SELECT 1 FROM relay_budget_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
BEGIN SELECT RAISE(ABORT,'transport port reserved by finite budget'); END;
CREATE TRIGGER relay_udp_budget_transport_exclusive BEFORE INSERT ON relay_udp_intents
WHEN EXISTS(SELECT 1 FROM relay_budget_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
BEGIN SELECT RAISE(ABORT,'transport port reserved by finite budget'); END;
CREATE TRIGGER relay_http_budget_transport_exclusive BEFORE INSERT ON relay_http_intents
WHEN EXISTS(SELECT 1 FROM relay_budget_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
BEGIN SELECT RAISE(ABORT,'transport port reserved by finite budget'); END;
CREATE TRIGGER relay_https_budget_transport_exclusive BEFORE INSERT ON relay_https_intents
WHEN EXISTS(SELECT 1 FROM relay_budget_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
BEGIN SELECT RAISE(ABORT,'transport port reserved by finite budget'); END;
