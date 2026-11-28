-- Archive the exact finite mapping and claimed intent before releasing their
-- live rows. Never recycle an allocation ID, mapping ID, grant or generation.
CREATE TABLE relay_budget_retirements (
 allocation_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_budget_reclaims(allocation_id),
 grant_id TEXT NOT NULL UNIQUE REFERENCES relay_budget_grants(id),
 mapping_id TEXT NOT NULL UNIQUE,
 owner_id TEXT NOT NULL REFERENCES users(id),
 device_id TEXT NOT NULL,
 node_id TEXT NOT NULL REFERENCES nodes(id),
 node_generation INTEGER NOT NULL CHECK(node_generation>=1),
 mapping_revision INTEGER NOT NULL CHECK(mapping_revision>=1),
 local_port INTEGER NOT NULL CHECK(local_port BETWEEN 1 AND 65535),
 relay_port INTEGER NOT NULL CHECK(relay_port BETWEEN 30000 AND 59999),
 bind_port INTEGER NOT NULL CHECK(bind_port BETWEEN 20000 AND 29999),
 intent_created_at INTEGER NOT NULL,
 intent_claimed_at INTEGER NOT NULL CHECK(intent_claimed_at>=intent_created_at),
 old_generation INTEGER NOT NULL CHECK(old_generation=3),
 new_generation INTEGER NOT NULL CHECK(new_generation=4),
 confirmation TEXT NOT NULL CHECK(confirmation='offline_ports_and_engine_verified_stopped'),
 retired_at INTEGER NOT NULL CHECK(retired_at>0)
) STRICT;
CREATE TRIGGER relay_budget_retirement_validate BEFORE INSERT ON relay_budget_retirements
WHEN NEW.retired_at<>unixepoch() OR NOT EXISTS(
 SELECT 1 FROM relay_budget_reclaims r JOIN relay_allocation_fences f ON f.allocation_id=r.allocation_id
 JOIN relay_allocations a ON a.id=f.allocation_id JOIN mappings m ON m.id=a.live_mapping_id
 JOIN relay_budget_intents i ON i.grant_id=f.grant_id
 WHERE r.allocation_id=NEW.allocation_id AND r.grant_id=NEW.grant_id AND f.grant_id=r.grant_id
 AND f.grant_kind='finite' AND a.state='reserved' AND a.generation=NEW.old_generation
 AND a.mapping_id=NEW.mapping_id AND m.id=NEW.mapping_id AND m.owner_id=NEW.owner_id AND a.owner_id=NEW.owner_id
 AND m.device_id=NEW.device_id AND m.protocol='tcp' AND m.domain_id IS NULL AND m.enabled=0
 AND m.local_host='127.0.0.1' AND m.local_port=NEW.local_port AND m.revision=NEW.mapping_revision
 AND a.mapping_revision=m.revision AND a.node_id=NEW.node_id AND a.node_generation=NEW.node_generation
 AND m.node_id=a.node_id AND m.bind_port=NEW.bind_port AND a.bind_port=m.bind_port
 AND i.node_id=a.node_id AND i.relay_port=NEW.relay_port AND i.bind_port=m.bind_port
 AND i.intent_mode='guarded_tcp' AND i.execution_opt_in=1 AND i.created_at=NEW.intent_created_at
 AND i.claimed_at=NEW.intent_claimed_at AND NEW.retired_at>=r.reclaimed_at AND NEW.retired_at>=f.expires_at+2
 AND NOT EXISTS(SELECT 1 FROM relay_grants g WHERE g.allocation_id=a.id)
 AND NOT EXISTS(SELECT 1 FROM runtime_requests x WHERE x.mapping_id=m.id)
 AND NOT EXISTS(SELECT 1 FROM mapping_traffic x WHERE x.mapping_id=m.id)
 AND NOT EXISTS(SELECT 1 FROM bandwidth_reservations x WHERE x.mapping_id=m.id))
BEGIN SELECT RAISE(ABORT,'invalid budget retirement'); END;
CREATE TRIGGER relay_budget_retirement_no_update BEFORE UPDATE ON relay_budget_retirements
BEGIN SELECT RAISE(ABORT,'budget retirement immutable'); END;
CREATE TRIGGER relay_budget_retirement_no_delete BEFORE DELETE ON relay_budget_retirements
BEGIN SELECT RAISE(ABORT,'budget retirement retained'); END;
-- Permit precisely one terminal transition and never change the historical
-- binding. Existing ordinary grants and unreclaimed finite rows stay blocked.
DROP TRIGGER relay_fenced_allocation_retained;
CREATE TRIGGER relay_fenced_allocation_retained BEFORE UPDATE ON relay_allocations
WHEN EXISTS(SELECT 1 FROM relay_allocation_fences f WHERE f.allocation_id=OLD.id)
 AND NOT (
 NEW.id=OLD.id AND NEW.owner_id=OLD.owner_id AND NEW.request_key=OLD.request_key AND NEW.request_digest=OLD.request_digest
 AND NEW.mapping_id=OLD.mapping_id AND NEW.node_id=OLD.node_id AND NEW.node_generation=OLD.node_generation
 AND NEW.mapping_revision=OLD.mapping_revision AND NEW.bind_port=OLD.bind_port AND NEW.created_at=OLD.created_at
 AND (
 (OLD.state='reserved' AND NEW.state='reserved' AND NEW.live_mapping_id IS OLD.live_mapping_id
 AND NEW.generation=(SELECT new_generation FROM relay_allocation_fences WHERE allocation_id=OLD.id))
 OR (OLD.state='reserved' AND OLD.generation=3 AND NEW.state='cancelled' AND NEW.live_mapping_id IS NULL AND NEW.generation=4
 AND EXISTS(SELECT 1 FROM relay_budget_retirements r WHERE r.allocation_id=OLD.id))
 ))
BEGIN SELECT RAISE(ABORT,'fenced allocation immutable'); END;
DROP TRIGGER relay_budget_no_cancel;
CREATE TRIGGER relay_budget_no_cancel BEFORE UPDATE OF state,live_mapping_id ON relay_allocations
WHEN EXISTS(SELECT 1 FROM relay_budget_previews b WHERE b.allocation_id=OLD.id)
 AND (NEW.state<>OLD.state OR NEW.live_mapping_id IS NOT OLD.live_mapping_id)
 AND NOT (OLD.state='reserved' AND OLD.generation=3 AND NEW.state='cancelled' AND NEW.generation=4
 AND NEW.live_mapping_id IS NULL AND EXISTS(SELECT 1 FROM relay_budget_retirements r WHERE r.allocation_id=OLD.id))
BEGIN SELECT RAISE(ABORT,'budget preview requires reconciliation'); END;
DROP TRIGGER relay_budget_intent_no_delete;
CREATE TRIGGER relay_budget_intent_no_delete BEFORE DELETE ON relay_budget_intents
WHEN NOT EXISTS(SELECT 1 FROM relay_budget_retirements r JOIN relay_allocations a ON a.id=r.allocation_id
 WHERE r.grant_id=OLD.grant_id AND r.node_id=OLD.node_id AND r.relay_port=OLD.relay_port
 AND r.bind_port=OLD.bind_port AND r.intent_created_at=OLD.created_at AND r.intent_claimed_at=OLD.claimed_at
 AND OLD.intent_mode='guarded_tcp' AND OLD.execution_opt_in=1 AND a.state='cancelled' AND a.generation=4)
BEGIN SELECT RAISE(ABORT,'budget intent requires reconciliation'); END;
CREATE TRIGGER relay_retired_mapping_no_recreate BEFORE INSERT ON mappings
WHEN EXISTS(SELECT 1 FROM relay_budget_retirements r WHERE r.mapping_id=NEW.id)
BEGIN SELECT RAISE(ABORT,'retired mapping id'); END;
CREATE TRIGGER relay_budget_retirement_apply AFTER INSERT ON relay_budget_retirements
BEGIN
 UPDATE relay_allocations SET generation=4,state='cancelled',live_mapping_id=NULL WHERE id=NEW.allocation_id AND generation=3;
 DELETE FROM relay_budget_intents WHERE grant_id=NEW.grant_id;
 DELETE FROM mappings WHERE id=NEW.mapping_id;
 INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
 VALUES(NEW.owner_id,'allocation.budget_retired',NEW.allocation_id,4,NEW.grant_id,'monthly_retained');
END;
