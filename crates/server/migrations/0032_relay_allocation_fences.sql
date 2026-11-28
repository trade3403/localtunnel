-- A fence proves the prior authorization's server-side expiry, not that
-- its process or port has been cleaned up. Retain all resources and quota.
CREATE TABLE relay_allocation_fences (
 allocation_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_allocations(id),
 grant_id TEXT NOT NULL CHECK(length(grant_id)=32),
 grant_kind TEXT NOT NULL CHECK(grant_kind IN ('ordinary','finite')),
 old_generation INTEGER NOT NULL CHECK(old_generation=2),
 new_generation INTEGER NOT NULL CHECK(new_generation=old_generation+1),
 node_id TEXT NOT NULL REFERENCES nodes(id),
 node_generation INTEGER NOT NULL CHECK(node_generation>=1),
 expires_at INTEGER NOT NULL CHECK(expires_at>0),
 fenced_at INTEGER NOT NULL CHECK(fenced_at>=expires_at+2)
) STRICT;
CREATE TRIGGER relay_fence_validate BEFORE INSERT ON relay_allocation_fences
WHEN NEW.fenced_at<>unixepoch() OR NOT EXISTS(
 SELECT 1 FROM relay_allocations a WHERE a.id=NEW.allocation_id AND a.state='reserved'
 AND a.generation=NEW.old_generation AND a.node_id=NEW.node_id AND a.node_generation=NEW.node_generation
 AND (
 (NEW.grant_kind='ordinary' AND EXISTS(SELECT 1 FROM relay_grants g WHERE g.allocation_id=a.id AND g.id=NEW.grant_id
  AND g.generation=a.generation AND g.node_id=a.node_id AND g.node_generation=a.node_generation AND g.expires_at=NEW.expires_at))
 OR
 (NEW.grant_kind='finite' AND EXISTS(SELECT 1 FROM relay_budget_grants g JOIN relay_budget_previews b ON b.allocation_id=g.allocation_id
  WHERE g.allocation_id=a.id AND g.id=NEW.grant_id AND b.node_id=a.node_id AND b.node_generation=a.node_generation AND g.expires_at=NEW.expires_at))
 ))
BEGIN SELECT RAISE(ABORT,'invalid or premature allocation fence'); END;
CREATE TRIGGER relay_fence_advance AFTER INSERT ON relay_allocation_fences
BEGIN
 UPDATE relay_allocations SET generation=NEW.new_generation WHERE id=NEW.allocation_id AND generation=NEW.old_generation;
END;
CREATE TRIGGER relay_fence_no_update BEFORE UPDATE ON relay_allocation_fences
BEGIN SELECT RAISE(ABORT,'allocation fence immutable'); END;
CREATE TRIGGER relay_fence_no_delete BEFORE DELETE ON relay_allocation_fences
BEGIN SELECT RAISE(ABORT,'allocation fence retained'); END;
CREATE TRIGGER relay_fenced_allocation_retained BEFORE UPDATE ON relay_allocations
WHEN EXISTS(SELECT 1 FROM relay_allocation_fences f WHERE f.allocation_id=OLD.id)
 AND (NEW.generation<>(SELECT new_generation FROM relay_allocation_fences WHERE allocation_id=OLD.id)
 OR NEW.state<>OLD.state OR NEW.live_mapping_id IS NOT OLD.live_mapping_id OR NEW.node_id<>OLD.node_id
 OR NEW.node_generation<>OLD.node_generation OR NEW.mapping_revision<>OLD.mapping_revision OR NEW.bind_port<>OLD.bind_port)
BEGIN SELECT RAISE(ABORT,'fenced allocation retained for reconciliation'); END;
