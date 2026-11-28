-- One exact, revocable owner opt-in per claimed source. No credentials.
CREATE TABLE relay_auto_failover (
 source_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_allocations(id),
 grant_id TEXT NOT NULL UNIQUE REFERENCES relay_budget_grants(id),
 entitlement_revision INTEGER NOT NULL CHECK(entitlement_revision>=1),
 enabled_at INTEGER NOT NULL CHECK(enabled_at>0),
 cancelled_at INTEGER CHECK(cancelled_at>=enabled_at)
) STRICT;
CREATE TRIGGER relay_auto_failover_validate BEFORE INSERT ON relay_auto_failover
WHEN NEW.enabled_at<>unixepoch() OR NEW.cancelled_at IS NOT NULL OR NOT EXISTS(
 SELECT 1 FROM relay_allocations a JOIN relay_budget_grants g ON g.allocation_id=a.id
 JOIN relay_budget_intents i ON i.grant_id=g.id
 JOIN tenants t ON t.owner_id=a.owner_id JOIN tenant_entitlements e ON e.tenant_id=t.id
 JOIN users u ON u.id=a.owner_id
 WHERE a.id=NEW.source_id AND g.id=NEW.grant_id AND a.state='reserved' AND a.generation IN (2,3)
 AND i.execution_opt_in=1 AND i.claimed_at IS NOT NULL AND e.revision=NEW.entitlement_revision
 AND u.enabled=1 AND u.role='admin' AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch()))
BEGIN SELECT RAISE(ABORT,'invalid auto failover opt-in'); END;
CREATE TRIGGER relay_auto_failover_one_cancel BEFORE UPDATE ON relay_auto_failover
WHEN NEW.source_id<>OLD.source_id OR NEW.grant_id<>OLD.grant_id OR NEW.entitlement_revision<>OLD.entitlement_revision
 OR NEW.enabled_at<>OLD.enabled_at OR OLD.cancelled_at IS NOT NULL OR NEW.cancelled_at IS NULL
 OR NEW.cancelled_at<>unixepoch() OR EXISTS(SELECT 1 FROM relay_failover_links l WHERE l.source_id=OLD.source_id)
BEGIN SELECT RAISE(ABORT,'auto failover opt-in immutable or already acted on'); END;
CREATE TRIGGER relay_auto_failover_no_delete BEFORE DELETE ON relay_auto_failover
BEGIN SELECT RAISE(ABORT,'auto failover opt-in retained'); END;
