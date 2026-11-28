-- A single immutable successor reservation per retired source.
-- Each allocation retains its own generation; lineage epoch is distinct.
CREATE TABLE relay_failover_links (
 source_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_budget_retirements(allocation_id),
 successor_id TEXT NOT NULL UNIQUE REFERENCES relay_allocations(id),
 source_grant_id TEXT NOT NULL REFERENCES relay_budget_grants(id),
 lineage_epoch INTEGER NOT NULL CHECK(lineage_epoch>=2),
 entitlement_revision INTEGER NOT NULL CHECK(entitlement_revision>=1),
 created_at INTEGER NOT NULL CHECK(created_at>0),
 CHECK(source_id<>successor_id)
) STRICT;
CREATE TRIGGER relay_failover_link_validate BEFORE INSERT ON relay_failover_links
WHEN NEW.created_at<>unixepoch() OR NOT EXISTS(
 SELECT 1 FROM relay_budget_retirements r JOIN relay_allocations old ON old.id=r.allocation_id
 JOIN relay_allocations a ON a.id=NEW.successor_id
 JOIN mappings m ON m.id=a.live_mapping_id JOIN relay_budget_previews b ON b.allocation_id=a.id
 JOIN relay_budget_previews prior ON prior.allocation_id=old.id
 WHERE r.allocation_id=NEW.source_id AND r.grant_id=NEW.source_grant_id
 AND old.state='cancelled' AND old.generation=4 AND a.state='reserved' AND a.generation=1
 AND a.owner_id=old.owner_id AND a.node_id<>old.node_id AND a.bind_port=r.bind_port
 AND m.owner_id=a.owner_id AND m.device_id=r.device_id AND m.local_port=r.local_port
 AND m.protocol='tcp' AND m.domain_id IS NULL AND m.enabled=0
 AND b.tenant_id=prior.tenant_id AND b.entitlement_revision=NEW.entitlement_revision
 AND b.rate_bytes_per_second=prior.rate_bytes_per_second AND b.monthly_bytes=prior.monthly_bytes
 AND b.connection_slots=prior.connection_slots AND b.month_utc=strftime('%Y-%m','now')
 AND NEW.lineage_epoch=coalesce((SELECT lineage_epoch FROM relay_failover_links WHERE successor_id=old.id),1)+1
 AND NOT EXISTS(SELECT 1 FROM relay_budget_grants g WHERE g.allocation_id=a.id)
)
BEGIN SELECT RAISE(ABORT,'invalid failover successor'); END;
CREATE TRIGGER relay_failover_link_no_update BEFORE UPDATE ON relay_failover_links
BEGIN SELECT RAISE(ABORT,'failover link immutable'); END;
CREATE TRIGGER relay_failover_link_no_delete BEFORE DELETE ON relay_failover_links
BEGIN SELECT RAISE(ABORT,'failover link retained'); END;
