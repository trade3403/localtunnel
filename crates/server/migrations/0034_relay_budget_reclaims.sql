-- Reclaim only reusable rate and slot capacity. Full monthly slice,
-- mapping, ports, original grant and all evidence remain reserved.
CREATE TABLE relay_budget_reclaims (
 allocation_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_cleanup_reports(allocation_id),
 grant_id TEXT NOT NULL,
 fenced_generation INTEGER NOT NULL CHECK(fenced_generation=3),
 confirmation TEXT NOT NULL CHECK(confirmation='offline_engine_and_guard_verified_stopped'),
 reclaimed_at INTEGER NOT NULL CHECK(reclaimed_at>0)
) STRICT;
CREATE TRIGGER relay_budget_reclaim_validate BEFORE INSERT ON relay_budget_reclaims
WHEN NEW.reclaimed_at<>unixepoch() OR NOT EXISTS(
 SELECT 1 FROM relay_cleanup_reports c JOIN relay_allocation_fences f ON f.allocation_id=c.allocation_id
 JOIN relay_allocations a ON a.id=f.allocation_id JOIN relay_budget_previews b ON b.allocation_id=a.id
 WHERE c.allocation_id=NEW.allocation_id AND c.grant_id=NEW.grant_id AND f.grant_id=c.grant_id
 AND c.fenced_generation=NEW.fenced_generation AND a.generation=f.new_generation AND a.state='reserved'
 AND f.grant_kind='finite' AND NEW.reclaimed_at>=c.reported_at AND NEW.reclaimed_at>=f.expires_at+2)
BEGIN SELECT RAISE(ABORT,'invalid budget reclaim'); END;
CREATE TRIGGER relay_budget_reclaim_no_update BEFORE UPDATE ON relay_budget_reclaims
BEGIN SELECT RAISE(ABORT,'budget reclaim immutable'); END;
CREATE TRIGGER relay_budget_reclaim_no_delete BEFORE DELETE ON relay_budget_reclaims
BEGIN SELECT RAISE(ABORT,'budget reclaim retained'); END;
CREATE VIEW relay_budget_active AS SELECT b.* FROM relay_budget_previews b
 WHERE NOT EXISTS(SELECT 1 FROM relay_budget_reclaims r WHERE r.allocation_id=b.allocation_id);
DROP TRIGGER relay_budget_validate;
CREATE TRIGGER relay_budget_validate BEFORE INSERT ON relay_budget_previews
WHEN NOT EXISTS(
 SELECT 1 FROM relay_allocations a JOIN tenants t ON t.owner_id=a.owner_id
 JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans p ON p.id=e.plan_id
 JOIN nodes n ON n.id=a.node_id JOIN relay_identities r ON r.node_id=n.id
 JOIN mappings m ON m.id=a.live_mapping_id AND m.owner_id=a.owner_id
 JOIN relay_heartbeat h ON h.node_id=n.id AND h.generation=r.generation
 JOIN devices d ON d.id=m.device_id AND d.owner_id=a.owner_id JOIN users u ON u.id=a.owner_id
 WHERE a.id=NEW.allocation_id AND a.state='reserved' AND a.generation=1
 AND t.id=NEW.tenant_id AND a.node_id=NEW.node_id AND a.node_generation=NEW.node_generation
 AND r.generation=NEW.node_generation AND a.mapping_revision=NEW.mapping_revision AND m.revision=a.mapping_revision
 AND e.revision=NEW.entitlement_revision AND n.policy_revision=NEW.policy_revision
 AND NEW.month_utc=strftime('%Y-%m','now') AND NEW.created_at=unixepoch()
 AND m.enabled=0 AND d.enabled=1 AND u.enabled=1 AND u.role='admin'
 AND n.enabled=1 AND n.policy_mode='active' AND r.token_digest IS NOT NULL
 AND h.received_at BETWEEN unixepoch()-15 AND unixepoch()
 AND e.state='active' AND (e.expires_at IS NULL OR e.expires_at>unixepoch())
 AND (SELECT count(*) FROM mappings x WHERE x.node_id=n.id)<=min(n.approved_capacity,h.capacity)
 AND (SELECT count(*) FROM mappings x WHERE x.owner_id=a.owner_id)<=p.max_mappings
 AND (SELECT count(*) FROM devices x WHERE x.owner_id=a.owner_id AND x.enabled=1)<=p.max_active_devices
 AND NOT EXISTS(SELECT 1 FROM bandwidth_reservations x WHERE x.tenant_id=t.id)
 AND NOT EXISTS(SELECT 1 FROM relay_grants g JOIN relay_allocations z ON z.id=g.allocation_id WHERE z.owner_id=a.owner_id)
 AND p.max_bandwidth_bps IS NOT NULL AND p.max_monthly_bytes IS NOT NULL AND p.max_concurrent_connections IS NOT NULL
 AND (SELECT coalesce(sum(b.rate_bytes_per_second),0) FROM relay_budget_active b WHERE b.tenant_id=t.id)<=p.max_bandwidth_bps/8-NEW.rate_bytes_per_second
 AND (SELECT coalesce(sum(b.connection_slots),0) FROM relay_budget_active b WHERE b.tenant_id=t.id)<=p.max_concurrent_connections-NEW.connection_slots
 AND (SELECT coalesce(sum(b.monthly_bytes),0) FROM relay_budget_previews b WHERE b.tenant_id=t.id AND b.month_utc=NEW.month_utc)
 <=p.max_monthly_bytes-NEW.monthly_bytes-coalesce((SELECT q.charged_bytes FROM tenant_monthly_usage q WHERE q.tenant_id=t.id AND q.month_utc=NEW.month_utc),0)
)
BEGIN SELECT RAISE(ABORT,'budget preview unavailable'); END;
