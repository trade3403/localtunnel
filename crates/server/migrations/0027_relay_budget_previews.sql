-- Conservative, non-executable cross-node reservations. No automatic reclamation.
CREATE TABLE relay_budget_previews (
    allocation_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_allocations(id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    node_generation INTEGER NOT NULL CHECK(node_generation>=1),
    allocation_generation INTEGER NOT NULL CHECK(allocation_generation=1),
    mapping_revision INTEGER NOT NULL CHECK(mapping_revision>=1),
    entitlement_revision INTEGER NOT NULL CHECK(entitlement_revision>=1),
    policy_revision INTEGER NOT NULL CHECK(policy_revision>=1),
    rate_bytes_per_second INTEGER NOT NULL CHECK(rate_bytes_per_second BETWEEN 65536 AND 125000000),
    monthly_bytes INTEGER NOT NULL CHECK(monthly_bytes BETWEEN 1 AND 9000000000000000),
    connection_slots INTEGER NOT NULL CHECK(connection_slots BETWEEN 1 AND 65536),
    month_utc TEXT NOT NULL CHECK(length(month_utc)=7),
    created_at INTEGER NOT NULL CHECK(created_at>0)
) STRICT;
CREATE INDEX relay_budget_tenant ON relay_budget_previews(tenant_id,month_utc);
CREATE TRIGGER relay_budget_immutable BEFORE UPDATE ON relay_budget_previews
BEGIN SELECT RAISE(ABORT,'budget preview immutable'); END;
CREATE TRIGGER relay_budget_no_delete BEFORE DELETE ON relay_budget_previews
BEGIN SELECT RAISE(ABORT,'budget preview requires reconciliation'); END;
CREATE TRIGGER relay_budget_no_cancel BEFORE UPDATE OF state,live_mapping_id ON relay_allocations
WHEN EXISTS(SELECT 1 FROM relay_budget_previews b WHERE b.allocation_id=OLD.id)
 AND (NEW.state<>OLD.state OR NEW.live_mapping_id IS NOT OLD.live_mapping_id)
BEGIN SELECT RAISE(ABORT,'budget preview requires reconciliation'); END;
-- Never mix a non-executable distributed budget with legacy runtime
-- or previously issued unlimited grants, even after a plan change.
CREATE TRIGGER relay_budget_blocks_legacy BEFORE INSERT ON bandwidth_reservations
WHEN EXISTS(SELECT 1 FROM relay_budget_previews b WHERE b.tenant_id=NEW.tenant_id)
BEGIN SELECT RAISE(ABORT,'distributed budget preview retained'); END;
CREATE TRIGGER relay_budget_blocks_grants BEFORE INSERT ON relay_grants
WHEN EXISTS(SELECT 1 FROM relay_allocations a JOIN tenants t ON t.owner_id=a.owner_id
 JOIN relay_budget_previews b ON b.tenant_id=t.id WHERE a.id=NEW.allocation_id)
BEGIN SELECT RAISE(ABORT,'distributed budget is not executable'); END;
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
 AND (SELECT coalesce(sum(b.rate_bytes_per_second),0) FROM relay_budget_previews b WHERE b.tenant_id=t.id)<=p.max_bandwidth_bps/8-NEW.rate_bytes_per_second
 AND (SELECT coalesce(sum(b.connection_slots),0) FROM relay_budget_previews b WHERE b.tenant_id=t.id)<=p.max_concurrent_connections-NEW.connection_slots
 AND (SELECT coalesce(sum(b.monthly_bytes),0) FROM relay_budget_previews b WHERE b.tenant_id=t.id AND b.month_utc=NEW.month_utc)
 <=p.max_monthly_bytes-NEW.monthly_bytes-coalesce((SELECT q.charged_bytes FROM tenant_monthly_usage q WHERE q.tenant_id=t.id AND q.month_utc=NEW.month_utc),0)
)
BEGIN SELECT RAISE(ABORT,'budget preview unavailable'); END;
