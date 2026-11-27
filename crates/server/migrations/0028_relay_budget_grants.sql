-- Non-executable finite-budget observation; separate from unlimited grants.
CREATE TABLE relay_budget_grants (
    id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
    allocation_id TEXT NOT NULL UNIQUE REFERENCES relay_budget_previews(allocation_id),
    device_revision INTEGER NOT NULL CHECK(device_revision>=1),
    issued_at INTEGER NOT NULL CHECK(issued_at>0),
    expires_at INTEGER NOT NULL CHECK(expires_at=issued_at+15),
    revoked_at INTEGER CHECK(revoked_at>=issued_at)
) STRICT;
CREATE TRIGGER relay_budget_grant_validate BEFORE INSERT ON relay_budget_grants
WHEN NEW.revoked_at IS NOT NULL OR NOT EXISTS(
 SELECT 1 FROM relay_budget_previews b JOIN relay_allocations a ON a.id=b.allocation_id
 JOIN mappings m ON m.id=a.live_mapping_id AND m.revision=b.mapping_revision
 JOIN devices d ON d.id=m.device_id AND d.revision=NEW.device_revision
 WHERE b.allocation_id=NEW.allocation_id AND a.state='reserved' AND a.generation=1
 AND a.node_id=b.node_id AND a.node_generation=b.node_generation AND a.mapping_revision=b.mapping_revision
 AND m.protocol='tcp' AND m.domain_id IS NULL AND m.enabled=0
 AND b.month_utc=strftime('%Y-%m',NEW.issued_at,'unixepoch')
 AND b.month_utc=strftime('%Y-%m',NEW.expires_at,'unixepoch'))
BEGIN SELECT RAISE(ABORT,'invalid budget grant binding'); END;
CREATE TRIGGER relay_budget_grant_immutable BEFORE UPDATE ON relay_budget_grants
WHEN NEW.id<>OLD.id OR NEW.allocation_id<>OLD.allocation_id OR NEW.device_revision<>OLD.device_revision
 OR NEW.issued_at<>OLD.issued_at OR NEW.expires_at<>OLD.expires_at
 OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
BEGIN SELECT RAISE(ABORT,'budget grant immutable'); END;
CREATE TRIGGER relay_budget_grant_no_delete BEFORE DELETE ON relay_budget_grants
BEGIN SELECT RAISE(ABORT,'budget grant requires reconciliation'); END;
