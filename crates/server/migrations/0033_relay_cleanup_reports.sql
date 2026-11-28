-- Node observations only, not proof of cleanup or permission to release.
CREATE TABLE relay_cleanup_reports (
 allocation_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_allocation_fences(allocation_id),
 grant_id TEXT NOT NULL,
 node_id TEXT NOT NULL REFERENCES nodes(id),
 node_generation INTEGER NOT NULL CHECK(node_generation>=1),
 fenced_generation INTEGER NOT NULL CHECK(fenced_generation=3),
 relay_port INTEGER NOT NULL CHECK(relay_port BETWEEN 30000 AND 59999),
 bind_port INTEGER NOT NULL CHECK(bind_port BETWEEN 20000 AND 29999),
 reported_at INTEGER NOT NULL CHECK(reported_at>0)
) STRICT;
CREATE TRIGGER relay_cleanup_report_validate BEFORE INSERT ON relay_cleanup_reports
WHEN NEW.reported_at<>unixepoch() OR NOT EXISTS(
 SELECT 1 FROM relay_allocation_fences f JOIN relay_allocations a ON a.id=f.allocation_id
 JOIN relay_budget_intents i ON i.grant_id=f.grant_id
 JOIN relay_identities r ON r.node_id=f.node_id AND r.generation=f.node_generation
 JOIN nodes n ON n.id=r.node_id
 WHERE f.allocation_id=NEW.allocation_id AND f.grant_kind='finite'
 AND f.grant_id=NEW.grant_id AND f.node_id=NEW.node_id AND f.node_generation=NEW.node_generation
 AND f.new_generation=NEW.fenced_generation AND a.generation=f.new_generation AND a.state='reserved'
 AND i.execution_opt_in=1 AND i.claimed_at IS NOT NULL AND i.node_id=f.node_id
 AND i.relay_port=NEW.relay_port AND i.bind_port=NEW.bind_port AND i.bind_port=a.bind_port
 AND NEW.reported_at>=f.fenced_at AND r.token_digest IS NOT NULL AND n.enabled=1)
BEGIN SELECT RAISE(ABORT,'invalid cleanup observation'); END;
CREATE TRIGGER relay_cleanup_report_no_update BEFORE UPDATE ON relay_cleanup_reports
BEGIN SELECT RAISE(ABORT,'cleanup observation immutable'); END;
CREATE TRIGGER relay_cleanup_report_no_delete BEFORE DELETE ON relay_cleanup_reports
BEGIN SELECT RAISE(ABORT,'cleanup observation retained'); END;
