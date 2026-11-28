-- The earliest observed failure for a claimed, executable finite grant.
-- Detection is NOT proof of a stopped engine; no quota or port release.
CREATE TABLE relay_failure_observations (
 allocation_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_allocations(id),
 grant_id TEXT NOT NULL UNIQUE REFERENCES relay_budget_grants(id),
 node_id TEXT NOT NULL REFERENCES nodes(id),
 node_generation INTEGER NOT NULL CHECK(node_generation>=1),
 reason TEXT NOT NULL CHECK(reason IN ('node_disabled','identity_unavailable','heartbeat_stale')),
 observed_at INTEGER NOT NULL CHECK(observed_at>0)
) STRICT;
CREATE VIEW relay_failed_finite_claims AS
 SELECT a.id AS allocation_id,g.id AS grant_id,a.node_id,a.node_generation,g.expires_at,
 CASE WHEN n.enabled=0 THEN 'node_disabled'
 WHEN r.token_digest IS NULL OR r.generation<>a.node_generation THEN 'identity_unavailable'
 ELSE 'heartbeat_stale' END AS reason
 FROM relay_allocations a JOIN relay_budget_grants g ON g.allocation_id=a.id
 JOIN relay_budget_intents i ON i.grant_id=g.id AND i.node_id=a.node_id AND i.bind_port=a.bind_port
 JOIN nodes n ON n.id=a.node_id
 LEFT JOIN relay_identities r ON r.node_id=n.id
 LEFT JOIN relay_heartbeat h ON h.node_id=n.id AND h.generation=r.generation
 WHERE a.state='reserved' AND a.generation=2 AND i.execution_opt_in=1 AND i.claimed_at IS NOT NULL
 AND (n.enabled=0 OR r.token_digest IS NULL OR r.generation<>a.node_generation
 OR h.received_at IS NULL OR h.received_at NOT BETWEEN unixepoch()-15 AND unixepoch());
CREATE TRIGGER relay_failure_observation_validate BEFORE INSERT ON relay_failure_observations
WHEN NEW.observed_at<>unixepoch() OR NOT EXISTS(
 SELECT 1 FROM relay_failed_finite_claims f WHERE f.allocation_id=NEW.allocation_id
 AND f.grant_id=NEW.grant_id AND f.node_id=NEW.node_id AND f.node_generation=NEW.node_generation AND f.reason=NEW.reason)
BEGIN SELECT RAISE(ABORT,'invalid failure observation'); END;
CREATE TRIGGER relay_failure_observation_no_update BEFORE UPDATE ON relay_failure_observations
BEGIN SELECT RAISE(ABORT,'failure observation immutable'); END;
CREATE TRIGGER relay_failure_observation_no_delete BEFORE DELETE ON relay_failure_observations
BEGIN SELECT RAISE(ABORT,'failure observation retained'); END;
