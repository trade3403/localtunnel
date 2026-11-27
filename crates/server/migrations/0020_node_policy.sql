-- A directory entry is not a scheduling grant. Existing nodes default to zero approved capacity.
ALTER TABLE nodes ADD COLUMN approved_capacity INTEGER NOT NULL DEFAULT 0 CHECK(approved_capacity BETWEEN 0 AND 65536);
ALTER TABLE nodes ADD COLUMN region TEXT NOT NULL DEFAULT 'unassigned' CHECK(length(region) BETWEEN 1 AND 32 AND region NOT GLOB '*[^a-z0-9_-]*');
ALTER TABLE nodes ADD COLUMN policy_mode TEXT NOT NULL DEFAULT 'active' CHECK(policy_mode IN ('active','draining','maintenance'));
ALTER TABLE nodes ADD COLUMN policy_revision INTEGER NOT NULL DEFAULT 1 CHECK(policy_revision>=1);
CREATE TABLE node_policy_audit (
    seq INTEGER PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    revision INTEGER NOT NULL CHECK(revision>=2),
    approved_capacity INTEGER NOT NULL CHECK(approved_capacity BETWEEN 0 AND 65536),
    region TEXT NOT NULL CHECK(length(region) BETWEEN 1 AND 32 AND region NOT GLOB '*[^a-z0-9_-]*'),
    mode TEXT NOT NULL CHECK(mode IN ('active','draining','maintenance')),
    created_at INTEGER NOT NULL DEFAULT(unixepoch()),
    UNIQUE(node_id,revision)
) STRICT;
