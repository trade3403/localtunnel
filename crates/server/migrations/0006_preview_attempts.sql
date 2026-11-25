-- Historical operator attempts, not a live routing/availability claim.
CREATE TABLE preview_attempts (
    id TEXT PRIMARY KEY NOT NULL,
    mapping_id TEXT,
    mapping_revision INTEGER NOT NULL CHECK (mapping_revision>=0),
    prefix_name TEXT NOT NULL,
    listen_port INTEGER NOT NULL CHECK (listen_port BETWEEN 1024 AND 65535),
    operation TEXT NOT NULL CHECK (operation IN ('init','apply','apply-checked')),
    outcome TEXT NOT NULL DEFAULT 'pending' CHECK (outcome IN ('pending','succeeded','failed_or_unknown')),
    started_at INTEGER NOT NULL DEFAULT (unixepoch()),
    finished_at INTEGER,
    CHECK ((outcome='pending' AND finished_at IS NULL) OR (outcome<>'pending' AND finished_at IS NOT NULL)),
    CHECK ((mapping_id IS NULL AND mapping_revision=0) OR (mapping_id IS NOT NULL AND mapping_revision>0))
) STRICT;
CREATE INDEX preview_attempts_mapping ON preview_attempts(mapping_id,started_at);
