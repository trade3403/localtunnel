-- One outstanding request per mapping, no executable or secret fields.
CREATE TABLE runtime_requests (
    mapping_id TEXT PRIMARY KEY NOT NULL REFERENCES mappings(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL UNIQUE,
    mapping_revision INTEGER NOT NULL CHECK (mapping_revision>=1),
    state TEXT NOT NULL CHECK (state IN ('queued','starting','running','stopping','stopped','failed_or_unknown')),
    requested_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
