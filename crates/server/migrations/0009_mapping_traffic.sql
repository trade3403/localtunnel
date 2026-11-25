-- Observed HTTP gateway traffic, not encrypted-link or billing counters.
CREATE TABLE mapping_traffic (
    request_id TEXT PRIMARY KEY NOT NULL,
    mapping_id TEXT NOT NULL REFERENCES mappings(id) ON DELETE CASCADE,
    mapping_revision INTEGER NOT NULL CHECK(mapping_revision >= 1),
    requests INTEGER NOT NULL CHECK(requests >= 0),
    request_bytes INTEGER NOT NULL CHECK(request_bytes >= 0),
    response_bytes INTEGER NOT NULL CHECK(response_bytes >= 0),
    sampled_at INTEGER NOT NULL,
    sampling_state TEXT NOT NULL CHECK(sampling_state IN ('sampled','partial','unavailable'))
) STRICT;
CREATE INDEX mapping_traffic_recent ON mapping_traffic(mapping_id,sampled_at DESC,request_id DESC);
