-- One observation per node; never an authorization or a capacity grant.
CREATE TABLE relay_heartbeat (
    node_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_identities(node_id),
    generation INTEGER NOT NULL CHECK(generation>=1),
    received_at INTEGER NOT NULL,
    protocol_version INTEGER NOT NULL CHECK(protocol_version=1),
    capacity INTEGER NOT NULL CHECK(capacity BETWEEN 0 AND 65536)
) STRICT;
