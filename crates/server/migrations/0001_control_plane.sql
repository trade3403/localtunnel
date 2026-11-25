-- Desired configuration only; no claim of authenticated/online tunnel state.
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','user')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE TABLE devices (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    credential_digest BLOB NOT NULL CHECK (length(credential_digest)=32),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision>=1),
    UNIQUE (owner_id,id)
) STRICT;

CREATE TABLE nodes (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1))
) STRICT;

CREATE TABLE domains (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL REFERENCES users(id),
    hostname TEXT NOT NULL COLLATE NOCASE UNIQUE,
    verified_at INTEGER,
    UNIQUE (owner_id,id)
) STRICT;

CREATE TABLE mappings (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL REFERENCES users(id),
    device_id TEXT NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    domain_id TEXT UNIQUE,
    protocol TEXT NOT NULL CHECK (protocol IN ('http','https','tcp')),
    local_host TEXT NOT NULL DEFAULT '127.0.0.1' CHECK (local_host='127.0.0.1'),
    local_port INTEGER NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
    bind_port INTEGER NOT NULL CHECK (bind_port BETWEEN 1 AND 65535),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision>=1),
    CHECK ((protocol='tcp' AND domain_id IS NULL) OR (protocol IN ('http','https') AND domain_id IS NOT NULL)),
    FOREIGN KEY (owner_id,device_id) REFERENCES devices(owner_id,id),
    FOREIGN KEY (owner_id,domain_id) REFERENCES domains(owner_id,id),
    UNIQUE (node_id,bind_port)
) STRICT;

CREATE INDEX mappings_owner_device ON mappings(owner_id,device_id);
