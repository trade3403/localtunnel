-- Add UDP desired metadata, preserving all rows, FKs, indexes and triggers.
-- SQLx runs this migration in one transaction with foreign keys enabled.
-- Copy dependent tables first; never DROP a parent while its CASCADE children exist.
-- Install triggers only AFTER copying rows to preserve revisions/audit history.
CREATE TEMP TABLE lt_mappings_0011 AS SELECT * FROM mappings;
CREATE TEMP TABLE lt_runtime_0011 AS SELECT * FROM runtime_requests;
CREATE TEMP TABLE lt_traffic_0011 AS SELECT * FROM mapping_traffic;
DROP TABLE mapping_traffic;
DROP TABLE runtime_requests;
DROP TABLE mappings;

CREATE TABLE mappings (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL REFERENCES users(id),
    device_id TEXT NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    domain_id TEXT UNIQUE,
    protocol TEXT NOT NULL CHECK (protocol IN ('http','https','tcp','udp')),
    local_host TEXT NOT NULL DEFAULT '127.0.0.1' CHECK (local_host='127.0.0.1'),
    local_port INTEGER NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
    bind_port INTEGER NOT NULL CHECK (bind_port BETWEEN 1 AND 65535),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision>=1),
    CHECK ((protocol IN ('tcp','udp') AND domain_id IS NULL) OR (protocol IN ('http','https') AND domain_id IS NOT NULL)),
    FOREIGN KEY (owner_id,device_id) REFERENCES devices(owner_id,id),
    FOREIGN KEY (owner_id,domain_id) REFERENCES domains(owner_id,id),
    UNIQUE (node_id,bind_port)
) STRICT;

CREATE INDEX mappings_owner_device ON mappings(owner_id,device_id);

INSERT INTO mappings SELECT * FROM lt_mappings_0011;

-- One outstanding request per mapping, no executable or secret fields.
CREATE TABLE runtime_requests (
    mapping_id TEXT PRIMARY KEY NOT NULL REFERENCES mappings(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL UNIQUE,
    mapping_revision INTEGER NOT NULL CHECK (mapping_revision>=1),
    state TEXT NOT NULL CHECK (state IN ('queued','starting','running','stopping','stopped','failed_or_unknown')),
    requested_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

INSERT INTO runtime_requests SELECT * FROM lt_runtime_0011;

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

INSERT INTO mapping_traffic SELECT * FROM lt_traffic_0011;

CREATE TRIGGER mapping_config_insert AFTER INSERT ON mappings
BEGIN
    UPDATE devices SET revision=revision+1 WHERE id=NEW.device_id;
END;
CREATE TRIGGER mapping_config_update AFTER UPDATE ON mappings
BEGIN
    UPDATE devices SET revision=revision+1 WHERE id IN (OLD.device_id,NEW.device_id);
END;
CREATE TRIGGER mapping_config_delete AFTER DELETE ON mappings
BEGIN
    UPDATE devices SET revision=revision+1 WHERE id=OLD.device_id;
END;


CREATE TRIGGER audit_mapping_create AFTER INSERT ON mappings
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (NEW.owner_id,'mapping.created',NEW.id,NEW.revision,NULL,NULL);
END;

CREATE TRIGGER audit_mapping_update AFTER UPDATE ON mappings
WHEN OLD.revision<>NEW.revision
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (NEW.owner_id,'mapping.updated',NEW.id,NEW.revision,NULL,NULL);
END;

CREATE TRIGGER audit_mapping_remove AFTER DELETE ON mappings
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (OLD.owner_id,'mapping.deleted',OLD.id,OLD.revision,NULL,NULL);
END;

CREATE TRIGGER audit_runtime_create AFTER INSERT ON runtime_requests
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    SELECT owner_id,'runtime.transition',NEW.mapping_id,NEW.mapping_revision,NEW.request_id,NEW.state FROM mappings WHERE id=NEW.mapping_id;
END;
CREATE TRIGGER audit_runtime_change AFTER UPDATE ON runtime_requests
WHEN OLD.state<>NEW.state OR OLD.request_id<>NEW.request_id
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    SELECT owner_id,'runtime.transition',NEW.mapping_id,NEW.mapping_revision,NEW.request_id,NEW.state FROM mappings WHERE id=NEW.mapping_id;
END;

DROP TABLE lt_traffic_0011;
DROP TABLE lt_runtime_0011;
DROP TABLE lt_mappings_0011;
