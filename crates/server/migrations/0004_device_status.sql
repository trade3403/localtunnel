CREATE TABLE device_status (
    device_id TEXT PRIMARY KEY NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    last_seen_at INTEGER NOT NULL,
    reported_revision INTEGER NOT NULL CHECK (reported_revision>=0),
    reported_state TEXT NOT NULL CHECK (reported_state IN ('idle','starting','running','error'))
) STRICT;

-- Configuration revision changes with each desired mapping mutation. A move
-- between devices invalidates both snapshots.
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

-- A device or owner authorization change invalidates old liveness evidence.
CREATE TRIGGER clear_device_status AFTER UPDATE OF enabled,credential_digest ON devices
WHEN OLD.enabled<>NEW.enabled OR OLD.credential_digest<>NEW.credential_digest
BEGIN
    DELETE FROM device_status WHERE device_id=NEW.id;
END;
CREATE TRIGGER clear_owner_device_status AFTER UPDATE OF enabled,role ON users
WHEN OLD.enabled<>NEW.enabled OR OLD.role<>NEW.role
BEGIN
    DELETE FROM device_status WHERE device_id IN (SELECT id FROM devices WHERE owner_id=NEW.id);
END;
