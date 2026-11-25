CREATE TABLE device_pairings (
    owner_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_digest BLOB NOT NULL UNIQUE CHECK (length(code_digest)=32),
    expires_at INTEGER NOT NULL
) STRICT;
CREATE TRIGGER revoke_device_pairing AFTER UPDATE OF password_hash,role,enabled ON users
WHEN OLD.password_hash<>NEW.password_hash OR OLD.role<>NEW.role OR OLD.enabled<>NEW.enabled
BEGIN
    DELETE FROM device_pairings WHERE owner_id=NEW.id;
END;
