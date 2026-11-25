CREATE TABLE admin_sessions (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_digest BLOB NOT NULL UNIQUE CHECK (length(token_digest)=32),
    expires_at INTEGER NOT NULL
) STRICT;
CREATE TRIGGER revoke_admin_session AFTER UPDATE OF password_hash,role,enabled ON users
WHEN OLD.password_hash<>NEW.password_hash OR OLD.role<>NEW.role OR OLD.enabled<>NEW.enabled
BEGIN
    DELETE FROM admin_sessions WHERE user_id=NEW.id;
END;
