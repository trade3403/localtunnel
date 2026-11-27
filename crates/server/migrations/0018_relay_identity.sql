-- Existing node directory entries remain unregistered until explicit issuance.
CREATE TABLE relay_identities (
    node_id TEXT PRIMARY KEY NOT NULL REFERENCES nodes(id),
    token_digest BLOB UNIQUE CHECK(token_digest IS NULL OR length(token_digest)=32),
    generation INTEGER NOT NULL CHECK(generation>=1),
    changed_at INTEGER NOT NULL DEFAULT(unixepoch())
) STRICT;
CREATE TABLE relay_identity_audit (
    seq INTEGER PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    generation INTEGER NOT NULL CHECK(generation>=1),
    event TEXT NOT NULL CHECK(event IN ('issued','rotated','revoked','disabled')),
    created_at INTEGER NOT NULL DEFAULT(unixepoch())
) STRICT;
-- Re-enabling a directory entry must never resurrect its old credential.
CREATE TRIGGER relay_identity_disable AFTER UPDATE OF enabled ON nodes
WHEN OLD.enabled=1 AND NEW.enabled=0
BEGIN
    INSERT INTO relay_identity_audit(node_id,generation,event)
        SELECT node_id,generation+1,'disabled' FROM relay_identities
        WHERE node_id=NEW.id AND token_digest IS NOT NULL;
    UPDATE relay_identities SET token_digest=NULL,generation=generation+1,changed_at=unixepoch()
        WHERE node_id=NEW.id AND token_digest IS NOT NULL;
END;
