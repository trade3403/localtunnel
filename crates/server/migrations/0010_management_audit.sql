-- Committed state transitions, not a complete request/security audit.
-- Keep resource identity after deletion; never copy credential fields.
CREATE TABLE management_audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    revision INTEGER,
    request_id TEXT,
    state TEXT,
    occurred_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
CREATE INDEX management_audit_owner_seq ON management_audit(owner_id,seq DESC);
CREATE INDEX management_audit_age ON management_audit(occurred_at);

CREATE TRIGGER audit_session_create AFTER INSERT ON admin_sessions
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (NEW.user_id,'session.created',NEW.user_id,NULL,NULL,NULL);
END;

CREATE TRIGGER audit_session_replace AFTER UPDATE ON admin_sessions
WHEN OLD.token_digest<>NEW.token_digest
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (NEW.user_id,'session.replaced',NEW.user_id,NULL,NULL,NULL);
END;

CREATE TRIGGER audit_session_remove AFTER DELETE ON admin_sessions
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (OLD.user_id,'session.removed',OLD.user_id,NULL,NULL,NULL);
END;

CREATE TRIGGER audit_pairing_create AFTER INSERT ON device_pairings
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (NEW.owner_id,'pairing.issued',NEW.owner_id,NULL,NULL,NULL);
END;

CREATE TRIGGER audit_pairing_replace AFTER UPDATE ON device_pairings
WHEN OLD.code_digest<>NEW.code_digest
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (NEW.owner_id,'pairing.replaced',NEW.owner_id,NULL,NULL,NULL);
END;

CREATE TRIGGER audit_device_enroll AFTER INSERT ON devices
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (NEW.owner_id,'device.created',NEW.id,NEW.revision,NULL,NULL);
END;

CREATE TRIGGER audit_device_auth_change AFTER UPDATE OF enabled,credential_digest ON devices
WHEN OLD.enabled<>NEW.enabled OR OLD.credential_digest<>NEW.credential_digest
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (NEW.owner_id,'device.authorization_changed',NEW.id,NEW.revision,NULL,CASE WHEN NEW.enabled=1 THEN 'enabled' ELSE 'disabled' END);
END;

CREATE TRIGGER audit_domain_create AFTER INSERT ON domains
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (NEW.owner_id,'domain.created',NEW.id,NULL,NULL,NULL);
END;

CREATE TRIGGER audit_domain_proof AFTER UPDATE OF verification_token,verified_at ON domains
WHEN OLD.verification_token IS NOT NEW.verification_token OR OLD.verified_at IS NOT NEW.verified_at
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (NEW.owner_id,'domain.proof_changed',NEW.id,NULL,NULL,CASE WHEN NEW.verified_at IS NULL THEN 'unverified' ELSE 'verified' END);
END;

CREATE TRIGGER audit_domain_remove AFTER DELETE ON domains
BEGIN
    INSERT INTO management_audit(owner_id,event,resource_id,revision,request_id,state)
    VALUES (OLD.owner_id,'domain.deleted',OLD.id,NULL,NULL,NULL);
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
