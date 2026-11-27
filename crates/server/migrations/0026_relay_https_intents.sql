-- HTTPS exact hostname/verified proof and fixed dedicated gateway port.
CREATE TABLE relay_https_intents (
    grant_id TEXT PRIMARY KEY NOT NULL REFERENCES relay_grants(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    relay_port INTEGER NOT NULL CHECK(relay_port BETWEEN 30000 AND 59999),
    bind_port INTEGER NOT NULL CHECK(bind_port BETWEEN 20000 AND 29999),
    gateway_port INTEGER NOT NULL CHECK(gateway_port BETWEEN 60000 AND 64999),
    domain_id TEXT NOT NULL REFERENCES domains(id),
    hostname TEXT NOT NULL CHECK(length(hostname) BETWEEN 1 AND 240),
    certificate_sha256 TEXT NOT NULL CHECK(length(certificate_sha256)=64 AND certificate_sha256 NOT GLOB '*[^0-9a-f]*'),
    proof_token TEXT NOT NULL,
    verified_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL CHECK(created_at>0),
    claimed_at INTEGER CHECK(claimed_at>=created_at),
    UNIQUE(node_id,relay_port),
    UNIQUE(node_id,gateway_port)
) STRICT;
CREATE TRIGGER relay_https_intent_validate BEFORE INSERT ON relay_https_intents
WHEN NEW.claimed_at IS NOT NULL OR NOT EXISTS(
    SELECT 1 FROM relay_grants g JOIN relay_allocations a ON a.id=g.allocation_id
    JOIN mappings m ON m.id=g.mapping_id JOIN domains d ON d.id=m.domain_id AND d.owner_id=m.owner_id
    WHERE g.id=NEW.grant_id AND g.node_id=NEW.node_id AND a.node_id=NEW.node_id
    AND a.generation=g.generation AND a.state='reserved' AND a.live_mapping_id=m.id
    AND m.protocol='https' AND m.enabled=0 AND m.bind_port=NEW.bind_port
    AND d.id=NEW.domain_id AND d.hostname=NEW.hostname AND d.verification_token=NEW.proof_token
    AND d.verified_at=NEW.verified_at AND d.verified_at BETWEEN NEW.created_at-285 AND NEW.created_at
    AND g.revoked_at IS NULL AND g.issued_at<=NEW.created_at AND g.expires_at>NEW.created_at)
BEGIN SELECT RAISE(ABORT,'invalid HTTPS intent binding'); END;
CREATE TRIGGER relay_https_intent_one_shot BEFORE UPDATE ON relay_https_intents
WHEN NEW.grant_id<>OLD.grant_id OR NEW.node_id<>OLD.node_id OR NEW.relay_port<>OLD.relay_port
 OR NEW.bind_port<>OLD.bind_port OR NEW.gateway_port<>OLD.gateway_port OR NEW.domain_id<>OLD.domain_id
 OR NEW.hostname<>OLD.hostname OR NEW.certificate_sha256<>OLD.certificate_sha256 OR NEW.proof_token<>OLD.proof_token OR NEW.verified_at<>OLD.verified_at
 OR NEW.created_at<>OLD.created_at OR OLD.claimed_at IS NOT NULL OR NEW.claimed_at IS NULL
BEGIN SELECT RAISE(ABORT,'HTTPS intent is immutable after claim'); END;
CREATE TRIGGER relay_https_intent_no_delete BEFORE DELETE ON relay_https_intents
BEGIN SELECT RAISE(ABORT,'HTTPS intent requires reconciliation'); END;
CREATE TRIGGER relay_https_transport_exclusive BEFORE INSERT ON relay_https_intents
WHEN EXISTS(SELECT 1 FROM relay_tcp_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
 OR EXISTS(SELECT 1 FROM relay_udp_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
 OR EXISTS(SELECT 1 FROM relay_http_intents t WHERE t.node_id=NEW.node_id AND (t.relay_port=NEW.relay_port OR t.gateway_port=NEW.gateway_port))
BEGIN SELECT RAISE(ABORT,'transport port reserved'); END;
CREATE TRIGGER relay_tcp_https_transport_exclusive BEFORE INSERT ON relay_tcp_intents
WHEN EXISTS(SELECT 1 FROM relay_https_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
BEGIN SELECT RAISE(ABORT,'transport port reserved by HTTPS'); END;
CREATE TRIGGER relay_udp_https_transport_exclusive BEFORE INSERT ON relay_udp_intents
WHEN EXISTS(SELECT 1 FROM relay_https_intents t WHERE t.node_id=NEW.node_id AND t.relay_port=NEW.relay_port)
BEGIN SELECT RAISE(ABORT,'transport port reserved by HTTPS'); END;

CREATE TRIGGER relay_http_https_transport_exclusive BEFORE INSERT ON relay_http_intents
WHEN EXISTS(SELECT 1 FROM relay_https_intents t WHERE t.node_id=NEW.node_id AND (t.relay_port=NEW.relay_port OR t.gateway_port=NEW.gateway_port))
BEGIN SELECT RAISE(ABORT,'transport or gateway port reserved by HTTPS'); END;
