-- V0.8 additive tenant and plan inventory. Existing owner-scoped authorization
-- is unchanged. This migration does NOT grant cross-owner membership or
-- enable enforcement of configurable commercial limits.
CREATE TABLE commercial_plans (
    id TEXT PRIMARY KEY NOT NULL,
    code TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version>=1),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    max_active_devices INTEGER NOT NULL CHECK(max_active_devices BETWEEN 1 AND 64),
    max_retained_devices INTEGER NOT NULL CHECK(max_retained_devices BETWEEN max_active_devices AND 256),
    max_mappings INTEGER NOT NULL CHECK(max_mappings BETWEEN 1 AND 4096),
    max_bandwidth_bps INTEGER CHECK(max_bandwidth_bps>0),
    max_monthly_bytes INTEGER CHECK(max_monthly_bytes>0),
    max_concurrent_connections INTEGER CHECK(max_concurrent_connections>0),
    UNIQUE(code,version)
) STRICT;

-- Null means a policy has not been configured, not measured usage of zero.
INSERT INTO commercial_plans VALUES
    ('legacy-v1','legacy',1,'Legacy preview',64,256,4096,NULL,NULL,NULL);

CREATE TABLE tenants (
    id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
    owner_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL DEFAULT(unixepoch())
) STRICT;
CREATE TABLE tenant_entitlements (
    tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL REFERENCES commercial_plans(id),
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','suspended')),
    expires_at INTEGER CHECK(expires_at>0),
    revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>=1),
    updated_at INTEGER NOT NULL DEFAULT(unixepoch())
) STRICT;

INSERT INTO tenants(id,owner_id,created_at)
SELECT lower(hex(randomblob(16))),id,created_at FROM users;
INSERT INTO tenant_entitlements(tenant_id,plan_id)
SELECT id,'legacy-v1' FROM tenants;

-- Covers the existing bootstrap and future operator-created users in the
-- same transaction. The tenant ID is an identifier, not a credential.
CREATE TRIGGER commercial_tenant_for_user AFTER INSERT ON users
BEGIN
    INSERT INTO tenants(id,owner_id) VALUES(lower(hex(randomblob(16))),NEW.id);
    INSERT INTO tenant_entitlements(tenant_id,plan_id)
    SELECT id,'legacy-v1' FROM tenants WHERE owner_id=NEW.id;
END;
