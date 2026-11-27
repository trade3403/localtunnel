-- Trusted local operator mutations and committed audit; no passwords,
-- device credentials or arbitrary operator-provided text in audit rows.
CREATE TABLE commercial_operator_audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL CHECK(event IN ('plan.created','account.created','entitlement.assigned')),
    tenant_id TEXT,
    plan_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision>=1),
    state TEXT CHECK(state IN ('active','suspended')),
    expires_at INTEGER CHECK(expires_at>0),
    occurred_at INTEGER NOT NULL DEFAULT(unixepoch()),
    CHECK((event='plan.created' AND tenant_id IS NULL AND state IS NULL AND expires_at IS NULL)
        OR (event IN ('account.created','entitlement.assigned') AND tenant_id IS NOT NULL AND state IS NOT NULL))
) STRICT;
-- A published version cannot silently change policy for all its holders.
CREATE TRIGGER commercial_plan_immutable_update BEFORE UPDATE ON commercial_plans
BEGIN SELECT RAISE(ABORT,'published plan immutable'); END;
CREATE TRIGGER commercial_plan_immutable_delete BEFORE DELETE ON commercial_plans
BEGIN SELECT RAISE(ABORT,'published plan immutable'); END;
