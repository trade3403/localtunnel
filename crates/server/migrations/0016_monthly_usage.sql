-- UTC calendar-month prepaid application stream budget. A committed debit
-- is never refunded, even if a following write fails or the worker crashes.
CREATE TABLE tenant_monthly_usage (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    month_utc TEXT NOT NULL CHECK(length(month_utc)=7 AND month_utc GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]'),
    charged_bytes INTEGER NOT NULL CHECK(charged_bytes BETWEEN 0 AND 9000000000000000),
    PRIMARY KEY(tenant_id,month_utc)
) STRICT;
ALTER TABLE bandwidth_reservations ADD COLUMN monthly_cap INTEGER
    CHECK(monthly_cap BETWEEN 1 AND 9000000000000000);
