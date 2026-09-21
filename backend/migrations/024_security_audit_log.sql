-- Audit events for denied cross-tenant access (issue #279). Applied via notification-handler {"action":"migrate"}.
CREATE TABLE IF NOT EXISTS security_audit_log (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type        TEXT NOT NULL,
    actor_email       TEXT,
    cloud_account_ids UUID[] NOT NULL DEFAULT '{}',
    http_method       TEXT,
    path              TEXT,
    source_ip         TEXT,
    detail            JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_security_audit_accounts ON security_audit_log USING GIN (cloud_account_ids);
CREATE INDEX IF NOT EXISTS idx_security_audit_time ON security_audit_log (occurred_at DESC);
