-- External auditor access (issue #279). Applied via audit-management-handler {"migrate": true}.
-- External auditors get a per-audit, revocable, expiring secret link. Only the SHA-256 of the token is stored.
CREATE TABLE IF NOT EXISTS audit_auditor_access (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id      UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    auditor_email TEXT NOT NULL,
    auditor_name  TEXT,
    token_hash    TEXT NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS audit_auditor_access_audit_idx ON audit_auditor_access(audit_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_auditor_access TO cspm_lambda;
