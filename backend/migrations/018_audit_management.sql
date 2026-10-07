-- Migration: Audit Management, v1 (GitHub issue #260)
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Scope decision: issue #260's Proposed Solution describes a full standalone
-- audit-GRC platform (annual audit calendar with calendar-app integration,
-- real-time multi-user collaboration, formal sampling/interview tooling,
-- automated escalation workflows, and support for a framework named "OFDSS"
-- that does not correspond to any real, recognized standard). Building all
-- of that in one pass would mean either faking integrations this codebase
-- has no real connection to, or inventing a framework this platform cannot
-- actually verify anything against — both violate this codebase's standing
-- "no fabricated evidence" rule.
--
-- What's built instead, for real: audit records with a findings register
-- auto-seeded from this account's own live scan data for the audit's
-- framework (the same findings already verified elsewhere in this product —
-- no new measurement, just a new lens on data that already exists), manual
-- findings for non-technical auditor observations, remediation tracking
-- (mirrors the already-built, already-tested TPRM remediation-task pattern),
-- and evidence linking to documents already in the Trust Center vault
-- (reuse, not a second copy of the same file). "OFDSS" is left out of the
-- framework picklist below rather than silently invented or silently
-- dropped — see docs/internal/architecture/aws/audit_management.md.

CREATE TABLE IF NOT EXISTS audits (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    title              VARCHAR(255) NOT NULL,
    audit_type         VARCHAR(30)  NOT NULL DEFAULT 'internal',
    framework          VARCHAR(100),
    scope_description  TEXT,
    status             VARCHAR(20)  NOT NULL DEFAULT 'planned',
    lead_auditor_name  VARCHAR(255),
    lead_auditor_org   VARCHAR(255),
    stakeholders       TEXT,
    start_date         DATE,
    end_date           DATE,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_findings (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id      UUID         NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    source        VARCHAR(10)  NOT NULL DEFAULT 'manual', -- 'scan' | 'manual'
    check_id      VARCHAR(100),
    resource_name VARCHAR(255),
    title         VARCHAR(500) NOT NULL,
    description   TEXT,
    remediation   TEXT,
    severity      VARCHAR(20)  NOT NULL DEFAULT 'MEDIUM',
    risk_rating   VARCHAR(20),
    root_cause    TEXT,
    status        VARCHAR(20)  NOT NULL DEFAULT 'open', -- open, in_remediation, verified, closed
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_remediation_tasks (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_finding_id    UUID         NOT NULL REFERENCES audit_findings(id) ON DELETE CASCADE,
    title               VARCHAR(500) NOT NULL,
    owner_name          VARCHAR(255),
    owner_email         VARCHAR(255),
    due_date            DATE,
    status              VARCHAR(20)  NOT NULL DEFAULT 'open', -- open, in_progress, completed, verified
    verification_notes  TEXT,
    verified_by         VARCHAR(255),
    verified_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_evidence (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id             UUID         NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    audit_finding_id     UUID         REFERENCES audit_findings(id) ON DELETE SET NULL,
    title                VARCHAR(255) NOT NULL,
    source               VARCHAR(20)  NOT NULL DEFAULT 'upload', -- upload | trust_center
    s3_key               VARCHAR(500),
    trust_document_id    UUID         REFERENCES trust_documents(id) ON DELETE SET NULL,
    filename             VARCHAR(255),
    uploaded_by          VARCHAR(255),
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audits_account_idx ON audits(cloud_account_id);
CREATE INDEX IF NOT EXISTS audit_findings_audit_idx ON audit_findings(audit_id);
CREATE INDEX IF NOT EXISTS audit_remediation_finding_idx ON audit_remediation_tasks(audit_finding_id);
CREATE INDEX IF NOT EXISTS audit_evidence_audit_idx ON audit_evidence(audit_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON audits TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_findings TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_remediation_tasks TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_evidence TO cspm_lambda;
