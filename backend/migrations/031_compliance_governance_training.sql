-- Onboarding steps 5, 6 and 7 (#270): Configure Compliance (#281),
-- Configure Governance (#282) and Complete Security Training.
--
-- Everything is scoped to an organization (users.organization_id, from
-- 002_organizations_and_team.sql), the same tenant boundary the team and
-- auditor steps use. UUID keys throughout: the runtime role cannot use
-- sequences created by the admin role.
--
-- Changes are recorded in the existing team_audit_log (003), so the
-- organization keeps one audit trail instead of one per module.

-- ── Step 5: compliance frameworks the organization has chosen ─────────
-- framework_name is validated in the handler against the frameworks
-- Niagaros actually maps findings to (MAPPED_FRAMEWORK_NAMES); no CHECK
-- here, so adding a framework does not need a migration.
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    framework_name       TEXT        NOT NULL,
    enabled              BOOLEAN     NOT NULL DEFAULT true,
    version              TEXT,
    owner_email          TEXT,
    certification_status VARCHAR(20) NOT NULL DEFAULT 'not_started'
        CHECK (certification_status IN ('not_started', 'in_progress', 'certified', 'expired')),
    effective_date       DATE,
    expiration_date      DATE,
    updated_by           UUID,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, framework_name),
    CHECK (expiration_date IS NULL OR effective_date IS NULL OR expiration_date >= effective_date)
);

CREATE TABLE IF NOT EXISTS compliance_certifications (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name               TEXT        NOT NULL,
    standard           TEXT        NOT NULL,
    status             VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'in_renewal', 'suspended', 'expired')),
    certification_body TEXT,
    issue_date         DATE,
    expiration_date    DATE,
    renewal_date       DATE,
    created_by         UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expiration_date IS NULL OR issue_date IS NULL OR expiration_date >= issue_date)
);

-- ── Step 6: governance policies, versioned, with approval ─────────────
-- A policy is the stable identity; its text lives in versions. Publishing
-- a new version never overwrites an old one, so history stays auditable.
CREATE TABLE IF NOT EXISTS governance_policies (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                     TEXT        NOT NULL,
    category                 TEXT        NOT NULL,
    owner_email              TEXT        NOT NULL,
    approver_email           TEXT        NOT NULL,
    review_date              DATE,
    requires_acknowledgement BOOLEAN     NOT NULL DEFAULT true,
    published_version        INTEGER,
    retired                  BOOLEAN     NOT NULL DEFAULT false,
    created_by               UUID,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS governance_policy_versions (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id      UUID        NOT NULL REFERENCES governance_policies(id) ON DELETE CASCADE,
    version        INTEGER     NOT NULL,
    content        TEXT        NOT NULL,
    change_summary TEXT,
    status         VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'pending_approval', 'approved', 'rejected')),
    author_id      UUID        NOT NULL,
    decided_by     UUID,
    decided_at     TIMESTAMPTZ,
    decision_note  TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (policy_id, version),
    -- Separation of duties, enforced in the database as well as the handler:
    -- nobody approves their own text.
    CHECK (decided_by IS NULL OR decided_by <> author_id)
);

-- Exceptions never silently bypass a requirement: justification, risk,
-- owner and an end date are mandatory, and only an approved, unexpired
-- exception counts as active (computed on read, not stored).
CREATE TABLE IF NOT EXISTS governance_exceptions (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_id             UUID        REFERENCES governance_policies(id) ON DELETE SET NULL,
    requirement           TEXT        NOT NULL,
    justification         TEXT        NOT NULL,
    risk                  VARCHAR(10) NOT NULL CHECK (risk IN ('low', 'medium', 'high', 'critical')),
    compensating_controls TEXT,
    scope                 TEXT,
    owner_email           TEXT        NOT NULL,
    requested_by          UUID        NOT NULL,
    status                VARCHAR(20) NOT NULL DEFAULT 'requested'
        CHECK (status IN ('requested', 'approved', 'rejected', 'revoked')),
    start_date            DATE        NOT NULL DEFAULT CURRENT_DATE,
    expiration_date       DATE        NOT NULL,
    decided_by            UUID,
    decided_at            TIMESTAMPTZ,
    decision_note         TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expiration_date >= start_date),
    CHECK (decided_by IS NULL OR decided_by <> requested_by)
);

-- ── Step 7: security training = reading and acknowledging policies ────
-- One row per person per policy version: a new version needs a new
-- acknowledgement, an old one stays on record.
CREATE TABLE IF NOT EXISTS policy_acknowledgements (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_id       UUID        NOT NULL REFERENCES governance_policies(id) ON DELETE CASCADE,
    version         INTEGER     NOT NULL,
    user_id         UUID        NOT NULL,
    acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (policy_id, version, user_id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_frameworks_org ON compliance_frameworks(organization_id);
CREATE INDEX IF NOT EXISTS idx_compliance_certifications_org ON compliance_certifications(organization_id);
CREATE INDEX IF NOT EXISTS idx_governance_policies_org ON governance_policies(organization_id);
CREATE INDEX IF NOT EXISTS idx_governance_policy_versions_policy ON governance_policy_versions(policy_id);
CREATE INDEX IF NOT EXISTS idx_governance_exceptions_org ON governance_exceptions(organization_id);
CREATE INDEX IF NOT EXISTS idx_policy_acknowledgements_org ON policy_acknowledgements(organization_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_frameworks      TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_certifications  TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE         ON governance_policies        TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE         ON governance_policy_versions TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE         ON governance_exceptions      TO cspm_lambda;
GRANT SELECT, INSERT                 ON policy_acknowledgements    TO cspm_lambda;

-- Production has default privileges that give cspm_lambda SELECT, INSERT, UPDATE
-- and DELETE on every new table. Take back what the runtime must not have: policy
-- history, exceptions and acknowledgements are audit evidence and are never
-- deleted (or, for acknowledgements, changed) by the application.
REVOKE DELETE         ON governance_policies, governance_policy_versions, governance_exceptions FROM cspm_lambda;
REVOKE UPDATE, DELETE ON policy_acknowledgements FROM cspm_lambda;
