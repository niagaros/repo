-- Migration: Third-Party Risk Management (TPRM), v1 (GitHub issue #261)
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Scope decision: issue #261's Proposed Solution describes a full standalone
-- TPRM product (procurement/CMDB/ticketing integrations, AI questionnaire
-- review, breach/dark-web monitoring, financial-stability scoring, executive
-- reporting). Building all of that in one pass would mean either faking
-- integrations this codebase has no real connection to, or inventing risk
-- signals (breach data, financial health, dark-web exposure) with no real
-- data source — both violate this codebase's standing "no fabricated
-- evidence" rule.
--
-- What's built instead, for real: a vendor registry with risk scoring from
-- only the factors this platform can actually verify — vendor-declared
-- criticality, real certification expiry dates, and whether a real security
-- assessment has actually been received and approved for that vendor.
--
-- Note on Questionnaire Automation (issue #259): that feature answers
-- questionnaires sent TO this account by ITS customers, using this
-- account's own findings/evidence — the opposite direction from TPRM, which
-- tracks questionnaires this account sends OUT to ITS vendors. Its data
-- model (drafting answers from the account's own control evidence) doesn't
-- fit a vendor's self-reported assessment, so TPRM gets its own
-- tprm_assessments table below rather than forcing a reuse that would
-- misrepresent whose evidence a vendor's answers actually are.
-- See docs/internal/architecture/aws/tprm.md for the full scope table.

CREATE TABLE IF NOT EXISTS tprm_vendors (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    name              VARCHAR(255) NOT NULL,
    category          VARCHAR(100),
    criticality       VARCHAR(20)  NOT NULL DEFAULT 'medium',
    business_owner    VARCHAR(255),
    contact_email     VARCHAR(255),
    website           VARCHAR(255),
    status            VARCHAR(20)  NOT NULL DEFAULT 'active',
    notes             TEXT,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tprm_assessments (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id           UUID         NOT NULL REFERENCES tprm_vendors(id) ON DELETE CASCADE,
    questionnaire_type  VARCHAR(50)  NOT NULL DEFAULT 'custom',
    status              VARCHAR(20)  NOT NULL DEFAULT 'not_sent',
    sent_at             TIMESTAMPTZ,
    received_at         TIMESTAMPTZ,
    approved_at         TIMESTAMPTZ,
    s3_key              VARCHAR(500),
    filename            VARCHAR(255),
    notes               TEXT,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tprm_certifications (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id           UUID         NOT NULL REFERENCES tprm_vendors(id) ON DELETE CASCADE,
    certification_type  VARCHAR(50)  NOT NULL,
    issued_date         DATE,
    expiry_date         DATE,
    s3_key              VARCHAR(500),
    filename            VARCHAR(255),
    uploaded_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tprm_audit_log (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id   UUID         NOT NULL REFERENCES tprm_vendors(id) ON DELETE CASCADE,
    actor       VARCHAR(255),
    action      VARCHAR(50)  NOT NULL,
    at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS tprm_vendors_account_idx ON tprm_vendors(cloud_account_id);
CREATE INDEX IF NOT EXISTS tprm_certifications_vendor_idx ON tprm_certifications(vendor_id);
CREATE INDEX IF NOT EXISTS tprm_assessments_vendor_idx ON tprm_assessments(vendor_id);
CREATE INDEX IF NOT EXISTS tprm_audit_log_vendor_idx ON tprm_audit_log(vendor_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_vendors TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_certifications TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_assessments TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_audit_log TO cspm_lambda;
