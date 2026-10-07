-- Migration: TPRM userstory completion pass (GitHub issue #261, continued)
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Re-read the literal issue text line by line against what was built and
-- found real, concrete, missed items — not new invented scope:
--   - "Compliance & Certifications" names NIS2/DORA/ISO42001/HITRUST/CIS/
--     NIST CSF/EU AI Act explicitly; only 6 of these existed as trackable
--     certification types.
--   - "Evidence Management" names audit reports/pentests/policies/
--     insurance certificates/BCPs as distinct evidence, not just
--     certifications.
--   - "Contract renewals" (Continuous Monitoring) and "contracts"
--     (acceptance criterion 5) have no data model at all yet.
--   - Acceptance criterion 3 says notifications go "to the vendor owner" —
--     business_owner was a name with no email to actually notify.
--   - "Data sensitivity" (Risk Scoring) and "service inventory"/"asset
--     relationships" (Vendor Inventory) have no fields yet.
--   - "Findings & Remediation" (risk acceptance, exception management,
--     corrective action tracking, escalation workflows) has nothing built.

ALTER TABLE tprm_vendors
    ADD COLUMN IF NOT EXISTS business_owner_email      VARCHAR(255),
    ADD COLUMN IF NOT EXISTS services_provided         TEXT,
    ADD COLUMN IF NOT EXISTS internal_systems_accessed TEXT,
    ADD COLUMN IF NOT EXISTS handles_sensitive_data    BOOLEAN,
    ADD COLUMN IF NOT EXISTS contract_start_date       DATE,
    ADD COLUMN IF NOT EXISTS contract_end_date         DATE,
    ADD COLUMN IF NOT EXISTS contract_s3_key           VARCHAR(500),
    ADD COLUMN IF NOT EXISTS contract_filename         VARCHAR(255),
    ADD COLUMN IF NOT EXISTS website_tls_valid         BOOLEAN,
    ADD COLUMN IF NOT EXISTS website_checked_at        TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS tprm_remediation_tasks (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id           UUID         NOT NULL REFERENCES tprm_vendors(id) ON DELETE CASCADE,
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
    due_date            DATE,
    status              VARCHAR(20)  NOT NULL DEFAULT 'open',
    assigned_to         VARCHAR(255),
    acceptance_reason   TEXT,
    accepted_by         VARCHAR(255),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS tprm_remediation_tasks_vendor_idx ON tprm_remediation_tasks(vendor_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_vendors TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_remediation_tasks TO cspm_lambda;
