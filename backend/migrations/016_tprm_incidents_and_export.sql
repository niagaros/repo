-- Migration: TPRM known-incident log + registration number (GitHub issue #261, continued)
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- "Breach notifications" and "financial stability" from the issue have no
-- real automated data source in this codebase (no breach-monitoring or
-- credit-check API is configured/paid for here) — automating either would
-- mean inventing data. What IS real and honest: letting an admin record a
-- specific, real, publicly-reported incident they actually read about
-- (with a source URL so it's checkable), and letting a vendor's own real
-- company registration number be stored for a human to look up in a real
-- public registry (KVK, Companies House, etc.) — neither is computed or
-- verified by this platform, both are exactly what they claim to be.

CREATE TABLE IF NOT EXISTS tprm_incidents (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id      UUID         NOT NULL REFERENCES tprm_vendors(id) ON DELETE CASCADE,
    title          VARCHAR(255) NOT NULL,
    description    TEXT,
    source_url     VARCHAR(500),
    occurred_date  DATE,
    reported_by    VARCHAR(255),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

ALTER TABLE tprm_vendors
    ADD COLUMN IF NOT EXISTS registration_number VARCHAR(100);

CREATE INDEX IF NOT EXISTS tprm_incidents_vendor_idx ON tprm_incidents(vendor_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_incidents TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_vendors TO cspm_lambda;
