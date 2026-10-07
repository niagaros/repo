-- Migration: custom_frameworks / custom_framework_controls
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Lets a customer define their own compliance framework made up of
-- controls they compose themselves out of the product's existing, real
-- check catalog (CIS/FSBP/GitHub checks already scanned for their
-- account). This is a product feature, not a published standard —
-- unlike every other *_mapper_handler.py in this codebase, the mapping
-- (which check_ids belong to which control) is user-authored data, not
-- a hardcoded, research-backed dict. The scoring mechanism reused is
-- identical to every other framework: a control FAILs if any of its
-- mapped checks currently FAIL for a resource.

CREATE TABLE IF NOT EXISTS custom_frameworks (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    name             VARCHAR(255) NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS custom_framework_controls (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    custom_framework_id UUID         NOT NULL REFERENCES custom_frameworks(id) ON DELETE CASCADE,
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
    severity            VARCHAR(20)  NOT NULL DEFAULT 'MEDIUM',
    remediation         TEXT,
    mapped_checks       JSONB        NOT NULL DEFAULT '[]',
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS custom_frameworks_account_idx ON custom_frameworks(cloud_account_id);
CREATE INDEX IF NOT EXISTS custom_framework_controls_framework_idx ON custom_framework_controls(custom_framework_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON custom_frameworks TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON custom_framework_controls TO cspm_lambda;

-- Register the mapper half of custom_framework_handler.py so it runs
-- automatically in the orchestrator's mapper wave for every account,
-- exactly like every other *_mapper_handler.py.
INSERT INTO scanners (function_name, resource_type, description, enabled)
VALUES ('custom-framework-handler', 'compliance', 'User-defined Custom Frameworks (product feature, not a published standard)', true)
ON CONFLICT (function_name) DO NOTHING;
