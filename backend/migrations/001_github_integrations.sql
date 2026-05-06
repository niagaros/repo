-- Migration: github_integrations table
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Stores one row per customer GitHub organization.
-- github_token_secret is the AWS Secrets Manager secret name (not the token itself).
-- The secret's SecretString should be either plain-text PAT
-- or a JSON object: {"github_token": "<pat>"}
--
-- Required PAT scopes: repo, read:org, admin:org

CREATE TABLE IF NOT EXISTS github_integrations (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id    UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    org_name            TEXT        NOT NULL,
    github_token_secret TEXT        NOT NULL,   -- Secrets Manager secret name/ARN
    installed_by        TEXT,                   -- email of user who connected GitHub
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS github_integrations_account_uq
    ON github_integrations(cloud_account_id);

-- Allow the Lambda role (cspm_lambda) to read/write this table
GRANT SELECT, INSERT, UPDATE, DELETE ON github_integrations TO cspm_lambda;

-- Register the scanner in the scanners table so the orchestrator picks it up.
-- Change the function_name to whatever you deploy the Lambda as.
INSERT INTO scanners (function_name, resource_type, description, enabled)
VALUES (
    'github-cis-scanner',
    'github_repository',
    'CIS GitHub Benchmark v1.0.0 — automated checks (branch protection, MFA, secret scanning)',
    true
)
ON CONFLICT (function_name) DO NOTHING;
