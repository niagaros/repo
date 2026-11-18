-- Minimal pre-existing tables the CIEM handler touches, for local PostgreSQL tests.
-- cloud_accounts as in production (owner_email, role_arn, external_id); workspace_integrations reduced to the
-- columns integrations_handler._load reads (the real 028 also needs audit_findings from 018).
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cspm_lambda') THEN CREATE ROLE cspm_lambda; END IF;
END $$;
CREATE TABLE IF NOT EXISTS cloud_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_email TEXT NOT NULL,
    account_id VARCHAR(50) NOT NULL,
    account_name VARCHAR(255),
    role_arn VARCHAR(512) NOT NULL DEFAULT 'arn:aws:iam::111122223333:role/CSPMScannerRole',
    external_id VARCHAR(255),
    status VARCHAR(20) DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS workspace_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider TEXT NOT NULL, site_url TEXT, account_email TEXT, project TEXT, secret_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
