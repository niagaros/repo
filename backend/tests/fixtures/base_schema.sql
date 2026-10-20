-- Minimal pre-migration schema for local Postgres tests: the parts of the
-- production database that predate backend/migrations (users comes from
-- docs/internal/architecture/aws/aws_rds_installation.md).
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cspm_lambda') THEN
        CREATE ROLE cspm_lambda;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cognito_sub VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);
