-- github_integrations as created by migration 001 (which also registers a scanner row in a table these tests
-- do not have), for the AI Inventory PostgreSQL tests.
CREATE TABLE IF NOT EXISTS github_integrations (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id    UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    org_name            TEXT        NOT NULL,
    github_token_secret TEXT        NOT NULL,
    installed_by        TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS github_integrations_account_uq ON github_integrations(cloud_account_id);
