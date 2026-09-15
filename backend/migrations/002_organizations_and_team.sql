-- Migration: organizations + team invites (issue #265 "Invite Team")
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Problem this solves: today every `users` row and every `cloud_accounts`
-- row is a fully independent island — nothing groups multiple users
-- together as "one company's team". Inviting a team member has nowhere
-- to invite them INTO. This migration adds that shared grouping.
--
-- Note on cloud_accounts: docs/internal/architecture/aws/aws_rds_installation.md
-- describes cloud_accounts.user_id (FK to users.id), but the actual deployed
-- code (get-dashboard-data/lambda_function.py, and mark_account_disconnected /
-- get_account_contact in config/database.py) reads and writes
-- cloud_accounts.owner_email instead. That doc appears stale. This migration
-- follows the verified, actually-deployed column (owner_email), not the doc.
-- Worth reconciling the doc separately.
--
-- Backwards compatible: every existing user is backfilled into their own
-- single-person organization, so nothing that already works breaks.

-- ── organizations ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS organizations (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- IMPORTANT: the existing Cognito post-confirmation trigger that creates a
-- new `users` row on signup (see aws_rds_installation.md — "Populated
-- automatically by Cognito post-confirmation trigger") is NOT in this repo
-- and only ever inserted (cognito_sub, email, full_name). Once
-- organization_id below is made NOT NULL, that unmodified trigger would
-- start failing on every new signup.
--
-- Fix: a BEFORE INSERT trigger on `users` that auto-creates a solo
-- organization whenever a row arrives without one. This means the
-- existing signup code needs zero changes AND "a brand new user starts in
-- their own organization" keeps working — it's just enforced here instead
-- of in application code we don't have access to.
CREATE OR REPLACE FUNCTION assign_default_organization() RETURNS TRIGGER AS $$
DECLARE
    new_org_id UUID;
BEGIN
    IF NEW.organization_id IS NULL THEN
        INSERT INTO organizations (name)
        VALUES (COALESCE(NULLIF(NEW.full_name, ''), NEW.email, 'New organization'))
        RETURNING id INTO new_org_id;
        NEW.organization_id := new_org_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_default_organization ON users;
CREATE TRIGGER users_default_organization
    BEFORE INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION assign_default_organization();

-- ── users: which organization + what role within it ─────────────────
-- Role set matches the PVA's own Step 2 wording exactly (#265):
-- "Assign roles (Admin, Security, Compliance, Viewer)". Anything beyond
-- these four (custom roles, permission inheritance, ...) is out of scope
-- for this first pass.
ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'admin'
    CHECK (role IN ('admin', 'security', 'compliance', 'viewer'));
-- 'deactivated' covers the PVA's "Remove users / Suspend or deactivate
-- accounts" — deliberately not a hard DELETE, so findings/audit history
-- tied to this user's actions stay intact.
ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'deactivated'));

-- Backfill: every existing user who has no organization yet gets their own,
-- named after them, and keeps their default 'admin' role (they were the
-- only user of their data before this migration, so this doesn't change
-- what they can already do).
DO $$
DECLARE
    u RECORD;
    new_org_id UUID;
BEGIN
    FOR u IN SELECT id, email, full_name FROM users WHERE organization_id IS NULL LOOP
        INSERT INTO organizations (name)
        VALUES (COALESCE(NULLIF(u.full_name, ''), u.email))
        RETURNING id INTO new_org_id;

        UPDATE users SET organization_id = new_org_id WHERE id = u.id;
    END LOOP;
END $$;

ALTER TABLE users ALTER COLUMN organization_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);

-- ── cloud_accounts: which organization owns this connected AWS account ──
ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);

UPDATE cloud_accounts ca
SET organization_id = u.organization_id
FROM users u
WHERE ca.owner_email = u.email
  AND ca.organization_id IS NULL;

-- Left nullable on purpose: if owner_email doesn't match any users row
-- (e.g. a stale/orphaned account), backfill can't resolve an organization
-- for it. Forcing NOT NULL here would fail the whole migration on data we
-- can't safely fix automatically. Investigate any NULLs after running this.
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_organization ON cloud_accounts(organization_id);

-- ── team_invites ──────────────────────────────────────────────────────
-- One row per invitation. The invited person signs up completely
-- normally (existing Cognito flow, untouched) and lands in their own
-- auto-created solo organization via the trigger above. Acceptance then
-- happens via POST /team/accept-invite (api/team_handler.py), called once
-- automatically after their first login: it finds this pending row by
-- email, moves them into organization_id/role from here, and flips this
-- row to 'accepted'. Their now-empty solo organization is left behind
-- (harmless — a brand new user owns nothing yet) rather than deleted.
CREATE TABLE IF NOT EXISTS team_invites (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           TEXT        NOT NULL,
    role            VARCHAR(20) NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('admin', 'security', 'compliance', 'viewer')),
    invited_by      UUID        REFERENCES users(id),
    status          VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'revoked')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at     TIMESTAMPTZ,
    UNIQUE (organization_id, email)
);

CREATE INDEX IF NOT EXISTS idx_team_invites_organization ON team_invites(organization_id);

-- Allow the Lambda role to read/write the new tables and columns
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON team_invites   TO cspm_lambda;
