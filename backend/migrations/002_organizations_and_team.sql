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
-- LET OP: deze tabel bestaat al op de productiedatabase — hij is niet door
-- deze migratie aangemaakt. Het platform had al een (nog ongebruikt, 0 rijen)
-- organisatiebegrip met een bijbehorende `org_members`-tabel. Door de
-- IF NOT EXISTS slaat dit statement daar stilzwijgend overheen, dus de
-- definitie hieronder moet exact overeenkomen met wat er al staat — anders
-- werkt deze migratie lokaal wel en in productie niet.
--
-- Het verschil dat ertoe doet is `owner_email`: verplicht en zonder
-- standaardwaarde. Elke INSERT in deze tabel moet die kolom dus meegeven.
CREATE TABLE IF NOT EXISTS organizations (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    owner_email TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
        INSERT INTO organizations (name, owner_email)
        VALUES (COALESCE(NULLIF(NEW.full_name, ''), NEW.email, 'New organization'),
                NEW.email)
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
        INSERT INTO organizations (name, owner_email)
        VALUES (COALESCE(NULLIF(u.full_name, ''), u.email), u.email)
        RETURNING id INTO new_org_id;

        UPDATE users SET organization_id = new_org_id WHERE id = u.id;
    END LOOP;
END $$;

ALTER TABLE users ALTER COLUMN organization_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);

-- ── cloud_accounts: deliberately NOT given an organization_id ─────────
-- An earlier version of this migration added `cloud_accounts.organization_id`
-- and backfilled it. That column has been removed again, because nothing
-- reads it: every caller goes through
-- Database.list_organization_cloud_accounts(), which resolves ownership as
--     cloud_accounts.owner_email -> users.email -> users.organization_id
-- and never touches a column on cloud_accounts itself.
--
-- A column that is never read is not harmless. Against the real production
-- data the backfill resolved 0 of 6 rows (all six accounts carry an
-- owner_email belonging to someone who never registered), so the column
-- would sit there permanently empty while looking authoritative. Two
-- competing answers to "which organization owns this account" in one schema
-- is how someone later trusts the wrong one — silently, with no error and
-- no failing test, because no code exercises it.
--
-- If a direct link is ever genuinely needed — an account managed by several
-- people, or an owner moving between organizations — it should be added
-- together with the code that reads it.

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
