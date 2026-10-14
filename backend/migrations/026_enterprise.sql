-- Organizations, business units, members (issue #279). Applied via enterprise-handler {"action":"migrate"}.
CREATE TABLE IF NOT EXISTS organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS business_units (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);
CREATE TABLE IF NOT EXISTS bu_accounts (
    business_unit_id UUID NOT NULL REFERENCES business_units(id) ON DELETE CASCADE,
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    assigned_by      TEXT,
    assigned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (business_unit_id, cloud_account_id)
);
CREATE TABLE IF NOT EXISTS org_members (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email            TEXT NOT NULL,
    role             TEXT NOT NULL CHECK (role IN ('org_admin', 'bu_admin', 'viewer')),
    business_unit_id UUID REFERENCES business_units(id) ON DELETE CASCADE,
    invited_by       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS org_members_unique ON org_members (organization_id, lower(email), COALESCE(business_unit_id, '00000000-0000-0000-0000-000000000000'::uuid));
CREATE INDEX IF NOT EXISTS org_members_email_idx ON org_members (lower(email));
CREATE INDEX IF NOT EXISTS bu_accounts_account_idx ON bu_accounts (cloud_account_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, business_units, bu_accounts, org_members TO cspm_lambda;
