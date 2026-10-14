-- Migration: shared resources (issue #265, acceptance criterion #5)
-- Run as cspm_admin
--
-- "Given an administrator shares a dashboard with a team, when team
--  membership changes, then access is updated automatically based on
--  current membership."
--
-- Scope for this MVP pass: only 'dashboard' as a resource_type (the type
-- literally named in the criterion). The PVA's broader "Shared Resources"
-- list (reports, compliance projects, risk registers, API keys, ...) is
-- a much larger feature area, explicitly out of scope here.
--
-- Design choice that makes "access updated automatically" true almost
-- for free: there is no separate access-grant table listing who can see
-- a shared resource. Access is computed live as "every ACTIVE member of
-- this organization" every time the resource list is read (see
-- Database.get_organization_members / the new list_shared_resources
-- query) — so a newly invited member sees it immediately, and an
-- offboarded member loses access immediately, with no separate step to
-- keep in sync.
--
-- "with a team" is interpreted as "with the organization" rather than a
-- named sub-team, since Niagaros has no sub-team/department concept yet
-- (the PVA's "Groups & Teams" section — departments, dynamic groups — is
-- its own, larger, unbuilt feature area).

CREATE TABLE IF NOT EXISTS shared_resources (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource_type   VARCHAR(50) NOT NULL DEFAULT 'dashboard',
    resource_name   TEXT        NOT NULL,
    created_by      UUID        REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_shared_resources_org ON shared_resources(organization_id);

GRANT SELECT, INSERT, DELETE ON shared_resources TO cspm_lambda;
