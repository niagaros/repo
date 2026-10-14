-- Migration: role changes + audit log (issue #265, acceptance criterion #2)
-- Run as cspm_admin
--
-- "Given an administrator modifies a user's role, when the change is
--  saved, then permissions are updated immediately and logged."
--
-- team_audit_log is deliberately generic (a free-text `action` + a JSONB
-- `details` blob) rather than a role-change-specific table. This pass
-- only writes 'role_changed' events, but the same table is meant to be
-- reused for acceptance criterion #6 ("all user, role, and permission
-- changes are available with timestamps and actor information") without
-- another migration — invite_created / invite_revoked / member_deactivated
-- / invite_accepted events can log into it later with no schema change.

CREATE TABLE IF NOT EXISTS team_audit_log (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id   UUID        REFERENCES users(id),
    action          TEXT        NOT NULL,
    target_user_id  UUID        REFERENCES users(id),
    details         JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_team_audit_log_org_time
    ON team_audit_log(organization_id, created_at DESC);

GRANT SELECT, INSERT ON team_audit_log TO cspm_lambda;
