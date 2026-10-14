-- Migration: audit engagements for issue #266 ("Invite Auditors")
-- Run as cspm_admin
--
-- Design choice, matching the pattern already used for shared_resources
-- (issue #265 AC5): an auditor's access is never a stored "yes/no" grant
-- that has to be revoked by a separate step. It is computed live, on
-- every request, from two facts: is there an engagement_auditors row for
-- this email, and is that engagement's end_date still in the future?
-- That is what makes AC3 ("Given an audit engagement reaches its end
-- date, when the engagement closes, then auditor access is automatically
-- revoked") true by construction, the same way AC5 worked for team
-- members — nothing has to run "at midnight on the end date" to flip a
-- flag; the very next request after end_date simply stops matching.
--
-- Auditors are deliberately NOT rows in `users`. The PVA is explicit that
-- auditors must be "securely managed independently from internal users"
-- (often external — audit firms, certification bodies) and are scoped to
-- one engagement, not one organization membership with a role. They are
-- identified purely by email, matched against the same Cognito-
-- authenticated caller identity every other endpoint in this codebase
-- already uses (_get_authenticated_email) — so an auditor still needs a
-- real account in the same Cognito pool to log in at all, but never
-- becomes a member of the audited organization.
--
-- engagement_scope is what makes "only the approved audit scope and
-- evidence are accessible" (AC1) concrete rather than aspirational: scope
-- is a list of the organization's own cloud_accounts, the same real
-- entity the shared-dashboard fix (migration 006) already links to —
-- not a free-text description an admin could type anything into.

CREATE TABLE IF NOT EXISTS audit_engagements (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    start_date      DATE        NOT NULL DEFAULT CURRENT_DATE,
    end_date        DATE        NOT NULL,
    created_by      UUID        REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (end_date >= start_date)
);

CREATE TABLE IF NOT EXISTS engagement_scope (
    engagement_id   UUID NOT NULL REFERENCES audit_engagements(id) ON DELETE CASCADE,
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    PRIMARY KEY (engagement_id, cloud_account_id)
);

CREATE TABLE IF NOT EXISTS engagement_auditors (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id   UUID        NOT NULL REFERENCES audit_engagements(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL,
    full_name       TEXT,
    invited_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (engagement_id, email)
);

-- "Additional evidence" is modeled as a request to add one more of the
-- organization's own cloud accounts to this engagement's scope — the
-- same real entity engagement_scope already uses — rather than a
-- free-text description of a document that doesn't exist anywhere in
-- Niagaros yet. Approving a request inserts into engagement_scope;
-- denying it does not. This is what makes AC2's "selected documents
-- become available without exposing unrelated information" concretely
-- true: the auditor's view (scoped to engagement_scope) only ever grows
-- by exactly the one account that was approved.
CREATE TABLE IF NOT EXISTS engagement_evidence_requests (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id   UUID        NOT NULL REFERENCES audit_engagements(id) ON DELETE CASCADE,
    auditor_email   VARCHAR(255) NOT NULL,
    cloud_account_id UUID       NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending / approved / denied
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

-- Separate from team_audit_log on purpose: that table's actor_user_id
-- references users(id), and auditors are deliberately not users rows.
-- This also matches the PVA's own framing of auditor activity as its own
-- reporting surface ("Reporting: active auditors, evidence requests,
-- auditor activity, download history"), distinct from the admin-facing
-- team audit log.
CREATE TABLE IF NOT EXISTS engagement_activity_log (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id   UUID        NOT NULL REFERENCES audit_engagements(id) ON DELETE CASCADE,
    auditor_email   VARCHAR(255) NOT NULL,
    action          VARCHAR(50) NOT NULL, -- e.g. 'login', 'evidence_downloaded', 'evidence_requested'
    details         JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_engagements_org ON audit_engagements(organization_id);
CREATE INDEX IF NOT EXISTS idx_engagement_auditors_email ON engagement_auditors(email);
CREATE INDEX IF NOT EXISTS idx_engagement_activity_log_engagement ON engagement_activity_log(engagement_id);

GRANT SELECT, INSERT, UPDATE ON audit_engagements TO cspm_lambda;
GRANT SELECT, INSERT, DELETE ON engagement_scope TO cspm_lambda;
GRANT SELECT, INSERT, DELETE ON engagement_auditors TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE ON engagement_evidence_requests TO cspm_lambda;
GRANT SELECT, INSERT ON engagement_activity_log TO cspm_lambda;
