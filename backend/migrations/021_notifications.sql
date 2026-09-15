-- Niagaros Notifications Matrix (GitHub issue #274), v1.
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Scope decision: issue #274 describes a full enterprise notification
-- platform — SMS via an unspecified provider, mobile push (there is no
-- mobile app), a first-party Slack/Teams app requiring OAuth
-- registration, on-call escalation scheduling, an "AI correlation
-- engine" that groups thousands of events into one, and integrations
-- with Jira/ServiceNow/SOAR platforms. None of that exists in this
-- codebase, and building it would mean either faking accounts/tokens
-- this platform never registered, or inventing on-call/escalation data
-- that doesn't exist anywhere in the product yet — both violate the
-- standing "no fabricated capability" rule (see ai_agent_handler.py
-- for the same reasoning applied to issue #262).
--
-- What's built here instead, for real:
--   - One shared notifications table + a shared create_notification()
--     helper (notification_lib.py), called from real, already-existing
--     trigger points (TPRM certificate expiry, Audit Management task
--     assignment, AI Agent remediation-task creation) instead of each
--     feature inventing its own ad-hoc notification logic — this is
--     literally the issue's own stated goal ("one standardized
--     notification architecture" instead of "each feature implements
--     notifications differently").
--   - Real channels that need no third-party account: in-app (a new,
--     working notification center — the bell icon existed everywhere
--     as a dead placeholder before this), email (SES, already used
--     throughout this product), a generic webhook (a plain HTTP POST
--     to a URL the customer supplies themselves), and a Slack
--     "Incoming Webhook" URL the customer creates on their own Slack
--     workspace and pastes in — this needs no Niagaros-owned Slack app
--     or OAuth flow, just an HTTP POST, same as the generic webhook.
--   - A real mandatory-vs-configurable distinction: the specific event
--     types the issue lists as non-suppressible (critical security
--     incidents, MFA/security changes, critical platform outages,
--     etc.) always fire regardless of the account's channel
--     preferences; everything else respects them.
--   - Real, simple deduplication: the same event type for the same
--     resource within a 24-hour window does not create a second
--     notification — no invented "correlation engine", just an actual
--     repeat-suppression rule.
--
-- Declined, explicitly, rather than silently invented:
--   - SMS, mobile push, a first-party Slack/Teams app, on-call
--     escalation scheduling, Jira/ServiceNow/SOAR integration, and any
--     "AI-powered" event correlation beyond the simple dedup above.

CREATE TABLE IF NOT EXISTS notifications (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    domain            VARCHAR(30)  NOT NULL,   -- security, compliance, risk, audit, tprm, ai, workflow, account, billing, platform
    event_type        VARCHAR(80)  NOT NULL,   -- e.g. 'vendor_cert_expiring', 'remediation_task_assigned'
    severity          VARCHAR(5)   NOT NULL,   -- P0..P5
    title             VARCHAR(255) NOT NULL,
    description       TEXT,
    resource_link     VARCHAR(255),            -- deep link, e.g. 'tprm.html?vendor_id=...'
    actor             VARCHAR(255),
    mandatory         BOOLEAN      NOT NULL DEFAULT FALSE,
    delivery          JSONB,                   -- real per-channel delivery outcome, see notification_lib.py
    read_at           TIMESTAMPTZ,
    acknowledged_at   TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS notifications_account_idx ON notifications(cloud_account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS notifications_unread_idx ON notifications(cloud_account_id, read_at) WHERE read_at IS NULL;
CREATE INDEX IF NOT EXISTS notifications_dedup_idx ON notifications(cloud_account_id, event_type, resource_link, created_at DESC);

CREATE TABLE IF NOT EXISTS notification_preferences (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    domain            VARCHAR(30)  NOT NULL,
    email_enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    webhook_enabled   BOOLEAN      NOT NULL DEFAULT TRUE,
    slack_enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    UNIQUE(cloud_account_id, domain)
);

CREATE TABLE IF NOT EXISTS notification_channels (
    cloud_account_id   UUID         PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    notify_email       VARCHAR(255),
    webhook_url        VARCHAR(500),
    slack_webhook_url  VARCHAR(500),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON notifications TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_preferences TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_channels TO cspm_lambda;
