-- Niagaros Notifications Matrix (GitHub issue #274), v1 + v2.
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Scope decision: issue #274 describes a full enterprise notification
-- platform — SMS, mobile push, a first-party Slack/Teams app requiring
-- OAuth registration, on-call escalation scheduling, an "AI
-- correlation engine" that groups thousands of events into one, and
-- integrations with Jira/ServiceNow/SOAR platforms.
--
-- What's built here, for real (v1):
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
--   - A real mandatory-vs-configurable distinction and real, simple
--     24h dedup by event+resource (no invented "correlation engine").
--
-- v2: re-examined two of the v1 declines and found real ways to build
-- them without fabricating anything —
--   - SMS: AWS itself has SNS, which sends real text messages directly
--     (no Twilio or other third-party SMS provider needed) — the exact
--     same relationship this product already has with SES for email.
--     Honestly noted: this AWS account's SNS SMS is still in the AWS
--     sandbox (a $1/month spend cap, delivery restricted to numbers
--     explicitly verified in that sandbox) until production access is
--     requested — the same kind of restriction SES itself started
--     under. The code path is real; the account-level limit is stated
--     plainly, not hidden.
--   - Escalation: a real, minimal policy (one escalation contact per
--     account + a wait time) plus a real EventBridge-scheduled Lambda
--     that checks for mandatory, unacknowledged notifications past
--     that window and notifies the escalation contact — no invented
--     on-call calendar, just the literal "if unacknowledged after N
--     minutes, notify the next contact" rule from the issue.
--
-- Still declined, because there is genuinely no way to build them
-- without fabricating something that does not exist:
--   - Mobile push — there is no Niagaros mobile app anywhere in this
--     codebase, so there are no device tokens to deliver to.
--   - A first-party Slack/Teams app (OAuth, slash commands, bot
--     tokens) — needs a Slack/Microsoft developer account this
--     product doesn't have; the customer-supplied Incoming Webhook
--     above already covers the real "get notified in Slack" need.
--   - Jira/ServiceNow/SOAR — not built this pass; the generic webhook
--     already lets a customer route notifications into any tool that
--     accepts one, including these.
--   - Any "AI-powered" event correlation beyond the dedup rule above.

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
    sms_enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    UNIQUE(cloud_account_id, domain)
);
ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS sms_enabled BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS notification_channels (
    cloud_account_id   UUID         PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    notify_email       VARCHAR(255),
    webhook_url        VARCHAR(500),
    slack_webhook_url  VARCHAR(500),
    sms_number         VARCHAR(20),   -- E.164 format, e.g. +31612345678
    escalation_email   VARCHAR(255),  -- who gets notified if a mandatory event goes unacknowledged
    escalation_minutes INTEGER      NOT NULL DEFAULT 15,
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS sms_number VARCHAR(20);
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS escalation_email VARCHAR(255);
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS escalation_minutes INTEGER NOT NULL DEFAULT 15;

-- v2: real escalation — see get-notifications-escalate/ Lambda, run on an
-- EventBridge schedule, which finds mandatory+unacknowledged notifications
-- older than escalation_minutes and notifies the escalation contact once.
CREATE TABLE IF NOT EXISTS notification_escalations (
    notification_id  UUID         PRIMARY KEY REFERENCES notifications(id) ON DELETE CASCADE,
    escalated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    escalated_to      VARCHAR(255)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON notifications TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_preferences TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_channels TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_escalations TO cspm_lambda;
