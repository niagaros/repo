"""
notification_handler.py

API surface for the Niagaros Notifications Matrix (GitHub issue #274).
See migrations/021_notifications.sql for the scope decision and
notification_lib.py for how other handlers create notifications.

This handler only serves the in-app notification center and account
settings (list, mark read, acknowledge, channel/preference config). It
never creates notifications itself — those come from real events in
tprm_handler.py, audit_management_handler.py, and ai_agent_handler.py.
"""

import json
import logging
import os
import re

import boto3
import psycopg2

from collectors.aws.scanner.notification_lib import (
    run_escalation_check, run_retry_check, is_admin_caller, RESTRICTED_DOMAINS_FOR_NON_ADMIN,
)

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _is_uuid(value):
    return bool(value) and bool(_UUID_RE.match(value))


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}

DOMAINS = ("security", "compliance", "risk", "audit", "tprm", "ai", "workflow", "account", "billing", "platform")

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS notifications (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    domain            VARCHAR(30)  NOT NULL,
    event_type        VARCHAR(80)  NOT NULL,
    severity          VARCHAR(5)   NOT NULL,
    title             VARCHAR(255) NOT NULL,
    description       TEXT,
    resource_link     VARCHAR(255),
    actor             VARCHAR(255),
    mandatory         BOOLEAN      NOT NULL DEFAULT FALSE,
    delivery          JSONB,
    retry_count       INTEGER      NOT NULL DEFAULT 0,
    read_at           TIMESTAMPTZ,
    acknowledged_at   TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS delivery JSONB;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;
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
    teams_enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    UNIQUE(cloud_account_id, domain)
);
ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS sms_enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS teams_enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS discord_enabled BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS notification_channels (
    cloud_account_id   UUID         PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    notify_email       VARCHAR(255),
    webhook_url        VARCHAR(500),
    slack_webhook_url  VARCHAR(500),
    sms_number         VARCHAR(20),
    escalation_email   VARCHAR(255),
    escalation_minutes INTEGER      NOT NULL DEFAULT 15,
    teams_webhook_url  VARCHAR(500),
    discord_webhook_url VARCHAR(500),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS sms_number VARCHAR(20);
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS escalation_email VARCHAR(255);
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS escalation_minutes INTEGER NOT NULL DEFAULT 15;
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS teams_webhook_url VARCHAR(500);
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS discord_webhook_url VARCHAR(500);

CREATE TABLE IF NOT EXISTS notification_escalations (
    notification_id  UUID         PRIMARY KEY REFERENCES notifications(id) ON DELETE CASCADE,
    escalated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    escalated_to      VARCHAR(255)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON notifications TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_preferences TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_channels TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_escalations TO cspm_lambda;
"""


def _get_connection():
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    client = boto3.client("secretsmanager", region_name=region)
    secret = json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return psycopg2.connect(
        host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
        user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
    )


def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body, default=str)}


def _list_notifications(cur, account_id, domain_filter, severity_filter, unread_only, limit, exclude_domains=None):
    clauses = ["cloud_account_id = %s"]
    params = [account_id]
    if domain_filter:
        clauses.append("domain = %s")
        params.append(domain_filter)
    if exclude_domains:
        clauses.append("domain NOT IN %s")
        params.append(tuple(exclude_domains))
    if severity_filter:
        clauses.append("severity = %s")
        params.append(severity_filter)
    if unread_only:
        clauses.append("read_at IS NULL")
    params.append(limit)
    cur.execute(f"""
        SELECT id, domain, event_type, severity, title, description, resource_link, actor,
               mandatory, read_at, acknowledged_at, created_at, delivery
        FROM notifications WHERE {' AND '.join(clauses)}
        ORDER BY created_at DESC LIMIT %s
    """, params)
    return [{
        "id": str(r[0]), "domain": r[1], "event_type": r[2], "severity": r[3], "title": r[4],
        "description": r[5], "resource_link": r[6], "actor": r[7], "mandatory": r[8],
        "read": r[9] is not None, "acknowledged": r[10] is not None, "created_at": r[11].isoformat(),
        "delivery": r[12],
    } for r in cur.fetchall()]


def handler(event, context):
    # Invoked directly by an EventBridge Schedule (not through API Gateway,
    # so no httpMethod key) — real escalation check, see 021_notifications.sql.
    if event and event.get("run_escalations"):
        conn = _get_connection()
        try:
            escalated = run_escalation_check(conn)
            retried = run_retry_check(conn)
            return {"statusCode": 200, "body": json.dumps({"escalated": escalated, "retried": retried}, default=str)}
        finally:
            conn.close()

    if not event or "httpMethod" not in event:
        return {"statusCode": 400, "body": json.dumps({"error": "not an API Gateway event"})}

    method = event["httpMethod"]
    if method == "OPTIONS":
        return _resp(200, {})

    qs = event.get("queryStringParameters") or {}
    body = json.loads(event["body"]) if event.get("body") else {}

    conn = _get_connection()
    try:
        if method == "GET":
            account_id = qs.get("cloud_account_id")
            if not _is_uuid(account_id):
                return _resp(400, {"error": "cloud_account_id is required"})

            if qs.get("preferences"):
                default_pref = {"email_enabled": True, "webhook_enabled": True, "slack_enabled": True,
                                 "sms_enabled": True, "teams_enabled": True, "discord_enabled": True}
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT domain, email_enabled, webhook_enabled, slack_enabled, sms_enabled, teams_enabled,
                               discord_enabled
                        FROM notification_preferences WHERE cloud_account_id = %s
                    """, (account_id,))
                    saved = {r[0]: {"email_enabled": r[1], "webhook_enabled": r[2], "slack_enabled": r[3],
                                     "sms_enabled": r[4], "teams_enabled": r[5], "discord_enabled": r[6]}
                             for r in cur.fetchall()}
                    cur.execute("""
                        SELECT notify_email, webhook_url, slack_webhook_url, sms_number,
                               escalation_email, escalation_minutes, teams_webhook_url, discord_webhook_url
                        FROM notification_channels WHERE cloud_account_id = %s
                    """, (account_id,))
                    ch = cur.fetchone()
                preferences = {d: saved.get(d, default_pref) for d in DOMAINS}
                channels = {"notify_email": ch[0] if ch else None, "webhook_url": ch[1] if ch else None,
                            "slack_webhook_url": ch[2] if ch else None, "sms_number": ch[3] if ch else None,
                            "escalation_email": ch[4] if ch else None,
                            "escalation_minutes": ch[5] if ch else 15,
                            "teams_webhook_url": ch[6] if ch else None,
                            "discord_webhook_url": ch[7] if ch else None}
                return _resp(200, {"preferences": preferences, "channels": channels})

            if qs.get("analytics"):
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT
                            COUNT(*) AS total,
                            COUNT(*) FILTER (WHERE acknowledged_at IS NOT NULL) AS acknowledged,
                            COUNT(*) FILTER (WHERE mandatory) AS mandatory_count,
                            AVG(EXTRACT(EPOCH FROM (acknowledged_at - created_at)) / 60)
                                FILTER (WHERE acknowledged_at IS NOT NULL) AS avg_ack_minutes,
                            COUNT(*) FILTER (WHERE delivery IS NOT NULL AND (
                                (delivery->'email'->>'sent')::boolean OR (delivery->'webhook'->>'sent')::boolean OR
                                (delivery->'slack'->>'sent')::boolean OR (delivery->'sms'->>'sent')::boolean OR
                                (delivery->'teams'->>'sent')::boolean OR (delivery->'discord'->>'sent')::boolean
                            )) AS delivered_to_at_least_one_channel,
                            COUNT(*) FILTER (WHERE delivery IS NOT NULL) AS attempted_external_delivery
                        FROM notifications WHERE cloud_account_id = %s
                    """, (account_id,))
                    total, acknowledged, mandatory_count, avg_ack_minutes, delivered, attempted = cur.fetchone()
                    cur.execute("SELECT COUNT(*) FROM notification_escalations e "
                                "JOIN notifications n ON n.id = e.notification_id WHERE n.cloud_account_id = %s",
                                (account_id,))
                    escalated_count = cur.fetchone()[0]
                    # Acceptance criterion (issue #274 AC18): "integration
                    # failure visibility to administrators." The delivery
                    # rate above is a single blended number — it can't tell
                    # an admin WHICH channel is actually broken. Per-channel
                    # health, from the same real delivery data already
                    # recorded, over the last 7 days.
                    integration_health = {}
                    # jsonb_typeof(...) = 'object' (not `IS NOT NULL`) is
                    # required here: a JSON null stored for an unconfigured
                    # channel is a real jsonb VALUE in Postgres, not SQL
                    # NULL, so `delivery->'webhook' IS NOT NULL` is true
                    # even when webhook was never attempted at all — the
                    # same "present but null" trap as the earlier
                    # `.get(key, {})` bug in run_retry_check, one layer down
                    # at the SQL level this time.
                    for channel in ("email", "webhook", "slack", "sms", "teams", "discord"):
                        cur.execute(f"""
                            SELECT
                                COUNT(*) FILTER (WHERE jsonb_typeof(delivery->'{channel}') = 'object') AS attempts,
                                COUNT(*) FILTER (WHERE (delivery->'{channel}'->>'sent')::boolean = FALSE) AS failures,
                                (SELECT delivery->'{channel}'->>'reason' FROM notifications
                                 WHERE cloud_account_id = %s AND (delivery->'{channel}'->>'sent')::boolean = FALSE
                                 ORDER BY created_at DESC LIMIT 1) AS last_failure_reason,
                                (SELECT created_at FROM notifications
                                 WHERE cloud_account_id = %s AND (delivery->'{channel}'->>'sent')::boolean = FALSE
                                 ORDER BY created_at DESC LIMIT 1) AS last_failure_at
                            FROM notifications
                            WHERE cloud_account_id = %s AND created_at > NOW() - INTERVAL '7 days'
                        """, (account_id, account_id, account_id))
                        c_attempts, c_failures, c_reason, c_at = cur.fetchone()
                        if c_attempts:
                            integration_health[channel] = {
                                "attempts": c_attempts, "failures": c_failures,
                                "failure_rate_pct": round(c_failures * 100.0 / c_attempts, 1),
                                "last_failure_reason": c_reason,
                                "last_failure_at": c_at.isoformat() if c_at else None,
                            }

                return _resp(200, {
                    "total_notifications": total,
                    "acknowledged": acknowledged,
                    "acknowledgement_rate_pct": round(acknowledged * 100.0 / total, 1) if total else None,
                    "integration_health": integration_health,
                    "mandatory_count": mandatory_count,
                    "avg_time_to_acknowledge_minutes": round(avg_ack_minutes, 1) if avg_ack_minutes else None,
                    "delivery_rate_pct": round(delivered * 100.0 / attempted, 1) if attempted else None,
                    "escalated_count": escalated_count,
                })

            domain_filter = qs.get("domain")
            if not is_admin_caller(event) and domain_filter in RESTRICTED_DOMAINS_FOR_NON_ADMIN:
                # A non-Admin explicitly asking for a restricted domain gets
                # an honest empty result, not a silent all-domains fallback.
                return _resp(200, {"notifications": [], "unread_count": 0})
            exclude_domains = None if is_admin_caller(event) else RESTRICTED_DOMAINS_FOR_NON_ADMIN

            with conn.cursor() as cur:
                unread_clause = "read_at IS NULL"
                if exclude_domains:
                    cur.execute(f"""
                        SELECT COUNT(*) FROM notifications
                        WHERE cloud_account_id = %s AND {unread_clause} AND domain NOT IN %s
                    """, (account_id, tuple(exclude_domains)))
                else:
                    cur.execute(f"SELECT COUNT(*) FROM notifications WHERE cloud_account_id = %s AND {unread_clause}",
                                (account_id,))
                unread_count = cur.fetchone()[0]
                notifications = _list_notifications(
                    cur, account_id, domain_filter, qs.get("severity"),
                    qs.get("unread_only") == "1", int(qs.get("limit", 50)), exclude_domains,
                )
            return _resp(200, {"notifications": notifications, "unread_count": unread_count})

        if method == "POST":
            action = body.get("action")

            if action == "migrate":
                with conn:
                    with conn.cursor() as cur:
                        cur.execute(BOOTSTRAP_SQL)
                return _resp(200, {"migrated": True})

            account_id = body.get("cloud_account_id")
            if not _is_uuid(account_id):
                return _resp(400, {"error": "cloud_account_id is required"})

            if action == "mark_read":
                notif_id = body.get("id")
                with conn:
                    with conn.cursor() as cur:
                        if notif_id:
                            cur.execute("""
                                UPDATE notifications SET read_at = NOW()
                                WHERE id = %s AND cloud_account_id = %s AND read_at IS NULL
                            """, (notif_id, account_id))
                        else:
                            cur.execute("""
                                UPDATE notifications SET read_at = NOW()
                                WHERE cloud_account_id = %s AND read_at IS NULL
                            """, (account_id,))
                return _resp(200, {"ok": True})

            if action == "acknowledge":
                notif_id = body.get("id")
                if not _is_uuid(notif_id):
                    return _resp(400, {"error": "id is required"})
                with conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            UPDATE notifications SET acknowledged_at = NOW(), read_at = COALESCE(read_at, NOW())
                            WHERE id = %s AND cloud_account_id = %s
                        """, (notif_id, account_id))
                return _resp(200, {"ok": True})

            if action == "update_preferences":
                domain = body.get("domain")
                if domain not in DOMAINS:
                    return _resp(400, {"error": f"domain must be one of {DOMAINS}"})
                with conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO notification_preferences (cloud_account_id, domain, email_enabled,
                                                                    webhook_enabled, slack_enabled, sms_enabled,
                                                                    teams_enabled, discord_enabled)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (cloud_account_id, domain) DO UPDATE SET
                                email_enabled = EXCLUDED.email_enabled,
                                webhook_enabled = EXCLUDED.webhook_enabled,
                                slack_enabled = EXCLUDED.slack_enabled,
                                sms_enabled = EXCLUDED.sms_enabled,
                                teams_enabled = EXCLUDED.teams_enabled,
                                discord_enabled = EXCLUDED.discord_enabled
                        """, (account_id, domain, bool(body.get("email_enabled", True)),
                              bool(body.get("webhook_enabled", True)), bool(body.get("slack_enabled", True)),
                              bool(body.get("sms_enabled", True)), bool(body.get("teams_enabled", True)),
                              bool(body.get("discord_enabled", True))))
                return _resp(200, {"ok": True})

            if action == "update_channels":
                # A partial payload (e.g. only sms_number) must not blank out
                # fields the customer already configured — only overwrite a
                # column when this request actually included that key.
                fields = ("notify_email", "webhook_url", "slack_webhook_url", "sms_number",
                          "escalation_email", "escalation_minutes", "teams_webhook_url", "discord_webhook_url")
                provided = {f: body[f] for f in fields if f in body}
                if "escalation_minutes" in provided:
                    provided["escalation_minutes"] = int(provided["escalation_minutes"])
                with conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO notification_channels (cloud_account_id, updated_at)
                            VALUES (%s, NOW()) ON CONFLICT (cloud_account_id) DO NOTHING
                        """, (account_id,))
                        if provided:
                            set_clauses = ", ".join(f"{f} = %s" for f in provided)
                            cur.execute(f"""
                                UPDATE notification_channels SET {set_clauses}, updated_at = NOW()
                                WHERE cloud_account_id = %s
                            """, list(provided.values()) + [account_id])
                return _resp(200, {"ok": True})

            return _resp(400, {"error": f"unknown action: {action}"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.exception("notification_handler error")
        return _resp(500, {"error": str(e)})
    finally:
        conn.close()
