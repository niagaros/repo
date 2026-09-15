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
    read_at           TIMESTAMPTZ,
    acknowledged_at   TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS delivery JSONB;
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


def _list_notifications(cur, account_id, domain_filter, severity_filter, unread_only, limit):
    clauses = ["cloud_account_id = %s"]
    params = [account_id]
    if domain_filter:
        clauses.append("domain = %s")
        params.append(domain_filter)
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
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT domain, email_enabled, webhook_enabled, slack_enabled
                        FROM notification_preferences WHERE cloud_account_id = %s
                    """, (account_id,))
                    saved = {r[0]: {"email_enabled": r[1], "webhook_enabled": r[2], "slack_enabled": r[3]}
                             for r in cur.fetchall()}
                    cur.execute("""
                        SELECT notify_email, webhook_url, slack_webhook_url
                        FROM notification_channels WHERE cloud_account_id = %s
                    """, (account_id,))
                    ch = cur.fetchone()
                preferences = {d: saved.get(d, {"email_enabled": True, "webhook_enabled": True, "slack_enabled": True})
                               for d in DOMAINS}
                channels = {"notify_email": ch[0] if ch else None, "webhook_url": ch[1] if ch else None,
                            "slack_webhook_url": ch[2] if ch else None}
                return _resp(200, {"preferences": preferences, "channels": channels})

            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM notifications WHERE cloud_account_id = %s AND read_at IS NULL",
                            (account_id,))
                unread_count = cur.fetchone()[0]
                notifications = _list_notifications(
                    cur, account_id, qs.get("domain"), qs.get("severity"),
                    qs.get("unread_only") == "1", int(qs.get("limit", 50)),
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
                                                                    webhook_enabled, slack_enabled)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT (cloud_account_id, domain) DO UPDATE SET
                                email_enabled = EXCLUDED.email_enabled,
                                webhook_enabled = EXCLUDED.webhook_enabled,
                                slack_enabled = EXCLUDED.slack_enabled
                        """, (account_id, domain, bool(body.get("email_enabled", True)),
                              bool(body.get("webhook_enabled", True)), bool(body.get("slack_enabled", True))))
                return _resp(200, {"ok": True})

            if action == "update_channels":
                with conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO notification_channels (cloud_account_id, notify_email, webhook_url,
                                                                 slack_webhook_url, updated_at)
                            VALUES (%s, %s, %s, %s, NOW())
                            ON CONFLICT (cloud_account_id) DO UPDATE SET
                                notify_email = EXCLUDED.notify_email,
                                webhook_url = EXCLUDED.webhook_url,
                                slack_webhook_url = EXCLUDED.slack_webhook_url,
                                updated_at = NOW()
                        """, (account_id, body.get("notify_email"), body.get("webhook_url"),
                              body.get("slack_webhook_url")))
                return _resp(200, {"ok": True})

            return _resp(400, {"error": f"unknown action: {action}"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.exception("notification_handler error")
        return _resp(500, {"error": str(e)})
    finally:
        conn.close()
