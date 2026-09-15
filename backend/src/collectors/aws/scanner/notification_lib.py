"""
notification_lib.py

Shared notification helper for the Niagaros Notifications Matrix
(GitHub issue #274). See migrations/021_notifications.sql for the full
scope decision (what's built for real vs. explicitly declined).

Import this from any handler that has a real event worth notifying
about, instead of building another one-off notification path:

    from collectors.aws.scanner.notification_lib import create_notification
    create_notification(
        conn, cloud_account_id, domain="tprm", event_type="vendor_cert_expiring",
        severity="P2", title="Certificate expiring: SOC 2 (Acme Inc.)",
        description="Expires 2026-10-01.", resource_link="tprm.html?vendor_id=...",
    )

create_notification() always writes the in-app row. It then delivers to
email / webhook / Slack-incoming-webhook only if that account has a
channel configured AND (the event is mandatory OR the account's
per-domain preference for that channel is enabled).
"""

import json
import logging
import os
import urllib.request

import boto3

logger = logging.getLogger(__name__)

DOMAINS = ("security", "compliance", "risk", "audit", "tprm", "ai", "workflow", "account", "billing", "platform")
SEVERITIES = ("P0", "P1", "P2", "P3", "P4", "P5")

NOTIFICATION_SENDER_EMAIL = os.environ.get("NOTIFICATION_SENDER_EMAIL", "bottomclipzz@gmail.com")

# The issue's own literal "Mandatory" list (non-suppressible), mapped to the
# real event_type strings this codebase actually emits. Anything not listed
# here respects the account's notification_preferences.
MANDATORY_EVENT_TYPES = {
    "critical_security_finding",
    "account_compromise_suspected",
    "suspicious_privileged_activity",
    "mfa_disabled",
    "critical_platform_outage",
    "security_incident_affecting_customers",
    "critical_compliance_deadline",
    "mandatory_admin_action",
}

DEDUP_WINDOW_SQL = "created_at > NOW() - INTERVAL '24 hours'"


def _get_connection_for_lib(conn):
    return conn


def create_notification(conn, cloud_account_id, domain, event_type, severity, title,
                         description=None, resource_link=None, actor=None):
    if domain not in DOMAINS:
        raise ValueError(f"domain must be one of {DOMAINS}")
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    mandatory = event_type in MANDATORY_EVENT_TYPES or severity == "P0"

    with conn:
        with conn.cursor() as cur:
            # Real, simple deduplication: same event+resource for this
            # account within 24h does not create a second notification.
            cur.execute(f"""
                SELECT id FROM notifications
                WHERE cloud_account_id = %s AND event_type = %s
                  AND resource_link IS NOT DISTINCT FROM %s AND {DEDUP_WINDOW_SQL}
                LIMIT 1
            """, (cloud_account_id, event_type, resource_link))
            existing = cur.fetchone()
            if existing:
                return {"id": str(existing[0]), "deduplicated": True}

            cur.execute("""
                INSERT INTO notifications (cloud_account_id, domain, event_type, severity, title,
                                            description, resource_link, actor, mandatory)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (cloud_account_id, domain, event_type, severity, title, description,
                  resource_link, actor, mandatory))
            notification_id = str(cur.fetchone()[0])

            cur.execute("""
                SELECT email_enabled, webhook_enabled, slack_enabled
                FROM notification_preferences WHERE cloud_account_id = %s AND domain = %s
            """, (cloud_account_id, domain))
            prefs_row = cur.fetchone()
            email_ok = mandatory or prefs_row is None or prefs_row[0]
            webhook_ok = mandatory or prefs_row is None or prefs_row[1]
            slack_ok = mandatory or prefs_row is None or prefs_row[2]

            cur.execute("""
                SELECT notify_email, webhook_url, slack_webhook_url
                FROM notification_channels WHERE cloud_account_id = %s
            """, (cloud_account_id,))
            channels_row = cur.fetchone()

    delivery = {"in_app": True, "email": None, "webhook": None, "slack": None}
    if channels_row:
        notify_email, webhook_url, slack_webhook_url = channels_row
        if email_ok and notify_email:
            delivery["email"] = _send_email(notify_email, title, description, severity)
        if webhook_ok and webhook_url:
            delivery["webhook"] = _post_webhook(webhook_url, {
                "id": notification_id, "domain": domain, "event_type": event_type,
                "severity": severity, "title": title, "description": description,
                "resource_link": resource_link,
            })
        if slack_ok and slack_webhook_url:
            delivery["slack"] = _post_webhook(slack_webhook_url, {
                "text": f"[{severity}] {title}" + (f"\n{description}" if description else ""),
            })

    # Acceptance criterion (issue #274): "Given a notification is
    # delivered, when the provider confirms delivery, then delivery
    # status is recorded." Persist the real outcome, not just return it.
    with conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE notifications SET delivery = %s WHERE id = %s",
                        (json.dumps(delivery, default=str), notification_id))

    return {"id": notification_id, "deduplicated": False, "mandatory": mandatory, "delivery": delivery}


def _send_email(to_email, title, description, severity):
    if not NOTIFICATION_SENDER_EMAIL:
        return {"sent": False, "reason": "not_configured"}
    body = f"[{severity}] {title}\n\n{description or ''}".strip()
    ses = boto3.client("sesv2", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))
    try:
        ses.send_email(
            FromEmailAddress=NOTIFICATION_SENDER_EMAIL,
            Destination={"ToAddresses": [to_email]},
            Content={"Simple": {"Subject": {"Data": f"Niagaros: {title}", "Charset": "UTF-8"},
                                 "Body": {"Text": {"Data": body, "Charset": "UTF-8"}}}},
        )
        return {"sent": True}
    except Exception as e:
        logger.exception("notification email failed")
        return {"sent": False, "reason": str(e)}


def _post_webhook(url, payload):
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload, default=str).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return {"sent": True, "status": resp.status}
    except Exception as e:
        logger.exception("notification webhook failed")
        return {"sent": False, "reason": str(e)}
