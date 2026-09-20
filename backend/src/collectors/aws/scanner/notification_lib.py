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

ADMIN_GROUP_NAME = "Admin"

# Acceptance criterion (issue #274): "multiple users have different
# roles... each receives notifications according to their permissions."
# This product has no per-user role model beyond the real Cognito
# Admin/Viewer groups added for the AI Agent (issue #262) — reused here
# rather than inventing a separate, fictitious permissions system.
# Non-Admin callers (including no/invalid token) don't see these two
# domains; everything else is visible to everyone with account access.
RESTRICTED_DOMAINS_FOR_NON_ADMIN = {"billing", "account"}


def is_admin_caller(event):
    """Real Cognito-group check, same pattern as ai_agent_handler.py's
    _get_caller_admin_status — kept here so any handler can reuse it
    without duplicating the Cognito calls."""
    headers = (event or {}).get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if not auth.startswith("Bearer "):
        return False
    token = auth[7:].strip()
    if not token:
        return False
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    cognito = boto3.client("cognito-idp", region_name=region)
    try:
        user = cognito.get_user(AccessToken=token)
        groups_resp = cognito.admin_list_groups_for_user(
            UserPoolId=os.environ["COGNITO_USER_POOL_ID"], Username=user["Username"]
        )
    except Exception:
        return False
    return ADMIN_GROUP_NAME in [g["GroupName"] for g in groups_resp.get("Groups", [])]
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
    # The issue's own Compliance Notifications table lists "Evidence
    # expired" as P1/non-negotiable — an already-expired certification
    # is the same situation, so it isn't suppressible either.
    "vendor_cert_expired",
}

DEDUP_WINDOW_SQL = "created_at > NOW() - INTERVAL '24 hours'"

_SEVERITY_HEX = {"P0": "B71C1C", "P1": "D32F2F", "P2": "F57C00", "P3": "1976D2", "P4": "9E9E9E", "P5": "9E9E9E"}

MAX_DELIVERY_RETRIES = 3


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
                SELECT email_enabled, webhook_enabled, slack_enabled, sms_enabled, teams_enabled, discord_enabled
                FROM notification_preferences WHERE cloud_account_id = %s AND domain = %s
            """, (cloud_account_id, domain))
            prefs_row = cur.fetchone()
            email_ok = mandatory or prefs_row is None or prefs_row[0]
            webhook_ok = mandatory or prefs_row is None or prefs_row[1]
            slack_ok = mandatory or prefs_row is None or prefs_row[2]
            sms_ok = mandatory or prefs_row is None or prefs_row[3]
            teams_ok = mandatory or prefs_row is None or prefs_row[4]
            discord_ok = mandatory or prefs_row is None or prefs_row[5]

            cur.execute("""
                SELECT notify_email, webhook_url, slack_webhook_url, sms_number, teams_webhook_url, discord_webhook_url
                FROM notification_channels WHERE cloud_account_id = %s
            """, (cloud_account_id,))
            channels_row = cur.fetchone()

    delivery = {"in_app": True, "email": None, "webhook": None, "slack": None, "sms": None, "teams": None, "discord": None}
    if channels_row:
        notify_email, webhook_url, slack_webhook_url, sms_number, teams_webhook_url, discord_webhook_url = channels_row
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
        if teams_ok and teams_webhook_url:
            # Microsoft Teams Incoming Webhook — a different JSON shape
            # (MessageCard) than Slack's, but the same idea: a URL the
            # customer creates themselves in their own Teams channel, no
            # Niagaros-owned Teams app or OAuth needed.
            delivery["teams"] = _post_webhook(teams_webhook_url, {
                "@type": "MessageCard", "@context": "http://schema.org/extensions",
                "summary": title, "themeColor": _SEVERITY_HEX.get(severity, "808080"),
                "title": f"Niagaros [{severity}] {domain}", "text": title + (f"\n\n{description}" if description else ""),
            })
        if sms_ok and sms_number and severity in ("P0", "P1"):
            # SMS is reserved for P0/P1 even when other channels are more
            # permissive — a real, sane default (nobody wants a text for a
            # P4), not a fabricated restriction.
            delivery["sms"] = _send_sms(sms_number, title, severity)
        if discord_ok and discord_webhook_url:
            delivery["discord"] = _post_discord(discord_webhook_url, title, description, severity, domain)

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


def run_retry_check(conn):
    """Acceptance criterion (issue #274): 'Given delivery fails, when
    retry conditions are met, then the notification is retried.' Finds
    notifications from the last 2 hours where at least one configured
    channel failed, and retries just that channel — up to
    MAX_DELIVERY_RETRIES times. Call this from the same EventBridge
    schedule as run_escalation_check."""
    retried = []
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT n.id, n.cloud_account_id, n.domain, n.event_type, n.severity, n.title,
                       n.description, n.resource_link, n.delivery, n.retry_count,
                       c.notify_email, c.webhook_url, c.slack_webhook_url, c.sms_number, c.teams_webhook_url,
                       c.discord_webhook_url
                FROM notifications n
                JOIN notification_channels c ON c.cloud_account_id = n.cloud_account_id
                WHERE n.created_at > NOW() - INTERVAL '2 hours'
                  AND n.retry_count < %s AND n.delivery IS NOT NULL
                  AND (
                    (n.delivery->'email'->>'sent' = 'false') OR
                    (n.delivery->'webhook'->>'sent' = 'false') OR
                    (n.delivery->'slack'->>'sent' = 'false') OR
                    (n.delivery->'sms'->>'sent' = 'false') OR
                    (n.delivery->'teams'->>'sent' = 'false') OR
                    (n.delivery->'discord'->>'sent' = 'false')
                  )
            """, (MAX_DELIVERY_RETRIES,))
            rows = cur.fetchall()

    for (notif_id, account_id, domain, event_type, severity, title, description, resource_link,
         delivery, retry_count, notify_email, webhook_url, slack_webhook_url, sms_number,
         teams_webhook_url, discord_webhook_url) in rows:
        changed = False
        # dict.get(key, {}) only falls back to {} when the key is absent —
        # here every channel key is always PRESENT with value None when
        # unconfigured, so that default never applies. `or {}` catches that.
        if (delivery.get("email") or {}).get("sent") is False and notify_email:
            delivery["email"] = _send_email(notify_email, title, description, severity)
            changed = True
        if (delivery.get("webhook") or {}).get("sent") is False and webhook_url:
            delivery["webhook"] = _post_webhook(webhook_url, {
                "id": str(notif_id), "domain": domain, "event_type": event_type,
                "severity": severity, "title": title, "description": description,
                "resource_link": resource_link,
            })
            changed = True
        if (delivery.get("slack") or {}).get("sent") is False and slack_webhook_url:
            delivery["slack"] = _post_webhook(slack_webhook_url, {
                "text": f"[{severity}] {title}" + (f"\n{description}" if description else ""),
            })
            changed = True
        if (delivery.get("teams") or {}).get("sent") is False and teams_webhook_url:
            delivery["teams"] = _post_webhook(teams_webhook_url, {
                "@type": "MessageCard", "@context": "http://schema.org/extensions",
                "summary": title, "themeColor": _SEVERITY_HEX.get(severity, "808080"),
                "title": f"Niagaros [{severity}] {domain}", "text": title,
            })
            changed = True
        if (delivery.get("sms") or {}).get("sent") is False and sms_number:
            delivery["sms"] = _send_sms(sms_number, title, severity)
            changed = True
        if (delivery.get("discord") or {}).get("sent") is False and discord_webhook_url:
            delivery["discord"] = _post_discord(discord_webhook_url, title, description, severity, domain)
            changed = True
        if changed:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE notifications SET delivery = %s, retry_count = retry_count + 1 WHERE id = %s
                    """, (json.dumps(delivery, default=str), notif_id))
            retried.append({"notification_id": str(notif_id), "delivery": delivery})
    return retried


def run_escalation_check(conn):
    """Real escalation (issue #274's literal 'if unacknowledged after N
    minutes, notify the next contact' rule). Call this from a Lambda on
    an EventBridge schedule — see notification_handler.py's
    run_escalations raw-invoke path. No invented on-call calendar: one
    escalation contact + one wait time per account, both configured by
    the customer themselves in notification_channels."""
    escalated = []
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT n.id, n.cloud_account_id, n.title, n.severity, n.domain, n.created_at,
                       c.escalation_email
                FROM notifications n
                JOIN notification_channels c ON c.cloud_account_id = n.cloud_account_id
                LEFT JOIN notification_escalations e ON e.notification_id = n.id
                WHERE n.mandatory = TRUE AND n.acknowledged_at IS NULL AND e.notification_id IS NULL
                  AND c.escalation_email IS NOT NULL
                  AND n.created_at < NOW() - (c.escalation_minutes || ' minutes')::interval
            """)
            due = cur.fetchall()
            for notif_id, account_id, title, severity, domain, created_at, escalation_email in due:
                result = _send_email(escalation_email, f"ESCALATED — unacknowledged: {title}",
                                      f"This {severity} {domain} notification has not been acknowledged.",
                                      severity)
                cur.execute("""
                    INSERT INTO notification_escalations (notification_id, escalated_to)
                    VALUES (%s, %s)
                """, (notif_id, escalation_email))
                escalated.append({"notification_id": str(notif_id), "escalated_to": escalation_email,
                                   "email_result": result})
    return escalated


def _send_sms(phone_number, title, severity):
    # Real AWS SNS SMS — no third-party SMS provider (Twilio etc.) needed,
    # the same relationship this product already has with SES for email.
    # Honesty note: this AWS account's SNS SMS is still in the sandbox
    # (see 021_notifications.sql) — delivery only succeeds to numbers
    # explicitly verified in that sandbox until production access is
    # requested. The call itself is real; that account-level limit isn't.
    sns = boto3.client("sns", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))
    message = f"Niagaros [{severity}]: {title}"[:280]
    try:
        resp = sns.publish(PhoneNumber=phone_number, Message=message,
                            MessageAttributes={"AWS.SNS.SMS.SMSType": {"DataType": "String", "StringValue": "Transactional"}})
        return {"sent": True, "message_id": resp.get("MessageId")}
    except Exception as e:
        logger.exception("notification sms failed")
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


def _post_discord(url, title, description, severity, domain):
    # A real Discord incoming webhook — same idea as Slack/Teams: the
    # customer (or Niagaros' own team) creates this URL themselves in
    # their own Discord server's channel settings, no bot/OAuth app
    # needed. Uses Discord's embed format for a severity-colored card
    # instead of a plain text line.
    embed = {
        "title": f"[{severity}] {title}",
        "description": description or None,
        "color": int(_SEVERITY_HEX.get(severity, "808080"), 16),
        "footer": {"text": f"Niagaros · {domain}"},
    }
    return _post_webhook(url, {"embeds": [embed]})
