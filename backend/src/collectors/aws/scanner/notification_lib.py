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

import ipaddress
import json
import logging
import os
import socket
import urllib.parse
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


NOTIFICATION_QUEUE_URL = os.environ.get("NOTIFICATION_QUEUE_URL")


def _enqueue_delivery(notification_id):
    """Acceptance criterion (issue #274 AC20): 'asynchronous high-volume
    processing without blocking core workflows.' Real bug this fixes: a
    user clicking 'create remediation task' waited on up to 5 sequential
    external HTTP calls (email, webhook, Slack, Teams, Discord — each with
    its own timeout) inside that same API request, before ever getting a
    response. Delivery is now handed off to a real SQS queue and a
    separate Lambda invocation (notification-handler's own SQS trigger,
    see deliver_queued_notification) performs it — the caller's request
    returns as soon as the in-app row exists.

    Returns False (never raises) on a send failure too — the row is already
    committed by this point, so the caller must fall back to the same
    synchronous delivery used when no queue is configured at all; otherwise
    a transient SQS error leaves a notification permanently stuck with
    delivery=NULL, which run_retry_check's own WHERE clause can never pick
    up (it only looks at notifications where delivery IS NOT NULL)."""
    if not NOTIFICATION_QUEUE_URL:
        return False
    try:
        sqs = boto3.client("sqs", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))
        sqs.send_message(QueueUrl=NOTIFICATION_QUEUE_URL, MessageBody=json.dumps({"notification_id": notification_id}))
    except Exception:
        logger.exception("could not enqueue notification %s for delivery — falling back to synchronous delivery", notification_id)
        return False
    return True


def create_notification(conn, cloud_account_id, domain, event_type, severity, title,
                         description=None, resource_link=None, actor=None):
    if domain not in DOMAINS:
        raise ValueError(f"domain must be one of {DOMAINS}")
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    mandatory = event_type in MANDATORY_EVENT_TYPES or severity == "P0"

    with conn:
        with conn.cursor() as cur:
            # Real, simple deduplication: same event+resource for this account
            # within 24h does not create a second notification — UNLESS the new
            # occurrence is more severe than the one already recorded. Without
            # that check, a resource whose LOW-severity finding already fired
            # once could re-fail as CRITICAL an hour later and be silently
            # suppressed as "a duplicate" for the rest of the 24h window.
            cur.execute(f"""
                SELECT id, severity FROM notifications
                WHERE cloud_account_id = %s AND event_type = %s
                  AND resource_link IS NOT DISTINCT FROM %s AND {DEDUP_WINDOW_SQL}
                LIMIT 1
            """, (cloud_account_id, event_type, resource_link))
            existing = cur.fetchone()
            if existing:
                existing_id, existing_severity = existing
                existing_idx = SEVERITIES.index(existing_severity) if existing_severity in SEVERITIES else len(SEVERITIES)
                new_idx = SEVERITIES.index(severity)
                if new_idx >= existing_idx:
                    return {"id": str(existing_id), "deduplicated": True}

            cur.execute("""
                INSERT INTO notifications (cloud_account_id, domain, event_type, severity, title,
                                            description, resource_link, actor, mandatory)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (cloud_account_id, domain, event_type, severity, title, description,
                  resource_link, actor, mandatory))
            notification_id = str(cur.fetchone()[0])

    # The in-app row exists — hand delivery off to the queue and return
    # immediately instead of blocking this request on external HTTP calls.
    if _enqueue_delivery(notification_id):
        return {"id": notification_id, "deduplicated": False, "mandatory": mandatory, "delivery": "queued"}

    # No queue configured (e.g. local/manual invocation without the env
    # var) — fall back to the original synchronous delivery so nothing
    # silently stops working.
    return deliver_now(conn, notification_id, cloud_account_id, domain, event_type, severity, title,
                        description, resource_link, mandatory)


def deliver_now(conn, notification_id, cloud_account_id, domain, event_type, severity, title,
                 description, resource_link, mandatory):
    """The real delivery step, run either synchronously (fallback) or from
    the SQS consumer (deliver_queued_notification) — same logic either way."""
    with conn:
        with conn.cursor() as cur:
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

    # Real "audience targeting" (from the issue's own epic description):
    # notification_channels above is one slot per channel per account —
    # this covers any ADDITIONAL people who care about this category (or
    # every category, if they didn't scope it), on top of the primary
    # channels, not instead of them. One person can have several channels
    # filled in at once (e.g. email AND sms) — each gets dispatched
    # separately. Ignores per-domain preference toggles deliberately — a
    # named recipient someone added on purpose should get it regardless
    # of the account-wide toggle.
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, label, notify_email, sms_number, slack_webhook_url, teams_webhook_url,
                   discord_webhook_url, webhook_url
            FROM notification_recipients
            WHERE cloud_account_id = %s AND (domains IS NULL OR domains = '{}' OR %s = ANY(domains))
        """, (cloud_account_id, domain))
        extra_recipients = cur.fetchall()
    additional = []
    for recipient_id, label, r_email, r_sms, r_slack, r_teams, r_discord, r_webhook in extra_recipients:
        person_channels = {"email": r_email, "sms": r_sms, "slack": r_slack,
                            "teams": r_teams, "discord": r_discord, "webhook": r_webhook}
        for channel, target in person_channels.items():
            if not target:
                continue
            result = dispatch_to_channel(channel, target, title, description, severity, domain,
                                          notification_id, event_type, resource_link)
            additional.append({"recipient_id": str(recipient_id), "label": label, "channel": channel, **result})
    if additional:
        delivery["additional_recipients"] = additional

    # Acceptance criterion (issue #274): "Given a notification is
    # delivered, when the provider confirms delivery, then delivery
    # status is recorded." Persist the real outcome, not just return it.
    with conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE notifications SET delivery = %s WHERE id = %s",
                        (json.dumps(delivery, default=str), notification_id))
    _log_delivery_attempts(conn, notification_id, delivery, "initial")

    return {"id": notification_id, "deduplicated": False, "mandatory": mandatory, "delivery": delivery}


def _log_delivery_attempts(conn, notification_id, delivery, attempt_kind):
    """Real, append-only delivery history — notifications.delivery is a single
    JSONB field every later attempt overwrites, so this is the only place the
    outcome of an earlier attempt survives a later retry. Never raises: a
    logging failure must not break real delivery."""
    try:
        rows = []
        for channel in ("email", "webhook", "slack", "sms", "teams", "discord"):
            r = delivery.get(channel)
            if isinstance(r, dict) and "sent" in r:
                rows.append((notification_id, channel, None, bool(r.get("sent")), r.get("reason"), attempt_kind))
        for entry in delivery.get("additional_recipients") or []:
            if "sent" in entry:
                rows.append((notification_id, entry.get("channel"), entry.get("recipient_id"),
                             bool(entry.get("sent")), entry.get("reason"), attempt_kind))
        if not rows:
            return
        with conn:
            with conn.cursor() as cur:
                cur.executemany("""
                    INSERT INTO notification_delivery_attempts
                        (notification_id, channel, recipient_id, sent, reason, attempt_kind)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, rows)
    except Exception:
        logger.exception("could not log delivery attempt history for notification %s", notification_id)
        try:
            conn.rollback()
        except Exception:
            pass


def deliver_queued_notification(conn, notification_id):
    """Called from notification-handler's SQS trigger (one real
    notification per queue message). Looks up the row this Lambda
    invocation didn't itself create, then runs the same real delivery
    logic as the synchronous fallback.

    SQS is at-least-once — the same message can be (and, in practice,
    sometimes is) delivered to this trigger more than once. Without a check,
    a redelivery re-runs deliver_now and re-sends every real email/SMS/
    webhook a second time. deliver_now already sets `delivery` at the end of
    a real run, so its presence means "already delivered" and a redelivery
    is a genuine no-op, not a second send."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT cloud_account_id, domain, event_type, severity, title, description,
                   resource_link, mandatory, delivery
            FROM notifications WHERE id = %s
        """, (notification_id,))
        row = cur.fetchone()
    if not row:
        return {"error": "notification not found", "id": notification_id}
    cloud_account_id, domain, event_type, severity, title, description, resource_link, mandatory, delivery = row
    if delivery is not None:
        return {"id": notification_id, "already_delivered": True, "delivery": delivery}
    return deliver_now(conn, notification_id, str(cloud_account_id), domain, event_type, severity, title,
                        description, resource_link, mandatory)


def dispatch_to_channel(channel, target, title, description, severity, domain, notification_id, event_type, resource_link):
    """Send one notification to one arbitrary (channel, target) pair —
    used for additional named recipients, where the channel type isn't
    known ahead of time the way it is for the account's own fixed
    columns in notification_channels."""
    if channel == "email":
        return _send_email(target, title, description, severity)
    if channel == "sms":
        return _send_sms(target, title, severity)
    if channel == "webhook":
        return _post_webhook(target, {
            "id": notification_id, "domain": domain, "event_type": event_type,
            "severity": severity, "title": title, "description": description, "resource_link": resource_link,
        })
    if channel == "slack":
        return _post_webhook(target, {"text": f"[{severity}] {title}" + (f"\n{description}" if description else "")})
    if channel == "teams":
        return _post_webhook(target, {
            "@type": "MessageCard", "@context": "http://schema.org/extensions",
            "summary": title, "themeColor": _SEVERITY_HEX.get(severity, "808080"),
            "title": f"Niagaros [{severity}] {domain}", "text": title + (f"\n\n{description}" if description else ""),
        })
    if channel == "discord":
        return _post_discord(target, title, description, severity, domain)
    return {"sent": False, "reason": f"unknown channel: {channel}"}



def _friendly_reason(e):
    """A short, honest, non-technical explanation of a real delivery failure — the full exception is always
    logged separately for debugging, this is only what a customer sees."""
    text = str(e)
    low = text.lower()
    if "messagerejected" in low and "not verified" in low:
        return "This email address is not verified yet (AWS SES sandbox mode). Verify it in AWS, or request production access, before real delivery will work."
    if "connection refused" in low or "errno 111" in low:
        return "Could not connect — the destination refused the connection. Double-check the URL and that the receiving service is running."
    if "name or service not known" in low or "nodename nor servname" in low or "getaddrinfo failed" in low:
        return "Could not connect — the address could not be resolved. Double-check the URL for typos."
    if "timed out" in low or "timeout" in low:
        return "The destination did not respond in time. It may be down or blocking our request."
    if "404" in text and ("http error" in low or "not found" in low):
        return "The destination address responded with \"not found\" — double-check the URL is still valid."
    if "401" in text or "403" in text or "unauthorized" in low or "forbidden" in low:
        return "The destination rejected our credentials — double-check the URL/token is still valid."
    if "ssl" in low or "certificate" in low:
        return "Could not establish a secure connection to the destination."
    return "Delivery failed. Double-check the address is correct and reachable."


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
        return {"sent": False, "reason": _friendly_reason(e)}


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
                    (n.delivery->'discord'->>'sent' = 'false') OR
                    EXISTS (
                        SELECT 1 FROM jsonb_array_elements(COALESCE(n.delivery->'additional_recipients', '[]'::jsonb)) e
                        WHERE e->>'sent' = 'false'
                    )
                  )
            """, (MAX_DELIVERY_RETRIES,))
            rows = cur.fetchall()

    for (notif_id, account_id, domain, event_type, severity, title, description, resource_link,
         delivery, retry_count, notify_email, webhook_url, slack_webhook_url, sms_number,
         teams_webhook_url, discord_webhook_url) in rows:
        changed = False
        just_retried = {"additional_recipients": []}  # only what THIS round actually retried — for history logging
        # dict.get(key, {}) only falls back to {} when the key is absent —
        # here every channel key is always PRESENT with value None when
        # unconfigured, so that default never applies. `or {}` catches that.
        if (delivery.get("email") or {}).get("sent") is False and notify_email:
            delivery["email"] = _send_email(notify_email, title, description, severity)
            just_retried["email"] = delivery["email"]
            changed = True
        if (delivery.get("webhook") or {}).get("sent") is False and webhook_url:
            delivery["webhook"] = _post_webhook(webhook_url, {
                "id": str(notif_id), "domain": domain, "event_type": event_type,
                "severity": severity, "title": title, "description": description,
                "resource_link": resource_link,
            })
            just_retried["webhook"] = delivery["webhook"]
            changed = True
        if (delivery.get("slack") or {}).get("sent") is False and slack_webhook_url:
            delivery["slack"] = _post_webhook(slack_webhook_url, {
                "text": f"[{severity}] {title}" + (f"\n{description}" if description else ""),
            })
            just_retried["slack"] = delivery["slack"]
            changed = True
        if (delivery.get("teams") or {}).get("sent") is False and teams_webhook_url:
            delivery["teams"] = _post_webhook(teams_webhook_url, {
                "@type": "MessageCard", "@context": "http://schema.org/extensions",
                "summary": title, "themeColor": _SEVERITY_HEX.get(severity, "808080"),
                "title": f"Niagaros [{severity}] {domain}", "text": title,
            })
            just_retried["teams"] = delivery["teams"]
            changed = True
        if (delivery.get("sms") or {}).get("sent") is False and sms_number:
            delivery["sms"] = _send_sms(sms_number, title, severity)
            just_retried["sms"] = delivery["sms"]
            changed = True
        if (delivery.get("discord") or {}).get("sent") is False and discord_webhook_url:
            delivery["discord"] = _post_discord(discord_webhook_url, title, description, severity, domain)
            just_retried["discord"] = delivery["discord"]
            changed = True
        # Additional (named) recipients were never covered by a retry at all — only
        # the account's primary channels above were. Re-look-up each failed
        # recipient's current target (the failure result itself only records the
        # channel and outcome, not the address/URL) and retry just that channel.
        additional = delivery.get("additional_recipients") or []
        failed_additional = [a for a in additional if a.get("sent") is False]
        if failed_additional:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, notify_email, sms_number, slack_webhook_url, teams_webhook_url,
                           discord_webhook_url, webhook_url
                    FROM notification_recipients WHERE cloud_account_id = %s
                """, (account_id,))
                targets_by_id = {str(r[0]): {"email": r[1], "sms": r[2], "slack": r[3],
                                              "teams": r[4], "discord": r[5], "webhook": r[6]}
                                  for r in cur.fetchall()}
            for entry in failed_additional:
                target = (targets_by_id.get(entry.get("recipient_id")) or {}).get(entry.get("channel"))
                if not target:
                    continue  # recipient or that channel was removed since — nothing left to retry
                result = dispatch_to_channel(entry["channel"], target, title, description, severity, domain,
                                              notif_id, event_type, resource_link)
                entry.update(result)
                just_retried["additional_recipients"].append(entry)
                changed = True
        if changed:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE notifications SET delivery = %s, retry_count = retry_count + 1 WHERE id = %s
                    """, (json.dumps(delivery, default=str), notif_id))
            # Log only what this round actually retried — delivery still carries
            # every earlier, already-succeeded channel's result too, and those
            # must not be re-logged as if they were retried again just now.
            _log_delivery_attempts(conn, notif_id, just_retried, "retry")
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
                # Only a real, sent escalation counts as "done" (this query's own
                # WHERE clause treats a row here as "already escalated, never
                # again"). A failed send must be left alone so the next scheduled
                # run picks it back up and actually retries it, instead of the
                # unacknowledged notification silently never escalating at all.
                if result.get("sent"):
                    cur.execute("""
                        INSERT INTO notification_escalations (notification_id, escalated_to)
                        VALUES (%s, %s)
                    """, (notif_id, escalation_email))
                else:
                    logger.warning("escalation email failed for notification %s, will retry next run: %s",
                                    notif_id, result.get("reason"))
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
        return {"sent": False, "reason": _friendly_reason(e)}


class WebhookBlocked(Exception):
    pass


def _assert_public_webhook_url(url):
    """SSRF guard (this handler's `target`/webhook_url ultimately reaches
    urllib.request.urlopen with a fully caller-supplied URL): reject anything
    that isn't a plain https(s) call to a public host. Without this, a
    customer-configured webhook — or the test_channel action's `target`,
    which is nothing but this — could point at this Lambda's own container
    credentials endpoint (169.254.170.2) or the EC2/Lambda metadata address
    (169.254.169.254) and exfiltrate its real IAM credentials, or reach any
    other internal/private address this Lambda's network can otherwise see.
    Honesty note: this validates the resolved IP(s) once, up front, then
    connects by hostname as normal — it does not pin the connection to the
    validated IP, so it does not close a DNS-rebinding race where the name
    resolves differently a moment later. That residual gap is real."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise WebhookBlocked("webhook URL must be http:// or https://")
    host = parsed.hostname
    if not host:
        raise WebhookBlocked("webhook URL has no host")
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as e:
        raise WebhookBlocked(f"could not resolve webhook host: {e}")
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise WebhookBlocked("webhook URL resolves to a private/internal address, which is not allowed")


def _post_webhook(url, payload):
    try:
        _assert_public_webhook_url(url)
        req = urllib.request.Request(
            url, data=json.dumps(payload, default=str).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return {"sent": True, "status": resp.status}
    except WebhookBlocked as e:
        logger.warning("webhook blocked by SSRF guard: %s", e)
        return {"sent": False, "reason": str(e)}
    except Exception as e:
        logger.exception("notification webhook failed")
        return {"sent": False, "reason": _friendly_reason(e)}


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
