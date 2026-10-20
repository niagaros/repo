"""
post_confirmation.py — Cognito PostConfirmation trigger for user pool niagaros-users.

Creates the `users` row for someone who has just confirmed their sign-up. Migration 002 assumed this
trigger already existed ("the existing Cognito post-confirmation trigger ... is NOT in this repo"), but it
was never built: on 14 Oct 2026 only 2 of 12 Cognito users had a row, and every organization-scoped
endpoint (team, auditors, steps 5-7) refused the other 10. The users_default_organization trigger from
migration 002 then puts the new user in their own organization as admin; a pending team invitation is
accepted later by /team/accept-invite (useRequireAuth calls it on every page load).

Rules:
  - It must never block a sign-up. Cognito fails the confirmation response if this Lambda raises or runs
    past 5 seconds, so every error is logged and swallowed, every call has a short timeout without
    retries, and each step is skipped when too little of the invocation's time is left.
  - Only a verified email is provisioned (an administrator can confirm a user without verifying it).
  - Identity is the Cognito `sub`. If the email already belongs to a row with another `sub`, nothing is
    written: that row is someone else's account and is never adopted.
  - Re-running is harmless (ON CONFLICT DO NOTHING; the DB trigger's organization is rolled back if the
    insert loses).
"""
import json
import logging
import os

import boto3
import psycopg2
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_secret_cache: dict = {}


# The Lambda has a 4-second timeout (Cognito allows 5). A step only starts when its worst case still
# fits in what is left, plus headroom to return: Secrets Manager <= 2 s (1 s connect + 1 s read, no
# retries), PostgreSQL connect <= 2 s (libpq's minimum connect_timeout), three statements <= 0.5 s each.
NEED_MS = {"secret": 3600, "connect": 2700, "provision": 1800}
_FAST = Config(connect_timeout=1, read_timeout=1, retries={"total_max_attempts": 1})


class _OutOfTime(Exception):
    pass


def _ensure_time(context, step):
    if context is not None and context.get_remaining_time_in_millis() < NEED_MS[step]:
        raise _OutOfTime()


def _credentials() -> dict:
    if not _secret_cache:
        name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
        sm = boto3.client("secretsmanager", config=_FAST)
        _secret_cache.update(json.loads(sm.get_secret_value(SecretId=name)["SecretString"]))
    return _secret_cache


def _connect():
    c = _credentials()
    return psycopg2.connect(
        host=c["host"], dbname=c.get("database") or c.get("dbname"), user=c["username"], password=c["password"],
        port=c.get("port", 5432), sslmode="require", connect_timeout=2,
        options="-c statement_timeout=500 -c lock_timeout=300",
    )


def provision_user(conn, sub: str, email: str, full_name: str | None) -> str:
    """Returns 'created', 'exists' or 'email_taken'. Commits or rolls back itself."""
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE cognito_sub = %s", (sub,))
        if cur.fetchone():
            conn.rollback()
            return "exists"
        cur.execute("SELECT 1 FROM users WHERE lower(email) = lower(%s)", (email,))
        if cur.fetchone():
            conn.rollback()
            return "email_taken"
        cur.execute("INSERT INTO users (cognito_sub, email, full_name) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                    (sub, email, full_name or None))
        created = cur.rowcount == 1
    if created:
        conn.commit()
        return "created"
    conn.rollback()  # lost a race; also undoes the organization the DB trigger made
    return "exists"


def lambda_handler(event, context):
    # Only a confirmed sign-up creates a user; a confirmed password reset does not.
    if event.get("triggerSource") != "PostConfirmation_ConfirmSignUp":
        return event
    attrs = (event.get("request") or {}).get("userAttributes") or {}
    sub, email = attrs.get("sub"), attrs.get("email")
    if not sub or not email:
        logger.warning("post_confirmation: event without sub or email; nothing to do")
        return event
    if attrs.get("email_verified") != "true":
        logger.info("post_confirmation: email not verified; not provisioning (the API does it once verified)")
        return event
    conn = None
    try:
        if not _secret_cache:
            _ensure_time(context, "secret")
            _credentials()
        _ensure_time(context, "connect")
        conn = _connect()
        _ensure_time(context, "provision")
        outcome = provision_user(conn, sub, email, attrs.get("name"))
        if outcome == "email_taken":
            logger.warning("post_confirmation: email already belongs to another identity; not provisioning")
        else:
            logger.info(f"post_confirmation: {outcome}")
    except _OutOfTime:
        logger.warning("post_confirmation: skipped, not enough time left before Cognito's limit")
    except Exception as e:
        # Never fail the sign-up: the governance API also provisions on first request as a fallback.
        logger.error(f"post_confirmation: could not provision user — {type(e).__name__}: {e}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return event
