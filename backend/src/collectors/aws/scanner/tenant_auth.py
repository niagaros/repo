"""
tenant_auth.py
Tenant isolation for every handler that serves an account's private data (issue #279: authentication,
authorization, tenant isolation, IDOR/BOLA).

    denied = guard(event, conn, qs, body, REFS, public=is_public)
    if denied: return _resp(*denied)

Rules
  1. The caller must present a valid Cognito access token (same check get-dashboard-data uses).
  2. Every account the request touches must be owned by that caller (cloud_accounts.owner_email).
     "Touches" = an explicit cloud_account_id AND every referenced record id (vendor_id, audit_id,
     questionnaire_id, ...), each resolved to the account that really owns it — so an id-only action such as
     delete_vendor cannot reach another tenant's row even though it names no account.
  3. Explicitly public entry points (a public Trust Center page, a share link with its secret token)
     are declared by the handler through `public`; everything else is private by default.

Operational safety valve: setting the Lambda environment variable TENANT_AUTH_ENFORCE=0 turns enforcement off
without a redeploy (e.g. if a page that predates the token change must keep working). It is on by default.
"""
import logging
import os
import re

import boto3

logger = logging.getLogger(__name__)

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _is_uuid(v):
    return isinstance(v, str) and bool(_UUID_RE.match(v))


def authenticate(event):
    """Returns the caller's verified email, or None when the token is missing/invalid/expired."""
    headers = (event or {}).get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    if not token:
        return None
    try:
        cognito = boto3.client("cognito-idp", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))
        user = cognito.get_user(AccessToken=token)
    except Exception:
        return None
    return next((a["Value"] for a in user["UserAttributes"] if a["Name"] == "email"), None)


def _accounts_touched(cur, qs, body, refs):
    accounts = set()
    for src in (qs or {}, body or {}):
        acct = src.get("cloud_account_id")
        if _is_uuid(acct):
            accounts.add(acct.lower())
        for key, sql in (refs or {}).items():
            val = src.get(key)
            if isinstance(val, str) and (key == "token" or _is_uuid(val)):
                cur.execute(sql, (val,))
                row = cur.fetchone()
                if row and row[0]:
                    accounts.add(str(row[0]).lower())
    return accounts


def guard(event, conn, qs, body, refs=None, public=None):
    """None when allowed, else (status_code, message)."""
    if os.environ.get("TENANT_AUTH_ENFORCE", "1") == "0":
        return None
    if public is not None and public(event, qs or {}, body or {}):
        return None
    email = authenticate(event)
    if not email:
        return 401, "Unauthorized"
    with conn.cursor() as cur:
        accounts = _accounts_touched(cur, qs, body, refs)
        if accounts:
            cur.execute(
                "SELECT count(*) FROM cloud_accounts WHERE id = ANY(%s::uuid[]) AND lower(owner_email) = lower(%s)",
                (list(accounts), email),
            )
            if cur.fetchone()[0] != len(accounts):
                logger.warning("tenant isolation: %s denied access to %s", email, sorted(accounts))
                return 403, "Forbidden"
    conn.commit()
    return None
