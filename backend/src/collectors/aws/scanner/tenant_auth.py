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
import json
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


# POST actions that only read (everything else that is not GET counts as a change).
READ_ONLY_ACTIONS = ("ask",)

# An account is reachable by (a) its owner, or (b) a member of an organization that has the account in one of its
# business units - the organization's owner and org_admins org-wide, bu_admins/viewers only in their own unit -
# and only owners, org_admins and bu_admins may change anything.
ACCESS_SQL = """
SELECT c.id FROM cloud_accounts c
WHERE c.id = ANY(%(ids)s::uuid[])
  AND (
    lower(c.owner_email) = lower(%(email)s)
    OR EXISTS (
      SELECT 1 FROM bu_accounts ba
      JOIN business_units b ON b.id = ba.business_unit_id
      JOIN organizations o ON o.id = b.organization_id
      LEFT JOIN org_members m ON m.organization_id = o.id AND lower(m.email) = lower(%(email)s)
      WHERE ba.cloud_account_id = c.id
        AND ( lower(o.owner_email) = lower(%(email)s)
              OR ( m.id IS NOT NULL
                   AND (m.business_unit_id IS NULL OR m.business_unit_id = b.id)
                   AND (NOT %(write)s OR m.role IN ('org_admin', 'bu_admin')) ) )
    )
  )
"""


def _is_write(event, body):
    if ((event or {}).get("httpMethod") or "GET") in ("GET", "HEAD", "OPTIONS"):
        return False
    return (body or {}).get("action") not in READ_ONLY_ACTIONS


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


def _record_denial(conn, email, accounts, event, qs, body):
    """Every cross-tenant attempt leaves an audit event the owner of the targeted account can read
    (security_audit_log). Recording must never turn a denial into an error."""
    try:
        identity = ((event or {}).get("requestContext") or {}).get("identity") or {}
        detail = {"action": (body or {}).get("action"), "query_keys": sorted((qs or {}).keys())[:10]}
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO security_audit_log (event_type, actor_email, cloud_account_ids, http_method, path, source_ip, detail)
                   VALUES ('access_denied', %s, %s::uuid[], %s, %s, %s, %s::jsonb)""",
                (email, sorted(accounts), (event or {}).get("httpMethod"), (event or {}).get("path"),
                 identity.get("sourceIp"), json.dumps(detail)),
            )
        conn.commit()
    except Exception:
        logger.exception("could not write the security audit event")
        try:
            conn.rollback()
        except Exception:
            pass


def account_allowed(cur, email, account_id, write=False):
    """Explicit single-account check for a call site where the id being acted on is only
    known AFTER guard() already ran — e.g. resolved via a lookup inside the action itself,
    against a table REFS (declared once, at request entry) cannot see. guard()'s own
    REFS-based check only protects ids present in qs/body under a name REFS declares; when a
    handler has more than one code path that reaches the same kind of id through a different
    table, each of those paths must call this directly instead of trusting REFS covered it."""
    if not _is_uuid(account_id):
        return False
    cur.execute(ACCESS_SQL, {"ids": [str(account_id).lower()], "email": email, "write": write})
    return len(cur.fetchall()) == 1


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
            cur.execute(ACCESS_SQL, {"ids": list(accounts), "email": email, "write": _is_write(event, body)})
            if len(cur.fetchall()) != len(accounts):
                logger.warning("tenant isolation: %s denied access to %s", email, sorted(accounts))
                _record_denial(conn, email, accounts, event, qs, body)
                return 403, "Forbidden"
    conn.commit()
    return None
