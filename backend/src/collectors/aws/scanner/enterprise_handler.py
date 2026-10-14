"""
enterprise_handler.py
Enterprise structure and permissions (issue #279: Enterprise Onboarding / Enterprise Permissions).

  Organization  -> Business Units -> AWS accounts (each account is assigned by ITS OWNER, who thereby consents)
  Members       -> role (org_admin | bu_admin | viewer) scoped to the whole organization or to ONE business unit

Access rule enforced everywhere by tenant_auth.guard:
  * the owner of an account always has full access to it;
  * an organization's owner (and its org_admins) can reach every account assigned to a business unit of the organization;
  * a member scoped to a business unit reaches ONLY the accounts of that unit;
  * viewers can read but never change anything.

POST actions: create_organization, create_business_unit, assign_account, unassign_account, invite_member,
              update_member, remove_member, delete_organization
GET  ?organizations=1  everything the caller can see, filtered to what their role allows.
"""
import json
import logging
import os
import re

import boto3
import psycopg2

from collectors.aws.scanner.tenant_auth import authenticate

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
ROLES = ("org_admin", "bu_admin", "viewer")
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

CORS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS business_units (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);
CREATE TABLE IF NOT EXISTS bu_accounts (
    business_unit_id UUID NOT NULL REFERENCES business_units(id) ON DELETE CASCADE,
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    assigned_by      TEXT,
    assigned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (business_unit_id, cloud_account_id)
);
CREATE TABLE IF NOT EXISTS org_members (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email            TEXT NOT NULL,
    role             TEXT NOT NULL CHECK (role IN ('org_admin', 'bu_admin', 'viewer')),
    business_unit_id UUID REFERENCES business_units(id) ON DELETE CASCADE,
    invited_by       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS org_members_unique ON org_members (organization_id, lower(email), COALESCE(business_unit_id, '00000000-0000-0000-0000-000000000000'::uuid));
CREATE INDEX IF NOT EXISTS org_members_email_idx ON org_members (lower(email));
CREATE INDEX IF NOT EXISTS bu_accounts_account_idx ON bu_accounts (cloud_account_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, business_units, bu_accounts, org_members TO cspm_lambda;
"""


def _resp(status, body):
    return {"statusCode": status, "headers": CORS, "body": json.dumps(body, default=str)}


def _get_connection():
    client = boto3.client("secretsmanager", region_name=REGION)
    s = json.loads(client.get_secret_value(SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"],
                            password=s["password"], sslmode="require", connect_timeout=10)


def _role_in_org(cur, org_id, email):
    """('owner'|'org_admin'|'bu_admin'|'viewer'|None, business_unit_id or None)."""
    cur.execute("SELECT owner_email FROM organizations WHERE id = %s", (org_id,))
    row = cur.fetchone()
    if not row:
        return None, None
    if row[0].lower() == email.lower():
        return "owner", None
    cur.execute("SELECT role, business_unit_id FROM org_members WHERE organization_id = %s AND lower(email) = lower(%s) ORDER BY (business_unit_id IS NULL) DESC LIMIT 1",
                (org_id, email))
    m = cur.fetchone()
    return (m[0], str(m[1]) if m[1] else None) if m else (None, None)


def _can_manage(role):
    return role in ("owner", "org_admin")


def _invite_email(to, org_name, role, sender_name):
    sender = os.environ.get("ENTERPRISE_SENDER_EMAIL") or "bottomclipzz@gmail.com"
    try:
        boto3.client("sesv2", region_name=REGION).send_email(
            FromEmailAddress=sender, Destination={"ToAddresses": [to]},
            Content={"Simple": {
                "Subject": {"Data": f"You have been added to {org_name} on Niagaros"},
                "Body": {"Text": {"Data": f"{sender_name} added you to the organization \"{org_name}\" as {role.replace('_', ' ')}.\n"
                                          f"Sign in to Niagaros with this email address to see the accounts you have been given access to.\n"}},
            }},
        )
        return {"sent": True}
    except Exception as e:
        logger.warning("invitation email failed: %s", e)
        return {"sent": False, "reason": str(e)}


def _overview(cur, email):
    """Every organization the caller can see, filtered to what their role allows."""
    cur.execute("""
        SELECT DISTINCT o.id FROM organizations o
        LEFT JOIN org_members m ON m.organization_id = o.id AND lower(m.email) = lower(%s)
        WHERE lower(o.owner_email) = lower(%s) OR m.id IS NOT NULL
    """, (email, email))
    out = []
    for (org_id,) in cur.fetchall():
        role, scope = _role_in_org(cur, str(org_id), email)
        cur.execute("SELECT name, owner_email, created_at FROM organizations WHERE id = %s", (org_id,))
        name, owner, created = cur.fetchone()
        cur.execute("SELECT id, name FROM business_units WHERE organization_id = %s ORDER BY name", (org_id,))
        units = []
        for bu_id, bu_name in cur.fetchall():
            if scope and str(bu_id) != scope:
                continue
            cur.execute("""
                SELECT c.id, c.account_name FROM bu_accounts ba JOIN cloud_accounts c ON c.id = ba.cloud_account_id
                WHERE ba.business_unit_id = %s ORDER BY c.account_name
            """, (bu_id,))
            units.append({"id": str(bu_id), "name": bu_name, "accounts": [{"id": str(a), "name": n} for a, n in cur.fetchall()]})
        members = []
        if _can_manage(role):
            cur.execute("SELECT id, email, role, business_unit_id, created_at FROM org_members WHERE organization_id = %s ORDER BY created_at", (org_id,))
            members = [{"id": str(i), "email": e, "role": r, "business_unit_id": str(b) if b else None, "created_at": c} for i, e, r, b, c in cur.fetchall()]
        out.append({"id": str(org_id), "name": name, "owner_email": owner, "created_at": created, "my_role": role,
                    "my_scope_business_unit_id": scope, "business_units": units, "members": members})
    return out


def handler(event, context):
    if event and event.get("action") == "migrate":
        conn = _get_connection()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(BOOTSTRAP_SQL)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()
    if not event or "httpMethod" not in event:
        return {"statusCode": 400, "body": json.dumps({"error": "not an API Gateway event"})}
    method = event["httpMethod"]
    if method == "OPTIONS":
        return _resp(200, {})
    try:
        body = json.loads(event["body"]) if event.get("body") else {}
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
    except (ValueError, TypeError):
        return _resp(400, {"error": "Invalid JSON"})
    email = authenticate(event)
    if not email:
        return _resp(401, {"error": "Unauthorized"})

    qs = event.get("queryStringParameters") or {}
    conn = _get_connection()
    try:
        if method == "GET":
            with conn.cursor() as cur:
                return _resp(200, {"organizations": _overview(cur, email), "caller": email})
        if method != "POST":
            return _resp(405, {"error": "method not allowed"})

        action = body.get("action")
        with conn:
            with conn.cursor() as cur:
                if action == "create_organization":
                    name = (body.get("name") or "").strip()
                    if not name:
                        return _resp(400, {"error": "name is required"})
                    cur.execute("INSERT INTO organizations (name, owner_email) VALUES (%s, %s) RETURNING id", (name, email))
                    return _resp(200, {"id": str(cur.fetchone()[0])})

                org_id = body.get("organization_id")
                if action == "create_business_unit":
                    role, _ = _role_in_org(cur, org_id, email) if org_id else (None, None)
                    if not _can_manage(role):
                        return _resp(403, {"error": "Forbidden"})
                    name = (body.get("name") or "").strip()
                    if not name:
                        return _resp(400, {"error": "name is required"})
                    cur.execute("INSERT INTO business_units (organization_id, name) VALUES (%s, %s) ON CONFLICT (organization_id, name) DO NOTHING RETURNING id", (org_id, name))
                    row = cur.fetchone()
                    if not row:
                        return _resp(409, {"error": "a business unit with that name already exists"})
                    return _resp(200, {"id": str(row[0])})

                if action in ("assign_account", "unassign_account"):
                    cur.execute("SELECT organization_id FROM business_units WHERE id = %s", (body.get("business_unit_id"),))
                    r = cur.fetchone()
                    if not r:
                        return _resp(404, {"error": "business unit not found"})
                    role, scope = _role_in_org(cur, str(r[0]), email)
                    cur.execute("SELECT owner_email FROM cloud_accounts WHERE id = %s", (body.get("cloud_account_id"),))
                    a = cur.fetchone()
                    if not a:
                        return _resp(404, {"error": "account not found"})
                    owns = a[0].lower() == email.lower()
                    if action == "assign_account":
                        # The account's owner consents by assigning it; and must be allowed to add to THIS unit.
                        allowed = owns and (_can_manage(role) or (role == "bu_admin" and scope == body["business_unit_id"]))
                    else:
                        allowed = owns or _can_manage(role)
                    if not allowed:
                        return _resp(403, {"error": "Forbidden"})
                    if action == "assign_account":
                        cur.execute("INSERT INTO bu_accounts (business_unit_id, cloud_account_id, assigned_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                                    (body["business_unit_id"], body["cloud_account_id"], email))
                    else:
                        cur.execute("DELETE FROM bu_accounts WHERE business_unit_id = %s AND cloud_account_id = %s", (body["business_unit_id"], body["cloud_account_id"]))
                    return _resp(200, {"ok": True})

                if action == "invite_member":
                    role, _ = _role_in_org(cur, org_id, email) if org_id else (None, None)
                    if not _can_manage(role):
                        return _resp(403, {"error": "Forbidden"})
                    to = (body.get("email") or "").strip()
                    new_role, bu_id = body.get("role"), body.get("business_unit_id") or None
                    if not _EMAIL_RE.match(to):
                        return _resp(400, {"error": "a valid email is required"})
                    if new_role not in ROLES:
                        return _resp(400, {"error": f"role must be one of {ROLES}"})
                    if new_role == "org_admin" and bu_id:
                        return _resp(400, {"error": "org_admin applies to the whole organization"})
                    if new_role != "org_admin" and not bu_id:
                        return _resp(400, {"error": "bu_admin and viewer must be scoped to a business_unit_id"})
                    if bu_id:
                        cur.execute("SELECT 1 FROM business_units WHERE id = %s AND organization_id = %s", (bu_id, org_id))
                        if not cur.fetchone():
                            return _resp(400, {"error": "that business unit is not part of this organization"})
                    cur.execute("""INSERT INTO org_members (organization_id, email, role, business_unit_id, invited_by) VALUES (%s, %s, %s, %s, %s)
                                   ON CONFLICT DO NOTHING RETURNING id""", (org_id, to, new_role, bu_id, email))
                    row = cur.fetchone()
                    if not row:
                        return _resp(409, {"error": "that person already has this access"})
                    cur.execute("SELECT name FROM organizations WHERE id = %s", (org_id,))
                    return _resp(200, {"id": str(row[0]), "email": _invite_email(to, cur.fetchone()[0], new_role, email)})

                if action in ("update_member", "remove_member"):
                    cur.execute("SELECT organization_id FROM org_members WHERE id = %s", (body.get("member_id"),))
                    r = cur.fetchone()
                    if not r:
                        return _resp(404, {"error": "member not found"})
                    role, _ = _role_in_org(cur, str(r[0]), email)
                    if not _can_manage(role):
                        return _resp(403, {"error": "Forbidden"})
                    if action == "remove_member":
                        cur.execute("DELETE FROM org_members WHERE id = %s", (body["member_id"],))
                    else:
                        if body.get("role") not in ROLES:
                            return _resp(400, {"error": f"role must be one of {ROLES}"})
                        cur.execute("UPDATE org_members SET role = %s WHERE id = %s", (body["role"], body["member_id"]))
                    return _resp(200, {"ok": True})

                if action == "delete_organization":
                    role, _ = _role_in_org(cur, org_id, email) if org_id else (None, None)
                    if role != "owner":
                        return _resp(403, {"error": "Only the owner can delete an organization"})
                    cur.execute("DELETE FROM organizations WHERE id = %s", (org_id,))
                    return _resp(200, {"deleted": True})

        return _resp(400, {"error": f"unknown action: {action}"})
    except Exception as e:
        logger.error("enterprise_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": "internal error"})
    finally:
        conn.close()
