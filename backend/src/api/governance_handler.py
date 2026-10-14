"""
governance_handler.py — onboarding steps 5, 6 and 7 of the Onboarding
Accelerator (#270):

  5. Configure Compliance  (#281)  GET/PUT/POST/DELETE /compliance...
  6. Configure Governance  (#282)  GET/POST            /governance...
  7. Security Training             GET/POST            /training...

Same shape as team_handler / auditor_handler: one Lambda, HTTP API payload
v2.0, the caller resolved through team_handler._get_caller (Cognito access
token -> active user -> organization), and every query scoped to that
organization. No row from another organization can be read or changed:
ids from the request are only ever used together with the caller's
organization_id.

What each step means, and when it counts as done (see step_complete in the
GET responses — the onboarding page reads that, it never decides itself):

  5. The organization has chosen at least one framework. Only frameworks
     Niagaros actually maps findings to can be chosen (MAPPED_FRAMEWORK_NAMES),
     so a choice here always has real checks behind it.
  6. At least one policy has an approved, published version. Policies are
     versioned; a version is written by one person and approved by another
     (separation of duties, also enforced by a CHECK in the database).
  7. "Training" is reading and acknowledging the published policies that
     require it. Niagaros has no course content of its own, and inventing
     some would be fake; an acknowledgement per person per version is real
     and measurable. Done when every active member has acknowledged the
     current version of every such policy.

Every change is written to team_audit_log with the previous and new state,
so the organization keeps one audit trail.
"""
import base64
import json
import logging
import os
import re
from datetime import date, datetime, timedelta

from config.database import Database, MAPPED_FRAMEWORK_NAMES
from api.team_handler import _get_caller, _response, _route_path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

COMPLIANCE_EDITORS = {"admin", "compliance"}
GOVERNANCE_AUTHORS = {"admin", "compliance", "security"}

FRAMEWORK_STATUSES = {"not_started", "in_progress", "certified", "expired"}
CERTIFICATION_STATUSES = {"active", "in_renewal", "suspended", "expired"}
RISK_LEVELS = {"low", "medium", "high", "critical"}
POLICY_CATEGORIES = [
    "Information Security", "Access Control", "Data Protection", "Risk Management",
    "Incident Management", "Third-Party Risk", "Cloud Security", "AI Governance",
    "Acceptable Use", "Business Continuity", "Change Management", "Vulnerability Management",
    "Other",
]

# How far ahead an expiry or review date counts as "coming up" on the pages.
REMINDER_DAYS = 30

AUDIT_PREFIXES = ("compliance_", "governance_", "training_")

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _token_from_our_pool(event: dict) -> bool:
    """
    cognito-idp:GetUser accepts a valid access token from ANY user pool, and anyone can create a
    pool and give themselves any email address. So before trusting the email GetUser returns, check
    that the token was issued by our pool. GetUser itself verifies the signature for the pool named
    in `iss`, so checking `iss` here is enough to pin it to ours. Fails closed when the pool id is
    not configured.
    """
    pool_id = os.environ.get("COGNITO_USER_POOL_ID", "")
    if not pool_id:
        logger.error("governance_handler: COGNITO_USER_POOL_ID is not set; refusing all requests")
        return False
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if not auth.startswith("Bearer "):
        return False
    try:
        payload = auth[7:].strip().split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return False
    region = pool_id.split("_")[0]
    return (claims.get("iss") == f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"
            and claims.get("token_use") == "access")


class RequestError(Exception):
    """A request the caller has to fix; becomes a 4xx with a readable message."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# ── input helpers ────────────────────────────────────────────────────────

def _body(event: dict) -> dict:
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        raise RequestError(400, "The request body is not valid JSON.")
    if not isinstance(body, dict):
        raise RequestError(400, "The request body must be a JSON object.")
    return body


def _text(body: dict, field: str, label: str, required: bool = True, max_len: int = 200) -> str | None:
    value = body.get(field)
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise RequestError(400, f"{label} is required.")
        return None
    if not isinstance(value, str):
        raise RequestError(400, f"{label} must be text.")
    value = value.strip()
    if len(value) > max_len:
        raise RequestError(400, f"{label} can be at most {max_len} characters.")
    return value


def _date(body: dict, field: str, label: str, required: bool = False) -> date | None:
    value = body.get(field)
    if value in (None, ""):
        if required:
            raise RequestError(400, f"{label} is required.")
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date()
    except ValueError:
        raise RequestError(400, f"{label} must be a date (YYYY-MM-DD).")


def _choice(body: dict, field: str, label: str, allowed, default=None) -> str:
    value = body.get(field, default)
    if value not in allowed:
        raise RequestError(400, f"{label} must be one of: {', '.join(sorted(allowed))}.")
    return value


def _bool(body: dict, field: str, label: str, default: bool | None = None) -> bool:
    value = body.get(field, default)
    if not isinstance(value, bool):
        raise RequestError(400, f"{label} must be true or false.")
    return value


def _uuid(value, label: str) -> str:
    if not isinstance(value, str) or not UUID_RE.match(value):
        raise RequestError(404, f"{label} not found.")
    return value


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def _days_until(d: date | None) -> int | None:
    return (d - date.today()).days if d else None


def _active_members(db: Database, organization_id: str) -> list:
    return [m for m in db.get_organization_members(organization_id) if m["status"] == "active"]


def _member_email(db: Database, organization_id: str, email: str | None, label: str) -> str | None:
    """An owner/approver must be an active member of the organization — ownership by a stranger is no ownership."""
    if email is None:
        return None
    for m in _active_members(db, organization_id):
        if m["email"].lower() == email.lower():
            return m["email"]
    raise RequestError(400, f"{label} must be an active member of your team.")


def _require_role(caller: dict, roles: set, what: str):
    if caller["role"] not in roles:
        raise RequestError(403, f"Your role ({caller['role']}) cannot {what}.")


def _audit(db: Database, caller: dict, action: str, details: dict):
    """Writes the audit row in the caller's open transaction (not via Database.log_audit_event, which
    commits on its own): the change and its audit entry are committed together or not at all."""
    with db.conn.cursor() as cur:
        cur.execute("""
            INSERT INTO team_audit_log (organization_id, actor_user_id, action, details)
            VALUES (%s, %s, %s, %s)
        """, (caller["organization_id"], caller["id"], action, json.dumps(details, default=str)))


def _audit_trail(db: Database, organization_id: str, limit: int = 100) -> list:
    with db.conn.cursor() as cur:
        cur.execute("""
            SELECT al.action, al.details, al.created_at, actor.email
            FROM team_audit_log al
            LEFT JOIN users actor ON actor.id = al.actor_user_id
            WHERE al.organization_id = %s
              AND (al.action LIKE 'compliance\\_%%' OR al.action LIKE 'governance\\_%%' OR al.action LIKE 'training\\_%%')
            ORDER BY al.created_at DESC
            LIMIT %s
        """, (organization_id, limit))
        rows = cur.fetchall()
    return [{"action": r[0], "details": r[1], "created_at": _iso(r[2]), "actor_email": r[3]} for r in rows]


# ── step 5: compliance ───────────────────────────────────────────────────

def _frameworks(db: Database, organization_id: str) -> list:
    with db.conn.cursor() as cur:
        cur.execute("""
            SELECT id, framework_name, enabled, version, owner_email, certification_status,
                   effective_date, expiration_date, updated_at
            FROM compliance_frameworks WHERE organization_id = %s ORDER BY framework_name
        """, (organization_id,))
        rows = cur.fetchall()
    return [{
        "id": str(r[0]), "framework_name": r[1], "enabled": r[2], "version": r[3], "owner_email": r[4],
        "certification_status": r[5], "effective_date": _iso(r[6]), "expiration_date": _iso(r[7]),
        "expires_in_days": _days_until(r[7]), "updated_at": _iso(r[8]),
    } for r in rows]


def _certifications(db: Database, organization_id: str) -> list:
    with db.conn.cursor() as cur:
        cur.execute("""
            SELECT id, name, standard, status, certification_body, issue_date, expiration_date, renewal_date
            FROM compliance_certifications WHERE organization_id = %s ORDER BY expiration_date NULLS LAST, name
        """, (organization_id,))
        rows = cur.fetchall()
    return [{
        "id": str(r[0]), "name": r[1], "standard": r[2], "status": r[3], "certification_body": r[4],
        "issue_date": _iso(r[5]), "expiration_date": _iso(r[6]), "renewal_date": _iso(r[7]),
        "expires_in_days": _days_until(r[6]),
    } for r in rows]


def compliance_step_complete(db: Database, organization_id: str) -> bool:
    with db.conn.cursor() as cur:
        cur.execute("SELECT 1 FROM compliance_frameworks WHERE organization_id = %s AND enabled LIMIT 1",
                    (organization_id,))
        return cur.fetchone() is not None


def handle_get_compliance(caller: dict, db: Database, event: dict) -> dict:
    org = caller["organization_id"]
    return _response(200, {
        "catalog": sorted(MAPPED_FRAMEWORK_NAMES),
        "frameworks": _frameworks(db, org),
        "certifications": _certifications(db, org),
        "members": [m["email"] for m in _active_members(db, org)],
        "reminder_days": REMINDER_DAYS,
        "can_edit": caller["role"] in COMPLIANCE_EDITORS,
        "step_complete": compliance_step_complete(db, org),
    })


def handle_save_framework(caller: dict, db: Database, event: dict) -> dict:
    _require_role(caller, COMPLIANCE_EDITORS, "change compliance frameworks")
    body = _body(event)
    org = caller["organization_id"]
    name = body.get("framework_name")
    if name not in MAPPED_FRAMEWORK_NAMES:
        raise RequestError(400, "Choose a framework from the list; Niagaros only offers frameworks it can check.")
    enabled = _bool(body, "enabled", "Enabled", default=True)
    version = _text(body, "version", "Version", required=False, max_len=50)
    owner = _member_email(db, org, _text(body, "owner_email", "Owner", required=False), "The owner")
    status = _choice(body, "certification_status", "Certification status", FRAMEWORK_STATUSES, "not_started")
    effective = _date(body, "effective_date", "Effective date")
    expiration = _date(body, "expiration_date", "Expiration date")
    if effective and expiration and expiration < effective:
        raise RequestError(400, "The expiration date cannot be before the effective date.")

    before = next((f for f in _frameworks(db, org) if f["framework_name"] == name), None)
    with db.conn.cursor() as cur:
        cur.execute("""
            INSERT INTO compliance_frameworks
                (organization_id, framework_name, enabled, version, owner_email, certification_status,
                 effective_date, expiration_date, updated_by, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (organization_id, framework_name) DO UPDATE SET
                enabled = EXCLUDED.enabled, version = EXCLUDED.version, owner_email = EXCLUDED.owner_email,
                certification_status = EXCLUDED.certification_status, effective_date = EXCLUDED.effective_date,
                expiration_date = EXCLUDED.expiration_date, updated_by = EXCLUDED.updated_by, updated_at = NOW()
        """, (org, name, enabled, version, owner, status, effective, expiration, caller["id"]))
    after = next(f for f in _frameworks(db, org) if f["framework_name"] == name)
    strip = lambda f: f and {k: v for k, v in f.items() if k not in ("id", "updated_at", "expires_in_days")}
    _audit(db, caller, "compliance_framework_saved",
           {"framework": name, "previous": strip(before), "new": strip(after)})
    db.conn.commit()
    return _response(200, {"framework": after, "step_complete": compliance_step_complete(db, org)})


def handle_add_certification(caller: dict, db: Database, event: dict) -> dict:
    _require_role(caller, COMPLIANCE_EDITORS, "add certifications")
    body = _body(event)
    org = caller["organization_id"]
    name = _text(body, "name", "Certification name")
    standard = _text(body, "standard", "Standard")
    status = _choice(body, "status", "Status", CERTIFICATION_STATUSES, "active")
    cert_body = _text(body, "certification_body", "Certification body", required=False)
    issue = _date(body, "issue_date", "Issue date")
    expiration = _date(body, "expiration_date", "Expiration date")
    renewal = _date(body, "renewal_date", "Renewal date")
    if issue and expiration and expiration < issue:
        raise RequestError(400, "The expiration date cannot be before the issue date.")
    with db.conn.cursor() as cur:
        cur.execute("""
            INSERT INTO compliance_certifications
                (organization_id, name, standard, status, certification_body, issue_date, expiration_date,
                 renewal_date, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
        """, (org, name, standard, status, cert_body, issue, expiration, renewal, caller["id"]))
        new_id = str(cur.fetchone()[0])
    _audit(db, caller, "compliance_certification_added",
           {"id": new_id, "name": name, "standard": standard, "status": status,
            "expiration_date": _iso(expiration)})
    db.conn.commit()
    return _response(201, {"id": new_id})


def handle_delete_certification(caller: dict, db: Database, event: dict, cert_id: str) -> dict:
    _require_role(caller, COMPLIANCE_EDITORS, "remove certifications")
    cert_id = _uuid(cert_id, "Certification")
    with db.conn.cursor() as cur:
        cur.execute("""
            DELETE FROM compliance_certifications WHERE id = %s AND organization_id = %s
            RETURNING name, standard, status, expiration_date
        """, (cert_id, caller["organization_id"]))
        row = cur.fetchone()
    if not row:
        db.conn.rollback()
        raise RequestError(404, "Certification not found.")
    _audit(db, caller, "compliance_certification_removed",
           {"id": cert_id, "previous": {"name": row[0], "standard": row[1], "status": row[2],
                                        "expiration_date": _iso(row[3])}})
    db.conn.commit()
    return _response(200, {"removed": cert_id})


# ── step 6: governance ───────────────────────────────────────────────────

def _policies(db: Database, organization_id: str) -> list:
    with db.conn.cursor() as cur:
        cur.execute("""
            SELECT id, name, category, owner_email, approver_email, review_date, requires_acknowledgement,
                   published_version, retired, created_at
            FROM governance_policies WHERE organization_id = %s ORDER BY retired, name
        """, (organization_id,))
        policies = cur.fetchall()
        cur.execute("""
            SELECT v.policy_id, v.version, v.content, v.change_summary, v.status, a.email, d.email,
                   v.decided_at, v.decision_note, v.created_at, v.author_id
            FROM governance_policy_versions v
            JOIN governance_policies p ON p.id = v.policy_id
            LEFT JOIN users a ON a.id = v.author_id
            LEFT JOIN users d ON d.id = v.decided_by
            WHERE p.organization_id = %s
            ORDER BY v.version DESC
        """, (organization_id,))
        versions = cur.fetchall()
    by_policy: dict = {}
    for v in versions:
        by_policy.setdefault(str(v[0]), []).append({
            "version": v[1], "content": v[2], "change_summary": v[3], "status": v[4],
            "author_email": v[5], "decided_by_email": v[6], "decided_at": _iso(v[7]),
            "decision_note": v[8], "created_at": _iso(v[9]), "author_id": str(v[10]),
        })
    out = []
    for p in policies:
        pid = str(p[0])
        review_in = _days_until(p[5])
        out.append({
            "id": pid, "name": p[1], "category": p[2], "owner_email": p[3], "approver_email": p[4],
            "review_date": _iso(p[5]), "review_in_days": review_in,
            "requires_acknowledgement": p[6], "published_version": p[7], "retired": p[8],
            "created_at": _iso(p[9]), "versions": by_policy.get(pid, []),
        })
    return out


def _exceptions(db: Database, organization_id: str) -> list:
    with db.conn.cursor() as cur:
        cur.execute("""
            SELECT e.id, e.policy_id, p.name, e.requirement, e.justification, e.risk, e.compensating_controls,
                   e.scope, e.owner_email, r.email, e.status, e.start_date, e.expiration_date,
                   d.email, e.decided_at, e.decision_note, e.created_at, e.requested_by
            FROM governance_exceptions e
            LEFT JOIN governance_policies p ON p.id = e.policy_id
            LEFT JOIN users r ON r.id = e.requested_by
            LEFT JOIN users d ON d.id = e.decided_by
            WHERE e.organization_id = %s
            ORDER BY e.created_at DESC
        """, (organization_id,))
        rows = cur.fetchall()
    today = date.today()
    out = []
    for r in rows:
        active = r[10] == "approved" and r[11] <= today <= r[12]
        out.append({
            "id": str(r[0]), "policy_id": str(r[1]) if r[1] else None, "policy_name": r[2],
            "requirement": r[3], "justification": r[4], "risk": r[5], "compensating_controls": r[6],
            "scope": r[7], "owner_email": r[8], "requested_by_email": r[9], "status": r[10],
            "start_date": _iso(r[11]), "expiration_date": _iso(r[12]), "expires_in_days": _days_until(r[12]),
            "expired": r[12] < today, "active": active,
            "decided_by_email": r[13], "decided_at": _iso(r[14]), "decision_note": r[15],
            "created_at": _iso(r[16]), "requested_by": str(r[17]),
        })
    return out


def governance_step_complete(db: Database, organization_id: str) -> bool:
    with db.conn.cursor() as cur:
        cur.execute("""SELECT 1 FROM governance_policies
                       WHERE organization_id = %s AND NOT retired AND published_version IS NOT NULL LIMIT 1""",
                    (organization_id,))
        return cur.fetchone() is not None


def handle_get_governance(caller: dict, db: Database, event: dict) -> dict:
    org = caller["organization_id"]
    return _response(200, {
        "policies": _policies(db, org),
        "exceptions": _exceptions(db, org),
        "audit": _audit_trail(db, org),
        "categories": POLICY_CATEGORIES,
        "members": [{"email": m["email"], "role": m["role"]} for m in _active_members(db, org)],
        "me": {"id": caller["id"], "email": caller["email"], "role": caller["role"]},
        "reminder_days": REMINDER_DAYS,
        "can_author": caller["role"] in GOVERNANCE_AUTHORS,
        "step_complete": governance_step_complete(db, org),
    })


def _policy_row(db: Database, organization_id: str, policy_id: str, lock: bool = False):
    policy_id = _uuid(policy_id, "Policy")
    with db.conn.cursor() as cur:
        cur.execute(f"""
            SELECT id, name, owner_email, approver_email, published_version, retired
            FROM governance_policies WHERE id = %s AND organization_id = %s {'FOR UPDATE' if lock else ''}
        """, (policy_id, organization_id))
        row = cur.fetchone()
    if not row:
        raise RequestError(404, "Policy not found.")
    return {"id": str(row[0]), "name": row[1], "owner_email": row[2], "approver_email": row[3],
            "published_version": row[4], "retired": row[5]}


def handle_create_policy(caller: dict, db: Database, event: dict) -> dict:
    _require_role(caller, GOVERNANCE_AUTHORS, "write policies")
    body = _body(event)
    org = caller["organization_id"]
    name = _text(body, "name", "Policy name", max_len=150)
    category = _choice(body, "category", "Category", set(POLICY_CATEGORIES))
    owner = _member_email(db, org, _text(body, "owner_email", "Owner"), "The owner")
    approver = _member_email(db, org, _text(body, "approver_email", "Approver"), "The approver")
    if approver.lower() == caller["email"].lower():
        raise RequestError(400, "Choose someone else as approver: you cannot approve a policy you wrote.")
    review = _date(body, "review_date", "Review date")
    requires_ack = _bool(body, "requires_acknowledgement", "Requires acknowledgement", default=True)
    content = _text(body, "content", "Policy text", max_len=20000)
    summary = _text(body, "change_summary", "Change summary", required=False, max_len=500)
    with db.conn.cursor() as cur:
        cur.execute("SELECT 1 FROM governance_policies WHERE organization_id = %s AND lower(name) = lower(%s)",
                    (org, name))
        if cur.fetchone():
            raise RequestError(409, "A policy with this name already exists.")
        cur.execute("""
            INSERT INTO governance_policies
                (organization_id, name, category, owner_email, approver_email, review_date,
                 requires_acknowledgement, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
        """, (org, name, category, owner, approver, review, requires_ack, caller["id"]))
        policy_id = str(cur.fetchone()[0])
        cur.execute("""
            INSERT INTO governance_policy_versions (policy_id, version, content, change_summary, status, author_id)
            VALUES (%s, 1, %s, %s, 'pending_approval', %s)
        """, (policy_id, content, summary or "First version", caller["id"]))
    _audit(db, caller, "governance_policy_created",
           {"policy_id": policy_id, "name": name, "category": category, "owner": owner,
            "approver": approver, "version": 1, "status": "pending_approval"})
    db.conn.commit()
    return _response(201, {"id": policy_id, "version": 1})


def handle_new_policy_version(caller: dict, db: Database, event: dict, policy_id: str) -> dict:
    _require_role(caller, GOVERNANCE_AUTHORS, "write policies")
    body = _body(event)
    org = caller["organization_id"]
    policy = _policy_row(db, org, policy_id, lock=True)
    if policy["retired"]:
        raise RequestError(409, "This policy is retired.")
    content = _text(body, "content", "Policy text", max_len=20000)
    summary = _text(body, "change_summary", "Change summary", max_len=500)
    with db.conn.cursor() as cur:
        cur.execute("""SELECT 1 FROM governance_policy_versions
                       WHERE policy_id = %s AND status = 'pending_approval'""", (policy["id"],))
        if cur.fetchone():
            db.conn.rollback()
            raise RequestError(409, "A version of this policy is already waiting for approval.")
        cur.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM governance_policy_versions WHERE policy_id = %s",
                    (policy["id"],))
        version = cur.fetchone()[0]
        cur.execute("""
            INSERT INTO governance_policy_versions (policy_id, version, content, change_summary, status, author_id)
            VALUES (%s, %s, %s, %s, 'pending_approval', %s)
        """, (policy["id"], version, content, summary, caller["id"]))
    _audit(db, caller, "governance_policy_version_submitted",
           {"policy_id": policy["id"], "name": policy["name"], "version": version,
            "published_version": policy["published_version"]})
    db.conn.commit()
    return _response(201, {"id": policy["id"], "version": version})


def handle_policy_decision(caller: dict, db: Database, event: dict, policy_id: str) -> dict:
    body = _body(event)
    org = caller["organization_id"]
    policy = _policy_row(db, org, policy_id, lock=True)
    if policy["retired"]:
        db.conn.rollback()
        raise RequestError(409, "This policy is retired.")
    approve = _bool(body, "approve", "Approve")
    note = _text(body, "note", "Reason", required=not approve, max_len=1000)
    expected_version = body.get("version")
    if not isinstance(expected_version, int) or isinstance(expected_version, bool):
        db.conn.rollback()
        raise RequestError(400, "Say which version you reviewed.")
    is_named_approver = policy["approver_email"].lower() == caller["email"].lower()
    if not (is_named_approver or caller["role"] == "admin"):
        db.conn.rollback()
        raise RequestError(403, "Only the policy's approver or an admin can decide on it.")
    with db.conn.cursor() as cur:
        cur.execute("""SELECT version, author_id FROM governance_policy_versions
                       WHERE policy_id = %s AND status = 'pending_approval' FOR UPDATE""", (policy["id"],))
        row = cur.fetchone()
        if not row:
            db.conn.rollback()
            raise RequestError(409, "There is no version waiting for approval.")
        version, author_id = row
        if version != expected_version:
            db.conn.rollback()
            raise RequestError(409, f"Version {version} is now waiting for approval, not the version you reviewed. "
                                    "Reload and read it first.")
        if str(author_id) == caller["id"]:
            db.conn.rollback()
            raise RequestError(403, "You wrote this version, so someone else has to approve it.")
        cur.execute("""
            UPDATE governance_policy_versions
            SET status = %s, decided_by = %s, decided_at = NOW(), decision_note = %s
            WHERE policy_id = %s AND version = %s
        """, ("approved" if approve else "rejected", caller["id"], note, policy["id"], version))
        if approve:
            cur.execute("UPDATE governance_policies SET published_version = %s WHERE id = %s",
                        (version, policy["id"]))
    _audit(db, caller, "governance_policy_approved" if approve else "governance_policy_rejected",
           {"policy_id": policy["id"], "name": policy["name"], "version": version, "note": note,
            "previous_published_version": policy["published_version"],
            "published_version": version if approve else policy["published_version"]})
    db.conn.commit()
    return _response(200, {"id": policy["id"], "version": version, "status": "approved" if approve else "rejected"})


def handle_retire_policy(caller: dict, db: Database, event: dict, policy_id: str) -> dict:
    _require_role(caller, {"admin"}, "retire policies")
    policy = _policy_row(db, caller["organization_id"], policy_id, lock=True)
    if policy["retired"]:
        db.conn.rollback()
        raise RequestError(409, "This policy is already retired.")
    with db.conn.cursor() as cur:
        cur.execute("UPDATE governance_policies SET retired = true WHERE id = %s", (policy["id"],))
    _audit(db, caller, "governance_policy_retired",
           {"policy_id": policy["id"], "name": policy["name"], "published_version": policy["published_version"]})
    db.conn.commit()
    return _response(200, {"id": policy["id"], "retired": True})


def handle_request_exception(caller: dict, db: Database, event: dict) -> dict:
    _require_role(caller, GOVERNANCE_AUTHORS, "request exceptions")
    body = _body(event)
    org = caller["organization_id"]
    policy_id = body.get("policy_id") or None
    if policy_id:
        policy_id = _policy_row(db, org, policy_id)["id"]
    requirement = _text(body, "requirement", "Requirement", max_len=500)
    justification = _text(body, "justification", "Business justification", max_len=2000)
    risk = _choice(body, "risk", "Risk", RISK_LEVELS)
    compensating = _text(body, "compensating_controls", "Compensating controls", required=False, max_len=2000)
    scope = _text(body, "scope", "Scope", required=False, max_len=500)
    owner = _member_email(db, org, _text(body, "owner_email", "Owner"), "The owner")
    start = _date(body, "start_date", "Start date") or date.today()
    expiration = _date(body, "expiration_date", "Expiration date", required=True)
    if expiration < start:
        raise RequestError(400, "The expiration date cannot be before the start date.")
    if expiration > start + timedelta(days=366):
        raise RequestError(400, "An exception can last at most one year; request a new one after that.")
    with db.conn.cursor() as cur:
        cur.execute("""
            INSERT INTO governance_exceptions
                (organization_id, policy_id, requirement, justification, risk, compensating_controls, scope,
                 owner_email, requested_by, start_date, expiration_date)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
        """, (org, policy_id, requirement, justification, risk, compensating, scope, owner, caller["id"],
              start, expiration))
        new_id = str(cur.fetchone()[0])
    _audit(db, caller, "governance_exception_requested",
           {"exception_id": new_id, "requirement": requirement, "risk": risk, "owner": owner,
            "start_date": _iso(start), "expiration_date": _iso(expiration)})
    db.conn.commit()
    return _response(201, {"id": new_id})


def _exception_row(db: Database, organization_id: str, exception_id: str):
    exception_id = _uuid(exception_id, "Exception")
    with db.conn.cursor() as cur:
        cur.execute("""SELECT id, status, requested_by, requirement FROM governance_exceptions
                       WHERE id = %s AND organization_id = %s FOR UPDATE""", (exception_id, organization_id))
        row = cur.fetchone()
    if not row:
        db.conn.rollback()
        raise RequestError(404, "Exception not found.")
    return {"id": str(row[0]), "status": row[1], "requested_by": str(row[2]), "requirement": row[3]}


def handle_exception_decision(caller: dict, db: Database, event: dict, exception_id: str) -> dict:
    _require_role(caller, {"admin"}, "approve or reject exceptions")
    body = _body(event)
    approve = _bool(body, "approve", "Approve")
    note = _text(body, "note", "Reason", required=not approve, max_len=1000)
    exc = _exception_row(db, caller["organization_id"], exception_id)
    if exc["status"] != "requested":
        db.conn.rollback()
        raise RequestError(409, f"This exception is already {exc['status']}.")
    if exc["requested_by"] == caller["id"]:
        db.conn.rollback()
        raise RequestError(403, "You requested this exception, so another admin has to decide on it.")
    new_status = "approved" if approve else "rejected"
    with db.conn.cursor() as cur:
        cur.execute("""UPDATE governance_exceptions SET status = %s, decided_by = %s, decided_at = NOW(),
                       decision_note = %s WHERE id = %s""", (new_status, caller["id"], note, exc["id"]))
    _audit(db, caller, f"governance_exception_{new_status}",
           {"exception_id": exc["id"], "requirement": exc["requirement"], "previous_status": "requested",
            "status": new_status, "note": note})
    db.conn.commit()
    return _response(200, {"id": exc["id"], "status": new_status})


def handle_revoke_exception(caller: dict, db: Database, event: dict, exception_id: str) -> dict:
    _require_role(caller, {"admin"}, "revoke exceptions")
    body = _body(event)
    note = _text(body, "note", "Reason", max_len=1000)
    exc = _exception_row(db, caller["organization_id"], exception_id)
    if exc["status"] != "approved":
        db.conn.rollback()
        raise RequestError(409, "Only an approved exception can be revoked.")
    with db.conn.cursor() as cur:
        cur.execute("""UPDATE governance_exceptions SET status = 'revoked', decision_note = %s
                       WHERE id = %s""", (note, exc["id"]))
    _audit(db, caller, "governance_exception_revoked",
           {"exception_id": exc["id"], "requirement": exc["requirement"], "previous_status": "approved",
            "status": "revoked", "note": note})
    db.conn.commit()
    return _response(200, {"id": exc["id"], "status": "revoked"})


# ── step 7: training (policy acknowledgement) ────────────────────────────

def _training_state(db: Database, organization_id: str) -> dict:
    members = _active_members(db, organization_id)
    with db.conn.cursor() as cur:
        cur.execute("""
            SELECT p.id, p.name, p.category, p.published_version, v.content
            FROM governance_policies p
            JOIN governance_policy_versions v ON v.policy_id = p.id AND v.version = p.published_version
            WHERE p.organization_id = %s AND NOT p.retired AND p.requires_acknowledgement
              AND p.published_version IS NOT NULL
            ORDER BY p.name
        """, (organization_id,))
        policies = cur.fetchall()
        cur.execute("""
            SELECT a.policy_id, a.version, a.user_id, a.acknowledged_at
            FROM policy_acknowledgements a
            JOIN governance_policies p ON p.id = a.policy_id AND a.version = p.published_version
            WHERE a.organization_id = %s
        """, (organization_id,))
        acks = {(str(r[0]), r[1], str(r[2])): r[3] for r in cur.fetchall()}
    member_ids = {m["id"] for m in members}
    items = []
    for p in policies:
        pid, version = str(p[0]), p[3]
        acked = [uid for (ap, av, uid) in acks if ap == pid and av == version and uid in member_ids]
        items.append({"policy_id": pid, "name": p[1], "category": p[2], "version": version, "content": p[4],
                      "acknowledged_count": len(acked), "acked_user_ids": acked})
    progress = []
    for m in members:
        done = sum(1 for i in items if m["id"] in i["acked_user_ids"])
        progress.append({"email": m["email"], "role": m["role"], "done": done, "total": len(items)})
    complete = bool(items) and all(p["done"] == p["total"] for p in progress)
    return {"items": items, "progress": progress, "member_count": len(members), "complete": complete}


def training_step_complete(db: Database, organization_id: str) -> bool:
    return _training_state(db, organization_id)["complete"]


def handle_get_training(caller: dict, db: Database, event: dict) -> dict:
    state = _training_state(db, caller["organization_id"])
    me = caller["id"]
    items = [{k: v for k, v in i.items() if k != "acked_user_ids"} | {"acknowledged_by_me": me in i["acked_user_ids"]}
             for i in state["items"]]
    return _response(200, {
        "policies": items,
        # Only roles that manage the program see everyone's progress.
        "progress": state["progress"] if caller["role"] in GOVERNANCE_AUTHORS else None,
        "member_count": state["member_count"],
        "step_complete": state["complete"],
    })


def handle_acknowledge(caller: dict, db: Database, event: dict) -> dict:
    body = _body(event)
    org = caller["organization_id"]
    policy = _policy_row(db, org, body.get("policy_id"))
    version = body.get("version")
    if policy["retired"] or policy["published_version"] is None:
        raise RequestError(409, "This policy has no published version to acknowledge.")
    if version != policy["published_version"]:
        raise RequestError(409, "A newer version of this policy has been published. Reload and read it first.")
    with db.conn.cursor() as cur:
        cur.execute("""
            INSERT INTO policy_acknowledgements (organization_id, policy_id, version, user_id)
            VALUES (%s, %s, %s, %s) ON CONFLICT (policy_id, version, user_id) DO NOTHING
        """, (org, policy["id"], version, caller["id"]))
        inserted = cur.rowcount
    if inserted:
        _audit(db, caller, "training_policy_acknowledged",
               {"policy_id": policy["id"], "name": policy["name"], "version": version})
    db.conn.commit()
    return _response(200, {"policy_id": policy["id"], "version": version, "acknowledged": True,
                           "step_complete": training_step_complete(db, org)})


# ── routing ──────────────────────────────────────────────────────────────

def _route(method: str, path: str):
    """Returns (handler, path_arg) or (None, None). The id is read from the path itself, so the
    API Gateway routes can be greedy ({proxy+}) without each needing a named parameter."""
    p = path.rstrip("/")
    parts = p.strip("/").split("/")
    simple = {
        ("GET", "/compliance"): handle_get_compliance,
        ("POST", "/compliance/frameworks"): handle_save_framework,
        ("POST", "/compliance/certifications"): handle_add_certification,
        ("GET", "/governance"): handle_get_governance,
        ("POST", "/governance/policies"): handle_create_policy,
        ("POST", "/governance/exceptions"): handle_request_exception,
        ("GET", "/training"): handle_get_training,
        ("POST", "/training/acknowledge"): handle_acknowledge,
    }
    if (method, p) in simple:
        return simple[(method, p)], None
    if method == "DELETE" and len(parts) == 3 and parts[:2] == ["compliance", "certifications"]:
        return handle_delete_certification, parts[2]
    if method == "POST" and len(parts) == 4 and parts[:2] == ["governance", "policies"]:
        action = {"versions": handle_new_policy_version, "decision": handle_policy_decision,
                  "retire": handle_retire_policy}.get(parts[3])
        if action:
            return action, parts[2]
    if method == "POST" and len(parts) == 4 and parts[:2] == ["governance", "exceptions"]:
        action = {"decision": handle_exception_decision, "revoke": handle_revoke_exception}.get(parts[3])
        if action:
            return action, parts[2]
    return None, None


def handle(event: dict, db: Database) -> dict:
    method = (event.get("requestContext") or {}).get("http", {}).get("method", "")
    path = _route_path(event)
    handler, arg = _route(method, path)
    if not handler:
        return _response(404, {"error": f"no route for {method} {path}"})
    caller = _get_caller(event, db) if _token_from_our_pool(event) else None
    if not caller:
        return _response(401, {"error": "unauthorized"})
    try:
        return handler(caller, db, event, arg) if arg is not None else handler(caller, db, event)
    except RequestError as e:
        try:
            db.conn.rollback()
        except Exception:
            pass
        return _response(e.status, {"error": e.message})


def lambda_handler(event, context):
    """
    Routes (payload format v2.0, API hzf92ft6j7, stage "default"), explicit methods only:
        GET /compliance, POST /compliance/{proxy+}, DELETE /compliance/{proxy+}
        GET /governance, POST /governance/{proxy+}
        GET /training,   POST /training/{proxy+}
    Never ANY: an ANY route also catches the browser's CORS preflight (OPTIONS), which API Gateway
    then forwards here instead of answering it, and the browser blocks the real request. Only methods
    in the API's CORS config (GET, POST, DELETE, PATCH) work from a browser, so no PUT.
    """
    db = None
    try:
        db = Database()
        return handle(event, db)
    except Exception as e:
        # Details to the logs only; database errors can name tables and constraints.
        logger.error(f"governance_handler: unhandled error — {e}", exc_info=True)
        return _response(500, {"error": "Something went wrong on our side. Please try again."})
    finally:
        if db:
            db.close()
