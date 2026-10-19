"""
ciem_handler.py — CIEM API (issue #17). One Lambda behind GET/POST /ciem, guarded by tenant_auth.guard like
every other account-data handler: the caller must own (or be an authorised org member of) the cloud account,
and every referenced id (finding_id, review_id, item_id, integration_id) is resolved to its real account first.

GET  /ciem?cloud_account_id=...&view=
       overview | identities | identity&arn= | findings | finding&finding_id= | paths | external | reviews |
       review&review_id= | settings | audit | scans | export&what=findings|identities|audit&format=csv|json
POST /ciem {cloud_account_id, action, ...}
       set_finding_status  finding_id, status, reason, accepted_until
       save_settings       observation_days, rules
       create_review       name, scope, reviewer_email, due_date
       decide_review_item  review_id, item_id, decision, note
       create_ticket       finding_id, integration_id
       refresh_ticket      finding_id

Read-only towards AWS: nothing here changes a customer's cloud permissions. Remediation is guidance, tickets,
approval (risk acceptance with an end date) and verification by the next scan.
"""
import csv
import io
import json
import logging
import os
import re
from datetime import date, datetime, timedelta

import boto3
import psycopg2
from psycopg2.extras import Json

from collectors.aws.scanner.tenant_auth import authenticate, guard
from collectors.aws.scanner.ciem_engine import POLICY_RULES, SEV_ORDER

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
CORS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}
REFS = {
    "finding_id": "SELECT cloud_account_id FROM ciem_findings WHERE id = %s",
    "review_id": "SELECT cloud_account_id FROM ciem_access_reviews WHERE id = %s",
    "item_id": "SELECT r.cloud_account_id FROM ciem_review_items i JOIN ciem_access_reviews r ON r.id = i.review_id WHERE i.id = %s",
    "integration_id": "SELECT cloud_account_id FROM workspace_integrations WHERE id = %s",
}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
STATUSES = ("open", "in_progress", "accepted", "false_positive")
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(v):
    """Spreadsheet-safe text: a value that starts like a formula is prefixed so it is shown, never run."""
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        v = json.dumps(v, default=str)
    v = str(v)
    return "'" + v if v.startswith(_FORMULA_START) else v
OBS_DAYS = (30, 60, 90, 180, 365)


class BadRequest(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def _resp(status, body, headers=None):
    return {"statusCode": status, "headers": {**CORS, **(headers or {})},
            "body": body if isinstance(body, str) else json.dumps(body, default=str)}


def _get_connection():
    s = json.loads(boto3.client("secretsmanager", region_name=REGION).get_secret_value(
        SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"],
                            password=s["password"], sslmode="require", connect_timeout=10)


def _uuid(v, what):
    if not isinstance(v, str) or not UUID_RE.match(v):
        raise BadRequest(404, f"{what} not found")
    return v


def _audit(cur, account, actor, action, target=None, details=None):
    cur.execute("INSERT INTO ciem_audit_log (cloud_account_id, actor_email, action, target, details) VALUES (%s, %s, %s, %s, %s)",
                (account, actor, action, target, Json(details or {}, dumps=lambda o: json.dumps(o, default=str))))


def _latest_scan(cur, account, with_inventory=True):
    cur.execute(f"""SELECT id, status, started_at, finished_at, error, coverage, limitations, summary, observation_days, trigger
                    FROM ciem_scans WHERE cloud_account_id = %s
                    {"AND status IN ('succeeded', 'partial')" if with_inventory else ""}
                    ORDER BY started_at DESC LIMIT 1""", (account,))
    r = cur.fetchone()
    if not r:
        return None
    return {"id": str(r[0]), "status": r[1], "started_at": r[2], "finished_at": r[3], "error": r[4], "coverage": r[5],
            "limitations": r[6], "summary": r[7], "observation_days": r[8], "trigger": r[9]}


# ── reads ────────────────────────────────────────────────────────────────────

def view_overview(cur, account):
    latest = _latest_scan(cur, account)
    last_any = _latest_scan(cur, account, with_inventory=False)
    cur.execute("""SELECT status, severity, count(*) FROM ciem_findings WHERE cloud_account_id = %s GROUP BY 1, 2""", (account,))
    counts = {}
    for st, sev, n in cur.fetchall():
        counts.setdefault(st, {})[sev] = n
    cur.execute("""SELECT started_at, status, summary FROM ciem_scans WHERE cloud_account_id = %s
                   AND status IN ('succeeded', 'partial') ORDER BY started_at DESC LIMIT 12""", (account,))
    trend = [{"at": a, "status": s, "findings_by_severity": (m or {}).get("findings_by_severity"),
              "least_privilege_pct": ((m or {}).get("least_privilege") or {}).get("pct")} for a, s, m in cur.fetchall()][::-1]
    top = []
    if latest:
        cur.execute("""SELECT arn, name, kind, classification, risk_score, risk_severity, data->'risk_reasons'
                       FROM ciem_identities WHERE scan_id = %s AND kind <> 'group' ORDER BY risk_score DESC, name LIMIT 10""", (latest["id"],))
        top = [{"arn": a, "name": n, "kind": k, "classification": c, "risk_score": s, "risk_severity": sv, "risk_reasons": rr}
               for a, n, k, c, s, sv, rr in cur.fetchall()]
    cur.execute("""SELECT count(*) FILTER (WHERE status = 'resolved'), count(*) FILTER (WHERE status IN ('open', 'in_progress')),
                          count(*) FILTER (WHERE status = 'resolved' AND resolved_at > NOW() - INTERVAL '30 days')
                   FROM ciem_findings WHERE cloud_account_id = %s""", (account,))
    resolved, open_, resolved_30 = cur.fetchone()
    return {"latest_scan": latest, "last_attempt": last_any, "finding_counts": counts, "trend": trend, "top_identities": top,
            "remediation": {"resolved": resolved, "open": open_, "resolved_last_30_days": resolved_30}}


def view_identities(cur, account):
    latest = _latest_scan(cur, account)
    if not latest:
        return {"latest_scan": None, "identities": []}
    cur.execute("""SELECT i.arn, i.name, i.kind, i.classification, i.risk_score, i.risk_severity, i.admin, i.owner,
                          i.data->>'classification_basis', i.data->>'classification_reason', i.data->>'last_used',
                          i.data->'credentials'->>'password_last_used', jsonb_array_length(COALESCE(i.data->'policies', '[]'::jsonb)),
                          jsonb_array_length(COALESCE(i.data->'escalation', '[]'::jsonb)), i.data->'unused'->>'status',
                          (SELECT count(*) FROM ciem_findings f WHERE f.cloud_account_id = i.cloud_account_id
                             AND f.identity_arn = i.arn AND f.status IN ('open', 'in_progress'))
                   FROM ciem_identities i WHERE i.scan_id = %s ORDER BY i.risk_score DESC, i.name""", (latest["id"],))
    cols = ("arn", "name", "kind", "classification", "risk_score", "risk_severity", "admin", "owner", "classification_basis",
            "classification_reason", "role_last_used", "password_last_used", "policy_count", "escalation_paths", "unused_status", "open_findings")
    return {"latest_scan": {k: latest[k] for k in ("id", "status", "started_at", "finished_at", "observation_days")},
            "identities": [dict(zip(cols, r)) for r in cur.fetchall()]}


def view_identity(cur, account, arn):
    latest = _latest_scan(cur, account)
    if not latest or not arn:
        raise BadRequest(404, "identity not found")
    cur.execute("SELECT data FROM ciem_identities WHERE scan_id = %s AND arn = %s", (latest["id"], arn))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "identity not found")
    cur.execute("""SELECT s.started_at, i.risk_score FROM ciem_identities i JOIN ciem_scans s ON s.id = i.scan_id
                   WHERE i.cloud_account_id = %s AND i.arn = %s ORDER BY s.started_at""", (account, arn))
    history = [{"at": a, "risk_score": sc} for a, sc in cur.fetchall()]
    cur.execute("""SELECT id, severity, title, status, category FROM ciem_findings
                   WHERE cloud_account_id = %s AND identity_arn = %s ORDER BY status = 'resolved', severity""", (account, arn))
    findings = [{"id": str(i), "severity": s, "title": t, "status": st, "category": c} for i, s, t, st, c in cur.fetchall()]
    findings.sort(key=lambda f: (f["status"] == "resolved", -SEV_ORDER.get(f["severity"], 0)))
    return {"identity": r[0], "risk_history": history, "findings": findings, "scan": {"id": latest["id"], "started_at": latest["started_at"]}}


FINDING_COLS = ("id", "rule", "category", "severity", "title", "identity_arn", "identity_name", "status", "status_reason",
                "status_by", "status_at", "accepted_until", "first_seen", "last_seen", "resolved_at", "ticket")


def view_findings(cur, account):
    cur.execute(f"""SELECT {', '.join(FINDING_COLS)} FROM ciem_findings WHERE cloud_account_id = %s""", (account,))
    rows = [dict(zip(FINDING_COLS, r)) for r in cur.fetchall()]
    for r in rows:
        r["id"] = str(r["id"])
    rows.sort(key=lambda f: (f["status"] in ("resolved", "false_positive", "accepted", "suppressed"), -SEV_ORDER.get(f["severity"], 0), f["title"]))
    return {"findings": rows}


def view_finding(cur, account, fid):
    cur.execute(f"""SELECT {', '.join(FINDING_COLS)}, details, recommendation, compliance FROM ciem_findings
                    WHERE id = %s AND cloud_account_id = %s""", (_uuid(fid, "finding"), account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "finding not found")
    f = dict(zip(FINDING_COLS + ("details", "recommendation", "compliance"), r))
    f["id"] = str(f["id"])
    cur.execute("""SELECT id, provider, project FROM workspace_integrations WHERE cloud_account_id = %s ORDER BY created_at""", (account,))
    f["integrations"] = [{"id": str(i), "provider": p, "project": pr} for i, p, pr in cur.fetchall()]
    return {"finding": f}


def view_paths(cur, account):
    latest = _latest_scan(cur, account)
    if not latest:
        return {"paths": []}
    cur.execute("""SELECT arn, name, kind, data->'escalation', data->'can_assume' FROM ciem_identities
                   WHERE scan_id = %s AND (jsonb_array_length(COALESCE(data->'escalation', '[]'::jsonb)) > 0
                                          OR jsonb_array_length(COALESCE(data->'can_assume', '[]'::jsonb)) > 0)""", (latest["id"],))
    out = []
    for arn, name, kind, esc, assume in cur.fetchall():
        out.append({"arn": arn, "name": name, "kind": kind, "escalation": esc or [], "can_assume": assume or []})
    out.sort(key=lambda x: -len(x["escalation"]))
    return {"paths": out}


def view_external(cur, account):
    latest = _latest_scan(cur, account)
    if not latest:
        return {"trusts": [], "resources": []}
    cur.execute("""SELECT arn, name, data->'trust' FROM ciem_identities WHERE scan_id = %s AND kind = 'role'""", (latest["id"],))
    trusts = []
    for arn, name, trust in cur.fetchall():
        for t in trust or []:
            if t.get("class") in ("external_account", "public", "public_restricted", "oidc_federation", "saml_federation", "cognito_federation"):
                trusts.append({"role_arn": arn, "role": name, **t})
    cur.execute("""SELECT id, title, severity, status, details FROM ciem_findings WHERE cloud_account_id = %s
                   AND category = 'external_resource_access' ORDER BY status = 'resolved', severity""", (account,))
    resources = [{"id": str(i), "title": t, "severity": s, "status": st, "details": d} for i, t, s, st, d in cur.fetchall()]
    return {"trusts": trusts, "resources": resources, "coverage": (latest["coverage"] or {}).get("access_analyzer")}


def view_reviews(cur, account):
    cur.execute("""SELECT r.id, r.name, r.scope, r.reviewer_email, r.due_date, r.status, r.created_by, r.created_at, r.completed_at,
                          count(i.id), count(i.decision)
                   FROM ciem_access_reviews r LEFT JOIN ciem_review_items i ON i.review_id = r.id
                   WHERE r.cloud_account_id = %s GROUP BY r.id ORDER BY r.created_at DESC""", (account,))
    cols = ("id", "name", "scope", "reviewer_email", "due_date", "status", "created_by", "created_at", "completed_at", "items", "decided")
    out = [dict(zip(cols, r)) for r in cur.fetchall()]
    for r in out:
        r["id"] = str(r["id"])
        r["overdue"] = r["status"] == "open" and r["due_date"] < date.today()
    return {"reviews": out}


def view_review(cur, account, rid):
    cur.execute("SELECT name, scope, reviewer_email, due_date, status FROM ciem_access_reviews WHERE id = %s AND cloud_account_id = %s",
                (_uuid(rid, "review"), account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "review not found")
    cur.execute("""SELECT id, identity_arn, identity_name, snapshot, decision, note, decided_by, decided_at
                   FROM ciem_review_items WHERE review_id = %s ORDER BY identity_name""", (rid,))
    items = [{"id": str(i), "identity_arn": a, "identity_name": n, "snapshot": s, "decision": d, "note": no, "decided_by": by, "decided_at": at}
             for i, a, n, s, d, no, by, at in cur.fetchall()]
    return {"review": {"id": rid, "name": r[0], "scope": r[1], "reviewer_email": r[2], "due_date": r[3], "status": r[4]}, "items": items}


def view_settings(cur, account):
    cur.execute("SELECT observation_days, rules, updated_by, updated_at FROM ciem_settings WHERE cloud_account_id = %s", (account,))
    r = cur.fetchone()
    days, rules = (r[0], r[1] or {}) if r else (90, {})
    out = []
    for rid, (title, sev) in POLICY_RULES.items():
        cfg = rules.get(rid) or {}
        out.append({"id": rid, "title": title, "default_severity": sev, "enabled": cfg.get("enabled", True),
                    "severity": cfg.get("severity") or sev})
    return {"observation_days": days, "observation_choices": list(OBS_DAYS), "rules": out,
            "updated_by": r[2] if r else None, "updated_at": r[3] if r else None}


def view_audit(cur, account):
    cur.execute("""SELECT created_at, actor_email, action, target, details FROM ciem_audit_log
                   WHERE cloud_account_id = %s ORDER BY created_at DESC LIMIT 300""", (account,))
    return {"audit": [{"at": a, "actor": b, "action": c, "target": d, "details": e} for a, b, c, d, e in cur.fetchall()]}


def view_scans(cur, account):
    cur.execute("""SELECT id, status, trigger, started_at, finished_at, error, summary->'findings_by_severity', coverage
                   FROM ciem_scans WHERE cloud_account_id = %s ORDER BY started_at DESC LIMIT 20""", (account,))
    return {"scans": [{"id": str(i), "status": s, "trigger": t, "started_at": a, "finished_at": f, "error": e,
                       "findings_by_severity": fb, "coverage": c} for i, s, t, a, f, e, fb, c in cur.fetchall()]}


def export(cur, account, what, fmt, actor):
    if what == "findings":
        cur.execute("""SELECT severity, status, category, title, identity_arn, first_seen, last_seen, resolved_at, status_reason,
                              accepted_until, recommendation->>'proposed', compliance FROM ciem_findings
                       WHERE cloud_account_id = %s ORDER BY status, severity""", (account,))
        cols = ["severity", "status", "category", "title", "identity_arn", "first_seen", "last_seen", "resolved_at",
                "status_reason", "accepted_until", "recommendation", "compliance"]
        rows = cur.fetchall()
    elif what == "identities":
        latest = _latest_scan(cur, account)
        rows, cols = [], ["arn", "name", "kind", "classification", "risk_score", "risk_severity", "admin", "owner"]
        if latest:
            cur.execute("""SELECT arn, name, kind, classification, risk_score, risk_severity, admin, owner FROM ciem_identities
                           WHERE scan_id = %s ORDER BY risk_score DESC""", (latest["id"],))
            rows = cur.fetchall()
    elif what == "audit":
        cur.execute("""SELECT created_at, actor_email, action, target, details FROM ciem_audit_log
                       WHERE cloud_account_id = %s ORDER BY created_at DESC""", (account,))
        cols, rows = ["at", "actor", "action", "target", "details"], cur.fetchall()
    else:
        raise BadRequest(400, "what must be findings, identities or audit")
    _audit(cur, account, actor, "export", what, {"format": fmt, "rows": len(rows)})
    if fmt == "json":
        return _resp(200, {"what": what, "rows": [dict(zip(cols, r)) for r in rows]})
    if fmt != "csv":
        raise BadRequest(400, "format must be csv or json")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([_csv_cell(v) for v in r])
    return _resp(200, buf.getvalue(), {"Content-Type": "text/csv; charset=utf-8",
                                       "Content-Disposition": f'attachment; filename="niagaros-ciem-{what}.csv"'})


# ── writes ───────────────────────────────────────────────────────────────────

def set_finding_status(cur, account, body, actor):
    fid = _uuid(body.get("finding_id"), "finding")
    status = body.get("status")
    if status not in STATUSES:
        raise BadRequest(400, f"status must be one of: {', '.join(STATUSES)}")
    reason = (body.get("reason") or "").strip() or None
    until = None
    if status in ("accepted", "false_positive") and not reason:
        raise BadRequest(400, "A reason is required.")
    if reason and len(reason) > 1000:
        raise BadRequest(400, "The reason can be at most 1000 characters.")
    if status == "accepted":
        try:
            until = datetime.strptime(str(body.get("accepted_until")), "%Y-%m-%d").date()
        except ValueError:
            raise BadRequest(400, "An accepted risk needs an end date (YYYY-MM-DD).")
        if until <= date.today() or until > date.today() + timedelta(days=366):
            raise BadRequest(400, "The end date must be in the future and at most one year away.")
    cur.execute("SELECT status FROM ciem_findings WHERE id = %s AND cloud_account_id = %s FOR UPDATE", (fid, account))
    row = cur.fetchone()
    if not row:
        raise BadRequest(404, "finding not found")
    if row[0] == "resolved":
        raise BadRequest(409, "This finding is resolved by the latest scan; it re-opens automatically if it comes back.")
    if row[0] == "suppressed":
        raise BadRequest(409, "This finding's rule is switched off in CIEM settings; switch it on to work on it.")
    cur.execute("""UPDATE ciem_findings SET status = %s, status_reason = %s, status_by = %s, status_at = NOW(),
                   accepted_until = %s WHERE id = %s""", (status, reason, actor, until, fid))
    _audit(cur, account, actor, "finding_status", fid, {"from": row[0], "to": status, "reason": reason, "accepted_until": until})
    return {"finding_id": fid, "status": status}


def save_settings(cur, account, body, actor):
    days = body.get("observation_days")
    if days not in OBS_DAYS:
        raise BadRequest(400, f"observation_days must be one of {list(OBS_DAYS)}")
    rules_in = body.get("rules") or {}
    if not isinstance(rules_in, dict):
        raise BadRequest(400, "rules must be an object")
    rules = {}
    for rid, cfg in rules_in.items():
        if rid not in POLICY_RULES or not isinstance(cfg, dict):
            raise BadRequest(400, f"unknown rule: {rid}")
        sev = cfg.get("severity")
        if sev is not None and sev not in ("critical", "high", "medium", "low"):
            raise BadRequest(400, f"invalid severity for {rid}")
        enabled = cfg.get("enabled", True)
        if not isinstance(enabled, bool):
            raise BadRequest(400, f"invalid enabled flag for {rid}")
        rules[rid] = {"enabled": enabled, **({"severity": sev} if sev else {})}
    cur.execute("SELECT observation_days, rules FROM ciem_settings WHERE cloud_account_id = %s", (account,))
    before = cur.fetchone()
    cur.execute("""INSERT INTO ciem_settings (cloud_account_id, observation_days, rules, updated_by, updated_at)
                   VALUES (%s, %s, %s, %s, NOW())
                   ON CONFLICT (cloud_account_id) DO UPDATE SET observation_days = EXCLUDED.observation_days,
                       rules = EXCLUDED.rules, updated_by = EXCLUDED.updated_by, updated_at = NOW()""",
                (account, days, Json(rules), actor))
    _audit(cur, account, actor, "settings", None, {"previous": {"observation_days": before[0], "rules": before[1]} if before else None,
                                                     "new": {"observation_days": days, "rules": rules}})
    return {"saved": True, "note": "Applies from the next scan."}


def create_review(cur, account, body, actor):
    name = (body.get("name") or "").strip()
    scope = body.get("scope")
    reviewer = (body.get("reviewer_email") or "").strip()
    if not name or len(name) > 150:
        raise BadRequest(400, "A name (max 150 characters) is required.")
    if scope not in ("privileged", "machine", "human", "all"):
        raise BadRequest(400, "scope must be privileged, machine, human or all")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", reviewer):
        raise BadRequest(400, "A valid reviewer email is required.")
    try:
        due = datetime.strptime(str(body.get("due_date")), "%Y-%m-%d").date()
    except ValueError:
        raise BadRequest(400, "due_date must be a date (YYYY-MM-DD).")
    if due < date.today():
        raise BadRequest(400, "The due date cannot be in the past.")
    latest = _latest_scan(cur, account)
    if not latest:
        raise BadRequest(409, "There is no CIEM scan yet to review.")
    where = {"privileged": "AND (admin IS NOT NULL OR data->'capabilities' @> '[{\"category\": \"identity\"}]'::jsonb)",
             "machine": "AND classification = 'machine'", "human": "AND classification = 'human'", "all": ""}[scope]
    cur.execute(f"""SELECT arn, name, jsonb_build_object('kind', kind, 'classification', classification, 'admin', admin,
                           'risk_score', risk_score, 'policies', data->'policies', 'owner', owner)
                    FROM ciem_identities WHERE scan_id = %s AND kind <> 'group' AND classification <> 'service_linked' {where}""",
                (latest["id"],))
    items = cur.fetchall()
    if not items:
        raise BadRequest(409, "No identities match this scope.")
    cur.execute("""INSERT INTO ciem_access_reviews (cloud_account_id, name, scope, reviewer_email, due_date, created_by)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""", (account, name, scope, reviewer, due, actor))
    rid = str(cur.fetchone()[0])
    for arn, n, snap in items:
        cur.execute("INSERT INTO ciem_review_items (review_id, identity_arn, identity_name, snapshot) VALUES (%s, %s, %s, %s)",
                    (rid, arn, n, Json(snap)))
    _audit(cur, account, actor, "review_created", rid, {"name": name, "scope": scope, "reviewer": reviewer, "due": due, "items": len(items)})
    return {"review_id": rid, "items": len(items), "_notify": {"title": f"Access review '{name}' assigned to {reviewer}",
                                                                "description": f"{len(items)} identities to review by {due}."}}


def decide_review_item(cur, account, body, actor):
    rid, iid = _uuid(body.get("review_id"), "review"), _uuid(body.get("item_id"), "review item")
    decision = body.get("decision")
    if decision not in ("keep", "reduce", "remove"):
        raise BadRequest(400, "decision must be keep, reduce or remove")
    note = (body.get("note") or "").strip() or None
    if decision != "keep" and not note:
        raise BadRequest(400, "Say what should change.")
    cur.execute("""SELECT r.status FROM ciem_access_reviews r JOIN ciem_review_items i ON i.review_id = r.id
                   WHERE r.id = %s AND i.id = %s AND r.cloud_account_id = %s FOR UPDATE OF r""", (rid, iid, account))
    row = cur.fetchone()
    if not row:
        raise BadRequest(404, "review item not found")
    if row[0] != "open":
        raise BadRequest(409, "This review is completed.")
    cur.execute("""UPDATE ciem_review_items SET decision = %s, note = %s, decided_by = %s, decided_at = NOW() WHERE id = %s
                   RETURNING identity_arn""", (decision, note, actor, iid))
    arn = cur.fetchone()[0]
    cur.execute("SELECT count(*) FILTER (WHERE decision IS NULL) FROM ciem_review_items WHERE review_id = %s", (rid,))
    remaining = cur.fetchone()[0]
    if remaining == 0:
        cur.execute("UPDATE ciem_access_reviews SET status = 'completed', completed_at = NOW() WHERE id = %s", (rid,))
    _audit(cur, account, actor, "review_decision", arn, {"review_id": rid, "decision": decision, "note": note})
    return {"remaining": remaining, "completed": remaining == 0}


def create_ticket(cur, account, body, actor):
    from collectors.aws.scanner.integrations_handler import _client_for, _load
    fid = _uuid(body.get("finding_id"), "finding")
    integ = _load(cur, _uuid(body.get("integration_id"), "integration"))
    if not integ or integ["cloud_account_id"] != account:
        raise BadRequest(404, "integration not found")
    if not integ["project"]:
        raise BadRequest(400, "Select a project for this integration first (Integrations page).")
    cur.execute("SELECT title, severity, recommendation, identity_arn, ticket FROM ciem_findings WHERE id = %s AND cloud_account_id = %s FOR UPDATE",
                (fid, account))
    f = cur.fetchone()
    if not f:
        raise BadRequest(404, "finding not found")
    if f[4]:
        raise BadRequest(409, "A ticket already exists for this finding.")
    rec = f[2] or {}
    desc = (f"Niagaros CIEM finding ({f[1]}): {f[0]}\nIdentity: {f[3]}\n\nCurrent: {rec.get('current', '')}\n"
            f"Proposed: {rec.get('proposed', '')}\nWhy: {rec.get('reason', '')}\nImpact: {rec.get('impact', '')}\n"
            f"Rollback: {rec.get('rollback', '')}\nApprovals: {rec.get('approvals', '')}")
    t = _client_for(integ).create_ticket(integ["project"], f"[CIEM] {f[0]}", desc, f[1])
    ticket = {"provider": integ["provider"], "integration_id": integ["id"], **t, "status": "created", "created_by": actor}
    cur.execute("UPDATE ciem_findings SET ticket = %s, status = CASE WHEN status = 'open' THEN 'in_progress' ELSE status END WHERE id = %s",
                (Json(ticket), fid))
    _audit(cur, account, actor, "ticket_created", fid, {"provider": integ["provider"], "key": t.get("key")})
    return {"ticket": ticket}


def refresh_ticket(cur, account, body, actor):
    from collectors.aws.scanner.integrations_handler import _client_for, _load
    fid = _uuid(body.get("finding_id"), "finding")
    cur.execute("SELECT ticket FROM ciem_findings WHERE id = %s AND cloud_account_id = %s FOR UPDATE", (fid, account))
    r = cur.fetchone()
    if not r or not r[0]:
        raise BadRequest(404, "no ticket for this finding")
    t = r[0]
    integ = _load(cur, t["integration_id"])
    if not integ or integ["cloud_account_id"] != account:
        raise BadRequest(409, "The integration for this ticket no longer exists.")
    st = _client_for(integ).status(t)
    t.update({"status": st.get("name"), "done": st.get("done"), "checked_at": datetime.utcnow().isoformat() + "Z"})
    cur.execute("UPDATE ciem_findings SET ticket = %s WHERE id = %s", (Json(t), fid))
    return {"ticket": t, "note": "A finding is only marked resolved when the next scan no longer sees it, not when the ticket closes."}


ACTIONS = {"set_finding_status": set_finding_status, "save_settings": save_settings, "create_review": create_review,
           "decide_review_item": decide_review_item, "create_ticket": create_ticket, "refresh_ticket": refresh_ticket}
VIEWS = {"overview": view_overview, "identities": view_identities, "findings": view_findings, "paths": view_paths,
         "external": view_external, "reviews": view_reviews, "settings": view_settings, "audit": view_audit, "scans": view_scans}


def handle(event, conn):
    method = event.get("httpMethod")
    if method == "OPTIONS":
        return _resp(200, {})
    qs = event.get("queryStringParameters") or {}
    try:
        body = json.loads(event["body"]) if event.get("body") else {}
        if not isinstance(body, dict):
            raise ValueError
    except (ValueError, TypeError):
        return _resp(400, {"error": "Invalid JSON"})
    src = qs if method == "GET" else body
    account = src.get("cloud_account_id")
    if not isinstance(account, str) or not UUID_RE.match(account):
        return _resp(400, {"error": "cloud_account_id is required"})
    denied = guard(event, conn, qs, body, REFS, None)
    if denied:
        return _resp(denied[0], {"error": denied[1]})
    actor = authenticate(event) or "unknown"
    try:
        with conn.cursor() as cur:
            # Risk acceptances end on their date even between scans.
            cur.execute("""UPDATE ciem_findings SET status = 'open', status_reason = 'Re-opened: risk acceptance expired'
                           WHERE cloud_account_id = %s AND status = 'accepted' AND accepted_until < CURRENT_DATE""", (account,))
            if cur.rowcount:
                conn.commit()
            if method == "GET":
                view = qs.get("view", "overview")
                if view == "identity":
                    return _resp(200, view_identity(cur, account, qs.get("arn")))
                if view == "finding":
                    return _resp(200, view_finding(cur, account, qs.get("finding_id")))
                if view == "review":
                    return _resp(200, view_review(cur, account, qs.get("review_id")))
                if view == "export":
                    r = export(cur, account, qs.get("what"), qs.get("format", "csv"), actor)
                    conn.commit()
                    return r
                if view not in VIEWS:
                    return _resp(400, {"error": "unknown view"})
                return _resp(200, VIEWS[view](cur, account))
            if method != "POST":
                return _resp(405, {"error": "method not allowed"})
            action = body.get("action")
            if action not in ACTIONS:
                return _resp(400, {"error": "unknown action"})
            result = ACTIONS[action](cur, account, body, actor)
        conn.commit()
        note = result.pop("_notify", None) if isinstance(result, dict) else None
        if note:
            try:
                from collectors.aws.scanner.notification_lib import create_notification
                create_notification(conn, account, "security", "ciem_access_review_assigned", "P3", note["title"],
                                    description=note["description"], resource_link="ciem.html#reviews", actor=actor)
            except Exception:
                logger.exception("could not notify the access review")
        return _resp(200, result)
    except BadRequest as e:
        conn.rollback()
        return _resp(e.status, {"error": e.message})


def handler(event, context):
    if not event or "httpMethod" not in event:
        return _resp(400, {"error": "not an API Gateway event"})
    conn = _get_connection()
    try:
        return handle(event, conn)
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        name = type(e).__name__
        if name == "ProviderError":
            return _resp(502, {"error": f"The ticket system answered with an error: {str(e)[:200]}"})
        logger.error("ciem_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": "Something went wrong on our side. Please try again."})
    finally:
        conn.close()


lambda_handler = handler
