"""
ai_inventory_handler.py — AI Inventory API (issue #236). One Lambda behind GET/POST /ai-inventory, guarded by
tenant_auth.guard like every other account-data handler; every referenced id (asset_id, finding_id,
relationship_id, source/target asset) is resolved to its real account first, and every query below filters on
the caller's cloud_account_id again.

GET  /ai-inventory?cloud_account_id=...&view=
       overview | assets | asset&asset_id= | graph | shadow | findings | changes | settings | audit | scans |
       export&what=assets|findings|relationships|changes|audit&format=csv|json
POST /ai-inventory {cloud_account_id, action, ...}
       update_asset        asset_id, owner, business_purpose, environment, criticality, next_review_at,
                           lifecycle_status, approval_status, approval_reason, approval_until
       register_asset      name, asset_type, provider, description, + governance fields
       import_assets       rows: [{name, asset_type, provider, owner, ...}] (max 500)
       delete_asset        asset_id (manually registered or imported assets only)
       link_assets         source_asset_id, target_asset_id, rel_type, note
       unlink_assets       relationship_id (manual links only)
       set_finding_status  finding_id, status, reason, accepted_until
       create_ticket       finding_id, integration_id
       refresh_ticket      finding_id
       save_settings       approved_providers, github_repos, inactive_after_days
       run_scan            starts a scan of this account now

Nothing here changes the customer's AWS account or repositories. Scans never overwrite what people enter
(owner, purpose, approval, ...); people never overwrite what scans observed.
"""
import csv
import io
import json
import logging
import os
import re
from collections import deque
from datetime import date, datetime, timedelta, timezone

import boto3
import psycopg2
from psycopg2.extras import Json

from collectors.aws.scanner.tenant_auth import authenticate, guard
from collectors.aws.scanner.ai_inventory_engine import ASSET_TYPES, PROVIDERS, VERIFICATION_ORDER

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
SCANNER_FUNCTION = os.environ.get("AI_INVENTORY_SCANNER_FUNCTION", "ai-inventory-scanner")
CORS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}
REFS = {
    "asset_id": "SELECT cloud_account_id FROM ai_assets WHERE id = %s",
    "source_asset_id": "SELECT cloud_account_id FROM ai_assets WHERE id = %s",
    "target_asset_id": "SELECT cloud_account_id FROM ai_assets WHERE id = %s",
    "finding_id": "SELECT cloud_account_id FROM ai_inventory_findings WHERE id = %s",
    "relationship_id": "SELECT cloud_account_id FROM ai_asset_relationships WHERE id = %s",
    "integration_id": "SELECT cloud_account_id FROM workspace_integrations WHERE id = %s",
}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}(/[A-Za-z0-9_.-]{1,100})?$")
FINDING_STATUSES = ("open", "in_progress", "accepted", "false_positive")
ENVIRONMENTS = ("unknown", "production", "staging", "development", "test")
CRITICALITIES = ("unknown", "low", "medium", "high", "critical")
APPROVALS = ("unreviewed", "approved", "restricted", "rejected", "exception")
MANUAL_LIFECYCLE = ("active", "deprecated", "retired")
REL_TYPES = ("SERVED_BY", "USES_MODEL", "CALLS_PROVIDER", "DEPLOYED_ON", "CONNECTS_TO_MCP_SERVER", "DEPENDS_ON",
             "PROTECTED_BY_GUARDRAIL", "RETRIEVES_FROM", "USES_PROMPT", "EXPOSES_TOOL", "AUTHENTICATES_AS",
             "PROCESSES_DATA", "OWNED_BY_APPLICATION")
# what counts as "shadow AI": AI that is in use but nobody has reviewed yet
SHADOW_TYPES = ("application", "agent", "model_provider", "model", "model_deployment", "mcp_server", "ai_endpoint",
                "rag_pipeline", "vector_database")
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
J = lambda o: Json(o, dumps=lambda x: json.dumps(x, default=str))


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


def _csv_cell(v):
    """Spreadsheet-safe text: a value that starts like a formula is prefixed so it is shown, never run."""
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        v = json.dumps(v, default=str)
    v = str(v)
    return "'" + v if v.startswith(_FORMULA_START) else v


def _uuid(v, what):
    if not isinstance(v, str) or not UUID_RE.match(v):
        raise BadRequest(404, f"{what} not found")
    return v


def _text(body, key, maxlen, required=False, label=None):
    v = body.get(key)
    if v is None or (isinstance(v, str) and not v.strip()):
        if required:
            raise BadRequest(400, f"{label or key.replace('_', ' ').capitalize()} is required.")
        return None
    if not isinstance(v, str):
        raise BadRequest(400, f"{label or key.replace('_', ' ').capitalize()} must be text.")
    v = v.strip()
    if len(v) > maxlen:
        raise BadRequest(400, f"{label or key.replace('_', ' ').capitalize()} can be at most {maxlen} characters.")
    return v


def _date(v, what, max_days=None, allow_past=False):
    try:
        d = datetime.strptime(str(v), "%Y-%m-%d").date()
    except ValueError:
        raise BadRequest(400, f"{what} must be a date (YYYY-MM-DD).")
    if not allow_past and d <= date.today():
        raise BadRequest(400, f"{what} must be in the future.")
    if max_days and d > date.today() + timedelta(days=max_days):
        raise BadRequest(400, f"{what} can be at most {max_days} days away.")
    return d


def _audit(cur, account, actor, action, target=None, details=None):
    cur.execute("INSERT INTO ai_inventory_audit_log (cloud_account_id, actor_email, action, target, details) VALUES (%s, %s, %s, %s, %s)",
                (account, actor, action, target, J(details or {})))


def _change(cur, account, asset_id, change_type, previous, new, actor, impact=None):
    cur.execute("""INSERT INTO ai_asset_changes (cloud_account_id, asset_id, change_type, previous, new, source, actor, risk_impact)
                   VALUES (%s, %s, %s, %s, %s, 'manual', %s, %s)""", (account, asset_id, change_type, J(previous), J(new), actor, impact))


ASSET_COLS = ("id, asset_key, asset_type, name, provider, verification, metadata, origin, owner, business_purpose, environment, "
              "criticality, approval_status, approval_reason, approval_by, approval_at, approval_until, lifecycle_status, "
              "next_review_at, first_seen, last_seen, last_synced, last_verified")
ASSET_KEYS = [c.strip() for c in ASSET_COLS.split(",")]


def _asset_row(r):
    a = dict(zip(ASSET_KEYS, r))
    a["id"] = str(a["id"])
    a["type_label"] = ASSET_TYPES.get(a["asset_type"], a["asset_type"])
    return a


def _latest_scan(cur, account, finished=True):
    cur.execute(f"""SELECT id, status, trigger, started_at, finished_at, error, coverage, limitations, summary FROM ai_inventory_scans
                    WHERE cloud_account_id = %s {"AND status IN ('succeeded', 'partial')" if finished else ""}
                    ORDER BY started_at DESC LIMIT 1""", (account,))
    r = cur.fetchone()
    if not r:
        return None
    return dict(zip(("id", "status", "trigger", "started_at", "finished_at", "error", "coverage", "limitations", "summary"),
                    (str(r[0]),) + tuple(r[1:])))


# ── reads ────────────────────────────────────────────────────────────────────

def view_overview(cur, account):
    latest = _latest_scan(cur, account)
    last_any = _latest_scan(cur, account, finished=False)
    cur.execute("""SELECT asset_type, verification, lifecycle_status, approval_status, owner IS NOT NULL, business_purpose IS NOT NULL,
                          environment <> 'unknown', criticality <> 'unknown', next_review_at IS NOT NULL AND next_review_at < CURRENT_DATE,
                          approval_status = 'exception' AND approval_until < CURRENT_DATE
                   FROM ai_assets WHERE cloud_account_id = %s AND lifecycle_status <> 'retired'""", (account,))
    rows = cur.fetchall()
    governed = [r for r in rows if r[0] != "ai_identity"]
    by = lambda i: {k: sum(1 for r in governed if r[i] == k) for k in sorted({r[i] for r in governed})}
    n = len(governed)
    governance = {
        "denominator": n,
        "with_owner": sum(1 for r in governed if r[4]), "with_purpose": sum(1 for r in governed if r[5]),
        "with_environment": sum(1 for r in governed if r[6]), "with_criticality": sum(1 for r in governed if r[7]),
        "reviewed": sum(1 for r in governed if r[3] != "unreviewed"), "approved": sum(1 for r in governed if r[3] == "approved"),
        "review_overdue": sum(1 for r in governed if r[8]), "exceptions_expired": sum(1 for r in governed if r[9]),
        "note": "AI identities (IAM roles of AI workloads) are excluded; they are governed in CIEM.",
    }
    cur.execute("SELECT status, severity, count(*) FROM ai_inventory_findings WHERE cloud_account_id = %s GROUP BY 1, 2", (account,))
    findings = {}
    for st, sev, c in cur.fetchall():
        findings.setdefault(st, {})[sev] = c
    shadow = sum(1 for r in governed if r[0] in SHADOW_TYPES and r[3] == "unreviewed" and r[2] in ("active", "stale"))
    cur.execute("""SELECT count(*) FILTER (WHERE risk_impact = 'high'), count(*) FROM ai_asset_changes
                   WHERE cloud_account_id = %s AND detected_at > NOW() - INTERVAL '30 days'""", (account,))
    ch = cur.fetchone()
    cur.execute("""SELECT started_at, status, summary->'assets', summary->'findings_by_severity' FROM ai_inventory_scans
                   WHERE cloud_account_id = %s AND status IN ('succeeded', 'partial') ORDER BY started_at DESC LIMIT 12""", (account,))
    trend = [{"at": a, "status": s, "assets": n_, "findings_by_severity": f} for a, s, n_, f in cur.fetchall()][::-1]
    return {"latest_scan": latest, "last_attempt": last_any, "assets_total": n, "identities": len(rows) - n,
            "by_type": {ASSET_TYPES.get(k, k): v for k, v in by(0).items()}, "by_type_ids": by(0),
            "by_verification": by(1), "by_lifecycle": by(2), "by_approval": by(3),
            "governance": governance, "findings": findings, "shadow_ai": shadow,
            "changes_30d": {"high_impact": ch[0], "total": ch[1]}, "trend": trend,
            "verification_levels": {"declared": "Found in source code or configuration; may not be deployed",
                                    "discovered": "Listed by a cloud or provider API: it exists or is configured",
                                    "observed": "Usage evidence, e.g. invocation metrics",
                                    "verified": "Reviewed and approved by a person in your organisation"}}


def view_assets(cur, account, qs):
    where, args = ["cloud_account_id = %s"], [account]
    for key, col, allowed in (("type", "asset_type", ASSET_TYPES), ("verification", "verification", VERIFICATION_ORDER),
                              ("lifecycle", "lifecycle_status", ("active", "stale", "inactive", "deprecated", "retired")),
                              ("approval", "approval_status", APPROVALS), ("environment", "environment", ENVIRONMENTS),
                              ("criticality", "criticality", CRITICALITIES), ("origin", "origin", ("discovered", "manual", "imported"))):
        v = qs.get(key)
        if v:
            if v not in allowed:
                raise BadRequest(400, f"unknown {key}")
            where.append(f"{col} = %s")
            args.append(v)
    if qs.get("q"):
        where.append("(name ILIKE %s OR asset_key ILIKE %s OR coalesce(owner, '') ILIKE %s)")
        like = "%" + qs["q"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")[:100] + "%"
        args += [like, like, like]
    if qs.get("no_owner") == "1":
        where.append("owner IS NULL")
    cur.execute(f"""SELECT {ASSET_COLS},
                           (SELECT count(*) FROM ai_asset_relationships r WHERE r.source_asset_id = a.id OR r.target_asset_id = a.id),
                           (SELECT json_build_object('critical', count(*) FILTER (WHERE f.severity = 'critical'), 'high', count(*) FILTER (WHERE f.severity = 'high'),
                                                   'medium', count(*) FILTER (WHERE f.severity = 'medium'), 'low', count(*) FILTER (WHERE f.severity = 'low'))
                            FROM ai_inventory_findings f WHERE f.asset_id = a.id AND f.status IN ('open', 'in_progress')),
                           EXISTS (SELECT 1 FROM ai_asset_relationships r JOIN ai_assets i ON i.id = r.target_asset_id
                                   WHERE r.source_asset_id = a.id AND r.rel_type = 'AUTHENTICATES_AS' AND i.metadata->>'ciem_admin' = 'admin')
                    FROM ai_assets a WHERE {" AND ".join(where)}
                    ORDER BY CASE lifecycle_status WHEN 'active' THEN 0 WHEN 'stale' THEN 1 ELSE 2 END, asset_type, name LIMIT 1000""", args)
    out = []
    for r in cur.fetchall():
        a = _asset_row(r[:-3])
        a["relationships"] = r[-3]
        a["open_findings"] = sum((r[-2] or {}).values())
        a["risk_score"], a["risk_factors"] = risk_score(a, r[-2] or {}, r[-1])
        out.append(a)
    return {"assets": out, "truncated": len(out) == 1000, "types": ASSET_TYPES}


FINDING_POINTS = {"critical": 40, "high": 25, "medium": 10, "low": 3}


def risk_score(a, open_by_severity, admin_identity):
    """0-100 prioritisation aid, always returned with the factors that make it up."""
    factors = []
    pts = min(60, sum(FINDING_POINTS[s] * n for s, n in open_by_severity.items() if n))
    if pts:
        factors.append({"points": pts, "factor": "open findings: " + ", ".join(f"{n} {s}" for s, n in open_by_severity.items() if n)})
    if admin_identity:
        factors.append({"points": 15, "factor": "runs as an identity with full administrator access (CIEM)"})
    if a.get("approval_status") == "rejected" and a.get("lifecycle_status") in ("active", "stale"):
        factors.append({"points": 25, "factor": "rejected but still in use"})
    elif a.get("approval_status") == "unreviewed" and a.get("asset_type") != "ai_identity":
        factors.append({"points": 10, "factor": "not reviewed by your team"})
    if a.get("approval_status") == "exception" and a.get("approval_until") and str(a["approval_until"]) < date.today().isoformat():
        factors.append({"points": 10, "factor": "exception expired"})
    if a.get("environment") == "production":
        factors.append({"points": 10, "factor": "production"})
    if a.get("criticality") in ("high", "critical"):
        factors.append({"points": 15 if a["criticality"] == "critical" else 10, "factor": f"criticality {a['criticality']}"})
    return min(100, sum(f["points"] for f in factors)), factors


def _impact(cur, account, asset_id, depth=3):
    """Everything reachable from the asset (downstream: what it uses) and everything that reaches it (upstream:
    what depends on it), up to `depth` hops."""
    cur.execute("SELECT source_asset_id, target_asset_id, rel_type FROM ai_asset_relationships WHERE cloud_account_id = %s", (account,))
    out_e, in_e = {}, {}
    for s, t, ty in cur.fetchall():
        out_e.setdefault(str(s), []).append((str(t), ty))
        in_e.setdefault(str(t), []).append((str(s), ty))

    def walk(edges):
        seen, q = {asset_id: 0}, deque([asset_id])
        found = []
        while q:
            cur_id = q.popleft()
            if seen[cur_id] >= depth:
                continue
            for nxt, ty in edges.get(cur_id, []):
                if nxt not in seen:
                    seen[nxt] = seen[cur_id] + 1
                    found.append({"id": nxt, "via": ty, "hops": seen[nxt], "from": cur_id})
                    q.append(nxt)
        return found
    down, up = walk(out_e), walk(in_e)
    ids = list({x["id"] for x in down + up})
    names = {}
    if ids:
        cur.execute("SELECT id, name, asset_type, lifecycle_status FROM ai_assets WHERE id = ANY(%s::uuid[]) AND cloud_account_id = %s",
                    (ids, account))
        names = {str(i): {"name": n, "asset_type": t, "type_label": ASSET_TYPES.get(t, t), "lifecycle_status": l} for i, n, t, l in cur.fetchall()}
    for x in down + up:
        x.update(names.get(x["id"], {}))
    return {"downstream": down, "upstream": up, "depth": depth,
            "note": "Downstream: what this asset uses. Upstream: what would be affected if this asset changes or is removed."}


def view_asset(cur, account, asset_id):
    aid = _uuid(asset_id, "asset")
    cur.execute(f"SELECT {ASSET_COLS} FROM ai_assets WHERE id = %s AND cloud_account_id = %s", (aid, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "asset not found")
    a = _asset_row(r)
    cur.execute("""SELECT source, ref, verification, observed_at FROM ai_asset_observations WHERE asset_id = %s
                   ORDER BY observed_at DESC LIMIT 50""", (aid,))
    a["observations"] = [{"source": s, "ref": ref, "verification": v, "at": at} for s, ref, v, at in cur.fetchall()]
    cur.execute("""SELECT r.id, r.rel_type, r.verification, r.confidence, r.sources, r.note, r.origin, r.first_seen, r.last_seen,
                          r.source_asset_id = %s, o.id, o.name, o.asset_type
                   FROM ai_asset_relationships r
                   JOIN ai_assets o ON o.id = CASE WHEN r.source_asset_id = %s THEN r.target_asset_id ELSE r.source_asset_id END
                   WHERE r.cloud_account_id = %s AND (r.source_asset_id = %s OR r.target_asset_id = %s)
                   ORDER BY r.rel_type""", (aid, aid, account, aid, aid))
    a["relationships"] = [{"id": str(i), "type": t, "verification": v, "confidence": c, "sources": s, "note": n, "origin": o,
                           "first_seen": fs, "last_seen": ls, "direction": "out" if out else "in",
                           "other": {"id": str(oid), "name": on, "asset_type": ot, "type_label": ASSET_TYPES.get(ot, ot)}}
                          for i, t, v, c, s, n, o, fs, ls, out, oid, on, ot in cur.fetchall()]
    cur.execute("""SELECT change_type, previous, new, source, actor, risk_impact, detected_at FROM ai_asset_changes
                   WHERE asset_id = %s AND cloud_account_id = %s ORDER BY detected_at DESC LIMIT 100""", (aid, account))
    a["changes"] = [{"type": t, "previous": p, "new": n, "source": s, "actor": ac, "risk_impact": ri, "at": at}
                    for t, p, n, s, ac, ri, at in cur.fetchall()]
    cur.execute("""SELECT id, rule, severity, title, status, first_seen, last_seen FROM ai_inventory_findings
                   WHERE asset_id = %s AND cloud_account_id = %s ORDER BY status, severity""", (aid, account))
    a["findings"] = [{"id": str(i), "rule": ru, "severity": sv, "title": t, "status": st, "first_seen": fs, "last_seen": ls}
                     for i, ru, sv, t, st, fs, ls in cur.fetchall()]
    a["impact"] = _impact(cur, account, aid)
    cur.execute(f"SELECT " + """(SELECT json_build_object('critical', count(*) FILTER (WHERE f.severity = 'critical'), 'high', count(*) FILTER (WHERE f.severity = 'high'),
                                                   'medium', count(*) FILTER (WHERE f.severity = 'medium'), 'low', count(*) FILTER (WHERE f.severity = 'low'))
                            FROM ai_inventory_findings f WHERE f.asset_id = a.id AND f.status IN ('open', 'in_progress')),
                           EXISTS (SELECT 1 FROM ai_asset_relationships r JOIN ai_assets i ON i.id = r.target_asset_id
                                   WHERE r.source_asset_id = a.id AND r.rel_type = 'AUTHENTICATES_AS' AND i.metadata->>'ciem_admin' = 'admin')""" + " FROM ai_assets a WHERE a.id = %s", (aid,))
    by_sev, admin = cur.fetchone()
    a["risk_score"], a["risk_factors"] = risk_score(a, by_sev or {}, admin)
    return a


def view_graph(cur, account):
    cur.execute("""SELECT id, name, asset_type, verification, lifecycle_status, approval_status FROM ai_assets
                   WHERE cloud_account_id = %s AND lifecycle_status <> 'retired' LIMIT 1500""", (account,))
    nodes = [{"id": str(i), "name": n, "asset_type": t, "type_label": ASSET_TYPES.get(t, t), "verification": v,
              "lifecycle_status": l, "approval_status": ap} for i, n, t, v, l, ap in cur.fetchall()]
    ids = {x["id"] for x in nodes}
    cur.execute("""SELECT id, source_asset_id, target_asset_id, rel_type, verification, confidence, origin FROM ai_asset_relationships
                   WHERE cloud_account_id = %s""", (account,))
    edges = [{"id": str(i), "source": str(s), "target": str(t), "type": ty, "verification": v, "confidence": c, "origin": o}
             for i, s, t, ty, v, c, o in cur.fetchall() if str(s) in ids and str(t) in ids]
    return {"nodes": nodes, "edges": edges}


def view_shadow(cur, account):
    cur.execute(f"""SELECT {ASSET_COLS} FROM ai_assets WHERE cloud_account_id = %s AND origin = 'discovered'
                    AND approval_status = 'unreviewed' AND asset_type = ANY(%s) AND lifecycle_status IN ('active', 'stale')
                    ORDER BY first_seen DESC""", (account, list(SHADOW_TYPES)))
    items = [_asset_row(r) for r in cur.fetchall()]
    cur.execute("SELECT approved_providers FROM ai_inventory_settings WHERE cloud_account_id = %s", (account,))
    r = cur.fetchone()
    approved = r[0] if r else []
    return {"items": items, "approved_providers": approved,
            "definition": "AI in use that nobody in your organisation has reviewed yet (approval status 'unreviewed'). "
                          "Being custom-built or local is not a risk by itself; review each item and approve, restrict or reject it."}


def view_findings(cur, account, qs):
    where, args = ["f.cloud_account_id = %s"], [account]
    if qs.get("status"):
        if qs["status"] not in FINDING_STATUSES + ("resolved",):
            raise BadRequest(400, "unknown status")
        where.append("f.status = %s")
        args.append(qs["status"])
    cur.execute(f"""SELECT f.id, f.rule, f.severity, f.title, f.details, f.recommendation, f.compliance, f.status, f.status_reason,
                           f.status_by, f.status_at, f.accepted_until, f.ticket, f.first_seen, f.last_seen, f.resolved_at,
                           a.id, a.name, a.asset_type
                    FROM ai_inventory_findings f LEFT JOIN ai_assets a ON a.id = f.asset_id
                    WHERE {" AND ".join(where)}
                    ORDER BY CASE f.status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 WHEN 'accepted' THEN 2 ELSE 3 END,
                             CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                             f.first_seen DESC LIMIT 1000""", args)
    keys = ("id", "rule", "severity", "title", "details", "recommendation", "compliance", "status", "status_reason", "status_by",
            "status_at", "accepted_until", "ticket", "first_seen", "last_seen", "resolved_at")
    out = []
    for r in cur.fetchall():
        f = dict(zip(keys, r[:16]))
        f["id"] = str(f["id"])
        f["asset"] = {"id": str(r[16]), "name": r[17], "asset_type": r[18], "type_label": ASSET_TYPES.get(r[18], r[18])} if r[16] else None
        out.append(f)
    cur.execute("SELECT id, provider, project FROM workspace_integrations WHERE cloud_account_id = %s ORDER BY created_at", (account,))
    integrations = [{"id": str(i), "provider": p, "project": pr} for i, p, pr in cur.fetchall()]
    return {"findings": out, "integrations": integrations}


def view_changes(cur, account, qs):
    days = qs.get("days", "30")
    if days not in ("7", "30", "90", "365"):
        raise BadRequest(400, "days must be 7, 30, 90 or 365")
    cur.execute("""SELECT c.change_type, c.previous, c.new, c.source, c.actor, c.risk_impact, c.detected_at, a.id,
                          COALESCE(a.name, c.asset_name, '(deleted asset)'), a.asset_type
                   FROM ai_asset_changes c LEFT JOIN ai_assets a ON a.id = c.asset_id
                   WHERE c.cloud_account_id = %s AND c.detected_at > NOW() - make_interval(days => %s)
                   ORDER BY c.detected_at DESC LIMIT 500""", (account, int(days)))
    return {"changes": [{"type": t, "previous": p, "new": n, "source": s, "actor": ac, "risk_impact": ri, "at": at,
                         "asset": {"id": str(i) if i else None, "name": nm, "asset_type": ty,
                                   "type_label": ASSET_TYPES.get(ty, ty) if ty else "deleted"}}
                        for t, p, n, s, ac, ri, at, i, nm, ty in cur.fetchall()]}


def view_settings(cur, account):
    cur.execute("""SELECT approved_providers, github_repos, inactive_after_days, updated_by, updated_at FROM ai_inventory_settings
                   WHERE cloud_account_id = %s""", (account,))
    r = cur.fetchone()
    cur.execute("SELECT org_name FROM github_integrations WHERE cloud_account_id = %s", (account,))
    gh = cur.fetchone()
    return {"approved_providers": r[0] if r else [], "github_repos": r[1] if r else [], "inactive_after_days": r[2] if r else 30,
            "updated_by": r[3] if r else None, "updated_at": r[4] if r else None,
            "providers": [{"id": k, "name": v["name"]} for k, v in PROVIDERS.items()],
            "github_org": gh[0] if gh else None}


def view_audit(cur, account):
    cur.execute("""SELECT created_at, actor_email, action, target, details FROM ai_inventory_audit_log
                   WHERE cloud_account_id = %s ORDER BY created_at DESC LIMIT 300""", (account,))
    return {"audit": [{"at": a, "actor": b, "action": c, "target": d, "details": e} for a, b, c, d, e in cur.fetchall()]}


def view_scans(cur, account):
    cur.execute("""SELECT id, status, trigger, started_at, finished_at, error, summary, limitations FROM ai_inventory_scans
                   WHERE cloud_account_id = %s ORDER BY started_at DESC LIMIT 20""", (account,))
    return {"scans": [{"id": str(i), "status": s, "trigger": t, "started_at": a, "finished_at": f, "error": e, "summary": sm,
                       "limitations": lm} for i, s, t, a, f, e, sm, lm in cur.fetchall()]}


def _evidence(cur, account):
    """Evidence package: what was inventoried, from which sources, when, how sure, and what was not covered."""
    scan = _latest_scan(cur, account)
    cur.execute(f"SELECT {ASSET_COLS} FROM ai_assets WHERE cloud_account_id = %s ORDER BY asset_type, name", (account,))
    assets = [_asset_row(r) for r in cur.fetchall()]
    cur.execute("""SELECT o.asset_id, o.source, o.ref, o.verification, o.observed_at FROM ai_asset_observations o JOIN ai_assets a ON a.id = o.asset_id
                   WHERE a.cloud_account_id = %s ORDER BY o.observed_at DESC""", (account,))
    obs = {}
    for aid, src, ref, ver, at in cur.fetchall():
        lst = obs.setdefault(str(aid), [])
        if len(lst) < 20:
            lst.append({"source": src, "ref": ref, "verification": ver, "at": at})
    for a in assets:
        a["observations"] = obs.get(a["id"], [])
    cur.execute("""SELECT s.name, r.rel_type, t.name, r.sources, r.verification, r.confidence, r.origin, r.first_seen, r.last_seen
                   FROM ai_asset_relationships r JOIN ai_assets s ON s.id = r.source_asset_id JOIN ai_assets t ON t.id = r.target_asset_id
                   WHERE r.cloud_account_id = %s""", (account,))
    rels = [dict(zip(("source", "type", "target", "sources", "verification", "confidence", "origin", "first_seen", "last_seen"), r)) for r in cur.fetchall()]
    cur.execute("""SELECT rule, severity, title, status, status_reason, accepted_until, details, compliance, first_seen, last_seen, resolved_at
                   FROM ai_inventory_findings WHERE cloud_account_id = %s ORDER BY first_seen""", (account,))
    findings = [dict(zip(("rule", "severity", "title", "status", "status_reason", "accepted_until", "evidence", "compliance", "first_seen",
                          "last_seen", "resolved_at"), r)) for r in cur.fetchall()]
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "scope": {"cloud_account_id": account,
            "regions": ((scan or {}).get("summary") or {}).get("regions"), "sources_read": ((scan or {}).get("summary") or {}).get("sources_read")},
            "latest_scan": scan, "limitations": (scan or {}).get("limitations") or [],
            "verification_levels": {"declared": "found in code or configuration", "discovered": "listed by AWS", "observed": "usage evidence",
                                    "verified": "reviewed by a person"},
            "assets": assets, "relationships": rels, "findings": findings,
            "note": "Covers only the sources listed under scope; it is not proof that no other AI is in use."}


def export(cur, account, what, fmt, actor):
    if what == "evidence":
        if fmt != "json":
            raise BadRequest(400, "The evidence package is only available as JSON.")
        data = _evidence(cur, account)
        _audit(cur, account, actor, "export", what, {"format": fmt, "assets": len(data["assets"])})
        return _resp(200, data)
    if what == "assets":
        cols = ["asset_type", "name", "provider", "verification", "origin", "lifecycle_status", "approval_status", "approval_reason",
                "approval_until", "owner", "business_purpose", "environment", "criticality", "next_review_at", "first_seen",
                "last_seen", "last_verified", "asset_key"]
        cur.execute(f"SELECT {', '.join(cols)} FROM ai_assets WHERE cloud_account_id = %s ORDER BY asset_type, name", (account,))
    elif what == "findings":
        cols = ["severity", "status", "rule", "title", "asset", "first_seen", "last_seen", "resolved_at", "status_reason",
                "accepted_until", "recommendation", "compliance"]
        cur.execute("""SELECT f.severity, f.status, f.rule, f.title, a.name, f.first_seen, f.last_seen, f.resolved_at, f.status_reason,
                              f.accepted_until, f.recommendation->>'proposed', f.compliance
                       FROM ai_inventory_findings f LEFT JOIN ai_assets a ON a.id = f.asset_id
                       WHERE f.cloud_account_id = %s ORDER BY f.status, f.severity""", (account,))
    elif what == "relationships":
        cols = ["source", "source_type", "relationship", "target", "target_type", "verification", "confidence", "origin", "first_seen", "last_seen"]
        cur.execute("""SELECT s.name, s.asset_type, r.rel_type, t.name, t.asset_type, r.verification, r.confidence, r.origin, r.first_seen, r.last_seen
                       FROM ai_asset_relationships r JOIN ai_assets s ON s.id = r.source_asset_id JOIN ai_assets t ON t.id = r.target_asset_id
                       WHERE r.cloud_account_id = %s ORDER BY s.name, r.rel_type""", (account,))
    elif what == "changes":
        cols = ["at", "asset", "change_type", "previous", "new", "source", "actor", "risk_impact"]
        cur.execute("""SELECT c.detected_at, COALESCE(a.name, c.asset_name), c.change_type, c.previous, c.new, c.source, c.actor, c.risk_impact
                       FROM ai_asset_changes c LEFT JOIN ai_assets a ON a.id = c.asset_id
                       WHERE c.cloud_account_id = %s ORDER BY c.detected_at DESC""", (account,))
    elif what == "audit":
        cols = ["at", "actor", "action", "target", "details"]
        cur.execute("""SELECT created_at, actor_email, action, target, details FROM ai_inventory_audit_log
                       WHERE cloud_account_id = %s ORDER BY created_at DESC""", (account,))
    else:
        raise BadRequest(400, "what must be assets, findings, relationships, changes, audit or evidence")
    if fmt not in ("csv", "json"):
        raise BadRequest(400, "format must be csv or json")
    rows = cur.fetchall()
    _audit(cur, account, actor, "export", what, {"format": fmt, "rows": len(rows)})
    if fmt == "json":
        return _resp(200, {"what": what, "rows": [dict(zip(cols, r)) for r in rows]})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([_csv_cell(v) for v in r])
    return _resp(200, buf.getvalue(), {"Content-Type": "text/csv; charset=utf-8",
                                       "Content-Disposition": f'attachment; filename="niagaros-ai-inventory-{what}.csv"'})


# ── writes ───────────────────────────────────────────────────────────────────

GOVERNANCE_FIELDS = ("owner", "business_purpose", "environment", "criticality", "next_review_at", "lifecycle_status",
                     "approval_status", "approval_reason", "approval_until")


def _governance(body, current=None):
    """Validated governance fields present in body (only those keys)."""
    out = {}
    if "owner" in body:
        out["owner"] = _text(body, "owner", 200)
    if "business_purpose" in body:
        out["business_purpose"] = _text(body, "business_purpose", 2000)
    if "environment" in body:
        if body["environment"] not in ENVIRONMENTS:
            raise BadRequest(400, f"environment must be one of: {', '.join(ENVIRONMENTS)}")
        out["environment"] = body["environment"]
    if "criticality" in body:
        if body["criticality"] not in CRITICALITIES:
            raise BadRequest(400, f"criticality must be one of: {', '.join(CRITICALITIES)}")
        out["criticality"] = body["criticality"]
    if "next_review_at" in body:
        out["next_review_at"] = _date(body["next_review_at"], "The next review date", max_days=731) if body["next_review_at"] else None
    if "lifecycle_status" in body:
        if body["lifecycle_status"] not in MANUAL_LIFECYCLE:
            raise BadRequest(400, "lifecycle_status can be set to active, deprecated or retired ('stale' and 'inactive' come from scans).")
        out["lifecycle_status"] = body["lifecycle_status"]
    if "approval_status" in body:
        st = body["approval_status"]
        if st not in APPROVALS:
            raise BadRequest(400, f"approval_status must be one of: {', '.join(APPROVALS)}")
        reason = _text(body, "approval_reason", 1000)
        if st in ("restricted", "rejected", "exception") and not reason:
            raise BadRequest(400, "Give a reason for this decision.")
        until = None
        if st == "exception":
            if not body.get("approval_until"):
                raise BadRequest(400, "An exception needs an end date (YYYY-MM-DD).")
            until = _date(body["approval_until"], "The exception end date", max_days=366)
        out.update({"approval_status": st, "approval_reason": reason, "approval_until": until})
    return out


def _apply_governance(cur, account, aid, fields, actor, before):
    if not fields:
        raise BadRequest(400, "Nothing to update.")
    sets, args = [], []
    for k, v in fields.items():
        sets.append(f"{k} = %s")
        args.append(v)
    if "approval_status" in fields:
        reviewed = fields["approval_status"] != "unreviewed"
        sets += ["approval_by = %s", "approval_at = NOW()",
                 # withdrawing a review falls back to the strongest level the scans actually showed
                 """verification = CASE WHEN %s THEN 'verified' ELSE COALESCE(
                        (SELECT o.verification FROM ai_asset_observations o WHERE o.asset_id = ai_assets.id
                         ORDER BY CASE o.verification WHEN 'observed' THEN 3 WHEN 'discovered' THEN 2 WHEN 'declared' THEN 1 ELSE 0 END DESC
                         LIMIT 1), 'declared') END""",
                 "last_verified = CASE WHEN %s THEN NOW() ELSE last_verified END"]
        args += [actor if reviewed else None, reviewed, reviewed]
    cur.execute(f"UPDATE ai_assets SET {', '.join(sets)} WHERE id = %s AND cloud_account_id = %s", args + [aid, account])
    prev = {k: before.get(k) for k in fields}
    changed = {k: v for k, v in fields.items() if prev.get(k) != v}
    if "approval_status" in fields and "approval_status" not in changed and fields["approval_status"] != "unreviewed" \
            and before.get("verification") != "verified":
        # the same decision submitted again after the asset changed: the review is renewed
        _change(cur, account, aid, "review_confirmed", {"verification": before.get("verification")},
                {"verification": "verified", "approval_status": fields["approval_status"]}, actor)
    if changed:
        kind = "approval_changed" if "approval_status" in changed else "governance_updated"
        _change(cur, account, aid, kind, {k: prev[k] for k in changed}, changed, actor,
                "medium" if kind == "approval_changed" else None)
    return changed


def update_asset(cur, account, body, actor):
    aid = _uuid(body.get("asset_id"), "asset")
    cur.execute(f"SELECT {ASSET_COLS} FROM ai_assets WHERE id = %s AND cloud_account_id = %s FOR UPDATE", (aid, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "asset not found")
    before = _asset_row(r)
    fields = _governance({k: body[k] for k in GOVERNANCE_FIELDS if k in body})
    changed = _apply_governance(cur, account, aid, fields, actor, before)
    _audit(cur, account, actor, "asset_updated", aid, {"name": before["name"], "changed": changed})
    return {"asset_id": aid, "changed": sorted(changed)}


def _register(cur, account, row, actor, origin):
    name = _text(row, "name", 200, required=True, label="Name")
    atype = row.get("asset_type")
    if atype not in ASSET_TYPES:
        raise BadRequest(400, f"asset_type must be one of: {', '.join(ASSET_TYPES)}")
    provider = _text(row, "provider", 100)
    description = _text(row, "description", 2000)
    gov = _governance({k: row[k] for k in GOVERNANCE_FIELDS if k in row and row[k] not in (None, "")})
    meta = {"description": description, "registered_by": actor}
    cur.execute("""INSERT INTO ai_assets (cloud_account_id, asset_key, asset_type, name, provider, verification, metadata, origin)
                   VALUES (%s, 'manual:' || gen_random_uuid()::text, %s, %s, %s, 'declared', %s, %s) RETURNING id""",
                (account, atype, name, provider, J({k: v for k, v in meta.items() if v}), origin))
    aid = str(cur.fetchone()[0])
    _change(cur, account, aid, "registered", None, {"name": name, "asset_type": atype, "origin": origin}, actor)
    if gov:
        _apply_governance(cur, account, aid, gov, actor, {})
    return aid


def register_asset(cur, account, body, actor):
    aid = _register(cur, account, body, actor, "manual")
    _audit(cur, account, actor, "asset_registered", aid, {"name": body.get("name"), "asset_type": body.get("asset_type")})
    return {"asset_id": aid}


def import_assets(cur, account, body, actor):
    rows = body.get("rows")
    if not isinstance(rows, list) or not rows:
        raise BadRequest(400, "rows must be a non-empty list")
    if len(rows) > 500:
        raise BadRequest(400, "At most 500 rows per import.")
    ids = []
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise BadRequest(400, f"Row {i}: not an object")
        try:
            ids.append(_register(cur, account, row, actor, "imported"))
        except BadRequest as e:
            raise BadRequest(400, f"Row {i}: {e.message} Nothing was imported.")
    _audit(cur, account, actor, "assets_imported", None, {"rows": len(ids)})
    return {"imported": len(ids)}


def delete_asset(cur, account, body, actor):
    aid = _uuid(body.get("asset_id"), "asset")
    cur.execute("SELECT origin, name, asset_type FROM ai_assets WHERE id = %s AND cloud_account_id = %s FOR UPDATE", (aid, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "asset not found")
    if r[0] == "discovered":
        raise BadRequest(409, "Discovered assets come back with the next scan; set their lifecycle to 'retired' instead.")
    cur.execute("DELETE FROM ai_assets WHERE id = %s AND cloud_account_id = %s", (aid, account))
    _audit(cur, account, actor, "asset_deleted", aid, {"name": r[1], "asset_type": r[2], "origin": r[0]})
    return {"deleted": True}


def link_assets(cur, account, body, actor):
    s = _uuid(body.get("source_asset_id"), "asset")
    t = _uuid(body.get("target_asset_id"), "asset")
    if s == t:
        raise BadRequest(400, "An asset cannot be linked to itself.")
    rtype = body.get("rel_type")
    if rtype not in REL_TYPES:
        raise BadRequest(400, f"rel_type must be one of: {', '.join(REL_TYPES)}")
    note = _text(body, "note", 500)
    cur.execute("SELECT id, name FROM ai_assets WHERE id = ANY(%s::uuid[]) AND cloud_account_id = %s", ([s, t], account))
    found = {str(i): n for i, n in cur.fetchall()}
    if len(found) != 2:
        raise BadRequest(404, "asset not found")
    cur.execute("""INSERT INTO ai_asset_relationships (cloud_account_id, source_asset_id, target_asset_id, rel_type, sources,
                                                       verification, confidence, note, origin, created_by)
                   VALUES (%s, %s, %s, %s, %s, 'declared', 'high', %s, 'manual', %s)
                   ON CONFLICT (source_asset_id, target_asset_id, rel_type) DO NOTHING RETURNING id""",
                (account, s, t, rtype, J([f"manual:{actor}"]), note, actor))
    r = cur.fetchone()
    if not r:
        raise BadRequest(409, "This relationship already exists.")
    _audit(cur, account, actor, "assets_linked", str(r[0]), {"source": found[s], "type": rtype, "target": found[t], "note": note})
    return {"relationship_id": str(r[0])}


def unlink_assets(cur, account, body, actor):
    rid = _uuid(body.get("relationship_id"), "relationship")
    cur.execute("""DELETE FROM ai_asset_relationships WHERE id = %s AND cloud_account_id = %s AND origin = 'manual'
                   RETURNING rel_type, source_asset_id, target_asset_id""", (rid, account))
    r = cur.fetchone()
    if not r:
        cur.execute("SELECT 1 FROM ai_asset_relationships WHERE id = %s AND cloud_account_id = %s", (rid, account))
        if cur.fetchone():
            raise BadRequest(409, "Discovered relationships come from the scan and cannot be removed by hand.")
        raise BadRequest(404, "relationship not found")
    _audit(cur, account, actor, "assets_unlinked", rid, {"type": r[0], "source": str(r[1]), "target": str(r[2])})
    return {"deleted": True}


def set_finding_status(cur, account, body, actor):
    fid = _uuid(body.get("finding_id"), "finding")
    status = body.get("status")
    if status not in FINDING_STATUSES:
        raise BadRequest(400, f"status must be one of: {', '.join(FINDING_STATUSES)}")
    reason = _text(body, "reason", 1000)
    until = None
    if status in ("accepted", "false_positive") and not reason:
        raise BadRequest(400, "A reason is required.")
    if status == "accepted":
        if not body.get("accepted_until"):
            raise BadRequest(400, "An accepted risk needs an end date (YYYY-MM-DD).")
        until = _date(body["accepted_until"], "The end date", max_days=366)
    cur.execute("SELECT status FROM ai_inventory_findings WHERE id = %s AND cloud_account_id = %s FOR UPDATE", (fid, account))
    row = cur.fetchone()
    if not row:
        raise BadRequest(404, "finding not found")
    if row[0] == "resolved":
        raise BadRequest(409, "This finding is resolved by the latest scan; it re-opens automatically if it comes back.")
    cur.execute("""UPDATE ai_inventory_findings SET status = %s, status_reason = %s, status_by = %s, status_at = NOW(),
                   accepted_until = %s WHERE id = %s""", (status, reason, actor, until, fid))
    _audit(cur, account, actor, "finding_status", fid, {"from": row[0], "to": status, "reason": reason, "accepted_until": until})
    return {"finding_id": fid, "status": status}


def create_ticket(cur, account, body, actor):
    from collectors.aws.scanner.integrations_handler import _client_for, _load
    fid = _uuid(body.get("finding_id"), "finding")
    integ = _load(cur, _uuid(body.get("integration_id"), "integration"))
    if not integ or integ["cloud_account_id"] != account:
        raise BadRequest(404, "integration not found")
    if not integ["project"]:
        raise BadRequest(400, "Select a project for this integration first (Integrations page).")
    cur.execute("""SELECT f.title, f.severity, f.recommendation, a.name, f.ticket FROM ai_inventory_findings f
                   LEFT JOIN ai_assets a ON a.id = f.asset_id WHERE f.id = %s AND f.cloud_account_id = %s FOR UPDATE OF f""", (fid, account))
    f = cur.fetchone()
    if not f:
        raise BadRequest(404, "finding not found")
    if f[4]:
        raise BadRequest(409, "A ticket already exists for this finding.")
    rec = f[2] or {}
    desc = (f"Niagaros AI Inventory finding ({f[1]}): {f[0]}\nAsset: {f[3] or '-'}\n\nCurrent: {rec.get('current', '')}\n"
            f"Proposed: {rec.get('proposed', '')}\nWhy: {rec.get('reason', '')}\nImpact: {rec.get('impact', '')}\n"
            f"Rollback: {rec.get('rollback', '')}\nApprovals: {rec.get('approvals', '')}")
    t = _client_for(integ).create_ticket(integ["project"], f"[AI Inventory] {f[0]}", desc, f[1])
    ticket = {"provider": integ["provider"], "integration_id": integ["id"], **t, "status": "created", "created_by": actor}
    cur.execute("""UPDATE ai_inventory_findings SET ticket = %s, status = CASE WHEN status = 'open' THEN 'in_progress' ELSE status END
                   WHERE id = %s""", (Json(ticket), fid))
    _audit(cur, account, actor, "ticket_created", fid, {"provider": integ["provider"], "key": t.get("key")})
    return {"ticket": ticket}


def refresh_ticket(cur, account, body, actor):
    from collectors.aws.scanner.integrations_handler import _client_for, _load
    fid = _uuid(body.get("finding_id"), "finding")
    cur.execute("SELECT ticket FROM ai_inventory_findings WHERE id = %s AND cloud_account_id = %s FOR UPDATE", (fid, account))
    r = cur.fetchone()
    if not r or not r[0]:
        raise BadRequest(404, "no ticket for this finding")
    t = r[0]
    integ = _load(cur, t["integration_id"])
    if not integ or integ["cloud_account_id"] != account:
        raise BadRequest(409, "The integration for this ticket no longer exists.")
    st = _client_for(integ).status(t)
    t.update({"status": st.get("name"), "done": st.get("done"), "checked_at": datetime.utcnow().isoformat() + "Z"})
    cur.execute("UPDATE ai_inventory_findings SET ticket = %s WHERE id = %s", (Json(t), fid))
    return {"ticket": t, "note": "A finding is only marked resolved when the next scan no longer sees it, not when the ticket closes."}


def save_settings(cur, account, body, actor):
    providers = body.get("approved_providers", [])
    if not isinstance(providers, list) or any(p not in PROVIDERS for p in providers):
        raise BadRequest(400, "approved_providers must be a list of known provider ids")
    repos = body.get("github_repos", [])
    if not isinstance(repos, list) or len(repos) > 100 or any(
            not isinstance(r, str) or not REPO_RE.match(r) or any(part.strip(".") == "" for part in r.split("/")) for r in repos):
        raise BadRequest(400, "github_repos must be a list of up to 100 repository names (name or owner/name)")
    days = body.get("inactive_after_days", 30)
    if not isinstance(days, int) or isinstance(days, bool) or not 7 <= days <= 365:
        raise BadRequest(400, "inactive_after_days must be a whole number between 7 and 365")
    cur.execute("SELECT approved_providers, github_repos, inactive_after_days FROM ai_inventory_settings WHERE cloud_account_id = %s", (account,))
    before = cur.fetchone()
    new = {"approved_providers": sorted(set(providers)), "github_repos": sorted(set(repos)), "inactive_after_days": days}
    cur.execute("""INSERT INTO ai_inventory_settings (cloud_account_id, approved_providers, github_repos, inactive_after_days, updated_by, updated_at)
                   VALUES (%s, %s, %s, %s, %s, NOW())
                   ON CONFLICT (cloud_account_id) DO UPDATE SET approved_providers = EXCLUDED.approved_providers,
                       github_repos = EXCLUDED.github_repos, inactive_after_days = EXCLUDED.inactive_after_days,
                       updated_by = EXCLUDED.updated_by, updated_at = NOW()""",
                (account, J(new["approved_providers"]), J(new["github_repos"]), days, actor))
    _audit(cur, account, actor, "settings", None, {"previous": dict(zip(new, before)) if before else None, "new": new})
    return {"saved": True, "note": "Applies from the next scan."}


def run_scan(cur, account, body, actor):
    cur.execute("""SELECT 1 FROM ai_inventory_scans WHERE cloud_account_id = %s AND status = 'running'
                   AND started_at > NOW() - INTERVAL '20 minutes'""", (account,))
    if cur.fetchone():
        raise BadRequest(409, "A scan is already running for this account.")
    # the scan row only appears once the scanner starts, so the request itself (audit log) is what is limited
    cur.execute("""SELECT 1 FROM ai_inventory_audit_log WHERE cloud_account_id = %s AND action = 'scan_started'
                   AND created_at > NOW() - INTERVAL '5 minutes'""", (account,))
    if cur.fetchone():
        raise BadRequest(429, "A scan was started less than 5 minutes ago. Please wait a moment.")
    cur.execute("SELECT 1 FROM cloud_accounts WHERE id = %s AND status = 'active'", (account,))
    if not cur.fetchone():
        raise BadRequest(409, "This account is not active, so it cannot be scanned.")
    boto3.client("lambda", region_name=REGION).invoke(
        FunctionName=SCANNER_FUNCTION, InvocationType="Event",
        Payload=json.dumps({"cloud_account_id": account, "trigger": "manual", "_async": True}).encode())
    _audit(cur, account, actor, "scan_started", None, {})
    return {"started": True, "note": "The scan runs in the background; refresh in a minute or two."}


ACTIONS = {"update_asset": update_asset, "register_asset": register_asset, "import_assets": import_assets,
           "delete_asset": delete_asset, "link_assets": link_assets, "unlink_assets": unlink_assets,
           "set_finding_status": set_finding_status, "create_ticket": create_ticket, "refresh_ticket": refresh_ticket,
           "save_settings": save_settings, "run_scan": run_scan}
VIEWS = {"overview": view_overview, "graph": view_graph, "shadow": view_shadow, "settings": view_settings,
         "audit": view_audit, "scans": view_scans}
VIEWS_QS = {"assets": view_assets, "findings": view_findings, "changes": view_changes}


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
    account = account.lower()
    denied = guard(event, conn, qs, body, REFS, None)
    if denied:
        return _resp(denied[0], {"error": denied[1]})
    actor = authenticate(event) or "unknown"
    try:
        with conn.cursor() as cur:
            # Risk acceptances and exceptions end on their date even between scans.
            cur.execute("""UPDATE ai_inventory_findings SET status = 'open', status_reason = 'Re-opened: risk acceptance expired'
                           WHERE cloud_account_id = %s AND status = 'accepted' AND accepted_until < CURRENT_DATE""", (account,))
            if cur.rowcount:
                conn.commit()
            if method == "GET":
                view = qs.get("view", "overview")
                if view == "asset":
                    return _resp(200, view_asset(cur, account, qs.get("asset_id")))
                if view == "export":
                    r = export(cur, account, qs.get("what"), qs.get("format", "csv"), actor)
                    conn.commit()
                    return r
                if view in VIEWS_QS:
                    return _resp(200, VIEWS_QS[view](cur, account, qs))
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
        return _resp(200, result)
    except BadRequest as e:
        conn.rollback()
        return _resp(e.status, {"error": e.message})


def handler(event, context):
    if not event or "httpMethod" not in event:
        return _resp(400, {"error": "not an API Gateway event"})
    if event.get("httpMethod") == "OPTIONS":
        return _resp(200, {})
    if os.environ.get("TENANT_AUTH_ENFORCE", "1") != "0" and not authenticate(event):
        return _resp(401, {"error": "Unauthorized"})
    conn = _get_connection()
    try:
        return handle(event, conn)
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logger.error("ai_inventory_handler error: %s", e, exc_info=True)
        if type(e).__name__ == "ProviderError":
            return _resp(502, {"error": "The ticket system did not accept the request. Check the connection and project on the Integrations page."})
        return _resp(500, {"error": "Something went wrong on our side. Please try again."})
    finally:
        conn.close()


lambda_handler = handler
