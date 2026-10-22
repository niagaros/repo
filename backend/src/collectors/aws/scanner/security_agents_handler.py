"""
security_agents_handler.py — Security Agents API (issue #239). One Lambda behind GET/POST /security-agents, guarded
by tenant_auth.guard like every other account-data handler: every referenced id (work_item_id, incident_id,
detection_id, approval_id, authorization_id, run_id, integration_id) is resolved to its real account first, and
every query filters on the caller's cloud_account_id again. Unauthenticated calls are rejected before the
database is opened.

GET  /security-agents?cloud_account_id=...&view=
       overview | agents | agent&agent_id= | runs | run&run_id= | queue | item&work_item_id= | detections |
       incidents | incident&incident_id= | attack_paths | approvals | policies | settings | audit |
       export&what=queue|detections|incidents|runs|audit&format=csv|json
POST /security-agents {cloud_account_id, action, ...}
       configure_agent, authorize_agent, revoke_authorization, set_policy, run_evaluation, approve_agent,
       set_agent_status, activate_recommended, run_agents, transition_item, assign_item, record_remediation,
       create_ticket, refresh_ticket, request_containment, decide_approval, update_incident, update_detection,
       save_settings, request_technique

Niagaros never changes a customer's systems from here. Containment and changes are prepared and approved; your
team executes them; a later scan verifies them.
"""
import csv
import io
import json
import logging
import os
import re
from datetime import date, datetime, timedelta, timezone

import boto3
import psycopg2
from psycopg2.extras import Json

from collectors.aws.scanner.tenant_auth import authenticate, guard
from collectors.aws.scanner import security_agents_engine as E

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
REGION = os.environ.get("SECRET_REGION", "eu-west-1")
RUNNER_FUNCTION = os.environ.get("SECURITY_AGENTS_RUNNER_FUNCTION", "security-agents-scanner")
CORS = {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization"}
REFS = {
    "work_item_id": "SELECT cloud_account_id FROM sa_work_items WHERE id = %s",
    "incident_id": "SELECT cloud_account_id FROM sa_incidents WHERE id = %s",
    "detection_id": "SELECT cloud_account_id FROM sa_detections WHERE id = %s",
    "approval_id": "SELECT cloud_account_id FROM sa_approvals WHERE id = %s",
    "authorization_id": "SELECT cloud_account_id FROM sa_authorizations WHERE id = %s",
    "run_id": "SELECT cloud_account_id FROM sa_runs WHERE id = %s",
    "integration_id": "SELECT cloud_account_id FROM workspace_integrations WHERE id = %s",
}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
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


def _uuid(v, what):
    if not isinstance(v, str) or not UUID_RE.match(v):
        raise BadRequest(404, f"{what} not found")
    return v


def _text(body, key, maxlen, required=False, label=None):
    v = body.get(key)
    name = label or key.replace("_", " ").capitalize()
    if v is None or (isinstance(v, str) and not v.strip()):
        if required:
            raise BadRequest(400, f"{name} is required.")
        return None
    if not isinstance(v, str):
        raise BadRequest(400, f"{name} must be text.")
    v = v.strip()
    if len(v) > maxlen:
        raise BadRequest(400, f"{name} can be at most {maxlen} characters.")
    return v


def _date(v, what, max_days):
    try:
        d = datetime.strptime(str(v), "%Y-%m-%d").date()
    except ValueError:
        raise BadRequest(400, f"{what} must be a date (YYYY-MM-DD).")
    if d <= date.today() or d > date.today() + timedelta(days=max_days):
        raise BadRequest(400, f"{what} must be in the future and at most {max_days} days away.")
    return d


def _agent(body):
    a = body.get("agent_id")
    if a not in E.AGENTS:
        raise BadRequest(404, "agent not found")
    return a


def _csv_cell(v):
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        v = json.dumps(v, default=str)
    v = str(v)
    return "'" + v if v.startswith(_FORMULA_START) else v


def _audit(cur, account, actor, action, target=None, details=None):
    cur.execute("INSERT INTO sa_audit_log (cloud_account_id, actor_email, action, target, details) VALUES (%s, %s, %s, %s, %s)",
                (account, actor, action, target, J(details or {})))


def _event(cur, account, item_id, frm, to, actor, note=None, details=None):
    cur.execute("""INSERT INTO sa_work_item_events (cloud_account_id, work_item_id, from_state, to_state, actor, actor_kind, note, details)
                   VALUES (%s, %s, %s, %s, %s, 'human', %s, %s)""", (account, item_id, frm, to, actor, note, J(details or {})))


def _seed(cur, account):
    for agent_id in E.AGENTS:
        cur.execute("""INSERT INTO sa_agents (cloud_account_id, agent_id, agent_version) VALUES (%s, %s, %s)
                       ON CONFLICT (cloud_account_id, agent_id) DO NOTHING""", (account, agent_id, E.ENGINE_VERSION))


def _settings(cur, account):
    cur.execute("SELECT environment, lookback_hours, updated_by, updated_at FROM sa_settings WHERE cloud_account_id = %s", (account,))
    r = cur.fetchone()
    return {"environment": r[0] if r else "production", "lookback_hours": r[1] if r else 24,
            "updated_by": r[2] if r else None, "updated_at": r[3] if r else None}


def _context(cur, account):
    """The same inputs the runner uses, so API-initiated actions get the same execution-time decision."""
    from collectors.aws.scanner.security_agents_runner_handler import load_context
    return load_context(cur, account)


_DENIALS = []   # blocked decisions of the current request; re-written after a rollback so the audit keeps them


def _decide(cur, account, agent_id, action, actor, target=None, technique=None):
    ctx = _context(cur, account)
    d = E.authorize(agent_id, ctx["states"].get(agent_id, "registered"), action, account, ctx["environment"], ctx["auths"],
                    ctx["policies"], technique=technique)
    cur.execute("""INSERT INTO sa_actions (cloud_account_id, agent_id, action, target, environment, decision, reason, execution_status, initiated_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                (account, agent_id, action, target, ctx["environment"], d["decision"], d["reason"],
                 "not_started" if d["decision"] == "allow" else ("waiting" if d["decision"] == "approval_required" else "skipped"), actor))
    d["action_id"] = cur.fetchone()[0]
    d["environment"] = ctx["environment"]
    if d["decision"] == "block":
        _DENIALS.append((account, agent_id, action, target, ctx["environment"], d["reason"], actor))
    return d


# ── reads ────────────────────────────────────────────────────────────────────

def _agent_rows(cur, account):
    cur.execute("""SELECT agent_id, status, owner, business_purpose, approved_by, approved_at, agent_version, last_run_at, last_run_status
                   FROM sa_agents WHERE cloud_account_id = %s""", (account,))
    rows = {r[0]: dict(zip(("agent_id", "status", "owner", "business_purpose", "approved_by", "approved_at", "agent_version",
                            "last_run_at", "last_run_status"), r)) for r in cur.fetchall()}
    cur.execute("""SELECT agent_id, max(valid_until) FROM sa_authorizations WHERE cloud_account_id = %s AND revoked_at IS NULL
                   AND valid_until > NOW() AND valid_from <= NOW() GROUP BY 1""", (account,))
    auth = dict(cur.fetchall())
    cur.execute("""SELECT DISTINCT ON (agent_id) agent_id, passed, agent_version, created_at FROM sa_evaluations
                   WHERE cloud_account_id = %s ORDER BY agent_id, created_at DESC""", (account,))
    evals = {a: {"passed": p, "agent_version": v, "at": t} for a, p, v, t in cur.fetchall()}
    out = []
    for agent_id, meta in E.AGENTS.items():
        r = rows.get(agent_id) or {"status": "registered"}
        ev = evals.get(agent_id)
        out.append({"agent_id": agent_id, **meta, "category_label": E.CATEGORY_LABEL[meta["category"]],
                    "model": "none — deterministic rules", "framework": "Niagaros security-agents", "engine_version": E.ENGINE_VERSION,
                    "status": r["status"], "owner": r.get("owner"), "business_purpose": r.get("business_purpose"),
                    "approved_by": r.get("approved_by"), "approved_at": r.get("approved_at"), "last_run_at": r.get("last_run_at"),
                    "last_run_status": r.get("last_run_status"), "authorized_until": auth.get(agent_id),
                    "evaluation": ev, "evaluation_current": bool(ev and ev["passed"] and ev["agent_version"] == E.ENGINE_VERSION),
                    "actions_detail": [{"id": a, **E.ACTIONS[a]} for a in meta["actions"]]})
    return out


def view_overview(cur, account):
    _seed(cur, account)
    agents = _agent_rows(cur, account)
    cur.execute("SELECT state, severity, category, count(*) FROM sa_work_items WHERE cloud_account_id = %s GROUP BY 1, 2, 3", (account,))
    by_state, by_sev, by_cat = {}, {}, {}
    rows = cur.fetchall()
    for st, sv, ct, n in rows:
        by_state[st] = by_state.get(st, 0) + n
        if st in E.OPEN_STATES:
            by_sev[sv] = by_sev.get(sv, 0) + n
            by_cat[ct] = by_cat.get(ct, 0) + n
    cur.execute("""SELECT
          count(*) FILTER (WHERE state = 'resolved' AND verification->>'result' = 'passed'),
          count(*) FILTER (WHERE state = 'resolved' AND verification->>'result' = 'passed' AND remediated_at IS NOT NULL),
          count(*) FILTER (WHERE remediated_at IS NOT NULL),
          count(*) FILTER (WHERE plan IS NOT NULL),
          count(*) FILTER (WHERE owner IS NOT NULL AND state = ANY(%s)),
          count(*) FILTER (WHERE state = ANY(%s)),
          count(*) FILTER (WHERE state = 'false_positive'),
          count(*),
          avg(EXTRACT(EPOCH FROM resolved_at - first_seen) / 86400) FILTER (WHERE state = 'resolved' AND verification->>'result' = 'passed'),
          count(*) FILTER (WHERE state = 'resolved' AND verification->>'result' = 'closed_by_person')
        FROM sa_work_items WHERE cloud_account_id = %s""", (list(E.OPEN_STATES), list(E.OPEN_STATES), account))
    resolved, resolved_after_fix, remediated, planned, owned, open_n, fp, total, mttr, closed_by_person = cur.fetchone()
    cur.execute("SELECT count(DISTINCT work_item_id) FROM sa_work_item_events WHERE cloud_account_id = %s AND to_state = 'reopened'", (account,))
    recurred = cur.fetchone()[0]
    cur.execute("""SELECT decision, count(*) FROM sa_actions WHERE cloud_account_id = %s AND created_at > NOW() - INTERVAL '30 days' GROUP BY 1""", (account,))
    decisions = dict(cur.fetchall())
    cur.execute("SELECT count(*) FROM sa_approvals WHERE cloud_account_id = %s AND decision = 'pending' AND expires_at > NOW()", (account,))
    pending = cur.fetchone()[0]
    cur.execute("SELECT status, severity, count(*) FROM sa_incidents WHERE cloud_account_id = %s GROUP BY 1, 2", (account,))
    incidents = {}
    for st, sv, n in cur.fetchall():
        incidents.setdefault(st, {})[sv] = n
    cur.execute("""SELECT DISTINCT ON (agent_id) agent_id, status, started_at, completed_at, limitations, coverage, summary, resource_usage
                   FROM sa_runs WHERE cloud_account_id = %s ORDER BY agent_id, started_at DESC""", (account,))
    latest = {a: {"status": s, "started_at": st, "completed_at": c, "limitations": l, "coverage_window": {k: (cv or {}).get(k) for k in ("window_start", "window_end")},
                  "summary": sm, "resource_usage": ru} for a, s, st, c, l, cv, sm, ru in cur.fetchall()}
    return {
        "agents": [{k: a[k] for k in ("agent_id", "name", "category", "category_label", "status", "last_run_at", "last_run_status",
                                      "authorized_until", "evaluation_current", "mode")} for a in agents],
        "agents_by_status": {s: sum(1 for a in agents if a["status"] == s) for s in sorted({a["status"] for a in agents})},
        "latest_runs": latest,
        "queue": {"by_state": by_state, "open_by_severity": by_sev, "open_by_category": by_cat},
        "incidents": incidents, "pending_approvals": pending,
        "actions_30d": {"allowed": decisions.get("allow", 0), "approval_required": decisions.get("approval_required", 0),
                        "blocked": decisions.get("block", 0)},
        "metrics": {
            "work_items_total": total, "open": open_n, "closed_after_investigation": closed_by_person,
            "recommended": planned, "remediation_recorded": remediated, "verified_resolved": resolved,
            "verified_after_recorded_fix": resolved_after_fix,
            "pct_remediations_verified": round(100 * resolved_after_fix / remediated) if remediated else None,
            "pct_open_with_owner": round(100 * owned / open_n) if open_n else None,
            "false_positive_rate_pct": round(100 * fp / total) if total else None,
            "recurred": recurred, "mean_days_to_verified_resolution": round(float(mttr), 1) if mttr is not None else None,
            "note": "Recommended = a plan exists; remediation recorded = your team says it changed something; verified = a later scan "
                    "no longer reports it. Only the last counts as fixed.",
        },
        "settings": _settings(cur, account),
        "boundaries": {
            "red": "Analysis only (Observe & Assess). No exploitation, scanning, credential attacks or live prompt-injection tests.",
            "blue": "CloudTrail management events in one region; gaps are reported, never read as 'no threat'. Containment is approved here and executed by your team.",
            "green": "Plans, tickets and verification re-scans. Niagaros does not change your systems; an item is resolved only when a later scan confirms it.",
            "model": "No language model makes decisions; agents are deterministic rules with versioned evaluations.",
        },
        "levels": E.LEVELS,
    }


def view_agents(cur, account):
    _seed(cur, account)
    return {"agents": _agent_rows(cur, account), "levels": E.LEVELS, "lifecycle": E.AGENT_LIFECYCLE}


def view_agent(cur, account, agent_id):
    if agent_id not in E.AGENTS:
        raise BadRequest(404, "agent not found")
    _seed(cur, account)
    a = next(x for x in _agent_rows(cur, account) if x["agent_id"] == agent_id)
    cur.execute("""SELECT id, environments, allowed_actions, prohibited_actions, valid_from, valid_until, reason, approved_by, created_at,
                          revoked_at, revoked_by FROM sa_authorizations WHERE cloud_account_id = %s AND agent_id = %s ORDER BY created_at DESC""",
                (account, agent_id))
    keys = ("id", "environments", "allowed_actions", "prohibited_actions", "valid_from", "valid_until", "reason", "approved_by", "created_at",
            "revoked_at", "revoked_by")
    a["authorizations"] = [{**dict(zip(keys, r)), "id": str(r[0])} for r in cur.fetchall()]
    cur.execute("SELECT agent_version, passed, result, run_by, created_at FROM sa_evaluations WHERE cloud_account_id = %s AND agent_id = %s ORDER BY created_at DESC LIMIT 20",
                (account, agent_id))
    a["evaluations"] = [dict(zip(("agent_version", "passed", "result", "run_by", "at"), r)) for r in cur.fetchall()]
    cur.execute("""SELECT id, status, trigger, started_at, completed_at, summary FROM sa_runs WHERE cloud_account_id = %s AND agent_id = %s
                   ORDER BY started_at DESC LIMIT 20""", (account, agent_id))
    a["runs"] = [{"id": str(i), "status": s, "trigger": t, "started_at": st, "completed_at": c, "summary": sm} for i, s, t, st, c, sm in cur.fetchall()]
    a["policies"] = _policy_matrix(cur, account, agent_id)
    return a


def _policy_matrix(cur, account, only=None):
    cur.execute("SELECT agent_id, action, environment, level, requires_approval, updated_by FROM sa_policies WHERE cloud_account_id = %s", (account,))
    set_ = {(a, ac, en): {"level": lv, "requires_approval": ra, "updated_by": ub} for a, ac, en, lv, ra, ub in cur.fetchall()}
    out = []
    for agent_id, meta in E.AGENTS.items():
        if only and agent_id != only:
            continue
        for action in meta["actions"]:
            for env in E.ENVIRONMENTS:
                p = set_.get((agent_id, action, env))
                d = E.default_policy(agent_id, action, env)
                out.append({"agent_id": agent_id, "action": action, "action_label": E.ACTIONS[action]["label"], "environment": env,
                            "needs": E.ACTIONS[action]["level"], "executable": E.ACTIONS[action]["executable"],
                            "level": (p or d)["level"], "requires_approval": (p or d)["requires_approval"], "custom": bool(p),
                            "updated_by": (p or {}).get("updated_by")})
    return out


def view_policies(cur, account):
    return {"policies": _policy_matrix(cur, account), "levels": E.LEVELS, "prohibited_techniques": E.PROHIBITED_TECHNIQUES,
            "environment": _settings(cur, account)["environment"]}


def view_runs(cur, account):
    cur.execute("""SELECT id, workflow_id, agent_id, status, trigger, initiated_by, started_at, completed_at, summary, limitations, resource_usage
                   FROM sa_runs WHERE cloud_account_id = %s ORDER BY started_at DESC LIMIT 200""", (account,))
    keys = ("id", "workflow_id", "agent_id", "status", "trigger", "initiated_by", "started_at", "completed_at", "summary", "limitations", "resource_usage")
    return {"runs": [{**dict(zip(keys, r)), "id": str(r[0]), "workflow_id": str(r[1]), "agent_name": E.AGENTS.get(r[2], {}).get("name")}
                     for r in cur.fetchall()]}


def view_run(cur, account, run_id):
    rid = _uuid(run_id, "run")
    cur.execute("""SELECT id, workflow_id, agent_id, agent_version, status, trigger, initiated_by, policy_version, scope_snapshot, started_at,
                          completed_at, resource_usage, coverage, limitations, summary, error FROM sa_runs WHERE id = %s AND cloud_account_id = %s""",
                (rid, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "run not found")
    keys = ("id", "workflow_id", "agent_id", "agent_version", "status", "trigger", "initiated_by", "policy_version", "scope_snapshot",
            "started_at", "completed_at", "resource_usage", "coverage", "limitations", "summary", "error")
    run = {**dict(zip(keys, r)), "id": str(r[0]), "workflow_id": str(r[1])}
    cur.execute("SELECT action, target, decision, reason, execution_status, created_at FROM sa_actions WHERE run_id = %s ORDER BY created_at", (rid,))
    run["actions"] = [dict(zip(("action", "target", "decision", "reason", "execution_status", "at"), x)) for x in cur.fetchall()]
    cur.execute("SELECT evidence_type, source_reference, content_hash, verification_status, collected_at FROM sa_evidence WHERE run_id = %s ORDER BY collected_at LIMIT 200", (rid,))
    run["evidence"] = [dict(zip(("type", "source", "content_hash", "status", "at"), x)) for x in cur.fetchall()]
    return run


ITEM_COLS = ("id", "agent_id", "category", "source_type", "source_id", "title", "severity", "confidence", "priority", "priority_reasons",
             "basis", "evidence", "assets", "recommendation", "attack_path", "validation", "active_threat", "state", "state_reason", "owner",
             "due_at", "accepted_until", "plan", "change_reference", "remediated_at", "remediated_by", "verification", "ticket", "first_seen",
             "last_seen", "resolved_at")


def _item_row(r):
    i = dict(zip(ITEM_COLS, r))
    i["id"] = str(i["id"])
    i["agent_name"] = E.AGENTS.get(i["agent_id"], {}).get("name")
    return i


def view_queue(cur, account, qs):
    where, args = ["cloud_account_id = %s"], [account]
    for key, col, allowed in (("category", "category", ("red", "blue", "green")), ("state", "state", E.STATES),
                              ("severity", "severity", ("critical", "high", "medium", "low", "info"))):
        v = qs.get(key)
        if v:
            if v not in allowed:
                raise BadRequest(400, f"unknown {key}")
            where.append(f"{col} = %s")
            args.append(v)
    if qs.get("open") == "1":
        where.append("state = ANY(%s)")
        args.append(list(E.OPEN_STATES))
    if qs.get("owner"):
        where.append("owner = %s")
        args.append(qs["owner"][:200])
    cur.execute(f"SELECT {', '.join(ITEM_COLS)} FROM sa_work_items WHERE {' AND '.join(where)} ORDER BY priority DESC, first_seen DESC LIMIT 1000", args)
    return {"items": [_item_row(r) for r in cur.fetchall()], "states": E.STATES}


def view_item(cur, account, item_id):
    iid = _uuid(item_id, "work item")
    cur.execute(f"SELECT {', '.join(ITEM_COLS)} FROM sa_work_items WHERE id = %s AND cloud_account_id = %s", (iid, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "work item not found")
    i = _item_row(r)
    cur.execute("SELECT from_state, to_state, actor, actor_kind, note, details, created_at FROM sa_work_item_events WHERE work_item_id = %s ORDER BY created_at",
                (iid,))
    i["history"] = [dict(zip(("from", "to", "actor", "actor_kind", "note", "details", "at"), x)) for x in cur.fetchall()]
    cur.execute("SELECT evidence_type, source_reference, content_hash, verification_status, summary, collected_at FROM sa_evidence WHERE work_item_id = %s ORDER BY collected_at DESC LIMIT 50",
                (iid,))
    i["evidence_log"] = [dict(zip(("type", "source", "content_hash", "status", "summary", "at"), x)) for x in cur.fetchall()]
    cur.execute("SELECT id, action, decision, requested_by, decided_by, reason, created_at, expires_at, execution_result FROM sa_approvals WHERE work_item_id = %s ORDER BY created_at DESC",
                (iid,))
    i["approvals"] = [{**dict(zip(("id", "action", "decision", "requested_by", "decided_by", "reason", "at", "expires_at", "execution_result"), x)),
                       "id": str(x[0])} for x in cur.fetchall()]
    cur.execute("SELECT id, summary, severity, status FROM sa_incidents WHERE cloud_account_id = %s AND related_work_items ? %s",
                (account, _fingerprint_of(cur, iid)))
    i["incidents"] = [{"id": str(a), "summary": b, "severity": c, "status": d} for a, b, c, d in cur.fetchall()]
    i["allowed_transitions"] = sorted(E.HUMAN_TRANSITIONS.get(i["state"], set()) | ({"resolved"} if i["source_type"] == "detection" and i["state"] in E.OPEN_STATES else set()))
    cur.execute("SELECT id, provider, project FROM workspace_integrations WHERE cloud_account_id = %s ORDER BY created_at", (account,))
    i["integrations"] = [{"id": str(a), "provider": b, "project": c} for a, b, c in cur.fetchall()]
    return i


def _fingerprint_of(cur, iid):
    cur.execute("SELECT fingerprint FROM sa_work_items WHERE id = %s", (iid,))
    r = cur.fetchone()
    return r[0] if r else ""


def view_detections(cur, account):
    cur.execute("""SELECT id, rule, agent_id, severity, title, mitre, principal, resources, source_ip, region, first_event_at, last_event_at,
                          event_count, event_ids, event_names, why, respond, status, status_reason, incident_id FROM sa_detections
                   WHERE cloud_account_id = %s ORDER BY first_event_at DESC LIMIT 500""", (account,))
    keys = ("id", "rule", "agent_id", "severity", "title", "mitre", "principal", "resources", "source_ip", "region", "first_event_at",
            "last_event_at", "event_count", "event_ids", "event_names", "why", "respond", "status", "status_reason", "incident_id")
    rows = [{**dict(zip(keys, r)), "id": str(r[0]), "incident_id": str(r[19]) if r[19] else None} for r in cur.fetchall()]
    cur.execute("""SELECT coverage, limitations, started_at FROM sa_runs WHERE cloud_account_id = %s AND agent_id LIKE 'blue-%%' AND agent_id <> 'blue-incident-triage'
                   ORDER BY started_at DESC LIMIT 3""", (account,))
    cov = [{"coverage": {k: c.get(k) for k in ("window_start", "window_end")} if c else {}, "limitations": l, "at": t} for c, l, t in cur.fetchall()]
    return {"detections": rows, "rules": [{k: d[k] for k in ("id", "agent", "severity", "title", "mitre", "events", "why")} for d in E.DETECTIONS],
            "recent_coverage": cov}


def view_incidents(cur, account):
    cur.execute("""SELECT id, principal, severity, summary, hypothesis, basis, resources, related_work_items, status, status_reason, owner,
                          first_event_at, last_event_at FROM sa_incidents WHERE cloud_account_id = %s ORDER BY last_event_at DESC LIMIT 300""", (account,))
    keys = ("id", "principal", "severity", "summary", "hypothesis", "basis", "resources", "related_work_items", "status", "status_reason",
            "owner", "first_event_at", "last_event_at")
    return {"incidents": [{**dict(zip(keys, r)), "id": str(r[0])} for r in cur.fetchall()]}


def view_incident(cur, account, incident_id):
    iid = _uuid(incident_id, "incident")
    inc = next((i for i in view_incidents(cur, account)["incidents"] if i["id"] == iid), None)
    if not inc:
        raise BadRequest(404, "incident not found")
    cur.execute("""SELECT id, rule, severity, title, principal, first_event_at, event_count, event_ids, why, respond, status FROM sa_detections
                   WHERE incident_id = %s AND cloud_account_id = %s ORDER BY first_event_at""", (iid, account))
    inc["detections"] = [{**dict(zip(("id", "rule", "severity", "title", "principal", "first_event_at", "event_count", "event_ids", "why",
                                      "respond", "status"), r)), "id": str(r[0])} for r in cur.fetchall()]
    fps = inc["related_work_items"] or []
    cur.execute(f"SELECT {', '.join(ITEM_COLS)} FROM sa_work_items WHERE cloud_account_id = %s AND fingerprint = ANY(%s)", (account, fps))
    inc["work_items"] = [_item_row(r) for r in cur.fetchall()]
    cur.execute("SELECT id, action, decision, requested_by, decided_by, reason, created_at FROM sa_approvals WHERE incident_id = %s ORDER BY created_at DESC", (iid,))
    inc["approvals"] = [{**dict(zip(("id", "action", "decision", "requested_by", "decided_by", "reason", "at"), x)), "id": str(x[0])} for x in cur.fetchall()]
    return inc


def view_attack_paths(cur, account):
    cur.execute(f"""SELECT {', '.join(ITEM_COLS)} FROM sa_work_items WHERE cloud_account_id = %s AND attack_path IS NOT NULL
                    AND attack_path <> 'null'::jsonb AND state = ANY(%s) ORDER BY priority DESC""", (account, list(E.OPEN_STATES)))
    return {"paths": [_item_row(r) for r in cur.fetchall()],
            "note": "Potential paths derived from configuration. None has been tested or exploited."}


def view_approvals(cur, account):
    cur.execute("""UPDATE sa_approvals SET decision = 'expired' WHERE cloud_account_id = %s AND decision = 'pending' AND expires_at <= NOW()""", (account,))
    cur.execute("""SELECT a.id, a.agent_id, a.action, a.target, a.payload, a.requested_by, a.decision, a.decided_by, a.reason, a.created_at,
                          a.expires_at, a.decided_at, a.executed_at, a.execution_result, a.work_item_id, a.incident_id, w.title, i.summary
                   FROM sa_approvals a LEFT JOIN sa_work_items w ON w.id = a.work_item_id LEFT JOIN sa_incidents i ON i.id = a.incident_id
                   WHERE a.cloud_account_id = %s ORDER BY (a.decision = 'pending') DESC, a.created_at DESC LIMIT 300""", (account,))
    keys = ("id", "agent_id", "action", "target", "payload", "requested_by", "decision", "decided_by", "reason", "created_at", "expires_at",
            "decided_at", "executed_at", "execution_result", "work_item_id", "incident_id", "work_item_title", "incident_summary")
    out = []
    for r in cur.fetchall():
        a = dict(zip(keys, r))
        a.update({"id": str(a["id"]), "work_item_id": str(a["work_item_id"]) if a["work_item_id"] else None,
                  "incident_id": str(a["incident_id"]) if a["incident_id"] else None,
                  "action_label": E.ACTIONS.get(a["action"], {}).get("label"), "executable": E.ACTIONS.get(a["action"], {}).get("executable")})
        out.append(a)
    return {"approvals": out}


def view_audit(cur, account):
    cur.execute("SELECT created_at, actor_email, action, target, details FROM sa_audit_log WHERE cloud_account_id = %s ORDER BY created_at DESC LIMIT 300", (account,))
    audit = [{"at": a, "actor": b, "action": c, "target": d, "details": e} for a, b, c, d, e in cur.fetchall()]
    cur.execute("""SELECT created_at, agent_id, action, target, decision, reason, initiated_by FROM sa_actions WHERE cloud_account_id = %s
                   AND decision <> 'allow' ORDER BY created_at DESC LIMIT 200""", (account,))
    gated = [dict(zip(("at", "agent_id", "action", "target", "decision", "reason", "initiated_by"), r)) for r in cur.fetchall()]
    return {"audit": audit, "policy_decisions": gated}


def export(cur, account, what, fmt, actor):
    queries = {
        "queue": ("SELECT category, agent_id, severity, priority, state, title, source_type, owner, first_seen, remediated_at, change_reference, resolved_at, state_reason FROM sa_work_items WHERE cloud_account_id = %s ORDER BY priority DESC",
                  ["category", "agent", "severity", "priority", "state", "title", "source", "owner", "first_seen", "remediated_at", "change_reference", "resolved_at", "state_reason"]),
        "detections": ("SELECT first_event_at, rule, severity, title, mitre, principal, source_ip, event_count, status, status_reason FROM sa_detections WHERE cloud_account_id = %s ORDER BY first_event_at DESC",
                       ["first_event_at", "rule", "severity", "title", "mitre", "principal", "source_ip", "event_count", "status", "status_reason"]),
        "incidents": ("SELECT first_event_at, last_event_at, principal, severity, summary, hypothesis, status, status_reason, owner FROM sa_incidents WHERE cloud_account_id = %s ORDER BY last_event_at DESC",
                      ["first_event_at", "last_event_at", "principal", "severity", "summary", "hypothesis", "status", "status_reason", "owner"]),
        "runs": ("SELECT started_at, completed_at, agent_id, status, trigger, initiated_by, summary, limitations FROM sa_runs WHERE cloud_account_id = %s ORDER BY started_at DESC",
                 ["started_at", "completed_at", "agent", "status", "trigger", "initiated_by", "summary", "limitations"]),
        "audit": ("SELECT created_at, actor_email, action, target, details FROM sa_audit_log WHERE cloud_account_id = %s ORDER BY created_at DESC",
                  ["at", "actor", "action", "target", "details"]),
    }
    if what not in queries:
        raise BadRequest(400, "what must be queue, detections, incidents, runs or audit")
    if fmt not in ("csv", "json"):
        raise BadRequest(400, "format must be csv or json")
    sql, cols = queries[what]
    cur.execute(sql, (account,))
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
                                       "Content-Disposition": f'attachment; filename="niagaros-security-agents-{what}.csv"'})


# ── agent lifecycle ─────────────────────────────────────────────────────────

def _status(cur, account, agent_id):
    _seed(cur, account)
    cur.execute("SELECT status FROM sa_agents WHERE cloud_account_id = %s AND agent_id = %s FOR UPDATE", (account, agent_id))
    return cur.fetchone()[0]


def configure_agent(cur, account, body, actor):
    agent_id = _agent(body)
    owner = _text(body, "owner", 200, required=True)
    purpose = _text(body, "business_purpose", 1000)
    st = _status(cur, account, agent_id)
    if st == "retired":
        raise BadRequest(409, "This agent is retired.")
    new = "configured" if st == "registered" else st
    cur.execute("UPDATE sa_agents SET owner = %s, business_purpose = %s, status = %s, updated_at = NOW() WHERE cloud_account_id = %s AND agent_id = %s",
                (owner, purpose, new, account, agent_id))
    _audit(cur, account, actor, "agent_configured", agent_id, {"owner": owner, "purpose": purpose, "from": st, "to": new})
    return {"agent_id": agent_id, "status": new}


def authorize_agent(cur, account, body, actor):
    agent_id = _agent(body)
    envs = body.get("environments") or []
    if not isinstance(envs, list) or not envs or any(e not in E.ENVIRONMENTS for e in envs):
        raise BadRequest(400, f"environments must be a non-empty list of: {', '.join(E.ENVIRONMENTS)}")
    days = body.get("valid_days", 90)
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 365:
        raise BadRequest(400, "valid_days must be between 1 and 365.")
    allowed = body.get("allowed_actions") or []
    prohibited = body.get("prohibited_actions") or []
    agent_actions = E.AGENTS[agent_id]["actions"]
    if not isinstance(allowed, list) or any(a not in agent_actions for a in allowed):
        raise BadRequest(400, "allowed_actions must be actions this agent has.")
    if not isinstance(prohibited, list) or any(a not in agent_actions for a in prohibited):
        raise BadRequest(400, "prohibited_actions must be actions this agent has.")
    reason = _text(body, "reason", 1000, required=True, label="A reason")
    cur.execute("""INSERT INTO sa_authorizations (cloud_account_id, agent_id, scope_type, scope_reference, environments, allowed_actions,
                                                  prohibited_actions, valid_until, reason, approved_by)
                   VALUES (%s, %s, 'account', %s, %s, %s, %s, NOW() + make_interval(days => %s), %s, %s) RETURNING id, valid_until""",
                (account, agent_id, account, J(sorted(set(envs))), J(sorted(set(allowed))), J(sorted(set(prohibited))), days, reason, actor))
    aid, until = cur.fetchone()
    _audit(cur, account, actor, "authorization_granted", agent_id, {"authorization_id": str(aid), "environments": envs, "valid_until": until,
                                                                     "allowed": allowed, "prohibited": prohibited, "reason": reason})
    return {"authorization_id": str(aid), "valid_until": until}


def revoke_authorization(cur, account, body, actor):
    aid = _uuid(body.get("authorization_id"), "authorization")
    cur.execute("""UPDATE sa_authorizations SET revoked_at = NOW(), revoked_by = %s WHERE id = %s AND cloud_account_id = %s AND revoked_at IS NULL
                   RETURNING agent_id""", (actor, aid, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "authorization not found or already revoked")
    _audit(cur, account, actor, "authorization_revoked", r[0], {"authorization_id": aid})
    return {"revoked": True, "note": "Takes effect immediately: the next action of this agent is checked again."}


def set_policy(cur, account, body, actor):
    agent_id = _agent(body)
    action = body.get("policy_action")      # 'action' is the API dispatch key
    if action not in E.AGENTS[agent_id]["actions"]:
        raise BadRequest(400, "This agent does not have that action.")
    env = body.get("environment")
    if env not in E.ENVIRONMENTS:
        raise BadRequest(400, "unknown environment")
    level = body.get("level")
    if level not in E.LEVELS:
        raise BadRequest(400, "level must be L0..L5")
    requires = body.get("requires_approval")
    if not isinstance(requires, bool):
        raise BadRequest(400, "requires_approval must be true or false")
    if level == "L5":
        raise BadRequest(400, "L5 (emergency execution) is not available: Niagaros has no emergency actions in customer accounts.")
    if E.ACTIONS[action]["level"] == "L3" and not requires:
        raise BadRequest(400, "Actions that change your systems always need approval.")
    cur.execute("""INSERT INTO sa_policies (cloud_account_id, agent_id, action, environment, level, requires_approval, updated_by, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                   ON CONFLICT (cloud_account_id, agent_id, action, environment) DO UPDATE SET level = EXCLUDED.level,
                       requires_approval = EXCLUDED.requires_approval, updated_by = EXCLUDED.updated_by, updated_at = NOW()""",
                (account, agent_id, action, env, level, requires, actor))
    _audit(cur, account, actor, "policy_changed", agent_id, {"action": action, "environment": env, "level": level, "requires_approval": requires})
    return {"saved": True}


def run_evaluation(cur, account, body, actor):
    agent_id = _agent(body)
    res = E.evaluate(agent_id)
    cur.execute("INSERT INTO sa_evaluations (cloud_account_id, agent_id, agent_version, passed, result, run_by) VALUES (%s, %s, %s, %s, %s, %s)",
                (account, agent_id, E.ENGINE_VERSION, res["passed"], J(res), actor))
    st = _status(cur, account, agent_id)
    if res["passed"] and st == "configured":
        cur.execute("UPDATE sa_agents SET status = 'tested', updated_at = NOW() WHERE cloud_account_id = %s AND agent_id = %s", (account, agent_id))
        st = "tested"
    _audit(cur, account, actor, "agent_evaluated", agent_id, {"passed": res["passed"], "precision": res["precision"], "recall": res["recall"]})
    return {"evaluation": res, "status": st}


def approve_agent(cur, account, body, actor):
    agent_id = _agent(body)
    st = _status(cur, account, agent_id)
    agent = next(a for a in _agent_rows(cur, account) if a["agent_id"] == agent_id)
    missing = []
    if not agent["owner"]:
        missing.append("an owner")
    if not agent["authorized_until"]:
        missing.append("a valid authorisation for this account")
    if not agent["evaluation_current"]:
        missing.append("a passed evaluation of the current version")
    if missing:
        raise BadRequest(409, "Before activation the agent needs " + ", ".join(missing) + ".")
    if st not in ("tested", "approved", "paused", "restricted", "configured"):
        raise BadRequest(409, f"An agent that is {st} cannot be activated.")
    cur.execute("""UPDATE sa_agents SET status = 'active', approved_by = %s, approved_at = NOW(), agent_version = %s, updated_at = NOW()
                   WHERE cloud_account_id = %s AND agent_id = %s""", (actor, E.ENGINE_VERSION, account, agent_id))
    _audit(cur, account, actor, "agent_approved", agent_id, {"from": st, "to": "active", "version": E.ENGINE_VERSION})
    return {"agent_id": agent_id, "status": "active"}


def set_agent_status(cur, account, body, actor):
    agent_id = _agent(body)
    new = body.get("status")
    if new not in ("paused", "restricted", "deprecated", "retired"):
        raise BadRequest(400, "status must be paused, restricted, deprecated or retired (use approve_agent to activate)")
    st = _status(cur, account, agent_id)
    if st == "retired":
        raise BadRequest(409, "This agent is retired.")
    reason = _text(body, "reason", 500, required=True, label="A reason")
    cur.execute("UPDATE sa_agents SET status = %s, updated_at = NOW() WHERE cloud_account_id = %s AND agent_id = %s", (new, account, agent_id))
    _audit(cur, account, actor, "agent_status", agent_id, {"from": st, "to": new, "reason": reason})
    return {"agent_id": agent_id, "status": new}


def activate_recommended(cur, account, body, actor):
    """One click for the standard setup, each step recorded as if done by hand: owner = you, authorisation for this
    account and environment for 90 days, evaluation, activation."""
    env = _settings(cur, account)["environment"]
    done = []
    for agent_id in E.AGENTS:
        st = _status(cur, account, agent_id)
        if st in ("active", "retired", "deprecated"):
            continue
        configure_agent(cur, account, {"agent_id": agent_id, "owner": actor, "business_purpose": E.AGENTS[agent_id]["specialization"]}, actor)
        authorize_agent(cur, account, {"agent_id": agent_id, "environments": [env], "valid_days": 90,
                                        "reason": "Recommended setup (read-only analysis for this account)"}, actor)
        res = run_evaluation(cur, account, {"agent_id": agent_id}, actor)
        if res["evaluation"]["passed"]:
            approve_agent(cur, account, {"agent_id": agent_id}, actor)
            done.append(agent_id)
    return {"activated": done, "environment": env, "authorization_days": 90}


def run_agents(cur, account, body, actor):
    cur.execute("""SELECT 1 FROM sa_audit_log WHERE cloud_account_id = %s AND action = 'agents_run_requested' AND created_at > NOW() - INTERVAL '5 minutes'""",
                (account,))
    if cur.fetchone():
        raise BadRequest(429, "Agents were started less than 5 minutes ago. Please wait a moment.")
    cur.execute("SELECT count(*) FROM sa_agents WHERE cloud_account_id = %s AND status = 'active'", (account,))
    if not cur.fetchone()[0]:
        raise BadRequest(409, "No agent is active yet. Activate agents under Agent registry first.")
    only = body.get("agents")
    if only is not None and (not isinstance(only, list) or any(a not in E.AGENTS for a in only)):
        raise BadRequest(400, "agents must be a list of agent ids")
    boto3.client("lambda", region_name=REGION).invoke(FunctionName=RUNNER_FUNCTION, InvocationType="Event", Payload=json.dumps(
        {"cloud_account_id": account, "trigger": "manual", "initiated_by": actor, "agents": only, "_async": True}).encode())
    _audit(cur, account, actor, "agents_run_requested", None, {"agents": only or "all active"})
    return {"started": True, "note": "The agents run in the background; refresh in a minute."}


def request_technique(cur, account, body, actor):
    """Records an attempt to use an offensive technique; always blocked (scope enforcement is auditable)."""
    agent_id = _agent(body)
    technique = body.get("technique")
    d = _decide(cur, account, agent_id, "analyze", actor, target=body.get("target"), technique=technique or "unknown")
    _audit(cur, account, actor, "technique_blocked", agent_id, {"technique": technique, "reason": d["reason"]})
    return {"decision": d["decision"], "reason": d["reason"]}


# ── work items ──────────────────────────────────────────────────────────────

def _lock_item(cur, account, body):
    iid = _uuid(body.get("work_item_id"), "work item")
    cur.execute("SELECT state, source_type, title, recommendation, severity, ticket, owner FROM sa_work_items WHERE id = %s AND cloud_account_id = %s FOR UPDATE",
                (iid, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "work item not found")
    return iid, dict(zip(("state", "source_type", "title", "recommendation", "severity", "ticket", "owner"), r))


def transition_item(cur, account, body, actor):
    iid, it = _lock_item(cur, account, body)
    new = body.get("to")
    reason = _text(body, "reason", 1000)
    if new == "resolved" and it["source_type"] == "detection" and it["state"] in E.OPEN_STATES:
        if not reason:
            raise BadRequest(400, "Say how it was investigated and closed.")
    elif not E.can_transition(it["state"], new, "human"):
        if new in ("resolved", "reopened"):
            raise BadRequest(409, "Only the Verification Agent resolves or re-opens items, based on a later scan.")
        raise BadRequest(409, f"Cannot move from {it['state']} to {new}.")
    until = None
    if new in ("accepted_risk", "false_positive", "blocked") and not reason:
        raise BadRequest(400, "A reason is required.")
    if new == "accepted_risk":
        if not body.get("accepted_until"):
            raise BadRequest(400, "An accepted risk needs an end date (YYYY-MM-DD).")
        until = _date(body["accepted_until"], "The end date", 366)
    cur.execute("""UPDATE sa_work_items SET state = %s, state_reason = %s, accepted_until = %s,
                          resolved_at = CASE WHEN %s = 'resolved' THEN NOW() ELSE resolved_at END,
                          verification = CASE WHEN %s = 'resolved' THEN %s ELSE verification END WHERE id = %s""",
                (new, reason, until, new, new, J({"result": "closed_by_person", "reason": reason, "by": actor,
                                                  "note": "Closed after investigation by a person; no scan covers detections."}), iid))
    _event(cur, account, iid, it["state"], new, actor, reason, {"accepted_until": until})
    _audit(cur, account, actor, "item_transition", iid, {"from": it["state"], "to": new, "reason": reason})
    return {"work_item_id": iid, "state": new}


def assign_item(cur, account, body, actor):
    iid, it = _lock_item(cur, account, body)
    owner = _text(body, "owner", 200, required=True)
    due = _date(body["due_at"], "The due date", 366) if body.get("due_at") else None
    new = "assigned" if it["state"] in ("new", "triaged", "reopened") else it["state"]
    cur.execute("UPDATE sa_work_items SET owner = %s, due_at = %s, state = %s WHERE id = %s", (owner, due, new, iid))
    _event(cur, account, iid, it["state"], new, actor, f"Assigned to {owner}", {"due_at": due})
    _audit(cur, account, actor, "item_assigned", iid, {"owner": owner, "due_at": due})
    return {"work_item_id": iid, "state": new}


def record_remediation(cur, account, body, actor):
    iid, it = _lock_item(cur, account, body)
    ref = _text(body, "change_reference", 500, required=True, label="A change reference (PR, ticket or change ID)")
    note = _text(body, "note", 1000)
    if it["source_type"] == "detection":
        raise BadRequest(409, "Detections are closed after investigation, not remediated.")
    if it["state"] not in ("assigned", "in_progress", "triaged", "new", "reopened"):
        raise BadRequest(409, f"A remediation cannot be recorded while the item is {it['state']}.")
    cur.execute("UPDATE sa_work_items SET state = 'remediated', change_reference = %s, remediated_at = NOW(), remediated_by = %s, state_reason = %s WHERE id = %s",
                (ref, actor, note, iid))
    _event(cur, account, iid, it["state"], "remediated", actor, note, {"change_reference": ref})
    _audit(cur, account, actor, "remediation_recorded", iid, {"change_reference": ref})
    return {"work_item_id": iid, "state": "remediated",
            "note": "Not resolved yet: the Verification Agent closes it once a scan that runs after now no longer reports the problem."}


def create_ticket(cur, account, body, actor):
    from collectors.aws.scanner.integrations_handler import _client_for, _load
    iid, it = _lock_item(cur, account, body)
    if it["ticket"]:
        raise BadRequest(409, "A ticket already exists for this work item.")
    integ = _load(cur, _uuid(body.get("integration_id"), "integration"))
    if not integ or integ["cloud_account_id"] != account:
        raise BadRequest(404, "integration not found")
    if not integ["project"]:
        raise BadRequest(400, "Select a project for this integration first (Integrations page).")
    d = _decide(cur, account, "green-remediation-planner", "create_ticket", actor, target=iid)
    if d["decision"] == "block":
        raise BadRequest(403, f"Blocked by policy: {d['reason']}")
    if d["decision"] == "approval_required":
        apr = _request_approval(cur, account, "green-remediation-planner", "create_ticket", actor, work_item_id=iid,
                                payload={"integration_id": integ["id"]}, action_id=d["action_id"])
        return {"approval_required": True, "approval_id": apr}
    t = _do_ticket(cur, account, iid, it, integ, actor)
    cur.execute("UPDATE sa_actions SET execution_status = 'succeeded' WHERE id = %s", (d["action_id"],))
    return {"ticket": t}


def _do_ticket(cur, account, iid, it, integ, actor):
    from collectors.aws.scanner.integrations_handler import _client_for
    rec = it["recommendation"] or {}
    desc = (f"Niagaros Security Agents work item ({it['severity']}): {it['title']}\n\nNow: {rec.get('current', '')}\n"
            f"Change: {rec.get('proposed', '')}\nWhy: {rec.get('reason', '')}\nRollback: {rec.get('rollback', '')}\n\n"
            "Close condition: a Niagaros scan after the change no longer reports this.")
    t = _client_for(integ).create_ticket(integ["project"], f"[Niagaros] {it['title']}"[:250], desc, it["severity"])
    ticket = {"provider": integ["provider"], "integration_id": integ["id"], **t, "status": "created", "created_by": actor}
    cur.execute("UPDATE sa_work_items SET ticket = %s, state = CASE WHEN state IN ('new', 'triaged', 'assigned') THEN 'in_progress' ELSE state END WHERE id = %s",
                (Json(ticket), iid))
    _event(cur, account, iid, it["state"], "in_progress" if it["state"] in ("new", "triaged", "assigned") else it["state"], actor,
           f"Ticket {t.get('key')} created", {"ticket": t.get("key")})
    _audit(cur, account, actor, "ticket_created", iid, {"provider": integ["provider"], "key": t.get("key")})
    return ticket


def refresh_ticket(cur, account, body, actor):
    from collectors.aws.scanner.integrations_handler import _client_for, _load
    iid, it = _lock_item(cur, account, body)
    t = it["ticket"]
    if not t:
        raise BadRequest(404, "no ticket for this work item")
    integ = _load(cur, t["integration_id"])
    if not integ or integ["cloud_account_id"] != account:
        raise BadRequest(409, "The integration for this ticket no longer exists.")
    st = _client_for(integ).status(t)
    t.update({"status": st.get("name"), "done": st.get("done"), "checked_at": datetime.now(timezone.utc).isoformat()})
    cur.execute("UPDATE sa_work_items SET ticket = %s WHERE id = %s", (Json(t), iid))
    return {"ticket": t, "note": "A closed ticket does not resolve the work item; a later scan does."}


def _request_approval(cur, account, agent_id, action, actor, work_item_id=None, incident_id=None, payload=None, target=None, action_id=None):
    cur.execute("""INSERT INTO sa_approvals (cloud_account_id, agent_id, action, work_item_id, incident_id, target, payload, requested_by, expires_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW() + INTERVAL '7 days') RETURNING id""",
                (account, agent_id, action, work_item_id, incident_id, target, J(payload or {}), actor))
    aid = str(cur.fetchone()[0])
    if action_id:
        cur.execute("UPDATE sa_actions SET approval_id = %s WHERE id = %s", (aid, action_id))
    if work_item_id:
        cur.execute("SELECT state FROM sa_work_items WHERE id = %s", (work_item_id,))
        st = cur.fetchone()[0]
        if st in ("in_progress", "assigned", "triaged", "new", "reopened"):
            cur.execute("UPDATE sa_work_items SET state = 'awaiting_approval' WHERE id = %s", (work_item_id,))
            _event(cur, account, work_item_id, st, "awaiting_approval", actor, f"Approval requested: {E.ACTIONS[action]['label']}")
    _audit(cur, account, actor, "approval_requested", aid, {"action": action, "work_item_id": work_item_id, "incident_id": incident_id})
    return aid


def request_containment(cur, account, body, actor):
    plan = _text(body, "plan", 2000, required=True, label="The containment step")
    rollback = _text(body, "rollback", 1000, required=True, label="A rollback or recovery step")
    agent_id = body.get("agent_id") or "blue-identity-defense"
    if agent_id not in ("blue-identity-defense", "blue-cloud-threat"):
        raise BadRequest(400, "Containment is requested through the Identity Defense or Cloud Threat agent.")
    wid = _uuid(body["work_item_id"], "work item") if body.get("work_item_id") else None
    inc = _uuid(body["incident_id"], "incident") if body.get("incident_id") else None
    if not wid and not inc:
        raise BadRequest(400, "Link the containment to a work item or an incident.")
    if wid:
        cur.execute("SELECT 1 FROM sa_work_items WHERE id = %s AND cloud_account_id = %s", (wid, account))
        if not cur.fetchone():
            raise BadRequest(404, "work item not found")
    if inc:
        cur.execute("SELECT 1 FROM sa_incidents WHERE id = %s AND cloud_account_id = %s", (inc, account))
        if not cur.fetchone():
            raise BadRequest(404, "incident not found")
    d = _decide(cur, account, agent_id, "containment", actor, target=wid or inc)
    if d["decision"] == "block":
        raise BadRequest(403, f"Blocked by policy: {d['reason']}")
    aid = _request_approval(cur, account, agent_id, "containment", actor, work_item_id=wid, incident_id=inc,
                            payload={"plan": plan, "rollback": rollback}, action_id=d["action_id"])
    return {"approval_id": aid, "note": "Needs approval. After approval your team executes it; Niagaros has no write access to your account."}


def _writers(cur, account):
    """People with write rights on the account: the owner and org/business-unit admins."""
    cur.execute("""SELECT lower(c.owner_email) FROM cloud_accounts c WHERE c.id = %s
                   UNION SELECT lower(o.owner_email) FROM bu_accounts ba JOIN business_units b ON b.id = ba.business_unit_id
                         JOIN organizations o ON o.id = b.organization_id WHERE ba.cloud_account_id = %s
                   UNION SELECT lower(m.email) FROM bu_accounts ba JOIN business_units b ON b.id = ba.business_unit_id
                         JOIN org_members m ON m.organization_id = b.organization_id
                         WHERE ba.cloud_account_id = %s AND m.role IN ('org_admin', 'bu_admin')
                           AND (m.business_unit_id IS NULL OR m.business_unit_id = b.id)""", (account, account, account))
    return {r[0] for r in cur.fetchall() if r[0]}


def decide_approval(cur, account, body, actor):
    aid = _uuid(body.get("approval_id"), "approval")
    decision = body.get("decision")
    if decision not in ("approved", "rejected"):
        raise BadRequest(400, "decision must be approved or rejected")
    reason = _text(body, "reason", 1000, required=True, label="A reason")
    cur.execute("""SELECT agent_id, action, work_item_id, incident_id, payload, requested_by, decision, expires_at FROM sa_approvals
                   WHERE id = %s AND cloud_account_id = %s FOR UPDATE""", (aid, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "approval not found")
    agent_id, action, wid, inc, payload, requested_by, current, expires = r
    if current != "pending":
        raise BadRequest(409, f"This request is already {current}.")
    if expires <= datetime.now(timezone.utc):
        cur.execute("UPDATE sa_approvals SET decision = 'expired' WHERE id = %s", (aid,))
        raise BadRequest(409, "This request has expired.")
    # separation of duties: a person does not approve their own request when someone else could
    self_approval = (requested_by or "").lower() == (actor or "").lower()
    if self_approval and len(_writers(cur, account) - {(actor or "").lower()}) > 0:
        raise BadRequest(403, "You requested this; another administrator of this account has to decide.")
    result = None
    if decision == "approved":
        if action == "create_ticket":
            from collectors.aws.scanner.integrations_handler import _load
            d = _decide(cur, account, agent_id, action, actor, target=str(wid))   # re-checked at execution time
            if d["decision"] == "block":
                raise BadRequest(403, f"Blocked by policy at execution time: {d['reason']}")
            integ = _load(cur, payload.get("integration_id"))
            if not integ or integ["cloud_account_id"] != account:
                raise BadRequest(409, "The integration no longer exists.")
            iid, it = _lock_item(cur, account, {"work_item_id": str(wid)})
            if it["ticket"]:
                raise BadRequest(409, "A ticket was already created for this work item; reject this request instead.")
            t = _do_ticket(cur, account, iid, it, integ, actor)
            cur.execute("UPDATE sa_actions SET execution_status = 'succeeded' WHERE id = %s", (d["action_id"],))
            result = {"executed": True, "ticket": t.get("key")}
        elif action == "request_rescan":
            d = _decide(cur, account, agent_id, action, actor, target=body.get("target"))
            if d["decision"] == "block":
                raise BadRequest(403, f"Blocked by policy at execution time: {d['reason']}")
            cur.execute("SELECT target FROM sa_approvals WHERE id = %s", (aid,))
            fn = cur.fetchone()[0]
            from collectors.aws.scanner.security_agents_runner_handler import RESCAN_FUNCTIONS
            if fn not in RESCAN_FUNCTIONS.values():   # the same configured names the runner requests
                raise BadRequest(409, "Unknown scanner.")
            boto3.client("lambda", region_name=REGION).invoke(FunctionName=fn, InvocationType="Event", Payload=json.dumps(
                {"cloud_account_id": account, "trigger": "manual", "_async": True}).encode())
            cur.execute("UPDATE sa_actions SET execution_status = 'succeeded' WHERE id = %s", (d["action_id"],))
            result = {"executed": True, "scanner": fn}
        else:
            result = {"executed": False, "note": "Approved. Your team carries it out in your AWS account with its own access; Niagaros cannot. "
                                                 "Record the change on the work item; a later scan verifies it."}
    cur.execute("""UPDATE sa_approvals SET decision = %s, decided_by = %s, reason = %s, decided_at = NOW(),
                          executed_at = CASE WHEN %s THEN NOW() ELSE NULL END, execution_result = %s WHERE id = %s""",
                (decision, actor, reason, bool(result and result.get("executed")), J(result or {}), aid))
    if wid:
        cur.execute("SELECT state FROM sa_work_items WHERE id = %s", (wid,))
        st = cur.fetchone()[0]
        if st == "awaiting_approval":
            cur.execute("UPDATE sa_work_items SET state = 'in_progress' WHERE id = %s", (wid,))
            _event(cur, account, wid, st, "in_progress", actor, f"Approval {decision}: {reason}")
    _audit(cur, account, actor, "approval_decided", aid, {"decision": decision, "reason": reason, "action": action,
                                                         "self_approved_single_admin": self_approval, "result": result})
    return {"approval_id": aid, "decision": decision, "result": result}


def update_incident(cur, account, body, actor):
    iid = _uuid(body.get("incident_id"), "incident")
    status = body.get("status")
    if status not in ("open", "investigating", "contained", "closed"):
        raise BadRequest(400, "status must be open, investigating, contained or closed")
    reason = _text(body, "reason", 1000)
    if status in ("closed", "contained") and not reason:
        raise BadRequest(400, "Say what was found or done.")
    owner = _text(body, "owner", 200)
    cur.execute("UPDATE sa_incidents SET status = %s, status_reason = %s, owner = COALESCE(%s, owner) WHERE id = %s AND cloud_account_id = %s RETURNING id",
                (status, reason, owner, iid, account))
    if not cur.fetchone():
        raise BadRequest(404, "incident not found")
    _audit(cur, account, actor, "incident_updated", iid, {"status": status, "reason": reason, "owner": owner})
    return {"incident_id": iid, "status": status}


def update_detection(cur, account, body, actor):
    did = _uuid(body.get("detection_id"), "detection")
    status = body.get("status")
    if status not in ("open", "acknowledged", "benign", "escalated"):
        raise BadRequest(400, "status must be open, acknowledged, benign or escalated")
    reason = _text(body, "reason", 1000)
    if status == "benign" and not reason:
        raise BadRequest(400, "Say why it is benign.")
    cur.execute("UPDATE sa_detections SET status = %s, status_reason = %s, status_by = %s WHERE id = %s AND cloud_account_id = %s RETURNING id",
                (status, reason, actor, did, account))
    if not cur.fetchone():
        raise BadRequest(404, "detection not found")
    _audit(cur, account, actor, "detection_updated", did, {"status": status, "reason": reason})
    return {"detection_id": did, "status": status}


def save_settings(cur, account, body, actor):
    env = body.get("environment")
    if env not in E.ENVIRONMENTS:
        raise BadRequest(400, "unknown environment")
    hours = body.get("lookback_hours", 24)
    if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= 2160:
        raise BadRequest(400, "lookback_hours must be between 1 and 2160 (90 days, the CloudTrail event history limit).")
    before = _settings(cur, account)
    cur.execute("""INSERT INTO sa_settings (cloud_account_id, environment, lookback_hours, updated_by, updated_at) VALUES (%s, %s, %s, %s, NOW())
                   ON CONFLICT (cloud_account_id) DO UPDATE SET environment = EXCLUDED.environment, lookback_hours = EXCLUDED.lookback_hours,
                       updated_by = EXCLUDED.updated_by, updated_at = NOW()""", (account, env, hours, actor))
    _audit(cur, account, actor, "settings", None, {"previous": {k: before[k] for k in ("environment", "lookback_hours")},
                                                    "new": {"environment": env, "lookback_hours": hours}})
    note = "Applies from the next run."
    if env != before["environment"]:
        note += " Authorisations are per environment: agents authorised only for the old one will be blocked until re-authorised."
    return {"saved": True, "note": note}


ACTIONS = {"configure_agent": configure_agent, "authorize_agent": authorize_agent, "revoke_authorization": revoke_authorization,
           "set_policy": set_policy, "run_evaluation": run_evaluation, "approve_agent": approve_agent, "set_agent_status": set_agent_status,
           "activate_recommended": activate_recommended, "run_agents": run_agents, "transition_item": transition_item,
           "assign_item": assign_item, "record_remediation": record_remediation, "create_ticket": create_ticket,
           "refresh_ticket": refresh_ticket, "request_containment": request_containment, "decide_approval": decide_approval,
           "update_incident": update_incident, "update_detection": update_detection, "save_settings": save_settings,
           "request_technique": request_technique}
VIEWS = {"overview": view_overview, "agents": view_agents, "runs": view_runs, "detections": view_detections, "incidents": view_incidents,
         "attack_paths": view_attack_paths, "approvals": view_approvals, "policies": view_policies,
         "settings": lambda cur, a: _settings(cur, a), "audit": view_audit}
ID_VIEWS = {"agent": ("agent_id", view_agent), "run": ("run_id", view_run), "item": ("work_item_id", view_item),
            "incident": ("incident_id", view_incident)}


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
            cur.execute("""UPDATE sa_work_items SET state = 'reopened', state_reason = 'Risk acceptance expired'
                           WHERE cloud_account_id = %s AND state = 'accepted_risk' AND accepted_until < CURRENT_DATE RETURNING id""", (account,))
            for (iid,) in cur.fetchall():
                cur.execute("""INSERT INTO sa_work_item_events (cloud_account_id, work_item_id, from_state, to_state, actor, actor_kind, note)
                               VALUES (%s, %s, 'accepted_risk', 'reopened', 'green-verification', 'agent', 'Risk acceptance expired')""", (account, iid))
            conn.commit()
            if method == "GET":
                view = qs.get("view", "overview")
                if view in ID_VIEWS:
                    key, fn = ID_VIEWS[view]
                    r = _resp(200, fn(cur, account, qs.get(key)))
                    conn.commit()
                    return r
                if view == "queue":
                    return _resp(200, view_queue(cur, account, qs))
                if view == "export":
                    r = export(cur, account, qs.get("what"), qs.get("format", "csv"), actor)
                    conn.commit()
                    return r
                if view not in VIEWS:
                    return _resp(400, {"error": "unknown view"})
                r = _resp(200, VIEWS[view](cur, account))
                conn.commit()
                return r
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
        _persist_denials(conn)
        return _resp(e.status, {"error": e.message})
    finally:
        _DENIALS.clear()


def _persist_denials(conn):
    if not _DENIALS:
        return
    with conn.cursor() as cur:
        for account, agent_id, action, target, env, reason, actor in _DENIALS:
            cur.execute("""INSERT INTO sa_actions (cloud_account_id, agent_id, action, target, environment, decision, reason, execution_status, initiated_by)
                           VALUES (%s, %s, %s, %s, %s, 'block', %s, 'skipped', %s)""", (account, agent_id, action, target, env, reason, actor))
    conn.commit()


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
    except Exception as e:  # noqa: BLE001
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        logger.error("security_agents_handler error: %s", e, exc_info=True)
        if type(e).__name__ == "ProviderError":
            return _resp(502, {"error": "The ticket system did not accept the request. Check the connection and project on the Integrations page."})
        return _resp(500, {"error": "Something went wrong on our side. Please try again."})
    finally:
        conn.close()


lambda_handler = handler
