"""
security_agents_runner_handler.py — runs the Red, Blue and Green security agents for one cloud account (issue #239).
Invoked by the orchestrator in wave 1 like every scanner ({"cloud_account_id", "role_arn", "external_id", "region"})
or by the API ("run now"); hands itself off to an async invocation so the caller is not held up.

One invocation = one workflow: every active agent gets its own run row, and every action it wants to take is
checked against the authorisation and autonomy policy at that moment (sa_actions records allow, approval_required
and block decisions alike). Agents that are not active, or have no valid authorisation, do not run.

Order: Red (publish weaknesses) -> Blue (CloudTrail detections) -> Incident Triage (correlate) -> Green planning
-> Verification (close only what a later scan no longer reports; re-open what comes back).
"""
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import boto3
import psycopg2
from botocore.config import Config
from psycopg2.extras import Json

from collectors.aws.scanner import security_agents_engine as E

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
REGION = os.environ.get("SECRET_REGION", "eu-west-1")
J = lambda o: Json(o, dumps=lambda x: json.dumps(x, default=str))
RETRY = Config(retries={"max_attempts": 6, "mode": "adaptive"})
MAX_PAGES_PER_EVENT = 10
RESCAN_FUNCTIONS = {"ciem_finding": os.environ.get("CIEM_SCANNER_FUNCTION", "ciem-scanner"),
                    "ai_inventory_finding": os.environ.get("AI_INVENTORY_SCANNER_FUNCTION", "ai-inventory-scanner")}
# Mapped-framework findings are duplicates of the native ones (see config/database.py); only native findings count.
try:
    from config.database import MAPPED_FRAMEWORK_NAMES
except Exception:  # noqa: BLE001 - packaging without config/ must not silently include duplicates
    MAPPED_FRAMEWORK_NAMES = None


def _get_connection():
    s = json.loads(boto3.client("secretsmanager", region_name=REGION).get_secret_value(
        SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"],
                            password=s["password"], sslmode="require", connect_timeout=10)


def _assume(role_arn, external_id, region):
    c = boto3.client("sts", region_name=REGION).assume_role(
        RoleArn=role_arn, ExternalId=external_id, RoleSessionName="niagaros-security-agents", DurationSeconds=3600)["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                         aws_session_token=c["SessionToken"], region_name=region)


def _hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


# ── context ────────────────────────────────────────────────────────────────

def load_context(cur, account_id):
    cur.execute("SELECT environment, lookback_hours FROM sa_settings WHERE cloud_account_id = %s", (account_id,))
    r = cur.fetchone()
    env, lookback = (r[0], r[1]) if r else ("production", 24)
    for agent_id in E.AGENTS:
        cur.execute("""INSERT INTO sa_agents (cloud_account_id, agent_id, agent_version) VALUES (%s, %s, %s)
                       ON CONFLICT (cloud_account_id, agent_id) DO NOTHING""", (account_id, agent_id, E.ENGINE_VERSION))
    cur.execute("SELECT agent_id, status FROM sa_agents WHERE cloud_account_id = %s", (account_id,))
    states = dict(cur.fetchall())
    cur.execute("""SELECT agent_id, scope_type, scope_reference, environments, allowed_actions, prohibited_actions, valid_from,
                          valid_until, revoked_at FROM sa_authorizations WHERE cloud_account_id = %s AND revoked_at IS NULL""", (account_id,))
    keys = ("agent_id", "scope_type", "scope_reference", "environments", "allowed_actions", "prohibited_actions", "valid_from",
            "valid_until", "revoked_at")
    auths = [dict(zip(keys, row)) for row in cur.fetchall()]
    cur.execute("SELECT agent_id, action, environment, level, requires_approval FROM sa_policies WHERE cloud_account_id = %s", (account_id,))
    policies = {(a, ac, en): {"level": lv, "requires_approval": ra} for a, ac, en, lv, ra in cur.fetchall()}
    return {"environment": env, "lookback_hours": lookback, "states": states, "auths": auths, "policies": policies}


class Workflow:
    """Bookkeeping for one invocation: runs, action decisions, evidence."""

    def __init__(self, conn, account_id, ctx, trigger, initiated_by):
        self.conn, self.account, self.ctx, self.trigger, self.initiated_by = conn, account_id, ctx, trigger, initiated_by
        self.workflow_id = str(uuid.uuid4())
        self.blocked, self.notifications = [], []

    def check(self, cur, run_id, agent_id, action, target=None, technique=None):
        self.ctx = load_context(cur, self.account)   # revocations, pauses and policy changes apply mid-workflow
        d = E.authorize(agent_id, self.ctx["states"].get(agent_id, "registered"), action, self.account, self.ctx["environment"],
                        self.ctx["auths"], self.ctx["policies"], technique=technique)
        cur.execute("""INSERT INTO sa_actions (cloud_account_id, run_id, agent_id, action, target, environment, decision, reason,
                                               execution_status, initiated_by)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                    (self.account, run_id, agent_id, action, (target or "")[:500] or None, self.ctx["environment"], d["decision"],
                     d["reason"], "not_started" if d["decision"] == "allow" else ("waiting" if d["decision"] == "approval_required" else "skipped"),
                     self.initiated_by or "agent"))
        d["action_id"] = cur.fetchone()[0]
        if d["decision"] == "block":
            self.blocked.append({"agent": agent_id, "action": action, "reason": d["reason"]})
        return d

    def done(self, cur, action_id, ok=True):
        cur.execute("UPDATE sa_actions SET execution_status = %s WHERE id = %s", ("succeeded" if ok else "failed", action_id))

    def start(self, cur, agent_id):
        scope = {"account": self.account, "environment": self.ctx["environment"],
                 "authorizations": [{"valid_until": a["valid_until"], "environments": a["environments"]}
                                    for a in self.ctx["auths"] if a["agent_id"] == agent_id]}
        cur.execute("""INSERT INTO sa_runs (cloud_account_id, workflow_id, agent_id, agent_version, trigger, initiated_by, policy_version, scope_snapshot)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                    (self.account, self.workflow_id, agent_id, E.ENGINE_VERSION, self.trigger, self.initiated_by, E.POLICY_VERSION, J(scope)))
        return cur.fetchone()[0], time.time()

    def finish(self, cur, run_id, t0, status, summary=None, coverage=None, limitations=None, usage=None, error=None):
        cur.execute("""UPDATE sa_runs SET status = %s, completed_at = NOW(), summary = %s, coverage = %s, limitations = %s,
                              resource_usage = %s, error = %s WHERE id = %s""",
                    (status, J(summary or {}), J(coverage or {}), J(limitations or []),
                     J({**(usage or {}), "duration_seconds": round(time.time() - t0, 2)}), error, run_id))
        cur.execute("UPDATE sa_agents SET last_run_at = NOW(), last_run_status = %s WHERE cloud_account_id = %s AND agent_id = (SELECT agent_id FROM sa_runs WHERE id = %s)",
                    (status, self.account, run_id))

    def evidence(self, cur, run_id, item_id, etype, ref, summary, status):
        cur.execute("""INSERT INTO sa_evidence (cloud_account_id, run_id, work_item_id, evidence_type, source_reference, content_hash, summary, verification_status)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (self.account, run_id, item_id, etype, str(ref)[:500], _hash(summary), J(summary), status))


def _event(cur, account, item_id, frm, to, actor, kind, note=None, details=None):
    cur.execute("""INSERT INTO sa_work_item_events (cloud_account_id, work_item_id, from_state, to_state, actor, actor_kind, note, details)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""", (account, item_id, frm, to, actor, kind, note, J(details or {})))


def publish(cur, wf, run_id, items):
    """Upsert work items. New -> 'new'. A resolved item that is reported again is re-opened by verification logic."""
    new, reopened = [], []
    for it in items:
        cur.execute("SELECT id, state, accepted_until FROM sa_work_items WHERE cloud_account_id = %s AND fingerprint = %s FOR UPDATE",
                    (wf.account, it["fingerprint"]))
        row = cur.fetchone()
        if row is None:
            cur.execute("""INSERT INTO sa_work_items (cloud_account_id, fingerprint, agent_id, category, source_type, source_id, title, severity,
                                                      confidence, priority, priority_reasons, basis, evidence, assets, recommendation, attack_path, validation)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                        (wf.account, it["fingerprint"], it["agent_id"], it["category"], it["source_type"], it["source_id"], it["title"][:500],
                         it["severity"], it["confidence"], it["priority"], J(it["priority_reasons"]), it["basis"], J(it["evidence"]),
                         J(it["assets"]), J(it["recommendation"]), J(it.get("attack_path")), J(it["validation"])))
            iid = cur.fetchone()[0]
            _event(cur, wf.account, iid, None, "new", it["agent_id"], "agent", "Published by the agent")
            wf.evidence(cur, run_id, iid, it["source_type"], it["source_id"], it["evidence"],
                        "observed" if it["category"] == "blue" else "calculated")
            new.append(it)
            continue
        iid, state, accepted_until = row
        cur.execute("""UPDATE sa_work_items SET title = %s, severity = %s, confidence = %s, evidence = %s, assets = %s, recommendation = %s,
                              attack_path = %s, basis = %s, last_seen = NOW(),
                              priority = CASE WHEN active_threat THEN LEAST(100, %s + 20) ELSE %s END, priority_reasons = %s
                       WHERE id = %s""",
                    (it["title"][:500], it["severity"], it["confidence"], J(it["evidence"]), J(it["assets"]), J(it["recommendation"]),
                     J(it.get("attack_path")), it["basis"], it["priority"], it["priority"], J(it["priority_reasons"]), iid))
        expired = state == "accepted_risk" and accepted_until and accepted_until < datetime.now(timezone.utc).date()
        if state == "resolved" or expired:
            cur.execute("UPDATE sa_work_items SET state = 'reopened', state_reason = %s, resolved_at = NULL WHERE id = %s",
                        ("Reported again by the latest scan" if state == "resolved" else "Risk acceptance expired", iid))
            _event(cur, wf.account, iid, state, "reopened", "green-verification", "agent",
                   "Reported again by the latest scan" if state == "resolved" else "Risk acceptance expired")
            reopened.append(it)
    return new, reopened


# ── data for Red ───────────────────────────────────────────────────────────

def red_inputs(cur, account):
    cur.execute("""SELECT arn, name, kind, admin, risk_score FROM ciem_identities WHERE scan_id = (
                       SELECT id FROM ciem_scans WHERE cloud_account_id = %s AND status IN ('succeeded', 'partial') ORDER BY started_at DESC LIMIT 1)""",
                (account,))
    identities = [dict(zip(("arn", "name", "kind", "admin", "risk_score"), r)) for r in cur.fetchall()]
    cur.execute("""SELECT id, rule, category, severity, title, identity_arn, details, recommendation, status FROM ciem_findings
                   WHERE cloud_account_id = %s AND status IN ('open', 'in_progress')""", (account,))
    ciem = [dict(zip(("id", "rule", "category", "severity", "title", "identity_arn", "details", "recommendation", "status"), r))
            for r in cur.fetchall()]
    scanner = []
    if MAPPED_FRAMEWORK_NAMES:
        cur.execute("""SELECT f.id, f.check_id, f.title, f.severity, r.resource_type, r.resource_id, f.remediation, f.details, f.framework
                       FROM findings f JOIN resources r ON r.id = f.resource_id
                       WHERE r.cloud_account_id = %s AND f.status = 'open' AND upper(f.severity) IN ('CRITICAL', 'HIGH')
                         AND (f.framework IS NULL OR NOT (f.framework = ANY(%s)))""", (account, list(MAPPED_FRAMEWORK_NAMES)))
        scanner = [dict(zip(("id", "check_id", "title", "severity", "resource_type", "resource_arn", "remediation", "details", "framework"), r))
                   for r in cur.fetchall()]
    cur.execute("""SELECT f.id, f.rule, f.severity, f.title, f.details, f.recommendation, f.status, a.asset_key, a.name
                   FROM ai_inventory_findings f LEFT JOIN ai_assets a ON a.id = f.asset_id
                   WHERE f.cloud_account_id = %s AND f.status IN ('open', 'in_progress')""", (account,))
    ai = [dict(zip(("id", "rule", "severity", "title", "details", "recommendation", "status", "asset_key", "asset_name"), r))
          for r in cur.fetchall()]
    return identities, ciem, scanner, ai


def source_state(cur, account, source_type, source_id):
    """What the source that reported a work item says now. present: True / False / None (unknown)."""
    if source_type in ("ciem_finding", "ai_inventory_finding"):
        table = "ciem_findings" if source_type == "ciem_finding" else "ai_inventory_findings"
        cur.execute(f"SELECT status, last_seen, resolved_at FROM {table} WHERE id = %s AND cloud_account_id = %s", (source_id, account))
        r = cur.fetchone()
        if not r:
            return {"present": None, "status": "source record removed", "checked_at": None}
        status, last_seen, resolved_at = r
        if status == "suppressed":
            return {"present": None, "status": "rule switched off in the source", "checked_at": None}
        if status == "resolved":
            return {"present": False, "status": "resolved by re-collection", "checked_at": resolved_at}
        return {"present": True, "status": status, "checked_at": last_seen}
    if source_type == "scanner_finding":
        cur.execute("""SELECT f.status, f.detected_at FROM findings f JOIN resources r ON r.id = f.resource_id
                       WHERE f.id = %s AND r.cloud_account_id = %s""", (source_id, account))
        r = cur.fetchone()
        if not r:
            return {"present": None, "status": "source record removed", "checked_at": None}
        checked = r[1].replace(tzinfo=timezone.utc) if r[1] and r[1].tzinfo is None else r[1]
        return {"present": r[0] == "open", "status": "passes the check" if r[0] == "pass" else r[0], "checked_at": checked}
    return {"present": None, "status": "verified by a person (no scan covers it)", "checked_at": None}


# ── Blue telemetry ─────────────────────────────────────────────────────────

def collect_cloudtrail(session, region, since):
    ct = session.client("cloudtrail", region_name=region, config=RETRY)
    events, coverage, calls = [], {}, 0
    end = datetime.now(timezone.utc)
    day_start = since.replace(hour=0, minute=0, second=0, microsecond=0)
    for name in E.DETECTION_EVENTS:
        start = day_start if name in E.THRESHOLD_EVENTS else since   # counted per day: read the whole day again
        try:
            token, pages = None, 0
            while True:
                kw = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": name}], "StartTime": start, "EndTime": end,
                      "MaxResults": 50}
                if token:
                    kw["NextToken"] = token
                r = ct.lookup_events(**kw)
                calls += 1
                events += r.get("Events", [])
                token, pages = r.get("NextToken"), pages + 1
                if not token or pages >= MAX_PAGES_PER_EVENT:
                    break
            coverage[name] = {"ok": True, "truncated": bool(token)}
        except Exception as e:  # noqa: BLE001 - one unreadable event name is a coverage gap, not a failed run
            coverage[name] = {"ok": False, "error": getattr(e, "response", {}).get("Error", {}).get("Code") or type(e).__name__}
    return events, coverage, calls, end


# ── the workflow ───────────────────────────────────────────────────────────

def run(conn, account_id, session, trigger="schedule", region=None, initiated_by=None, only=None):
    region = region or REGION
    with conn.cursor() as cur:
        ctx = load_context(cur, account_id)
    conn.commit()
    wf = Workflow(conn, account_id, ctx, trigger, initiated_by)
    active = [a for a in E.AGENTS if ctx["states"].get(a) == "active" and (not only or a in only)]
    summary = {"workflow_id": wf.workflow_id, "active_agents": active, "runs": {}}
    if not active:
        summary["note"] = "No agent is active for this account. Configure, authorise, evaluate and approve agents first."
        return summary
    red_items = []
    # ── Red ──
    with conn.cursor() as cur:
        identities, ciem, scanner, ai = red_inputs(cur, account_id)
        inputs = {"red-identity-attack-path": lambda: E.red_identity(identities, ciem),
                  "red-vulnerability-assessment": lambda: E.red_vulnerabilities(scanner),
                  "red-ai-security": lambda: E.red_ai(ai)}
        for agent_id, produce in inputs.items():
            if agent_id not in active:
                continue
            run_id, t0 = wf.start(cur, agent_id)
            if wf.check(cur, run_id, agent_id, "read_inventory")["decision"] != "allow" or \
               wf.check(cur, run_id, agent_id, "analyze")["decision"] != "allow":
                wf.finish(cur, run_id, t0, "blocked", limitations=["Not authorised to read or analyse for this account."])
                summary["runs"][agent_id] = "blocked"
                continue
            items = produce()
            pub = wf.check(cur, run_id, agent_id, "publish_work_item")
            new = reopened = []
            if pub["decision"] == "allow":
                new, reopened = publish(cur, wf, run_id, items)
                wf.done(cur, pub["action_id"])
            red_items += items
            lim = []
            if agent_id == "red-vulnerability-assessment" and not MAPPED_FRAMEWORK_NAMES:
                lim.append("Scanner findings were not read (configuration missing).")
            if agent_id == "red-identity-attack-path" and not identities:
                lim.append("No CIEM scan yet: entitlement-based attack paths are not analysed.")
            lim.append("Analysis only: potential weaknesses from configuration. Nothing was exploited or actively tested.")
            if new and any(i["severity"] in ("critical", "high") for i in new):
                wf.notifications.append(("red", agent_id, [i for i in new if i["severity"] in ("critical", "high")]))
            wf.finish(cur, run_id, t0, "succeeded" if pub["decision"] == "allow" else "blocked",
                      {"items": len(items), "new": len(new), "reopened": len(reopened), "by_severity": _count(items, "severity")},
                      limitations=lim, usage={"items_analysed": len(items)})
            summary["runs"][agent_id] = {"items": len(items), "new": len(new)}
    conn.commit()
    # ── Blue ──
    blue = [a for a in ("blue-identity-defense", "blue-cloud-threat", "blue-ai-threat-defense") if a in active]
    detections = []
    if blue:
        with conn.cursor() as cur:
            allowed = []
            for agent_id in blue:
                run_id, t0 = wf.start(cur, agent_id)
                ok = all(wf.check(cur, run_id, agent_id, a)["decision"] == "allow" for a in ("read_telemetry", "analyze"))
                if ok:
                    allowed.append((agent_id, run_id, t0))
                else:
                    wf.finish(cur, run_id, t0, "blocked", limitations=["Not authorised to read telemetry for this account."])
                    summary["runs"][agent_id] = "blocked"
            if allowed:
                floor = datetime.now(timezone.utc) - timedelta(hours=ctx["lookback_hours"])
                since_by = {}
                for agent_id, _, _ in allowed:
                    # each agent continues from its own last complete read; partial or blocked runs do not move it
                    cur.execute("""SELECT max((coverage->>'window_end')::timestamptz) FROM sa_runs WHERE cloud_account_id = %s
                                   AND agent_id = %s AND status = 'succeeded' AND coverage->>'window_end' IS NOT NULL""", (account_id, agent_id))
                    last_end = cur.fetchone()[0]
                    since_by[agent_id] = max(floor, last_end - timedelta(minutes=15)) if last_end else floor
                since = min(since_by.values())
                try:
                    events, cov, calls, end = collect_cloudtrail(session, region, since)
                    err = None
                except Exception as e:  # noqa: BLE001
                    events, cov, calls, end, err = [], {}, 0, None, type(e).__name__
                found = E.detect(events, region)
                gaps = [n for n, c in cov.items() if not c.get("ok")]
                trunc = [n for n, c in cov.items() if c.get("truncated")]
                for agent_id, run_id, t0 in allowed:
                    my_since = since_by[agent_id]
                    mine = [d for d in found if d["agent_id"] == agent_id and E._as_dt(d["last_event_at"]) >= my_since]
                    needed = {n for d in E.DETECTIONS if d["agent"] == agent_id for n in d["events"]}
                    my_gaps = sorted(needed & set(gaps))
                    lim = [f"CloudTrail management events in {region} only, from {my_since.isoformat()} (LookupEvents keeps 90 days)."]
                    if err:
                        lim.append("CloudTrail could not be read: no conclusion about threats is possible for this period.")
                    if my_gaps:
                        lim.append(f"Events not readable: {', '.join(my_gaps)}. Activity of those kinds is not covered.")
                    if needed & set(trunc):
                        lim.append(f"More than {MAX_PAGES_PER_EVENT * 50} events for {', '.join(sorted(needed & set(trunc)))}; the newest were analysed.")
                    publish_ok = wf.check(cur, run_id, agent_id, "publish_work_item")["decision"] == "allow"
                    stored = store_detections(cur, wf, run_id, mine) if publish_ok else []
                    detections += stored
                    my_trunc = bool(needed & set(trunc))
                    status = "failed" if err else ("partial" if my_gaps or my_trunc or not publish_ok else "succeeded")
                    wf.finish(cur, run_id, t0, status, {"detections": len(mine), "new": len([d for d in stored if d["_new"]]),
                                                        "events_read": len(events)},
                              coverage={"window_start": my_since.isoformat(),
                                        "window_end": end.isoformat() if status == "succeeded" else None,
                                        "event_names": {n: cov.get(n) for n in sorted(needed)}},
                              limitations=lim, usage={"api_calls": calls, "events": len(events)})
                    summary["runs"][agent_id] = {"detections": len(mine), "status": status}
        conn.commit()
    # ── Incident triage ──
    if "blue-incident-triage" in active:
        with conn.cursor() as cur:
            run_id, t0 = wf.start(cur, "blue-incident-triage")
            if all(wf.check(cur, run_id, "blue-incident-triage", a)["decision"] == "allow"
                   for a in ("read_inventory", "analyze", "publish_work_item")):
                n = triage_incidents(cur, wf, run_id)
                wf.finish(cur, run_id, t0, "succeeded", n)
                summary["runs"]["blue-incident-triage"] = n
            else:
                wf.finish(cur, run_id, t0, "blocked")
        conn.commit()
    # ── Green planning ──
    if "green-remediation-planner" in active:
        with conn.cursor() as cur:
            run_id, t0 = wf.start(cur, "green-remediation-planner")
            readable = wf.check(cur, run_id, "green-remediation-planner", "read_inventory")["decision"] == "allow"
            d = wf.check(cur, run_id, "green-remediation-planner", "propose_remediation")
            planned = 0
            if readable and d["decision"] == "allow":
                cur.execute("""SELECT id, source_type, confidence, recommendation FROM sa_work_items
                               WHERE cloud_account_id = %s AND plan IS NULL AND state = ANY(%s) AND category <> 'blue'""",
                            (account_id, list(E.OPEN_STATES)))
                for iid, st, conf, rec in cur.fetchall():
                    cur.execute("UPDATE sa_work_items SET plan = %s WHERE id = %s",
                                (J(E.remediation_plan({"source_type": st, "confidence": conf, "recommendation": rec})), iid))
                    planned += 1
                wf.done(cur, d["action_id"])
            wf.finish(cur, run_id, t0, "succeeded" if readable and d["decision"] == "allow" else "blocked", {"plans_created": planned})
            summary["runs"]["green-remediation-planner"] = {"plans": planned}
        conn.commit()
    # ── Verification ──
    if "green-verification" in active:
        with conn.cursor() as cur:
            summary["runs"]["green-verification"] = verification(cur, wf, session)
        conn.commit()
    _notify(conn, wf)
    summary["blocked_actions"] = wf.blocked
    return summary


def _count(items, key):
    out = {}
    for i in items:
        out[i[key]] = out.get(i[key], 0) + 1
    return out


def store_detections(cur, wf, run_id, found):
    stored = []
    for d in found:
        cur.execute("""INSERT INTO sa_detections (cloud_account_id, fingerprint, run_id, rule, agent_id, severity, title, mitre, principal, resources,
                                                  source_ip, region, first_event_at, last_event_at, event_count, event_ids, event_names, why, respond)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (cloud_account_id, fingerprint) DO UPDATE SET last_event_at = GREATEST(sa_detections.last_event_at, EXCLUDED.last_event_at),
                           event_count = GREATEST(sa_detections.event_count, EXCLUDED.event_count), event_ids = EXCLUDED.event_ids
                       RETURNING id, (xmax = 0)""",
                    (wf.account, d["fingerprint"], run_id, d["rule"], d["agent_id"], d["severity"], d["title"], d["mitre"], d["principal"],
                     J(d["resources"]), d["source_ip"], d["region"], d["first_event_at"], d["last_event_at"], d["event_count"],
                     J(d["event_ids"]), J(d["event_names"]), d["why"], d["respond"]))
        did, is_new = cur.fetchone()
        d["_id"], d["_new"] = did, is_new
        if is_new:
            wf.evidence(cur, run_id, None, "cloudtrail_events", f"CloudTrail {d['region']}: {', '.join(d['event_ids'][:5])}",
                        {"rule": d["rule"], "event_ids": d["event_ids"], "principal": d["principal"]}, "observed")
            if d["severity"] in ("critical", "high", "medium"):
                score, why = E.priority(d["severity"], "high", None, None, True)
                item = {"fingerprint": E.fingerprint("detection", d["fingerprint"]), "agent_id": d["agent_id"], "category": "blue",
                        "source_type": "detection", "source_id": str(did), "title": f"{d['title']} ({d['principal'].split('/')[-1]})",
                        "severity": d["severity"], "confidence": "high", "basis": d["basis"],
                        "evidence": {"rule": d["rule"], "mitre": d["mitre"], "event_ids": d["event_ids"], "first_event_at": d["first_event_at"],
                                     "event_count": d["event_count"], "source_ip": d["source_ip"]},
                        "assets": [{"type": "aws_identity", "ref": d["principal"]}] + [{"type": "aws_resource", "ref": r} for r in d["resources"][:5]],
                        "recommendation": {"current": d["why"], "proposed": d["respond"],
                                           "reason": "Observed in CloudTrail; whether it was malicious is for you to confirm.",
                                           "rollback": "Not applicable (investigation)."},
                        "priority": score, "priority_reasons": why,
                        "validation": {"status": "observed", "note": "The events happened (CloudTrail). Intent is not established."}}
                publish(cur, wf, run_id, [item])
        stored.append(d)
    return stored


def triage_incidents(cur, wf, run_id):
    cur.execute("""SELECT fingerprint, rule, agent_id, severity, principal, resources, first_event_at, last_event_at FROM sa_detections
                   WHERE cloud_account_id = %s AND status IN ('open', 'acknowledged', 'escalated') AND last_event_at > NOW() - INTERVAL '7 days'""",
                (wf.account,))
    dets = [{"fingerprint": f, "rule": r, "agent_id": a, "severity": s, "principal": p, "resources": res or [],
             "first_event_at": fe.isoformat(), "last_event_at": le.isoformat()} for f, r, a, s, p, res, fe, le in cur.fetchall()]
    cur.execute("""SELECT fingerprint, assets FROM sa_work_items WHERE cloud_account_id = %s AND category = 'red' AND state = ANY(%s)""",
                (wf.account, list(E.OPEN_STATES)))
    items = [{"fingerprint": f, "assets": a or []} for f, a in cur.fetchall()]
    incidents = E.triage(dets, items)
    created = 0
    for inc in incidents:
        cur.execute("""INSERT INTO sa_incidents (cloud_account_id, fingerprint, principal, severity, summary, hypothesis, basis, resources,
                                                 related_work_items, first_event_at, last_event_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (cloud_account_id, fingerprint) DO UPDATE SET severity = EXCLUDED.severity, summary = EXCLUDED.summary,
                           hypothesis = EXCLUDED.hypothesis, resources = EXCLUDED.resources, related_work_items = EXCLUDED.related_work_items,
                           last_event_at = EXCLUDED.last_event_at
                       RETURNING id, (xmax = 0)""",
                    (wf.account, inc["fingerprint"], inc["principal"], inc["severity"], inc["summary"], inc["hypothesis"], inc["basis"],
                     J(inc["resources"]), J(inc["related_work_items"]), inc["first_event_at"], inc["last_event_at"]))
        iid, is_new = cur.fetchone()
        created += int(is_new)
        cur.execute("UPDATE sa_detections SET incident_id = %s WHERE cloud_account_id = %s AND fingerprint = ANY(%s)",
                    (iid, wf.account, inc["detections"]))
        if inc["related_work_items"]:
            cur.execute("""UPDATE sa_work_items SET active_threat = TRUE, priority = LEAST(100, priority + 20),
                                  priority_reasons = priority_reasons || %s::jsonb
                           WHERE cloud_account_id = %s AND fingerprint = ANY(%s) AND NOT active_threat""",
                        (json.dumps([{"points": 20, "reason": "related suspicious activity detected"}]), wf.account, inc["related_work_items"]))
        if is_new and inc["severity"] in ("critical", "high"):
            wf.notifications.append(("incident", "blue-incident-triage", [inc]))
    return {"incidents": len(incidents), "new": created}


def verification(cur, wf, session):
    agent_id = "green-verification"
    run_id, t0 = wf.start(cur, agent_id)
    if any(wf.check(cur, run_id, agent_id, a)["decision"] != "allow" for a in ("read_inventory", "verify")):
        wf.finish(cur, run_id, t0, "blocked")
        return "blocked"
    cur.execute("""SELECT id, state, source_type, source_id, remediated_at, title FROM sa_work_items
                   WHERE cloud_account_id = %s AND state = ANY(%s) AND source_type <> 'detection' FOR UPDATE""",
                (wf.account, list(E.OPEN_STATES)))
    counts = {"passed": 0, "failed": 0, "pending": 0, "rescans_requested": 0}
    rescan = set()
    for iid, state, st, sid, rem_at, title in cur.fetchall():
        src = source_state(cur, wf.account, st, sid)
        v = E.verify({}, src, rem_at)
        counts[v["result"]] += 1
        record = {**v, "source_status": src["status"], "checked_at": src["checked_at"], "verified_by": agent_id,
                  "at": datetime.now(timezone.utc).isoformat()}
        if v["result"] == "passed" and E.can_transition(state, "resolved", "verification"):
            cur.execute("UPDATE sa_work_items SET state = 'resolved', resolved_at = NOW(), verification = %s, state_reason = %s WHERE id = %s",
                        (J(record), v["reason"], iid))
            _event(cur, wf.account, iid, state, "resolved", agent_id, "agent", v["reason"], record)
            wf.evidence(cur, run_id, iid, "verification", f"{st}:{sid}", record, "verified")
        elif v["result"] == "failed" and state in ("remediated", "verification"):
            cur.execute("UPDATE sa_work_items SET state = 'reopened', verification = %s, state_reason = %s WHERE id = %s",
                        (J(record), "Verification failed: " + v["reason"], iid))
            _event(cur, wf.account, iid, state, "reopened", agent_id, "agent", v["reason"], record)
            wf.evidence(cur, run_id, iid, "verification", f"{st}:{sid}", record, "verified")
            wf.notifications.append(("verification_failed", agent_id, [{"title": title, "reason": v["reason"]}]))
        else:
            cur.execute("UPDATE sa_work_items SET verification = %s WHERE id = %s", (J(record), iid))
            if state == "remediated" and st in RESCAN_FUNCTIONS:
                rescan.add(st)
    for st in sorted(rescan):
        fn = RESCAN_FUNCTIONS[st]
        d = wf.check(cur, run_id, agent_id, "request_rescan", target=fn)
        if d["decision"] == "allow":
            try:
                boto3.client("lambda", region_name=REGION).invoke(FunctionName=fn, InvocationType="Event", Payload=json.dumps(
                    {"cloud_account_id": wf.account, "trigger": "manual", "_async": True}).encode())
                wf.done(cur, d["action_id"])
                counts["rescans_requested"] += 1
            except Exception:  # noqa: BLE001
                logger.exception("rescan request failed")
                wf.done(cur, d["action_id"], ok=False)
        elif d["decision"] == "approval_required":
            cur.execute("""SELECT 1 FROM sa_approvals WHERE cloud_account_id = %s AND action = 'request_rescan' AND target = %s
                           AND decision = 'pending' AND expires_at > NOW()""", (wf.account, fn))
            if not cur.fetchone():
                cur.execute("""INSERT INTO sa_approvals (cloud_account_id, agent_id, action, target, payload, requested_by, expires_at)
                               VALUES (%s, %s, 'request_rescan', %s, %s, %s, NOW() + INTERVAL '7 days') RETURNING id""",
                            (wf.account, agent_id, fn, J({"reason": "Verify recorded remediations"}), agent_id))
                cur.execute("UPDATE sa_actions SET approval_id = %s WHERE id = %s", (cur.fetchone()[0], d["action_id"]))
                wf.notifications.append(("approval", agent_id, [{"title": f"Approve a verification re-scan ({fn})"}]))
    wf.finish(cur, run_id, t0, "succeeded", counts,
              limitations=["Scanner (CIS/FSBP) findings are re-checked by the regular account scan; no extra scan is started for them."])
    return counts


def _notify(conn, wf):
    if not wf.notifications and not wf.blocked:
        return
    try:
        from collectors.aws.scanner.notification_lib import create_notification
    except Exception:  # noqa: BLE001
        return
    link = f"security_agents.html?account_id={wf.account}"
    try:
        for kind, agent_id, items in wf.notifications:
            with conn.cursor() as cur:
                d = wf.check(cur, None, agent_id, "notify", target=kind)
                if d["decision"] == "allow":
                    wf.done(cur, d["action_id"])
            conn.commit()
            if d["decision"] != "allow":
                continue
            if kind == "red":
                crit = any(i["severity"] == "critical" for i in items)
                create_notification(conn, wf.account, "security", "critical_security_finding" if crit else "security_agent_finding",
                                    "P1" if crit else "P2", f"{len(items)} new high-risk weakness(es) from {E.AGENTS[agent_id]['name']}",
                                    description="; ".join(i["title"] for i in items[:5]), resource_link=link + "#queue", actor=agent_id)
            elif kind == "incident":
                inc = items[0]
                create_notification(conn, wf.account, "security", "suspicious_privileged_activity", "P1",
                                    f"Possible incident: {inc['summary']}", description=inc["hypothesis"], resource_link=link + "#incidents",
                                    actor=agent_id)
            elif kind == "verification_failed":
                create_notification(conn, wf.account, "security", "security_agent_verification_failed", "P2",
                                    f"Remediation not confirmed: {items[0]['title']}", description=items[0]["reason"],
                                    resource_link=link + "#queue", actor=agent_id)
            elif kind == "approval":
                create_notification(conn, wf.account, "security", "security_agent_approval_required", "P3", items[0]["title"],
                                    resource_link=link + "#approvals", actor=agent_id)
        blocked = [b for b in wf.blocked if b["action"] != "notify"]   # a silenced agent must not notify about being silenced
        if blocked:
            create_notification(conn, wf.account, "security", "security_agent_blocked", "P3",
                                f"{len(blocked)} agent action(s) were blocked by policy",
                                description="; ".join(f"{b['agent']}: {b['reason']}" for b in blocked[:5]),
                                resource_link=link + "#audit", actor="policy-engine")
    except Exception:  # noqa: BLE001
        logger.exception("security agent notification failed")


def handler(event, context):
    account_id = (event or {}).get("cloud_account_id")
    if not account_id:
        return {"statusCode": 400, "body": json.dumps({"error": "cloud_account_id is required"})}
    if not event.get("_async") and context is not None and os.environ.get("SECURITY_AGENTS_ASYNC", "1") == "1":
        boto3.client("lambda", region_name=REGION).invoke(FunctionName=context.invoked_function_arn, InvocationType="Event",
                                                          Payload=json.dumps({**event, "_async": True}).encode())
        return {"statusCode": 202, "body": json.dumps({"status": "queued"})}
    conn = _get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT role_arn, external_id, COALESCE(region, %s), status FROM cloud_accounts WHERE id = %s", (REGION, account_id))
            row = cur.fetchone()
        conn.commit()
        if not row:
            return {"statusCode": 404, "body": json.dumps({"error": "unknown cloud account"})}
        role_arn, external_id, region, status = row
        if status != "active":
            return {"statusCode": 200, "body": json.dumps({"status": "skipped", "reason": "account not active"})}
        try:
            session = _assume(event.get("role_arn") or role_arn, event.get("external_id") or external_id, event.get("region") or region)
        except Exception:  # noqa: BLE001
            logger.exception("assume role failed")
            session = None
        if session is None:
            with conn.cursor() as cur:
                ctx = load_context(cur, account_id)
                wf = Workflow(conn, account_id, ctx, event.get("trigger", "schedule"), event.get("initiated_by"))
                for agent_id in E.AGENTS:
                    if ctx["states"].get(agent_id) == "active":
                        run_id, t0 = wf.start(cur, agent_id)
                        wf.finish(cur, run_id, t0, "failed", error="Niagaros could not sign in to this AWS account with the scanner role.")
            conn.commit()
            return {"statusCode": 200, "body": json.dumps({"status": "failed", "error": "assume_role"})}
        out = run(conn, account_id, session, event.get("trigger", "schedule"), event.get("region") or region,
                  event.get("initiated_by"), event.get("agents"))
        return {"statusCode": 200, "body": json.dumps(out, default=str)}
    except Exception:  # noqa: BLE001
        conn.rollback()
        logger.exception("security agents run failed")
        return {"statusCode": 500, "body": json.dumps({"status": "failed"})}
    finally:
        conn.close()


lambda_handler = handler
