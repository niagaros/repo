"""
critical_issues_handler.py — Zero Critical Issues (issue #296). One Lambda behind GET/POST /critical-issues, guarded by
tenant_auth.guard like every other account-data handler.

Where the data comes from
  The scanners stay the only source of truth for whether a critical problem exists:
    findings               severity CRITICAL, framework not a mapped-framework duplicate (same rule as the dashboard)
    ciem_findings          severity critical
    ai_inventory_findings  severity critical
  critical_issues adds what a scanner cannot know (owner, deadline, plan, accepted risk, history). Every read first
  syncs the two (`sync_issues`): new failures become issues, a failure seen again after it was resolved reopens the
  issue, and an issue is only ever marked resolved when a scan AFTER the remediation no longer reports it.

Zero-critical status (`posture`)
  A zero count is only reported as "Zero Critical Issues" when the required evidence is fresh and coverage is
  complete; otherwise the status says why the claim cannot be made. Accepted risks are always counted separately.

GET  /critical-issues?cloud_account_id=...&view=
       overview | issues | issue&issue_id= | history | settings | export&format=csv|json
GET  /critical-issues?view=portfolio          every account the caller may see, with business units
POST /critical-issues {cloud_account_id, action, ...}
       assign            issue_id, owner_email, due_date
       set_plan          issue_id, remediation_plan
       start             issue_id
       mark_remediated   issue_id, note
       request_risk_acceptance  issue_id, justification, rationale, risk_owner, compensating_controls,
                                residual_risk, expires_on, review_every_days
       decide_risk       issue_id, decision (approve|reject), note        (a different person than the requester)
       mark_false_positive  issue_id, evidence
       reopen            issue_id, reason
       save_settings     sla_days, freshness_days

Nothing here changes a customer's cloud resources: remediation is planned and tracked here, applied by the customer,
and verified by the next scan.
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

from collectors.aws.scanner.tenant_auth import ACCESS_SQL, account_allowed, authenticate, guard

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
CORS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}
REFS = {"issue_id": "SELECT cloud_account_id FROM critical_issues WHERE id = %s"}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")

# Kept identical to MAPPED_FRAMEWORK_NAMES in config/database.py (and get-dashboard-data): these are per-framework
# copies of one real misconfiguration and must never be counted as separate critical issues.
MAPPED_FRAMEWORK_NAMES = (
    'ISO 27001:2022', 'NIST CSF v2.0', 'GDPR', 'SOC2', 'PCI DSS v4.0', 'NIS2', 'HIPAA',
    'NIST 800-53 Rev 5', 'BSI-C5', 'CSA CCM 4.0', 'FedRAMP Moderate Rev 4', 'ISO 42001',
    'ISO 27017', 'AWS FTR', 'MVSP', 'TISAX', 'HITRUST CSF', 'DORA', 'CRI Profile',
    'EU AI Act', 'NIST AI RMF', 'ISO 27701', 'ISO 27018', 'Microsoft SSPA',
    'CIS Controls v8.1', '23 NYCRR 500 (NYDFS)', 'NIST Privacy Framework',
)
UNRESOLVED = ("open", "assigned", "in_progress", "remediated", "reopened")
WORKING = ("open", "assigned", "in_progress", "reopened")
SOURCE_LABEL = {"findings": "Cloud posture", "ciem_findings": "Identity & entitlements (CIEM)",
                "ai_inventory_findings": "AI assets"}
SOURCE_PAGE = {"findings": "niagaros-dashboard.html", "ciem_findings": "ciem.html",
               "ai_inventory_findings": "ai_inventory.html"}
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


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


def _now():
    return datetime.now(timezone.utc)


def _aware(ts):
    """findings.detected_at is a naive UTC timestamp; everything else is timestamptz."""
    if ts is None:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _csv_cell(v):
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        v = json.dumps(v, default=str)
    v = str(v)
    return "'" + v if v.startswith(_FORMULA_START) else v


def _text(body, key, what, required=True, max_len=4000):
    v = body.get(key)
    if v is None or (isinstance(v, str) and not v.strip()):
        if required:
            raise BadRequest(400, f"{what} is required")
        return None
    if not isinstance(v, str):
        raise BadRequest(400, f"{what} must be text")
    v = v.strip()
    if len(v) > max_len:
        raise BadRequest(400, f"{what} is too long (max {max_len} characters)")
    return v


def _date(body, key, what, required=True, min_day=None, max_days_ahead=None):
    v = body.get(key)
    if not v:
        if required:
            raise BadRequest(400, f"{what} is required")
        return None
    try:
        d = date.fromisoformat(str(v)[:10])
    except ValueError:
        raise BadRequest(400, f"{what} must be a date (YYYY-MM-DD)")
    if min_day and d < min_day:
        raise BadRequest(400, f"{what} cannot be in the past")
    if max_days_ahead and d > date.today() + timedelta(days=max_days_ahead):
        raise BadRequest(400, f"{what} can be at most {max_days_ahead} days ahead")
    return d


# ── settings ────────────────────────────────────────────────────────────────

def _settings(cur, account):
    cur.execute("SELECT sla_days, freshness_days, updated_by, updated_at FROM critical_issue_settings WHERE cloud_account_id = %s",
                (account,))
    r = cur.fetchone()
    if not r:
        return {"sla_days": 7, "freshness_days": 10, "updated_by": None, "updated_at": None, "default": True}
    return {"sla_days": r[0], "freshness_days": r[1], "updated_by": r[2], "updated_at": r[3], "default": False}


# ── reading the scanners ────────────────────────────────────────────────────

def _rec_text(rec):
    """CIEM / AI Inventory store a structured recommendation; show its proposed change as the headline."""
    if isinstance(rec, dict):
        return rec.get("proposed") or rec.get("summary") or rec.get("action")
    return rec


def _failing_sources(cur, account):
    """Every critical problem the scanners currently report for this account, keyed by (source, source_id)."""
    out = {}
    cur.execute("""
        SELECT f.id, f.check_id, f.title, f.description, f.remediation, f.details, f.framework,
               f.first_detected_at, f.detected_at, r.resource_type, r.resource_id, r.resource_name, r.region
        FROM findings f JOIN resources r ON r.id = f.resource_id
        WHERE r.cloud_account_id = %s AND upper(f.severity) = 'CRITICAL' AND f.status = 'open'
          AND (f.framework IS NULL OR NOT (f.framework = ANY(%s)))
    """, (account, list(MAPPED_FRAMEWORK_NAMES)))
    for (fid, check, title, desc, rem, details, fw, first, seen, rtype, rid, rname, region) in cur.fetchall():
        out[("findings", str(fid))] = {
            "title": f"{check}: {title}" if check and title and not title.startswith(check) else (title or check),
            "check_id": check, "framework": fw, "description": desc, "recommendation": rem,
            "evidence": details or {}, "first_detected_at": _aware(first) or _aware(seen),
            "last_observed_at": _aware(seen), "asset": {"type": rtype, "id": rid, "name": rname, "region": region},
        }
    cur.execute("""
        SELECT id, rule, category, title, identity_arn, identity_name, details, recommendation, first_seen, last_seen, status
        FROM ciem_findings WHERE cloud_account_id = %s AND severity = 'critical'
          AND (status IN ('open', 'in_progress') OR (status = 'accepted' AND accepted_until < CURRENT_DATE))
    """, (account,))
    for (fid, rule, cat, title, arn, name, details, rec, first, last, _st) in cur.fetchall():
        out[("ciem_findings", str(fid))] = {
            "title": title, "check_id": rule, "framework": f"CIEM · {cat}", "description": None,
            "recommendation": _rec_text(rec),
            "recommendation_detail": rec, "evidence": details or {}, "first_detected_at": _aware(first),
            "last_observed_at": _aware(last), "asset": {"type": "iam-identity", "id": arn, "name": name, "region": None},
        }
    cur.execute("""
        SELECT id, rule, title, details, recommendation, first_seen, last_seen
        FROM ai_inventory_findings
        WHERE cloud_account_id = %s AND severity = 'critical'
          AND (status IN ('open', 'in_progress') OR (status = 'accepted' AND accepted_until < CURRENT_DATE))
    """, (account,))
    for (fid, rule, title, details, rec, first, last) in cur.fetchall():
        out[("ai_inventory_findings", str(fid))] = {
            "title": title, "check_id": rule, "framework": "AI Inventory", "description": None,
            "recommendation": _rec_text(rec),
            "recommendation_detail": rec, "evidence": details or {}, "first_detected_at": _aware(first),
            "last_observed_at": _aware(last),
            "asset": {"type": "ai-asset", "id": None, "region": None,
                      "name": (details or {}).get("asset_name") if isinstance(details, dict) else None},
        }
    return out


def _last_full_scan(cur, account, source):
    """When the module that owns `source` last completed a full scan of the account (None = never)."""
    if source == "findings":
        cur.execute("SELECT last_scan_at FROM cloud_accounts WHERE id = %s", (account,))
    else:
        table = "ciem_scans" if source == "ciem_findings" else "ai_inventory_scans"
        cur.execute(f"SELECT max(finished_at) FROM {table} WHERE cloud_account_id = %s AND status = 'succeeded'", (account,))
    r = cur.fetchone()
    return _aware(r[0]) if r else None


def _source_state(cur, source, source_id, account=None):
    """(state, observed_at) of a source row that is NOT failing any more:
    'passed'  the scanner evaluated it again and it passes      -> verified resolution
    'gone'    the row no longer exists (resource removed by a complete scan) -> verified resolution
    'accepted' / 'suppressed' / 'false_positive' handled in the source module -> not a verified resolution
    """
    if source == "findings":
        cur.execute("SELECT status, detected_at FROM findings WHERE id = %s", (source_id,))
        r = cur.fetchone()
        if not r:
            return "gone", _last_full_scan(cur, account, source)
        return ("passed" if r[0] == "pass" else r[0]), _aware(r[1])
    table = "ciem_findings" if source == "ciem_findings" else "ai_inventory_findings"
    cur.execute(f"SELECT status, COALESCE(resolved_at, last_seen) FROM {table} WHERE id = %s", (source_id,))
    r = cur.fetchone()
    if not r:
        return "gone", _last_full_scan(cur, account, source)
    st = {"resolved": "passed"}.get(r[0], r[0])
    return st, _aware(r[1])


# ── sync ─────────────────────────────────────────────────────────────────────

def _event(cur, issue_id, account, actor, event, from_status=None, to_status=None, detail=None):
    cur.execute("""INSERT INTO critical_issue_events (issue_id, cloud_account_id, actor, event, from_status, to_status, detail)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (issue_id, account, actor, event, from_status, to_status,
                 Json(detail or {}, dumps=lambda o: json.dumps(o, default=str))))


def _lock(cur, account):
    cur.execute("SELECT pg_advisory_xact_lock(hashtext('critical_issues:' || %s))", (str(account),))


def sync_issues(cur, account, settings=None, notify=None):
    """Bring critical_issues in line with what the scanners report now. Returns the failing-source map."""
    # One sync or change per account at a time (released at commit/rollback), so concurrent page loads cannot
    # record the same reopen/escalation twice or overwrite each other's lifecycle changes.
    _lock(cur, account)
    settings = settings or _settings(cur, account)
    failing = _failing_sources(cur, account)
    cur.execute("""SELECT id, source, source_id, status, remediated_at, risk_expires_on, due_date, escalated_at, title,
                          last_observed_at
                   FROM critical_issues WHERE cloud_account_id = %s""", (account,))
    existing = {(r[1], str(r[2])): r for r in cur.fetchall()}
    today = date.today()

    for key, src in failing.items():
        row = existing.get(key)
        if not row:
            cur.execute("""INSERT INTO critical_issues (cloud_account_id, source, source_id, title, status, due_date,
                                                        first_detected_at, last_observed_at)
                           VALUES (%s, %s, %s, %s, 'open', %s, %s, %s)
                           ON CONFLICT (cloud_account_id, source, source_id) DO NOTHING RETURNING id""",
                        (account, key[0], key[1], src["title"][:500], today + timedelta(days=settings["sla_days"]),
                         src["first_detected_at"], src["last_observed_at"]))
            ins = cur.fetchone()
            if not ins:
                continue
            iid = ins[0]
            _event(cur, iid, account, "scanner", "detected", None, "open",
                   {"source": key[0], "check_id": src["check_id"], "observed_at": src["last_observed_at"]})
            continue
        iid, _s, _sid, status, remediated_at, _exp, _due, _esc, _t, _seen = row
        cur.execute("UPDATE critical_issues SET last_observed_at = %s, title = %s, updated_at = NOW() WHERE id = %s",
                    (src["last_observed_at"], src["title"][:500], iid))
        if status == "resolved":
            # The problem is back: count it again, with a fresh deadline.
            cur.execute("""UPDATE critical_issues SET status = 'reopened', reopen_count = reopen_count + 1, resolved_at = NULL,
                                  verified_by_scan_at = NULL, remediated_at = NULL, escalated_at = NULL, due_date = %s
                           WHERE id = %s""", (today + timedelta(days=settings["sla_days"]), iid))
            _event(cur, iid, account, "scanner", "reopened", "resolved", "reopened", {"observed_at": src["last_observed_at"]})
        elif status == "remediated" and remediated_at and src["last_observed_at"] and src["last_observed_at"] > remediated_at:
            # Someone said it was fixed, but a later scan still sees it: the remediation failed, and stays visible.
            cur.execute("UPDATE critical_issues SET status = 'in_progress', remediated_at = NULL WHERE id = %s", (iid,))
            _event(cur, iid, account, "scanner", "verification_failed", "remediated", "in_progress",
                   {"observed_at": src["last_observed_at"], "remediated_at": remediated_at})

    for key, row in existing.items():
        iid, source, source_id, status, remediated_at, risk_expires_on, due, escalated_at, title, last_seen = row
        if key not in failing and status not in ("resolved", "false_positive"):
            state, observed = _source_state(cur, source, source_id, account)
            # Verification needs an observation made AFTER the problem was last seen and after any claimed fix;
            # anything older (or no observation at all) leaves the issue waiting for the next scan.
            must_follow = max([x for x in (remediated_at if status == "remediated" else None, last_seen) if x], default=None)
            if state in ("passed", "gone") and (observed is None or (must_follow and observed <= must_follow)):
                state = "awaiting_scan"
            if state in ("passed", "gone"):
                cur.execute("""UPDATE critical_issues SET status = 'resolved', resolved_at = NOW(), verified_by_scan_at = %s,
                                      escalated_at = NULL, risk_approval = CASE WHEN risk_approval = 'pending' THEN NULL
                                      ELSE risk_approval END, updated_at = NOW() WHERE id = %s""", (observed, iid))
                _event(cur, iid, account, "scanner", "verified_resolved", status, "resolved",
                       {"evidence": "a scan no longer reports this problem" if state == "passed"
                                    else "a complete scan no longer finds the affected resource",
                        "observed_at": observed})
                continue
        if status == "accepted_risk" and risk_expires_on and risk_expires_on < today:
            cur.execute("""UPDATE critical_issues SET status = 'open', risk_approval = NULL, escalated_at = NULL, due_date = %s,
                           updated_at = NOW() WHERE id = %s""", (today + timedelta(days=settings["sla_days"]), iid))
            _event(cur, iid, account, "system", "risk_acceptance_expired", "accepted_risk", "open",
                   {"expired_on": risk_expires_on})
            continue
        if status in WORKING and due and due < today and not escalated_at and key in failing:
            cur.execute("UPDATE critical_issues SET escalated_at = NOW() WHERE id = %s", (iid,))
            _event(cur, iid, account, "system", "escalated", status, status, {"due_date": due, "reason": "deadline passed"})
            if notify:
                notify(account, title, due, iid)
    return failing


_PENDING_NOTIFICATIONS = []


def _notify_overdue(conn):
    """Escalations are queued and only sent after the request's own changes are committed: create_notification
    manages its own transaction, and a failure there must never roll back the issue history."""
    def queue(account, title, due, iid):
        _PENDING_NOTIFICATIONS.append((account, title, due, iid))
    return queue


def _flush_notifications(conn):
    pending = list(_PENDING_NOTIFICATIONS)
    _PENDING_NOTIFICATIONS.clear()
    for account, title, due, iid in pending:
        try:
            from collectors.aws.scanner.notification_lib import create_notification
            create_notification(conn, account, "security", "critical_issue_overdue", "P1",
                                f"Critical issue overdue: {title[:150]}",
                                f"The remediation deadline ({due}) has passed and the scanner still reports the problem.",
                                resource_link=f"critical_issues.html?account_id={account}&issue_id={iid}", actor="system")
        except Exception:
            # The escalation itself is already in the issue history; a failed notification must not break the page.
            logger.exception("could not create the overdue notification")
            try:
                conn.rollback()
            except Exception:
                pass


# ── posture ──────────────────────────────────────────────────────────────────

def coverage(cur, account, settings):
    """What was assessed, when, and what is missing. Required domains decide whether a zero claim is allowed."""
    fresh_after = _now() - timedelta(days=settings["freshness_days"])
    cur.execute("SELECT status, last_scan_at, account_name FROM cloud_accounts WHERE id = %s", (account,))
    acct = cur.fetchone()
    cur.execute("""SELECT resource_type, count(*), max(last_scanned_at) FROM resources WHERE cloud_account_id = %s
                   GROUP BY 1""", (account,))
    by_type = {t: (n, _aware(ts)) for t, n, ts in cur.fetchall()}
    domains = []

    # Every resource type must have been re-read recently: a scanner that stopped working leaves its rows with an
    # old last_scanned_at. The oldest type decides, and the account-wide IAM evidence must exist at all.
    iam = by_type.get("iam-account")
    stamps = [ts for _n, ts in by_type.values()]
    posture_at = min(stamps) if iam and all(stamps) else None
    oldest_type = min(by_type.items(), key=lambda kv: kv[1][1])[0] if iam and all(stamps) else None
    domains.append({
        "domain": "Cloud posture (AWS configuration)", "required": True,
        "evidence_at": posture_at,
        "state": "missing" if not posture_at else ("stale" if posture_at < fresh_after else "fresh"),
        "detail": ((f"{sum(n for n, _ in by_type.values())} resources across {len(by_type)} resource types; "
                    f"oldest evidence: {oldest_type}") if posture_at
                   else "No complete scan of the account (IAM evidence missing)" if by_type
                   else "No scan has produced results for this account yet"),
        "resource_types": {t: {"resources": n, "last_scanned_at": ts} for t, (n, ts) in sorted(by_type.items())},
    })

    for table, label, required in (("ciem_scans", "Identity & entitlements (CIEM)", True),
                                   ("ai_inventory_scans", "AI assets", False)):
        cur.execute(f"""SELECT status, finished_at, started_at FROM {table} WHERE cloud_account_id = %s
                        AND status <> 'running' ORDER BY started_at DESC LIMIT 1""", (account,))
        r = cur.fetchone()
        cur.execute(f"""SELECT max(finished_at) FROM {table} WHERE cloud_account_id = %s AND status = 'succeeded'""",
                    (account,))
        ok_at = _aware(cur.fetchone()[0])
        if not r:
            state, detail = "missing", "Never scanned"
        elif r[0] == "partial":
            state, detail = "partial", "Last scan could not read every data source, so it cannot support a zero claim"
        elif not ok_at:
            state, detail = "failed", f"Last scan {r[0]}; no successful scan yet"
        elif ok_at < fresh_after:
            state, detail = "stale", f"Last successful scan {ok_at:%Y-%m-%d}"
        else:
            state = "fresh" if r[0] == "succeeded" else "degraded"
            detail = f"Last scan {r[0]}"
        domains.append({"domain": label, "required": required, "evidence_at": ok_at, "state": state, "detail": detail})

    required = [d for d in domains if d["required"]]
    # Only a complete, fresh assessment counts. 'degraded' = the latest attempt failed after an earlier success.
    covered = sum(1 for d in required if d["state"] == "fresh")
    return {
        "account_status": acct[0] if acct else None,
        "account_name": acct[2] if acct else None,
        "last_scan_at": _aware(acct[1]) if acct else None,
        "freshness_days": settings["freshness_days"],
        "domains": domains,
        "required_covered": covered, "required_total": len(required),
        "coverage_pct": round(100 * covered / len(required)) if required else 0,
        "complete": bool(required) and covered == len(required) and bool(acct and acct[0] == "active"),
        "stale": any(d["state"] == "stale" for d in required),
        "not_assessed": ["Code & CI/CD (only GitHub repository settings are scanned)", "Workload runtime",
                         "Data classification (DSPM)", "Kubernetes"],
    }


def _risk(issue, src, settings):
    """Explainable risk score: severity is fixed (critical), risk adds age, scope and recurrence."""
    factors = [{"factor": "Severity: critical (from the scanner)", "points": 70}]
    first = issue.get("first_detected_at")
    if first:
        age = (_now() - first).days
        if age > settings["sla_days"]:
            pts = min(15, 5 + (age - settings["sla_days"]) // 7)
            factors.append({"factor": f"Open for {age} days (deadline policy {settings['sla_days']} days)", "points": pts})
    asset = (src or {}).get("asset") or {}
    if asset.get("type") in ("iam-account", "iam-identity"):
        factors.append({"factor": "Affects identity and access for the whole account", "points": 10})
    if issue.get("reopen_count"):
        factors.append({"factor": f"Came back {issue['reopen_count']} time(s) after being resolved",
                        "points": min(10, 5 * issue["reopen_count"])})
    if not issue.get("owner_email"):
        factors.append({"factor": "No accountable owner", "points": 5})
    return min(100, sum(f["points"] for f in factors)), factors


def posture(counts, cov):
    """The customer-facing zero-critical status, with the reason it was chosen."""
    open_n, in_prog, verify, accepted = counts["open"], counts["in_progress"], counts["verification_pending"], counts["accepted"]
    if open_n + in_prog > 0:
        status = "remediation_in_progress" if in_prog else "critical_issues_present"
        reason = f"{open_n + in_prog} unresolved critical issue(s)" + (f", {in_prog} being remediated" if in_prog else "")
    elif verify:
        status, reason = "validation_required", f"{verify} issue(s) marked as fixed, waiting for a scan to confirm"
    elif cov["stale"]:
        status, reason = "evidence_stale", f"Evidence older than {cov['freshness_days']} days cannot support a current claim"
    elif not cov["complete"]:
        missing = [d["domain"] + " (" + d["state"] + ")" for d in cov["domains"] if d["required"] and d["state"] != "fresh"]
        status, reason = "coverage_incomplete", "Not assessed: " + ", ".join(missing)
    elif accepted:
        status, reason = "accepted_risk", f"No unresolved critical issues, but {accepted} accepted under an approved exception"
    else:
        status, reason = "zero_critical", "No unresolved critical findings within the assessed scope, with fresh evidence"
    return {"status": status, "reason": reason, "verified_zero": status == "zero_critical"}


def _issue_rows(cur, account, ids=None):
    cur.execute(f"""SELECT id, source, source_id, title, status, owner_email, due_date, remediation_plan, first_detected_at,
                           last_observed_at, remediated_at, remediated_by, resolved_at, verified_by_scan_at, reopen_count,
                           escalated_at, risk_justification, risk_rationale, risk_owner, risk_approver, compensating_controls,
                           residual_risk, risk_expires_on, risk_review_every_days, risk_approval, risk_requested_by,
                           risk_requested_at, risk_decided_at, false_positive_evidence, created_at, updated_at
                    FROM critical_issues WHERE cloud_account_id = %s {"AND id = ANY(%s::uuid[])" if ids else ""}
                    ORDER BY created_at""", (account, ids) if ids else (account,))
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def _display_status(issue):
    if issue["status"] == "remediated":
        return "verification_pending"
    return issue["status"]


def _enrich(issues, failing, settings):
    today = date.today()
    out = []
    for i in issues:
        src = failing.get((i["source"], str(i["source_id"])))
        score, factors = _risk(i, src, settings)
        unresolved = i["status"] in UNRESOLVED
        out.append({
            **{k: v for k, v in i.items() if k not in ("source_id",)},
            "id": str(i["id"]), "source_id": str(i["source_id"]),
            "source_label": SOURCE_LABEL[i["source"]], "source_page": SOURCE_PAGE[i["source"]],
            "display_status": _display_status(i),
            "still_reported": src is not None,
            "asset": (src or {}).get("asset"), "check_id": (src or {}).get("check_id"),
            "framework": (src or {}).get("framework"),
            "overdue": bool(unresolved and i["status"] != "remediated" and i["due_date"] and i["due_date"] < today),
            "age_days": (_now() - i["first_detected_at"]).days if i["first_detected_at"] else None,
            "risk_score": score if unresolved else None, "risk_factors": factors if unresolved else [],
            "pending_risk_request": i["risk_approval"] == "pending",
        })
    return out


def _counts(enriched):
    c = {"open": 0, "in_progress": 0, "verification_pending": 0, "accepted": 0, "resolved": 0, "reopened": 0,
         "false_positive": 0, "overdue": 0, "unassigned": 0, "without_plan": 0, "new_7d": 0, "escalated": 0}
    week = _now() - timedelta(days=7)
    for i in enriched:
        s = i["status"]
        if s in ("open", "assigned", "reopened"):
            c["open"] += 1
        elif s == "in_progress":
            c["in_progress"] += 1
        elif s == "remediated":
            c["verification_pending"] += 1
        elif s == "accepted_risk":
            c["accepted"] += 1
        elif s == "resolved":
            c["resolved"] += 1
        elif s == "false_positive":
            c["false_positive"] += 1
        if s == "reopened":
            c["reopened"] += 1
        if s in UNRESOLVED:
            c["overdue"] += 1 if i["overdue"] else 0
            c["unassigned"] += 0 if i["owner_email"] else 1
            c["without_plan"] += 0 if i["remediation_plan"] else 1
            c["escalated"] += 1 if i["escalated_at"] else 0
        if i["created_at"] and i["created_at"] >= week:
            c["new_7d"] += 1
    return c


def _metrics(cur, account, enriched):
    resolved = [i for i in enriched if i["status"] == "resolved" and i["resolved_at"] and i["first_detected_at"]]
    mttr = (sum((i["resolved_at"] - i["first_detected_at"]).total_seconds() for i in resolved) / len(resolved) / 86400
            if resolved else None)
    open_ages = [i["age_days"] for i in enriched if i["status"] in UNRESOLVED and i["age_days"] is not None]
    cur.execute("""SELECT count(*) FILTER (WHERE event = 'verified_resolved'), count(*) FILTER (WHERE event = 'verification_failed'),
                          count(*) FILTER (WHERE event = 'reopened')
                   FROM critical_issue_events WHERE cloud_account_id = %s""", (account,))
    ok, failed, reopened = cur.fetchone()
    attempts = ok + failed
    ever_resolved = ok
    return {
        "mean_time_to_remediate_days": round(mttr, 1) if mttr is not None else None,
        "oldest_open_days": max(open_ages) if open_ages else None,
        "remediation_success_rate_pct": round(100 * ok / attempts) if attempts else None,
        "recurrence_rate_pct": round(100 * reopened / ever_resolved) if ever_resolved else None,
        "verified_resolutions": ok, "failed_verifications": failed, "reopen_events": reopened,
    }


def _snapshot(cur, account, pst, counts, cov):
    cur.execute("""INSERT INTO critical_posture_snapshots (cloud_account_id, day, status, open_critical, accepted_critical,
                                                           overdue_critical, evidence)
                   VALUES (%s, CURRENT_DATE, %s, %s, %s, %s, %s)
                   ON CONFLICT (cloud_account_id, day) DO UPDATE SET status = EXCLUDED.status,
                       open_critical = EXCLUDED.open_critical, accepted_critical = EXCLUDED.accepted_critical,
                       overdue_critical = EXCLUDED.overdue_critical, evidence = EXCLUDED.evidence, recorded_at = NOW()""",
                (account, pst["status"], counts["open"] + counts["in_progress"], counts["accepted"], counts["overdue"],
                 Json({"coverage_pct": cov["coverage_pct"], "last_scan_at": cov["last_scan_at"], "reason": pst["reason"],
                       "verification_pending": counts["verification_pending"]},
                      dumps=lambda o: json.dumps(o, default=str))))


def _source_accepted(cur, account):
    """Critical findings accepted inside CIEM / AI Inventory: shown with accepted risks, never hidden."""
    out = []
    for table, label in (("ciem_findings", "CIEM"), ("ai_inventory_findings", "AI Inventory")):
        cur.execute(f"""SELECT id, title, status_reason, status_by, accepted_until FROM {table}
                        WHERE cloud_account_id = %s AND severity = 'critical' AND status = 'accepted'
                          AND accepted_until >= CURRENT_DATE""", (account,))
        out += [{"id": str(r[0]), "title": r[1], "reason": r[2], "accepted_by": r[3], "until": r[4], "module": label}
                for r in cur.fetchall()]
    return out


def view_overview(conn, cur, account):
    settings = _settings(cur, account)
    failing = sync_issues(cur, account, settings, _notify_overdue(conn))
    enriched = _enrich(_issue_rows(cur, account), failing, settings)
    counts = _counts(enriched)
    src_accepted = _source_accepted(cur, account)
    counts["accepted"] += len(src_accepted)
    cov = coverage(cur, account, settings)
    pst = posture(counts, cov)
    _snapshot(cur, account, pst, counts, cov)
    by_domain, by_asset = {}, {}
    for i in enriched:
        if i["status"] in UNRESOLVED:
            by_domain[i["source_label"]] = by_domain.get(i["source_label"], 0) + 1
            t = (i.get("asset") or {}).get("type") or "unknown"
            by_asset[t] = by_asset.get(t, 0) + 1
    top = sorted([i for i in enriched if i["status"] in UNRESOLVED], key=lambda i: -(i["risk_score"] or 0))[:5]
    return {
        "posture": pst, "counts": counts, "coverage": cov, "metrics": _metrics(cur, account, enriched),
        "by_domain": by_domain, "by_asset_type": by_asset, "top": top, "settings": settings,
        "accepted_in_modules": src_accepted,
        "scope": {"cloud_account_id": account, "account_name": cov["account_name"], "provider": "AWS",
                  "sources": list(SOURCE_LABEL.values()),
                  "rule": "Critical = severity CRITICAL reported by a Niagaros scanner. Per-framework copies of the same "
                          "misconfiguration are counted once."},
        "calculated_at": _now(),
    }


def view_issues(conn, cur, account, qs):
    settings = _settings(cur, account)
    failing = sync_issues(cur, account, settings, _notify_overdue(conn))
    enriched = _enrich(_issue_rows(cur, account), failing, settings)
    st = (qs.get("status") or "").strip()
    if st == "unresolved":
        enriched = [i for i in enriched if i["status"] in UNRESOLVED]
    elif st:
        enriched = [i for i in enriched if i["display_status"] == st]
    owner = (qs.get("owner") or "").strip().lower()
    if owner == "none":
        enriched = [i for i in enriched if not i["owner_email"]]
    elif owner:
        enriched = [i for i in enriched if (i["owner_email"] or "").lower() == owner]
    if (qs.get("source") or "") in SOURCE_LABEL:
        enriched = [i for i in enriched if i["source"] == qs["source"]]
    if qs.get("overdue") == "1":
        enriched = [i for i in enriched if i["overdue"]]
    enriched.sort(key=lambda i: (i["status"] not in UNRESOLVED, -(i["risk_score"] or 0), str(i["created_at"])))
    return {"issues": enriched, "settings": settings}


def view_issue(conn, cur, account, issue_id):
    settings = _settings(cur, account)
    failing = sync_issues(cur, account, settings, _notify_overdue(conn))
    rows = _issue_rows(cur, account, [issue_id])
    if not rows:
        raise BadRequest(404, "Issue not found")
    issue = _enrich(rows, failing, settings)[0]
    src = failing.get((issue["source"], issue["source_id"]))
    cur.execute("""SELECT at, actor, event, from_status, to_status, detail FROM critical_issue_events
                   WHERE issue_id = %s ORDER BY at""", (issue_id,))
    history = [{"at": a, "actor": b, "event": c, "from": d, "to": e, "detail": f} for a, b, c, d, e, f in cur.fetchall()]
    return {"issue": issue, "evidence": (src or {}).get("evidence"), "description": (src or {}).get("description"),
            "recommendation": (src or {}).get("recommendation"),
            "recommendation_detail": (src or {}).get("recommendation_detail"), "history": history}


def view_history(cur, account):
    cur.execute("""SELECT day, status, open_critical, accepted_critical, overdue_critical, evidence FROM critical_posture_snapshots
                   WHERE cloud_account_id = %s ORDER BY day DESC LIMIT 180""", (account,))
    snaps = [{"day": a, "status": b, "open": c, "accepted": d, "overdue": e, "evidence": f} for a, b, c, d, e, f in cur.fetchall()]
    cur.execute("""SELECT e.at, e.actor, e.event, e.from_status, e.to_status, i.title, e.issue_id FROM critical_issue_events e
                   JOIN critical_issues i ON i.id = e.issue_id WHERE e.cloud_account_id = %s ORDER BY e.at DESC LIMIT 300""",
                (account,))
    events = [{"at": a, "actor": b, "event": c, "from": d, "to": e, "title": f, "issue_id": str(g)}
              for a, b, c, d, e, f, g in cur.fetchall()]
    return {"snapshots": snaps, "events": events}


def view_export(conn, cur, account, fmt):
    ov = view_overview(conn, cur, account)
    issues = view_issues(conn, cur, account, {})["issues"]
    if fmt == "json":
        return {"exported_at": _now(), "overview": ov, "issues": issues}
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["id", "title", "source_label", "check_id", "display_status", "risk_score", "owner_email", "due_date", "overdue",
            "first_detected_at", "last_observed_at", "resolved_at", "verified_by_scan_at", "reopen_count", "escalated_at",
            "remediation_plan", "risk_justification", "risk_owner", "risk_approver", "risk_expires_on"]
    w.writerow(cols + ["asset_type", "asset_name"])
    for i in issues:
        a = i.get("asset") or {}
        w.writerow([_csv_cell(i.get(c)) for c in cols] + [_csv_cell(a.get("type")), _csv_cell(a.get("name"))])
    w.writerow([])
    w.writerow(["zero_critical_status", ov["posture"]["status"], ov["posture"]["reason"]])
    w.writerow(["coverage_pct", ov["coverage"]["coverage_pct"], "calculated_at", ov["calculated_at"]])
    return buf.getvalue()


def view_portfolio(cur, email):
    cur.execute("SELECT id FROM cloud_accounts")
    ids = [str(r[0]) for r in cur.fetchall()]
    if not ids:
        return {"accounts": []}
    cur.execute(ACCESS_SQL, {"ids": ids, "email": email, "write": False})
    allowed = [str(r[0]) for r in cur.fetchall()]
    if not allowed:
        return {"accounts": []}
    cur.execute("""
        SELECT c.id, c.account_name, c.status, c.last_scan_at,
               (SELECT string_agg(DISTINCT b.name, ', ') FROM bu_accounts ba JOIN business_units b ON b.id = ba.business_unit_id
                  JOIN organizations o ON o.id = b.organization_id
                  LEFT JOIN org_members m ON m.organization_id = o.id AND lower(m.email) = lower(%s)
                 WHERE ba.cloud_account_id = c.id
                   AND (lower(o.owner_email) = lower(%s)
                        OR (m.id IS NOT NULL AND (m.business_unit_id IS NULL OR m.business_unit_id = b.id)))) AS units,
               (SELECT status FROM critical_posture_snapshots s WHERE s.cloud_account_id = c.id ORDER BY day DESC LIMIT 1),
               (SELECT count(*) FROM critical_issues i WHERE i.cloud_account_id = c.id AND i.status IN %s),
               (SELECT count(*) FROM critical_issues i WHERE i.cloud_account_id = c.id AND i.status = 'accepted_risk')
        FROM cloud_accounts c WHERE c.id = ANY(%s::uuid[]) ORDER BY c.account_name
    """, (email, email, UNRESOLVED, allowed))
    return {"accounts": [{"cloud_account_id": str(a), "account_name": b, "account_status": c, "last_scan_at": d,
                          "business_units": e, "last_status": f, "unresolved": g, "accepted": h}
                         for a, b, c, d, e, f, g, h in cur.fetchall()],
            "note": "Counts are as of the last time each account's critical-issue view was opened (daily snapshot)."}


# ── writes ───────────────────────────────────────────────────────────────────

def _load(cur, account, issue_id):
    if not isinstance(issue_id, str) or not UUID_RE.match(issue_id):
        raise BadRequest(404, "Issue not found")
    _lock(cur, account)
    cur.execute("""SELECT status, risk_requested_by, risk_approval, owner_email, risk_expires_on FROM critical_issues
                   WHERE id = %s AND cloud_account_id = %s FOR UPDATE""", (issue_id, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "Issue not found")
    return {"status": r[0], "risk_requested_by": r[1], "risk_approval": r[2], "owner_email": r[3], "risk_expires_on": r[4]}


def _set_status(cur, account, issue_id, actor, cur_status, new_status, event, detail=None, extra_sql="", extra_args=()):
    cur.execute(f"UPDATE critical_issues SET status = %s, updated_at = NOW() {extra_sql} WHERE id = %s",
                (new_status, *extra_args, issue_id))
    _event(cur, issue_id, account, actor, event, cur_status, new_status, detail)


def do_action(cur, account, actor, body):
    action = body.get("action")
    if action == "save_settings":
        try:
            sla, fresh = int(body.get("sla_days")), int(body.get("freshness_days"))
        except (TypeError, ValueError):
            raise BadRequest(400, "Deadline and freshness must be whole numbers of days")
        if not (1 <= sla <= 90) or not (1 <= fresh <= 60):
            raise BadRequest(400, "Deadline must be 1–90 days and evidence freshness 1–60 days")
        cur.execute("""INSERT INTO critical_issue_settings (cloud_account_id, sla_days, freshness_days, updated_by)
                       VALUES (%s, %s, %s, %s) ON CONFLICT (cloud_account_id) DO UPDATE SET sla_days = EXCLUDED.sla_days,
                       freshness_days = EXCLUDED.freshness_days, updated_by = EXCLUDED.updated_by, updated_at = NOW()""",
                    (account, sla, fresh, actor))
        return {"saved": True, "note": "New deadlines apply to issues detected from now on."}

    issue_id = body.get("issue_id")
    it = _load(cur, account, issue_id)
    st = it["status"]
    if action == "assign":
        owner = _text(body, "owner_email", "Owner", max_len=320).lower()
        if not EMAIL_RE.match(owner):
            raise BadRequest(400, "Owner must be an email address")
        if not account_allowed(cur, owner, account):
            raise BadRequest(400, "The owner must be someone with access to this cloud account")
        due = _date(body, "due_date", "Deadline", required=False, min_day=date.today(), max_days_ahead=365)
        if st not in WORKING:
            raise BadRequest(409, "Only an unresolved issue can be assigned")
        new = "assigned" if st in ("open", "reopened") else st
        if due:
            # A new deadline restarts escalation for it.
            cur.execute("UPDATE critical_issues SET owner_email = %s, due_date = %s, escalated_at = NULL WHERE id = %s",
                        (owner, due, issue_id))
        else:
            cur.execute("UPDATE critical_issues SET owner_email = %s WHERE id = %s", (owner, issue_id))
        _set_status(cur, account, issue_id, actor, st, new, "assigned", {"owner": owner, "due_date": due})
    elif action == "set_plan":
        plan = _text(body, "remediation_plan", "Remediation plan")
        if st not in UNRESOLVED:
            raise BadRequest(409, "This issue is not open")
        cur.execute("UPDATE critical_issues SET remediation_plan = %s, updated_at = NOW() WHERE id = %s", (plan, issue_id))
        _event(cur, issue_id, account, actor, "plan_updated", st, st, {"plan": plan[:500]})
    elif action == "start":
        if st not in ("open", "assigned", "reopened"):
            raise BadRequest(409, "Remediation can only start on an open issue")
        _set_status(cur, account, issue_id, actor, st, "in_progress", "remediation_started")
    elif action == "mark_remediated":
        note = _text(body, "note", "What was changed", max_len=2000)
        if st not in WORKING:
            raise BadRequest(409, "Only an unresolved issue can be marked as fixed")
        _set_status(cur, account, issue_id, actor, st, "remediated", "remediated", {"note": note},
                    ", remediated_at = NOW(), remediated_by = %s", (actor,))
        return {"saved": True, "note": "Marked as fixed. It counts as resolved only after the next scan confirms it."}
    elif action == "request_risk_acceptance":
        if st not in WORKING:
            raise BadRequest(409, "Only an unresolved issue can be accepted as a risk")
        if it["risk_approval"] == "pending":
            raise BadRequest(409, "A risk acceptance request is already waiting for approval")
        fields = {
            "risk_justification": _text(body, "justification", "Business justification"),
            "risk_rationale": _text(body, "rationale", "Technical rationale"),
            "risk_owner": _text(body, "risk_owner", "Risk owner", max_len=320),
            "compensating_controls": _text(body, "compensating_controls", "Compensating controls"),
            "residual_risk": _text(body, "residual_risk", "Residual risk"),
        }
        expires = _date(body, "expires_on", "Expiry date", min_day=date.today() + timedelta(days=1), max_days_ahead=365)
        try:
            review = int(body.get("review_every_days") or 90)
        except (TypeError, ValueError):
            raise BadRequest(400, "Review interval must be a number of days")
        if review not in (30, 60, 90, 180):
            raise BadRequest(400, "Review interval must be 30, 60, 90 or 180 days")
        cur.execute("""UPDATE critical_issues SET risk_justification = %s, risk_rationale = %s, risk_owner = %s,
                              compensating_controls = %s, residual_risk = %s, risk_expires_on = %s, risk_review_every_days = %s,
                              risk_approval = 'pending', risk_requested_by = %s, risk_requested_at = NOW(),
                              risk_approver = NULL, risk_decided_at = NULL, updated_at = NOW() WHERE id = %s""",
                    (*fields.values(), expires, review, actor, issue_id))
        _event(cur, issue_id, account, actor, "risk_acceptance_requested", st, st, {**fields, "expires_on": expires})
        return {"saved": True, "note": "Request recorded. Another person with write access must approve it."}
    elif action == "decide_risk":
        decision = body.get("decision")
        if decision not in ("approve", "reject"):
            raise BadRequest(400, "Decision must be approve or reject")
        if it["risk_approval"] != "pending":
            raise BadRequest(409, "There is no pending risk acceptance request")
        if (it["risk_requested_by"] or "").lower() == actor.lower():
            raise BadRequest(403, "The person who requested the exception cannot approve it")
        if decision == "approve" and st not in WORKING:
            raise BadRequest(409, "This issue is no longer open, so the exception is not needed")
        if decision == "approve" and (not it["risk_expires_on"] or it["risk_expires_on"] <= date.today()):
            raise BadRequest(409, "This exception has already expired; ask for a new request")
        note = _text(body, "note", "Note", required=False, max_len=2000)
        if decision == "approve":
            _set_status(cur, account, issue_id, actor, st, "accepted_risk", "risk_accepted", {"note": note},
                        ", risk_approval = 'approved', risk_approver = %s, risk_decided_at = NOW()", (actor,))
        else:
            cur.execute("UPDATE critical_issues SET risk_approval = 'rejected', risk_approver = %s, risk_decided_at = NOW() WHERE id = %s",
                        (actor, issue_id))
            _event(cur, issue_id, account, actor, "risk_rejected", st, st, {"note": note})
    elif action == "mark_false_positive":
        evidence = _text(body, "evidence", "Supporting evidence")
        if st not in WORKING:
            raise BadRequest(409, "Only an unresolved issue can be marked as a false positive")
        _set_status(cur, account, issue_id, actor, st, "false_positive", "marked_false_positive", {"evidence": evidence},
                    ", false_positive_evidence = %s, risk_approval = CASE WHEN risk_approval = 'pending' THEN NULL ELSE risk_approval END",
                    (evidence,))
    elif action == "reopen":
        reason = _text(body, "reason", "Reason", max_len=2000)
        if st not in ("accepted_risk", "false_positive"):
            raise BadRequest(409, "Only an accepted risk or a false positive can be reopened by hand")
        _set_status(cur, account, issue_id, actor, st, "open", "reopened_by_user", {"reason": reason},
                    ", risk_approval = NULL, false_positive_evidence = NULL")
    else:
        raise BadRequest(400, "Unknown action")
    return {"saved": True}


# ── entry point ─────────────────────────────────────────────────────────────

def handler(event, context):
    method = (event or {}).get("httpMethod") or ((event or {}).get("requestContext") or {}).get("http", {}).get("method") or "GET"
    if method == "OPTIONS":
        return _resp(200, {})
    qs = (event or {}).get("queryStringParameters") or {}
    body = {}
    if method == "POST":
        try:
            body = json.loads((event or {}).get("body") or "{}")
        except (TypeError, ValueError):
            return _resp(400, {"error": "Invalid request"})
        if not isinstance(body, dict):
            return _resp(400, {"error": "Invalid request"})
    conn = None
    _PENDING_NOTIFICATIONS.clear()
    try:
        conn = _get_connection()
        denied = guard(event, conn, qs, body, REFS)
        if denied:
            return _resp(denied[0], {"error": denied[1]})
        email = authenticate(event) if os.environ.get("TENANT_AUTH_ENFORCE", "1") != "0" else "unknown"
        if not email:
            return _resp(401, {"error": "Unauthorized"})
        with conn.cursor() as cur:
            if method == "GET" and qs.get("view") == "portfolio":
                return _resp(200, view_portfolio(cur, email))
            account = (body if method == "POST" else qs).get("cloud_account_id")
            if not isinstance(account, str) or not UUID_RE.match(account):
                return _resp(400, {"error": "cloud_account_id is required"})
            if method == "POST":
                result = do_action(cur, account, email, body)
                conn.commit()
                return _resp(200, result)
            view = qs.get("view") or "overview"
            if view == "overview":
                result = view_overview(conn, cur, account)
            elif view == "issues":
                result = view_issues(conn, cur, account, qs)
            elif view == "issue":
                iid = qs.get("issue_id")
                if not isinstance(iid, str) or not UUID_RE.match(iid):
                    return _resp(404, {"error": "Issue not found"})
                result = view_issue(conn, cur, account, iid)
            elif view == "history":
                result = view_history(cur, account)
            elif view == "settings":
                result = _settings(cur, account)
            elif view == "export":
                fmt = qs.get("format") if qs.get("format") in ("csv", "json") else "csv"
                result = view_export(conn, cur, account, fmt)
                conn.commit()
                _flush_notifications(conn)
                if fmt == "csv":
                    return _resp(200, result, {"Content-Type": "text/csv",
                                               "Content-Disposition": "attachment; filename=critical-issues.csv"})
                return _resp(200, result)
            else:
                return _resp(400, {"error": "Unknown view"})
            conn.commit()
            _flush_notifications(conn)
            return _resp(200, result)
    except BadRequest as e:
        if conn:
            conn.rollback()
        return _resp(e.status, {"error": e.message})
    except Exception:
        logger.exception("critical issues request failed")
        if conn:
            conn.rollback()
        return _resp(500, {"error": "Something went wrong while loading critical issues. Please try again."})
    finally:
        if conn:
            conn.close()
