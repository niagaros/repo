"""
cost_handler.py — Niagaros Cloud Cost API (issue #295). One Lambda behind GET/POST /cloud-cost, guarded by
tenant_auth.guard (account owner or authorised org / business-unit member; writes need a write role).

GET  /cloud-cost?cloud_account_id=...&view=
       overview | explorer&group=service|record_type|tag|day&from=&to= | opportunities | opportunity&opportunity_id=
       | budgets | alerts | commitments | ai | kubernetes | ingestions | audit | export&what=daily|opportunities&format=csv|json
GET  /cloud-cost?view=portfolio                 month-to-date per account and business unit the caller may see
POST /cloud-cost {cloud_account_id, action, ...}
       enable {accept_charges: true} | disable | refresh | save_settings {allocation_tag_key, anomaly_min_amount}
       create_budget {name, monthly_amount, thresholds, forecast_alert} | update_budget {budget_id, ...} | archive_budget
       acknowledge_alert / resolve_alert {alert_id, note}
       request_approval / decide_opportunity {decision} / mark_executed {note} / dismiss {reason} / restore
       {opportunity_id}

All numbers come from what the cost scanner stored; nothing is estimated here except where the response says so.
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

from collectors.aws.scanner import cost_engine as E
from collectors.aws.scanner.tenant_auth import ACCESS_SQL, authenticate, guard

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
SCANNER = os.environ.get("COST_SCANNER_FUNCTION", "cloud-cost-scanner")
CORS = {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization"}
REFS = {
    "opportunity_id": "SELECT cloud_account_id FROM cost_opportunities WHERE id = %s",
    "budget_id": "SELECT cloud_account_id FROM cost_budgets WHERE id = %s",
    "alert_id": "SELECT cloud_account_id FROM cost_alerts WHERE id = %s",
}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
TAG_RE = re.compile(r"^[\w .:/=+@-]{1,128}$")
REFRESH_MIN_MINUTES = 60
CE_REQUESTS_PER_RUN = "about 8"
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
_J = lambda o: Json(o, dumps=lambda x: json.dumps(x, default=str))  # noqa: E731


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


def _text(body, key, what, required=True, max_len=2000):
    v = body.get(key)
    if v is None or (isinstance(v, str) and not v.strip()):
        if required:
            raise BadRequest(400, f"{what} is required")
        return None
    if not isinstance(v, str):
        raise BadRequest(400, f"{what} must be text")
    v = v.strip()
    if len(v) > max_len:
        raise BadRequest(400, f"{what} is too long")
    return v


def _audit(cur, account, actor, action, target=None, details=None):
    cur.execute("INSERT INTO cost_audit_log (cloud_account_id, actor_email, action, target, details) VALUES (%s, %s, %s, %s, %s)",
                (account, actor, action, target, _J(details or {})))


def _settings(cur, account):
    cur.execute("""SELECT enabled, enabled_by, enabled_at, allocation_tag_key, anomaly_min_amount, updated_by, updated_at
                   FROM cost_settings WHERE cloud_account_id = %s""", (account,))
    r = cur.fetchone()
    if not r:
        return {"enabled": False, "enabled_by": None, "enabled_at": None, "allocation_tag_key": None,
                "anomaly_min_amount": 5.0, "updated_by": None, "updated_at": None}
    return {"enabled": r[0], "enabled_by": r[1], "enabled_at": r[2], "allocation_tag_key": r[3],
            "anomaly_min_amount": float(r[4]), "updated_by": r[5], "updated_at": r[6]}


def _latest_ingestion(cur, account, ok_only=False):
    cur.execute(f"""SELECT id, status, started_at, finished_at, trigger, ce_requests, coverage, error, period_start, period_end
                    FROM cost_ingestions WHERE cloud_account_id = %s
                    {"AND status IN ('succeeded', 'partial')" if ok_only else ""} ORDER BY started_at DESC LIMIT 1""", (account,))
    r = cur.fetchone()
    if not r:
        return None
    return {"id": str(r[0]), "status": r[1], "started_at": r[2], "finished_at": r[3], "trigger": r[4], "ce_requests": r[5],
            "coverage": r[6], "error": r[7], "period_start": r[8], "period_end": r[9]}


def _current_forecast(cur, account, today, cols):
    """The forecast made by the LATEST successful ingestion, for a period starting on the day that ingestion ran.
    An older forecast would overlap actual cost ingested since and count it twice, so then there is no forecast."""
    cur.execute(f"""SELECT {cols} FROM cost_forecasts f
                    WHERE f.ingestion_id = (SELECT id FROM cost_ingestions WHERE cloud_account_id = %s
                                              AND status IN ('succeeded', 'partial') ORDER BY started_at DESC LIMIT 1)
                      AND f.period_start = %s AND f.period_end > %s""", (account, today, today))
    return cur.fetchone()


def _records(cur, account, start, end=None, services=None):
    sql = """SELECT day, service, record_type, amount, estimated, currency FROM cost_daily
             WHERE cloud_account_id = %s AND day >= %s"""
    args = [account, start]
    if end:
        sql += " AND day < %s"
        args.append(end)
    if services:
        sql += " AND service = ANY(%s)"
        args.append(list(services))
    cur.execute(sql, args)
    return [{"day": d, "service": s, "record_type": t, "amount": float(a), "estimated": e, "currency": c}
            for d, s, t, a, e, c in cur.fetchall()]


def _security_by_service(cur, account, services):
    """Open security findings on the resources behind each billed service (cost next to risk)."""
    out = {}
    types = {s: E.SERVICE_TO_RESOURCE_TYPES[s] for s in services if s in E.SERVICE_TO_RESOURCE_TYPES}
    if not types:
        return out
    cur.execute("""SELECT r.resource_type, upper(f.severity), count(*) FROM findings f JOIN resources r ON r.id = f.resource_id
                   WHERE r.cloud_account_id = %s AND f.status = 'open'
                     AND (f.framework IS NULL OR NOT (f.framework = ANY(%s)))
                   GROUP BY 1, 2""", (account, list(_mapped())))
    by_type = {}
    for t, sev, n in cur.fetchall():
        by_type.setdefault(t, {})[sev] = n
    for svc, rtypes in types.items():
        agg = {}
        for t in rtypes:
            for sev, n in (by_type.get(t) or {}).items():
                agg[sev] = agg.get(sev, 0) + n
        out[svc] = agg
    return out


def _mapped():
    from collectors.aws.scanner.critical_issues_handler import MAPPED_FRAMEWORK_NAMES
    return MAPPED_FRAMEWORK_NAMES


# ── views ───────────────────────────────────────────────────────────────────

def view_overview(cur, account):
    settings = _settings(cur, account)
    today = date.today()
    latest = _latest_ingestion(cur, account)
    ok = _latest_ingestion(cur, account, ok_only=True)
    recs = _records(cur, account, today - timedelta(days=E_HISTORY))
    summary = E.summarize(recs, today)
    f = _current_forecast(cur, account, today, "mean_amount, currency, period_start, period_end, created_at")
    forecast = None
    if f:
        forecast = {"remaining_month": round(float(f[0]), 2), "currency": f[1], "from": f[2], "to": f[3], "made_at": f[4],
                    "month_total": round(summary["month_to_date"] + float(f[0]), 2),
                    "basis": "AWS Cost Explorer forecast for the rest of the month + month to date"}
    cur.execute("""SELECT count(*) FILTER (WHERE status = 'open'), count(*) FILTER (WHERE status = 'acknowledged')
                   FROM cost_alerts WHERE cloud_account_id = %s""", (account,))
    open_alerts, ack_alerts = cur.fetchone()
    cur.execute("""SELECT count(*) FILTER (WHERE status <> 'verified'),
                          COALESCE(sum(monthly_savings) FILTER (WHERE status <> 'verified'), 0),
                          count(*) FILTER (WHERE monthly_savings IS NULL AND status <> 'verified'),
                          COALESCE(sum(baseline_monthly) FILTER (WHERE status = 'verified'), 0)
                   FROM cost_opportunities WHERE cloud_account_id = %s AND status IN ('observed', 'approval_requested', 'approved', 'executed', 'verified')""",
                (account,))
    n_opp, savings, unknown, verified = cur.fetchone()
    alloc = None
    if settings["allocation_tag_key"]:
        cur.execute("""SELECT tag_value, sum(amount) FROM cost_allocation_daily WHERE cloud_account_id = %s AND tag_key = %s
                       AND day >= %s GROUP BY 1 ORDER BY 2 DESC""", (account, settings["allocation_tag_key"], today.replace(day=1)))
        rows = [{"value": v or None, "amount": round(float(a), 2)} for v, a in cur.fetchall()]
        total = sum(r["amount"] for r in rows)
        un = sum(r["amount"] for r in rows if r["value"] is None)
        alloc = {"tag_key": settings["allocation_tag_key"], "values": rows,
                 "unallocated": round(un, 2), "unallocated_pct": round(100 * un / total, 1) if total else None}
    top = summary["by_service"][:12]
    sec = _security_by_service(cur, account, [s["service"] for s in top])
    for s in top:
        s["open_findings"] = sec.get(s["service"])
    return {
        "settings": settings, "latest_ingestion": latest, "last_successful_ingestion": ok,
        "summary": {**summary, "by_service": top}, "forecast": forecast,
        "alerts": {"open": open_alerts, "acknowledged": ack_alerts},
        "opportunities": {"count": n_opp, "monthly_savings_known": round(float(savings), 2), "savings_unknown": unknown,
                          "verified_monthly_savings": round(float(verified), 2)},
        "allocation": alloc,
        "freshness": {"latest_day_with_data": summary["latest_day_with_data"],
                      "note": "AWS billing data arrives with a delay of up to 24 hours; recent days are AWS estimates until the bill is final."},
        "charges_note": f"Each refresh makes {CE_REQUESTS_PER_RUN} AWS Cost Explorer requests, billed by AWS to this account at $0.01 each.",
    }


E_HISTORY = 90


def view_explorer(cur, account, qs):
    group = qs.get("group") or "service"
    try:
        start = date.fromisoformat(qs.get("from")) if qs.get("from") else date.today() - timedelta(days=30)
        end = date.fromisoformat(qs.get("to")) if qs.get("to") else date.today() + timedelta(days=1)
    except ValueError:
        raise BadRequest(400, "Dates must be YYYY-MM-DD")
    if end <= start or (end - start).days > 400:
        raise BadRequest(400, "Choose a range of at most 400 days")
    if group == "tag":
        s = _settings(cur, account)
        if not s["allocation_tag_key"]:
            raise BadRequest(400, "Choose a cost-allocation tag in Settings first")
        cur.execute("""SELECT tag_value, sum(amount), bool_or(estimated) FROM cost_allocation_daily WHERE cloud_account_id = %s
                       AND tag_key = %s AND day >= %s AND day < %s GROUP BY 1 ORDER BY 2 DESC""",
                    (account, s["allocation_tag_key"], start, end))
        rows = [{"key": v or "(untagged — unallocated)", "amount": round(float(a), 2), "estimated": e} for v, a, e in cur.fetchall()]
        return {"group": group, "from": start, "to": end, "rows": rows, "tag_key": s["allocation_tag_key"]}
    col = {"service": "service", "record_type": "record_type", "day": "day"}.get(group)
    if not col:
        raise BadRequest(400, "Unknown grouping")
    cur.execute(f"""SELECT {col}, sum(amount), bool_or(estimated), max(currency) FROM cost_daily WHERE cloud_account_id = %s
                    AND day >= %s AND day < %s GROUP BY 1 ORDER BY {"1" if col == "day" else "2 DESC"}""", (account, start, end))
    rows = [{"key": k, "amount": round(float(a), 4 if col == "day" else 2), "estimated": e, "currency": c}
            for k, a, e, c in cur.fetchall()]
    return {"group": group, "from": start, "to": end, "rows": rows, "total": round(sum(r["amount"] for r in rows), 2)}


def view_opportunities(cur, account):
    cur.execute("""SELECT id, kind, region, resource_id, title, monthly_savings, savings_basis, confidence, risk, status,
                          requested_by, approved_by, executed_by, executed_at, verified_at, first_seen, last_seen
                   FROM cost_opportunities WHERE cloud_account_id = %s ORDER BY
                   CASE status WHEN 'observed' THEN 0 WHEN 'approval_requested' THEN 1 WHEN 'approved' THEN 2 WHEN 'executed' THEN 3
                   WHEN 'verified' THEN 4 ELSE 5 END, monthly_savings DESC NULLS LAST""", (account,))
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    for r in rows:
        r["id"] = str(r["id"])
        r["monthly_savings"] = float(r["monthly_savings"]) if r["monthly_savings"] is not None else None
    ing = _latest_ingestion(cur, account, ok_only=True)
    return {"opportunities": rows, "coverage": (ing or {}).get("coverage", {}).get("idle_resources"),
            "not_covered": ["EC2 rightsizing (opt-in at AWS)", "Compute Optimizer (not enrolled)", "Snapshots and backups",
                            "Kubernetes workloads"],
            "related_findings_note": "Niagaros scanners do not cover EC2 volumes, addresses or load balancers yet, so "
                                     "no security findings can be linked to these resources."}


def view_opportunity(cur, account, oid):
    cur.execute("SELECT * FROM cost_opportunities WHERE id = %s AND cloud_account_id = %s", (oid, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "Opportunity not found")
    o = dict(zip([d[0] for d in cur.description], r))
    o["id"] = str(o["id"])
    for k in ("monthly_savings", "baseline_monthly"):
        o[k] = float(o[k]) if o[k] is not None else None
    cur.execute("""SELECT created_at, actor_email, action, details FROM cost_audit_log WHERE cloud_account_id = %s AND target = %s
                   ORDER BY created_at""", (account, oid))
    o["history"] = [{"at": a, "actor": b, "action": c, "details": d} for a, b, c, d in cur.fetchall()]
    return o


def view_budgets(cur, account):
    today = date.today()
    summary = E.summarize(_records(cur, account, today.replace(day=1) - timedelta(days=1)), today)
    f = _current_forecast(cur, account, today, "mean_amount")
    fc_total = summary["month_to_date"] + float(f[0]) if f else None
    cur.execute("""SELECT id, name, monthly_amount, currency, thresholds, forecast_alert, active, created_by, created_at
                   FROM cost_budgets WHERE cloud_account_id = %s ORDER BY active DESC, created_at""", (account,))
    out = []
    for bid, name, amt, cur_, th, fa, active, by, at in cur.fetchall():
        ev = E.evaluate_budget({"monthly_amount": amt, "thresholds": th, "forecast_alert": fa}, summary["month_to_date"], fc_total)
        out.append({"id": str(bid), "name": name, "monthly_amount": float(amt), "currency": cur_, "thresholds": th,
                    "forecast_alert": fa, "active": active, "created_by": by, "created_at": at, **ev})
    return {"budgets": out, "month_to_date": summary["month_to_date"], "currency": summary["currency"],
            "forecast_month_total": round(fc_total, 2) if fc_total is not None else None}


def view_alerts(cur, account):
    cur.execute("""SELECT id, kind, title, amount, detail, status, created_at, acknowledged_by, acknowledged_at, resolved_by,
                          resolved_at, note FROM cost_alerts WHERE cloud_account_id = %s
                   ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END, created_at DESC LIMIT 300""", (account,))
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    for r in rows:
        r["id"] = str(r["id"])
        r["amount"] = float(r["amount"]) if r["amount"] is not None else None
    return {"alerts": rows}


def _latest_snapshots(cur, account):
    cur.execute("""SELECT DISTINCT ON (kind) kind, available, data, created_at FROM cost_commitment_snapshots
                   WHERE cloud_account_id = %s ORDER BY kind, created_at DESC""", (account,))
    return {k: {"available": a, "data": d, "read_at": t} for k, a, d, t in cur.fetchall()}


def view_commitments(cur, account):
    snaps = _latest_snapshots(cur, account)
    util = [{"kind": k, **snaps[k]} for k in ("reservations", "savings_plans") if k in snaps]
    inv = (snaps.get("inventory") or {}).get("data") or {}
    inv_ok = (snaps.get("inventory") or {}).get("available", True)
    recs = (snaps.get("recommendations") or {}).get("data") or {}
    cur.execute("""SELECT id, status, title, monthly_savings FROM cost_opportunities WHERE cloud_account_id = %s
                   AND kind = 'commitment_purchase' ORDER BY first_seen DESC LIMIT 10""", (account,))
    proposals = [{"id": str(a), "status": b, "title": c, "monthly_savings": float(d) if d is not None else None} for a, b, c, d in cur.fetchall()]
    return {"commitments": util, "period": "last 30 days",
            "inventory": inv.get("items") or [], "inventory_read_at": (snaps.get("inventory") or {}).get("read_at"),
            "inventory_complete": inv_ok, "inventory_errors": inv.get("errors"),
            "recommendations": recs, "proposals": proposals,
            "expiry_rule": "Active commitments ending within 90, 60 and 30 days raise an alert",
            "not_covered": ["Purchases are made by you in AWS; Niagaros only tracks approval and verifies the result"]}


def view_subset(cur, account, services, label, limits):
    today = date.today()
    recs = _records(cur, account, today - timedelta(days=E_HISTORY), services=services)
    s = E.summarize(recs, today)
    return {"label": label, "services_considered": list(services), "summary": s, "limitations": limits}


def view_ai(cur, account):
    out = view_subset(cur, account, E.AI_SERVICES, "AI services", AI_LIMITS)
    cur.execute("""SELECT month, service, usage_type, amount, usage_quantity, unit, estimated FROM cost_usage_type_monthly
                   WHERE cloud_account_id = %s AND month >= %s ORDER BY month DESC, amount DESC""",
                (account, (date.today() - timedelta(days=E_HISTORY)).replace(day=1)))
    rows = []
    for m, svc, ut, amt, qty, unit, est in cur.fetchall():
        d = E.describe_ai_usage_type(ut)
        rows.append({"month": m, "service": svc, "usage_type": ut, "model": d["model"], "direction": d["direction"],
                     "amount": round(float(amt), 4), "quantity": float(qty) if qty is not None else None, "unit": unit, "estimated": est})
    by_model = {}
    for r in rows:
        by_model[r["model"]] = round(by_model.get(r["model"], 0) + r["amount"], 4)
    out.update({"by_usage_type": rows, "by_model": sorted(({"model": k, "amount": v} for k, v in by_model.items()), key=lambda x: -x["amount"]),
                "model_basis": "Model and token direction are read from the AWS usage type name"})
    return out


def view_kubernetes(cur, account):
    out = view_subset(cur, account, E.KUBERNETES_SERVICES, "Kubernetes (EKS)", K8S_LIMITS)
    snaps = _latest_snapshots(cur, account)
    out["clusters"] = ((snaps.get("eks_clusters") or {}).get("data") or {}).get("clusters") or []
    # Only spend that carries the cluster tag; untagged spend is the rest of the account, not a cluster.
    cur.execute("""SELECT tag_value, sum(amount) FROM cost_allocation_daily WHERE cloud_account_id = %s AND tag_key = 'aws:eks:cluster-name'
                   AND tag_value <> '' AND day >= %s GROUP BY 1 ORDER BY 2 DESC""", (account, date.today().replace(day=1)))
    out["cost_by_cluster"] = [{"cluster": v, "amount": round(float(a), 2)} for v, a in cur.fetchall()]
    out["clusters_readable"] = (snaps.get("eks_clusters") or {}).get("available", True)
    ing = _latest_ingestion(cur, account, ok_only=True)
    out["cluster_cost_status"] = ((ing or {}).get("coverage") or {}).get("eks_cost")
    return out


def view_portfolio(cur, email):
    cur.execute("SELECT id FROM cloud_accounts")
    ids = [str(r[0]) for r in cur.fetchall()]
    cur.execute(ACCESS_SQL, {"ids": ids or ["00000000-0000-0000-0000-000000000000"], "email": email, "write": False})
    allowed = [str(r[0]) for r in cur.fetchall()]
    if not allowed:
        return {"accounts": []}
    month = date.today().replace(day=1)
    cur.execute("""
        SELECT c.id, c.account_name, COALESCE(s.enabled, false),
               (SELECT string_agg(DISTINCT b.name, ', ') FROM bu_accounts ba JOIN business_units b ON b.id = ba.business_unit_id
                  JOIN organizations o ON o.id = b.organization_id
                  LEFT JOIN org_members m ON m.organization_id = o.id AND lower(m.email) = lower(%s)
                 WHERE ba.cloud_account_id = c.id
                   AND (lower(o.owner_email) = lower(%s) OR (m.id IS NOT NULL AND (m.business_unit_id IS NULL OR m.business_unit_id = b.id)))),
               (SELECT sum(amount) FROM cost_daily d WHERE d.cloud_account_id = c.id AND d.day >= %s),
               (SELECT max(currency) FROM cost_daily d WHERE d.cloud_account_id = c.id),
               (SELECT max(finished_at) FROM cost_ingestions i WHERE i.cloud_account_id = c.id AND i.status IN ('succeeded', 'partial'))
        FROM cloud_accounts c LEFT JOIN cost_settings s ON s.cloud_account_id = c.id
        WHERE c.id = ANY(%s::uuid[]) ORDER BY c.account_name""", (email, email, month, allowed))
    return {"accounts": [{"cloud_account_id": str(a), "account_name": b, "enabled": e, "business_units": u,
                          "month_to_date": round(float(m), 2) if m is not None else None, "currency": cu, "last_ingested": li}
                         for a, b, e, u, m, cu, li in cur.fetchall()]}


def view_export(cur, account, what, fmt, actor):
    if what == "opportunities":
        rows = view_opportunities(cur, account)["opportunities"]
        cols = ["id", "kind", "region", "resource_id", "title", "monthly_savings", "savings_basis", "confidence", "risk", "status",
                "requested_by", "approved_by", "executed_by", "executed_at", "verified_at", "first_seen", "last_seen"]
    elif what == "daily":
        cur.execute("""SELECT day, service, record_type, amount, currency, estimated, source, metric, updated_at FROM cost_daily
                       WHERE cloud_account_id = %s ORDER BY day, service, record_type""", (account,))
        cols = ["day", "service", "record_type", "amount", "currency", "estimated", "source", "metric", "updated_at"]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    else:
        raise BadRequest(400, "Unknown export")
    _audit(cur, account, actor, "export", what, {"format": fmt, "rows": len(rows)})
    if fmt == "json":
        return {"exported_at": datetime.now(timezone.utc), "what": what, "rows": rows,
                "method": "Amounts are AWS Cost Explorer UnblendedCost per day, service and record type; 'estimated' marks "
                          "days AWS has not finalised. Savings use AWS Pricing API list prices (see savings_basis)."}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([_csv_cell(r.get(c)) for c in cols])
    return buf.getvalue()


# ── actions ─────────────────────────────────────────────────────────────────

def _thresholds(v):
    if v is None:
        return [50, 80, 100]
    if not isinstance(v, list) or not v or len(v) > 6:
        raise BadRequest(400, "Thresholds must be a list of up to 6 percentages")
    try:
        out = sorted({int(x) for x in v})
    except (TypeError, ValueError):
        raise BadRequest(400, "Thresholds must be whole percentages")
    if any(x < 1 or x > 200 for x in out):
        raise BadRequest(400, "Thresholds must be between 1 and 200 percent")
    return out


def _amount(v):
    try:
        a = round(float(v), 2)
    except (TypeError, ValueError):
        raise BadRequest(400, "Amount must be a number")
    if not (0 < a <= 100_000_000):
        raise BadRequest(400, "Amount must be more than 0")
    return a


def _load_opp(cur, account, oid):
    _uuid(oid, "Opportunity")
    cur.execute("""SELECT status, requested_by, monthly_savings FROM cost_opportunities WHERE id = %s AND cloud_account_id = %s
                   FOR UPDATE""", (oid, account))
    r = cur.fetchone()
    if not r:
        raise BadRequest(404, "Opportunity not found")
    return r


def _reserve_run(cur, account, actor, enforce_cooldown=True):
    """Atomically reserve one paid ingestion: one at a time per account, and manual ones at most once an hour.
    The reserved row's id is handed to the scanner, which claims it exactly once."""
    cur.execute("SELECT pg_advisory_xact_lock(hashtext('cost_ingest:' || %s))", (account,))
    cur.execute("""SELECT 1 FROM cost_ingestions WHERE cloud_account_id = %s AND status = 'running'
                   AND started_at > NOW() - interval '15 minutes'""", (account,))
    if cur.fetchone():
        raise BadRequest(409, "A refresh is already running")
    if enforce_cooldown:
        cur.execute("""SELECT EXTRACT(EPOCH FROM (NOW() - max(started_at))) / 60 FROM cost_ingestions
                       WHERE cloud_account_id = %s AND trigger = 'manual'""", (account,))
        mins = cur.fetchone()[0]
        if mins is not None and float(mins) < REFRESH_MIN_MINUTES:
            raise BadRequest(429, f"Cost data was refreshed {int(float(mins))} minutes ago; AWS updates it a few times a day. Try again later.")
    cur.execute("""INSERT INTO cost_ingestions (cloud_account_id, trigger, requested_by) VALUES (%s, 'manual', %s) RETURNING id""",
                (account, actor))
    return str(cur.fetchone()[0])


def do_action(cur, account, actor, body):
    a = body.get("action")
    if a == "enable":
        if body.get("accept_charges") is not True:
            raise BadRequest(400, "Confirm that AWS bills each Cost Explorer request ($0.01) to this account")
        if _settings(cur, account)["enabled"]:
            return {"saved": True, "note": "Cost data is already on."}, None
        cur.execute("""INSERT INTO cost_settings (cloud_account_id, enabled, enabled_by, enabled_at, updated_by)
                       VALUES (%s, true, %s, NOW(), %s) ON CONFLICT (cloud_account_id) DO UPDATE SET enabled = true,
                       enabled_by = EXCLUDED.enabled_by, enabled_at = NOW(), updated_by = EXCLUDED.updated_by, updated_at = NOW()""",
                    (account, actor, actor))
        _audit(cur, account, actor, "enable_cost_ingestion", None, {"accepted_charges": True})
        try:
            run_id = _reserve_run(cur, account, actor)
        except BadRequest:
            return {"saved": True, "note": "Cost data is on. The next scheduled refresh will load it."}, None
        return {"saved": True, "note": "Cost data is on. The first refresh starts now and takes about a minute."}, run_id
    if a == "disable":
        cur.execute("UPDATE cost_settings SET enabled = false, updated_by = %s, updated_at = NOW() WHERE cloud_account_id = %s",
                    (actor, account))
        _audit(cur, account, actor, "disable_cost_ingestion")
        return {"saved": True, "note": "Cost data is off. Stored history is kept."}, None
    if a == "refresh":
        if not _settings(cur, account)["enabled"]:
            raise BadRequest(409, "Turn on cost ingestion first")
        run_id = _reserve_run(cur, account, actor)
        _audit(cur, account, actor, "refresh", run_id)
        return {"saved": True, "note": "Refresh started; it takes about a minute."}, run_id
    if a == "save_settings":
        tag = body.get("allocation_tag_key")
        if tag not in (None, ""):
            if not isinstance(tag, str) or not TAG_RE.match(tag):
                raise BadRequest(400, "Tag key may contain letters, digits, spaces and . : / = + - @ _ (max 128)")
        try:
            mn = float(body.get("anomaly_min_amount", 5))
        except (TypeError, ValueError):
            raise BadRequest(400, "Minimum anomaly amount must be a number")
        if not (0 <= mn <= 1_000_000):
            raise BadRequest(400, "Minimum anomaly amount is out of range")
        cur.execute("""INSERT INTO cost_settings (cloud_account_id, allocation_tag_key, anomaly_min_amount, updated_by)
                       VALUES (%s, %s, %s, %s) ON CONFLICT (cloud_account_id) DO UPDATE SET allocation_tag_key = EXCLUDED.allocation_tag_key,
                       anomaly_min_amount = EXCLUDED.anomaly_min_amount, updated_by = EXCLUDED.updated_by, updated_at = NOW()""",
                    (account, tag or None, mn, actor))
        _audit(cur, account, actor, "save_settings", None, {"allocation_tag_key": tag or None, "anomaly_min_amount": mn})
        return {"saved": True, "note": "Saved. The tag is used from the next refresh."}, None
    if a == "create_budget":
        name = _text(body, "name", "Name", max_len=120)
        amt = _amount(body.get("monthly_amount"))
        th = _thresholds(body.get("thresholds"))
        cur.execute("""INSERT INTO cost_budgets (cloud_account_id, name, monthly_amount, thresholds, forecast_alert, created_by)
                       VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""", (account, name, amt, th, body.get("forecast_alert") is not False, actor))
        bid = str(cur.fetchone()[0])
        _audit(cur, account, actor, "create_budget", bid, {"name": name, "monthly_amount": amt, "thresholds": th})
        return {"saved": True, "budget_id": bid, "note": "Budget saved. It is checked at every refresh."}, None
    if a in ("update_budget", "archive_budget"):
        bid = _uuid(body.get("budget_id"), "Budget")
        cur.execute("SELECT name FROM cost_budgets WHERE id = %s AND cloud_account_id = %s", (bid, account))
        if not cur.fetchone():
            raise BadRequest(404, "Budget not found")
        if a == "archive_budget":
            cur.execute("UPDATE cost_budgets SET active = false, updated_by = %s, updated_at = NOW() WHERE id = %s", (actor, bid))
            _audit(cur, account, actor, "archive_budget", bid)
        else:
            name = _text(body, "name", "Name", max_len=120)
            amt = _amount(body.get("monthly_amount"))
            th = _thresholds(body.get("thresholds"))
            cur.execute("""UPDATE cost_budgets SET name = %s, monthly_amount = %s, thresholds = %s, forecast_alert = %s,
                           updated_by = %s, updated_at = NOW() WHERE id = %s""",
                        (name, amt, th, body.get("forecast_alert") is not False, actor, bid))
            _audit(cur, account, actor, "update_budget", bid, {"name": name, "monthly_amount": amt, "thresholds": th})
        return {"saved": True}, None
    if a in ("acknowledge_alert", "resolve_alert"):
        aid = _uuid(body.get("alert_id"), "Alert")
        note = _text(body, "note", "Note", required=(a == "resolve_alert"))
        cur.execute("SELECT status FROM cost_alerts WHERE id = %s AND cloud_account_id = %s FOR UPDATE", (aid, account))
        r = cur.fetchone()
        if not r:
            raise BadRequest(404, "Alert not found")
        if r[0] == "resolved":
            raise BadRequest(409, "This alert is already resolved")
        if a == "acknowledge_alert":
            cur.execute("UPDATE cost_alerts SET status = 'acknowledged', acknowledged_by = %s, acknowledged_at = NOW(), note = COALESCE(%s, note) WHERE id = %s",
                        (actor, note, aid))
        else:
            cur.execute("UPDATE cost_alerts SET status = 'resolved', resolved_by = %s, resolved_at = NOW(), note = %s WHERE id = %s",
                        (actor, note, aid))
        _audit(cur, account, actor, a, aid, {"note": note})
        return {"saved": True}, None
    if a == "propose_commitment_purchase":
        which = body.get("which")
        if which not in ("savings_plans", "reservations"):
            raise BadRequest(400, "Choose savings_plans or reservations")
        rec = ((_latest_snapshots(cur, account).get("recommendations") or {}).get("data") or {}).get(which) or {}
        if not rec.get("available"):
            raise BadRequest(409, "AWS has no current recommendation of this kind")
        label = "Compute Savings Plan" if which == "savings_plans" else "EC2 reservation"
        detail = {k: v for k, v in rec.items() if k != "available"}
        fp = f"commitment_purchase:{which}:{rec.get('recommendation_id') or date.today().isoformat()}"
        cur.execute("""INSERT INTO cost_opportunities (cloud_account_id, fingerprint, kind, region, resource_id, title, monthly_savings,
                               savings_basis, confidence, risk, detail, recommendation, rollback)
                       VALUES (%s, %s, 'commitment_purchase', 'global', %s, %s, %s, %s, 'medium', 'high', %s, %s, %s)
                       ON CONFLICT (cloud_account_id, fingerprint) DO NOTHING RETURNING id""",
                    (account, fp, rec.get("recommendation_id") or which,
                     f"Buy a {label} ({rec.get('term')}, {rec.get('payment')})"[:500], rec.get("estimated_monthly_savings"),
                     rec.get("basis"), _J(detail),
                     f"Buy the {label} AWS recommends in the AWS console, after approval.",
                     "A commitment cannot be cancelled; it can only be sold (reservations) or left to expire."))
        row = cur.fetchone()
        if not row:
            raise BadRequest(409, "This recommendation was already proposed")
        _audit(cur, account, actor, "propose_commitment_purchase", str(row[0]), {"which": which})
        return {"saved": True, "opportunity_id": str(row[0]),
                "note": "Proposed. It needs approval by a second person before anyone buys it."}, None
    if a in ("request_approval", "decide_opportunity", "mark_executed", "dismiss", "restore"):
        oid = body.get("opportunity_id")
        status, requested_by, savings = _load_opp(cur, account, oid)
        if a == "request_approval":
            if status != "observed":
                raise BadRequest(409, "Approval can only be requested for a new opportunity")
            cur.execute("""UPDATE cost_opportunities SET status = 'approval_requested', requested_by = %s, requested_at = NOW()
                           WHERE id = %s""", (actor, oid))
            note = "Sent for approval. Another person with write access must approve it."
        elif a == "decide_opportunity":
            decision = body.get("decision")
            if decision not in ("approve", "reject"):
                raise BadRequest(400, "Decision must be approve or reject")
            if status != "approval_requested":
                raise BadRequest(409, "This opportunity is not waiting for approval")
            if (requested_by or "").lower() == actor.lower():
                raise BadRequest(403, "The person who asked for approval cannot approve it")
            if decision == "approve":
                cur.execute("""UPDATE cost_opportunities SET status = 'approved', approved_by = %s, approved_at = NOW(),
                               baseline_monthly = monthly_savings WHERE id = %s""", (actor, oid))
            else:
                cur.execute("UPDATE cost_opportunities SET status = 'observed', requested_by = NULL, requested_at = NULL WHERE id = %s", (oid,))
            note = "Approved. Make the change in AWS, then mark it as done." if decision == "approve" else "Rejected."
        elif a == "mark_executed":
            n = _text(body, "note", "What was changed")
            if status != "approved":
                raise BadRequest(409, "Only an approved opportunity can be marked as done")
            cur.execute("""UPDATE cost_opportunities SET status = 'executed', executed_by = %s, executed_at = NOW(), execution_note = %s
                           WHERE id = %s""", (actor, n, oid))
            note = "Marked as done. The next refresh checks whether the resource is really gone."
        elif a == "dismiss":
            reason = _text(body, "reason", "Reason")
            if status in ("verified", "dismissed", "executed"):
                raise BadRequest(409, "This opportunity can no longer be dismissed")
            cur.execute("UPDATE cost_opportunities SET status = 'dismissed', dismissed_reason = %s WHERE id = %s", (reason, oid))
            note = "Dismissed."
        else:
            if status != "dismissed":
                raise BadRequest(409, "Only a dismissed opportunity can be restored")
            cur.execute("""UPDATE cost_opportunities SET status = 'observed', dismissed_reason = NULL, requested_by = NULL,
                           approved_by = NULL WHERE id = %s""", (oid,))
            note = "Restored."
        _audit(cur, account, actor, f"opportunity_{a}", oid, {k: body.get(k) for k in ("decision", "note", "reason") if body.get(k)})
        return {"saved": True, "note": note}, None
    raise BadRequest(400, "Unknown action")


def _start_refresh(account, actor, run_id):
    boto3.client("lambda", region_name=REGION).invoke(
        FunctionName=SCANNER, InvocationType="Event",
        Payload=json.dumps({"cloud_account_id": account, "trigger": "manual", "requested_by": actor,
                            "ingestion_id": run_id}).encode())


# ── entry ───────────────────────────────────────────────────────────────────

AI_LIMITS = ["Model, agent, token and inference level needs usage data from the AI provider; Niagaros reads billed AWS services only",
             "OpenAI, Anthropic and other providers are not connected"]
K8S_LIMITS = ["Only the EKS control-plane and related AWS charges are visible; namespace and workload allocation needs "
              "split cost allocation data, which is not ingested", "No Kubernetes cluster connector yet"]


def handler(event, context):
    method = (event or {}).get("httpMethod") or "GET"
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
                result, run_id = do_action(cur, account, email, body)
                conn.commit()
                if run_id:
                    try:
                        _start_refresh(account, email, run_id)
                    except Exception:  # noqa: BLE001
                        logger.exception("could not start the cost refresh")
                        cur.execute("""UPDATE cost_ingestions SET status = 'failed', finished_at = NOW(),
                                       error = 'The refresh could not be started' WHERE id = %s""", (run_id,))
                        conn.commit()
                        result["note"] = "Saved, but the refresh could not be started. Try again in a minute."
                return _resp(200, result)
            v = qs.get("view") or "overview"
            if v == "overview":
                r = view_overview(cur, account)
            elif v == "explorer":
                r = view_explorer(cur, account, qs)
            elif v == "opportunities":
                r = view_opportunities(cur, account)
            elif v == "opportunity":
                r = view_opportunity(cur, account, _uuid(qs.get("opportunity_id"), "Opportunity"))
            elif v == "budgets":
                r = view_budgets(cur, account)
            elif v == "alerts":
                r = view_alerts(cur, account)
            elif v == "commitments":
                r = view_commitments(cur, account)
            elif v == "ai":
                r = view_ai(cur, account)
            elif v == "kubernetes":
                r = view_kubernetes(cur, account)
            elif v == "ingestions":
                cur.execute("""SELECT id, status, started_at, finished_at, trigger, requested_by, ce_requests, coverage, error
                               FROM cost_ingestions WHERE cloud_account_id = %s ORDER BY started_at DESC LIMIT 50""", (account,))
                cols = [d[0] for d in cur.description]
                r = {"ingestions": [dict(zip(cols, x)) for x in cur.fetchall()]}
                cur.execute("""SELECT day, service, record_type, old_amount, new_amount, changed_at FROM cost_daily_revisions
                               WHERE cloud_account_id = %s ORDER BY changed_at DESC LIMIT 100""", (account,))
                r["revisions"] = [{"day": a, "service": b, "record_type": c, "old": float(d), "new": float(e), "at": f}
                                  for a, b, c, d, e, f in cur.fetchall()]
            elif v == "audit":
                cur.execute("""SELECT created_at, actor_email, action, target, details FROM cost_audit_log WHERE cloud_account_id = %s
                               ORDER BY created_at DESC LIMIT 300""", (account,))
                r = {"audit": [{"at": a, "actor": b, "action": c, "target": d, "details": e} for a, b, c, d, e in cur.fetchall()]}
            elif v == "export":
                fmt = qs.get("format") if qs.get("format") in ("csv", "json") else "csv"
                r = view_export(cur, account, qs.get("what") or "daily", fmt, email)
                conn.commit()
                if fmt == "csv":
                    return _resp(200, r, {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=cloud-cost.csv"})
                return _resp(200, r)
            else:
                return _resp(400, {"error": "Unknown view"})
            conn.commit()
            return _resp(200, r)
    except BadRequest as e:
        if conn:
            conn.rollback()
        return _resp(e.status, {"error": e.message})
    except Exception:
        logger.exception("cloud cost request failed")
        if conn:
            conn.rollback()
        return _resp(500, {"error": "Something went wrong while loading cloud cost. Please try again."})
    finally:
        if conn:
            conn.close()
