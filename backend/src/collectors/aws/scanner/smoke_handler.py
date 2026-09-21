"""
smoke_handler.py
Continuous production smoke tests (issue #279: "Given a deployment completes, production smoke tests validate critical
platform availability"). Runs inside AWS, independent of GitHub:

  * on a schedule (EventBridge rate(30 minutes)), and
  * right after every Amplify deployment (EventBridge event "Amplify Deployment Status Change" = SUCCEED).

All checks are read-only and anonymous. Each run is stored in test_runs / test_results (trigger = production-smoke) so the
dashboard can show it, and an alert email is sent when the platform goes from healthy to unhealthy, and every 6 hours
while it stays unhealthy.
"""
import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import boto3
import psycopg2
from psycopg2.extras import Json

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
API = os.environ.get("API_BASE", "https://hzf92ft6j7.execute-api.eu-west-1.amazonaws.com/default")
SITES = [s for s in os.environ.get("SMOKE_SITES", "https://main.d3joqokkaynfaq.amplifyapp.com,https://sofyan-dev.d3joqokkaynfaq.amplifyapp.com").split(",") if s]
ALERT_EMAIL = os.environ.get("SMOKE_ALERT_EMAIL", "bottomclipzz@gmail.com")
REPEAT_ALERT_SECONDS = 6 * 3600
PRIVATE_ENDPOINTS = ("notifications", "tprm", "questionnaires", "audit-management", "trust-center", "custom-frameworks", "ai-agent", "enterprise")


def _http(method, url, headers=None, body=None, timeout=15):
    """(status, body_text) - never raises for HTTP error statuses or network errors."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(2000).decode("utf-8", "replace")
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def run_checks():
    checks = []

    def check(name, ok, detail="", severity="P0"):
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:200], "severity": severity})

    s, b = _http("GET", f"{API}/status")
    try:
        d = json.loads(b) if s == 200 else {}
    except ValueError:
        d = {}
    check("status endpoint answers", s == 200, s)
    check("database is available", (d.get("database") or {}).get("status") == "operational", (d.get("database") or {}).get("status"))
    check("notification queue is healthy", (d.get("notification_queue") or {}).get("status") == "operational", (d.get("notification_queue") or {}).get("status"))
    check("platform overall status", d.get("overall_status") in ("operational", "degraded"), d.get("overall_status"), "P1")

    s, _ = _http("GET", f"{API}/get-dashboard-data")
    check("dashboard rejects anonymous callers", s == 401, s)
    s, _ = _http("GET", f"{API}/get-dashboard-data", {"Authorization": "Bearer forged.unsigned.jwt"})
    check("dashboard rejects a forged token", s == 401, s)
    for path in PRIVATE_ENDPOINTS:
        s, _ = _http("GET", f"{API}/{path}?cloud_account_id=00000000-0000-4000-8000-000000000000")
        check(f"{path}: anonymous callers cannot read account data", s == 401, s)
    s, _ = _http("POST", f"{API}/onboard", {"Content-Type": "application/json"}, b"{}")
    check("onboarding requires a signed-in user", s == 401, s)
    s, _ = _http("POST", f"{API}/scan", {"Content-Type": "application/json"}, b"{}")
    check("scan requires a signed-in user", s == 401, s)
    s, _ = _http("GET", f"{API}/test-results")
    check("test results are not public", s == 401, s)

    s, _ = _http("POST", f"{API}/tprm", {"Content-Type": "application/json", "Authorization": "Bearer x"}, b"{not json")
    check("malformed JSON is a client error, never a 5xx", 400 <= s < 500, s, "P2")
    s, _ = _http("OPTIONS", f"{API}/tprm", {"Origin": "https://example.com", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization"})
    check("CORS preflight works", s in (200, 204), s, "P2")

    for site in SITES:
        for page in ("", "niagaros-dashboard.html"):
            s, b = _http("GET", f"{site}/{page}")
            check(f"{site.split('//')[1].split('.')[0]}: /{page} loads", s == 200 and "<html" in b.lower(), s, "P1")
    s, b = _http("GET", f"{API}/trust-center?slug=smoke-test-nonexistent")
    check("public Trust Center answers a clean 404", s == 404, s, "P2")
    return checks


def _db():
    sm = boto3.client("secretsmanager", region_name=REGION)
    s = json.loads(sm.get_secret_value(SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"], password=s["password"],
                            sslmode="require", connect_timeout=10)


def _store(conn, checks, started, trigger_detail):
    passed = sum(c["ok"] for c in checks)
    failed = len(checks) - passed
    run_at = datetime.now(timezone.utc).isoformat()
    summary = {"run_at": run_at, "commit": trigger_detail, "branch": "production", "trigger": "production-smoke",
               "totals": {"tests": len(checks), "passed": passed, "failed": failed, "known_failure": 0, "blocked": 0, "skipped": 0},
               "checks": checks, "full_run_duration_s": round(time.time() - started, 1)}
    with conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO test_runs (run_at, commit_sha, branch, trigger, totals, summary) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                        (run_at, trigger_detail, "production", "production-smoke", Json(summary["totals"]), Json(summary)))
            run_id = cur.fetchone()[0]
            for c in checks:
                cur.execute("""INSERT INTO test_results (run_id, test_id, flow, severity, layer, status, message) VALUES (%s, %s, 'E2E-SMOKE-001', %s, 'smoke', %s, %s)""",
                            (run_id, f"smoke::{c['name']}", c["severity"], "passed" if c["ok"] else "failed", "" if c["ok"] else c["detail"]))
    return str(run_id)


def _should_alert(conn, failed):
    """Alert on healthy -> unhealthy, then at most every 6h while it stays unhealthy."""
    if not failed:
        return False
    with conn.cursor() as cur:
        cur.execute("""SELECT run_at, (totals->>'failed')::int FROM test_runs WHERE trigger = 'production-smoke' ORDER BY run_at DESC OFFSET 1 LIMIT 1""")
        prev = cur.fetchone()
        if not prev or (prev[1] or 0) == 0:
            return True
        cur.execute("SELECT max(run_at) FROM test_runs WHERE trigger = 'production-smoke-alert'")
        last_alert = cur.fetchone()[0]
    return last_alert is None or (datetime.now(timezone.utc) - last_alert).total_seconds() > REPEAT_ALERT_SECONDS


def _alert(conn, checks, trigger_detail):
    bad = [c for c in checks if not c["ok"]]
    lines = "\n".join(f"- [{c['severity']}] {c['name']} (got: {c['detail']})" for c in bad)
    try:
        boto3.client("sesv2", region_name=REGION).send_email(
            FromEmailAddress=ALERT_EMAIL, Destination={"ToAddresses": [ALERT_EMAIL]},
            Content={"Simple": {"Subject": {"Data": f"Niagaros production smoke: {len(bad)} check(s) failing"},
                                "Body": {"Text": {"Data": f"Production smoke tests failed ({trigger_detail}):\n\n{lines}\n\nDetails: Automated Testing dashboard."}}}})
        sent = True
    except Exception as e:
        logger.error("smoke alert email failed: %s", e)
        sent = False
    with conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO test_runs (run_at, commit_sha, branch, trigger, totals, summary) VALUES (now(), %s, 'production', 'production-smoke-alert', %s, %s)""",
                        (trigger_detail, Json({"tests": 0}), Json({"alert_sent": sent, "failing": [c["name"] for c in bad]})))
    return sent


def handler(event, context):
    started = time.time()
    detail = (event or {}).get("detail") or {}
    trigger_detail = (f"amplify:{detail.get('branchName', '?')}#{detail.get('jobId', '?')}" if event.get("source") == "aws.amplify" else "schedule")
    checks = run_checks()
    failed = sum(not c["ok"] for c in checks)
    conn = _db()
    try:
        run_id = _store(conn, checks, started, trigger_detail)
        alerted = _alert(conn, checks, trigger_detail) if _should_alert(conn, failed) else False
    finally:
        conn.close()
    logger.info("smoke run %s: %d checks, %d failed, alerted=%s", run_id, len(checks), failed, alerted)
    return {"run_id": run_id, "checks": len(checks), "failed": failed, "alerted": alerted, "trigger": trigger_detail,
            "failing": [c["name"] for c in checks if not c["ok"]]}
