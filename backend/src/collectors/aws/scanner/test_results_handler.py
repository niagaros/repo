"""
test_results_handler.py
Persists automated-test runs (issue #279) so the coverage dashboard reads real, historical data instead of a
file: every run, every test result, failure counts per flow, and flaky-by-history detection.

  POST /test-results   ingest one run     (header X-Ingest-Token, or a signed-in Cognito Admin)
  GET  /test-results   latest run + history + per-flow failure counts   (same two ways in)

The ingest token is a random secret in Secrets Manager (cspm/tests/ingest-token). It grants access to this one
endpoint only. Test results are platform data, not tenant data, so there is no cloud_account scoping here — access
is restricted to Admins and the ingest token instead.
"""
import hmac
import json
import logging
import os

import boto3
import psycopg2
from psycopg2.extras import Json


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DB_SECRET_NAME = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
TOKEN_SECRET_NAME = os.environ.get("INGEST_TOKEN_SECRET", "cspm/tests/ingest-token")
REGION = os.environ.get("SECRET_REGION", "eu-west-1")
ADMIN_GROUP_NAME = "Admin"
MAX_RESULTS = 5000
STATUSES = {"passed", "failed", "known_failure", "blocked", "skipped"}

CORS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS test_runs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_at      TIMESTAMPTZ NOT NULL,
    commit_sha  TEXT,
    branch      TEXT,
    trigger     TEXT,
    totals      JSONB NOT NULL,
    summary     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_at, commit_sha, trigger)
);
CREATE TABLE IF NOT EXISTS test_results (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id      UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
    test_id     TEXT NOT NULL,
    flow        TEXT,
    severity    TEXT,
    layer       TEXT,
    status      TEXT NOT NULL,
    duration_s  NUMERIC,
    failed_step TEXT,
    message     TEXT,
    flaky       BOOLEAN NOT NULL DEFAULT false
);
-- The first version used a BIGSERIAL id; the app's database user cannot use sequences created by the admin user,
-- so convert it (idempotent, and the table is empty when this runs).
DO $$ BEGIN
  IF (SELECT data_type FROM information_schema.columns WHERE table_name = 'test_results' AND column_name = 'id') <> 'uuid' THEN
    ALTER TABLE test_results ALTER COLUMN id DROP DEFAULT;
    ALTER TABLE test_results ALTER COLUMN id TYPE uuid USING gen_random_uuid();
    ALTER TABLE test_results ALTER COLUMN id SET DEFAULT gen_random_uuid();
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_test_results_flow ON test_results(flow, status);
CREATE INDEX IF NOT EXISTS idx_test_results_run  ON test_results(run_id);
CREATE INDEX IF NOT EXISTS idx_test_runs_run_at  ON test_runs(run_at DESC);
"""


def _resp(status, body):
    return {"statusCode": status, "headers": CORS, "body": json.dumps(body, default=str)}


def _secret(name):
    return boto3.client("secretsmanager", region_name=REGION).get_secret_value(SecretId=name)["SecretString"]


def _get_connection():
    s = json.loads(_secret(DB_SECRET_NAME))
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"],
                            password=s["password"], sslmode="require", connect_timeout=10)


def _caller(event):
    """Who is calling? Returns 'ingest' (valid ingest token), 'admin', 'not_admin', 'invalid_session' or 'anonymous'.
    An expired/invalid session is deliberately distinct from a valid session that lacks the Admin group."""
    headers = {k.lower(): v for k, v in ((event or {}).get("headers") or {}).items()}
    supplied = (headers.get("x-ingest-token") or "").strip()
    if supplied:
        try:
            ok = hmac.compare_digest(supplied.encode(), _secret(TOKEN_SECRET_NAME).strip().encode())
        except Exception:
            logger.exception("could not read the ingest token secret")
            return "invalid_session"
        return "ingest" if ok else "invalid_session"
    auth = headers.get("authorization") or ""
    if not auth.startswith("Bearer ") or not auth[7:].strip():
        return "anonymous"
    try:
        cognito = boto3.client("cognito-idp", region_name=REGION)
        user = cognito.get_user(AccessToken=auth[7:].strip())
    except Exception as e:
        logger.warning("session token rejected by Cognito: %s", type(e).__name__)
        return "invalid_session"
    try:
        groups = cognito.admin_list_groups_for_user(UserPoolId=os.environ["COGNITO_USER_POOL_ID"], Username=user["Username"])
    except Exception as e:
        logger.error("could not read the caller's groups: %s: %s", type(e).__name__, e)
        return "not_admin"
    names = [g["GroupName"] for g in groups.get("Groups", [])]
    if ADMIN_GROUP_NAME not in names:
        email = next((a["Value"] for a in user.get("UserAttributes", []) if a["Name"] == "email"), "?")
        logger.info("caller is not an Admin: username=%s email=%s groups=%s", user["Username"], email, names)
    logger.info("caller groups: %s", names)
    return "admin" if ADMIN_GROUP_NAME in names else "not_admin"


def validate_run(payload):
    """Returns an error string, or None when the payload is a well-formed run."""
    if not isinstance(payload, dict):
        return "body must be a JSON object"
    summary, results = payload.get("summary"), payload.get("results")
    if not isinstance(summary, dict) or not summary.get("run_at") or not isinstance(summary.get("totals"), dict):
        return "summary with run_at and totals is required"
    if not isinstance(results, list) or not results:
        return "results must be a non-empty list"
    if len(results) > MAX_RESULTS:
        return f"at most {MAX_RESULTS} results per run"
    for r in results:
        if not isinstance(r, dict) or not r.get("test_id") or r.get("status") not in STATUSES:
            return "every result needs a test_id and a valid status"
    return None


def _ingest(conn, payload):
    s = payload["summary"]
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO test_runs (run_at, commit_sha, branch, trigger, totals, summary)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (run_at, commit_sha, trigger) DO NOTHING RETURNING id
            """, (s["run_at"], s.get("commit"), s.get("branch"), s.get("trigger"), Json(s["totals"]), Json(s)))
            row = cur.fetchone()
            if not row:
                return None
            run_id = str(row[0])
            for r in payload["results"]:
                cur.execute("""
                    INSERT INTO test_results (run_id, test_id, flow, severity, layer, status, duration_s, failed_step, message, flaky)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (run_id, r["test_id"], r.get("flow"), r.get("severity"), r.get("layer"), r["status"],
                      r.get("duration_s"), r.get("failed_step"), (r.get("message") or "")[:2000], bool(r.get("flaky"))))
            return run_id


def _read(cur, run_id=None):
    if run_id:
        cur.execute("SELECT id, summary FROM test_runs WHERE id = %s", (run_id,))
    else:
        cur.execute("SELECT id, summary FROM test_runs WHERE trigger NOT LIKE 'production-smoke%%' ORDER BY run_at DESC LIMIT 1")
    row = cur.fetchone()
    if not row:
        return {"run": None, "history": [], "failure_counts": {}, "flaky_by_history": [], "smoke": None, "failure_history": {}}
    latest_id, summary = str(row[0]), row[1]

    cur.execute("SELECT flow, count(*) FROM test_results WHERE status = 'failed' AND flow IS NOT NULL GROUP BY flow")
    failure_counts = {f: int(n) for f, n in cur.fetchall()}
    for f in summary.get("flows", []):
        f["failure_count_history"] = failure_counts.get(f["id"], 0)

    cur.execute("""
        SELECT id, run_at, commit_sha, trigger, totals FROM test_runs WHERE trigger NOT LIKE 'production-smoke%%' ORDER BY run_at DESC LIMIT 30
    """)
    history = [{"id": str(i), "run_at": t, "commit": c, "trigger": g, "tests": tot.get("tests"), "passed": tot.get("passed"),
                "failed": tot.get("failed")} for i, t, c, g, tot in cur.fetchall()]

    cur.execute("""
        SELECT test_id FROM test_results
        WHERE run_id IN (SELECT id FROM test_runs WHERE trigger NOT LIKE 'production-smoke%%' ORDER BY run_at DESC LIMIT 20)
        GROUP BY test_id
        HAVING count(*) FILTER (WHERE status = 'failed') > 0 AND count(*) FILTER (WHERE status = 'passed') > 0
    """)
    flaky = [r[0] for r in cur.fetchall()]
    failing_ids = [f["test_id"] for f in summary.get("failures", []) if f.get("status") == "failed"]
    failure_history = {}
    if failing_ids:
        cur.execute("""SELECT r.test_id, array_agg(t.run_at ORDER BY t.run_at DESC) FROM test_results r JOIN test_runs t ON t.id = r.run_id
                       WHERE r.status = 'failed' AND r.test_id = ANY(%s) GROUP BY r.test_id""", (failing_ids,))
        failure_history = {tid: list(runs)[:10] for tid, runs in cur.fetchall()}
    cur.execute("SELECT run_at, commit_sha, totals, summary FROM test_runs WHERE trigger = 'production-smoke' ORDER BY run_at DESC LIMIT 1")
    sm = cur.fetchone()
    cur.execute("SELECT run_at, (totals->>'passed')::int, (totals->>'failed')::int FROM test_runs WHERE trigger = 'production-smoke' ORDER BY run_at DESC LIMIT 48")
    smoke_history = [{"run_at": a, "passed": b, "failed": c} for a, b, c in cur.fetchall()]
    smoke = None if not sm else {"run_at": sm[0], "trigger_detail": sm[1], "totals": sm[2], "failing": [c for c in sm[3].get("checks", []) if not c["ok"]],
                                 "history": smoke_history}
    return {"run": summary, "run_id": latest_id, "history": history, "failure_counts": failure_counts, "flaky_by_history": flaky, "smoke": smoke, "failure_history": failure_history}


def handler(event, context):
    if event.get("action") == "migrate":
        conn = _get_connection()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(BOOTSTRAP_SQL)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()
    if "httpMethod" not in event:
        return {"statusCode": 400, "body": json.dumps({"error": "not an API Gateway event"})}
    method = event["httpMethod"]
    if method == "OPTIONS":
        return _resp(200, {})
    who = _caller(event)
    if who == "anonymous":
        return _resp(401, {"error": "Unauthorized"})
    if who == "invalid_session":
        # An expired session must send the user back to sign in; a wrong ingest token is simply refused.
        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        return _resp(403 if headers.get("x-ingest-token") else 401, {"error": "Your session is invalid or has expired." if not headers.get("x-ingest-token") else "Invalid ingest token."})
    if who == "not_admin":
        return _resp(403, {"error": "Test results are visible to Admins only."})

    conn = _get_connection()
    try:
        if method == "GET":
            qs = event.get("queryStringParameters") or {}
            with conn.cursor() as cur:
                return _resp(200, _read(cur, qs.get("run_id")))
        if method == "POST":
            try:
                payload = json.loads(event.get("body") or "")
            except ValueError:
                return _resp(400, {"error": "Invalid JSON"})
            problem = validate_run(payload)
            if problem:
                return _resp(400, {"error": problem})
            run_id = _ingest(conn, payload)
            return _resp(200, {"stored": bool(run_id), "run_id": run_id, "duplicate": run_id is None})
        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.error("test_results_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": "internal error"})
    finally:
        conn.close()
