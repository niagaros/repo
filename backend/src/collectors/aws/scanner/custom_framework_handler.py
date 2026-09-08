"""
custom_framework_handler.py

Product feature, not a compliance-framework mapper: lets a customer
define their own named "framework" made up of controls they compose
themselves out of the account's real, already-scanned check catalog
(CIS/FSBP/GitHub check_ids). Unlike every other *_mapper_handler.py in
this codebase, the control-to-check mapping is user-authored data
stored in Postgres (custom_frameworks / custom_framework_controls,
migration 006), not a hardcoded, research-backed dict.

Two responsibilities in one Lambda, dispatched by event shape:
  - API Gateway proxy events (event["httpMethod"] present): CRUD for
    frameworks/controls, served to frontend/public/custom_frameworks.html.
  - Orchestrator mapper-wave events ({"cloud_account_id": ...} only, no
    httpMethod): run every custom framework for that account and upsert
    into `findings`, exactly like every other mapper — a control FAILs
    if any of its mapped checks currently FAIL for a resource.

Scoring logic and the findings upsert shape are intentionally identical
to sspa_mapper_handler.py / iso27018_mapper_handler.py etc. The only
difference is where the control definitions come from.
"""

import json
import logging
import os

import boto3
import psycopg2
from psycopg2.extras import Json

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS custom_frameworks (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    name             VARCHAR(255) NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS custom_framework_controls (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    custom_framework_id UUID         NOT NULL REFERENCES custom_frameworks(id) ON DELETE CASCADE,
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
    severity            VARCHAR(20)  NOT NULL DEFAULT 'MEDIUM',
    remediation         TEXT,
    mapped_checks       JSONB        NOT NULL DEFAULT '[]',
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS custom_frameworks_account_idx ON custom_frameworks(cloud_account_id);
CREATE INDEX IF NOT EXISTS custom_framework_controls_framework_idx ON custom_framework_controls(custom_framework_id);
"""

# One-time admin migration (grants + scanner registration) — run manually
# via {"migrate": true} against the admin secret, see migration 006.
ADMIN_MIGRATION_SQL = BOOTSTRAP_SQL + """
GRANT SELECT, INSERT, UPDATE, DELETE ON custom_frameworks TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON custom_framework_controls TO cspm_lambda;
INSERT INTO scanners (function_name, resource_type, description, enabled)
VALUES ('custom-framework-handler', 'compliance', 'User-defined Custom Frameworks (product feature, not a published standard)', true)
ON CONFLICT (function_name) DO NOTHING;
"""


def _get_connection():
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    client = boto3.client("secretsmanager", region_name=region)
    secret = json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return psycopg2.connect(
        host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
        user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
    )


# ── CRUD (API Gateway) ───────────────────────────────────────────────

def _list_frameworks(conn, cloud_account_id):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, name, created_at FROM custom_frameworks
            WHERE cloud_account_id = %s ORDER BY created_at
        """, (cloud_account_id,))
        frameworks = [{"id": str(r[0]), "name": r[1], "created_at": r[2].isoformat()} for r in cur.fetchall()]

        for fw in frameworks:
            cur.execute("""
                SELECT id, title, description, severity, remediation, mapped_checks
                FROM custom_framework_controls WHERE custom_framework_id = %s ORDER BY created_at
            """, (fw["id"],))
            controls = []
            for r in cur.fetchall():
                control_id = str(r[0])
                check_id = f"CUSTOM.{control_id[:8]}"
                cur.execute("""
                    SELECT f.result FROM findings f
                    JOIN resources res ON res.id = f.resource_id
                    WHERE f.check_id = %s
                """, (check_id,))
                results = [row[0] for row in cur.fetchall()]
                status = "FAIL" if "FAIL" in results else ("PASS" if results else "NOT_RUN")
                controls.append({
                    "id": control_id, "title": r[1], "description": r[2], "severity": r[3],
                    "remediation": r[4], "mapped_checks": r[5], "status": status,
                    "passed": results.count("PASS"), "failed": results.count("FAIL"),
                })
            fw["controls"] = controls
    return frameworks


def _create_framework(conn, cloud_account_id, name):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO custom_frameworks (cloud_account_id, name) VALUES (%s, %s) RETURNING id
            """, (cloud_account_id, name))
            return str(cur.fetchone()[0])


def _add_control(conn, framework_id, title, description, severity, remediation, checks):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO custom_framework_controls
                    (custom_framework_id, title, description, severity, remediation, mapped_checks)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (framework_id, title, description, severity, remediation, Json(checks)))
            return str(cur.fetchone()[0])


def _delete_framework(conn, framework_id):
    with conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM custom_framework_controls WHERE custom_framework_id = %s", (framework_id,))
            control_ids = [str(r[0]) for r in cur.fetchall()]
            for cid in control_ids:
                cur.execute("DELETE FROM findings WHERE check_id = %s", (f"CUSTOM.{cid[:8]}",))
            cur.execute("DELETE FROM custom_frameworks WHERE id = %s", (framework_id,))


def _delete_control(conn, control_id):
    with conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM findings WHERE check_id = %s", (f"CUSTOM.{control_id[:8]}",))
            cur.execute("DELETE FROM custom_framework_controls WHERE id = %s", (control_id,))


# ── mapping (orchestrator + manual "run now") ────────────────────────

def run_mapping(cloud_account_id: str) -> dict:
    conn = _get_connection()
    findings_upserted = 0
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                FROM findings f
                JOIN resources r ON r.id = f.resource_id
                WHERE r.cloud_account_id = %s
                  AND f.check_id NOT LIKE 'CUSTOM.%%'
            """, (cloud_account_id,))
            rows = cur.fetchall()

            by_check = {}
            for check_id, result, resource_id, resource_name, resource_type in rows:
                by_check.setdefault(check_id, []).append({
                    "resource_id": resource_id, "result": result,
                    "resource_name": resource_name, "resource_type": resource_type,
                })

            cur.execute("""
                SELECT cf.id, cf.name, cfc.id, cfc.title, cfc.description, cfc.severity,
                       cfc.remediation, cfc.mapped_checks
                FROM custom_frameworks cf
                JOIN custom_framework_controls cfc ON cfc.custom_framework_id = cf.id
                WHERE cf.cloud_account_id = %s
            """, (cloud_account_id,))
            controls = cur.fetchall()

        with conn:
            with conn.cursor() as cur:
                for fw_id, fw_name, ctrl_id, title, description, severity, remediation, mapped_checks in controls:
                    ctrl_id = str(ctrl_id)
                    check_id = f"CUSTOM.{ctrl_id[:8]}"
                    resource_results = {}
                    for mc in mapped_checks:
                        for entry in by_check.get(mc, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, [])
                            resource_results[rid].append(entry["result"])

                    if not resource_results:
                        continue

                    for resource_id, results_list in resource_results.items():
                        result = "FAIL" if "FAIL" in results_list else "PASS"
                        status = "open" if result == "FAIL" else "pass"
                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")
                        full_description = f"{description or title} ({passed} checks passing, {failed} failing)"

                        cur.execute("""
                            INSERT INTO findings
                                (resource_id, check_id, title, description, severity, status, result, framework, remediation, details, detected_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                            ON CONFLICT (resource_id, check_id) DO UPDATE SET
                                title = EXCLUDED.title, description = EXCLUDED.description, severity = EXCLUDED.severity,
                                status = EXCLUDED.status, result = EXCLUDED.result, framework = EXCLUDED.framework,
                                remediation = EXCLUDED.remediation, details = EXCLUDED.details, detected_at = NOW()
                        """, (
                            resource_id, check_id, title, full_description, severity,
                            status, result, f"Custom: {fw_name}", remediation,
                            Json({"custom_control_id": ctrl_id, "mapped_checks": mapped_checks, "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("Custom Frameworks mapping complete for %s: %d findings upserted", cloud_account_id, findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ── entrypoint ────────────────────────────────────────────────────────

def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body)}


def handler(event, context):
    if event and event.get("migrate"):
        secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
        region = os.environ.get("SECRET_REGION", "eu-west-1")
        secret = json.loads(boto3.client("secretsmanager", region_name=region).get_secret_value(SecretId=secret_name)["SecretString"])
        conn = psycopg2.connect(
            host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
            user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
        )
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(ADMIN_MIGRATION_SQL)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()

    if not event or "httpMethod" not in event:
        account_id = (event or {}).get("cloud_account_id")
        if not account_id:
            return {"statusCode": 400, "body": json.dumps({"error": "cloud_account_id required"})}
        result = run_mapping(account_id)
        return {"statusCode": 200, "body": json.dumps(result)}

    method = event["httpMethod"]
    if method == "OPTIONS":
        return _resp(200, {})

    qs = event.get("queryStringParameters") or {}
    body = json.loads(event["body"]) if event.get("body") else {}

    conn = _get_connection()
    try:
        if method == "GET":
            account_id = qs.get("cloud_account_id")
            if not account_id:
                return _resp(400, {"error": "cloud_account_id required"})
            return _resp(200, {"frameworks": _list_frameworks(conn, account_id)})

        if method == "POST":
            action = body.get("action")
            if action == "create_framework":
                fw_id = _create_framework(conn, body["cloud_account_id"], body["name"])
                return _resp(200, {"id": fw_id})
            if action == "add_control":
                ctrl_id = _add_control(conn, body["framework_id"], body["title"], body.get("description", ""),
                                        body.get("severity", "MEDIUM"), body.get("remediation", ""), body["checks"])
                return _resp(200, {"id": ctrl_id})
            if action == "run":
                result = run_mapping(body["cloud_account_id"])
                return _resp(200, result)
            return _resp(400, {"error": f"unknown action: {action}"})

        if method == "DELETE":
            if qs.get("framework_id"):
                _delete_framework(conn, qs["framework_id"])
                return _resp(200, {"deleted": "framework"})
            if qs.get("control_id"):
                _delete_control(conn, qs["control_id"])
                return _resp(200, {"deleted": "control"})
            return _resp(400, {"error": "framework_id or control_id required"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.error("custom_framework_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": str(e)})
    finally:
        conn.close()
