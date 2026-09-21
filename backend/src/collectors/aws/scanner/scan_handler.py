"""
scan_handler.py
Connect an AWS account, validate the connection, and scan it (issue #279: "Cloud infrastructure integration").

  POST {"action": "validate_connection", "cloud_account_id": ...}
        Assume the account's CSPMScannerRole (with its external id) and prove the connection: the caller identity must be
        the AWS account that was onboarded, and each read permission the scanners need is probed individually.
  POST {"action": "scan", "cloud_account_id": ...}
        Start a scan of THIS account only (the orchestrator no longer re-scans every customer). Throttled per account.
  GET  ?cloud_account_id=...   last scan time and the most recent scan request.

Everything is owner-only through the shared tenant guard. All AWS calls are read-only.
"""
import json
import logging
import os

import boto3
import psycopg2

from collectors.aws.scanner.tenant_auth import guard

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
ORCHESTRATOR = os.environ.get("ORCHESTRATOR_FUNCTION_NAME", "cspm_orchestrator")
THROTTLE_SECONDS = int(os.environ.get("SCAN_THROTTLE_SECONDS", "120"))

CORS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS scan_requests (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    requested_by     TEXT,
    requested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_requests_account ON scan_requests (cloud_account_id, requested_at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_requests TO cspm_lambda;
"""

# The read-only calls the scanners depend on; each is probed separately so a partial permission gap is visible.
PERMISSION_PROBES = (
    ("ec2:DescribeRegions", lambda s: s.client("ec2", region_name=REGION).describe_regions()),
    ("s3:ListAllMyBuckets", lambda s: s.client("s3").list_buckets()),
    ("iam:GetAccountSummary", lambda s: s.client("iam").get_account_summary()),
    ("rds:DescribeDBInstances", lambda s: s.client("rds", region_name=REGION).describe_db_instances(MaxRecords=20)),
    ("kms:ListKeys", lambda s: s.client("kms", region_name=REGION).list_keys(Limit=5)),
)


def _resp(status, body):
    return {"statusCode": status, "headers": CORS, "body": json.dumps(body, default=str)}


def _get_connection():
    client = boto3.client("secretsmanager", region_name=REGION)
    s = json.loads(client.get_secret_value(SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"],
                            password=s["password"], sslmode="require", connect_timeout=10)


def _account(cur, account_id):
    cur.execute("SELECT id, account_name, account_id, role_arn, external_id, region, last_scan_at FROM cloud_accounts WHERE id = %s", (account_id,))
    r = cur.fetchone()
    return None if not r else {"id": str(r[0]), "name": r[1], "aws_account_id": r[2], "role_arn": r[3], "external_id": str(r[4]),
                               "region": r[5], "last_scan_at": r[6]}


def validate_connection(acct):
    """Prove the connection with the real role; never raises."""
    result = {"connected": False, "expected_aws_account_id": acct["aws_account_id"], "role_arn": acct["role_arn"], "checks": []}
    try:
        creds = boto3.client("sts", region_name=REGION).assume_role(
            RoleArn=acct["role_arn"], ExternalId=acct["external_id"], RoleSessionName="niagaros-validate-connection", DurationSeconds=900)["Credentials"]
    except Exception as e:
        result["error"] = f"Could not assume the scanner role: {type(e).__name__}: {str(e)[:200]}"
        return result
    session = boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                            aws_session_token=creds["SessionToken"], region_name=REGION)
    identity = session.client("sts").get_caller_identity()
    result["aws_account_id"] = identity["Account"]
    result["account_matches"] = identity["Account"] == acct["aws_account_id"]
    for name, probe in PERMISSION_PROBES:
        try:
            probe(session)
            result["checks"].append({"permission": name, "ok": True})
        except Exception as e:
            result["checks"].append({"permission": name, "ok": False, "error": f"{type(e).__name__}: {str(e)[:160]}"})
    result["connected"] = result["account_matches"] and all(c["ok"] for c in result["checks"])
    return result


def handler(event, context):
    if event and event.get("action") == "migrate":
        conn = _get_connection()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(BOOTSTRAP_SQL)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()
    if not event or "httpMethod" not in event:
        return {"statusCode": 400, "body": json.dumps({"error": "not an API Gateway event"})}
    method = event["httpMethod"]
    if method == "OPTIONS":
        return _resp(200, {})
    qs = event.get("queryStringParameters") or {}
    try:
        body = json.loads(event["body"]) if event.get("body") else {}
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
    except (ValueError, TypeError):
        return _resp(400, {"error": "Invalid JSON"})

    account_id = qs.get("cloud_account_id") or body.get("cloud_account_id")
    conn = _get_connection()
    try:
        denied = guard(event, conn, qs, body, {}, None)
        if denied:
            return _resp(denied[0], {"error": denied[1]})
        if not account_id:
            return _resp(400, {"error": "cloud_account_id is required"})
        with conn.cursor() as cur:
            acct = _account(cur, account_id)
        if not acct:
            return _resp(404, {"error": "account not found"})

        if method == "GET":
            with conn.cursor() as cur:
                cur.execute("SELECT requested_at, requested_by FROM scan_requests WHERE cloud_account_id = %s ORDER BY requested_at DESC LIMIT 1", (account_id,))
                last = cur.fetchone()
            return _resp(200, {"last_scan_at": acct["last_scan_at"], "last_request": None if not last else {"requested_at": last[0], "requested_by": last[1]}})

        if method == "POST":
            action = body.get("action")
            if action == "validate_connection":
                return _resp(200, validate_connection(acct))
            if action == "scan":
                with conn.cursor() as cur:
                    cur.execute("SELECT EXTRACT(EPOCH FROM (now() - max(requested_at))) FROM scan_requests WHERE cloud_account_id = %s", (account_id,))
                    age = cur.fetchone()[0]
                if age is not None and age < THROTTLE_SECONDS:
                    return _resp(429, {"error": f"A scan was requested {int(age)}s ago; wait {int(THROTTLE_SECONDS - age)}s before requesting another."})
                with conn:
                    with conn.cursor() as cur:
                        cur.execute("INSERT INTO scan_requests (cloud_account_id, requested_by) VALUES (%s, %s) RETURNING requested_at",
                                    (account_id, body.get("requested_by") or "user"))
                        requested_at = cur.fetchone()[0]
                boto3.client("lambda", region_name=REGION).invoke(
                    FunctionName=ORCHESTRATOR, InvocationType="Event", Payload=json.dumps({"cloud_account_id": account_id}))
                return _resp(202, {"message": "Scan started for this account", "requested_at": requested_at})
            return _resp(400, {"error": f"unknown action: {action}"})
        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.error("scan_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": "internal error"})
    finally:
        conn.close()
