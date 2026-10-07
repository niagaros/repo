import json
import logging
import os
from typing import Dict, List

import boto3
import psycopg2

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# DB CONNECTION
# ---------------------------------------------------------------------------

def _get_db_credentials():
    secret_name = os.environ.get("DB_SECRET_NAME")
    region = os.environ.get("SECRET_REGION", "eu-west-1")

    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])


def _get_connection():
    creds = _get_db_credentials()
    return psycopg2.connect(
        host=creds["host"],
        port=creds.get("port", 5432),
        dbname=creds["database"],
        user=creds["username"],
        password=creds["password"],
        sslmode="require",
    )


# ---------------------------------------------------------------------------
# SCANNER STATUS UPDATE
# ---------------------------------------------------------------------------

def update_scanner_status(function_name: str, status: str, error: str = None):
    conn = _get_connection()

    try:
        with conn:
            with conn.cursor() as cur:

                if status == "triggered":
                    cur.execute("""
                        UPDATE scanners
                        SET last_triggered_at = NOW(),
                            last_status = %s,
                            total_runs = total_runs + 1
                        WHERE function_name = %s
                    """, (status, function_name))

                elif status == "failed":
                    cur.execute("""
                        UPDATE scanners
                        SET last_status = %s,
                            last_error = %s,
                            total_runs = total_runs + 1,
                            total_failures = total_failures + 1
                        WHERE function_name = %s
                    """, (status, error, function_name))

    finally:
        conn.close()


# ---------------------------------------------------------------------------
# SAVE KMS RESULTS
# ---------------------------------------------------------------------------

def save_kms_results(snapshot: Dict, results: List[Dict], cloud_account_id: str):

    conn = _get_connection()
    resource_uuid_cache = {}

    try:
        with conn:
            with conn.cursor() as cur:

                # ---------------------------------------------------------
                # 1️⃣ UPSERT RESOURCES
                # ---------------------------------------------------------
                for key in snapshot["kms_keys"]:

                    cur.execute("""
                        INSERT INTO resources
                        (cloud_account_id, resource_type, resource_id,
                         resource_name, region, config, last_scanned_at)
                        VALUES (%s,%s,%s,%s,%s,%s,NOW())
                        ON CONFLICT (cloud_account_id, resource_id)
                        DO UPDATE SET
                            resource_name = EXCLUDED.resource_name,
                            region = EXCLUDED.region,
                            config = EXCLUDED.config,
                            last_scanned_at = NOW()
                        RETURNING id
                    """, (
                        cloud_account_id,
                        "kms-key",
                        key["arn"],
                        key.get("alias"),
                        snapshot["region"],
                        json.dumps(key, default=str)
                    ))

                    resource_uuid = cur.fetchone()[0]
                    resource_uuid_cache[key["arn"]] = resource_uuid

                # ---------------------------------------------------------
                # 2️⃣ INSERT / UPDATE FINDINGS
                # ---------------------------------------------------------
                for result in results:

                    key_arn = result["resource_id"]
                    resource_uuid = resource_uuid_cache.get(key_arn)

                    if not resource_uuid:
                        continue

                    db_status = "open" if result["status"] == "FAIL" else "pass"

                    cur.execute("""
                        INSERT INTO findings
                        (resource_id, check_id, title, description,
                         severity, status, result, framework,
                         remediation, detected_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                        ON CONFLICT (resource_id, check_id)
                        DO UPDATE SET
                            title = EXCLUDED.title,
                            description = EXCLUDED.description,
                            severity = EXCLUDED.severity,
                            status = EXCLUDED.status,
                            result = EXCLUDED.result,
                            remediation = EXCLUDED.remediation,
                            detected_at = NOW()
                    """, (
                        resource_uuid,
                        result["control_id"],
                        result.get("title"),
                        result.get("message"),
                        result.get("severity", "medium"),
                        db_status,
                        result["status"],   # PASS / FAIL
                        "CIS AWS Foundations Benchmark v5.0.0",
                        result.get("remediation")
                    ))

                # ---------------------------------------------------------
                # 3️⃣ UPDATE COMPLIANCE SCORE
                # ---------------------------------------------------------
                total = len(results)
                passed = sum(1 for r in results if r["status"] == "PASS")
                failed = total - passed
                score = round((passed / total) * 100) if total > 0 else 0

                cur.execute("""
                    UPDATE cloud_accounts
                    SET last_scan_at = NOW(),
                        compliance_score = %s
                    WHERE id = %s
                """, (
                    json.dumps({
                        "score": score,
                        "passed": passed,
                        "failed": failed,
                        "total": total
                    }),
                    cloud_account_id
                ))

        logger.info("✅ KMS results saved successfully")

    finally:
        conn.close()