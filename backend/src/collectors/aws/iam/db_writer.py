"""
db_writer.py

Persists IAM scan results to the cspm_production PostgreSQL database.
"""

import json
import logging
import os
from typing import Any, Dict, List

import boto3
import psycopg2

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _get_db_credentials() -> Dict[str, Any]:
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
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
        connect_timeout=10,
    )


STATUS_MAP = {"PASS": "pass", "FAIL": "open"}


def _normalize_severity(raw: str) -> str:
    valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    upper = (raw or "").upper()
    return upper if upper in valid else "MEDIUM"


def _normalize_status(raw: str) -> str:
    return STATUS_MAP.get((raw or "").upper(), "open")


def _normalize_result(raw: str) -> str:
    upper = (raw or "").upper()
    return "PASS" if upper == "PASS" else "FAIL"


def save_scan_results(
    snapshot: Dict[str, Any],
    results: List[Dict[str, Any]],
    cloud_account_id: str,
) -> Dict[str, int]:
    region = snapshot.get("region", "global")
    resources: List[Dict[str, Any]] = snapshot.get("resources", [])

    conn = _get_connection()
    resources_upserted = 0
    findings_upserted = 0
    score = 0

    try:
        with conn:
            with conn.cursor() as cur:

                # 1. Upsert resources
                resource_id_cache: Dict[str, str] = {}

                for resource in resources:
                    resource_id = resource.get("resource_id")
                    if not resource_id:
                        continue

                    cur.execute(
                        """
                        INSERT INTO resources
                            (cloud_account_id, resource_type, resource_id,
                             resource_name, region, config, last_scanned_at)
                        VALUES
                            (%s, %s, %s, %s, %s, %s, NOW())
                        ON CONFLICT (cloud_account_id, resource_id)
                        DO UPDATE SET
                            resource_name   = EXCLUDED.resource_name,
                            region          = EXCLUDED.region,
                            config          = EXCLUDED.config,
                            last_scanned_at = NOW()
                        RETURNING id
                        """,
                        (
                            cloud_account_id,
                            resource.get("resource_type", "iam-unknown"),
                            resource_id,
                            resource.get("resource_name", ""),
                            resource.get("region", "global"),
                            json.dumps(resource.get("config", {}), default=str),
                        ),
                    )
                    row = cur.fetchone()
                    resource_id_cache[resource_id] = str(row[0])
                    resources_upserted += 1

                # 2. Upsert findings
                account_resource_id = next(
                    (r.get("resource_id") for r in resources if r.get("resource_type") == "iam-account"),
                    None
                )
                account_resource_uuid = resource_id_cache.get(account_resource_id) if account_resource_id else None

                for result in results:
                    check_id = result.get("check", "")

                    if not account_resource_uuid:
                        logger.warning("No iam-account resource found, skipping finding %s", check_id)
                        continue

                    cur.execute(
                        """
                        INSERT INTO findings
                            (resource_id, check_id, title, description,
                             severity, status, result, framework, remediation, details, detected_at)
                        VALUES
                            (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                        ON CONFLICT (resource_id, check_id)
                        DO UPDATE SET
                            title       = EXCLUDED.title,
                            description = EXCLUDED.description,
                            severity    = EXCLUDED.severity,
                            status      = EXCLUDED.status,
                            result      = EXCLUDED.result,
                            framework   = EXCLUDED.framework,
                            remediation = EXCLUDED.remediation,
                            details     = EXCLUDED.details,
                            detected_at = NOW()
                        """,
                        (
                            account_resource_uuid,
                            check_id,
                            result.get("title", check_id),
                            result.get("reason", ""),
                            _normalize_severity(result.get("severity", "MEDIUM")),
                            _normalize_status(result.get("status", "FAIL")),
                            _normalize_result(result.get("status", "FAIL")),
                            "CIS AWS Foundations Benchmark v5.0.0",
                            result.get("remediation", "Consult the CIS AWS Foundations Benchmark documentation."),
                            json.dumps(result, default=str),
                        ),
                    )
                    findings_upserted += 1

                # 3. Update compliance score
                total = len(results)
                passed = sum(1 for r in results if (r.get("status") or "").upper() == "PASS")
                failed = total - passed
                score = round((passed / total) * 100) if total > 0 else 0

                compliance_score = {
                    "score": score,
                    "passed": passed,
                    "failed": failed,
                    "total": total,
                }

                cur.execute(
                    """UPDATE cloud_accounts
                       SET last_scan_at = NOW(),
                           compliance_score = %s
                       WHERE id = %s""",
                    (json.dumps(compliance_score, default=str), cloud_account_id),
                )

    finally:
        conn.close()

    return {
        "resources_upserted": resources_upserted,
        "findings_upserted": findings_upserted,
        "compliance_score": score,
    }