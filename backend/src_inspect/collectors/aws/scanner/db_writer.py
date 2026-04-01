"""
db_writer.py

Persists CloudWatch scan results to the cspm_production PostgreSQL database.

Flow:
    1. Upsert the CloudTrail trail into `resources`
    2. Upsert each CIS check result into `findings`
    3. Update `last_scan_at` on the `cloud_accounts` row
"""

import json
import logging
import os
from typing import Any, Dict, List

import boto3
import psycopg2
from psycopg2.extras import execute_values

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# DB connection
# ---------------------------------------------------------------------------

def _get_db_credentials() -> Dict[str, Any]:
    """
    Fetches database credentials from AWS Secrets Manager.
    Secret name: cspm/database/credentials
    """
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")

    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])


def _get_connection():
    """Opens a psycopg2 connection using credentials from Secrets Manager."""
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

STATUS_MAP = {
    "PASS": "resolved",
    "FAIL": "open",
}


def _normalize_severity(raw: str) -> str:
    return SEVERITY_MAP.get((raw or "").upper(), "medium")


def _normalize_status(raw: str) -> str:
    return STATUS_MAP.get((raw or "").upper(), "open")




# ---------------------------------------------------------------------------
# Core writer
# ---------------------------------------------------------------------------

def save_scan_results(
    snapshot: Dict[str, Any],
    results: List[Dict[str, Any]],
    cloud_account_id: str,
) -> Dict[str, int]:
    """
    Persists a completed scan to the database.

    Args:
        snapshot:          The raw collector snapshot (used for resource config).
        results:           List of check result dicts from result.to_dict().
        cloud_account_id:  UUID of the cloud_accounts row for this AWS account.

    Returns:
        Dict with counts: {"resources_upserted": N, "findings_upserted": N}
    """
    region = snapshot.get("region", "unknown")
    account_id = snapshot.get("account_id", "unknown")

    trails = snapshot.get("cloudtrail", {}).get("trails", [])

    # Build a lookup: trail_arn -> trail dict (for resource config)
    trail_by_arn: Dict[str, Dict] = {
        t["trail_arn"]: t for t in trails if t.get("trail_arn")
    }

    conn = _get_connection()
    resources_upserted = 0
    findings_upserted = 0

    try:
        with conn:
            with conn.cursor() as cur:

                # ----------------------------------------------------------------
                # 1. Upsert resources
                #    One resource row per unique trail_arn referenced in results.
                # ----------------------------------------------------------------
                trail_arns_in_results = {
                    r["details"]["trail_arn"]
                    for r in results
                    if r.get("details", {}).get("trail_arn")
                }

                # resource_uuid cache: trail_arn -> UUID in DB
                resource_id_cache: Dict[str, str] = {}

                for trail_arn in trail_arns_in_results:
                    trail_data = trail_by_arn.get(trail_arn, {})
                    trail_name = trail_data.get("name") or trail_arn.split("/")[-1]

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
                            "cloudwatch_trail",
                            trail_arn,
                            trail_name,
                            region,
                            json.dumps(trail_data, default=str),
                        ),
                    )
                    row = cur.fetchone()
                    resource_id_cache[trail_arn] = str(row[0])
                    resources_upserted += 1
                    logger.info("Upserted resource: %s → %s", trail_arn, resource_id_cache[trail_arn])

                # ----------------------------------------------------------------
                # 2. Upsert findings
                #    One finding row per (resource_id, check_id).
                # ----------------------------------------------------------------
                for result in results:
                    control_id = result.get("control_id", "")
                    trail_arn = result.get("details", {}).get("trail_arn")

                    if not trail_arn or trail_arn not in resource_id_cache:
                        logger.warning("No resource found for trail_arn=%s, skipping finding %s", trail_arn, control_id)
                        continue

                    resource_uuid = resource_id_cache[trail_arn]
                    reasons = result.get("reasons", [])
                    description = " | ".join(reasons) if reasons else result.get("title", "")
                    remediation = result.get("remediation", "Raadpleeg de CIS AWS Foundations Benchmark documentatie voor herstelstappen.")

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
                            resource_uuid,
                            control_id,
                            result.get("title", ""),
                            description,
                            _normalize_severity(result.get("severity", "MEDIUM")),
                            _normalize_status(result.get("status", "FAIL")),
                            result.get("status", "FAIL"),
                            "CIS AWS Foundations Benchmark",
                            remediation,
                            json.dumps(result.get("details", {}), default=str),
                        ),
                    )
                    findings_upserted += 1
                    logger.info("Upserted finding: %s / %s → %s", control_id, resource_uuid, result.get("status"))

                # ----------------------------------------------------------------
                # 3. Calculate compliance score and update cloud_accounts
                # ----------------------------------------------------------------
                total = len(results)
                passed = sum(1 for r in results if r.get("status") == "PASS")
                failed = total - passed
                score = round((passed / total) * 100) if total > 0 else 0

                compliance_score = {
                    "score": score,
                    "passed": passed,
                    "failed": failed,
                    "total": total,
                    "scanned_at": str(snapshot.get("collected_at", "")),
                }

                cur.execute(
                    """UPDATE cloud_accounts
                       SET last_scan_at = NOW(),
                           compliance_score = %s
                       WHERE id = %s""",
                    (json.dumps(compliance_score, default=str), cloud_account_id),
                )
                logger.info(
                    "Updated compliance score for cloud_account_id=%s: %s/100 (%d/%d passing)",
                    cloud_account_id, score, passed, total
                )

    finally:
        conn.close()

    return {
        "resources_upserted": resources_upserted,
        "findings_upserted": findings_upserted,
        "compliance_score": score,
    }