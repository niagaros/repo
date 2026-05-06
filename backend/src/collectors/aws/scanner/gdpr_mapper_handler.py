"""
gdpr_mapper_handler.py

Maps existing CIS findings in the DB to GDPR Articles 25, 30 and 32.

Same approach as ISO 27001 mapper — reads existing findings, maps to GDPR
articles, writes back with framework = 'GDPR'.
"""

import json
import logging
import os

import boto3
import psycopg2

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CLOUD_ACCOUNT_ID = os.environ.get(
    "CLOUD_ACCOUNT_ID",
    "846e9e1b-c011-43ef-a38c-4762cc9b0f5a"
)

# ---------------------------------------------------------------------------
# GDPR → CIS check mapping
# ---------------------------------------------------------------------------
GDPR_MAPPING = {

    "Art.25": {
        "title": "Data Protection by Design and by Default",
        "severity": "HIGH",
        "description": (
            "Implement appropriate technical and organisational measures to ensure "
            "data protection principles are integrated into processing activities "
            "by default (encryption, access control, data minimisation)."
        ),
        "remediation": (
            "Enable S3 default encryption and block public access. "
            "Enable KMS key rotation for all customer-managed keys. "
            "Apply least-privilege IAM policies to restrict access to personal data. "
            "Remove unused IAM access keys and enforce strong password policies."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4",
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },

    "Art.30": {
        "title": "Records of Processing Activities",
        "severity": "MEDIUM",
        "description": (
            "Maintain records of all categories of processing activities under your "
            "responsibility, including purpose, data categories, recipients and "
            "retention periods. Logging and monitoring are required to demonstrate compliance."
        ),
        "remediation": (
            "Enable CloudTrail in all regions and ensure logs are delivered to CloudWatch. "
            "Configure metric filters and alarms for critical API events. "
            "Ensure S3 access logging is enabled on all buckets storing personal data."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
        ],
    },

    "Art.32": {
        "title": "Security of Processing",
        "severity": "HIGH",
        "description": (
            "Implement appropriate technical and organisational measures to ensure "
            "a level of security appropriate to the risk, including encryption of "
            "personal data, integrity and confidentiality, and ongoing testing."
        ),
        "remediation": (
            "Enable MFA for root and all IAM console users. "
            "Enable KMS encryption for all data at rest. "
            "Block public S3 access and enable bucket encryption. "
            "Enable CloudWatch alarms for unauthorised API activity. "
            "Rotate IAM access keys every 90 days."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4",
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
}


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _get_connection():
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    client = boto3.client("secretsmanager", region_name=region)
    secret = json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return psycopg2.connect(
        host=secret["host"],
        port=secret.get("port", 5432),
        dbname=secret["database"],
        user=secret["username"],
        password=secret["password"],
        sslmode="require",
        connect_timeout=10,
    )


# ---------------------------------------------------------------------------
# Core mapper
# ---------------------------------------------------------------------------

def run_mapping(cloud_account_id: str) -> dict:
    conn = _get_connection()
    findings_upserted = 0

    try:
        with conn:
            with conn.cursor() as cur:

                # 1. Read all existing findings for this account (non-GDPR)
                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework != 'GDPR'
                """, (cloud_account_id,))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for GDPR mapping", len(rows))

                # Build lookup: check_id -> list of findings
                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                # 2. For each GDPR article, determine result per resource
                for article_id, article_def in GDPR_MAPPING.items():
                    resource_results: dict = {}

                    for check_id in article_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {
                                "results": [],
                                "resource_name": entry["resource_name"],
                                "resource_type": entry["resource_type"],
                            })
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("GDPR %s: no matching findings found, skipping", article_id)
                        continue

                    # 3. Worst-case: if ANY check FAILS → article FAILS
                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        gdpr_result = "FAIL" if "FAIL" in results_list else "PASS"
                        gdpr_status = "open" if gdpr_result == "FAIL" else "pass"

                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")
                        description = (
                            f"{article_def['description']} "
                            f"({passed} checks passing, {failed} failing)"
                        )

                        cur.execute("""
                            INSERT INTO findings
                                (resource_id, check_id, title, description,
                                 severity, status, result, framework, remediation,
                                 details, detected_at)
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
                        """, (
                            resource_id,
                            article_id,
                            article_def["title"],
                            description,
                            article_def["severity"],
                            gdpr_status,
                            gdpr_result,
                            "GDPR",
                            article_def["remediation"],
                            json.dumps({
                                "gdpr_article":  article_id,
                                "mapped_checks": article_def["checks"],
                                "passed":        passed,
                                "failed":        failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "GDPR %s / resource %s → %s (%d/%d passing)",
                            article_id, resource_id, gdpr_result, passed, len(results_list)
                        )

        logger.info("GDPR mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("GDPR mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("GDPR mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
