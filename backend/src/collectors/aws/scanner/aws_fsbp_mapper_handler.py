"""
aws_fsbp_mapper_handler.py

Maps existing CIS/CloudWatch findings in the DB to AWS Foundational Security Best Practices controls.

Flow:
    1. Read all existing findings from the DB (CIS/FSBP framework)
    2. For each FSBP control, look at all mapped check_ids
    3. If ANY mapped check FAILs → FSBP control = FAIL (worst-case)
    4. Write FSBP findings back to findings table with framework = 'AWS Foundational Security Best Practices'

No new scans, no new collectors. Data already exists.
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
# AWS Foundational Security Best Practices → CIS/CloudWatch check mapping
# Mapped to existing scanners: IAM, S3, KMS, CloudWatch
# ---------------------------------------------------------------------------
FSBP_MAPPING = {

    # ── IAM Controls ───────────────────────────────────────────────────────

    "IAM.1": {
        "title": "IAM policies should not allow full '*' administrative privileges",
        "severity": "HIGH",
        "description": (
            "This control checks whether the default version of IAM policies "
            "has administrator access that includes a statement with 'Effect': 'Allow' "
            "with 'Action': '*' over 'Resource': '*'."
        ),
        "remediation": (
            "Remove policies that grant full administrative access. "
            "Apply least-privilege principle. Use specific actions and resources."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.5", "IAM.7", "IAM.8", "IAM.9",
        ],
    },
    "IAM.3": {
        "title": "IAM users' access keys should be rotated every 90 days or less",
        "severity": "MEDIUM",
        "description": (
            "This control checks whether the active access keys are rotated within 90 days."
        ),
        "remediation": (
            "Rotate active access keys every 90 days. Remove old access keys. "
            "Use IAM Access Analyzer to review key usage."
        ),
        "checks": [
            "IAM.3",
        ],
    },
    "IAM.4": {
        "title": "IAM root user access key should not exist",
        "severity": "CRITICAL",
        "description": (
            "This control checks whether the root user access key is present. "
            "The root account is the most privileged user in an AWS account."
        ),
        "remediation": (
            "Delete all root user access keys. Use IAM users for API access. "
            "Enable MFA on the root account."
        ),
        "checks": [
            "IAM.4",
        ],
    },
    "IAM.5": {
        "title": "MFA should be enabled for all IAM users that have a console password",
        "severity": "MEDIUM",
        "description": (
            "This control checks whether AWS multi-factor authentication (MFA) "
            "is enabled for all IAM users that use a console password."
        ),
        "remediation": (
            "Enable MFA for all IAM users with console access. "
            "Use hardware or virtual MFA devices."
        ),
        "checks": [
            "IAM.5",
        ],
    },
    "IAM.6": {
        "title": "Hardware MFA should be enabled for the root user",
        "severity": "CRITICAL",
        "description": (
            "This control checks whether your AWS account is enabled to use "
            "a hardware multi-factor authentication (MFA) device to sign in with root user credentials."
        ),
        "remediation": (
            "Enable hardware MFA for the root user account. "
            "Store the MFA device securely."
        ),
        "checks": [
            "IAM.6",
        ],
    },
    "IAM.7": {
        "title": "Password policies for IAM users should have strong configurations",
        "severity": "MEDIUM",
        "description": (
            "This control checks whether the account password policy for IAM users "
            "uses the recommended configurations."
        ),
        "remediation": (
            "Enforce strong password policies: minimum 14 characters, "
            "uppercase, lowercase, numbers, symbols, expiration 90 days, no reuse."
        ),
        "checks": [
            "IAM.7",
        ],
    },
    "IAM.8": {
        "title": "Unused IAM user credentials should be removed",
        "severity": "MEDIUM",
        "description": (
            "This control checks whether your IAM users have passwords or active "
            "access keys that have not been used for 90 days."
        ),
        "remediation": (
            "Remove unused IAM user passwords and access keys. "
            "Deactivate or delete unused IAM users."
        ),
        "checks": [
            "IAM.8",
        ],
    },

    # ── S3 Controls ────────────────────────────────────────────────────────

    # S3.1, S3.5, S3.8, S3.9, S3.12 were removed from this mapping on
    # 2026-09-03: they were wired to "checks" lists (S3.2.x Block Public
    # Access) that have no real relationship to what these controls
    # actually measure (server access logging, ACL usage, SSL enforcement).
    # A real customer fix (enabling S3 access logging on a bucket) was
    # verified live via the AWS API but never changed S3.9's stored
    # result, because S3.9 was never actually evaluating logging status —
    # it was silently re-reporting the Block Public Access result instead.
    # No existing scanner in this codebase calls get_bucket_logging,
    # get_bucket_ownership_controls, or inspects the bucket policy for a
    # SecureTransport deny statement, so there is currently no genuine
    # technical proxy for these 5 controls. They are listed in
    # MANUAL_EVIDENCE_CONTROLS below instead of being faked.

    # ── KMS Controls ───────────────────────────────────────────────────────

    "KMS.3": {
        "title": "AWS KMS keys should not be unintentionally deleted",
        "severity": "CRITICAL",
        "description": (
            "This control checks whether AWS KMS customer managed keys (CMK) "
            "are scheduled for deletion."
        ),
        "remediation": (
            "Do not schedule KMS keys for deletion. Cancel deletion if initiated. "
            "Ensure key retention period allows recovery."
        ),
        # Was self-referencing checks: ["KMS.3"] — but this codebase's own
        # rule engine (backend/src/rules/cis/kms/) uses its own internal
        # numbering where KMS.3 = "no wildcard actions in key policy", a
        # completely different check. The real "pending deletion" check is
        # internal KMS.5 (kms_5_key_not_pending_deletion.py). This control
        # was silently showing PASS/FAIL for the wrong underlying property.
        "checks": [
            "KMS.5",
        ],
    },
    "KMS.4": {
        "title": "AWS KMS key rotation should be enabled",
        "severity": "MEDIUM",
        "description": (
            "This control checks whether AWS KMS automatic key rotation is enabled "
            "for customer managed keys."
        ),
        "remediation": (
            "Enable automatic key rotation for all KMS customer managed keys. "
            "Rotation should happen annually."
        ),
        # Was self-referencing checks: ["KMS.4"] — internal KMS.4 is actually
        # "key not disabled" (kms_4_key_not_disabled.py), not rotation. The
        # real rotation check is internal KMS.1 (kms_1_rotation_enabled.py).
        # This control was showing PASS as long as keys weren't disabled,
        # regardless of whether rotation was ever turned on.
        "checks": [
            "KMS.1",
        ],
    },

    # ── CloudWatch Monitoring Controls ─────────────────────────────────────

    "CloudWatch.1": {
        "title": "CloudWatch alarms should be configured for CloudTrail",
        "severity": "MEDIUM",
        "description": (
            "This control checks whether CloudWatch metric filters and alarms "
            "are configured for CloudTrail API activity."
        ),
        "remediation": (
            "Configure CloudWatch metric filters for all CIS-required CloudTrail events. "
            "Create alarms to notify on suspicious activity."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("S3.1", "S3 Block Public Access setting should be enabled", "No scanner in this codebase inspects get_public_access_block at the account level"),
    ("S3.5", "S3 buckets should require requests to use Secure Socket Layer", "No scanner in this codebase inspects the bucket policy for a SecureTransport deny statement"),
    ("S3.8", "S3 Block Public Access setting should be enabled at the bucket level", "No scanner in this codebase inspects get_public_access_block at the bucket level"),
    ("S3.9", "S3 bucket server access logging should be enabled", "No scanner in this codebase calls get_bucket_logging"),
    ("S3.12", "S3 access control lists (ACLs) should not be used to manage user access to buckets", "No scanner in this codebase calls get_bucket_ownership_controls or get_bucket_acl"),
]

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

                # 1. Read all existing findings for this account
                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework != 'AWS Foundational Security Best Practices'
                """, (cloud_account_id,))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for mapping", len(rows))

                # Build lookup: check_id -> list of (resource_id, result, resource_name, resource_type)
                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                # 2. For each FSBP control, determine result per resource
                for fsbp_id, fsbp_def in FSBP_MAPPING.items():
                    # Collect all resource results across all mapped checks
                    resource_results: dict = {}  # resource_id -> list of results

                    for check_id in fsbp_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {
                                "results": [],
                                "resource_name": entry["resource_name"],
                                "resource_type": entry["resource_type"],
                            })
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("FSBP %s: no matching findings found, skipping", fsbp_id)
                        continue

                    # 3. Worst-case per resource: if ANY check FAILS → FSBP control FAILS
                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        fsbp_result = "FAIL" if "FAIL" in results_list else "PASS"
                        fsbp_status = "open" if fsbp_result == "FAIL" else "pass"

                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")
                        description = (
                            f"{fsbp_def['description']} "
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
                            fsbp_id,
                            fsbp_def["title"],
                            description,
                            fsbp_def["severity"],
                            fsbp_status,
                            fsbp_result,
                            "AWS Foundational Security Best Practices",
                            fsbp_def["remediation"],
                            json.dumps({
                                "fsbp_control": fsbp_id,
                                "mapped_checks": fsbp_def["checks"],
                                "passed": passed,
                                "failed": failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "FSBP %s / resource %s → %s (%d/%d passing)",
                            fsbp_id, resource_id, fsbp_result, passed, len(results_list)
                        )

        logger.info("FSBP mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("FSBP mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("FSBP mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
