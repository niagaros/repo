"""
iso27001_mapper_handler.py

Maps existing CIS/FSBP findings in the DB to ISO 27001:2022 Annex A controls.

Flow:
    1. Read all existing findings from the DB (CIS/FSBP framework)
    2. For each ISO control, look at all mapped check_ids
    3. If ANY mapped check FAILs → ISO control = FAIL (worst-case)
    4. Write ISO findings back to findings table with framework = 'ISO 27001:2022'

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
# ISO 27001:2022 → CIS/FSBP check mapping
# Add new entries here as more scanners are added.
# ---------------------------------------------------------------------------
ISO_MAPPING = {

    # ── A.5 Organizational controls ────────────────────────────────────────────

    "A.5.15": {
        "title": "Access Control",
        "severity": "HIGH",
        "description": (
            "Rules to control physical and logical access to information and other "
            "associated assets should be established."
        ),
        "remediation": (
            "Enforce IAM password policy with complexity requirements. "
            "Enable MFA for root and all IAM console users. "
            "Remove unused access keys and rotate active keys every 90 days. "
            "Remove root access keys. Attach policies to groups/roles only. "
            "Set minimum default repository permissions in GitHub organization settings. "
            "Restrict repository creation and deletion to authorized members only."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
            "github_1.3.8", "github_1.2.2", "github_1.2.3",
        ],
    },
    "A.5.17": {
        "title": "Authentication Information",
        "severity": "HIGH",
        "description": (
            "Allocation and management of authentication information should be controlled "
            "by a management process, including advising personnel on the appropriate "
            "handling of authentication information."
        ),
        "remediation": (
            "Enable MFA for the root account. "
            "Enable MFA for all IAM users with console access. "
            "Remove root access keys and enforce strong password policies. "
            "Require two-factor authentication for all GitHub organization members "
            "and outside collaborators."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.6",
            "github_1.3.4", "github_1.3.5",
        ],
    },
    "A.5.18": {
        "title": "Access Rights",
        "severity": "HIGH",
        "description": (
            "Access rights to information and other associated assets should be "
            "provisioned, reviewed, modified and removed in accordance with the "
            "organisation's topic-specific policy on and rules for access control."
        ),
        "remediation": (
            "Remove administrative privileges from IAM users, groups, and roles. "
            "Attach policies only to groups or roles, not directly to users. "
            "Review and remove overly permissive inline and managed policies."
        ),
        "checks": [
            "IAM.5", "IAM.7", "IAM.8", "IAM.9",
        ],
    },

    # ── A.8 Technological controls ─────────────────────────────────────────────

    "A.8.2": {
        "title": "Privileged Access Rights",
        "severity": "HIGH",
        "description": (
            "The allocation and use of privileged access rights should be restricted "
            "and managed."
        ),
        "remediation": (
            "Remove administrative privileges from IAM users, groups, and roles. "
            "Do not attach policies with full administrative access. "
            "Review and remove inline policies with administrative privileges."
        ),
        "checks": [
            "IAM.5", "IAM.7", "IAM.8", "IAM.9",
        ],
    },
    "A.8.3": {
        "title": "Information Access Restriction",
        "severity": "HIGH",
        "description": (
            "Access to information and other associated assets should be restricted "
            "in accordance with the established topic-specific policy on access control."
        ),
        "remediation": (
            "Ensure S3 buckets block public access. Remove public bucket policies. "
            "Apply least-privilege IAM policies."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },
    "A.8.4": {
        "title": "Access to Source Code",
        "severity": "HIGH",
        "description": (
            "Read and write access to source code, development tools and software libraries "
            "should be appropriately managed."
        ),
        "remediation": (
            "Enable branch protection on the default branch. "
            "Require at least 2 approvals before merging. "
            "Disallow force pushes and branch deletions. "
            "Enforce branch protection rules for administrators. "
            "Set minimum repository permissions for organization members."
        ),
        "checks": [
            "github_1.1.3", "github_1.1.4", "github_1.1.7",
            "github_1.1.14", "github_1.1.16", "github_1.1.17", "github_1.1.20",
            "github_1.3.8",
        ],
    },
    "A.8.5": {
        "title": "Secure Authentication",
        "severity": "HIGH",
        "description": (
            "Secure authentication technologies and procedures should be implemented "
            "based on information access restrictions and the topic-specific policy on access control."
        ),
        "remediation": (
            "Enable MFA for all IAM users with console access. Enable MFA for the root account. "
            "Rotate access keys every 90 days. Enable KMS key rotation. "
            "Require two-factor authentication for all GitHub organization members."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "github_1.3.4", "github_1.3.5",
        ],
    },
    "A.8.8": {
        "title": "Management of Technical Vulnerabilities",
        "severity": "HIGH",
        "description": (
            "Information about technical vulnerabilities of information systems in use "
            "should be obtained, the organisation's exposure to such vulnerabilities evaluated "
            "and appropriate measures taken."
        ),
        "remediation": (
            "Enable Dependabot (vulnerability) alerts on all GitHub repositories. "
            "Enable secret scanning to detect accidentally committed credentials. "
            "Review and remediate all open dependency alerts regularly."
        ),
        "checks": [
            "github_1.5.1", "github_1.5.5",
        ],
    },
    "A.8.29": {
        "title": "Security Testing in Development and Acceptance",
        "severity": "MEDIUM",
        "description": (
            "Security testing processes should be defined and implemented in the development lifecycle."
        ),
        "remediation": (
            "Require status checks (CI/CD) to pass before merging pull requests. "
            "Require code owner reviews on critical repositories. "
            "Enforce conversation resolution before merging to ensure review comments are addressed."
        ),
        "checks": [
            "github_1.1.7", "github_1.1.9", "github_1.1.11",
        ],
    },
    "A.8.32": {
        "title": "Change Management",
        "severity": "MEDIUM",
        "description": (
            "Changes to information processing facilities and information systems "
            "should be subject to change management procedures."
        ),
        "remediation": (
            "Require pull request reviews before merging to main branches. "
            "Dismiss stale reviews when new commits are pushed. "
            "Require status checks to pass. Restrict who can push directly to protected branches."
        ),
        "checks": [
            "github_1.1.3", "github_1.1.4", "github_1.1.9",
            "github_1.1.11", "github_1.1.20",
        ],
    },
    "A.8.11": {
        "title": "Data Masking",
        "severity": "HIGH",
        "description": (
            "Data masking should be used in accordance with the organisation's topic-specific "
            "policy on access control and other related topic-specific policies, and business "
            "requirements, taking applicable legislation into consideration."
        ),
        "remediation": (
            "Enable KMS CMK encryption for all data stores. Enable automatic KMS key rotation. "
            "Ensure KMS keys are not deleted unintentionally. "
            "Enable default encryption on S3 buckets using KMS."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },
    "A.8.15": {
        "title": "Logging",
        "severity": "MEDIUM",
        "description": (
            "Logs that record activities, exceptions, faults and other relevant events "
            "should be produced, stored, protected and analysed."
        ),
        "remediation": (
            "Ensure CloudTrail is enabled in all regions, delivers logs to CloudWatch, "
            "and has metric filters and alarms configured for all CIS-required events."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
    "A.8.16": {
        "title": "Monitoring Activities",
        "severity": "MEDIUM",
        "description": (
            "Networks, systems and applications should be monitored for anomalous behaviour "
            "and appropriate actions taken to evaluate potential information security incidents."
        ),
        "remediation": (
            "Configure CloudWatch alarms for all critical API activity. "
            "Ensure SNS topics have active subscriptions to notify on alarm state changes."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
    "A.8.24": {
        "title": "Use of Cryptography",
        "severity": "HIGH",
        "description": (
            "Rules for the effective use of cryptography, including cryptographic key management, "
            "should be defined and implemented."
        ),
        "remediation": (
            "Ensure KMS CMKs are used for encryption of sensitive data. "
            "Enable automatic key rotation. Ensure S3 buckets use server-side encryption."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
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

                # 1. Read all existing findings for this account
                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework != 'ISO 27001:2022'
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

                # 2. For each ISO control, determine result per resource
                for iso_id, iso_def in ISO_MAPPING.items():
                    # Collect all resource results across all mapped checks
                    resource_results: dict = {}  # resource_id -> list of results

                    for check_id in iso_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {
                                "results": [],
                                "resource_name": entry["resource_name"],
                                "resource_type": entry["resource_type"],
                            })
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("ISO %s: no matching findings found, skipping", iso_id)
                        continue

                    # 3. Worst-case per resource: if ANY check FAILS → ISO control FAILS
                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        iso_result = "FAIL" if "FAIL" in results_list else "PASS"
                        iso_status = "open" if iso_result == "FAIL" else "pass"

                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")
                        description = (
                            f"{iso_def['description']} "
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
                            iso_id,
                            iso_def["title"],
                            description,
                            iso_def["severity"],
                            iso_status,
                            iso_result,
                            "ISO 27001:2022",
                            iso_def["remediation"],
                            json.dumps({
                                "iso_control": iso_id,
                                "mapped_checks": iso_def["checks"],
                                "passed": passed,
                                "failed": failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "ISO %s / resource %s → %s (%d/%d passing)",
                            iso_id, resource_id, iso_result, passed, len(results_list)
                        )

        logger.info("ISO mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("ISO 27001 mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("ISO 27001 mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
