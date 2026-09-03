"""
soc2_mapper_handler.py

Maps existing CIS findings in the DB to SOC 2 Trust Services Criteria.

Same approach as ISO 27001 mapper — reads existing findings, maps to SOC 2
controls, writes back with framework = 'SOC2'.
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
# SOC 2 Trust Services Criteria → CIS check mapping
# ---------------------------------------------------------------------------
SOC2_MAPPING = {

    # ── CC1 — Control Environment ──────────────────────────────────────────

    "CC1.3": {
        "title": "Board Oversight of Security",
        "severity": "HIGH",
        "description": (
            "The board of directors demonstrates independence from management and "
            "exercises oversight of the development and performance of internal controls."
        ),
        "remediation": (
            "Remove administrative privileges from IAM users and roles. "
            "Enable MFA for all administrators. "
            "Apply least-privilege IAM policies and review access rights regularly."
        ),
        "checks": [
            "IAM.5", "IAM.7", "IAM.8", "IAM.9",
        ],
    },

    # ── CC2 — Communication ────────────────────────────────────────────────

    "CC2.2": {
        "title": "Internal Communication of Objectives",
        "severity": "MEDIUM",
        "description": (
            "The entity internally communicates information, including objectives "
            "and responsibilities for internal control, necessary to support the "
            "functioning of internal control."
        ),
        "remediation": (
            "Configure CloudWatch alarms and SNS notifications for critical security events. "
            "Ensure CloudTrail is enabled and delivering logs to CloudWatch Logs."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.14",
        ],
    },

    # ── CC3 — Risk Assessment ──────────────────────────────────────────────

    "CC3.2": {
        "title": "Risk Identification and Analysis",
        "severity": "HIGH",
        "description": (
            "The entity identifies risks to the achievement of its objectives across "
            "the entity and analyzes risks as a basis for determining how the risks "
            "should be managed."
        ),
        "remediation": (
            "Enable MFA for root and all IAM users. Remove root access keys. "
            "Ensure IAM password policy enforces complexity and rotation. "
            "Enable CloudWatch metric filters for root account usage."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.6", "IAM.7",
            "CloudWatch.1", "CloudWatch.3",
        ],
    },

    # ── CC4 — Monitoring Activities ────────────────────────────────────────

    "CC4.1": {
        "title": "Ongoing and Separate Evaluations",
        "severity": "MEDIUM",
        "description": (
            "The entity selects, develops, and performs ongoing and/or separate "
            "evaluations to determine whether the components of internal control "
            "are present and functioning."
        ),
        "remediation": (
            "Enable CloudTrail across all regions. Configure CloudWatch log metric filters "
            "for all required CIS events. Ensure SNS topics have active subscriptions."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    # ── CC6 — Logical and Physical Access ─────────────────────────────────

    "CC6.1": {
        "title": "Logical Access Security Software",
        "severity": "HIGH",
        "description": (
            "The entity implements logical access security software, infrastructure, "
            "and architectures over protected information assets to protect them from "
            "security events."
        ),
        "remediation": (
            "Enable MFA for root and all IAM users with console access. "
            "Enforce strong IAM password policy. Remove root access keys. "
            "Ensure access keys are rotated every 90 days."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },

    "CC6.2": {
        "title": "Prior to Issuing System Credentials",
        "severity": "HIGH",
        "description": (
            "Prior to issuing system credentials and granting system access, the entity "
            "registers and authorizes new internal and external users."
        ),
        "remediation": (
            "Ensure IAM policies are not attached directly to users — use groups or roles. "
            "Remove unused credentials and access keys. "
            "Enable MFA for all console users."
        ),
        "checks": [
            "IAM.2", "IAM.3", "IAM.5", "IAM.6",
            "IAM.7", "IAM.8", "IAM.9",
        ],
    },

    "CC6.3": {
        "title": "Role-Based Access and Least Privilege",
        "severity": "HIGH",
        "description": (
            "The entity authorizes, modifies, or removes access to data, software, "
            "functions, and other protected information assets based on roles and "
            "responsibilities and least-privilege principles."
        ),
        "remediation": (
            "Remove administrative privileges from IAM users. "
            "Attach policies to groups or roles only, not directly to users. "
            "Review and remove overly permissive inline and managed policies."
        ),
        "checks": [
            "IAM.5", "IAM.7", "IAM.8", "IAM.9",
        ],
    },

    "CC6.7": {
        "title": "Transmission and Movement of Data",
        "severity": "HIGH",
        "description": (
            "The entity restricts the transmission, movement, and removal of information "
            "to authorized internal and external users and processes and protects it "
            "during transmission."
        ),
        "remediation": (
            "Block public S3 access and remove public bucket policies. "
            "Enable S3 server-side encryption. "
            "Use KMS CMKs with automatic key rotation for data at rest."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
        ],
    },

    "CC6.8": {
        "title": "Prevention and Detection of Malware",
        "severity": "MEDIUM",
        "description": (
            "The entity implements controls to prevent or detect and act upon the "
            "introduction of unauthorized or malicious software."
        ),
        "remediation": (
            "Enable CloudWatch metric filters for unauthorized API calls and console sign-in failures. "
            "Configure alarms to alert on suspicious activity."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3",
            "CloudWatch.6", "CloudWatch.7",
        ],
    },

    # ── CC7 — System Operations ────────────────────────────────────────────

    "CC7.1": {
        "title": "Configuration and Vulnerability Management",
        "severity": "MEDIUM",
        "description": (
            "The entity uses detection and monitoring procedures to identify changes "
            "to configurations that result in the introduction of new vulnerabilities."
        ),
        "remediation": (
            "Enable CloudTrail in all regions. Configure CloudWatch alarms for "
            "config changes to security groups, network ACLs, and IAM policies."
        ),
        "checks": [
            "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7",
            "CloudWatch.8", "CloudWatch.9", "CloudWatch.10",
        ],
    },

    "CC7.2": {
        "title": "Monitor for Anomalies and Threats",
        "severity": "HIGH",
        "description": (
            "The entity monitors system components and the operation of those components "
            "for anomalies that are indicative of malicious acts, natural disasters, "
            "and errors affecting the entity's ability to meet its objectives."
        ),
        "remediation": (
            "Configure CloudWatch metric filters and alarms for all CIS-required events. "
            "Ensure SNS topics have active subscriptions for alarm notifications."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "CC7.3": {
        "title": "Evaluate Security Events",
        "severity": "HIGH",
        "description": (
            "The entity evaluates security events to determine whether they could or "
            "have resulted in a failure of the entity to meet its objectives."
        ),
        "remediation": (
            "Enable CloudWatch alarms for root account usage, IAM policy changes, "
            "and unauthorized API calls. Ensure alarms notify via SNS."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3",
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "CC7.4": {
        "title": "Incident Response",
        "severity": "HIGH",
        "description": (
            "The entity responds to identified security incidents by executing a "
            "defined incident response program to understand, contain, remediate, "
            "and communicate security incidents."
        ),
        "remediation": (
            "Enable CloudWatch alarms with SNS notifications for critical security events. "
            "Ensure CloudTrail logs are retained and accessible for incident investigation."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.14",
        ],
    },

    # ── CC8 — Change Management ────────────────────────────────────────────

    "CC8.1": {
        "title": "Change Management Process",
        "severity": "MEDIUM",
        "description": (
            "The entity authorizes, designs, develops or acquires, configures, "
            "documents, tests, approves, and implements changes to infrastructure, "
            "data, software, and procedures."
        ),
        "remediation": (
            "Enable CloudWatch metric filters for IAM policy changes, "
            "CloudTrail configuration changes, and security group changes. "
            "Configure alarms to notify on unauthorized changes."
        ),
        "checks": [
            "CloudWatch.4", "CloudWatch.5", "CloudWatch.6",
            "CloudWatch.8", "CloudWatch.9", "CloudWatch.10",
        ],
    },

    # ── A1 — Availability ──────────────────────────────────────────────────

    "A1.2": {
        "title": "Availability: Environmental Protections",
        "severity": "MEDIUM",
        "description": (
            "The entity authorizes, designs, develops or acquires, implements, "
            "operates, approves, maintains, and monitors environmental protections, "
            "software, data back-up processes, and recovery infrastructure."
        ),
        "remediation": (
            "Enable KMS key rotation. Ensure S3 buckets use server-side encryption "
            "with KMS. Enable CloudTrail logging in all regions."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
            "CloudWatch.1", "CloudWatch.2",
        ],
    },

    # ── C1 — Confidentiality ───────────────────────────────────────────────

    "C1.1": {
        "title": "Confidentiality: Identification",
        "severity": "HIGH",
        "description": (
            "The entity identifies and maintains confidential information to meet the "
            "entity's objectives related to confidentiality."
        ),
        "remediation": (
            "Ensure S3 buckets block public access and use server-side encryption. "
            "Use KMS CMKs to protect confidential data. "
            "Apply least-privilege IAM policies for access to sensitive buckets."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
        ],
    },

    "C1.2": {
        "title": "Confidentiality: Disposal",
        "severity": "HIGH",
        "description": (
            "The entity disposes of confidential information to meet the entity's "
            "objectives related to confidentiality."
        ),
        "remediation": (
            "Enable KMS key rotation and ensure keys are not scheduled for deletion "
            "without authorization. Use KMS CMKs for encryption so data is "
            "cryptographically unreadable when keys are deleted."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
        ],
    },

    # ── PI1 — Processing Integrity ─────────────────────────────────────────

    "PI1.5": {
        "title": "Processing Integrity: Storage",
        "severity": "MEDIUM",
        "description": (
            "The entity implements policies and procedures to store inputs, items in "
            "processing, and outputs completely, accurately, and timely in accordance "
            "with system specifications to meet the entity's objectives."
        ),
        "remediation": (
            "Enable S3 server-side encryption and block public access. "
            "Enable KMS key rotation. Enable S3 versioning on buckets storing "
            "processing outputs and audit logs."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
            "KMS.1", "KMS.2",
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

                # 1. Read all existing findings for this account (non-SOC2)
                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework != 'SOC2'
                """, (cloud_account_id,))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for SOC 2 mapping", len(rows))

                # Build lookup: check_id -> list of findings
                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                # 2. For each SOC 2 control, determine result per resource
                for ctrl_id, ctrl_def in SOC2_MAPPING.items():
                    resource_results: dict = {}

                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {
                                "results": [],
                                "resource_name": entry["resource_name"],
                                "resource_type": entry["resource_type"],
                            })
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("SOC2 %s: no matching findings found, skipping", ctrl_id)
                        continue

                    # 3. Worst-case: if ANY check FAILS → control FAILS
                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        soc2_result = "FAIL" if "FAIL" in results_list else "PASS"
                        soc2_status = "open" if soc2_result == "FAIL" else "pass"

                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")
                        description = (
                            f"{ctrl_def['description']} "
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
                            ctrl_id,
                            ctrl_def["title"],
                            description,
                            ctrl_def["severity"],
                            soc2_status,
                            soc2_result,
                            "SOC2",
                            ctrl_def["remediation"],
                            json.dumps({
                                "soc2_control":  ctrl_id,
                                "mapped_checks": ctrl_def["checks"],
                                "passed":        passed,
                                "failed":        failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "SOC2 %s / resource %s → %s (%d/%d passing)",
                            ctrl_id, resource_id, soc2_result, passed, len(results_list)
                        )

        logger.info("SOC 2 mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("SOC 2 mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("SOC 2 mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
