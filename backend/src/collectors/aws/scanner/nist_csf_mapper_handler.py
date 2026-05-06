"""
nist_csf_mapper_handler.py

Maps existing CIS findings in the DB to NIST CSF v2.0 controls.

Same approach as ISO 27001 mapper — reads existing findings, maps to NIST controls,
writes back with framework = 'NIST CSF v2.0'.
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
# NIST CSF v2.0 → our check_id mapping
# Based on Prowler's public NIST CSF mapping, translated to our check IDs
# ---------------------------------------------------------------------------
NIST_MAPPING = {

    # ── Govern (GV) ────────────────────────────────────────────────────────────

    "GV.RR-1": {
        "title": "Cybersecurity roles and responsibilities are coordinated",
        "section": "Govern (GV)",
        "severity": "HIGH",
        "description": (
            "Cybersecurity roles and responsibilities are coordinated "
            "and aligned with internal roles and external partners."
        ),
        "remediation": (
            "Remove administrative privileges from IAM users and roles. "
            "Enable MFA for administrators. "
            "Apply least privilege principles across all IAM policies."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },
    "GV.RR-2": {
        "title": "Cybersecurity responsibilities are established and communicated",
        "section": "Govern (GV)",
        "severity": "HIGH",
        "description": (
            "Cybersecurity responsibilities are established and communicated "
            "within the organization."
        ),
        "remediation": (
            "Ensure IAM policies are attached to groups or roles only, not directly to users. "
            "Remove admin privileges from individual users and roles. "
            "Enforce MFA for all console users."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },
    "GV.PO-1": {
        "title": "Cybersecurity policy is established, communicated, and enforced",
        "section": "Govern (GV)",
        "severity": "HIGH",
        "description": (
            "Cybersecurity policy is established, communicated, and enforced."
        ),
        "remediation": (
            "Attach IAM policies only to groups or roles. "
            "Remove administrative privileges from IAM users. "
            "Enforce MFA for all console users and rotate access keys regularly."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },
    "GV.PO-4": {
        "title": "Governance and risk management processes address cybersecurity risks",
        "section": "Govern (GV)",
        "severity": "MEDIUM",
        "description": (
            "Governance and risk management processes address cybersecurity risks."
        ),
        "remediation": (
            "Enable MFA for root and all IAM users with console access. "
            "Ensure CloudWatch alarms cover all critical API and configuration events. "
            "Enable CloudTrail in all regions."
        ),
        "checks": [
            "IAM.1", "IAM.2",
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
    "GV.OV-3": {
        "title": "Cybersecurity risk management strategy and practices are reviewed",
        "section": "Govern (GV)",
        "severity": "MEDIUM",
        "description": (
            "Cybersecurity risk management strategy and practices are reviewed "
            "and adjusted to adapt to changes in the threat landscape, "
            "technologies, or mission, business, or system environments."
        ),
        "remediation": (
            "Ensure CloudWatch metric filters and alarms are configured for all "
            "critical events including CloudTrail changes, policy changes, and "
            "network changes. Review and update security policies regularly."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    # ── Identify (ID) ──────────────────────────────────────────────────────────

    "ID.AM-6": {
        "title": "Cybersecurity roles and responsibilities for the workforce are established",
        "section": "Identify (ID)",
        "severity": "HIGH",
        "description": (
            "Cybersecurity roles and responsibilities for the entire workforce "
            "and third-party stakeholders are established."
        ),
        "remediation": (
            "Ensure IAM groups are used for access management. "
            "Attach policies to groups/roles, not directly to users. "
            "Review and remove overly broad permissions."
        ),
        "checks": [
            "IAM.5", "IAM.7", "IAM.8", "IAM.9",
        ],
    },
    "ID.RA-1": {
        "title": "Asset vulnerabilities are identified and documented",
        "section": "Identify (ID)",
        "severity": "HIGH",
        "description": (
            "Asset vulnerabilities are identified and documented."
        ),
        "remediation": (
            "Block public access on S3 buckets. "
            "Ensure KMS keys are not publicly accessible. "
            "Review and remediate all public resource configurations."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4",
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
        ],
    },
    "ID.RA-5": {
        "title": "Threats, vulnerabilities, likelihoods, and impacts are used to determine risk",
        "section": "Identify (ID)",
        "severity": "MEDIUM",
        "description": (
            "Threats, vulnerabilities, likelihoods, and impacts are used to "
            "determine risk."
        ),
        "remediation": (
            "Configure CloudWatch metric filters and alarms for unauthorized "
            "API calls, authentication failures, and network-related changes. "
            "Ensure all alarm actions are enabled."
        ),
        "checks": [
            "CloudWatch.5", "CloudWatch.6",
            "CloudWatch.1", "CloudWatch.2",
            "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    # ── Protect (PR) ───────────────────────────────────────────────────────────

    "PR.AC-1": {
        "title": "Identities and credentials are managed",
        "section": "Protect (PR)",
        "severity": "HIGH",
        "description": (
            "Identities and credentials are issued, managed, verified, revoked, "
            "and audited for authorized devices, users and processes."
        ),
        "remediation": (
            "Ensure all IAM users have MFA enabled. Remove unused access keys. "
            "Enforce password rotation. Remove root access keys."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },
    "PR.AC-3": {
        "title": "Remote access is managed",
        "section": "Protect (PR)",
        "severity": "HIGH",
        "description": (
            "Remote access is managed."
        ),
        "remediation": (
            "Block all public S3 access at the account and bucket level. "
            "Ensure no S3 buckets allow public read or write. "
            "Review bucket policies and ACLs for public access grants."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4",
        ],
    },
    "PR.AC-4": {
        "title": "Access permissions are managed with least privilege",
        "section": "Protect (PR)",
        "severity": "HIGH",
        "description": (
            "Access permissions and authorizations are managed, incorporating "
            "the principles of least privilege and separation of duties."
        ),
        "remediation": (
            "Remove administrative privileges from IAM users. "
            "Attach policies only to groups or roles, not directly to users. "
            "Review and remove overly permissive policies."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },
    "PR.AC-6": {
        "title": "Identities are proofed and bound to credentials",
        "section": "Protect (PR)",
        "severity": "HIGH",
        "description": (
            "Identities are proofed and bound to credentials and asserted "
            "in interactions."
        ),
        "remediation": (
            "Enable MFA for root and all IAM users with console access. "
            "Rotate access keys every 90 days. "
            "Remove unused access keys and attach policies to groups/roles only."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },
    "PR.AC-7": {
        "title": "Users and devices are authenticated commensurate with risk",
        "section": "Protect (PR)",
        "severity": "HIGH",
        "description": (
            "Users, devices, and other assets are authenticated commensurate "
            "with the risk of the transaction."
        ),
        "remediation": (
            "Enable MFA for root account and all IAM users with console access. "
            "Use hardware MFA for privileged accounts."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.5", "IAM.6",
        ],
    },
    "PR.DS-1": {
        "title": "Data-at-rest is protected",
        "section": "Protect (PR)",
        "severity": "HIGH",
        "description": (
            "Data-at-rest is protected using encryption."
        ),
        "remediation": (
            "Enable KMS encryption for all sensitive data stores. "
            "Enable default encryption on S3 buckets. "
            "Enable automatic KMS key rotation."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4",
        ],
    },
    "PR.DS-2": {
        "title": "Data-in-transit is protected",
        "section": "Protect (PR)",
        "severity": "HIGH",
        "description": (
            "Data-in-transit is protected."
        ),
        "remediation": (
            "Enforce HTTPS/TLS on all S3 bucket policies using secure transport "
            "policy conditions. Deny all non-HTTPS requests to S3 buckets."
        ),
        "checks": [
            "S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4",
        ],
    },
    "PR.DS-3": {
        "title": "Assets are formally managed throughout removal, transfers, and disposition",
        "section": "Protect (PR)",
        "severity": "MEDIUM",
        "description": (
            "Assets are formally managed throughout removal, transfers, "
            "and disposition."
        ),
        "remediation": (
            "Ensure KMS keys are not deleted unintentionally. "
            "Enable KMS key rotation. "
            "Block public access on S3 buckets to prevent unintended data exposure."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
        ],
    },
    "PR.DS-5": {
        "title": "Protections against data leaks are implemented",
        "section": "Protect (PR)",
        "severity": "HIGH",
        "description": (
            "Protections against data leaks are implemented."
        ),
        "remediation": (
            "Block public access on all S3 buckets. "
            "Remove public bucket policies. "
            "Enable S3 access logging."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4",
        ],
    },
    "PR.IP-1": {
        "title": "A baseline configuration is created and maintained",
        "section": "Protect (PR)",
        "severity": "MEDIUM",
        "description": (
            "A baseline configuration of information technology/industrial "
            "control systems is created and maintained incorporating security "
            "principles (e.g. concept of least functionality)."
        ),
        "remediation": (
            "Enforce MFA and least privilege IAM policies. "
            "Block all public S3 access at the account and bucket level. "
            "Remove overly permissive IAM policies."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4", "IAM.5",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
        ],
    },
    "PR.IP-7": {
        "title": "Protection processes are improved",
        "section": "Protect (PR)",
        "severity": "MEDIUM",
        "description": (
            "Protection processes are improved."
        ),
        "remediation": (
            "Configure CloudWatch alarms for unauthorized API calls and "
            "authentication failures. "
            "Ensure all critical security events have metric filters and active alarms."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6",
        ],
    },
    "PR.IP-8": {
        "title": "Effectiveness of protection technologies is shared",
        "section": "Protect (PR)",
        "severity": "MEDIUM",
        "description": (
            "Effectiveness of protection technologies is shared with appropriate parties."
        ),
        "remediation": (
            "Configure CloudWatch alarms to notify via SNS. "
            "Ensure metric filters cover all critical security events."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.4", "CloudWatch.5",
            "CloudWatch.7", "CloudWatch.8", "CloudWatch.9",
        ],
    },
    "PR.PT-1": {
        "title": "Audit/log records are determined and reviewed",
        "section": "Protect (PR)",
        "severity": "MEDIUM",
        "description": (
            "Audit/log records are determined, documented, implemented, "
            "and reviewed in accordance with policy."
        ),
        "remediation": (
            "Ensure CloudTrail is enabled in all regions with log file validation. "
            "Configure metric filters and alarms for all critical events. "
            "Enable CloudWatch log group encryption."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
    "PR.PT-4": {
        "title": "Communications and control networks are protected",
        "section": "Protect (PR)",
        "severity": "HIGH",
        "description": (
            "Communications and control networks are protected."
        ),
        "remediation": (
            "Enforce secure transport policies on S3 buckets. "
            "Enable KMS encryption on CloudTrail and S3. "
            "Restrict public access to all storage resources."
        ),
        "checks": [
            "S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4",
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
        ],
    },

    # ── Detect (DE) ────────────────────────────────────────────────────────────

    "DE.AE-1": {
        "title": "A baseline of network operations and expected data flows is established",
        "section": "Detect (DE)",
        "severity": "MEDIUM",
        "description": (
            "A baseline of network operations and expected data flows for users "
            "and systems is established and managed."
        ),
        "remediation": (
            "Enable CloudWatch metric filters for security group changes, "
            "CloudTrail configuration changes, and unauthorized API calls. "
            "Ensure all alarms have active notification actions."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2",
            "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
    "DE.AE-2": {
        "title": "Detected events are analyzed to understand attack targets and methods",
        "section": "Detect (DE)",
        "severity": "MEDIUM",
        "description": (
            "Detected events are analyzed to understand attack targets and methods."
        ),
        "remediation": (
            "Configure CloudWatch alarms for authentication failures, "
            "unauthorized API calls, root usage, KMS key deletions, "
            "and network/policy changes. Enable alarm actions for all critical filters."
        ),
        "checks": [
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7",
            "CloudWatch.8", "CloudWatch.9",
            "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
    "DE.AE-3": {
        "title": "Event data are collected and correlated from multiple sources",
        "section": "Detect (DE)",
        "severity": "MEDIUM",
        "description": (
            "Event data are collected and correlated from multiple sources "
            "and sensors."
        ),
        "remediation": (
            "Ensure CloudWatch metric filters cover CloudTrail configuration changes, "
            "AWS Config changes, network gateway changes, and IAM policy changes."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5",
            "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
    "DE.CM-1": {
        "title": "Networks are monitored to detect potential cybersecurity events",
        "section": "Detect (DE)",
        "severity": "MEDIUM",
        "description": (
            "Networks are monitored to detect potential cybersecurity events."
        ),
        "remediation": (
            "Configure CloudWatch alarms for network-related changes. "
            "Enable VPC flow logs. Monitor security group and NACL changes."
        ),
        "checks": [
            "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
    "DE.CM-3": {
        "title": "Personnel activity is monitored to detect potential cybersecurity events",
        "section": "Detect (DE)",
        "severity": "MEDIUM",
        "description": (
            "Personnel activity is monitored to detect potential cybersecurity events."
        ),
        "remediation": (
            "Enable CloudWatch alarms for IAM policy changes, "
            "unauthorized API calls, and console authentication failures."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3",
            "CloudWatch.4", "CloudWatch.5", "CloudWatch.6",
        ],
    },
    "DE.CM-7": {
        "title": "Monitoring for unauthorized personnel, connections, devices, and software",
        "section": "Detect (DE)",
        "severity": "MEDIUM",
        "description": (
            "Monitoring for unauthorized personnel, connections, devices, "
            "and software is performed."
        ),
        "remediation": (
            "Configure CloudWatch metric filters for all critical events: "
            "unauthorized API calls, root account usage, policy changes, "
            "KMS key deletions, S3 bucket policy changes, and network changes. "
            "Ensure all alarms have active notification actions."
        ),
        "checks": [
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7",
            "CloudWatch.8", "CloudWatch.9",
            "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },
    "DE.DP-4": {
        "title": "Event detection information is communicated",
        "section": "Detect (DE)",
        "severity": "MEDIUM",
        "description": (
            "Event detection information is communicated."
        ),
        "remediation": (
            "Ensure CloudWatch alarms have SNS actions configured. "
            "Configure alarms for authentication failures, unauthorized API calls, "
            "network changes, and KMS key events. "
            "Verify alarm actions are enabled and not in insufficient data state."
        ),
        "checks": [
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

                # Read all existing non-NIST findings
                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework NOT IN ('ISO 27001:2022', 'NIST CSF v2.0')
                """, (cloud_account_id,))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for NIST mapping", len(rows))

                # Build lookup: check_id -> list of resource results
                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                # Map to NIST controls
                for nist_id, nist_def in NIST_MAPPING.items():
                    resource_results: dict = {}

                    for check_id in nist_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {
                                "results":       [],
                                "resource_name": entry["resource_name"],
                                "resource_type": entry["resource_type"],
                            })
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("NIST %s: no matching findings, skipping", nist_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        nist_result = "FAIL" if "FAIL" in results_list else "PASS"
                        nist_status = "open" if nist_result == "FAIL" else "pass"
                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")

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
                            nist_id,
                            nist_def["title"],
                            nist_def["description"],
                            nist_def["severity"],
                            nist_status,
                            nist_result,
                            "NIST CSF v2.0",
                            nist_def["remediation"],
                            json.dumps({
                                "nist_control":  nist_id,
                                "section":       nist_def["section"],
                                "mapped_checks": nist_def["checks"],
                                "passed":        passed,
                                "failed":        failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "NIST %s / resource %s → %s (%d/%d passing)",
                            nist_id, resource_id, nist_result, passed, len(results_list)
                        )

        logger.info("NIST mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("NIST CSF mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("NIST CSF mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
