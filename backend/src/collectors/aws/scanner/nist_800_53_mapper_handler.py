"""
nist_800_53_mapper_handler.py

Maps existing CIS findings to NIST SP 800-53 Revision 5 controls.
Covers families: AC, AU, CA, CM, IA, SA, SC, SI.
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
# NIST SP 800-53 Rev 5 -> CIS check mapping
# ---------------------------------------------------------------------------
NIST_800_53_MAPPING = {

    # ── AC — Access Control ───────────────────────────────────────────────────

    "NIST-AC-2": {
        "title": "Account Management",
        "severity": "HIGH",
        "section": "AC — Access Control",
        "description": (
            "Support the management of system accounts using automated mechanisms. "
            "Manage IAM accounts with appropriate password policy, MFA, key rotation, "
            "and group-based access controls. Disable or remove accounts that are no "
            "longer needed or have been inactive."
        ),
        "remediation": (
            "Enforce IAM password policy with minimum 14 characters, complexity, and expiry. "
            "Enable MFA for root and all console users. Remove root access keys. "
            "Rotate access keys every 90 days. Attach policies to groups or roles only. "
            "Remove unused IAM credentials."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },

    "NIST-AC-2.3": {
        "title": "Account Management — Disable Accounts",
        "severity": "MEDIUM",
        "section": "AC — Access Control",
        "description": (
            "Disable accounts within the organization-defined time period when accounts "
            "have expired, are no longer associated with a user, are in violation of "
            "organizational policy, or have been inactive for the defined time period."
        ),
        "remediation": (
            "Disable or remove IAM users with no console activity for 90 or more days. "
            "Disable or delete access keys unused for 90 or more days. "
            "Enforce password expiry in IAM password policy."
        ),
        "checks": ["IAM.1", "IAM.8", "IAM.9"],
    },

    "NIST-AC-3": {
        "title": "Access Enforcement",
        "severity": "HIGH",
        "section": "AC — Access Control",
        "description": (
            "Enforce approved authorizations for logical access to information and system "
            "resources in accordance with applicable access control policies. "
            "S3 buckets shall not be publicly accessible and IAM privileges shall be minimal."
        ),
        "remediation": (
            "Block all public access to S3 buckets at account and bucket level. "
            "Attach IAM policies only to groups or roles. "
            "Remove IAM policies granting administrative privileges to individual users. "
            "Remove unused IAM access keys and console access."
        ),
        "checks": ["IAM.7", "IAM.9", "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4"],
    },

    "NIST-AC-3.7": {
        "title": "Access Enforcement — Role-Based Access Control",
        "severity": "HIGH",
        "section": "AC — Access Control",
        "description": (
            "Enforce a role-based access control policy over defined subjects and objects. "
            "IAM policies shall be attached to groups or roles, not individual users. "
            "S3 buckets shall not grant public access."
        ),
        "remediation": (
            "Attach IAM policies only to groups or roles. "
            "Remove individual user policy attachments. "
            "Block public access to all S3 buckets. "
            "Remove root access keys. Disable unused IAM access keys."
        ),
        "checks": ["IAM.4", "IAM.5", "IAM.7", "IAM.9", "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4"],
    },

    "NIST-AC-5": {
        "title": "Separation of Duties",
        "severity": "HIGH",
        "section": "AC — Access Control",
        "description": (
            "Separate duties of individuals as necessary to prevent malevolent activity. "
            "Define system access authorizations to support separation of duties. "
            "IAM policies shall not grant unrestricted administrative access."
        ),
        "remediation": (
            "Remove AWS managed or customer-managed policies granting administrative "
            "privileges from individual users. Attach policies only to groups or roles. "
            "Apply the principle of least privilege across all IAM assignments."
        ),
        "checks": ["IAM.7"],
    },

    "NIST-AC-6": {
        "title": "Least Privilege",
        "severity": "HIGH",
        "section": "AC — Access Control",
        "description": (
            "Employ the principle of least privilege, allowing only authorized accesses "
            "for users that are necessary to accomplish assigned organizational tasks. "
            "Block public access to storage resources and remove excess IAM privileges."
        ),
        "remediation": (
            "Remove root access keys. Attach IAM policies to groups or roles only. "
            "Remove administrative privileges from individual users. "
            "Block S3 public access. Disable unused IAM access keys and console credentials."
        ),
        "checks": ["IAM.4", "IAM.5", "IAM.7", "IAM.8", "IAM.9", "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4"],
    },

    "NIST-AC-6.2": {
        "title": "Least Privilege — Non-Privileged Accounts",
        "severity": "HIGH",
        "section": "AC — Access Control",
        "description": (
            "Require that users of system accounts with access to security functions use "
            "non-privileged accounts when accessing non-security functions. "
            "Root access keys shall not exist."
        ),
        "remediation": (
            "Remove root access keys. "
            "Remove AWS managed administrative policies from individual IAM users. "
            "Enforce separation between privileged and non-privileged roles."
        ),
        "checks": ["IAM.4", "IAM.7"],
    },

    "NIST-AC-17.2": {
        "title": "Remote Access — Cryptographic Protection",
        "severity": "HIGH",
        "section": "AC — Access Control",
        "description": (
            "Implement cryptographic mechanisms to protect the confidentiality and integrity "
            "of remote access sessions. S3 bucket policies shall enforce HTTPS-only access "
            "to ensure data in transit is always encrypted."
        ),
        "remediation": (
            "Apply S3 bucket policies denying non-HTTPS requests. "
            "Enable server-side encryption on all S3 buckets. "
            "Block public access to all S3 buckets."
        ),
        "checks": ["S3.3.5"],
    },

    # ── AU — Audit and Accountability ─────────────────────────────────────────

    "NIST-AU-6.1": {
        "title": "Audit Record Review — Automated Process Integration",
        "severity": "HIGH",
        "section": "AU — Audit and Accountability",
        "description": (
            "Integrate audit record review, analysis, and reporting processes using "
            "automated mechanisms. CloudWatch alarms shall automatically detect and alert "
            "on network configuration changes and security-relevant events."
        ),
        "remediation": (
            "Enable CloudWatch metric filters and alarms for network ACL changes, "
            "network gateway changes, route table changes, and VPC changes. "
            "Ensure all alarms have active SNS subscriptions."
        ),
        "checks": ["CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },

    "NIST-AU-9": {
        "title": "Protection of Audit Information",
        "severity": "HIGH",
        "section": "AU — Audit and Accountability",
        "description": (
            "Protect audit information and audit logging tools from unauthorized access, "
            "modification, and deletion. CloudTrail log file validation shall be enabled "
            "and changes to CloudTrail shall trigger automated alarms."
        ),
        "remediation": (
            "Enable CloudTrail log file validation on all trails. "
            "Enable CloudWatch metric filter and alarm for CloudTrail configuration changes "
            "to detect unauthorized modifications to the audit trail."
        ),
        "checks": ["CloudWatch.5"],
    },

    "NIST-AU-9.3": {
        "title": "Audit Protection — Cryptographic Protection",
        "severity": "HIGH",
        "section": "AU — Audit and Accountability",
        "description": (
            "Implement cryptographic mechanisms to protect the integrity of audit "
            "information and audit tools. KMS encryption shall protect audit logs "
            "stored in S3 and keys shall be rotated automatically."
        ),
        "remediation": (
            "Enable KMS encryption on S3 buckets containing audit logs. "
            "Enable KMS key rotation. "
            "Apply SSE-KMS to all CloudTrail destination buckets. "
            "Enable S3 versioning for audit log buckets."
        ),
        "checks": ["KMS.1", "KMS.2", "S3.3.1", "S3.3.2", "S3.3.5"],
    },

    "NIST-AU-11": {
        "title": "Audit Record Retention",
        "severity": "MEDIUM",
        "section": "AU — Audit and Accountability",
        "description": (
            "Retain audit records for the organization-defined time period to provide "
            "support for after-the-fact investigations of security incidents and to meet "
            "regulatory information retention requirements."
        ),
        "remediation": (
            "Configure CloudWatch log group retention policy to at least 365 days. "
            "Enable CloudWatch metric filter and alarm for root account usage "
            "to ensure audit trail completeness."
        ),
        "checks": ["CloudWatch.1", "CloudWatch.2"],
    },

    # ── CA — Assessment, Authorization, and Monitoring ────────────────────────

    "NIST-CA-7": {
        "title": "Continuous Monitoring",
        "severity": "HIGH",
        "section": "CA — Assessment and Monitoring",
        "description": (
            "Develop a system-level continuous monitoring strategy and implement continuous "
            "monitoring. CloudWatch alarms shall detect network configuration changes in "
            "real time and alert designated security personnel."
        ),
        "remediation": (
            "Enable CloudWatch metric filters and alarms for network ACL changes, "
            "network gateway changes, route table changes, and VPC changes. "
            "Ensure all alarms have active SNS subscriptions."
        ),
        "checks": ["CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },

    # ── CM — Configuration Management ─────────────────────────────────────────

    "NIST-CM-6": {
        "title": "Configuration Settings",
        "severity": "HIGH",
        "section": "CM — Configuration Management",
        "description": (
            "Establish and document configuration settings for system components that "
            "reflect the most restrictive mode consistent with operational requirements. "
            "All IAM, S3, and KMS security configurations shall meet the defined baseline."
        ),
        "remediation": (
            "Enforce IAM password policy. Enable MFA for root and all console users. "
            "Remove root access keys. Block S3 public access. Enable S3 encryption. "
            "Enable KMS key rotation. Apply least privilege IAM policies."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
            "KMS.1", "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },

    # ── IA — Identification and Authentication ────────────────────────────────

    "NIST-IA-2": {
        "title": "Identification and Authentication",
        "severity": "HIGH",
        "section": "IA — Identification and Authentication",
        "description": (
            "Uniquely identify and authenticate organizational users and the processes "
            "acting on behalf of users. Root account access keys shall be removed to "
            "prevent shared root credential usage."
        ),
        "remediation": (
            "Remove root access keys. Ensure each IAM user has a unique account. "
            "Enable MFA for root account. "
            "Use IAM roles for programmatic access where possible."
        ),
        "checks": ["IAM.3", "IAM.4"],
    },

    "NIST-IA-2.1": {
        "title": "MFA for Privileged Accounts",
        "severity": "CRITICAL",
        "section": "IA — Identification and Authentication",
        "description": (
            "Implement multi-factor authentication for access to privileged accounts. "
            "Hardware or virtual MFA shall be required for the root account and all IAM "
            "users with console access to privileged functions."
        ),
        "remediation": (
            "Enable hardware MFA for root account. "
            "Enable virtual or hardware MFA for all IAM users with console access. "
            "Consider hardware security keys for privileged administrators."
        ),
        "checks": ["IAM.3", "IAM.4"],
    },

    "NIST-IA-2.2": {
        "title": "MFA for Non-Privileged Accounts",
        "severity": "HIGH",
        "section": "IA — Identification and Authentication",
        "description": (
            "Implement multi-factor authentication for access to non-privileged accounts. "
            "MFA shall be required for all IAM users with AWS Management Console access "
            "regardless of privilege level."
        ),
        "remediation": (
            "Enable MFA for all IAM users with console access. "
            "Configure IAM policies to deny console access without MFA. "
            "Enable CloudWatch alarm for sign-in without MFA."
        ),
        "checks": ["IAM.3", "IAM.4"],
    },

    "NIST-IA-5": {
        "title": "Authenticator Management",
        "severity": "HIGH",
        "section": "IA — Identification and Authentication",
        "description": (
            "Manage system authenticators by establishing initial content, ensuring sufficient "
            "strength, changing or refreshing at defined intervals, and protecting against "
            "unauthorized use. Enforce restrictions on credential strength, rotation, and reuse."
        ),
        "remediation": (
            "Configure IAM password policy with minimum 14 characters, complexity, expiry, "
            "and reuse prevention. Rotate access keys every 90 days. "
            "Disable unused access keys and console credentials."
        ),
        "checks": ["IAM.1", "IAM.2", "IAM.6", "IAM.8", "IAM.9"],
    },

    "NIST-IA-5.1": {
        "title": "Authenticator Management — Password-Based Authentication",
        "severity": "MEDIUM",
        "section": "IA — Identification and Authentication",
        "description": (
            "For password-based authentication: enforce composition and complexity rules, "
            "allow long passwords and passphrases, employ automated tools to assist users "
            "in selecting strong passwords, and prevent password reuse."
        ),
        "remediation": (
            "Configure IAM password policy: minimum 14 characters, require uppercase, "
            "lowercase, numbers, and symbols. Set maximum password age to 90 days. "
            "Prevent reuse of the last 24 passwords."
        ),
        "checks": ["IAM.1"],
    },

    # ── SA — System and Services Acquisition ─────────────────────────────────

    "NIST-SA-9.6": {
        "title": "External System Services — Cryptographic Keys",
        "severity": "HIGH",
        "section": "SA — System and Services Acquisition",
        "description": (
            "Maintain exclusive control of cryptographic keys for encrypted material "
            "stored or transmitted through external systems. KMS customer-managed keys "
            "shall have automatic rotation enabled."
        ),
        "remediation": (
            "Enable automatic rotation for all KMS customer-managed keys. "
            "Ensure KMS keys are not publicly accessible or scheduled for deletion. "
            "Use CMKs rather than AWS-managed keys for sensitive data."
        ),
        "checks": ["KMS.1", "KMS.2", "KMS.3", "KMS.4"],
    },

    # ── SC — System and Communications Protection ─────────────────────────────

    "NIST-SC-7": {
        "title": "Boundary Protection",
        "severity": "HIGH",
        "section": "SC — System and Communications Protection",
        "description": (
            "Monitor and control communications at the external managed interfaces to the "
            "system. Publicly accessible S3 buckets represent unmanaged network boundaries "
            "and shall be blocked at both account and bucket level."
        ),
        "remediation": (
            "Block all public access to S3 buckets at account level and per-bucket. "
            "Enable S3 account-level public access block settings. "
            "Review and remediate any bucket-level ACLs granting public access."
        ),
        "checks": ["S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4"],
    },

    "NIST-SC-8": {
        "title": "Transmission Confidentiality and Integrity",
        "severity": "HIGH",
        "section": "SC — System and Communications Protection",
        "description": (
            "Protect the confidentiality and integrity of transmitted information. "
            "S3 bucket policies shall enforce HTTPS-only access to ensure data in "
            "transit is always encrypted and protected from interception."
        ),
        "remediation": (
            "Apply S3 bucket policies that deny non-HTTPS requests "
            "(aws:SecureTransport = false → Deny). "
            "Enable server-side encryption on all S3 buckets storing transmitted data."
        ),
        "checks": ["S3.3.5"],
    },

    "NIST-SC-8.1": {
        "title": "Transmission Confidentiality — Cryptographic Protection",
        "severity": "HIGH",
        "section": "SC — System and Communications Protection",
        "description": (
            "Implement cryptographic mechanisms to prevent unauthorized disclosure or detect "
            "changes to information during transmission. S3 must enforce TLS and KMS keys "
            "shall be rotated automatically."
        ),
        "remediation": (
            "Apply S3 bucket policies enforcing HTTPS. "
            "Enable S3 SSE-KMS encryption. "
            "Enable KMS key rotation for all customer-managed keys used to protect data."
        ),
        "checks": ["KMS.1", "KMS.2", "S3.3.5"],
    },

    "NIST-SC-12": {
        "title": "Cryptographic Key Establishment and Management",
        "severity": "HIGH",
        "section": "SC — System and Communications Protection",
        "description": (
            "Establish and manage cryptographic keys when cryptography is employed within "
            "the system. KMS customer-managed keys shall have automatic rotation enabled "
            "and shall not be scheduled for deletion or publicly accessible."
        ),
        "remediation": (
            "Enable automatic rotation for all KMS customer-managed keys. "
            "Ensure KMS keys are not publicly accessible. "
            "Do not schedule KMS keys for deletion. "
            "Use separate keys for different data classifications."
        ),
        "checks": ["KMS.1", "KMS.2", "KMS.3", "KMS.4"],
    },

    "NIST-SC-13": {
        "title": "Cryptographic Protection",
        "severity": "HIGH",
        "section": "SC — System and Communications Protection",
        "description": (
            "Determine the organization-defined cryptographic uses and implement the required "
            "cryptography in accordance with applicable laws, regulations, policies, and "
            "standards. KMS CMKs and S3 encryption shall meet all requirements."
        ),
        "remediation": (
            "Enable KMS key rotation. Apply SSE-KMS to all S3 buckets. "
            "Enable S3 versioning for immutability. "
            "Block public access to all S3 buckets. Apply HTTPS-only policies."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },

    "NIST-SC-28.1": {
        "title": "Protection of Information at Rest — Cryptographic Protection",
        "severity": "CRITICAL",
        "section": "SC — System and Communications Protection",
        "description": (
            "Implement cryptographic mechanisms to prevent unauthorized disclosure and "
            "modification of information at rest. KMS CMKs with automatic rotation shall "
            "encrypt all sensitive data stored in S3 and other storage services."
        ),
        "remediation": (
            "Enable KMS key rotation for all customer-managed keys. "
            "Apply SSE-KMS to all S3 buckets containing sensitive data. "
            "Block public access at account and bucket level. "
            "Enable S3 versioning."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },

    # ── SI — System and Information Integrity ─────────────────────────────────

    "NIST-SI-4": {
        "title": "System Monitoring",
        "severity": "HIGH",
        "section": "SI — System and Information Integrity",
        "description": (
            "Monitor the system to detect attacks and indicators of potential attacks. "
            "CloudWatch metric filters and alarms shall be configured to detect root account "
            "usage, authentication failures, and network configuration changes."
        ),
        "remediation": (
            "Enable CloudWatch metric filters and alarms for root account usage, "
            "authentication failures, and network configuration changes "
            "(ACL, gateway, route table, VPC). "
            "Ensure all alarms have active SNS subscriptions."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.3",
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "NIST-SI-4.12": {
        "title": "System Monitoring — Automated Alerts",
        "severity": "HIGH",
        "section": "SI — System and Information Integrity",
        "description": (
            "Alert designated personnel using automated mechanisms when indications of "
            "inappropriate or unusual activities with security implications occur, including "
            "network configuration changes and unauthorized access attempts."
        ),
        "remediation": (
            "Enable CloudWatch metric filters and alarms for network ACL changes, "
            "network gateway changes, route table changes, and VPC changes. "
            "Ensure SNS topics have active subscriptions."
        ),
        "checks": ["CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },

    "NIST-SI-7": {
        "title": "Software, Firmware, and Information Integrity",
        "severity": "HIGH",
        "section": "SI — System and Information Integrity",
        "description": (
            "Employ integrity verification tools to detect unauthorized changes to software, "
            "firmware, and information. CloudTrail log file validation shall be enabled and "
            "alerts configured for CloudTrail configuration changes."
        ),
        "remediation": (
            "Enable CloudTrail log file validation on all trails. "
            "Enable CloudWatch metric filter and alarm for CloudTrail configuration changes. "
            "Store CloudTrail logs in a versioned S3 bucket."
        ),
        "checks": ["CloudWatch.5", "S3.3.4"],
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

                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework != 'NIST 800-53 Rev 5'
                """, (cloud_account_id,))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for NIST 800-53 mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in NIST_800_53_MAPPING.items():
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
                        logger.info("NIST-800-53 %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        nist_result = "FAIL" if "FAIL" in results_list else "PASS"
                        nist_status = "open" if nist_result == "FAIL" else "pass"

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
                            nist_status,
                            nist_result,
                            "NIST 800-53 Rev 5",
                            ctrl_def["remediation"],
                            json.dumps({
                                "nist_control":  ctrl_id,
                                "nist_family":   ctrl_def["section"],
                                "mapped_checks": ctrl_def["checks"],
                                "passed":        passed,
                                "failed":        failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "NIST-800-53 %s / resource %s -> %s (%d/%d passing)",
                            ctrl_id, resource_id, nist_result, passed, len(results_list)
                        )

        logger.info("NIST 800-53 mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("NIST 800-53 Rev 5 mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("NIST 800-53 Rev 5 mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
