"""
pci_dss_mapper_handler.py

Maps existing CIS findings in the DB to PCI DSS v4.0 requirements.

Same approach as ISO 27001 mapper — reads existing findings, maps to PCI DSS
controls, writes back with framework = 'PCI DSS v4.0'.
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
# PCI DSS v4.0 -> CIS/FSBP check mapping
# ---------------------------------------------------------------------------
PCI_MAPPING = {

    # ── Requirement 1: Network Security Controls ───────────────────────────

    "PCI-1.2.5": {
        "title": "NSC Configurations Reviewed and Tested",
        "severity": "HIGH",
        "description": (
            "All services, protocols, and ports allowed are identified, approved, "
            "and have a defined business need. NSC rule sets are reviewed at least "
            "once every six months."
        ),
        "remediation": (
            "Configure CloudWatch metric filters and alarms to detect changes to "
            "security groups, network ACLs, and CloudTrail configuration. "
            "Review and document all allowed services, protocols, and ports. "
            "Ensure all changes to NSCs are logged and alerted on."
        ),
        "checks": [
            "CloudWatch.4", "CloudWatch.5", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10",
        ],
    },

    # ── Requirement 2: Apply Secure Configurations ─────────────────────────

    "PCI-2.2.1": {
        "title": "System Configuration Standards",
        "severity": "HIGH",
        "description": (
            "Configuration standards are developed, implemented, and maintained for "
            "all system components. Configuration standards address all known security "
            "vulnerabilities and are consistent with industry-accepted hardening standards."
        ),
        "remediation": (
            "Enforce least-privilege IAM policies. Remove administrative privileges "
            "from IAM users and assign them to groups or roles. "
            "Enforce MFA for all console users. Rotate access keys every 90 days. "
            "Remove unused credentials and access keys."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },

    # ── Requirement 3: Protect Stored Account Data ─────────────────────────

    "PCI-3.4.1": {
        "title": "PAN Masked Where Displayed",
        "severity": "HIGH",
        "description": (
            "The primary account number (PAN) is masked when displayed such that only "
            "personnel with a legitimate business need can see more than the first six "
            "and last four digits of the PAN. Stored account data is protected using "
            "strong encryption."
        ),
        "remediation": (
            "Enable KMS customer-managed key rotation. "
            "Apply server-side encryption (SSE-KMS) to all S3 buckets storing account data. "
            "Block public access on all S3 buckets. "
            "Ensure KMS keys are not pending deletion."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },

    "PCI-3.5.1": {
        "title": "PAN Protected with Strong Cryptography",
        "severity": "HIGH",
        "description": (
            "Primary account numbers are secured with strong cryptography wherever stored. "
            "Cryptographic keys used for encryption/decryption are protected against "
            "disclosure and misuse."
        ),
        "remediation": (
            "Enable KMS key rotation for all customer-managed keys. "
            "Use KMS CMKs with SSE for S3 buckets containing cardholder data. "
            "Block all public access to S3 buckets. "
            "Ensure KMS keys are not scheduled for deletion without authorization."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },

    # ── Requirement 4: Protect Data During Transmission ────────────────────

    "PCI-4.2.1": {
        "title": "Strong Cryptography for PAN Transmission",
        "severity": "HIGH",
        "description": (
            "Strong cryptography is used to safeguard PAN during transmission over "
            "open, public networks. Trusted keys/certificates are accepted. "
            "The protocol supports only trusted configurations."
        ),
        "remediation": (
            "Block public S3 access and enforce SSL/TLS-only access for all buckets "
            "storing cardholder data. Enable KMS encryption for data at rest. "
            "Ensure all data transmission uses TLS 1.2 or higher."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
        ],
    },

    # ── Requirement 7: Restrict Access to System Components ────────────────

    "PCI-7.2.1": {
        "title": "Access Controls Implemented",
        "severity": "HIGH",
        "description": (
            "Access to system components and cardholder data is limited to only those "
            "individuals whose job requires such access. Access controls grant the "
            "least privilege needed to perform a job function."
        ),
        "remediation": (
            "Remove administrative access from IAM users; use groups and roles only. "
            "Block all public access to S3 buckets containing cardholder data. "
            "Remove unused IAM permissions and review policies for over-privilege. "
            "Implement and enforce least-privilege IAM policies."
        ),
        "checks": [
            "IAM.5", "IAM.7", "IAM.8", "IAM.9",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
        ],
    },

    "PCI-7.2.4": {
        "title": "All User Accounts Reviewed",
        "severity": "MEDIUM",
        "description": (
            "All user accounts and related access privileges, including third-party and "
            "vendor accounts, are reviewed at least once every six months to confirm "
            "whether access and privileges are still required."
        ),
        "remediation": (
            "Regularly review and remove inactive IAM users and credentials. "
            "Disable or remove access keys unused for 90 days. "
            "Remove IAM users who no longer require access. "
            "Enforce strong password rotation policies."
        ),
        "checks": [
            "IAM.2", "IAM.3", "IAM.5", "IAM.6",
            "IAM.8", "IAM.9",
        ],
    },

    "PCI-7.2.6": {
        "title": "Least Privilege for All Access",
        "severity": "HIGH",
        "description": (
            "All access to query repositories of stored cardholder data is restricted "
            "to applications and individuals with a legitimate business need. "
            "Access is not directly accessible by the end user."
        ),
        "remediation": (
            "Attach IAM policies to groups or roles only, never directly to users. "
            "Remove overly permissive inline and managed policies. "
            "Apply S3 bucket policies restricting access to authorized roles only. "
            "Audit and remove unnecessary cross-account access."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.5", "IAM.7",
            "IAM.8", "IAM.9",
        ],
    },

    # ── Requirement 8: Identify Users and Authenticate Access ──────────────

    "PCI-8.2.1": {
        "title": "Unique Authentication Credentials for All Users",
        "severity": "HIGH",
        "description": (
            "All users are assigned a unique ID before allowing them to access system "
            "components or cardholder data. Shared or generic user IDs are prohibited "
            "unless documented and approved."
        ),
        "remediation": (
            "Enable MFA for root and all IAM users with console access. "
            "Disable root account access keys. "
            "Ensure each user has unique credentials and that shared accounts are removed. "
            "Remove unused credentials older than 90 days."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.8", "IAM.9",
        ],
    },

    "PCI-8.3.6": {
        "title": "Password/Passphrase Complexity Requirements",
        "severity": "MEDIUM",
        "description": (
            "If passwords/passphrases are used as authentication factors to meet "
            "Requirement 8.3.1, they meet a minimum length of at least 12 characters "
            "and contain both numeric and alphabetic characters."
        ),
        "remediation": (
            "Configure IAM account password policy to require a minimum length of 14 "
            "characters, at least one uppercase letter, one lowercase letter, one number, "
            "and one non-alphanumeric character. Enforce password rotation every 90 days "
            "and prevent reuse of the last 24 passwords."
        ),
        "checks": [
            "IAM.1", "IAM.2",
        ],
    },

    "PCI-8.4.2": {
        "title": "MFA for All Access into the CDE",
        "severity": "CRITICAL",
        "description": (
            "Multi-factor authentication (MFA) is implemented for all access into the "
            "cardholder data environment (CDE). MFA is required for all non-consumer "
            "users including administrators."
        ),
        "remediation": (
            "Enable MFA for the root account. Enable MFA for all IAM users with "
            "console access. Remove root access keys. "
            "Configure IAM policies to deny access to the CDE without active MFA. "
            "Use virtual or hardware MFA devices."
        ),
        "checks": [
            "IAM.3", "IAM.4",
        ],
    },

    "PCI-8.6.1": {
        "title": "System and Application Accounts Managed",
        "severity": "HIGH",
        "description": (
            "If accounts used by systems or applications can be used for interactive "
            "login, they are managed with the following: interactive use is prevented "
            "unless needed for an exceptional circumstance, interactive use is limited "
            "to the time needed, and business justification is documented."
        ),
        "remediation": (
            "Remove or disable IAM user accounts not in active use. "
            "Disable console access for service accounts. "
            "Rotate access keys regularly and remove unused keys. "
            "Use IAM roles for EC2 instances and Lambda instead of long-lived credentials."
        ),
        "checks": [
            "IAM.2", "IAM.5", "IAM.6",
            "IAM.8", "IAM.9",
        ],
    },

    # ── Requirement 10: Log and Monitor All Access ─────────────────────────

    "PCI-10.2.1": {
        "title": "Audit Logs Capture Required Events",
        "severity": "HIGH",
        "description": (
            "Audit logs capture all individual user access to cardholder data, all "
            "actions taken by root or with root/administrative privileges, access to "
            "all audit trails, invalid logical access attempts, use of identification "
            "and authentication mechanisms, initialization/stopping/pausing of audit logs, "
            "and creation/deletion of system-level objects."
        ),
        "remediation": (
            "Enable CloudTrail in all regions with log file validation. "
            "Configure CloudWatch metric filters for all required events: root usage, "
            "unauthorized API calls, console sign-in failures, IAM policy changes, "
            "CloudTrail changes, S3 policy changes, security group changes. "
            "Ensure all metric filters have active alarms with SNS subscriptions."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7",
        ],
    },

    "PCI-10.3.2": {
        "title": "Audit Logs Protected from Modifications",
        "severity": "HIGH",
        "description": (
            "Audit log files are protected to prevent modifications by individuals. "
            "Only individuals with a job-related need can view audit log files. "
            "Current audit log files are promptly backed up to a centralized log server "
            "or media that is difficult to modify."
        ),
        "remediation": (
            "Enable CloudTrail log file validation to detect tampering. "
            "Store CloudTrail logs in an S3 bucket with versioning, MFA delete, "
            "and block public access enabled. "
            "Apply bucket policies to prevent unauthorized deletion or modification. "
            "Enable CloudWatch Logs for real-time log streaming."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2",
        ],
    },

    "PCI-10.5.1": {
        "title": "Retain Audit Logs for At Least 12 Months",
        "severity": "MEDIUM",
        "description": (
            "Retain audit log history for at least 12 months with at least the most "
            "recent three months available for immediate analysis. "
            "Audit logs are available immediately for analysis."
        ),
        "remediation": (
            "Configure S3 lifecycle policies to retain CloudTrail logs for at least "
            "12 months. Enable S3 versioning and MFA delete on the CloudTrail bucket. "
            "Block all public access to the log storage bucket. "
            "Enable CloudWatch Logs with an appropriate retention period of 365+ days."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "CloudWatch.1", "CloudWatch.2",
        ],
    },

    "PCI-10.7.1": {
        "title": "Failures of Critical Security Controls Detected",
        "severity": "HIGH",
        "description": (
            "Failures of critical security controls are detected, reported, and "
            "responded to promptly. Failures of critical controls include failure of "
            "firewalls, IDS/IPS, anti-malware, change detection mechanisms, and "
            "audit logging."
        ),
        "remediation": (
            "Enable all CloudWatch metric filters and configure alarms with SNS "
            "notifications for: unauthorized API calls, console sign-in failures, "
            "root account usage, IAM policy changes, CloudTrail configuration changes, "
            "S3 policy changes, security group changes, NACL changes, gateway changes, "
            "route table changes, VPC changes."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    # ── Requirement 11: Test Security of Systems and Networks ──────────────

    "PCI-11.5.1": {
        "title": "Intrusion-Detection Techniques Employed",
        "severity": "HIGH",
        "description": (
            "Intrusion-detection and/or intrusion-prevention techniques are used to "
            "detect and/or prevent intrusions into the network. All traffic is monitored "
            "at the perimeter of the cardholder data environment as well as at critical "
            "points in the environment."
        ),
        "remediation": (
            "Configure CloudWatch metric filters and alarms to detect suspicious activity "
            "including unauthorized API calls and console sign-in failures. "
            "Enable AWS GuardDuty for threat detection. "
            "Ensure all alarms notify via SNS with active subscriptions."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3",
            "CloudWatch.6", "CloudWatch.7",
        ],
    },

    # ── Requirement 12: Support Information Security with Policies ─────────

    "PCI-12.3.3": {
        "title": "Cryptographic Key Management Policies",
        "severity": "HIGH",
        "description": (
            "All cryptographic cipher suites and protocols in use are documented and "
            "reviewed at least once every 12 months to confirm they remain secure. "
            "Cryptographic keys used for protection of stored account data are protected "
            "against disclosure and misuse."
        ),
        "remediation": (
            "Enable automatic rotation for all KMS customer-managed keys. "
            "Ensure no KMS keys are pending deletion without authorization. "
            "Audit all KMS key policies and grants. "
            "Document and review all cryptographic algorithms in use at least annually."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.4",
        ],
    },

    "PCI-12.6.2": {
        "title": "Security Awareness Training Program",
        "severity": "MEDIUM",
        "description": (
            "The security awareness program is reviewed at least once every 12 months "
            "and updated as necessary to address any new threats or vulnerabilities. "
            "Personnel are aware of policies and procedures relevant to their job function."
        ),
        "remediation": (
            "Configure CloudWatch alarms for root account usage to ensure personnel "
            "are trained not to use root credentials for daily operations. "
            "Enable CloudWatch metric filters for console sign-in failures and "
            "unauthorized API calls to identify potential insider threats."
        ),
        "checks": [
            "CloudWatch.11", "CloudWatch.12",
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

                # 1. Read all existing findings for this account (non-PCI)
                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework != 'PCI DSS v4.0'
                """, (cloud_account_id,))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for PCI DSS mapping", len(rows))

                # Build lookup: check_id -> list of findings
                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                # 2. For each PCI DSS control, determine result per resource
                for ctrl_id, ctrl_def in PCI_MAPPING.items():
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
                        logger.info("PCI DSS %s: no matching findings found, skipping", ctrl_id)
                        continue

                    # 3. Worst-case: if ANY check FAILS -> control FAILS
                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        pci_result = "FAIL" if "FAIL" in results_list else "PASS"
                        pci_status = "open" if pci_result == "FAIL" else "pass"

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
                            pci_status,
                            pci_result,
                            "PCI DSS v4.0",
                            ctrl_def["remediation"],
                            json.dumps({
                                "pci_control":   ctrl_id,
                                "mapped_checks": ctrl_def["checks"],
                                "passed":        passed,
                                "failed":        failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "PCI DSS %s / resource %s -> %s (%d/%d passing)",
                            ctrl_id, resource_id, pci_result, passed, len(results_list)
                        )

        logger.info("PCI DSS v4.0 mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("PCI DSS v4.0 mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("PCI DSS v4.0 mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
