"""
fedramp_mapper_handler.py

Maps existing CIS / FSBP findings in the DB to FedRAMP Moderate (Revision 4)
control families.

FedRAMP Moderate is a NIST SP 800-53 baseline. The Prowler
fedramp_moderate_revision_4_aws.json expresses each control as a list of
Prowler check names (e.g. iam_password_policy_minimum_length_14). The platform,
however, only scans IAM, S3, KMS and CloudWatch and stores findings under its
own check IDs (IAM.15, S3.2.1, CloudWatch.11, ...). This mapper therefore keeps
only the FedRAMP controls whose Prowler checks overlap with the services we
actually scan, translated to our internal check IDs.

Writes findings back with framework = 'FedRAMP Moderate Rev 4'.
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
    "cbb94e43-4e42-4fac-997e-8f931131bde7"
)

FRAMEWORK = "FedRAMP Moderate Rev 4"

# ---------------------------------------------------------------------------
# FedRAMP Moderate (NIST 800-53 Rev 4) -> internal check mapping
# Only control families with checks the platform actually runs are included
# (IAM / S3 / KMS / CloudWatch). Controls that map exclusively to EC2, RDS,
# GuardDuty, SecurityHub, CloudTrail, VPC, etc. are intentionally omitted.
# ---------------------------------------------------------------------------
FEDRAMP_MAPPING = {

    "AC-2": {
        "title": "AC-2 Account Management",
        "severity": "HIGH",
        "description": (
            "Information system accounts must be created, managed, monitored and "
            "reviewed under least-privilege principles, with strong credential "
            "hygiene and automated account-management support."
        ),
        "remediation": (
            "Attach IAM policies to groups/roles rather than users, enforce a "
            "strong password policy, remove unused access keys and console "
            "credentials, and keep an IAM Access Analyzer enabled."
        ),
        "checks": [
            "IAM.2", "IAM.15", "IAM.16", "IAM.22", "IAM.27", "IAM.28",
        ],
    },

    "AC-3": {
        "title": "AC-3 Access Enforcement",
        "severity": "HIGH",
        "description": (
            "The information system must enforce approved authorisations for "
            "logical access to information and resources, preventing public or "
            "unauthorised access to data stores."
        ),
        "remediation": (
            "Enable S3 Block Public Access at account and bucket level and ensure "
            "IAM policies are attached only to groups or roles."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4", "IAM.2",
        ],
    },

    "AC-6": {
        "title": "AC-6 Least Privilege",
        "severity": "HIGH",
        "description": (
            "Only authorised accesses necessary to accomplish assigned tasks may "
            "be granted. Privileged and unused access must be minimised."
        ),
        "remediation": (
            "Attach IAM policies to groups/roles only, remove unused access keys "
            "and console access, and review stale credentials regularly."
        ),
        "checks": [
            "IAM.2", "IAM.22", "IAM.27",
        ],
    },

    "AC-17": {
        "title": "AC-17 Remote Access",
        "severity": "MEDIUM",
        "description": (
            "Remote access methods must be monitored and controlled, and public "
            "exposure of resources must be prevented and alerted on."
        ),
        "remediation": (
            "Block public S3 access and enable CloudWatch alarms for network ACL "
            "and gateway changes to detect changes to remote-access paths."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "CloudWatch.11", "CloudWatch.12",
        ],
    },

    "AU-2": {
        "title": "AU-2 Audit Events",
        "severity": "HIGH",
        "description": (
            "The information system must be capable of auditing security-relevant "
            "events: authentication, account management, policy and privilege "
            "changes, key changes and network changes."
        ),
        "remediation": (
            "Configure the full CIS set of CloudWatch metric filters and alarms "
            "for unauthorised API calls, sign-in anomalies, root usage, IAM/CMK/"
            "S3 policy changes and network ACL/gateway/route/VPC changes."
        ),
        "checks": [
            "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5",
            "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9",
            "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13",
            "CloudWatch.14",
        ],
    },

    "AU-6": {
        "title": "AU-6 Audit Review, Analysis & Reporting",
        "severity": "HIGH",
        "description": (
            "Audit records must be reviewed and correlated to detect "
            "inappropriate activity, supported by automated alerting on "
            "infrastructure changes."
        ),
        "remediation": (
            "Enable CloudWatch alarms for network ACL, gateway, route table and "
            "VPC changes so that audit events are surfaced for review."
        ),
        "checks": [
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "AU-9": {
        "title": "AU-9 Protection of Audit Information",
        "severity": "HIGH",
        "description": (
            "Audit information and tools must be protected from unauthorised "
            "access, modification and deletion, including encryption of log data."
        ),
        "remediation": (
            "Restrict KMS key policies so audit/log encryption keys cannot be used "
            "to decrypt by any principal, protecting audit information at rest."
        ),
        "checks": [
            "KMS.1", "KMS.2",
        ],
    },

    "IA-2": {
        "title": "IA-2 Identification & Authentication",
        "severity": "CRITICAL",
        "description": (
            "The information system must uniquely identify and authenticate "
            "organisational users, with multi-factor authentication and strong "
            "password requirements."
        ),
        "remediation": (
            "Enforce a strong IAM password policy, enable MFA for all console "
            "users, and ensure IAM policies are scoped to groups/roles."
        ),
        "checks": [
            "IAM.2", "IAM.9", "IAM.15",
        ],
    },

    "IA-5": {
        "title": "IA-5 Authenticator Management",
        "severity": "HIGH",
        "description": (
            "Password authenticators must enforce minimum complexity, lifetime "
            "and reuse restrictions."
        ),
        "remediation": (
            "Enforce IAM password policy minimum length (14+) and password reuse "
            "prevention (24 generations)."
        ),
        "checks": [
            "IAM.15", "IAM.16",
        ],
    },

    "IR-4": {
        "title": "IR-4 Incident Handling",
        "severity": "HIGH",
        "description": (
            "Automated mechanisms must support incident handling, including "
            "alerting on infrastructure and network changes that may indicate "
            "compromise."
        ),
        "remediation": (
            "Enable CloudWatch alarms for network ACL, gateway, route table and "
            "VPC changes to support automated incident detection and handling."
        ),
        "checks": [
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "SC-7": {
        "title": "SC-7 Boundary Protection",
        "severity": "HIGH",
        "description": (
            "Communications must be monitored and controlled at external and key "
            "internal boundaries; publicly accessible components must be isolated."
        ),
        "remediation": (
            "Block public S3 access and enable CloudWatch alarms for network ACL, "
            "gateway, route table and VPC changes at the network boundary."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "SC-8": {
        "title": "SC-8 Transmission Confidentiality & Integrity",
        "severity": "HIGH",
        "description": (
            "Cryptographic mechanisms must protect the confidentiality and "
            "integrity of transmitted information (encryption in transit)."
        ),
        "remediation": (
            "Enforce TLS-only (secure transport) bucket policies and server-side "
            "encryption on all S3 buckets."
        ),
        "checks": [
            "S3.3.2", "S3.3.5",
        ],
    },

    "SC-12": {
        "title": "SC-12 Cryptographic Key Establishment & Management",
        "severity": "HIGH",
        "description": (
            "Cryptographic keys must be established and managed securely, with "
            "tightly scoped key policies and rotation."
        ),
        "remediation": (
            "Restrict KMS key policies so no principal can decrypt with all keys "
            "and enable automatic KMS key rotation."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.5", "KMS.6",
        ],
    },

    "SC-13": {
        "title": "SC-13 Use of Cryptography",
        "severity": "HIGH",
        "description": (
            "Approved cryptography must be implemented to protect information, "
            "including default encryption of stored data."
        ),
        "remediation": (
            "Enable S3 default server-side encryption on all buckets."
        ),
        "checks": [
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },

    "SC-28": {
        "title": "SC-28 Protection of Information at Rest",
        "severity": "CRITICAL",
        "description": (
            "The confidentiality and integrity of information at rest must be "
            "protected through encryption and secure key management."
        ),
        "remediation": (
            "Enable S3 default encryption and restrict KMS key policies; rotate "
            "customer-managed keys."
        ),
        "checks": [
            "S3.3.1", "S3.3.2", "S3.3.5", "KMS.1", "KMS.2", "KMS.5", "KMS.6",
        ],
    },

    "SI-4": {
        "title": "SI-4 Information System Monitoring",
        "severity": "HIGH",
        "description": (
            "The information system must be monitored to detect attacks, "
            "unauthorised connections and indicators of compromise, with "
            "system-generated alerts."
        ),
        "remediation": (
            "Enable the full CIS set of CloudWatch metric-filter alarms covering "
            "authentication, policy, key, storage and network changes."
        ),
        "checks": [
            "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5",
            "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9",
            "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13",
            "CloudWatch.14",
        ],
    },
}


# ---------------------------------------------------------------------------
# DB helpers  (identical to other mappers)
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
# Core mapper  (identical logic to GDPR / ISO 27001 / BSI C5 / CSA CCM mapper)
# ---------------------------------------------------------------------------

def run_mapping(cloud_account_id: str) -> dict:
    conn = _get_connection()
    findings_upserted = 0

    try:
        with conn:
            with conn.cursor() as cur:

                # 1. Read all existing findings for this account (non-FedRAMP)
                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework != %s
                """, (cloud_account_id, FRAMEWORK))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for FedRAMP mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                # 2. For each FedRAMP control, determine result per resource
                for control_id, control_def in FEDRAMP_MAPPING.items():
                    resource_results: dict = {}

                    for check_id in control_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {
                                "results": [],
                                "resource_name": entry["resource_name"],
                                "resource_type": entry["resource_type"],
                            })
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("FedRAMP %s: no matching findings found, skipping", control_id)
                        continue

                    # 3. Worst-case: if ANY check FAILS -> control FAILS
                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        fr_result = "FAIL" if "FAIL" in results_list else "PASS"
                        fr_status = "open" if fr_result == "FAIL" else "pass"

                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")
                        description = (
                            f"{control_def['description']} "
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
                            control_id,
                            control_def["title"],
                            description,
                            control_def["severity"],
                            fr_status,
                            fr_result,
                            FRAMEWORK,
                            control_def["remediation"],
                            json.dumps({
                                "fedramp_control": control_id,
                                "mapped_checks":   control_def["checks"],
                                "passed":          passed,
                                "failed":          failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "FedRAMP %s / resource %s -> %s (%d/%d passing)",
                            control_id, resource_id, fr_result, passed, len(results_list)
                        )

        logger.info("FedRAMP mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("FedRAMP mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("FedRAMP mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
