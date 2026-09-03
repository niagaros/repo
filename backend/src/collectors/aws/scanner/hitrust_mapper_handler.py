"""
hitrust_mapper_handler.py

Maps existing CIS/FSBP/GitHub findings in the DB to HITRUST CSF (Common
Security Framework) domains.

HITRUST CSF v11 is organized into 14 Control Categories, 19 Domains, 49
Control Objectives, and 156 Control References (source: HITRUST Alliance's
own published overview, cross-checked against rsisecurity.com's "19
HITRUST Domains" breakdown and strac.io's technical-requirements summary).
HITRUST itself is explicitly built on ISO/IEC 27001 as its foundation and
maps extensively to NIST 800-53, HIPAA, and PCI DSS as authoritative
sources — which is why several domains below reuse the same underlying
AWS evidence already used by this codebase's ISO 27001 / NIST 800-53 /
HIPAA mappers, exactly as HITRUST's own cross-referencing intends.

IMPORTANT — honest scope, same discipline as every other mapper here:
Of the 19 domains, only 11 have a genuine, existing technical proxy in
this AWS-account scanner:
  01 Information Protection, 06 Configuration Management, 07 Vulnerability
  Management, 09 Transmission Protection, 10 Password Management,
  11 Access Control, 12 Audit Logging and Monitoring, 15 Incident
  Management, 16 Business Continuity and Disaster Recovery, 17 Risk
  Management, 19 Data Protection and Privacy.
The other 8 (Endpoint Security, Portable Media Security, Mobile Device
Security, Wireless Security, Network Protection, Education/Training/
Awareness, Third-Party Assurance, Physical and Environmental Security)
require endpoint/MDM agents, network/VPC-level visibility, or
organisational evidence this scanner does not and, for physical security,
fundamentally cannot collect from the customer side of an AWS account.
They are listed as manual-evidence-required, not scanned or scored here.
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
# HITRUST CSF Domain -> CIS/FSBP/GitHub check mapping
# Only domains with a real, defensible technical proxy are included.
# ---------------------------------------------------------------------------
HITRUST_MAPPING = {

    "HITRUST.01": {
        "title": "Information Protection",
        "severity": "CRITICAL",
        "section": "Domain 01 — Information Protection Program",
        "description": (
            "Sensitive information shall be protected through encryption, "
            "data classification, data loss prevention, and secure "
            "disposal practices."
        ),
        "remediation": "Enable S3 default encryption and KMS customer-managed keys with automatic rotation.",
        "checks": ["S3.3.5", "KMS.1", "KMS.2", "KMS.3", "KMS.4"],
    },
    "HITRUST.06": {
        "title": "Configuration Management",
        "severity": "MEDIUM",
        "section": "Domain 06 — Configuration Management",
        "description": (
            "Change control, configuration audit, and configuration item "
            "identification shall be maintained, with unauthorized "
            "configuration changes detected and alerted on."
        ),
        "remediation": "Enable CloudWatch alarms for S3 bucket policy changes, network ACL/gateway/route table changes, and CloudTrail configuration changes.",
        "checks": ["CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "HITRUST.07": {
        "title": "Vulnerability Management",
        "severity": "HIGH",
        "section": "Domain 07 — Vulnerability Management",
        "description": (
            "Vulnerability scanning, patching, and dependency management "
            "processes shall be in place to identify and remediate known "
            "vulnerabilities."
        ),
        "remediation": "Enable Dependabot vulnerability alerts and secret scanning on all GitHub repositories.",
        "checks": ["github_1.5.1", "github_1.5.5"],
    },
    "HITRUST.09": {
        "title": "Transmission Protection",
        "severity": "HIGH",
        "section": "Domain 09 — Transmission Protection",
        "description": (
            "Data transmitted over networks shall be protected using "
            "encryption and secure transport protocols."
        ),
        "remediation": "Enforce HTTPS-only bucket policies on all S3 buckets to protect data in transit.",
        "checks": ["S3.3.2"],
    },
    "HITRUST.10": {
        "title": "Password Management",
        "severity": "HIGH",
        "section": "Domain 10 — Password Management",
        "description": (
            "Password policies shall enforce complexity, expiry, and "
            "reuse-prevention requirements, and credentials shall be "
            "protected against unauthorized use."
        ),
        "remediation": "Configure IAM password policy with complexity and expiry requirements. Rotate access keys regularly and remove unused credentials.",
        "checks": ["IAM.1", "IAM.6", "IAM.8", "IAM.9"],
    },
    "HITRUST.11": {
        "title": "Access Control",
        "severity": "CRITICAL",
        "section": "Domain 11 — Access Control",
        "description": (
            "User provisioning, role-based access control, and "
            "privileged access management shall restrict access to "
            "authorized identities only."
        ),
        "remediation": "Attach IAM policies to groups/roles only, not individual users. Remove administrative privileges from individual users. Enable MFA for all console access.",
        "checks": ["IAM.2", "IAM.3", "IAM.4", "IAM.5", "IAM.7"],
    },
    "HITRUST.12": {
        "title": "Audit Logging and Monitoring",
        "severity": "HIGH",
        "section": "Domain 12 — Audit Logging and Monitoring",
        "description": (
            "System and user activities shall be logged and monitored to "
            "support detection of security-relevant events."
        ),
        "remediation": "Enable multi-region CloudTrail with log file validation and CloudWatch alarms for all CIS-required security events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "HITRUST.15": {
        "title": "Incident Management",
        "severity": "HIGH",
        "section": "Domain 15 — Incident Management",
        "description": (
            "Mechanisms shall exist to detect suspected or known security "
            "incidents so that a response can be initiated."
        ),
        "remediation": "Ensure CloudTrail is enabled and CloudWatch alarms for unauthorized API calls and root account usage are active with a confirmed SNS subscription.",
        "checks": ["CloudWatch.1", "CloudWatch.3"],
    },
    "HITRUST.16": {
        "title": "Business Continuity and Disaster Recovery",
        "severity": "HIGH",
        "section": "Domain 16 — Business Continuity and Disaster Recovery",
        "description": (
            "Backup procedures, recovery plans, and continuity testing "
            "shall ensure data and services can be restored after a "
            "disruptive event."
        ),
        "remediation": "Enable automated backups / point-in-time recovery with adequate retention, and verify restore procedures are tested.",
        "checks": ["RDS.DR.1", "RDS.DR.2", "RDS.DR.3", "RDS.DR.4", "DynamoDB.DR.1", "DynamoDB.DR.2", "DynamoDB.DR.3"],
    },
    "HITRUST.17": {
        "title": "Risk Management",
        "severity": "MEDIUM",
        "section": "Domain 17 — Risk Management",
        "description": (
            "Information assets and their exposure to external parties "
            "shall be identified and reviewed as part of ongoing risk "
            "assessment."
        ),
        "remediation": "Enable IAM Access Analyzer to identify and review resources shared with external entities.",
        "checks": ["IAM.28"],
    },
    "HITRUST.19": {
        "title": "Data Protection and Privacy",
        "severity": "CRITICAL",
        "section": "Domain 19 — Data Protection and Privacy",
        "description": (
            "Data classification, retention, and disposal practices "
            "shall protect the confidentiality of sensitive information, "
            "and public exposure shall be prevented."
        ),
        "remediation": "Block all public access to S3 buckets at account and bucket level. Enable versioning to support data recoverability and retention.",
        "checks": ["S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4", "S3.3.3"],
    },
}

# The remaining 8 domains — require endpoint/MDM agents, network/VPC-level
# visibility, or organisational evidence this scanner does not collect;
# Physical and Environmental Security is fundamentally outside what a
# customer-side AWS-account scanner can ever observe.
MANUAL_EVIDENCE_CONTROLS = [
    ("HITRUST.02", "Endpoint Protection", "Requires endpoint/EDR agent data not collected by this scanner"),
    ("HITRUST.03", "Portable Media Security", "Requires device-management evidence not collected by this scanner"),
    ("HITRUST.04", "Mobile Device Security", "Requires MDM evidence not collected by this scanner"),
    ("HITRUST.05", "Wireless Security", "Requires network/Wi-Fi infrastructure evidence not collected by this scanner"),
    ("HITRUST.08", "Network Protection", "Requires VPC/security-group/network checks not yet implemented"),
    ("HITRUST.13", "Education, Training, and Awareness", "Organisational — not AWS-config verifiable"),
    ("HITRUST.14", "Third-Party Assurance", "Organisational — not AWS-config verifiable"),
    ("HITRUST.18", "Physical and Environmental Security", "Outside customer-side AWS visibility — AWS operates physical facilities"),
]


def _get_connection():
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    client = boto3.client("secretsmanager", region_name=region)
    secret = json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return psycopg2.connect(
        host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
        user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
    )


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
                      AND f.framework != 'HITRUST CSF'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for HITRUST mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in HITRUST_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("HITRUST %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        hitrust_result = "FAIL" if "FAIL" in results_list else "PASS"
                        hitrust_status = "open" if hitrust_result == "FAIL" else "pass"
                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")
                        description = f"{ctrl_def['description']} ({passed} checks passing, {failed} failing)"

                        cur.execute("""
                            INSERT INTO findings
                                (resource_id, check_id, title, description, severity, status, result, framework, remediation, details, detected_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                            ON CONFLICT (resource_id, check_id) DO UPDATE SET
                                title = EXCLUDED.title, description = EXCLUDED.description, severity = EXCLUDED.severity,
                                status = EXCLUDED.status, result = EXCLUDED.result, framework = EXCLUDED.framework,
                                remediation = EXCLUDED.remediation, details = EXCLUDED.details, detected_at = NOW()
                        """, (
                            resource_id, ctrl_id, ctrl_def["title"], description, ctrl_def["severity"],
                            hitrust_status, hitrust_result, "HITRUST CSF", ctrl_def["remediation"],
                            json.dumps({"hitrust_domain": ctrl_id, "hitrust_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("HITRUST mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
