"""
tisax_mapper_handler.py

Maps existing CIS/FSBP findings in the DB to TISAX (Trusted Information
Security Assessment Exchange) requirements, as assessed via the VDA ISA
(Information Security Assessment) catalogue published by the German
automotive industry association (VDA).

IMPORTANT — honest scope and sourcing, read before extending this file:
The full VDA ISA 6.0 catalogue (300+ requirement questions) is a
restricted/paid publication via the ENX Association — it is not fully
public, so this mapper does NOT invent specific sub-control numbers it
cannot verify. What is verifiable from public sources (VDA ISA 6.0.3
chapter breakdowns, cross-referenced across docusnap.com, dekra.com,
sorinmustaca.com, and itis-secure.com's ISO27001-to-VDA-ISA mapping) is:
  - Chapter 4 "Access Control" and the "Identity and Access Management"
    module (least-privilege authorization, password policy, MFA,
    privileged access management, access reviews) — confirmed "strong"
    alignment with ISO 27001 A.5.15-5.18 / A.8.2-8.5.
  - Chapter 5 "IT Security / Cyber Security", which explicitly covers
    encryption/cryptography and key management — confirmed "strong"
    alignment with ISO 27001 A.8.24 — plus two individually-named,
    confirmed sub-controls: 5.2.8 "IT Service Continuity Planning" and
    5.2.9 "Backup and Restore" (source: sorinmustaca.com's VDA ISA 6.0.3
    Sheet 4 deep-dive).
  - Operations Security within that same chapter (logging, monitoring)
    — confirmed "strong" alignment with ISO 27001 A.8.15/A.8.16.

Where only the chapter-level name is confirmed (not a specific decimal
sub-control number), this mapper uses the chapter identifier rather than
fabricating a sub-control number it cannot cite. This is deliberately
coarser than the ISO 27001/27017 mappers elsewhere in this codebase —
that is a reflection of what is actually publicly verifiable about VDA
ISA 6.0, not a shortcut.

Physical security, personnel security (HR), supplier relationships,
prototype protection, and the Data Protection module are NOT mapped —
none of them have an AWS-technical proxy this scanner can check.
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
# TISAX (VDA ISA) → CIS/FSBP check mapping
# ---------------------------------------------------------------------------
TISAX_MAPPING = {

    "VDA-ISA.4": {
        "title": "Access Control (Identity and Access Management)",
        "severity": "HIGH",
        "section": "VDA ISA Chapter 4 — Access Control",
        "description": (
            "Authorization concept based on least-privilege, password "
            "policy, multi-factor authentication, privileged access "
            "management, and regular access reviews."
        ),
        "remediation": (
            "Enforce IAM password policy. Enable MFA for root and all "
            "IAM console users. Remove unused credentials and rotate "
            "access keys regularly. Attach policies to groups/roles only."
        ),
        "checks": ["IAM.1", "IAM.2", "IAM.3", "IAM.4", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9"],
    },
    "VDA-ISA.5.CRYPTO": {
        "title": "Cryptography and Key Management",
        "severity": "HIGH",
        "section": "VDA ISA Chapter 5 — IT Security / Cyber Security",
        "description": (
            "Encryption standards and cryptographic key management "
            "should be defined and implemented for data at rest and in "
            "transit."
        ),
        "remediation": "Enable S3 default encryption and HTTPS-only bucket policies. Enable KMS key rotation.",
        "checks": ["S3.3.5", "S3.3.2", "KMS.1", "KMS.2", "KMS.3", "KMS.4"],
    },
    "VDA-ISA.5.OPS": {
        "title": "Operations Security (Logging & Monitoring)",
        "severity": "MEDIUM",
        "section": "VDA ISA Chapter 5 — IT Security / Cyber Security",
        "description": (
            "Logging and monitoring of IT systems for anomalous "
            "behaviour and security-relevant events."
        ),
        "remediation": "Ensure CloudTrail is enabled in all regions with CloudWatch alarms for CIS-required events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "VDA-ISA.5.2.9": {
        "title": "Backup and Restore",
        "severity": "HIGH",
        "section": "VDA ISA Chapter 5 — IT Security / Cyber Security (confirmed sub-control 5.2.9)",
        "description": "Data should be backed up and restore procedures verified.",
        "remediation": "Enable automated backups / point-in-time recovery with adequate retention, and verify restores are tested.",
        "checks": ["RDS.DR.1", "RDS.DR.2", "RDS.DR.3", "RDS.DR.4", "DynamoDB.DR.1", "DynamoDB.DR.2", "DynamoDB.DR.3"],
    },
    "VDA-ISA.5.2.8": {
        "title": "IT Service Continuity Planning",
        "severity": "HIGH",
        "section": "VDA ISA Chapter 5 — IT Security / Cyber Security (confirmed sub-control 5.2.8)",
        "description": "Redundancy and recovery planning for key IT systems.",
        "remediation": "Verify Multi-AZ/point-in-time-recovery is enabled for critical databases, and that restore procedures are tested.",
        "checks": ["RDS.DR.1", "RDS.DR.2", "RDS.DR.3", "RDS.DR.4", "DynamoDB.DR.1", "DynamoDB.DR.2", "DynamoDB.DR.3"],
    },
}

# Chapters/modules with no AWS-technical proxy this scanner can check.
MANUAL_EVIDENCE_CONTROLS = [
    ("VDA-ISA.1", "Information Security Management (Policies, ISMS Documentation)", "Organisational — not AWS-config verifiable"),
    ("VDA-ISA.2", "Personnel Security (Screening, Training, Offboarding)", "Organisational — not AWS-config verifiable"),
    ("VDA-ISA.3", "Physical Security and Business Continuity (Site/Facility)", "Physical — not AWS-config verifiable"),
    ("VDA-ISA.5.NETWORK", "Network Segmentation", "Requires VPC/security-group checks not yet implemented"),
    ("VDA-ISA.6", "Supplier Relationships", "Organisational — not AWS-config verifiable"),
    ("VDA-ISA.7", "Compliance", "Organisational — not AWS-config verifiable"),
    ("VDA-ISA.8", "Prototype Protection Module (if in scope)", "Physical/organisational — not AWS-config verifiable"),
    ("VDA-ISA.DP", "Data Protection Module (GDPR-aligned, if in scope)", "Organisational/legal — not AWS-config verifiable"),
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
                      AND f.framework != 'TISAX'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for TISAX mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in TISAX_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("TISAX %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        tisax_result = "FAIL" if "FAIL" in results_list else "PASS"
                        tisax_status = "open" if tisax_result == "FAIL" else "pass"
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
                            tisax_status, tisax_result, "TISAX", ctrl_def["remediation"],
                            json.dumps({"tisax_control": ctrl_id, "tisax_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("TISAX mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
