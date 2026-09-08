"""
cis_controls_mapper_handler.py

Maps existing CIS/FSBP/GitHub findings in the DB to CIS Controls v8.1
(source: CIS's own official list at cisecurity.org/controls/cis-controls-list
— 18 controls, 153 safeguards across Implementation Groups IG1-IG3).

CIS Controls is a vendor-neutral, org-wide security program, not a
cloud-specific benchmark like "CIS AWS Benchmark". Most of its 18
controls describe organizational processes (asset inventories, security
awareness training, incident response plans, vendor management,
penetration testing programs) that cannot be verified from an AWS API
response — no CSPM tool, including this one, can honestly claim to
automate those.

IMPORTANT — honest scope, read before extending this file:
Of the 18 controls, exactly 8 have a genuine, existing technical proxy
in this codebase's check catalog:
  - Control 3  Data Protection                         -> S3/KMS encryption checks
  - Control 4  Secure Configuration of Enterprise Assets -> S3 Block Public Access
  - Control 5  Account Management                        -> IAM credential lifecycle checks
  - Control 6  Access Control Management                 -> IAM least-privilege/MFA checks
  - Control 7  Continuous Vulnerability Management        -> GitHub Dependabot/secret scanning
  - Control 8  Audit Log Management                       -> CloudTrail/CloudWatch checks
  - Control 11 Data Recovery                              -> RDS/DynamoDB disaster-recovery checks
  - Control 16 Application Software Security              -> GitHub branch protection/review checks
The remaining 10 controls (1, 2, 9, 10, 12, 13, 14, 15, 17, 18) require
either asset/software inventories, email/browser/endpoint security
tooling, network monitoring (GuardDuty/VPC Flow Logs), or purely
organisational programs (training, vendor management, IR plans,
pentesting) that this product does not currently scan for any cloud
account — they are listed as manual-evidence-required rather than
approximated.
"""

import json
import logging
import os

import boto3
import psycopg2
from psycopg2.extras import Json

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CLOUD_ACCOUNT_ID = os.environ.get(
    "CLOUD_ACCOUNT_ID",
    "846e9e1b-c011-43ef-a38c-4762cc9b0f5a"
)

CIS_CONTROLS_MAPPING = {

    "CISCTRL.03": {
        "title": "Data Protection",
        "severity": "CRITICAL",
        "section": "CIS Controls v8.1 — Control 3",
        "description": (
            "Data at rest and in transit shall be protected using "
            "encryption and key management controls."
        ),
        "remediation": "Enable S3 default encryption, HTTPS-only bucket policies, and KMS key rotation.",
        "checks": ["S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4", "S3.3.5", "KMS.1", "KMS.2", "KMS.3", "KMS.4", "KMS.5", "KMS.6"],
    },
    "CISCTRL.04": {
        "title": "Secure Configuration of Enterprise Assets and Software",
        "severity": "CRITICAL",
        "section": "CIS Controls v8.1 — Control 4",
        "description": (
            "Enterprise assets shall be configured with a secure baseline, "
            "including blocking unintended public exposure of storage."
        ),
        "remediation": "Enable all four S3 Block Public Access settings on every bucket.",
        "checks": ["S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4"],
    },
    "CISCTRL.05": {
        "title": "Account Management",
        "severity": "CRITICAL",
        "section": "CIS Controls v8.1 — Control 5",
        "description": (
            "Account credentials shall be actively managed throughout "
            "their lifecycle, including rotation and removal when unused."
        ),
        "remediation": "Rotate IAM access keys every 90 days, remove the root access key, and remove unused credentials.",
        "checks": ["IAM.3", "IAM.4", "IAM.8", "IAM.22", "IAM.26", "IAM.27"],
    },
    "CISCTRL.06": {
        "title": "Access Control Management",
        "severity": "CRITICAL",
        "section": "CIS Controls v8.1 — Control 6",
        "description": (
            "Access to resources shall be granted and revoked based on "
            "least privilege, with strong authentication enforced."
        ),
        "remediation": "Enforce IAM password policy, MFA for console access, avoid full-admin policies, and review external access via Access Analyzer.",
        "checks": ["IAM.1", "IAM.2", "IAM.5", "IAM.6", "IAM.7", "IAM.9", "IAM.15", "IAM.16", "IAM.18", "IAM.28"],
    },
    "CISCTRL.07": {
        "title": "Continuous Vulnerability Management",
        "severity": "HIGH",
        "section": "CIS Controls v8.1 — Control 7",
        "description": (
            "A vulnerability management process shall be operated to "
            "identify and remediate known vulnerabilities on an ongoing basis."
        ),
        "remediation": "Enable Dependabot vulnerability alerts and secret scanning on all GitHub repositories.",
        "checks": ["github_1.5.1", "github_1.5.5"],
    },
    "CISCTRL.08": {
        "title": "Audit Log Management",
        "severity": "HIGH",
        "section": "CIS Controls v8.1 — Control 8",
        "description": (
            "Audit logs shall be collected, reviewed, and retained to "
            "support detection and investigation of security events."
        ),
        "remediation": "Enable multi-region CloudTrail with CloudWatch alarms for all CIS-required security events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "CISCTRL.11": {
        "title": "Data Recovery",
        "severity": "HIGH",
        "section": "CIS Controls v8.1 — Control 11",
        "description": (
            "Data recovery practices shall be established and validated "
            "to ensure enterprise assets are returned to a trusted state "
            "after a disruption."
        ),
        "remediation": "Enable automated backups with adequate retention on RDS and point-in-time recovery on DynamoDB, and validate restores.",
        "checks": ["RDS.DR.1", "RDS.DR.2", "RDS.DR.3", "RDS.DR.4", "DynamoDB.DR.1", "DynamoDB.DR.2", "DynamoDB.DR.3"],
    },
    "CISCTRL.16": {
        "title": "Application Software Security",
        "severity": "MEDIUM",
        "section": "CIS Controls v8.1 — Control 16",
        "description": (
            "In-house and third-party software shall be managed to "
            "prevent, detect, and remediate security weaknesses before "
            "they reach production."
        ),
        "remediation": "Require pull-request review and branch protection before merging to default branches.",
        "checks": ["github_1.1.3", "github_1.1.4", "github_1.1.7", "github_1.1.9", "github_1.1.11", "github_1.1.14", "github_1.1.16", "github_1.1.17", "github_1.1.20", "github_1.2.2", "github_1.2.3", "github_1.3.4", "github_1.3.5", "github_1.3.8"],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("CISCTRL.01", "Inventory and Control of Enterprise Assets", "Asset inventory process — not AWS-config verifiable"),
    ("CISCTRL.02", "Inventory and Control of Software Assets", "Software/SBOM inventory process — not AWS-config verifiable"),
    ("CISCTRL.09", "Email and Web Browser Protections", "No email/browser security tooling is scanned by this product"),
    ("CISCTRL.10", "Malware Defenses", "No endpoint/malware detection tooling is scanned by this product"),
    ("CISCTRL.12", "Network Infrastructure Management", "No VPC/network configuration scanner exists in this product yet"),
    ("CISCTRL.13", "Network Monitoring and Defense", "No GuardDuty/VPC Flow Logs scanner exists in this product yet"),
    ("CISCTRL.14", "Security Awareness and Skills Training", "Organisational training program — not AWS-config verifiable"),
    ("CISCTRL.15", "Service Provider Management", "Vendor/contract management process — not AWS-config verifiable"),
    ("CISCTRL.17", "Incident Response Management", "Organisational IR plan and exercises — not AWS-config verifiable"),
    ("CISCTRL.18", "Penetration Testing", "Contracted, point-in-time testing — not AWS-config verifiable"),
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
                      AND f.framework != 'CIS Controls v8.1'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for CIS Controls v8.1 mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in CIS_CONTROLS_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("CIS Controls %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        result = "FAIL" if "FAIL" in results_list else "PASS"
                        status = "open" if result == "FAIL" else "pass"
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
                            status, result, "CIS Controls v8.1", ctrl_def["remediation"],
                            Json({"cisctrl_control": ctrl_id, "cisctrl_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("CIS Controls v8.1 mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    if event and event.get("migrate"):
        conn = _get_connection()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO scanners (function_name, resource_type, description, enabled)
                        VALUES ('cspm-cis-controls-mapper', 'compliance', 'CIS Controls v8.1 -- 8 of 18 controls with a real technical AWS/GitHub proxy', true)
                        ON CONFLICT (function_name) DO NOTHING
                    """)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()

    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
