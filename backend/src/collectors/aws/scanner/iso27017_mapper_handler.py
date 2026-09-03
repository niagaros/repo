"""
iso27017_mapper_handler.py

Maps existing CIS/FSBP/GitHub findings in the DB to ISO/IEC 27017:2015
(cloud-specific information security controls).

ISO/IEC 27017:2015 is not a standalone control set: per ISO's own scope
statement, it "provides guidance ... on applying 37 of ISO 27001's Annex A
controls to cloud environments", plus 7 new, cloud-specific controls
prefixed "CLD" (source: ISO 27017:2015 overview, cross-checked against
sprinto.com, itgovernance/grcsolutions, and Microsoft's ISO 27017 compliance
page).

Same read-existing-findings-and-roll-up approach as every other mapper in
this codebase.

IMPORTANT — honest scope, same discipline as every other mapper here:
Of the 37 shared Annex A controls, this scanner already has real technical
proxies for 14 of them (reused, unmodified, from iso27001_mapper_handler.py
— ISO 27017 does not redefine these, it just says "apply them to cloud").
Of the 7 new CLD controls, only 2 have any real AWS-technical proxy with
checks that exist in this codebase (CLD.12.1.5 admin operational security,
CLD.12.4.5 cloud service monitoring). The other 5 CLD controls need
VPC/security-group segmentation and EC2/VM-hardening checks that this
scanner does not currently implement — inventing a PASS/FAIL for those off
unrelated AWS settings would be exactly the scanner dishonesty this
engagement has spent its whole duration removing. They are listed as
manual-evidence-required, not scanned.
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
# ISO/IEC 27017:2015 → CIS/FSBP/GitHub check mapping
# 14 shared ISO 27001 Annex A controls (reused as-is, ISO 27017 applies them
# to cloud without redefining them) + 2 genuinely checkable CLD controls.
# ---------------------------------------------------------------------------
ISO27017_MAPPING = {

    "ISO27017.A.5.15": {
        "title": "Access Control",
        "severity": "HIGH",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": (
            "Rules to control physical and logical access to information and "
            "other associated assets should be established."
        ),
        "remediation": (
            "Enforce IAM password policy with complexity requirements. Enable "
            "MFA for root and all IAM console users. Remove unused access "
            "keys and rotate active keys every 90 days."
        ),
        "checks": ["IAM.1", "IAM.2", "IAM.3", "IAM.4", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9"],
    },
    "ISO27017.A.5.17": {
        "title": "Authentication Information",
        "severity": "HIGH",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": (
            "Allocation and management of authentication information should "
            "be controlled by a management process."
        ),
        "remediation": "Enable MFA for the root account and all IAM console users. Remove root access keys.",
        "checks": ["IAM.1", "IAM.2", "IAM.3", "IAM.6"],
    },
    "ISO27017.A.5.18": {
        "title": "Access Rights",
        "severity": "HIGH",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": (
            "Access rights to information and other associated assets should "
            "be provisioned, reviewed, modified and removed in accordance "
            "with an access control policy."
        ),
        "remediation": "Remove administrative privileges from IAM users; attach policies only to groups/roles.",
        "checks": ["IAM.5", "IAM.7", "IAM.8", "IAM.9"],
    },
    "ISO27017.A.8.2": {
        "title": "Privileged Access Rights",
        "severity": "HIGH",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "The allocation and use of privileged access rights should be restricted and managed.",
        "remediation": "Remove administrative privileges from IAM users, groups, and roles.",
        "checks": ["IAM.5", "IAM.7", "IAM.8", "IAM.9"],
    },
    "ISO27017.A.8.3": {
        "title": "Information Access Restriction",
        "severity": "HIGH",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "Access to information and other associated assets should be restricted per policy.",
        "remediation": "Ensure S3 buckets block public access. Remove public bucket policies.",
        "checks": ["S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4", "S3.3.1", "S3.3.2", "S3.3.5"],
    },
    "ISO27017.A.8.4": {
        "title": "Access to Source Code",
        "severity": "HIGH",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "Read and write access to source code, development tools and software libraries should be appropriately managed.",
        "remediation": "Enable branch protection, require reviews, disallow force pushes to protected branches.",
        "checks": ["github_1.1.3", "github_1.1.4", "github_1.1.7", "github_1.1.14", "github_1.1.16", "github_1.1.17", "github_1.1.20", "github_1.3.8"],
    },
    "ISO27017.A.8.5": {
        "title": "Secure Authentication",
        "severity": "HIGH",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "Secure authentication technologies and procedures should be implemented.",
        "remediation": "Enable MFA for all IAM users and root. Rotate access keys. Enable KMS key rotation.",
        "checks": ["IAM.1", "IAM.2", "IAM.3", "IAM.4", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9", "KMS.1", "KMS.2", "KMS.3", "KMS.4"],
    },
    "ISO27017.A.8.8": {
        "title": "Management of Technical Vulnerabilities",
        "severity": "HIGH",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "Information about technical vulnerabilities should be obtained and evaluated, and appropriate measures taken.",
        "remediation": "Enable Dependabot alerts and secret scanning on all GitHub repositories.",
        "checks": ["github_1.5.1", "github_1.5.5"],
    },
    "ISO27017.A.8.11": {
        "title": "Data Masking",
        "severity": "HIGH",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "Data masking should be used in accordance with access control policy and business requirements.",
        "remediation": "Enable KMS CMK encryption for data stores. Enable automatic key rotation. Enable default S3 encryption.",
        "checks": ["KMS.1", "KMS.2", "KMS.3", "KMS.4", "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4", "S3.3.1", "S3.3.2", "S3.3.5"],
    },
    "ISO27017.A.8.15": {
        "title": "Logging",
        "severity": "MEDIUM",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "Logs recording activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.",
        "remediation": "Ensure CloudTrail is enabled in all regions with metric filters and alarms for CIS-required events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "ISO27017.A.8.16": {
        "title": "Monitoring Activities",
        "severity": "MEDIUM",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "Networks, systems and applications should be monitored for anomalous behaviour.",
        "remediation": "Configure CloudWatch alarms for critical API activity with active SNS subscriptions.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "ISO27017.A.8.24": {
        "title": "Use of Cryptography",
        "severity": "HIGH",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "Rules for the effective use of cryptography, including key management, should be defined and implemented.",
        "remediation": "Use KMS CMKs with automatic rotation. Ensure S3 buckets use server-side encryption.",
        "checks": ["KMS.1", "KMS.2", "KMS.3", "KMS.4", "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4", "S3.3.1", "S3.3.2", "S3.3.5"],
    },
    "ISO27017.A.8.29": {
        "title": "Security Testing in Development and Acceptance",
        "severity": "MEDIUM",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "Security testing processes should be defined and implemented in the development lifecycle.",
        "remediation": "Require CI status checks and code owner reviews before merging pull requests.",
        "checks": ["github_1.1.7", "github_1.1.9", "github_1.1.11"],
    },
    "ISO27017.A.8.32": {
        "title": "Change Management",
        "severity": "MEDIUM",
        "section": "Shared ISO 27001 Annex A control, applied to cloud",
        "description": "Changes to information processing facilities should be subject to change management procedures.",
        "remediation": "Require pull request reviews, dismiss stale reviews on new commits, require status checks.",
        "checks": ["github_1.1.3", "github_1.1.4", "github_1.1.9", "github_1.1.11", "github_1.1.20"],
    },

    # ── New, cloud-specific CLD controls (the 2 with a real technical proxy) ──
    "CLD.12.1.5": {
        "title": "Administrator's Operational Security",
        "severity": "HIGH",
        "section": "New cloud-specific control (ISO 27017 Annex A extension)",
        "description": (
            "Procedures for administrative operations of a cloud computing "
            "environment should be defined, documented and monitored."
        ),
        "remediation": "Remove standing administrative privileges from individual IAM users; require MFA for privileged access.",
        "checks": ["IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9"],
    },
    "CLD.12.4.5": {
        "title": "Monitoring of Cloud Services",
        "severity": "HIGH",
        "section": "New cloud-specific control (ISO 27017 Annex A extension)",
        "description": (
            "The cloud service customer should have the capability to "
            "monitor specified aspects of the operation of the cloud "
            "services that the cloud service provider uses."
        ),
        "remediation": "Ensure CloudTrail/CloudWatch monitoring and alarms are active for all CIS-required events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
}

# The remaining 23 shared Annex A controls (org policy, HR, physical
# security, supplier agreements, BCM, etc.) and 5 CLD controls without an
# AWS-technical proxy in this scanner (CLD.6.3.1 shared roles, CLD.8.1.5
# asset removal, CLD.9.5.1 VM segregation, CLD.9.5.2 VM hardening,
# CLD.13.1.4 virtual/physical network alignment — the last three need
# VPC/security-group/EC2 checks this scanner does not implement).
MANUAL_EVIDENCE_CONTROLS = [
    ("CLD.6.3.1", "Shared Roles and Responsibilities in Cloud Computing", "New cloud-specific control"),
    ("CLD.8.1.5", "Removal of Cloud Service Customer Assets", "New cloud-specific control"),
    ("CLD.9.5.1", "Segregation in Virtual Computing Environments", "New cloud-specific control — requires VPC/security-group checks not yet implemented"),
    ("CLD.9.5.2", "Virtual Machine Hardening", "New cloud-specific control — requires EC2/AMI hardening checks not yet implemented"),
    ("CLD.13.1.4", "Alignment of Security Management for Virtual and Physical Networks", "New cloud-specific control — requires network topology checks not yet implemented"),
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
                      AND f.framework != 'ISO 27017'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for ISO 27017 mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in ISO27017_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("ISO27017 %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        iso_result = "FAIL" if "FAIL" in results_list else "PASS"
                        iso_status = "open" if iso_result == "FAIL" else "pass"
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
                            iso_status, iso_result, "ISO 27017", ctrl_def["remediation"],
                            json.dumps({"iso27017_control": ctrl_id, "iso27017_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("ISO 27017 mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
