"""
nydfs_mapper_handler.py

Maps existing CIS/FSBP/GitHub findings in the DB to 23 NYCRR Part 500
("Cybersecurity Requirements for Financial Services Companies"), the
New York State Department of Financial Services (NYDFS) cybersecurity
regulation. Source: the regulation's own official text, promulgated by
the NYDFS Superintendent, effective March 1, 2017 (read directly from
the department's published PDF — exact section numbers and titles
below are copied verbatim, not paraphrased from a vendor summary).

Any bank, insurer, or other entity licensed under the New York Banking
Law, Insurance Law, or Financial Services Law is a "Covered Entity" and
must comply — this includes large, internationally recognized banks
and insurers with a New York license or branch, not just NY-based
firms. It replaces OFDSS in this product's Financial Frameworks
category: OFDSS's own site (ofdss.org) is currently returning HTTP 500
on every page and has no publicly archived, exact requirement list
this codebase could cite without guessing.

IMPORTANT — honest scope, read before extending this file:
23 NYCRR 500 is overwhelmingly a governance/process regulation (written
policies, a designated CISO, board reporting, incident-response plans,
vendor management, breach notification to the regulator). Of its 18
substantive requirement sections (500.02-500.18; 500.19-500.23 are
exemptions/administrative, not controls), exactly 6 have a genuine
technical AWS/GitHub proxy already in this codebase:
  - 500.06 Audit Trail                          -> CloudTrail/CloudWatch checks
  - 500.07 Access Privileges                     -> IAM least-privilege checks
  - 500.08 Application Security                  -> GitHub secure-dev-practice checks
  - 500.12 Multi-Factor Authentication            -> IAM MFA checks
  - 500.14(a) Monitoring of Authorized User Activity -> CloudWatch checks
  - 500.15 Encryption of Nonpublic Information    -> S3/KMS encryption checks
The remaining sections — the cybersecurity program and policy
themselves, CISO designation, penetration testing/vulnerability
assessment programs, risk assessment methodology, personnel/training
requirements (including 500.14(b)), third-party vendor security
policy, data-retention/disposal policy, the incident response plan
document, and the 72-hour regulator notification obligation — are
organisational, contractual, or documentation requirements that cannot
be verified from an AWS API response.
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

NYDFS_MAPPING = {

    "NYDFS.500.06": {
        "title": "Audit Trail",
        "severity": "HIGH",
        "section": "23 NYCRR 500.06",
        "description": (
            "Covered Entities shall securely maintain systems with audit "
            "trails designed to detect and respond to Cybersecurity Events."
        ),
        "remediation": "Enable multi-region CloudTrail with CloudWatch alarms for all CIS-required security events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13"],
    },
    "NYDFS.500.07": {
        "title": "Access Privileges",
        "severity": "CRITICAL",
        "section": "23 NYCRR 500.07",
        "description": (
            "Covered Entities shall limit user access privileges to "
            "Information Systems that provide access to Nonpublic "
            "Information and periodically review such access privileges."
        ),
        "remediation": "Enforce IAM password policy, remove unused credentials, avoid full-admin policies, and review external access via Access Analyzer.",
        "checks": ["IAM.1", "IAM.2", "IAM.7", "IAM.8", "IAM.15", "IAM.16", "IAM.18", "IAM.22", "IAM.26", "IAM.27", "IAM.28"],
    },
    "NYDFS.500.08": {
        "title": "Application Security",
        "severity": "MEDIUM",
        "section": "23 NYCRR 500.08",
        "description": (
            "Covered Entities shall use written procedures, guidelines, "
            "and standards designed to ensure secure development "
            "practices for in-house developed applications."
        ),
        "remediation": "Require pull-request review and branch protection before merging to default branches.",
        "checks": ["github_1.1.3", "github_1.1.4", "github_1.1.7", "github_1.1.9", "github_1.1.11", "github_1.1.14", "github_1.1.16", "github_1.1.17", "github_1.1.20", "github_1.2.2", "github_1.2.3", "github_1.3.4", "github_1.3.5", "github_1.3.8"],
    },
    "NYDFS.500.12": {
        "title": "Multi-Factor Authentication",
        "severity": "CRITICAL",
        "section": "23 NYCRR 500.12",
        "description": (
            "Covered Entities shall use Multi-Factor Authentication or "
            "equivalent risk-based controls for any individual accessing "
            "internal networks from an external network."
        ),
        "remediation": "Enable MFA for all IAM console users and hardware MFA for the root user.",
        "checks": ["IAM.5", "IAM.6", "IAM.9"],
    },
    "NYDFS.500.14a": {
        "title": "Monitoring of Authorized User Activity",
        "severity": "HIGH",
        "section": "23 NYCRR 500.14(a)",
        "description": (
            "Covered Entities shall implement risk-based policies and "
            "controls designed to monitor the activity of Authorized "
            "Users and detect unauthorized access, use, or tampering."
        ),
        "remediation": "Ensure CloudTrail is enabled and CloudWatch alarms for unauthorized API calls and unusual activity are active with a confirmed SNS subscription.",
        "checks": ["CloudWatch.1", "CloudWatch.3", "CloudWatch.4", "CloudWatch.14"],
    },
    "NYDFS.500.15": {
        "title": "Encryption of Nonpublic Information",
        "severity": "CRITICAL",
        "section": "23 NYCRR 500.15",
        "description": (
            "Covered Entities shall implement controls, including "
            "encryption, to protect Nonpublic Information both in "
            "transit over external networks and at rest."
        ),
        "remediation": "Enable S3 default encryption, HTTPS-only bucket policies, and KMS key rotation.",
        "checks": ["S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4", "S3.3.5", "KMS.1", "KMS.2", "KMS.3", "KMS.4", "KMS.5", "KMS.6"],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("NYDFS.500.02", "Cybersecurity Program", "Organisational program requirement — not AWS-config verifiable"),
    ("NYDFS.500.03", "Cybersecurity Policy", "Board/Senior-Officer-approved written policy — not AWS-config verifiable"),
    ("NYDFS.500.04", "Chief Information Security Officer", "Personnel designation and annual board reporting — not AWS-config verifiable"),
    ("NYDFS.500.05", "Penetration Testing and Vulnerability Assessments", "Contracted, point-in-time testing program — not AWS-config verifiable"),
    ("NYDFS.500.09", "Risk Assessment", "Documented risk-assessment methodology — not AWS-config verifiable"),
    ("NYDFS.500.10", "Cybersecurity Personnel and Intelligence", "Personnel staffing and training — not AWS-config verifiable"),
    ("NYDFS.500.11", "Third Party Service Provider Security Policy", "Vendor due-diligence policy — not AWS-config verifiable"),
    ("NYDFS.500.13", "Limitations on Data Retention", "Data-disposal policy for Nonpublic Information — not AWS-config verifiable"),
    ("NYDFS.500.14b", "Cybersecurity Awareness Training", "Personnel training program — not AWS-config verifiable"),
    ("NYDFS.500.16", "Incident Response Plan", "Written IR plan document — not AWS-config verifiable"),
    ("NYDFS.500.17", "Notices to Superintendent", "72-hour regulator breach notification and annual certification — not AWS-config verifiable"),
    ("NYDFS.500.18", "Confidentiality", "Legal disclosure-exemption provision — not a control"),
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
                      AND f.framework != '23 NYCRR 500 (NYDFS)'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for NYDFS mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in NYDFS_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("NYDFS %s: no matching findings found, skipping", ctrl_id)
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
                            status, result, "23 NYCRR 500 (NYDFS)", ctrl_def["remediation"],
                            Json({"nydfs_section": ctrl_id, "nydfs_citation": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("NYDFS mapping complete: %d findings upserted", findings_upserted)
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
                        VALUES ('cspm-nydfs-mapper', 'compliance', '23 NYCRR 500 (NYDFS) -- 6 of 18 substantive sections with a real technical AWS/GitHub proxy', true)
                        ON CONFLICT (function_name) DO NOTHING
                    """)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()

    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
