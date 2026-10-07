"""
mvsp_mapper_handler.py

Maps existing CIS/FSBP/GitHub findings in the DB to Minimum Viable Secure
Product (MVSP, mvsp.dev) controls.

MVSP defines exactly 25 controls across 4 categories: Business (1.x),
Application Design (2.x), Application Implementation (3.x), and
Operational (4.x) — verified directly against the published control text
at https://www.mvsp.dev/mvsp.en/.

Same read-existing-findings-and-roll-up approach as every other mapper in
this codebase.

IMPORTANT — honest scope:
Most of MVSP's 25 controls describe organisational process (vulnerability
disclosure policy, penetration testing, training, incident handling,
media sanitization, SSO availability, security headers, vulnerability
prevention training, data-flow documentation, build provenance) or the
product's own application-layer behaviour (HTTP security headers,
password-field validation) — none of which this AWS-account scanner can
verify from API responses. Only 6 of the 25 controls have a genuine,
existing technical proxy in this codebase: 2.6 (dependency patching via
GitHub Dependabot), 2.7 (logging via CloudTrail/CloudWatch), 2.8
(encryption via S3/KMS), 3.5 (credentials kept out of source, via GitHub
secret scanning), 4.2 (logical access/MFA via IAM), and 4.4 (backup and
disaster recovery via RDS/DynamoDB DR checks). The other 19 are listed as
manual-evidence-required, not scanned or scored here.
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
# MVSP → CIS/FSBP/GitHub check mapping
# Only controls with a real, defensible technical proxy are included.
# ---------------------------------------------------------------------------
MVSP_MAPPING = {

    "MVSP.2.6": {
        "title": "Dependency Patching",
        "severity": "HIGH",
        "section": "2. Application Design Controls",
        "description": (
            "Keep third-party dependencies current; prioritize patches for "
            "Known Exploited Vulnerabilities and medium+ severity issues."
        ),
        "remediation": "Enable Dependabot (vulnerability) alerts on all GitHub repositories and remediate open alerts.",
        "checks": ["github_1.5.1"],
    },
    "MVSP.2.7": {
        "title": "Logging",
        "severity": "MEDIUM",
        "section": "2. Application Design Controls",
        "description": (
            "Record authentication, data operations, configuration "
            "changes, and admin access with user ID, IP, timestamp, and "
            "action type, retained for 30+ days."
        ),
        "remediation": "Ensure CloudTrail is enabled in all regions with CloudWatch alarms for CIS-required events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "MVSP.2.8": {
        "title": "Encryption",
        "severity": "CRITICAL",
        "section": "2. Application Design Controls",
        "description": "Employ contemporary, maintained encryption standards for data moving between systems and data at rest.",
        "remediation": "Enable S3 default encryption and HTTPS-only bucket policies. Enable KMS key rotation.",
        "checks": ["S3.3.5", "S3.3.2", "KMS.1", "KMS.2", "KMS.3", "KMS.4"],
    },
    "MVSP.3.5": {
        "title": "Build and Release Process",
        "severity": "HIGH",
        "section": "3. Application Implementation Controls",
        "description": (
            "Use version control with documented build provenance; store "
            "credentials separately from source code."
        ),
        "remediation": "Enable secret scanning on all GitHub repositories to detect accidentally committed credentials.",
        "checks": ["github_1.5.5"],
    },
    "MVSP.4.2": {
        "title": "Logical Access",
        "severity": "HIGH",
        "section": "4. Operational Controls",
        "description": (
            "Restrict data access to authorized personnel with documented "
            "approval; deactivate unused accounts; require MFA for remote "
            "production access."
        ),
        "remediation": "Enable MFA for all IAM users and root. Remove unused IAM credentials.",
        "checks": ["IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9"],
    },
    "MVSP.4.4": {
        "title": "Backup and Disaster Recovery",
        "severity": "HIGH",
        "section": "4. Operational Controls",
        "description": (
            "Securely backup all data to a different location than where "
            "the application is running, and test recovery procedures "
            "annually."
        ),
        "remediation": "Enable automated backups / point-in-time recovery with adequate retention, and verify restores are tested.",
        "checks": ["RDS.DR.1", "RDS.DR.2", "RDS.DR.3", "RDS.DR.4", "DynamoDB.DR.1", "DynamoDB.DR.2", "DynamoDB.DR.3"],
    },
}

# The other 19 MVSP controls — organisational process or application-layer
# behaviour this AWS-account scanner cannot verify from API responses.
MANUAL_EVIDENCE_CONTROLS = [
    ("MVSP.1.1", "External Vulnerability Reports", "1. Business Controls"),
    ("MVSP.1.2", "Customer Testing", "1. Business Controls"),
    ("MVSP.1.3", "Self-Assessment", "1. Business Controls"),
    ("MVSP.1.4", "External Testing (Penetration Tests)", "1. Business Controls"),
    ("MVSP.1.5", "Training", "1. Business Controls"),
    ("MVSP.1.6", "Compliance (PCI DSS / ISO 27001 / SSAE 18 / GDPR)", "1. Business Controls"),
    ("MVSP.1.7", "Incident Handling", "1. Business Controls"),
    ("MVSP.1.8", "Data Handling (Media Sanitization)", "1. Business Controls"),
    ("MVSP.2.1", "Single Sign-On", "2. Application Design Controls"),
    ("MVSP.2.2", "HTTPS-only", "2. Application Design Controls"),
    ("MVSP.2.3", "Security Headers", "2. Application Design Controls"),
    ("MVSP.2.4", "Password Policy", "2. Application Design Controls"),
    ("MVSP.2.5", "Security Libraries", "2. Application Design Controls"),
    ("MVSP.3.1", "List of Data", "3. Application Implementation Controls"),
    ("MVSP.3.2", "Data Flow Diagram", "3. Application Implementation Controls"),
    ("MVSP.3.3", "Vulnerability Prevention", "3. Application Implementation Controls"),
    ("MVSP.3.4", "Time to Fix Vulnerabilities", "3. Application Implementation Controls"),
    ("MVSP.4.1", "Physical Access", "4. Operational Controls"),
    ("MVSP.4.3", "Sub-processors", "4. Operational Controls"),
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
                      AND f.framework != 'MVSP'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for MVSP mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in MVSP_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("MVSP %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        mvsp_result = "FAIL" if "FAIL" in results_list else "PASS"
                        mvsp_status = "open" if mvsp_result == "FAIL" else "pass"
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
                            mvsp_status, mvsp_result, "MVSP", ctrl_def["remediation"],
                            json.dumps({"mvsp_control": ctrl_id, "mvsp_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("MVSP mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
