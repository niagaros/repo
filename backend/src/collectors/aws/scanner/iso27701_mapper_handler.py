"""
iso27701_mapper_handler.py

Maps existing CIS/FSBP findings in the DB to ISO/IEC 27701:2019 (Privacy
Information Management System, PIMS) requirements.

ISO 27701 is explicitly a privacy extension to ISO 27001/27002: it uses
the same clause 4-10 management-system structure and adds a consolidated
Annex A/B (PII controller / PII processor controls) on top of the
supporting ISO 27001 information security controls (source: ISO's own
standard overview, cross-checked against scrut.io and isms.online PIMS
guides).

IMPORTANT — honest scope:
Because ISO 27701 explicitly incorporates ISO 27001's own controls as its
security foundation, this mapper reuses the same genuine technical
evidence already used by this codebase's ISO 27001 mapper (access
control, cryptography, logging), under privacy-specific category labels,
plus two genuinely privacy-specific technical proxies: PII retention
(via S3 versioning, supporting demonstrable history/recoverability) and
PII sharing/disclosure to third parties (via IAM Access Analyzer). The
substantive privacy obligations — purpose limitation, consent management,
data subject access/erasure/portability rights, privacy impact
assessments, cross-border transfer legal mechanisms — are process and
legal obligations that cannot be verified from AWS API responses and are
listed as manual-evidence-required.
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

ISO27701_MAPPING = {

    "ISO27701.ACCESS": {
        "title": "Access Control for PII",
        "severity": "CRITICAL",
        "section": "Supporting ISO 27001 Controls, applied to PII",
        "description": (
            "Access to systems and information processing PII shall be "
            "restricted to authorized personnel through least-privilege "
            "access controls and multi-factor authentication."
        ),
        "remediation": "Enforce IAM password policy, MFA for console access, and remove unused credentials.",
        "checks": ["IAM.1", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9"],
    },
    "ISO27701.CRYPTO": {
        "title": "Cryptography for PII Protection",
        "severity": "CRITICAL",
        "section": "Supporting ISO 27001 Controls, applied to PII",
        "description": (
            "Cryptographic controls shall be used to protect the "
            "confidentiality of PII at rest and in transit."
        ),
        "remediation": "Enable S3 default encryption, HTTPS-only bucket policies, and KMS key rotation.",
        "checks": ["S3.3.5", "S3.3.2", "KMS.1", "KMS.2", "KMS.3", "KMS.4"],
    },
    "ISO27701.LOG": {
        "title": "Logging and Monitoring of PII Processing",
        "severity": "HIGH",
        "section": "Supporting ISO 27001 Controls, applied to PII",
        "description": (
            "Access to and processing of PII shall be logged and "
            "monitored to support accountability and incident detection."
        ),
        "remediation": "Enable multi-region CloudTrail with CloudWatch alarms for all CIS-required security events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "ISO27701.RETENTION": {
        "title": "PII Retention and Disposal",
        "severity": "MEDIUM",
        "section": "Annex A/B — PII Controller/Processor Controls",
        "description": (
            "Processes shall exist to record the history of PII and "
            "support demonstrable retention and recovery."
        ),
        "remediation": "Enable S3 versioning on buckets storing PII so its change history is retained and reconstructable.",
        "checks": ["S3.3.3"],
    },
    "ISO27701.SHARING": {
        "title": "PII Sharing, Transfer and Disclosure",
        "severity": "HIGH",
        "section": "Annex A/B — PII Controller/Processor Controls",
        "description": (
            "The organization shall identify and review third parties "
            "and external accounts with access to PII."
        ),
        "remediation": "Enable IAM Access Analyzer to identify and review resources shared with external entities.",
        "checks": ["IAM.28"],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("ISO27701.PURPOSE", "Purpose Limitation and Conditions for Collection", "Legal/organisational — not AWS-config verifiable"),
    ("ISO27701.CONSENT", "Consent Management", "Organisational process — not AWS-config verifiable"),
    ("ISO27701.RIGHTS", "Obligations to PII Principals (Access, Erasure, Portability)", "Process obligation — not AWS-config verifiable"),
    ("ISO27701.PBD", "Privacy by Design and by Default", "Design process — not AWS-config verifiable"),
    ("ISO27701.TRANSFER", "Cross-Border Transfer Legal Mechanisms", "Legal — not AWS-config verifiable"),
    ("ISO27701.DPIA", "Privacy Impact Assessments", "Organisational process — not AWS-config verifiable"),
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
                      AND f.framework != 'ISO 27701'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for ISO 27701 mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in ISO27701_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("ISO27701 %s: no matching findings found, skipping", ctrl_id)
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
                            status, result, "ISO 27701", ctrl_def["remediation"],
                            json.dumps({"iso27701_control": ctrl_id, "iso27701_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("ISO 27701 mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
