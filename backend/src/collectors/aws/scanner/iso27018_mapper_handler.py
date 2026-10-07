"""
iso27018_mapper_handler.py

Maps existing CIS/FSBP findings in the DB to ISO/IEC 27018 (Code of
Practice for Protection of PII in Public Clouds acting as PII
Processors).

ISO 27018 is explicitly built on ISO/IEC 27002, giving cloud-specific
guidance for protecting PII (source: ISO's own standard scope statement,
cross-checked against TÜV SÜD, ISO.org, and ISMS.online overviews). Like
ISO 27017 (the general cloud-security extension already in this
codebase), ISO 27018 is the privacy-focused counterpart for public
cloud PII processors.

IMPORTANT — honest scope:
Of ISO 27018's real subject areas, only 3 have a genuine, existing
technical AWS proxy: access control to PII, cryptography protecting PII,
and the logging/monitoring capability that underpins breach-notification
obligations. The standard's other real requirements — confidentiality
agreements with staff processing PII, return/deletion of PII at contract
termination, notification of subcontractor engagement, and disclosure of
government access requests — are contractual/organisational obligations
that cannot be verified from AWS API responses.
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

ISO27018_MAPPING = {

    "ISO27018.ACCESS": {
        "title": "Access Control to PII",
        "severity": "CRITICAL",
        "section": "PII Processor Controls, applied to Public Cloud",
        "description": (
            "Access to PII processed in the public cloud shall be "
            "restricted to authorized personnel through least-privilege "
            "access controls and strong authentication."
        ),
        "remediation": "Enforce IAM password policy, MFA for console access, and remove unused credentials.",
        "checks": ["IAM.1", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9"],
    },
    "ISO27018.CRYPTO": {
        "title": "Cryptographic Protection of PII",
        "severity": "CRITICAL",
        "section": "PII Processor Controls, applied to Public Cloud",
        "description": (
            "PII processed in the public cloud shall be protected using "
            "cryptography at rest and in transit."
        ),
        "remediation": "Enable S3 default encryption, HTTPS-only bucket policies, and KMS key rotation.",
        "checks": ["S3.3.5", "S3.3.2", "KMS.1", "KMS.2", "KMS.3", "KMS.4"],
    },
    "ISO27018.BREACH": {
        "title": "Notification of a Data Breach Involving PII",
        "severity": "HIGH",
        "section": "PII Processor Controls, applied to Public Cloud",
        "description": (
            "Mechanisms shall exist to detect security incidents "
            "affecting PII promptly enough to support breach "
            "notification obligations."
        ),
        "remediation": "Ensure CloudTrail is enabled and CloudWatch alarms for unauthorized API calls and root usage are active with a confirmed SNS subscription.",
        # Was CloudWatch.3 (console sign-in without MFA) — "unauthorized API
        # calls" is CloudWatch.2.
        "checks": ["CloudWatch.1", "CloudWatch.2"],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("ISO27018.CONFIDENTIALITY", "Confidentiality Agreements for Staff Processing PII", "Contractual/HR — not AWS-config verifiable"),
    ("ISO27018.RETURN", "Return, Transfer and Disposal of PII at Contract Termination", "Contractual process — not AWS-config verifiable"),
    ("ISO27018.SUBCONTRACTOR", "Notification of Use of Subcontractors", "Contractual — not AWS-config verifiable"),
    ("ISO27018.GOVACCESS", "Disclosure of Government Access Requests", "Legal process — not AWS-config verifiable"),
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
                      AND f.framework != 'ISO 27018'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for ISO 27018 mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in ISO27018_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("ISO27018 %s: no matching findings found, skipping", ctrl_id)
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
                            status, result, "ISO 27018", ctrl_def["remediation"],
                            json.dumps({"iso27018_control": ctrl_id, "iso27018_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("ISO 27018 mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
