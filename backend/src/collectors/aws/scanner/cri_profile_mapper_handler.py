"""
cri_profile_mapper_handler.py

Maps existing CIS/FSBP/GitHub findings in the DB to the CRI Profile
(Cyber Risk Institute Profile for the Financial Sector).

The CRI Profile extends the 5 NIST CSF functions (Identify, Protect,
Detect, Respond, Recover) with 2 additional functions — Governance and
Supply Chain/Dependency Management — for a total of 7 functions, further
broken into categories and 318 diagnostic statements (source: Cyber Risk
Institute's own published Profile overview, cross-checked against
smartsuite.com and Vanta's CRI Profile guide).

IMPORTANT — honest scope:
The CRI Profile is built for regulated financial institutions (banks,
insurers, credit unions). Neither Domits nor Niagaros is such an entity —
this mapper is built as genuine product capability, not a claim that
either company is subject to CRI Profile assessment. The 318 individual
diagnostic statements are not fully public; this mapper works at the
7-function level (the verifiable top-level structure) rather than
inventing specific diagnostic-statement numbers it cannot cite.
Governance is organisational and is not mapped; the other 6 functions
each have a genuine, existing technical proxy.
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

CRI_MAPPING = {

    "CRI.IDENTIFY": {
        "title": "Identify",
        "severity": "MEDIUM",
        "section": "Function 2 — Identify",
        "description": (
            "The organization shall identify and review information "
            "assets and their exposure to external parties as a basis "
            "for risk management."
        ),
        "remediation": "Enable IAM Access Analyzer to identify resources shared with external entities.",
        "checks": ["IAM.28"],
    },
    "CRI.PROTECT": {
        "title": "Protect",
        "severity": "CRITICAL",
        "section": "Function 3 — Protect",
        "description": (
            "Safeguards shall be implemented to ensure delivery of "
            "critical services, including access control, credential "
            "hygiene, and encryption of data at rest and in transit."
        ),
        "remediation": "Enforce IAM password policy, MFA, credential rotation, and enable S3/KMS encryption.",
        "checks": ["IAM.1", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9", "KMS.1", "KMS.2", "KMS.3", "KMS.4", "S3.3.5", "S3.3.2"],
    },
    "CRI.DETECT": {
        "title": "Detect",
        "severity": "HIGH",
        "section": "Function 4 — Detect",
        "description": (
            "Activities shall be implemented to identify the occurrence "
            "of a cybersecurity event in a timely manner."
        ),
        "remediation": "Enable multi-region CloudTrail with CloudWatch alarms for all CIS-required security events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "CRI.RESPOND": {
        "title": "Respond",
        "severity": "HIGH",
        "section": "Function 5 — Respond",
        "description": (
            "Activities shall be implemented to take action regarding a "
            "detected cybersecurity incident, including active alerting "
            "on unauthorized access and root account usage."
        ),
        "remediation": "Ensure CloudWatch alarms for unauthorized API calls and root usage are active with a confirmed SNS subscription.",
        # Was CloudWatch.3 (console sign-in without MFA) — the text asks for
        # "unauthorized API calls", which is CloudWatch.2.
        "checks": ["CloudWatch.1", "CloudWatch.2"],
    },
    "CRI.RECOVER": {
        "title": "Recover",
        "severity": "HIGH",
        "section": "Function 6 — Recover",
        "description": (
            "Plans for resilience and restoration of services impaired "
            "by a cybersecurity incident shall be implemented and tested."
        ),
        "remediation": "Enable automated backups / point-in-time recovery with adequate retention, and verify restore procedures are tested.",
        "checks": ["RDS.DR.1", "RDS.DR.2", "RDS.DR.3", "RDS.DR.4", "DynamoDB.DR.1", "DynamoDB.DR.2", "DynamoDB.DR.3"],
    },
    "CRI.SUPPLYCHAIN": {
        "title": "Supply Chain / Dependency Management",
        "severity": "MEDIUM",
        "section": "Function 7 — Supply Chain / Dependency Management",
        "description": (
            "Risks arising from third-party dependencies and software "
            "supply chains shall be identified and managed, including "
            "monitoring for known vulnerabilities and external resource "
            "sharing."
        ),
        "remediation": "Enable Dependabot vulnerability alerts on all GitHub repositories and IAM Access Analyzer for external access.",
        "checks": ["github_1.5.1", "github_1.5.5", "IAM.28"],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("CRI.GOVERN", "Governance", "Organisational — not AWS-config verifiable"),
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
                      AND f.framework != 'CRI Profile'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for CRI Profile mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in CRI_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("CRI %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        cri_result = "FAIL" if "FAIL" in results_list else "PASS"
                        cri_status = "open" if cri_result == "FAIL" else "pass"
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
                            cri_status, cri_result, "CRI Profile", ctrl_def["remediation"],
                            json.dumps({"cri_function": ctrl_id, "cri_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("CRI Profile mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
