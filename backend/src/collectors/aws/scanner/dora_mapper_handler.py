"""
dora_mapper_handler.py

Maps existing CIS/FSBP findings in the DB to DORA (Regulation (EU)
2022/2554, Digital Operational Resilience Act) requirements.

DORA is an EU financial-sector regulation on ICT risk management. Its
real article structure (source: BMC, Glocert, and the EU regulation text
itself, cross-checked): Art. 6-7 ICT risk management framework, Art. 9
Protection and prevention, Art. 10 Detection, Art. 11 Response and
recovery, Art. 12 Backup policies and recovery methods, Art. 17-19 ICT
incident management, Art. 28-30 ICT third-party risk management.

IMPORTANT — honest scope:
DORA applies specifically to regulated EU financial entities. Neither
Domits nor Niagaros is a regulated financial entity, so this mapper is
built as genuine product capability (the same way TISAX — automotive —
and AWS FTR were built) rather than a claim that either company is
currently subject to DORA. Of DORA's real technical requirement areas,
6 have a genuine AWS-technical proxy and are mapped below. The rest
(management-body accountability, information-sharing arrangements,
Threat-Led Penetration Testing governance, contractual exit-strategy
terms with ICT providers) are organisational/contractual and cannot be
verified from AWS API responses.
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

DORA_MAPPING = {

    "DORA.6": {
        "title": "ICT Risk Management Framework",
        "severity": "HIGH",
        "section": "Art. 6-7 — ICT Risk Management Framework",
        "description": (
            "Financial entities shall have a sound, comprehensive, and "
            "well-documented ICT risk management framework, including "
            "strategies, policies, and tools to protect ICT assets."
        ),
        "remediation": "Enforce IAM password policy, MFA for all console users, and remove unused credentials.",
        "checks": ["IAM.1", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9"],
    },
    "DORA.9": {
        "title": "Protection and Prevention",
        "severity": "CRITICAL",
        "section": "Art. 9 — Protection and Prevention",
        "description": (
            "Financial entities shall continuously monitor and control "
            "the security and functioning of ICT systems, and minimise "
            "the impact of ICT risk through appropriate strategies, "
            "policies, procedures, protocols, and tools, including "
            "encryption of data at rest and in transit."
        ),
        "remediation": "Enable S3 default encryption, HTTPS-only bucket policies, and KMS key rotation.",
        "checks": ["S3.3.5", "S3.3.2", "KMS.1", "KMS.2", "KMS.3", "KMS.4"],
    },
    "DORA.10": {
        "title": "Detection",
        "severity": "HIGH",
        "section": "Art. 10 — Detection",
        "description": (
            "Financial entities shall have mechanisms to promptly detect "
            "anomalous activities, including ICT network performance "
            "issues and ICT-related incidents, and to identify potential "
            "material single points of failure."
        ),
        "remediation": "Enable multi-region CloudTrail with CloudWatch alarms for all CIS-required security events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "DORA.11": {
        "title": "Response and Recovery",
        "severity": "HIGH",
        "section": "Art. 11 — Response and Recovery",
        "description": (
            "Financial entities shall put in place a comprehensive ICT "
            "business continuity policy and dedicated response and "
            "recovery plans."
        ),
        "remediation": "Ensure CloudWatch alarms for unauthorized API calls and root usage are active with a confirmed SNS subscription for rapid response.",
        "checks": ["CloudWatch.1", "CloudWatch.3"],
    },
    "DORA.12": {
        "title": "Backup Policies and Recovery Methods",
        "severity": "HIGH",
        "section": "Art. 12 — Backup Policies and Recovery Methods",
        "description": (
            "Financial entities shall develop backup policies specifying "
            "the scope of data and recovery methods, so that all data "
            "and systems can be restored with minimum downtime and loss."
        ),
        "remediation": "Enable automated backups / point-in-time recovery with adequate retention, and verify restore procedures are tested.",
        "checks": ["RDS.DR.1", "RDS.DR.2", "RDS.DR.3", "RDS.DR.4", "DynamoDB.DR.1", "DynamoDB.DR.2", "DynamoDB.DR.3"],
    },
    "DORA.28": {
        "title": "ICT Third-Party Risk Management",
        "severity": "MEDIUM",
        "section": "Art. 28-30 — ICT Third-Party Risk Management",
        "description": (
            "Financial entities shall manage ICT third-party risk, "
            "including identifying which external parties have access "
            "to their ICT resources."
        ),
        "remediation": "Enable IAM Access Analyzer to identify and review resources shared with external entities.",
        "checks": ["IAM.28"],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("DORA.5", "Governance and Organisation (Management Body Accountability)", "Organisational — not AWS-config verifiable"),
    ("DORA.13", "Learning and Evolving / Information Sharing", "Organisational — not AWS-config verifiable"),
    ("DORA.17", "ICT-Related Incident Management Process", "Organisational process — not AWS-config verifiable"),
    ("DORA.24", "Digital Operational Resilience Testing Programme (TLPT)", "Requires governance of a testing programme, not a single AWS-config check"),
    ("DORA.30", "Key Contractual Provisions with ICT Providers", "Contractual — not AWS-config verifiable"),
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
                      AND f.framework != 'DORA'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for DORA mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in DORA_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("DORA %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        dora_result = "FAIL" if "FAIL" in results_list else "PASS"
                        dora_status = "open" if dora_result == "FAIL" else "pass"
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
                            dora_status, dora_result, "DORA", ctrl_def["remediation"],
                            json.dumps({"dora_article": ctrl_id, "dora_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("DORA mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
