"""
nist_ai_rmf_mapper_handler.py

Maps existing CIS/FSBP findings in the DB to the NIST AI Risk Management
Framework (AI RMF 1.0, NIST AI 100-1).

Real structure (source: NIST's own AI RMF 1.0 publication, cross-checked
against Securiti.ai and Orca Security's AI RMF guides): 4 core functions
— Govern (cross-cutting culture/accountability), Map (context and system
boundaries), Measure (analyze, assess, track AI risks — includes ongoing
monitoring and testing), Manage (allocate resources to risks, incident
response, recovery).

IMPORTANT — honest scope:
As already established for ISO 42001 and the EU AI Act mappers in this
codebase, Domits has no currently active AI system in production
(confirmed via zero CloudWatch invocations on every AI-response-
generation Lambda). AI RMF 1.0 is a voluntary framework for organizations
that operate AI systems; this mapper is genuine product capability, not
a claim that either company currently has an AI system to risk-manage.

AI RMF is overwhelmingly a governance/process framework — even more so
than ISO 42001's Annex A. Of its 4 functions, Govern and Map are
entirely organisational (culture, accountability, context-setting) and
have no AWS-technical proxy at all. Measure and Manage each have one
genuine technical proxy: continuous monitoring evidence for Measure, and
incident response / recovery capability for Manage.
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

NIST_AI_RMF_MAPPING = {

    "AIRMF.MEASURE": {
        "title": "Measure",
        "severity": "HIGH",
        "section": "Function 3 — Measure",
        "description": (
            "Identified AI risks shall be analyzed, assessed, and "
            "tracked using quantitative and qualitative techniques, "
            "supported by continuous monitoring of the system's "
            "operating environment."
        ),
        "remediation": "Enable multi-region CloudTrail with CloudWatch alarms for all CIS-required security events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "AIRMF.MANAGE": {
        "title": "Manage",
        "severity": "HIGH",
        "section": "Function 4 — Manage",
        "description": (
            "Resources shall be allocated to prioritized AI risks on a "
            "regular basis, covering risk response, incident response, "
            "and recovery of the AI system and its supporting data."
        ),
        "remediation": "Ensure CloudWatch alarms for unauthorized activity are active, and enable automated backups with tested restore procedures.",
        # Was CloudWatch.3 (console sign-in without MFA) — "unauthorized
        # activity" is CloudWatch.2 (unauthorized API calls).
        "checks": ["CloudWatch.1", "CloudWatch.2", "RDS.DR.1", "RDS.DR.2", "RDS.DR.3", "RDS.DR.4", "DynamoDB.DR.1", "DynamoDB.DR.2", "DynamoDB.DR.3"],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("AIRMF.GOVERN", "Govern", "Organisational culture and accountability — not AWS-config verifiable"),
    ("AIRMF.MAP", "Map", "Context and system-boundary identification — not AWS-config verifiable"),
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
                      AND f.framework != 'NIST AI RMF'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for NIST AI RMF mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in NIST_AI_RMF_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("NIST AI RMF %s: no matching findings found, skipping", ctrl_id)
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
                            status, result, "NIST AI RMF", ctrl_def["remediation"],
                            json.dumps({"airmf_function": ctrl_id, "airmf_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("NIST AI RMF mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
