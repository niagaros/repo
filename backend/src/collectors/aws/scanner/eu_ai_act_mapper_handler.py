"""
eu_ai_act_mapper_handler.py

Maps existing CIS/FSBP findings in the DB to the EU AI Act (Regulation
(EU) 2024/1689) requirements for high-risk AI systems.

Real article structure used here (source: the regulation's own Articles
10-17, cross-checked against WilmerHale, Goteleport, and Blue Arrow AI
Act guides): Art. 10 Data and data governance, Art. 11 / Annex IV
Technical documentation, Art. 12 Record-keeping (automatic logging for
the system's full lifetime), Art. 15 Accuracy, robustness and
cybersecurity, Art. 17 Quality management system.

IMPORTANT — honest scope, read before extending this file:
This scanner already established (via CloudWatch invocation metrics and
CloudTrail, not assumption) that Domits has NO currently active AI
system in production — every AI-response-generation Lambda shows zero
invocations. The EU AI Act's substantive obligations apply specifically
to high-risk AI systems being placed on the market or put into service;
with no live AI system, this framework does not currently apply as a
compliance obligation to Domits or Niagaros. This mapper exists as
readiness/product capability — the same honest posture already applied
to ISO 42001 — so that if/when a real AI system is deployed, the
technical evidence (logging, data protection, cryptographic integrity)
is already being collected. It is NOT a claim that either company is
currently subject to EU AI Act obligations.

Of the AI Act's technical requirement articles, only 3 have a genuine
AWS-technical proxy: Art. 10 (data governance protections), Art. 12
(automatic logging), and Art. 15 (cybersecurity of the system). Articles
9 (risk management system), 11/Annex IV (technical documentation), 14
(human oversight design), and 17 (quality management system) are
process/documentation obligations that cannot be verified from AWS API
responses.
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

EU_AI_ACT_MAPPING = {

    "EUAI.10": {
        "title": "Data and Data Governance",
        "severity": "CRITICAL",
        "section": "Art. 10 — Data and Data Governance",
        "description": (
            "Training, validation, and testing data sets used by "
            "high-risk AI systems shall be subject to appropriate data "
            "governance practices, including protection against "
            "unauthorized access."
        ),
        "remediation": "Block all public access to S3 buckets storing training/model data. Enable default encryption.",
        "checks": ["S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4", "S3.3.5"],
    },
    "EUAI.12": {
        "title": "Record-Keeping",
        "severity": "HIGH",
        "section": "Art. 12 — Record-Keeping",
        "description": (
            "High-risk AI systems shall technically allow for the "
            "automatic recording of events (logs) over the duration of "
            "the system's lifetime."
        ),
        "remediation": "Enable multi-region CloudTrail with CloudWatch alarms and log file validation.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "EUAI.15": {
        "title": "Accuracy, Robustness and Cybersecurity",
        "severity": "CRITICAL",
        "section": "Art. 15 — Accuracy, Robustness and Cybersecurity",
        "description": (
            "High-risk AI systems shall be designed to achieve an "
            "appropriate level of cybersecurity, resilient against "
            "attempts to alter their use, outputs, or performance."
        ),
        "remediation": "Enable KMS key rotation and least-privilege IAM access to protect the AI system's underlying infrastructure.",
        "checks": ["KMS.1", "KMS.2", "KMS.3", "KMS.4", "IAM.1", "IAM.2", "IAM.5"],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("EUAI.9", "Risk Management System", "Organisational process — not AWS-config verifiable"),
    ("EUAI.11", "Technical Documentation (Annex IV)", "Documentation obligation — not AWS-config verifiable"),
    ("EUAI.14", "Human Oversight", "Design/process obligation — not AWS-config verifiable"),
    ("EUAI.17", "Quality Management System", "Organisational process — not AWS-config verifiable"),
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
                      AND f.framework != 'EU AI Act'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for EU AI Act mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in EU_AI_ACT_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("EU AI Act %s: no matching findings found, skipping", ctrl_id)
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
                            status, result, "EU AI Act", ctrl_def["remediation"],
                            json.dumps({"euai_article": ctrl_id, "euai_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("EU AI Act mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
