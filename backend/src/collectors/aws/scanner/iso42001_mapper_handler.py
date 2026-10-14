"""
iso42001_mapper_handler.py

ISO/IEC 42001:2023 (AI Management System) Annex A — every control is manual
evidence. This mapper deliberately scores nothing automatically.

All 38 Annex A controls (A.2-A.10) ask the organisation to define, document or
run a process for its AI systems: an AI policy, roles, impact assessments,
data-management, provenance and data-preparation processes, supplier and
customer responsibilities. Nothing in an AWS API response proves that such a
process exists. On top of that, this scanner cannot tell which resources belong
to an AI system at all (there is no SageMaker/Bedrock collector and no "AI data"
tag), so even a control that touches data or logs cannot be scoped to the right
resources. Prowler (https://github.com/prowler-cloud/prowler) ships no ISO 42001
AWS mapping for the same reason.

Until 2026-10 this file mapped 11 controls onto unrelated CIS checks — e.g.
A.7.2 "Data for development and enhancement of AI system" (CRITICAL) onto S3
Block Public Access for *every* bucket, A.7.5 "Data provenance" onto S3
versioning. That produced pass/fail results for AI controls on buckets that hold
no AI data, which is fabricated compliance data. Those rows are now removed on
each run (see run_mapping), and the controls are listed below as manual evidence.
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
# No ISO 42001 control has a defensible technical proxy in this scanner (see the
# module docstring). Kept as a dict so the mapping loop and the stale-row cleanup
# in run_mapping work unchanged if a real, AI-scoped check is ever added.
# ---------------------------------------------------------------------------
ISO42001_MAPPING = {}

NO_TECHNICAL_PROXY_REASON = (
    "Every ISO 42001 Annex A control requires a documented process or decision for an AI "
    "system, and the scanner cannot identify which AWS resources belong to an AI system."
)

_PROCESS = "Organisational process — not AWS-config verifiable"
_DOC = "Documentation obligation — not AWS-config verifiable"
_AI_SCOPE = ("Process control scoped to AI-system data/resources — the scanner cannot identify "
             "which resources belong to an AI system")

# (control_id, title, reason) — same shape as every other mapper's manual list.
MANUAL_EVIDENCE_CONTROLS = [
    ("A.2.2", "AI Policy", _DOC),
    ("A.2.3", "Alignment With Other Organisational Policies", _PROCESS),
    ("A.2.4", "Review of the AI Policy", _PROCESS),
    ("A.3.2", "AI Roles and Responsibilities", _PROCESS),
    ("A.3.3", "Reporting of Concerns", _PROCESS),
    ("A.4.2", "Resource Documentation", _DOC),
    ("A.4.3", "Data Resources", _AI_SCOPE),
    ("A.4.4", "Tooling Resources", _DOC),
    ("A.4.5", "System and Computing Resources", _AI_SCOPE),
    ("A.4.6", "Human Resources", _DOC),
    ("A.5.2", "AI-System Impact-Assessment Process", _PROCESS),
    ("A.5.3", "Documentation of AI-System Impact Assessments", _DOC),
    ("A.5.4", "Assessing AI-System Impact on Individuals or Groups", _PROCESS),
    ("A.5.5", "Assessing Societal Impacts of AI Systems", _PROCESS),
    ("A.6.1.2", "Objectives for Responsible Development of AI Systems", _PROCESS),
    ("A.6.1.3", "Processes for Responsible AI-System Design and Development", _PROCESS),
    ("A.6.2.2", "AI-System Requirements and Specification", _DOC),
    ("A.6.2.3", "Documentation of AI-System Design and Development", _DOC),
    ("A.6.2.4", "AI-System Verification and Validation", _PROCESS),
    ("A.6.2.5", "AI-System Deployment", _PROCESS),
    ("A.6.2.6", "AI-System Operation and Monitoring", _AI_SCOPE),
    ("A.6.2.7", "AI-System Technical Documentation", _DOC),
    ("A.6.2.8", "AI-System Recording of Event Logs", _AI_SCOPE),
    ("A.7.2", "Data for Development and Enhancement of AI Systems", _AI_SCOPE),
    ("A.7.3", "Acquisition of Data", _PROCESS),
    ("A.7.4", "Quality of Data for AI Systems", _PROCESS),
    ("A.7.5", "Data Provenance", _AI_SCOPE),
    ("A.7.6", "Data Preparation", _AI_SCOPE),
    ("A.8.2", "System Documentation and Information for Users", _DOC),
    ("A.8.3", "External Reporting", _PROCESS),
    ("A.8.4", "Communication of Incidents", _PROCESS),
    ("A.8.5", "Information for Interested Parties", _PROCESS),
    ("A.9.2", "Processes for Responsible Use of AI Systems", _PROCESS),
    ("A.9.3", "Objectives for Responsible Use of AI Systems", _PROCESS),
    ("A.9.4", "Intended Use of the AI System", _PROCESS),
    ("A.10.2", "Allocating Responsibilities", _AI_SCOPE),
    ("A.10.3", "Suppliers", _PROCESS),
    ("A.10.4", "Customers", _PROCESS),
]

def _get_connection():
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    client = boto3.client("secretsmanager", region_name=region)
    secret = json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return psycopg2.connect(
        host=secret["host"],
        port=secret.get("port", 5432),
        dbname=secret["database"],
        user=secret["username"],
        password=secret["password"],
        sslmode="require",
        connect_timeout=10,
    )


def run_mapping(cloud_account_id: str) -> dict:
    conn = _get_connection()
    findings_upserted = 0

    try:
        with conn:
            with conn.cursor() as cur:

                # Remove this account's ISO 42001 rows for controls that are no longer
                # mapped (all of them, today), so earlier proxy results don't linger
                # on the dashboard. Only rows this mapper wrote: framework 'ISO 42001'.
                cur.execute("""
                    DELETE FROM findings f
                    USING resources r
                    WHERE r.id = f.resource_id
                      AND r.cloud_account_id = %s
                      AND f.framework = 'ISO 42001'
                      AND NOT (f.check_id = ANY(%s::text[]))
                """, (cloud_account_id, list(ISO42001_MAPPING)))
                if cur.rowcount:
                    logger.info("ISO42001: removed %d findings for unmapped controls", cur.rowcount)

                if not ISO42001_MAPPING:
                    return {"findings_upserted": 0, "findings_removed": cur.rowcount}

                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework != 'ISO 42001'
                """, (cloud_account_id,))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for ISO 42001 mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in ISO42001_MAPPING.items():
                    resource_results: dict = {}

                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {
                                "results": [],
                                "resource_name": entry["resource_name"],
                                "resource_type": entry["resource_type"],
                            })
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("ISO42001 %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        iso_result = "FAIL" if "FAIL" in results_list else "PASS"
                        iso_status = "open" if iso_result == "FAIL" else "pass"

                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")
                        description = (
                            f"{ctrl_def['description']} "
                            f"({passed} checks passing, {failed} failing)"
                        )

                        cur.execute("""
                            INSERT INTO findings
                                (resource_id, check_id, title, description,
                                 severity, status, result, framework, remediation,
                                 details, detected_at)
                            VALUES
                                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                            ON CONFLICT (resource_id, check_id)
                            DO UPDATE SET
                                title       = EXCLUDED.title,
                                description = EXCLUDED.description,
                                severity    = EXCLUDED.severity,
                                status      = EXCLUDED.status,
                                result      = EXCLUDED.result,
                                framework   = EXCLUDED.framework,
                                remediation = EXCLUDED.remediation,
                                details     = EXCLUDED.details,
                                detected_at = NOW()
                        """, (
                            resource_id,
                            ctrl_id,
                            ctrl_def["title"],
                            description,
                            ctrl_def["severity"],
                            iso_status,
                            iso_result,
                            "ISO 42001",
                            ctrl_def["remediation"],
                            json.dumps({
                                "iso42001_control": ctrl_id,
                                "iso42001_section": ctrl_def["section"],
                                "mapped_checks":    ctrl_def["checks"],
                                "passed":           passed,
                                "failed":           failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "ISO42001 %s / resource %s -> %s (%d/%d passing)",
                            ctrl_id, resource_id, iso_result, passed, len(results_list)
                        )

        logger.info("ISO 42001 mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
