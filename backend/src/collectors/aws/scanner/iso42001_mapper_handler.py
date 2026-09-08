"""
iso42001_mapper_handler.py

Maps existing CIS findings in the DB to ISO/IEC 42001:2023 (AI Management
System) Annex A controls.

Same read-existing-findings-and-roll-up approach as every other mapper in
this codebase (hipaa_mapper_handler.py, gdpr_mapper_handler.py, ...).

IMPORTANT — this is deliberately incomplete, on purpose:
ISO 42001 Annex A has 38 controls across 9 domains (A.2-A.10). Prowler
(https://github.com/prowler-cloud/prowler), the reference open-source CSPM
tool, does not ship an ISO 42001 AWS compliance mapping at all — because
most of Annex A is organisational/process ("is there a documented AI
policy", "has an impact assessment been performed", "are responsibilities
allocated to suppliers") and simply cannot be verified by inspecting AWS API
responses. No CSPM tool can automate a policy document review.

Only the ~8 controls below have a genuine, defensible technical proxy in
existing checks. The other 30 are NOT mapped here — faking a PASS/FAIL for
"AI Policy Documented" off of an unrelated AWS setting would be exactly the
kind of scanner dishonesty this project has spent this whole engagement
removing, not reintroducing under a new framework name. Those 30 need real
manual/organisational evidence (a policy document, a signed-off impact
assessment, etc.), tracked outside this scanner.
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
# ISO/IEC 42001:2023 Annex A → CIS check mapping
# Only controls with a real, defensible technical proxy are included.
# ---------------------------------------------------------------------------
ISO42001_MAPPING = {

    "A.4.3": {
        "title": "Data Resources",
        "severity": "HIGH",
        "section": "A.4 — Resources for AI Systems",
        "description": (
            "The organization shall determine and document the data resources "
            "used by the AI system, including their protection."
        ),
        "remediation": (
            "Enable S3 default encryption on buckets storing AI training/model "
            "data. Enable KMS key rotation for keys protecting that data."
        ),
        "checks": ["S3.3.5", "KMS.1"],
    },

    "A.4.5": {
        "title": "System and Computing Resources",
        "severity": "HIGH",
        "section": "A.4 — Resources for AI Systems",
        "description": (
            "The organization shall determine and document the system and "
            "computing resources needed for the AI system, and control access "
            "to them appropriately."
        ),
        "remediation": (
            "Attach IAM policies to groups/roles only, not individual users. "
            "Remove any policy granting unrestricted '*' administrative access."
        ),
        "checks": ["IAM.1", "IAM.2"],
    },

    "A.6.2.6": {
        "title": "AI-System Operation and Monitoring",
        "severity": "HIGH",
        "section": "A.6 — AI System Life Cycle",
        "description": (
            "The organization shall define and apply measures for continuous "
            "monitoring of the AI system's performance and behaviour throughout "
            "its operation."
        ),
        "remediation": (
            "Enable CloudWatch alarms for all CIS-required security-relevant "
            "events, with an active, confirmed SNS subscription so alerts "
            "actually reach someone."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "A.6.2.8": {
        "title": "AI-System Recording of Event Logs",
        "severity": "HIGH",
        "section": "A.6 — AI System Life Cycle",
        "description": (
            "The organization shall ensure that event logs are recorded for "
            "the AI system to enable identification, investigation, and "
            "reproduction of behaviour and incidents."
        ),
        "remediation": (
            "Ensure CloudTrail is enabled, multi-region, log-file-validated, "
            "and that root-usage and CloudTrail-configuration-change alarms "
            "are active."
        ),
        "checks": ["CloudWatch.1", "CloudWatch.5"],
    },

    "A.7.2": {
        "title": "Data for Development and Enhancement of AI Systems",
        "severity": "CRITICAL",
        "section": "A.7 — Data for AI Systems",
        "description": (
            "The organization shall determine, document, and implement data "
            "management processes related to the development of AI systems, "
            "including protecting that data from unauthorized access."
        ),
        "remediation": (
            "Enable S3 Block Public Access on all buckets storing training, "
            "evaluation, or fine-tuning data."
        ),
        "checks": ["S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4"],
    },

    "A.7.5": {
        "title": "Data Provenance",
        "severity": "MEDIUM",
        "section": "A.7 — Data for AI Systems",
        "description": (
            "The organization shall establish processes to record the "
            "provenance of data used by AI systems, including its origin and "
            "history of changes."
        ),
        "remediation": (
            "Enable S3 versioning on buckets storing AI training/model data "
            "so its change history is retained and reconstructable."
        ),
        "checks": ["S3.3.3"],
    },

    "A.7.6": {
        "title": "Data Preparation",
        "severity": "HIGH",
        "section": "A.7 — Data for AI Systems",
        "description": (
            "The organization shall define and document data preparation "
            "activities, including protection of data during preparation."
        ),
        "remediation": (
            "Enable S3 default encryption and enforce HTTPS-only bucket "
            "policies on buckets used during data preparation pipelines."
        ),
        "checks": ["S3.3.5", "S3.3.2"],
    },

    "A.10.2": {
        "title": "Allocating Responsibilities",
        "severity": "MEDIUM",
        "section": "A.10 — Third-Party and Customer Relationships",
        "description": (
            "The organization shall allocate responsibilities between itself "
            "and third parties involved in the AI system life cycle, "
            "including identifying which parties have access to its resources."
        ),
        "remediation": (
            "Enable IAM Access Analyzer to identify and review any resources "
            "shared with external (third-party) entities."
        ),
        "checks": ["IAM.28"],
    },

    "A.3.2": {
        "title": "AI Roles and Responsibilities",
        "severity": "MEDIUM",
        "section": "A.3 — Internal Organization",
        "description": (
            "The organization shall define and document roles and "
            "responsibilities related to AI, and communicate them across the "
            "organization."
        ),
        "remediation": (
            "Attach IAM policies to groups/roles that reflect defined "
            "responsibilities, rather than granting permissions to individual "
            "users ad hoc."
        ),
        "checks": ["IAM.2"],
    },

    "ISO42001.A.8.4": {
        "title": "Communication of Incidents",
        "severity": "HIGH",
        "section": "A.8 — Information for Interested Parties",
        "description": (
            "The organization shall establish a process for communicating "
            "incidents associated with the AI system to relevant interested "
            "parties."
        ),
        "remediation": (
            "Ensure CloudWatch alarms are active for all CIS-required "
            "security-relevant events, with a confirmed SNS subscription so "
            "incident notifications actually reach someone — an alarm nobody "
            "receives cannot communicate an incident to anyone."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "A.10.3": {
        "title": "Suppliers",
        "severity": "MEDIUM",
        "section": "A.10 — Third-Party and Customer Relationships",
        "description": (
            "The organization shall identify and document suppliers involved "
            "in the AI system life cycle and the resources they can access."
        ),
        "remediation": (
            "Enable IAM Access Analyzer to identify and review any resources "
            "shared with external supplier accounts or roles."
        ),
        "checks": ["IAM.28"],
    },
}

# ---------------------------------------------------------------------------
# The remaining 27 Annex A controls (A.2.2-A.2.4, A.3.3, A.4.2, A.4.4, A.4.6,
# A.5.2-A.5.5, A.6.1.2-A.6.1.3, A.6.2.2-A.6.2.5, A.6.2.7, A.7.3, A.7.4,
# A.8.2, A.8.3, A.8.5, A.9.2-A.9.4, A.10.4) genuinely cannot be verified from
# AWS API responses — they require a policy document, a signed-off impact
# assessment, or an organizational process to exist. They are listed on the
# frontend as "manual evidence required," not scanned or scored here, so a
# viewer sees the full 38-control structure without a fake PASS/FAIL being
# invented for something no CSPM tool can check.
MANUAL_EVIDENCE_CONTROLS = [
    ("A.2.2", "AI Policy", "A.2 — Policies Related to AI"),
    ("A.2.3", "Alignment With Other Organisational Policies", "A.2 — Policies Related to AI"),
    ("A.2.4", "Review of the AI Policy", "A.2 — Policies Related to AI"),
    ("A.3.3", "Reporting of Concerns", "A.3 — Internal Organization"),
    ("A.4.2", "Resource Documentation", "A.4 — Resources for AI Systems"),
    ("A.4.4", "Tooling Resources", "A.4 — Resources for AI Systems"),
    ("A.4.6", "Human Resources", "A.4 — Resources for AI Systems"),
    ("A.5.2", "AI-System Impact-Assessment Process", "A.5 — Assessing Impacts of AI Systems"),
    ("A.5.3", "Documentation of AI-System Impact Assessments", "A.5 — Assessing Impacts of AI Systems"),
    ("A.5.4", "Assessing AI-System Impact on Individuals or Groups", "A.5 — Assessing Impacts of AI Systems"),
    ("A.5.5", "Assessing Societal Impacts of AI Systems", "A.5 — Assessing Impacts of AI Systems"),
    ("A.6.1.2", "Objectives for Responsible Development of AI Systems", "A.6 — AI System Life Cycle"),
    ("A.6.1.3", "Processes for Responsible AI-System Design and Development", "A.6 — AI System Life Cycle"),
    ("A.6.2.2", "AI-System Requirements and Specification", "A.6 — AI System Life Cycle"),
    ("A.6.2.3", "Documentation of AI-System Design and Development", "A.6 — AI System Life Cycle"),
    ("A.6.2.4", "AI-System Verification and Validation", "A.6 — AI System Life Cycle"),
    ("A.6.2.5", "AI-System Deployment", "A.6 — AI System Life Cycle"),
    ("A.6.2.7", "AI-System Technical Documentation", "A.6 — AI System Life Cycle"),
    ("A.7.3", "Acquisition of Data", "A.7 — Data for AI Systems"),
    ("A.7.4", "Quality of Data for AI Systems", "A.7 — Data for AI Systems"),
    ("A.8.2", "System Documentation and Information for Users", "A.8 — Information for Interested Parties"),
    ("A.8.3", "External Reporting", "A.8 — Information for Interested Parties"),
    ("A.8.5", "Information for Interested Parties", "A.8 — Information for Interested Parties"),
    ("A.9.2", "Processes for Responsible Use of AI Systems", "A.9 — Use of AI Systems"),
    ("A.9.3", "Objectives for Responsible Use of AI Systems", "A.9 — Use of AI Systems"),
    ("A.9.4", "Intended Use of the AI System", "A.9 — Use of AI Systems"),
    ("A.10.4", "Customers", "A.10 — Third-Party and Customer Relationships"),
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
