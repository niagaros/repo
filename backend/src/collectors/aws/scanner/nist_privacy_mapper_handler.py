"""
nist_privacy_mapper_handler.py

Maps existing CIS/FSBP findings in the DB to the NIST Privacy Framework
v1.0 (source: NIST's own published Framework Core, cross-checked
against csf.tools' structured mirror of the same Core for exact
category IDs/titles — NIST deliberately designed this Core to mirror
NIST CSF's Identify/Protect/Detect structure so organisations could
implement privacy and security risk management jointly).

This replaces USDP (US Data Privacy) in this product's Privacy
Frameworks category: USDP is a Vanta-exclusive, proprietary bundling
of ~19 US state privacy laws (CCPA/CPRA, VCDPA, CPA, CTDPA, UCPA, etc.)
with no independently published specification this codebase could cite
without guessing at Vanta's own internal control text. NIST Privacy
Framework is freely published, vendor-neutral, and already used
alongside NIST CSF (already in this codebase) by large US
organisations across tech and finance.

IMPORTANT — honest scope, read before extending this file:
The Framework's five Functions (Identify-P, Govern-P, Control-P,
Communicate-P, Protect-P) are overwhelmingly organisational: data
inventories and mapping, business-environment understanding, privacy
risk assessment methodology, governance policy, risk-management
strategy, workforce training, ongoing-review processes, data-processing
policy/management, and communication with data subjects about
processing. None of that is verifiable from an AWS API response.
Only the Protect-P function's technology-facing categories have a
genuine, existing technical proxy in this codebase:
  - PR.AC-P Identity Management, Authentication, and Access Control -> IAM checks
  - PR.DS-P Data Security                                           -> S3/KMS encryption checks
  - PR.PT-P Protective Technology                                    -> CloudWatch/logging checks
Protect-P's own PR.PO-P (Data Protection Policy) and PR.MA-P
(Maintenance), and all of Identify-P, Govern-P, Control-P, and
Communicate-P, are listed as manual-evidence-required rather than
approximated.
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

NIST_PRIVACY_MAPPING = {

    "NISTPRIV.PR.AC-P": {
        "title": "Identity Management, Authentication, and Access Control",
        "severity": "CRITICAL",
        "section": "NIST Privacy Framework v1.0 — Protect-P",
        "description": (
            "Access to data and devices is limited to authorized users, "
            "processes, and devices, and is managed consistent with the "
            "assessed risk of unauthorized access."
        ),
        "remediation": "Enforce IAM password policy, MFA for console access, and remove unused credentials.",
        "checks": ["IAM.1", "IAM.2", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9", "IAM.28"],
    },
    "NISTPRIV.PR.DS-P": {
        "title": "Data Security",
        "severity": "CRITICAL",
        "section": "NIST Privacy Framework v1.0 — Protect-P",
        "description": (
            "Data is managed consistent with the organization's risk "
            "strategy to protect individuals' privacy, including "
            "protection at rest and in transit."
        ),
        "remediation": "Enable S3 default encryption, HTTPS-only bucket policies, and KMS key rotation.",
        "checks": ["S3.3.1", "S3.3.2", "S3.3.3", "S3.3.4", "S3.3.5", "KMS.1", "KMS.2", "KMS.3", "KMS.4", "KMS.5", "KMS.6"],
    },
    "NISTPRIV.PR.PT-P": {
        "title": "Protective Technology",
        "severity": "HIGH",
        "section": "NIST Privacy Framework v1.0 — Protect-P",
        "description": (
            "Technical security solutions are managed to ensure the "
            "security and resilience of systems and assets processing "
            "personal data, consistent with related policies."
        ),
        "remediation": "Enable multi-region CloudTrail with CloudWatch alarms for all CIS-required security events.",
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("NISTPRIV.ID-P", "Identify-P (Inventory, Business Environment, Risk Assessment, Ecosystem Risk Management)", "Organisational understanding of data processing — not AWS-config verifiable"),
    ("NISTPRIV.GV-P", "Govern-P (Governance Policy, Risk Management Strategy, Awareness & Training, Monitoring & Review)", "Governance program — not AWS-config verifiable"),
    ("NISTPRIV.CT-P", "Control-P (Data Processing Policy, Data Processing Management, Disassociated Processing)", "Data-handling policy and process — not AWS-config verifiable"),
    ("NISTPRIV.CM-P", "Communicate-P (Communication Policy, Data Processing Awareness)", "Transparency and data-subject communication — not AWS-config verifiable"),
    ("NISTPRIV.PR.PO-P", "Data Protection Policies, Processes, and Procedures", "Written policy — not AWS-config verifiable"),
    ("NISTPRIV.PR.MA-P", "Maintenance", "Maintenance process for systems processing personal data — not AWS-config verifiable"),
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
                      AND f.framework != 'NIST Privacy Framework'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for NIST Privacy Framework mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in NIST_PRIVACY_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("NIST Privacy %s: no matching findings found, skipping", ctrl_id)
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
                            status, result, "NIST Privacy Framework", ctrl_def["remediation"],
                            Json({"nistpriv_category": ctrl_id, "nistpriv_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("NIST Privacy Framework mapping complete: %d findings upserted", findings_upserted)
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
                        VALUES ('cspm-nist-privacy-mapper', 'compliance', 'NIST Privacy Framework v1.0 -- 3 of ~19 categories with a real technical AWS proxy', true)
                        ON CONFLICT (function_name) DO NOTHING
                    """)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()

    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
