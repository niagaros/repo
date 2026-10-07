"""
sspa_mapper_handler.py

Maps existing CIS/FSBP/GitHub findings in the DB to Microsoft's Supplier
Security and Privacy Assurance (SSPA) program Data Protection
Requirements (DPR).

Real, citable category names (source: Microsoft's own SSPA program
overview and Learn documentation, cross-checked against hyperproof.io
and Drata's SSPA guides): the DPR requires suppliers to maintain an
information security program covering privacy controls and security
controls including data loss prevention, vulnerability management, and
access management.

IMPORTANT — honest scope, read before extending this file:
Microsoft's full, numbered DPR document (with individual requirement
IDs) is not a freely published public specification — suppliers receive
it directly through the SSPA enrollment process. This mapper therefore
works at the category level explicitly named in Microsoft's own public
program materials (Access Management, Data Loss Prevention,
Vulnerability Management) rather than inventing specific DPR requirement
numbers it cannot cite. Neither Domits nor Niagaros is currently a
Microsoft supplier under this program — this mapper is genuine product
capability, not a claim that either company is enrolled in SSPA.

Privacy controls, the annual compliance attestation process, and AI
System-specific DPR requirements are organisational/contractual
obligations that cannot be verified from AWS API responses.
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

SSPA_MAPPING = {

    "SSPA.ACCESS": {
        "title": "Access Management",
        "severity": "CRITICAL",
        "section": "Data Protection Requirements — Security Controls",
        "description": (
            "Suppliers shall implement access management controls "
            "restricting access to Microsoft Personal and Confidential "
            "Data to authorized personnel only."
        ),
        "remediation": "Enforce IAM password policy, MFA for console access, and remove unused credentials.",
        "checks": ["IAM.1", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9"],
    },
    "SSPA.DLP": {
        "title": "Data Loss Prevention",
        "severity": "CRITICAL",
        "section": "Data Protection Requirements — Security Controls",
        "description": (
            "Suppliers shall implement data loss prevention controls to "
            "protect Microsoft Personal and Confidential Data from "
            "unauthorized disclosure."
        ),
        "remediation": "Block all public access to S3 buckets and enable default encryption.",
        "checks": ["S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4", "S3.3.5"],
    },
    "SSPA.VULN": {
        "title": "Vulnerability Management",
        "severity": "HIGH",
        "section": "Data Protection Requirements — Security Controls",
        "description": (
            "Suppliers shall maintain a vulnerability management program "
            "to identify and remediate known vulnerabilities."
        ),
        "remediation": "Enable Dependabot vulnerability alerts and secret scanning on all GitHub repositories.",
        "checks": ["github_1.5.1", "github_1.5.5"],
    },
}

MANUAL_EVIDENCE_CONTROLS = [
    ("SSPA.PRIVACY", "Privacy Controls", "Organisational/legal — not AWS-config verifiable"),
    ("SSPA.PROGRAM", "Information Security Program (Policies and Procedures)", "Organisational — not AWS-config verifiable"),
    ("SSPA.AI", "AI System-Specific Data Protection Requirements", "Organisational/contractual — not AWS-config verifiable"),
    ("SSPA.ATTESTATION", "Annual Compliance Attestation and Independent Assessment", "Contractual process — not AWS-config verifiable"),
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
                      AND f.framework != 'Microsoft SSPA'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for Microsoft SSPA mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in SSPA_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("SSPA %s: no matching findings found, skipping", ctrl_id)
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
                            status, result, "Microsoft SSPA", ctrl_def["remediation"],
                            json.dumps({"sspa_control": ctrl_id, "sspa_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("Microsoft SSPA mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
