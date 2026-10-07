"""
aws_ftr_mapper_handler.py

Maps existing CIS/FSBP findings in the DB to the security-relevant portion
of the AWS Foundational Technical Review (FTR) checklist.

The AWS FTR is AWS Partner Central's structured review of a partner
solution's architecture against a subset of the AWS Well-Architected
Framework (source: docs.aws.amazon.com/partner-central, and the nOps/Jit
FTR guides). Its published requirement areas relevant to security are:
  - IAM: no root-account use for daily ops, least privilege, MFA on all
    privileged accounts including root
  - Encryption at rest for data stores, TLS 1.2+ in transit
  - Network security: private subnets, least-access security groups
  - Logging: CloudTrail enabled in all regions, delivered to a
    dedicated access-controlled bucket
  - Reliability: automated backups with defined RTO/RPO, multi-AZ for
    critical workloads

IMPORTANT — honest scope:
FTR also covers Operational Excellence (IaC, CI/CD), Cost Optimization,
and Performance Efficiency — those are not security controls and are out
of scope for a security-posture scanner entirely, not "missing" from it.
Of the security-relevant items, this scanner has NO check for network
security (VPC/security-group/subnet configuration) — that would need an
EC2/VPC collector this codebase does not implement yet, so it is listed
as manual-evidence-required rather than faked. The remaining four areas
(IAM/least-privilege, encryption, logging, backup/DR) all have genuine,
existing technical checks and are mapped below.
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
# AWS FTR (security-relevant requirement areas) → CIS/FSBP check mapping
# ---------------------------------------------------------------------------
AWS_FTR_MAPPING = {

    "FTR.IAM": {
        "title": "Identity & Access Management",
        "severity": "HIGH",
        "section": "FTR Security — IAM & Authentication",
        "description": (
            "No root account usage for daily operations; individual IAM "
            "users or roles for all access; least-privilege policies "
            "enforced; MFA required for all privileged accounts, "
            "including the root account."
        ),
        "remediation": (
            "Remove root access keys. Enable MFA for root and all IAM "
            "console users. Attach policies to groups/roles only, not "
            "individual users. Rotate access keys every 90 days. Remove "
            "unused IAM credentials."
        ),
        "checks": ["IAM.1", "IAM.2", "IAM.3", "IAM.4", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9"],
    },
    "FTR.ENCRYPTION": {
        "title": "Data Encryption",
        "severity": "CRITICAL",
        "section": "FTR Security — Data Protection",
        "description": (
            "Server-side encryption should be enabled for data at rest, "
            "and TLS enforced for data in transit."
        ),
        "remediation": (
            "Enable S3 default encryption on all buckets. Enable KMS key "
            "rotation. Enforce HTTPS-only bucket policies."
        ),
        "checks": ["S3.3.5", "S3.3.2", "KMS.1", "KMS.2", "KMS.3", "KMS.4"],
    },
    "FTR.LOGGING": {
        "title": "Logging & Audit",
        "severity": "HIGH",
        "section": "FTR Security — Logging & Monitoring",
        "description": (
            "AWS CloudTrail should be enabled across all regions, with "
            "logs delivered to a dedicated, access-controlled bucket, and "
            "active monitoring/alerting on key security events."
        ),
        "remediation": (
            "Enable multi-region CloudTrail with log file validation. "
            "Configure CloudWatch metric filters and alarms for all "
            "CIS-required security events, with a confirmed SNS "
            "subscription."
        ),
        "checks": ["CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14"],
    },
    "FTR.BACKUP": {
        "title": "Backup, RTO/RPO & Multi-AZ Reliability",
        "severity": "HIGH",
        "section": "FTR Reliability",
        "description": (
            "Automated backups should exist with defined Recovery Time "
            "Objectives (RTO) and Recovery Point Objectives (RPO), with "
            "multi-AZ deployment for critical workloads."
        ),
        "remediation": (
            "Enable automated backups with an adequate retention window. "
            "Enable point-in-time recovery / continuous backups where "
            "supported. Verify restore procedures are tested, not just "
            "configured."
        ),
        "checks": ["RDS.DR.1", "RDS.DR.2", "RDS.DR.3", "RDS.DR.4", "DynamoDB.DR.1", "DynamoDB.DR.2", "DynamoDB.DR.3"],
    },
}

# Security-relevant FTR areas this scanner cannot yet verify, plus the
# non-security FTR pillars (Operational Excellence, Cost Optimization,
# Performance Efficiency) that are out of scope for a security scanner
# by definition, not merely unimplemented.
MANUAL_EVIDENCE_CONTROLS = [
    ("FTR.NETWORK", "Network Security (VPC private subnets, least-access security groups)", "FTR Security — requires VPC/security-group checks not yet implemented"),
    ("FTR.INCIDENT", "Documented Incident Response Procedures", "FTR Reliability — organisational process, not AWS-config verifiable"),
    ("FTR.OPEX", "Infrastructure as Code, CI/CD Pipelines", "FTR Operational Excellence — not a security control, out of scope for this scanner"),
    ("FTR.COST", "Cost Optimization (right-sizing, budgets, auto-scaling)", "FTR Cost Optimization / Performance Efficiency — not a security control, out of scope for this scanner"),
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
                      AND f.framework != 'AWS FTR'
                """, (cloud_account_id,))
                rows = cur.fetchall()
                logger.info("Read %d existing findings for AWS FTR mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id": resource_id, "result": result,
                        "resource_name": resource_name, "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in AWS_FTR_MAPPING.items():
                    resource_results: dict = {}
                    for check_id in ctrl_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {"results": [], "resource_name": entry["resource_name"], "resource_type": entry["resource_type"]})
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("AWS FTR %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        ftr_result = "FAIL" if "FAIL" in results_list else "PASS"
                        ftr_status = "open" if ftr_result == "FAIL" else "pass"
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
                            ftr_status, ftr_result, "AWS FTR", ctrl_def["remediation"],
                            json.dumps({"ftr_control": ctrl_id, "ftr_section": ctrl_def["section"], "mapped_checks": ctrl_def["checks"], "passed": passed, "failed": failed}),
                        ))
                        findings_upserted += 1

        logger.info("AWS FTR mapping complete: %d findings upserted", findings_upserted)
    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    result = run_mapping(account_id)
    return {"statusCode": 200, "body": json.dumps(result)}
