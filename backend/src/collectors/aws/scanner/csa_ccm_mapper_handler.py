"""
csa_ccm_mapper_handler.py

Maps existing CIS / FSBP findings in the DB to CSA CCM v4.0 (Cloud Security
Alliance — Cloud Controls Matrix) domains.

Same approach as the GDPR / ISO 27001 / BSI C5 mappers — reads existing
findings, maps them to CCM domains, writes them back with
framework = 'CSA CCM 4.0'.

Source: CSA Cloud Controls Matrix v4.0 mapped to AWS via Prowler ccc_aws.json,
translated to our internal check IDs (only checks the platform actually runs:
CloudWatch.*, IAM.*, KMS.*, S3.*).
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
    "cbb94e43-4e42-4fac-997e-8f931131bde7"
)

# ---------------------------------------------------------------------------
# CSA CCM v4.0 → internal check mapping
# Grouped by CCM domain. Only domains that overlap with the services the
# platform scans (IAM, S3, KMS, CloudWatch) are included; the rest of the 17
# CCM domains have no scannable data and are intentionally omitted.
# ---------------------------------------------------------------------------
CCM_MAPPING = {

    "A&A": {
        "title": "Audit & Assurance",
        "severity": "HIGH",
        "description": (
            "An independent audit and assurance program must be maintained, "
            "supported by tamper-evident audit logging and alerting on "
            "security-relevant events across the cloud environment."
        ),
        "remediation": (
            "Enable CloudWatch metric filters and alarms for unauthorised API "
            "calls, root account usage, CloudTrail configuration changes and "
            "failed console authentication so that audit evidence is captured."
        ),
        # Was [CW.2, CW.4, CW.6, CW.7] — CW.4 (IAM policy changes) and CW.7
        # (KMS CMK deletion) aren't in this control's text at all; CW.1 (root
        # usage) and CW.5 (CloudTrail config changes) are explicitly named
        # but were missing.
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.5", "CloudWatch.6",
        ],
    },

    "CEK": {
        "title": "Cryptography, Encryption & Key Management",
        "severity": "HIGH",
        "description": (
            "Cryptographic controls must protect data at rest and in transit. "
            "Customer-managed KMS keys must be tightly scoped and rotated, and "
            "object storage must enforce server-side and in-transit encryption."
        ),
        "remediation": (
            "Restrict KMS key policies so no principal can decrypt with all "
            "keys, enable KMS key rotation, and enforce S3 default encryption "
            "and TLS-only (secure transport) bucket policies."
        ),
        "checks": [
            "KMS.1", "KMS.2", "KMS.5", "KMS.6",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },

    "DSP": {
        "title": "Data Security & Privacy Lifecycle Management",
        "severity": "CRITICAL",
        "description": (
            "Data must be protected throughout its lifecycle. Object storage "
            "must block all public access and enforce encryption so that "
            "personal and sensitive data cannot be exposed."
        ),
        "remediation": (
            "Enable S3 Block Public Access at account and bucket level "
            "(BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
            "RestrictPublicBuckets) and enforce default encryption on all buckets."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },

    "GRC": {
        "title": "Governance, Risk & Compliance",
        "severity": "MEDIUM",
        "description": (
            "A governance, risk and compliance program must enforce baseline "
            "security policies, including a strong password policy, access "
            "analysis and a dedicated support escalation path."
        ),
        "remediation": (
            "Enforce a strong IAM password policy (length and reuse), enable "
            "IAM Access Analyzer, and ensure a dedicated IAM support role exists "
            "so incidents are handled without root credentials."
        ),
        "checks": [
            "IAM.15", "IAM.16", "IAM.18", "IAM.28",
        ],
    },

    "IAM": {
        "title": "Identity & Access Management",
        "severity": "CRITICAL",
        "description": (
            "Identity and access management must enforce least privilege, "
            "strong authentication, credential hygiene and a controlled "
            "escalation path for all human and machine identities."
        ),
        "remediation": (
            "Attach IAM policies to groups rather than users, enable MFA, "
            "enforce password length and reuse policies, remove unused "
            "credentials, rotate expired certificates, and enable IAM Access "
            "Analyzer and a dedicated support role."
        ),
        "checks": [
            "IAM.2", "IAM.9", "IAM.15", "IAM.16",
            "IAM.18", "IAM.22", "IAM.26", "IAM.27", "IAM.28",
        ],
    },

    "LOG": {
        "title": "Logging & Monitoring",
        "severity": "HIGH",
        "description": (
            "Security-relevant events must be logged and monitored. CloudWatch "
            "alarms must detect changes to authentication, IAM policies, "
            "encryption keys, storage policies and network infrastructure."
        ),
        "remediation": (
            "Create CloudWatch metric filters and alarms for the full CIS set: "
            "unauthorised API calls, console sign-in without MFA, root usage, "
            "IAM policy changes, CloudTrail and Config changes, CMK changes, "
            "S3 policy changes and network ACL / gateway / route table changes."
        ),
        # Was missing CloudWatch.1 (root usage) despite the text explicitly
        # naming "root usage" and claiming "the full CIS set".
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4", "CloudWatch.5",
            "CloudWatch.6", "CloudWatch.7", "CloudWatch.8", "CloudWatch.9",
            "CloudWatch.10", "CloudWatch.11", "CloudWatch.12", "CloudWatch.13",
            "CloudWatch.14",
        ],
    },

    "SEF": {
        "title": "Security Incident Management, E-Discovery & Cloud Forensics",
        "severity": "HIGH",
        "description": (
            "Security incidents must be detected and responded to quickly. "
            "Alerting on authentication anomalies and a dedicated support role "
            "are required to enable effective incident response in AWS."
        ),
        "remediation": (
            "Enable CloudWatch alarms for unauthorised API calls, console "
            "sign-in without MFA, root usage and failed authentication, and "
            "ensure a dedicated IAM support role exists for AWS Support escalation."
        ),
        # Was [CW.2, CW.3, CW.4, CW.7] — CW.4 (IAM policy changes) and CW.7
        # (KMS CMK deletion) aren't mentioned in this control's text; CW.1
        # (root usage) and CW.6 (failed authentication) are explicitly named
        # but were missing.
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.6",
            "IAM.18",
        ],
    },

    "TVM": {
        "title": "Threat & Vulnerability Management",
        "severity": "MEDIUM",
        "description": (
            "Threats and configuration drift must be detected continuously. "
            "Alarms on changes to keys, storage policies and network "
            "infrastructure surface potential attack activity."
        ),
        "remediation": (
            "Enable CloudWatch alarms for CMK disable/deletion, S3 bucket policy "
            "changes, AWS Config changes, security group changes and network "
            "ACL changes to detect threats and unauthorised modifications."
        ),
        # Was missing CloudWatch.7 (CMK disable/deletion) despite it being
        # the first thing named in the text; CloudWatch.12 (network gateway
        # changes) isn't mentioned (text says "network ACL changes", CW.11).
        "checks": [
            "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10",
            "CloudWatch.11",
        ],
    },
}

FRAMEWORK = "CSA CCM 4.0"


# ---------------------------------------------------------------------------
# DB helpers  (identical to other mappers)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Core mapper  (identical logic to GDPR / ISO 27001 / BSI C5 mapper)
# ---------------------------------------------------------------------------

def run_mapping(cloud_account_id: str) -> dict:
    conn = _get_connection()
    findings_upserted = 0

    try:
        with conn:
            with conn.cursor() as cur:

                # 1. Read all existing findings for this account (non-CCM)
                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework != %s
                """, (cloud_account_id, FRAMEWORK))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for CSA CCM mapping", len(rows))

                # Build lookup: check_id -> list of findings
                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                # 2. For each CCM domain, determine result per resource
                for domain_id, domain_def in CCM_MAPPING.items():
                    resource_results: dict = {}

                    for check_id in domain_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {
                                "results": [],
                                "resource_name": entry["resource_name"],
                                "resource_type": entry["resource_type"],
                            })
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("CSA CCM %s: no matching findings found, skipping", domain_id)
                        continue

                    # 3. Worst-case: if ANY check FAILS -> domain FAILS
                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        ccm_result = "FAIL" if "FAIL" in results_list else "PASS"
                        ccm_status = "open" if ccm_result == "FAIL" else "pass"

                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")
                        description = (
                            f"{domain_def['description']} "
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
                            domain_id,
                            domain_def["title"],
                            description,
                            domain_def["severity"],
                            ccm_status,
                            ccm_result,
                            FRAMEWORK,
                            domain_def["remediation"],
                            json.dumps({
                                "ccm_domain":    domain_id,
                                "mapped_checks": domain_def["checks"],
                                "passed":        passed,
                                "failed":        failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "CSA CCM %s / resource %s -> %s (%d/%d passing)",
                            domain_id, resource_id, ccm_result, passed, len(results_list)
                        )

        logger.info("CSA CCM mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("CSA CCM mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("CSA CCM mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
