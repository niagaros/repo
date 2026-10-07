"""
c5_mapper_handler.py

Maps existing CIS findings in the DB to BSI C5 (Cloud Computing Compliance
Criteria Catalogue) sections.

Same approach as GDPR / ISO 27001 mapper — reads existing findings, maps to
C5 sections, writes back with framework = 'BSI-C5'.

Source: BSI C5:2020 mapped to AWS via Prowler c5_aws.json
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
# BSI C5 → CIS check mapping
# Grouped by C5 section; checks derived from c5_aws.json Prowler mappings
# translated to our internal check IDs.
# ---------------------------------------------------------------------------
C5_MAPPING = {

    "OIS": {
        "title": "Organisation of Information Security",
        "severity": "HIGH",
        "description": (
            "The cloud service provider maintains an information security management "
            "system (ISMS) and enforces security policies across all relevant "
            "organisational units. Network-level monitoring and key management "
            "controls must be in place."
        ),
        "remediation": (
            "Enable CloudWatch alarms for changes to network ACLs, gateways and VPCs. "
            "Enable KMS CMK automatic rotation for all customer-managed keys. "
            "Ensure a dedicated IAM support role exists for incident management."
        ),
        # Was KMS.4 ("key not disabled", not mentioned) instead of KMS.1
        # ("automatic rotation"); IAM.8 (unused credentials) instead of
        # IAM.18 (the actual "dedicated support role" check).
        "checks": [
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.14",
            "IAM.18",
            "KMS.1",
        ],
    },

    "HR": {
        "title": "Personnel",
        "severity": "MEDIUM",
        "description": (
            "Personnel security controls ensure that employees and contractors "
            "handle cloud resources responsibly. Network-change monitoring and "
            "privileged-access controls support personnel accountability."
        ),
        "remediation": (
            "Enable CloudWatch alarms for network ACL, gateway and VPC changes "
            "to detect unauthorised modifications by personnel. "
            "Ensure a dedicated IAM support role is available for escalation."
        ),
        # IAM.8 (unused credentials) was standing in for "a dedicated IAM
        # support role" — that's IAM.18.
        "checks": [
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.14",
            "IAM.18",
        ],
    },

    "AM": {
        "title": "Asset Management",
        "severity": "MEDIUM",
        "description": (
            "All cloud assets must be inventoried and changes to network "
            "infrastructure must be monitored to maintain an accurate and "
            "up-to-date asset register."
        ),
        "remediation": (
            "Enable CloudWatch alarms for network ACL changes, gateway changes "
            "and VPC modifications so that all infrastructure changes are "
            "detected and recorded."
        ),
        "checks": [
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.14",
        ],
    },

    "PS": {
        "title": "Physical Security",
        "severity": "MEDIUM",
        "description": (
            "Data stored in the cloud must be protected against unauthorised "
            "physical or logical access. S3 bucket access controls are a "
            "key compensating control for data-at-rest protection."
        ),
        "remediation": (
            "Block all public S3 access at account and bucket level. "
            "Enable S3 Block Public Access for all four settings: "
            "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
        ],
    },

    "OPS": {
        "title": "Operations",
        "severity": "HIGH",
        "description": (
            "Operational security requires continuous monitoring of privileged "
            "actions, authentication events and infrastructure changes. "
            "Secure access key management and MFA enforcement are mandatory."
        ),
        "remediation": (
            "Enable CloudWatch alarms for network changes, VPC changes and gateway changes. "
            "Enable MFA for root account and all IAM console users. "
            "Remove unused IAM access keys older than 90 days. "
            "Enable S3 default encryption. "
            "Ensure a dedicated IAM support role exists."
        ),
        # Was IAM.1/IAM.2 (admin policies/policy attachment, not mentioned)
        # instead of IAM.5 (console MFA, explicitly named alongside root
        # MFA); S3.3.1 (public ACL) instead of S3.3.5 ("S3 default
        # encryption"); missing IAM.18 ("a dedicated IAM support role").
        "checks": [
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.14",
            "IAM.5", "IAM.6", "IAM.8", "IAM.18",
            "S3.3.5",
        ],
    },

    "IAM": {
        "title": "Identity and Access Management",
        "severity": "CRITICAL",
        "description": (
            "Identity and access management controls govern who can access "
            "cloud resources and how. Strong authentication, least-privilege "
            "policies, key rotation and secure storage access are all required."
        ),
        "remediation": (
            "Enable MFA for root and all IAM console users. "
            "Remove root access keys. "
            "Remove unused IAM access keys (>90 days). "
            "Rotate active access keys every 90 days. "
            "Enforce strong IAM password policy (min. 14 chars, no reuse). "
            "Ensure a dedicated IAM support role exists. "
            "Block public S3 access and enable bucket encryption."
        ),
        # Was also listing IAM.1/IAM.2 (admin policies/attachment, not
        # mentioned) and S3.3.1 (public ACL) instead of S3.3.5 ("enable
        # bucket encryption"); missing IAM.3 ("rotate active access keys
        # every 90 days") and IAM.18 ("a dedicated IAM support role"),
        # both explicitly named. IAM.5 (console MFA) was also missing.
        "checks": [
            "IAM.3", "IAM.4", "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9", "IAM.18",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.5",
        ],
    },

    "CRY": {
        "title": "Cryptography and Key Management",
        "severity": "HIGH",
        "description": (
            "Cryptographic controls protect data at rest and in transit. "
            "Customer-managed KMS keys must be rotated automatically, "
            "and S3 buckets must enforce server-side encryption."
        ),
        "remediation": (
            "Enable automatic rotation for all KMS customer-managed keys. "
            "Enable S3 default server-side encryption on all buckets. "
            "Remove root access keys and rotate IAM access keys every 90 days."
        ),
        # Was KMS.4 ("key not disabled") instead of KMS.1 ("automatic
        # rotation"); IAM.6/IAM.7 (root hardware MFA / password policy)
        # aren't mentioned — this text needs IAM.3 ("rotate IAM access keys
        # every 90 days"), which was missing. S3.3.1 (public ACL) isn't
        # mentioned either.
        "checks": [
            "IAM.3", "IAM.4",
            "KMS.1",
            "S3.3.5",
        ],
    },

    "COS": {
        "title": "Communication Security",
        "severity": "HIGH",
        "description": (
            "Communication security requires that data transmitted over networks "
            "is protected and that network infrastructure changes are monitored. "
            "S3 public access must be blocked to prevent data exposure."
        ),
        "remediation": (
            "Block all public S3 access (BlockPublicAcls, IgnorePublicAcls, "
            "BlockPublicPolicy, RestrictPublicBuckets). "
            "Enable CloudWatch alarms for gateway and VPC changes."
        ),
        "checks": [
            "CloudWatch.12", "CloudWatch.14",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
        ],
    },

    "DEV": {
        "title": "Procurement, Development and Modification of Information Systems",
        "severity": "MEDIUM",
        "description": (
            "Security must be integrated into system development and procurement "
            "processes. A dedicated IAM support role ensures secure escalation "
            "paths during system changes."
        ),
        "remediation": (
            "Ensure a dedicated IAM support role exists that allows authorised "
            "personnel to manage incidents without using root credentials."
        ),
        # IAM.8 (unused credentials) doesn't test whether a support role
        # exists — that's IAM.18.
        "checks": [
            "IAM.18",
        ],
    },

    "SSO": {
        "title": "Control and Monitoring of Service Providers and Suppliers",
        "severity": "MEDIUM",
        "description": (
            "Third-party and supplier access to cloud resources must be "
            "controlled and monitored. A dedicated IAM support role provides "
            "a controlled escalation path for supplier interactions."
        ),
        "remediation": (
            "Ensure a dedicated IAM support role exists and that supplier "
            "access is granted only through scoped IAM roles, not root or "
            "shared credentials."
        ),
        "checks": [
            "IAM.18",  # IAM.8 (unused credentials) didn't test for a support role
        ],
    },

    "SIM": {
        "title": "Security Incident Management",
        "severity": "HIGH",
        "description": (
            "Security incident management requires defined escalation paths "
            "and rapid response capabilities. A dedicated IAM support role "
            "is required to enable effective incident response in AWS."
        ),
        "remediation": (
            "Create a dedicated IAM support role (e.g. AWSSupportAccess policy) "
            "to ensure authorised personnel can engage AWS Support during incidents "
            "without using root credentials."
        ),
        "checks": [
            "IAM.18",  # IAM.8 (unused credentials) didn't test for a support role
        ],
    },

    "PSS": {
        "title": "Product Safety and Security",
        "severity": "HIGH",
        "description": (
            "Product safety and security controls ensure that cloud services "
            "are protected against unauthorised access and misuse. MFA, "
            "access key hygiene, network monitoring and encryption are key controls."
        ),
        "remediation": (
            "Enable MFA for root and all IAM console users. "
            "Remove unused IAM access keys and enforce password policies. "
            "Enable CloudWatch alarms for network ACL, gateway and VPC changes. "
            "Enable S3 default encryption on all buckets."
        ),
        # Was IAM.1/IAM.2 (admin policies/attachment, not mentioned) instead
        # of IAM.5 (console MFA, explicit alongside root MFA); missing IAM.7
        # (password policies) and IAM.8 (unused access keys), both explicit;
        # S3.3.1 (public ACL) instead of S3.3.5 ("S3 default encryption").
        "checks": [
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.14",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
            "S3.3.5",
        ],
    },
}


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
# Core mapper  (identical logic to GDPR / ISO 27001 mapper)
# ---------------------------------------------------------------------------

def run_mapping(cloud_account_id: str) -> dict:
    conn = _get_connection()
    findings_upserted = 0

    try:
        with conn:
            with conn.cursor() as cur:

                # 1. Read all existing findings for this account (non-C5)
                cur.execute("""
                    SELECT f.check_id, f.result, f.resource_id, r.resource_name, r.resource_type
                    FROM findings f
                    JOIN resources r ON r.id = f.resource_id
                    WHERE r.cloud_account_id = %s
                      AND f.framework != 'BSI-C5'
                """, (cloud_account_id,))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for BSI-C5 mapping", len(rows))

                # Build lookup: check_id -> list of findings
                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                # 2. For each C5 section, determine result per resource
                for section_id, section_def in C5_MAPPING.items():
                    resource_results: dict = {}

                    for check_id in section_def["checks"]:
                        for entry in by_check.get(check_id, []):
                            rid = entry["resource_id"]
                            resource_results.setdefault(rid, {
                                "results": [],
                                "resource_name": entry["resource_name"],
                                "resource_type": entry["resource_type"],
                            })
                            resource_results[rid]["results"].append(entry["result"])

                    if not resource_results:
                        logger.info("BSI-C5 %s: no matching findings found, skipping", section_id)
                        continue

                    # 3. Worst-case: if ANY check FAILS → section FAILS
                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        c5_result = "FAIL" if "FAIL" in results_list else "PASS"
                        c5_status = "open" if c5_result == "FAIL" else "pass"

                        passed = results_list.count("PASS")
                        failed = results_list.count("FAIL")
                        description = (
                            f"{section_def['description']} "
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
                            section_id,
                            section_def["title"],
                            description,
                            section_def["severity"],
                            c5_status,
                            c5_result,
                            "BSI-C5",
                            section_def["remediation"],
                            json.dumps({
                                "c5_section":    section_id,
                                "mapped_checks": section_def["checks"],
                                "passed":        passed,
                                "failed":        failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "BSI-C5 %s / resource %s → %s (%d/%d passing)",
                            section_id, resource_id, c5_result, passed, len(results_list)
                        )

        logger.info("BSI-C5 mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("BSI-C5 mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("BSI-C5 mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }