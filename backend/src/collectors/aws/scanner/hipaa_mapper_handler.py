"""
hipaa_mapper_handler.py

Maps existing CIS findings in the DB to HIPAA (45 CFR Part 164) requirements.
Covers 164.308 Administrative Safeguards and 164.312 Technical Safeguards.
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
# HIPAA (45 CFR Part 164) -> CIS check mapping
# ---------------------------------------------------------------------------
HIPAA_MAPPING = {

    # ── 164.308 Administrative Safeguards ─────────────────────────────────────

    "HIPAA-308.a.1.ii.b": {
        "title": "Risk Management",
        "severity": "HIGH",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement security measures sufficient to reduce risks and vulnerabilities "
            "to a reasonable and appropriate level. Protect the confidentiality, integrity, "
            "and availability of all ePHI the entity creates, receives, maintains, or transmits."
        ),
        "remediation": (
            "Remove root access keys. Block public access to all S3 buckets. "
            "Enable S3 server-side encryption. Enable KMS key rotation. "
            "Attach IAM policies to groups or roles only, not individual users."
        ),
        # Was IAM.7 (password policy, not mentioned) instead of IAM.2
        # ("Attach IAM policies to groups or roles only").
        "checks": ["IAM.2", "IAM.4", "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4", "S3.3.5", "KMS.1"],
    },

    "HIPAA-308.a.1.ii.d": {
        "title": "Information System Activity Review",
        "severity": "HIGH",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement procedures to regularly review records of information system activity, "
            "such as audit logs, access reports, and security incident tracking reports. "
            "CloudWatch metric filters and alarms shall cover all required security events."
        ),
        "remediation": (
            "Enable CloudWatch metric filters and alarms for root account usage, "
            "IAM policy changes, CloudTrail configuration changes, S3 policy changes, "
            "KMS CMK deletion, and authentication failures. "
            "Ensure all metric filters have active SNS subscriptions."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
        ],
    },

    "HIPAA-308.a.3.ii.a": {
        "title": "Authorization and Supervision",
        "severity": "HIGH",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement procedures for the authorization and/or supervision of workforce "
            "members who work with ePHI or in locations where it might be accessed. "
            "Multi-factor authentication shall be required for root and all console users."
        ),
        "remediation": (
            "Enable hardware MFA for root account. "
            "Enable virtual or hardware MFA for all IAM users with console access. "
            "Enable CloudWatch alarm for sign-in without MFA."
        ),
        # Was [IAM.3, IAM.4] (key rotation / root key existence) — this
        # control is entirely about MFA and never actually tested it.
        "checks": ["IAM.5", "IAM.6", "CloudWatch.3"],
    },

    "HIPAA-308.a.3.ii.b": {
        "title": "Workforce Clearance Procedure",
        "severity": "MEDIUM",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement procedures to determine that the access of a workforce member to ePHI "
            "is appropriate. Remove or restrict access for users who no longer require it. "
            "Apply least privilege across all IAM users and roles."
        ),
        "remediation": (
            "Remove root access keys. Attach IAM policies to groups or roles only. "
            "Remove unused IAM users and access keys. "
            "Disable IAM users with no console activity in 90 or more days."
        ),
        # Was also listing IAM.7 (password policy) and IAM.9 (root MFA) —
        # neither is mentioned; IAM.2 ("groups or roles only") was missing.
        "checks": ["IAM.2", "IAM.4", "IAM.8"],
    },

    "HIPAA-308.a.3.ii.c": {
        "title": "Termination Procedures",
        "severity": "MEDIUM",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement procedures for terminating access to ePHI when a workforce member's "
            "employment or arrangement ends. Rotate and revoke IAM access keys for "
            "departing personnel promptly."
        ),
        "remediation": (
            "Rotate IAM access keys every 90 days. "
            "Disable or delete access keys that have not been used in more than 90 days. "
            "Remove console access for inactive users immediately upon departure."
        ),
        # Was [IAM.2, IAM.6] (policy attachment / root hardware MFA) — this
        # text is entirely about key rotation and terminating unused access,
        # i.e. IAM.3 and IAM.8.
        "checks": ["IAM.3", "IAM.8"],
    },

    "HIPAA-308.a.4.i": {
        "title": "Information Access Management",
        "severity": "HIGH",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement policies and procedures for authorizing access to ePHI consistent "
            "with applicable requirements. Access shall be granted only based on documented "
            "business need and role assignment using least privilege."
        ),
        "remediation": (
            "Attach IAM policies only to groups or roles, not individual users. "
            "Remove inline policies with administrative privileges. "
            "Apply least privilege across all IAM assignments."
        ),
        # Was [IAM.5, IAM.7] (MFA / password policy) — text is "groups or
        # roles only" (IAM.2) and "remove inline admin-privilege policies"
        # (IAM.1).
        "checks": ["IAM.1", "IAM.2"],
    },

    "HIPAA-308.a.4.ii.b": {
        "title": "Access Authorization",
        "severity": "HIGH",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement policies and procedures for granting access to ePHI through access "
            "to a workstation, transaction, program, process, or other mechanism. "
            "IAM policies shall not grant unrestricted administrative access."
        ),
        "remediation": (
            "Remove IAM policies that grant administrative privileges to individual users. "
            "Attach policies only to groups or roles. "
            "Remove unused IAM users with console or programmatic access."
        ),
        # Was [IAM.7, IAM.9] (password policy / root MFA) — unrelated. Text
        # is "remove admin-privilege policies" (IAM.1), "groups/roles only"
        # (IAM.2), "remove unused users" (IAM.8).
        "checks": ["IAM.1", "IAM.2", "IAM.8"],
    },

    "HIPAA-308.a.4.ii.c": {
        "title": "Establishment and Modification of Access Rights",
        "severity": "HIGH",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement policies and procedures that establish, document, review, and modify "
            "a user's right of access to a workstation, transaction, program, or process. "
            "Credentials shall be rotated regularly and unused access deactivated promptly."
        ),
        "remediation": (
            "Configure IAM password policy to expire within 90 days with complexity requirements. "
            "Rotate access keys every 90 days. Remove root access keys. "
            "Disable unused access keys and console passwords."
        ),
        # Was missing IAM.3 (key rotation) and IAM.7 (password policy)
        # despite both being explicitly named; IAM.1/IAM.2/IAM.6/IAM.9
        # (admin policies/attachment/root MFA) aren't mentioned in this text.
        "checks": ["IAM.3", "IAM.4", "IAM.7", "IAM.8"],
    },

    "HIPAA-308.a.5.ii.c": {
        "title": "Log-in Monitoring",
        "severity": "HIGH",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement procedures for monitoring log-in attempts and reporting discrepancies. "
            "CloudWatch metric filters shall capture root account usage and authentication "
            "failures and trigger automated alarms for immediate response."
        ),
        "remediation": (
            "Enable CloudWatch metric filter and alarm for root account usage. "
            "Enable metric filter and alarm for authentication failures and sign-in without MFA. "
            "Ensure all SNS subscriptions are active."
        ),
        # Added CloudWatch.6 — text explicitly names "authentication
        # failures" (CW.6's real title), separate from "sign-in without MFA"
        # (CW.3), which was already correct.
        "checks": ["CloudWatch.1", "CloudWatch.3", "CloudWatch.6"],
    },

    "HIPAA-308.a.5.ii.d": {
        "title": "Password Management",
        "severity": "MEDIUM",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement procedures for creating, changing, and safeguarding passwords. "
            "IAM password policy shall enforce minimum length, complexity, expiry, "
            "and reuse prevention for all workforce members."
        ),
        "remediation": (
            "Configure IAM password policy: minimum 14 characters, uppercase, lowercase, "
            "numbers, symbols, expire in 90 days, prevent reuse of last 24 passwords. "
            "Rotate access keys every 90 days. Disable unused credentials."
        ),
        # Was [IAM.1, IAM.2, IAM.6, IAM.9] (admin policies/attachment/root
        # MFA — none mentioned here). Text needs the password policy (IAM.7,
        # missing) and key rotation (IAM.3, missing); IAM.8 was already
        # correct.
        "checks": ["IAM.3", "IAM.7", "IAM.8"],
    },

    "HIPAA-308.a.6.i": {
        "title": "Security Incident Procedures",
        "severity": "HIGH",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Implement policies and procedures to address security incidents. "
            "CloudWatch alarms shall be configured to detect unauthorized access, "
            "network configuration changes, and root account activity."
        ),
        "remediation": (
            "Enable CloudWatch metric filters and alarms for root account usage, "
            "authentication failures, network ACL changes, network gateway changes, "
            "route table changes, and VPC changes. Ensure SNS notifications are active."
        ),
        # Was CloudWatch.3 (sign-in without MFA) — text names "authentication
        # failures" specifically, which is CloudWatch.6.
        "checks": [
            "CloudWatch.1", "CloudWatch.6",
            "CloudWatch.11", "CloudWatch.12", "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "HIPAA-308.a.6.ii": {
        "title": "Response and Reporting",
        "severity": "HIGH",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Identify and respond to suspected or known security incidents; mitigate harmful "
            "effects and document security incidents and their outcomes. Comprehensive "
            "CloudWatch monitoring shall be in place for all security-relevant events."
        ),
        "remediation": (
            "Enable all CloudWatch metric filters and alarms for security events. "
            "Ensure CloudTrail is delivering logs to CloudWatch Logs. "
            "Configure SNS subscriptions for all alarms. "
            "Review and act on all triggered alarms promptly."
        ),
        # Was only 8 of 14 despite claiming "all CloudWatch metric filters
        # and alarms for security events" — contrast with HIPAA-312.b below,
        # which correctly lists the full CloudWatch.1-14 set for the same
        # kind of "all events" claim.
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "HIPAA-308.a.7.ii.a": {
        "title": "Data Backup Plan",
        "severity": "HIGH",
        "section": "164.308 — Administrative Safeguards",
        "description": (
            "Establish and implement procedures to create and maintain retrievable exact "
            "copies of ePHI. S3 versioning, encryption, and public access blocking shall "
            "protect ePHI backup copies from unauthorized access or loss."
        ),
        "remediation": (
            "Enable S3 versioning on all buckets containing ePHI. "
            "Block all public access to S3 buckets at account and bucket level. "
            "Enable S3 server-side encryption with KMS. "
            "Enable KMS key rotation for all encryption keys."
        ),
        # Was missing S3.3.3 (versioning) and KMS.1 (key rotation) despite
        # both being explicitly named ("Enable S3 versioning...", "Enable
        # KMS key rotation...").
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.3", "S3.3.5", "KMS.1",
        ],
    },

    # ── 164.312 Technical Safeguards ──────────────────────────────────────────

    "HIPAA-312.a.1": {
        "title": "Access Control",
        "severity": "CRITICAL",
        "section": "164.312 — Technical Safeguards",
        "description": (
            "Implement technical policies and procedures for electronic information systems "
            "that maintain ePHI to allow access only to authorized persons or software "
            "programs. S3 buckets shall not be publicly accessible."
        ),
        "remediation": (
            "Block all public access to S3 buckets at account level. "
            "Enable MFA for all IAM users with console access. "
            "Remove root access keys. "
            "Attach IAM policies only to groups or roles."
        ),
        # Was IAM.3 (key rotation, not mentioned) and IAM.7 (password
        # policy, not mentioned) instead of IAM.5 (console MFA) and IAM.2
        # (groups/roles only), both explicitly named.
        "checks": [
            "IAM.2", "IAM.4", "IAM.5",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
        ],
    },

    "HIPAA-312.a.2.i": {
        "title": "Unique User Identification",
        "severity": "HIGH",
        "section": "164.312 — Technical Safeguards",
        "description": (
            "Assign a unique name and/or number for identifying and tracking user identity. "
            "Shared credentials and root account usage shall be prohibited. "
            "Each IAM user shall have an individual, uniquely identified account."
        ),
        "remediation": (
            "Remove root access keys. "
            "Ensure each user has a unique IAM account. "
            "Disable unused IAM users and access keys. "
            "Assign access keys only to individual users, not shared roles."
        ),
        "checks": ["IAM.4", "IAM.5", "IAM.8", "IAM.9"],
    },

    "HIPAA-312.a.2.iv": {
        "title": "Encryption and Decryption",
        "severity": "CRITICAL",
        "section": "164.312 — Technical Safeguards",
        "description": (
            "Implement a mechanism to encrypt and decrypt ePHI. KMS customer-managed "
            "keys shall be used for encryption at rest. S3 buckets storing ePHI shall "
            "have server-side encryption enabled with automatic key rotation."
        ),
        "remediation": (
            "Enable KMS key rotation for all customer-managed keys. "
            "Apply SSE-KMS to all S3 buckets containing ePHI. "
            "Ensure KMS keys are not publicly accessible or scheduled for deletion. "
            "Block public access to all S3 buckets."
        ),
        # Was KMS.4 ("key not disabled", not mentioned) instead of KMS.5
        # ("scheduled for deletion", explicitly named); also missing S3.2.x
        # ("Block public access to all S3 buckets", explicit).
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.5",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },

    "HIPAA-312.b": {
        "title": "Audit Controls",
        "severity": "HIGH",
        "section": "164.312 — Technical Safeguards",
        "description": (
            "Implement hardware, software, and/or procedural mechanisms that record and "
            "examine activity in information systems that contain or use ePHI. "
            "All CloudWatch metric filters shall be active with log group retention configured."
        ),
        "remediation": (
            "Enable all 14 CloudWatch metric filters and alarms. "
            "Ensure CloudTrail is delivering logs to CloudWatch Logs. "
            "Configure log group retention of at least 365 days. "
            "Enable SNS notifications for all security alarms."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "HIPAA-312.c.1": {
        "title": "Integrity",
        "severity": "HIGH",
        "section": "164.312 — Technical Safeguards",
        "description": (
            "Implement policies and procedures to protect ePHI from improper alteration "
            "or destruction. S3 versioning, encryption, and secure transport policy "
            "shall ensure ePHI integrity throughout its lifecycle."
        ),
        "remediation": (
            "Enable S3 versioning on all buckets containing ePHI. "
            "Enable server-side encryption with KMS. "
            "Enforce HTTPS-only access with S3 bucket policies. "
            "Enable KMS key rotation to protect encryption keys."
        ),
        # Was S3.3.1 (public ACL, not mentioned) instead of S3.3.3
        # (versioning — "Enable S3 versioning..." is explicit).
        "checks": [
            "S3.3.2", "S3.3.3", "S3.3.5",
            "KMS.1", "KMS.2",
        ],
    },

    "HIPAA-312.d": {
        "title": "Person or Entity Authentication",
        "severity": "CRITICAL",
        "section": "164.312 — Technical Safeguards",
        "description": (
            "Implement procedures to verify that a person or entity seeking access to ePHI "
            "is the one claimed. MFA shall be required for root and all console users. "
            "Password policy shall enforce complexity and expiry."
        ),
        "remediation": (
            "Enable hardware MFA for root account. "
            "Enable MFA for all IAM users with console access. "
            "Configure IAM password policy with expiry, complexity, and reuse prevention."
        ),
        # Was [IAM.1, IAM.3, IAM.4] (admin policies/key rotation/root keys —
        # none of that is in this text). Entirely about MFA (hardware MFA
        # for root = IAM.6, console MFA = IAM.5) and password policy = IAM.7.
        "checks": ["IAM.5", "IAM.6", "IAM.7"],
    },

    "HIPAA-312.e.1": {
        "title": "Transmission Security",
        "severity": "HIGH",
        "section": "164.312 — Technical Safeguards",
        "description": (
            "Implement technical security measures to guard against unauthorized access "
            "to ePHI being transmitted over an electronic communications network. "
            "S3 buckets shall enforce secure transport and block all public access."
        ),
        "remediation": (
            "Apply S3 bucket policies that deny non-HTTPS requests. "
            "Enable server-side encryption for all S3 buckets containing ePHI. "
            "Block public access at account and bucket level."
        ),
        # S3.2.1/S3.2.2 are block-public-access settings, not "deny
        # non-HTTPS requests" — that's S3.3.2, which was missing entirely.
        # Completed the block-public-access set (S3.2.3/S3.2.4) to match
        # "at account and bucket level".
        "checks": ["S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4", "S3.3.2", "S3.3.5"],
    },

    "HIPAA-312.e.2.ii": {
        "title": "Encryption",
        "severity": "CRITICAL",
        "section": "164.312 — Technical Safeguards",
        "description": (
            "Implement a mechanism to encrypt ePHI whenever deemed appropriate. "
            "KMS CMKs with automatic rotation shall encrypt all ePHI at rest. "
            "S3 secure transport policy enforces encryption in transit."
        ),
        "remediation": (
            "Enable automatic rotation for all KMS customer-managed keys. "
            "Apply SSE-KMS to S3 buckets containing ePHI. "
            "Block public access to all S3 buckets. "
            "Enforce HTTPS transport with bucket policies."
        ),
        # Was also listing KMS.3/KMS.4 (key-policy wildcard action / key not
        # disabled — neither mentioned here); missing S3.2.x ("Block public
        # access to all S3 buckets", explicit).
        "checks": [
            "KMS.1", "KMS.2",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },
}


# ---------------------------------------------------------------------------
# DB helpers
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
# Core mapper
# ---------------------------------------------------------------------------

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
                      AND f.framework != 'HIPAA'
                """, (cloud_account_id,))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for HIPAA mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in HIPAA_MAPPING.items():
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
                        logger.info("HIPAA %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        hipaa_result = "FAIL" if "FAIL" in results_list else "PASS"
                        hipaa_status = "open" if hipaa_result == "FAIL" else "pass"

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
                            hipaa_status,
                            hipaa_result,
                            "HIPAA",
                            ctrl_def["remediation"],
                            json.dumps({
                                "hipaa_control":  ctrl_id,
                                "hipaa_section":  ctrl_def["section"],
                                "mapped_checks":  ctrl_def["checks"],
                                "passed":         passed,
                                "failed":         failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "HIPAA %s / resource %s -> %s (%d/%d passing)",
                            ctrl_id, resource_id, hipaa_result, passed, len(results_list)
                        )

        logger.info("HIPAA mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("HIPAA mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("HIPAA mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
