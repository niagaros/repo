"""
nis2_mapper_handler.py

Maps existing CIS findings in the DB to NIS2 (Directive (EU) 2022/2555) requirements.

Same approach as ISO 27001 mapper — reads existing findings, maps to NIS2
controls, writes back with framework = 'NIS2'.
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
# NIS2 (Directive (EU) 2022/2555) -> CIS check mapping
# ---------------------------------------------------------------------------
NIS2_MAPPING = {

    # ── Article 21(2)(a) — Policy on Security of NIS ──────────────────────

    "NIS2-1.1.1": {
        "title": "Security Policy for Network and Information Systems",
        "severity": "HIGH",
        "section": "Art. 21(2)(a) — Policy",
        "description": (
            "Relevant entities shall set out their approach to managing the security "
            "of their network and information systems, including objectives, commitments "
            "to continual improvement, and documentation retention requirements."
        ),
        "remediation": (
            "Enforce IAM password policy with expiry within 90 days. "
            "Rotate access keys every 90 days. "
            "Remove unused credentials. Enforce MFA for all console users."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.6",
        ],
    },

    "NIS2-1.2.1": {
        "title": "Roles and Responsibilities for NIS Security",
        "severity": "HIGH",
        "section": "Art. 21(2)(a) — Policy",
        "description": (
            "Relevant entities shall lay down responsibilities and authorities for "
            "network and information system security and assign them to roles. "
            "IAM policies shall be attached only to groups or roles, not users directly."
        ),
        "remediation": (
            "Attach IAM policies only to groups or roles. "
            "Remove administrative policies from individual IAM users. "
            "Review and restrict IAM roles with AdministratorAccess. "
            "Enforce least privilege across all IAM assignments."
        ),
        "checks": [
            "IAM.5", "IAM.7", "IAM.8", "IAM.9",
        ],
    },

    # ── Article 21(2)(a) — Risk Management Policy ─────────────────────────

    "NIS2-2.1.2": {
        "title": "Risk Management Framework",
        "severity": "HIGH",
        "section": "Art. 21(2)(a) — Risk Management",
        "description": (
            "Relevant entities shall establish and maintain a risk management framework "
            "to identify and address risks, follow a risk management methodology, "
            "and continuously monitor the implementation of risk treatment measures."
        ),
        "remediation": (
            "Enable MFA for root and all IAM console users. "
            "Enforce strong IAM password policy with complexity and rotation. "
            "Remove root access keys. Attach policies to groups/roles only. "
            "Rotate access keys every 90 days and remove unused credentials."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
        ],
    },

    "NIS2-2.2.3": {
        "title": "Compliance Monitoring at Planned Intervals",
        "severity": "MEDIUM",
        "section": "Art. 21(2)(a) — Risk Management",
        "description": (
            "Relevant entities shall perform compliance monitoring at planned intervals "
            "and when significant incidents or significant changes to operations or risks "
            "occur. CloudWatch metric filters and alarms shall cover all required events."
        ),
        "remediation": (
            "Enable all CloudWatch metric filters for: secret rotation, network ACL changes, "
            "gateway changes, route table changes, VPC changes, Config changes, "
            "CloudTrail changes, org changes, S3 policy changes, IAM policy changes, "
            "and security group changes. Ensure each filter has an active alarm and SNS subscription."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "NIS2-2.3.1": {
        "title": "Independent Review of NIS Security",
        "severity": "MEDIUM",
        "section": "Art. 21(2)(a) — Risk Management",
        "description": (
            "Relevant entities shall review independently their approach to managing "
            "network and information system security, including people, processes and "
            "technologies. Access key rotation and root usage monitoring are key indicators."
        ),
        "remediation": (
            "Rotate IAM access keys every 90 days. "
            "Enable CloudWatch metric filter and alarm for root account usage. "
            "Ensure a security audit role exists with read-only permissions. "
            "Review and remove unused credentials regularly."
        ),
        # Was ["IAM.2", "IAM.6", "CloudWatch.1"] — IAM.2 (policy attachment)
        # and IAM.6 (root hardware MFA) don't match "rotate access keys" /
        # "remove unused credentials"; that's IAM.3 and IAM.8.
        "checks": [
            "IAM.3", "IAM.8", "CloudWatch.1",
        ],
    },

    # ── Article 21(2)(b) — Incident Handling ──────────────────────────────

    "NIS2-3.2.1": {
        "title": "Monitoring and Logging of NIS Activities",
        "severity": "HIGH",
        "section": "Art. 21(2)(b) — Incident Handling",
        "description": (
            "Relevant entities shall lay down procedures and use tools to monitor and "
            "log activities on their network and information systems to detect events "
            "that could be considered as incidents and respond accordingly."
        ),
        "remediation": (
            "Enable CloudWatch metric filter and alarm for root account usage. "
            "Enable CloudTrail in all regions with CloudWatch Logs integration. "
            "Ensure log groups are not publicly accessible."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2",
        ],
    },

    "NIS2-3.2.2": {
        "title": "Automated Continuous Monitoring",
        "severity": "HIGH",
        "section": "Art. 21(2)(b) — Incident Handling",
        "description": (
            "Monitoring shall be automated and carried out either continuously or in "
            "periodic intervals. Relevant entities shall implement monitoring activities "
            "that minimise false positives and false negatives."
        ),
        "remediation": (
            "Enable CloudWatch metric filters for security group changes, IAM policy "
            "changes, AWS Organizations changes, and root account usage. "
            "Ensure all metric filters have active alarms with SNS subscriptions."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.11", "CloudWatch.12",
        ],
    },

    "NIS2-3.2.3": {
        "title": "Comprehensive Logging of System Access and Events",
        "severity": "HIGH",
        "section": "Art. 21(2)(b) — Incident Handling",
        "description": (
            "Relevant entities shall log: outbound/inbound network traffic, user "
            "creation/modification/deletion, access to systems and applications, "
            "authentication events, privileged access, changes to critical configuration "
            "files, and events from security tools such as firewalls."
        ),
        "remediation": (
            "Configure CloudWatch metric filters for all required events: policy changes, "
            "security group changes, network ACL/gateway/route/VPC changes, "
            "CloudTrail configuration changes, S3 bucket policy changes, "
            "root usage, authentication failures, sign-in without MFA, "
            "unauthorized API calls, and KMS CMK deletion."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    "NIS2-3.2.4": {
        "title": "Log Review and Alarm Thresholds",
        "severity": "HIGH",
        "section": "Art. 21(2)(b) — Incident Handling",
        "description": (
            "Logs shall be regularly reviewed for unusual or unwanted trends. "
            "Appropriate alarm thresholds shall be set. If threshold values are exceeded, "
            "an alarm shall be triggered automatically and a qualified response initiated."
        ),
        "remediation": (
            "Configure CloudWatch alarms for network gateway changes, VPC changes, "
            "CloudTrail configuration changes, unauthorized API calls, and route table "
            "changes. Ensure SNS topics have active subscriptions."
        ),
        "checks": [
            "CloudWatch.4", "CloudWatch.5", "CloudWatch.6",
            "CloudWatch.7", "CloudWatch.8", "CloudWatch.9", "CloudWatch.10",
        ],
    },

    "NIS2-3.2.5": {
        "title": "Log Retention and Protection",
        "severity": "MEDIUM",
        "section": "Art. 21(2)(b) — Incident Handling",
        "description": (
            "Relevant entities shall maintain and back up logs for a predefined period "
            "and shall protect them from unauthorised access or changes. "
            "CloudWatch log groups shall have a defined retention policy."
        ),
        "remediation": (
            "Set CloudWatch log group retention policy to at least 365 days. "
            "Store logs in S3 with block public access and versioning enabled. "
            "Enable CloudTrail log file validation to detect tampering."
        ),
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "CloudWatch.1", "CloudWatch.2",
        ],
    },

    "NIS2-3.5.4": {
        "title": "Incident Response Activity Logging",
        "severity": "HIGH",
        "section": "Art. 21(2)(b) — Incident Handling",
        "description": (
            "Relevant entities shall log incident response activities and record evidence. "
            "All CloudWatch metric filters must be active to capture incident-relevant events "
            "including CloudTrail changes, authentication failures, and policy changes."
        ),
        "remediation": (
            "Enable all CloudWatch metric filters and alarms for: Config changes, "
            "CloudTrail changes, authentication failures, org changes, KMS CMK deletion, "
            "S3 policy changes, IAM policy changes, root usage, security group changes, "
            "sign-in without MFA, and unauthorized API calls."
        ),
        "checks": [
            "CloudWatch.1", "CloudWatch.2", "CloudWatch.3", "CloudWatch.4",
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10", "CloudWatch.11", "CloudWatch.12",
            "CloudWatch.13", "CloudWatch.14",
        ],
    },

    # ── Article 21(2)(c) — Business Continuity ────────────────────────────

    "NIS2-4.1.1": {
        "title": "Business Continuity and Disaster Recovery Plan",
        "severity": "HIGH",
        "section": "Art. 21(2)(c) — Business Continuity",
        "description": (
            "Relevant entities shall lay down and maintain a business continuity and "
            "disaster recovery plan to apply in case of incidents. Backup copies shall "
            "be complete, accurate, and encrypted. Recovery objectives shall be defined."
        ),
        "remediation": (
            "Enable S3 server-side encryption and block public access for backup storage. "
            "Enable KMS key rotation for all keys used to encrypt backups. "
            "Ensure backup vaults are encrypted. Implement RDS automated backups."
        ),
        # Was also listing KMS.2/3/4 — this text only names "Enable KMS key
        # rotation", which is KMS.1; KMS.2-4 (key-policy/disabled checks)
        # aren't mentioned here.
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
            "KMS.1",
        ],
    },

    "NIS2-4.2.2": {
        "title": "Backup and Redundancy Management",
        "severity": "HIGH",
        "section": "Art. 21(2)(c) — Business Continuity",
        "description": (
            "Backup copies shall be complete and accurate. Relevant entities shall "
            "implement procedures for restoring data from backup copies and define "
            "retention periods based on business and regulatory requirements."
        ),
        "remediation": (
            "Enable S3 server-side encryption (SSE-KMS) on all backup buckets. "
            "Block all public access to S3 backup buckets. "
            "Enable KMS key rotation. "
            "Set CloudWatch log group retention policies meeting regulatory requirements."
        ),
        # Was also listing KMS.2 — only "Enable KMS key rotation" (KMS.1) is
        # named in this text.
        "checks": [
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
            "KMS.1",
        ],
    },

    # ── Article 21(2)(e) — Security in Acquisition, Development, Maintenance

    "NIS2-6.4.1": {
        "title": "Change Management Procedures",
        "severity": "MEDIUM",
        "section": "Art. 21(2)(e) — Security in Development",
        "description": (
            "Relevant entities shall apply change management procedures to control "
            "changes of network and information systems. Changes to network ACLs, "
            "gateways, route tables, and VPCs shall be monitored and alerted on."
        ),
        "remediation": (
            "Configure CloudWatch metric filters and alarms for: network ACL changes, "
            "network gateway changes, route table changes, and VPC changes. "
            "Ensure all alarms have active SNS subscriptions for prompt notification."
        ),
        "checks": [
            "CloudWatch.5", "CloudWatch.6", "CloudWatch.7", "CloudWatch.8",
            "CloudWatch.9", "CloudWatch.10",
        ],
    },

    # ── Article 21(2)(h) — Cryptography ───────────────────────────────────

    "NIS2-9.2.a": {
        "title": "Cryptographic Measures for Data at Rest and in Transit",
        "severity": "HIGH",
        "section": "Art. 21(2)(h) — Cryptography",
        "description": (
            "Relevant entities shall implement appropriate cryptographic measures based "
            "on asset classification, including protection of data at rest and in transit. "
            "KMS CMKs shall be used with automatic rotation enabled."
        ),
        "remediation": (
            "Enable automatic rotation for all KMS customer-managed keys. "
            "Apply SSE-KMS to all S3 buckets containing sensitive data. "
            "Ensure KMS keys are not publicly accessible or scheduled for deletion. "
            "Block public access to all S3 buckets."
        ),
        # Was KMS.4 (key not disabled — not mentioned) instead of KMS.5
        # ("scheduled for deletion", explicitly named); also missing S3.2.x
        # (block public access), which the text explicitly asks for.
        "checks": [
            "KMS.1", "KMS.2", "KMS.3", "KMS.5",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
            "S3.3.1", "S3.3.2", "S3.3.5",
        ],
    },

    "NIS2-9.2.c": {
        "title": "Cryptographic Key Management",
        "severity": "HIGH",
        "section": "Art. 21(2)(h) — Cryptography",
        "description": (
            "Relevant entities shall define their approach to key management, including "
            "generating, distributing, storing, changing, backing up, logging, auditing, "
            "and deactivating keys. Access keys shall be rotated regularly."
        ),
        "remediation": (
            "Rotate IAM access keys every 90 days. "
            "Enable KMS key rotation for all customer-managed keys. "
            "Ensure KMS keys are not publicly accessible. "
            "Remove root access keys. Disable unused access keys."
        ),
        # Was ["IAM.2", "IAM.6", ...] — policy attachment / root hardware MFA
        # don't match "rotate access keys" / "remove root access keys" /
        # "disable unused access keys"; those are IAM.3 / IAM.4 / IAM.8.
        # KMS.4 (key not disabled) isn't mentioned in this text either.
        "checks": [
            "IAM.3", "IAM.4", "IAM.8",
            "KMS.1", "KMS.2", "KMS.3",
        ],
    },

    "NIS2-9.2.c.v": {
        "title": "Password and Key Rotation Requirements",
        "severity": "MEDIUM",
        "section": "Art. 21(2)(h) — Cryptography",
        "description": (
            "Relevant entities shall require the change of authentication credentials "
            "at predefined intervals. IAM password policy shall enforce expiry, "
            "complexity, and prevent reuse of previous passwords."
        ),
        "remediation": (
            "Configure IAM password policy to expire within 90 days. "
            "Require uppercase, lowercase, numbers, and symbols. "
            "Set minimum length of 14 characters. "
            "Prevent reuse of the last 24 passwords."
        ),
        # Was ["IAM.1", "IAM.2"] (full-admin policies / policy attachment) —
        # this control is entirely about password policy, i.e. IAM.7.
        "checks": [
            "IAM.7",
        ],
    },

    # ── Article 21(2)(i)(j) — Access Control ──────────────────────────────

    "NIS2-11.1.1": {
        "title": "Access Control Policy",
        "severity": "HIGH",
        "section": "Art. 21(2)(i)(j) — Access Control",
        "description": (
            "Relevant entities shall establish and implement logical and physical access "
            "control policies based on business and security requirements. Access shall "
            "be granted only to authenticated users with a documented business need."
        ),
        "remediation": (
            "Enforce IAM password policy and MFA for all console users. "
            "Block public access to all S3 buckets. "
            "Remove unused IAM credentials. Attach policies to groups/roles only. "
            "Apply least privilege across all IAM users and roles."
        ),
        "checks": [
            "IAM.1", "IAM.2", "IAM.3", "IAM.4",
            "IAM.5", "IAM.6", "IAM.7", "IAM.8", "IAM.9",
            "S3.2.1", "S3.2.2", "S3.2.3", "S3.2.4",
        ],
    },

    "NIS2-11.2.2": {
        "title": "Management of Access Rights — Least Privilege",
        "severity": "HIGH",
        "section": "Art. 21(2)(i)(j) — Access Control",
        "description": (
            "Access rights shall be assigned and revoked based on the principles of "
            "need-to-know, least privilege and separation of duties. IAM policies shall "
            "not grant full access to CloudTrail or KMS."
        ),
        "remediation": (
            "Attach IAM policies only to groups or roles. "
            "Remove overly permissive inline policies with administrative privileges. "
            "Remove unused IAM users and access keys. "
            "Review and restrict policies allowing privilege escalation."
        ),
        # Was ["IAM.5", "IAM.7", "IAM.8", "IAM.9"] — console MFA, password
        # policy, and root MFA don't test policy attachment or admin-privilege
        # policies. IAM.1 (full-admin '*') and IAM.2 (direct policy attachment)
        # are what the remediation actually describes; IAM.8 (unused
        # users/keys) was already correct and is kept.
        "checks": [
            "IAM.1", "IAM.2", "IAM.8",
        ],
    },

    "NIS2-11.3.2": {
        "title": "Privileged and System Administration Accounts",
        "severity": "CRITICAL",
        "section": "Art. 21(2)(i)(j) — Access Control",
        "description": (
            "Relevant entities shall establish strong identification, authentication "
            "(including MFA), and authorisation procedures for privileged accounts. "
            "Root usage shall be avoided and system admin privileges individualised."
        ),
        "remediation": (
            "Enable MFA for root account and all IAM users with console access. "
            "Remove root access keys. Restrict AdministratorAccess role usage. "
            "Enable CloudWatch alarm for root account usage. "
            "Remove inline policies with administrative privileges."
        ),
        # Was ["IAM.3", "IAM.4", "IAM.7", "IAM.9", "CloudWatch.1"] — IAM.3
        # (key rotation) and IAM.7 (password policy) aren't mentioned in the
        # remediation; IAM.5 (console MFA) and IAM.1 (admin '*' policies) are
        # what's actually described but were missing. IAM.4/IAM.9/CloudWatch.1
        # were already correct.
        "checks": [
            "IAM.1", "IAM.4", "IAM.5", "IAM.9",
            "CloudWatch.1",
        ],
    },

    "NIS2-11.5.4": {
        "title": "Regular Review and Deactivation of Identities",
        "severity": "MEDIUM",
        "section": "Art. 21(2)(i)(j) — Access Control",
        "description": (
            "Relevant entities shall regularly review the identities for network and "
            "information systems and their users and, if no longer needed, deactivate "
            "them without delay."
        ),
        "remediation": (
            "Disable or remove IAM user console access not used for more than 90 days. "
            "Disable or delete access keys unused for more than 90 days. "
            "Remove IAM users who no longer require access. "
            "Rotate access keys and enforce password expiry."
        ),
        # Was ["IAM.2", "IAM.6", "IAM.8", "IAM.9"] — policy attachment and
        # root MFA don't relate to reviewing/deactivating stale identities.
        # The remediation explicitly calls for key rotation (IAM.3) and
        # password expiry (IAM.7); IAM.8 (unused creds) was already correct.
        "checks": [
            "IAM.3", "IAM.7", "IAM.8",
        ],
    },

    "NIS2-11.6.1": {
        "title": "Secure Authentication Procedures",
        "severity": "HIGH",
        "section": "Art. 21(2)(i)(j) — Access Control",
        "description": (
            "Relevant entities shall implement secure authentication procedures and "
            "technologies based on access restrictions and the access control policy. "
            "MFA shall be required for root and all console users."
        ),
        "remediation": (
            "Enable hardware MFA for root account. "
            "Enable virtual or hardware MFA for all IAM users with console access. "
            "Enable CloudWatch alarm for sign-in without MFA. "
            "Configure Cognito user pools to require MFA."
        ),
        # Was ["IAM.3", "IAM.4", "CloudWatch.3"] — key rotation / root key
        # existence aren't authentication-procedure checks. IAM.6 (root
        # hardware MFA) and IAM.5 (console MFA) are what's described;
        # CloudWatch.3 was already correct. No Cognito-MFA check exists in
        # this codebase's check set, so that part of the remediation has no
        # corresponding check — left uncovered rather than guessed at.
        "checks": [
            "IAM.5", "IAM.6",
            "CloudWatch.3",
        ],
    },

    "NIS2-11.7.2": {
        "title": "Multi-Factor Authentication",
        "severity": "CRITICAL",
        "section": "Art. 21(2)(i)(j) — Access Control",
        "description": (
            "Relevant entities shall ensure that the strength of authentication is "
            "appropriate for the classification of the asset to be accessed. "
            "MFA shall be implemented for all privileged and console access."
        ),
        "remediation": (
            "Enable hardware MFA for root account. "
            "Enable MFA for all IAM users with console access. "
            "Enable MFA delete on CloudTrail S3 buckets. "
            "Configure CloudWatch alarm for console sign-in without MFA. "
            "Enforce MFA for all administrator access."
        ),
        # Was ["IAM.3", "IAM.4", "CloudWatch.3"] — a CRITICAL control titled
        # "Multi-Factor Authentication" tested key rotation and root-key
        # existence, never MFA. IAM.5/IAM.6/IAM.9 cover console MFA, root
        # hardware MFA, and root MFA generally; CloudWatch.3 was already
        # correct. No S3 MFA-delete check exists in this codebase's check
        # set, so that part of the remediation has no corresponding check.
        "checks": [
            "IAM.5", "IAM.6", "IAM.9",
            "CloudWatch.3",
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
                      AND f.framework != 'NIS2'
                """, (cloud_account_id,))

                rows = cur.fetchall()
                logger.info("Read %d existing findings for NIS2 mapping", len(rows))

                by_check: dict = {}
                for check_id, result, resource_id, resource_name, resource_type in rows:
                    by_check.setdefault(check_id, []).append({
                        "resource_id":   resource_id,
                        "result":        result,
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                    })

                for ctrl_id, ctrl_def in NIS2_MAPPING.items():
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
                        logger.info("NIS2 %s: no matching findings found, skipping", ctrl_id)
                        continue

                    for resource_id, data in resource_results.items():
                        results_list = data["results"]
                        nis2_result = "FAIL" if "FAIL" in results_list else "PASS"
                        nis2_status = "open" if nis2_result == "FAIL" else "pass"

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
                            nis2_status,
                            nis2_result,
                            "NIS2",
                            ctrl_def["remediation"],
                            json.dumps({
                                "nis2_control":  ctrl_id,
                                "nis2_section":  ctrl_def["section"],
                                "mapped_checks": ctrl_def["checks"],
                                "passed":        passed,
                                "failed":        failed,
                            }),
                        ))
                        findings_upserted += 1
                        logger.info(
                            "NIS2 %s / resource %s -> %s (%d/%d passing)",
                            ctrl_id, resource_id, nis2_result, passed, len(results_list)
                        )

        logger.info("NIS2 mapping complete: %d findings upserted", findings_upserted)

    finally:
        conn.close()

    return {"findings_upserted": findings_upserted}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    account_id = event.get("cloud_account_id", CLOUD_ACCOUNT_ID) if event else CLOUD_ACCOUNT_ID
    logger.info("NIS2 mapper starting for cloud_account_id=%s", account_id)
    stats = run_mapping(account_id)
    logger.info("NIS2 mapper done: %s", stats)
    return {
        "statusCode": 200,
        "body": stats,
    }
