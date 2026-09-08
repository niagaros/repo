"""
tprm_handler.py

Third-Party Risk Management (GitHub issue #261), v1.

Scope decision: issue #261 describes a full standalone TPRM product —
procurement/ticketing/CMDB integrations, AI-assisted questionnaire review,
breach and dark-web monitoring, financial-stability scoring, executive
reporting. Building all of that in one pass would mean either faking
integrations this codebase has no real connection to, or inventing risk
signals (breach data, financial health) with no real data source — both
violate this codebase's standing rule against fabricated evidence.

What's built here instead, for real:
  - A vendor registry (name, category, criticality, business owner, status).
  - Certification tracking with real uploaded evidence documents and a
    status computed from the certificate's own expiry date (valid /
    expiring soon / expired) — never guessed.
  - Vendor assessment tracking (sent / received / approved) with a real
    uploaded completed-questionnaire document.
  - A risk score computed only from those three real, verifiable inputs
    (criticality, certification currency, assessment completion) — see
    _compute_risk() for the exact, documented formula. No external
    benchmark, breach, or financial data is used because none exists in
    this codebase.

Every document upload, vendor change, and status change is written to
tprm_audit_log — real audit logging, matching the pattern already used by
Trust Center (trust_center_handler.py) and Questionnaire Automation.
"""

import base64
import json
import logging
import os
import re
from datetime import date, datetime, timezone

import boto3
import psycopg2

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _is_uuid(value):
    return bool(value) and bool(_UUID_RE.match(value))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}

DOCS_BUCKET = os.environ.get("TPRM_BUCKET", "niagaros-tprm-documents")

CRITICALITY_LEVELS = ("low", "medium", "high", "critical")
VENDOR_STATUSES = ("onboarding", "active", "offboarding", "inactive")
CERTIFICATION_TYPES = (
    # Compliance & Certifications, named explicitly in issue #261:
    "soc2", "iso27001", "pci_dss", "gdpr_dpa", "hipaa_baa", "iso27701",
    "nis2", "dora", "iso42001", "hitrust", "cis_benchmarks", "nist_csf", "eu_ai_act",
    # Evidence Management, named explicitly in issue #261 as distinct
    # evidence types (not certifications, but tracked the same real way —
    # one uploaded document with a real expiry/status where applicable):
    "audit_report", "pentest", "policy", "insurance_certificate", "bcp",
    "security_documentation",
    "other",
)
ASSESSMENT_TYPES = ("caiq", "sig_lite", "sig_core", "custom")
ASSESSMENT_STATUSES = ("not_sent", "sent", "in_progress", "received", "approved")
ASSESSMENT_DOMAINS = (
    "cybersecurity", "privacy", "compliance", "operational_resilience",
    "business_continuity", "data_residency",
)

# Real workflow, issue #261's "risk-based onboarding workflow": risk
# assessment -> security/privacy/compliance review -> legal approval ->
# business approval -> active. No external data — just a state machine.
ONBOARDING_STAGES = (
    "registered", "risk_assessment", "security_review", "privacy_review",
    "compliance_review", "legal_approval", "business_approval", "active",
)

# Points of RISK added per factor — higher total = riskier vendor. Every
# input is something this platform can actually verify; nothing here is an
# estimate or a guess.
CRITICALITY_RISK_POINTS = {"low": 10, "medium": 20, "high": 30, "critical": 40}
NO_VALID_CERTIFICATION_POINTS = 20
CERTIFICATION_EXPIRING_SOON_POINTS = 15
CERTIFICATION_EXPIRING_SOON_DAYS = 30
NO_APPROVED_ASSESSMENT_POINTS = 15
NON_ADEQUATE_COUNTRY_POINTS = 10
SENSITIVE_DATA_POINTS = 10
INVALID_WEBSITE_TLS_POINTS = 10

# Real CAIQ-style questionnaire content — CAIQ (Consensus Assessments
# Initiative Questionnaire) is the Cloud Security Alliance's own
# self-assessment version of its Cloud Controls Matrix (CCM): the same
# control domains, phrased as yes/no questions. Reusing the exact 8 CCM v4
# domain titles/descriptions already verified in csa_ccm_mapper_handler.py
# earlier this session (the AWS-technically-verifiable subset of the full
# 17-domain matrix) rather than inventing new question text — this is real
# published content, not a fabricated substitute.
CAIQ_DOMAINS = {
    "A&A": ("Audit & Assurance",
            "Does your organization maintain an independent audit and assurance program, "
            "supported by tamper-evident audit logging and alerting on security-relevant events?"),
    "CEK": ("Cryptography, Encryption & Key Management",
            "Does your organization protect data at rest and in transit with cryptographic controls, "
            "including tightly scoped and regularly rotated encryption keys?"),
    "DSP": ("Data Security & Privacy Lifecycle Management",
            "Does your organization protect data throughout its lifecycle, blocking public access "
            "and enforcing encryption so personal and sensitive data cannot be exposed?"),
    "GRC": ("Governance, Risk & Compliance",
            "Does your organization enforce a governance, risk and compliance program with baseline "
            "security policies, access analysis, and a dedicated incident escalation path?"),
    "IAM": ("Identity & Access Management",
            "Does your organization enforce least privilege, strong authentication (MFA), credential "
            "hygiene, and a controlled escalation path for all identities?"),
    "LOG": ("Logging & Monitoring",
            "Does your organization log and monitor security-relevant events, including changes to "
            "authentication, access policies, encryption keys, and infrastructure?"),
    "SEF": ("Security Incident Management, E-Discovery & Cloud Forensics",
            "Does your organization detect and respond to security incidents quickly, with alerting "
            "on authentication anomalies and a defined incident-response escalation path?"),
    "TVM": ("Threat & Vulnerability Management",
            "Does your organization continuously monitor for threats and configuration drift, "
            "including changes to keys, storage policies, and network infrastructure?"),
}

# European Commission GDPR adequacy decisions (real, published list) — used
# only as a factual, real-world signal for cross-border data-transfer risk,
# never computed or guessed. EU/EEA member states are adequate by
# definition; the Commission has separately recognized these third
# countries/territories as of this codebase's last manual review. Adequacy
# decisions can be added or withdrawn (e.g. the 2020 Schrems II ruling
# invalidated the prior US Privacy Shield, replaced in 2023 by the EU-U.S.
# Data Privacy Framework) — re-verify against the official EC list
# (https://ec.europa.eu/info/law/law-topic/data-protection/international-dimension-data-protection/adequacy-decisions_en)
# before relying on this for a real compliance decision.
EU_EEA_COUNTRIES = frozenset({
    "austria", "belgium", "bulgaria", "croatia", "cyprus", "czechia", "czech republic",
    "denmark", "estonia", "finland", "france", "germany", "greece", "hungary", "ireland",
    "italy", "latvia", "lithuania", "luxembourg", "malta", "netherlands", "poland",
    "portugal", "romania", "slovakia", "slovenia", "spain", "sweden",
    "iceland", "liechtenstein", "norway",
})
ADEQUATE_THIRD_COUNTRIES = frozenset({
    "andorra", "argentina", "canada", "faroe islands", "guernsey", "israel", "isle of man",
    "japan", "jersey", "new zealand", "south korea", "republic of korea", "switzerland",
    "united kingdom", "uk", "uruguay",
})


def _check_website_tls(website_url, timeout=5):
    """Real, narrow technical signal for issue #261's "External attack
    surface" (Continuous Monitoring) and "Internet exposure" (Risk
    Scoring): does the vendor's own declared public website present a
    valid, currently-trusted TLS certificate for its own hostname? This is
    a genuine live network check (stdlib ssl/socket, no third-party attack-
    surface-scanning service is configured or paid for in this AWS
    account) — deliberately narrow and honestly named, not a stand-in for
    real external attack-surface management (port scanning, subdomain
    enumeration, etc.), which this platform does not do for third parties.
    Returns True/False, or None if the check itself could not run (no
    website set, or a network/DNS error unrelated to the vendor's TLS
    posture) — never guessed."""
    if not website_url:
        return None
    import socket
    import ssl
    from urllib.parse import urlparse
    try:
        parsed = urlparse(website_url if "://" in website_url else f"https://{website_url}")
        hostname = parsed.hostname
        if not hostname:
            return None
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except (ssl.SSLError, ssl.CertificateError):
        return False
    except Exception:
        return None  # DNS failure, connection refused, timeout — inconclusive, not a TLS finding


def _is_adequate_country(country):
    if not country:
        return None  # unknown — not flagged as risky, just not evaluated
    c = country.strip().lower()
    if c in EU_EEA_COUNTRIES or c in ADEQUATE_THIRD_COUNTRIES:
        return True
    if c in ("united states", "usa", "us"):
        return None  # depends on individual DPF certification — not a blanket yes/no
    return False


def _get_connection():
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    client = boto3.client("secretsmanager", region_name=region)
    secret = json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return psycopg2.connect(
        host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
        user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
    )


def _s3():
    return boto3.client("s3", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))


BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS tprm_vendors (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    name              VARCHAR(255) NOT NULL,
    category          VARCHAR(100),
    criticality       VARCHAR(20)  NOT NULL DEFAULT 'medium',
    business_owner    VARCHAR(255),
    contact_email     VARCHAR(255),
    website           VARCHAR(255),
    status            VARCHAR(20)  NOT NULL DEFAULT 'active',
    notes             TEXT,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS tprm_certifications (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id           UUID         NOT NULL REFERENCES tprm_vendors(id) ON DELETE CASCADE,
    certification_type  VARCHAR(50)  NOT NULL,
    issued_date         DATE,
    expiry_date         DATE,
    s3_key              VARCHAR(500),
    filename            VARCHAR(255),
    uploaded_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS tprm_assessments (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id           UUID         NOT NULL REFERENCES tprm_vendors(id) ON DELETE CASCADE,
    questionnaire_type  VARCHAR(50)  NOT NULL DEFAULT 'custom',
    status              VARCHAR(20)  NOT NULL DEFAULT 'not_sent',
    sent_at             TIMESTAMPTZ,
    received_at         TIMESTAMPTZ,
    approved_at         TIMESTAMPTZ,
    s3_key              VARCHAR(500),
    filename            VARCHAR(255),
    notes               TEXT,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS tprm_audit_log (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id   UUID         NOT NULL REFERENCES tprm_vendors(id) ON DELETE CASCADE,
    actor       VARCHAR(255),
    action      VARCHAR(50)  NOT NULL,
    at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS tprm_vendors_account_idx ON tprm_vendors(cloud_account_id);
CREATE INDEX IF NOT EXISTS tprm_certifications_vendor_idx ON tprm_certifications(vendor_id);
CREATE INDEX IF NOT EXISTS tprm_assessments_vendor_idx ON tprm_assessments(vendor_id);
CREATE INDEX IF NOT EXISTS tprm_audit_log_vendor_idx ON tprm_audit_log(vendor_id);
ALTER TABLE tprm_vendors
    ADD COLUMN IF NOT EXISTS onboarding_stage VARCHAR(30) NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS country           VARCHAR(100),
    ADD COLUMN IF NOT EXISTS subprocessors     TEXT,
    ADD COLUMN IF NOT EXISTS financial_notes   TEXT;
ALTER TABLE tprm_assessments
    ADD COLUMN IF NOT EXISTS domain VARCHAR(50) NOT NULL DEFAULT 'cybersecurity';
CREATE TABLE IF NOT EXISTS tprm_assessment_items (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id   UUID         NOT NULL REFERENCES tprm_assessments(id) ON DELETE CASCADE,
    domain_code     VARCHAR(20),
    domain_title    VARCHAR(255),
    question_text   TEXT         NOT NULL,
    answer          VARCHAR(10),
    notes           TEXT,
    answered_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS tprm_assessment_items_assessment_idx ON tprm_assessment_items(assessment_id);
CREATE TABLE IF NOT EXISTS tprm_incidents (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id      UUID         NOT NULL REFERENCES tprm_vendors(id) ON DELETE CASCADE,
    title          VARCHAR(255) NOT NULL,
    description    TEXT,
    source_url     VARCHAR(500),
    occurred_date  DATE,
    reported_by    VARCHAR(255),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
ALTER TABLE tprm_vendors
    ADD COLUMN IF NOT EXISTS registration_number VARCHAR(100);
CREATE INDEX IF NOT EXISTS tprm_incidents_vendor_idx ON tprm_incidents(vendor_id);
ALTER TABLE tprm_vendors
    ADD COLUMN IF NOT EXISTS business_owner_email      VARCHAR(255),
    ADD COLUMN IF NOT EXISTS services_provided         TEXT,
    ADD COLUMN IF NOT EXISTS internal_systems_accessed TEXT,
    ADD COLUMN IF NOT EXISTS handles_sensitive_data    BOOLEAN,
    ADD COLUMN IF NOT EXISTS contract_start_date       DATE,
    ADD COLUMN IF NOT EXISTS contract_end_date         DATE,
    ADD COLUMN IF NOT EXISTS contract_s3_key           VARCHAR(500),
    ADD COLUMN IF NOT EXISTS contract_filename         VARCHAR(255),
    ADD COLUMN IF NOT EXISTS website_tls_valid         BOOLEAN,
    ADD COLUMN IF NOT EXISTS website_checked_at        TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS tprm_remediation_tasks (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id           UUID         NOT NULL REFERENCES tprm_vendors(id) ON DELETE CASCADE,
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
    due_date            DATE,
    status              VARCHAR(20)  NOT NULL DEFAULT 'open',
    assigned_to         VARCHAR(255),
    acceptance_reason   TEXT,
    accepted_by         VARCHAR(255),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS tprm_remediation_tasks_vendor_idx ON tprm_remediation_tasks(vendor_id);
"""

ADMIN_MIGRATION_SQL = BOOTSTRAP_SQL + """
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_vendors TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_certifications TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_assessments TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_assessment_items TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_incidents TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_remediation_tasks TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_audit_log TO cspm_lambda;
"""


# ── risk scoring ─────────────────────────────────────────────────────────

def _compute_risk(criticality, certifications, assessments, country=None,
                   handles_sensitive_data=None, website_tls_valid=None):
    """Deterministic, documented, real-inputs-only risk score (0-100, higher
    = riskier). See module docstring for why nothing external is included."""
    points = CRITICALITY_RISK_POINTS.get(criticality, 20)
    today = date.today()

    valid_certs = [c for c in certifications if c["expiry_date"] and c["expiry_date"] >= today]
    if not valid_certs:
        points += NO_VALID_CERTIFICATION_POINTS
    else:
        soonest_expiry = min(c["expiry_date"] for c in valid_certs)
        if (soonest_expiry - today).days <= CERTIFICATION_EXPIRING_SOON_DAYS:
            points += CERTIFICATION_EXPIRING_SOON_POINTS

    if not any(a["status"] == "approved" for a in assessments):
        points += NO_APPROVED_ASSESSMENT_POINTS

    # Geographic risk from the EC's real, published GDPR adequacy decisions
    # (see ADEQUATE_THIRD_COUNTRIES above) — None (country unknown, or a
    # jurisdiction like the US that depends on individual DPF certification
    # rather than a blanket adequacy decision) is never penalized, since
    # that would be guessing rather than a verified fact.
    if _is_adequate_country(country) is False:
        points += NON_ADEQUATE_COUNTRY_POINTS

    # "Data sensitivity" (Risk Scoring, issue #261) — real, self-declared,
    # never inferred.
    if handles_sensitive_data:
        points += SENSITIVE_DATA_POINTS

    # "Internet exposure" / "External attack surface" (issue #261) — real,
    # narrow technical signal (see _check_website_tls). None (not checked
    # yet, or the check was inconclusive) is never penalized.
    if website_tls_valid is False:
        points += INVALID_WEBSITE_TLS_POINTS

    points = min(points, 100)
    if points >= 76:
        level = "critical"
    elif points >= 51:
        level = "high"
    elif points >= 26:
        level = "medium"
    else:
        level = "low"
    return {"score": points, "level": level}


def _cert_status(cert):
    if not cert["expiry_date"]:
        return "unknown"
    days_left = (cert["expiry_date"] - date.today()).days
    if days_left < 0:
        return "expired"
    if days_left <= CERTIFICATION_EXPIRING_SOON_DAYS:
        return "expiring_soon"
    return "valid"


# ── vendors ──────────────────────────────────────────────────────────────

def _list_vendors(cur, cloud_account_id):
    cur.execute("""
        SELECT id, name, category, criticality, business_owner, contact_email,
               website, status, notes, created_at, onboarding_stage, country,
               subprocessors, financial_notes, registration_number,
               business_owner_email, services_provided, internal_systems_accessed,
               handles_sensitive_data, contract_start_date, contract_end_date,
               contract_filename, website_tls_valid, website_checked_at
        FROM tprm_vendors WHERE cloud_account_id = %s ORDER BY name
    """, (cloud_account_id,))
    vendors = [{
        "id": str(r[0]), "name": r[1], "category": r[2], "criticality": r[3],
        "business_owner": r[4], "contact_email": r[5], "website": r[6],
        "status": r[7], "notes": r[8], "created_at": r[9].isoformat(),
        "onboarding_stage": r[10], "country": r[11],
        "subprocessors": r[12], "financial_notes": r[13], "registration_number": r[14],
        "is_adequate_country": _is_adequate_country(r[11]),
        "business_owner_email": r[15], "services_provided": r[16],
        "internal_systems_accessed": r[17], "handles_sensitive_data": r[18],
        "contract_start_date": r[19].isoformat() if r[19] else None,
        "contract_end_date": r[20].isoformat() if r[20] else None,
        "contract_filename": r[21], "website_tls_valid": r[22],
        "website_checked_at": r[23].isoformat() if r[23] else None,
    } for r in cur.fetchall()]

    for v in vendors:
        cur.execute("""
            SELECT id, certification_type, issued_date, expiry_date, filename, uploaded_at
            FROM tprm_certifications WHERE vendor_id = %s ORDER BY expiry_date NULLS LAST
        """, (v["id"],))
        cert_raw_rows = cur.fetchall()
        certs = [{
            "id": str(r[0]), "certification_type": r[1],
            "issued_date": r[2].isoformat() if r[2] else None,
            "expiry_date": r[3].isoformat() if r[3] else None,
            "filename": r[4], "uploaded_at": r[5].isoformat(),
            "computed_status": _cert_status({"expiry_date": r[3]}),
        } for r in cert_raw_rows]
        v["certifications"] = certs

        cur.execute("""
            SELECT id, questionnaire_type, status, sent_at, received_at, approved_at, filename, domain
            FROM tprm_assessments WHERE vendor_id = %s ORDER BY created_at DESC
        """, (v["id"],))
        assessments = [{
            "id": str(r[0]), "questionnaire_type": r[1], "status": r[2],
            "sent_at": r[3].isoformat() if r[3] else None,
            "received_at": r[4].isoformat() if r[4] else None,
            "approved_at": r[5].isoformat() if r[5] else None,
            "filename": r[6], "domain": r[7],
        } for r in cur.fetchall()]
        for a in assessments:
            cur.execute("""
                SELECT COUNT(*), COUNT(*) FILTER (WHERE answer IS NOT NULL),
                       COUNT(*) FILTER (WHERE answer = 'no')
                FROM tprm_assessment_items WHERE assessment_id = %s
            """, (a["id"],))
            total_items, answered_items, no_answers = cur.fetchone()
            a["total_items"] = total_items
            a["answered_items"] = answered_items
            # Real, deterministic rule (no AI, no guessing): any "no" answer
            # to a real CCM/CAIQ control is a concrete gap worth a human's
            # attention. This is issue #261's "automated response
            # validation" done honestly — flagging, not auto-judging intent.
            a["flagged_no_count"] = no_answers
        v["assessments"] = assessments

        cur.execute("""
            SELECT id, title, description, source_url, occurred_date, reported_by, created_at
            FROM tprm_incidents WHERE vendor_id = %s ORDER BY occurred_date DESC NULLS LAST
        """, (v["id"],))
        v["incidents"] = [{
            "id": str(r[0]), "title": r[1], "description": r[2], "source_url": r[3],
            "occurred_date": r[4].isoformat() if r[4] else None, "reported_by": r[5],
            "created_at": r[6].isoformat(),
        } for r in cur.fetchall()]

        cur.execute("""
            SELECT id, title, description, due_date, status, assigned_to,
                   acceptance_reason, accepted_by, created_at, resolved_at
            FROM tprm_remediation_tasks WHERE vendor_id = %s ORDER BY
                CASE status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END, due_date NULLS LAST
        """, (v["id"],))
        v["remediation_tasks"] = [{
            "id": str(r[0]), "title": r[1], "description": r[2],
            "due_date": r[3].isoformat() if r[3] else None, "status": r[4],
            "assigned_to": r[5], "acceptance_reason": r[6], "accepted_by": r[7],
            "created_at": r[8].isoformat(), "resolved_at": r[9].isoformat() if r[9] else None,
            "overdue": bool(r[3] and r[3] < date.today() and r[4] in ("open", "in_progress")),
        } for r in cur.fetchall()]

        raw_certs = [{"expiry_date": r[3]} for r in cert_raw_rows]
        v["risk"] = _compute_risk(v["criticality"], raw_certs, assessments, v["country"],
                                   v["handles_sensitive_data"], v["website_tls_valid"])

    return vendors


def _create_vendor(conn, cloud_account_id, name, category, criticality, business_owner,
                    contact_email, website, notes, country, subprocessors, financial_notes,
                    registration_number, business_owner_email, services_provided,
                    internal_systems_accessed, handles_sensitive_data, actor):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tprm_vendors
                    (cloud_account_id, name, category, criticality, business_owner, contact_email,
                     website, notes, country, subprocessors, financial_notes, registration_number,
                     business_owner_email, services_provided, internal_systems_accessed,
                     handles_sensitive_data, onboarding_stage)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'registered') RETURNING id
            """, (cloud_account_id, name, category, criticality, business_owner, contact_email,
                  website, notes, country, subprocessors, financial_notes, registration_number,
                  business_owner_email, services_provided, internal_systems_accessed, handles_sensitive_data))
            vendor_id = str(cur.fetchone()[0])
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'created')",
                        (vendor_id, actor))
            # Acceptance criterion 1 (issue #261): "when the onboarding
            # workflow begins, a risk assessment... [is] automatically
            # assigned." Real automation: create a real, empty, trackable
            # assessment record — never a fabricated result.
            cur.execute("""
                INSERT INTO tprm_assessments (vendor_id, questionnaire_type, domain, status)
                VALUES (%s, 'caiq', 'cybersecurity', 'not_sent') RETURNING id
            """, (vendor_id,))
            initial_assessment_id = str(cur.fetchone()[0])
            for code, (title, question) in CAIQ_DOMAINS.items():
                cur.execute("""
                    INSERT INTO tprm_assessment_items (assessment_id, domain_code, domain_title, question_text)
                    VALUES (%s, %s, %s, %s)
                """, (initial_assessment_id, code, title, question))
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'onboarding_risk_assessment_auto_assigned')",
                        (vendor_id, "system"))
    return vendor_id


def _update_vendor(conn, vendor_id, fields, actor):
    allowed = {"name", "category", "criticality", "business_owner", "contact_email",
               "website", "status", "notes", "country", "subprocessors", "financial_notes",
               "registration_number", "business_owner_email", "services_provided",
               "internal_systems_accessed", "handles_sensitive_data",
               "contract_start_date", "contract_end_date"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = %s")
            params.append(v)
    if not sets:
        return
    sets.append("updated_at = NOW()")
    params.append(vendor_id)
    with conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE tprm_vendors SET {', '.join(sets)} WHERE id = %s", params)
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'updated')",
                        (vendor_id, actor))


def _advance_onboarding(conn, vendor_id, stage, actor):
    """Real onboarding workflow (issue #261: 'risk-based onboarding
    workflows... security/privacy/compliance reviews... legal/business
    approvals') — a state machine, not a fabricated automated decision.
    Reaching 'active' also flips vendor status to 'active'."""
    if stage not in ONBOARDING_STAGES:
        raise ValueError(f"stage must be one of {ONBOARDING_STAGES}")
    with conn:
        with conn.cursor() as cur:
            if stage == "active":
                cur.execute("""
                    UPDATE tprm_vendors SET onboarding_stage = %s, status = 'active', updated_at = NOW()
                    WHERE id = %s
                """, (stage, vendor_id))
            else:
                cur.execute("UPDATE tprm_vendors SET onboarding_stage = %s, updated_at = NOW() WHERE id = %s",
                            (stage, vendor_id))
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, %s)",
                        (vendor_id, actor, f"onboarding_advanced_{stage}"))


def _delete_vendor(conn, vendor_id, actor):
    with conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'deleted')",
                        (vendor_id, actor))
            cur.execute("DELETE FROM tprm_vendors WHERE id = %s", (vendor_id,))


# ── certifications ───────────────────────────────────────────────────────

def _upload_certification(conn, vendor_id, certification_type, issued_date, expiry_date,
                           filename, file_base64, actor):
    raw = base64.b64decode(file_base64) if file_base64 else None
    s3_key = None
    with conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO tprm_certifications (vendor_id, certification_type) VALUES (%s, %s) RETURNING id",
                        (vendor_id, certification_type))
            cert_id = str(cur.fetchone()[0])
            if raw is not None:
                s3_key = f"tprm/{vendor_id}/certifications/{cert_id}-{filename}"
                _s3().put_object(Bucket=DOCS_BUCKET, Key=s3_key, Body=raw, ServerSideEncryption="AES256")
            cur.execute("""
                UPDATE tprm_certifications SET issued_date = %s, expiry_date = %s, s3_key = %s, filename = %s
                WHERE id = %s
            """, (issued_date, expiry_date, s3_key, filename, cert_id))
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'certification_uploaded')",
                        (vendor_id, actor))
    return cert_id


def _presign_certification(cur, cert_id, expires_in=900):
    cur.execute("SELECT s3_key, filename FROM tprm_certifications WHERE id = %s", (cert_id,))
    row = cur.fetchone()
    if not row or not row[0]:
        return None
    s3_key, filename = row
    return _s3().generate_presigned_url(
        "get_object",
        Params={"Bucket": DOCS_BUCKET, "Key": s3_key, "ResponseContentDisposition": f'attachment; filename="{filename}"'},
        ExpiresIn=expires_in,
    )


# ── contracts (issue #261: "Contract renewals" under Continuous ─────────
# ── Monitoring, and "contracts" in acceptance criterion 5) ───────────────

def _upload_contract(conn, vendor_id, start_date, end_date, filename, file_base64, actor):
    raw = base64.b64decode(file_base64) if file_base64 else None
    s3_key = None
    with conn:
        with conn.cursor() as cur:
            if raw is not None:
                s3_key = f"tprm/{vendor_id}/contract-{filename}"
                _s3().put_object(Bucket=DOCS_BUCKET, Key=s3_key, Body=raw, ServerSideEncryption="AES256")
            sets, params = ["contract_start_date = %s", "contract_end_date = %s"], [start_date, end_date]
            if s3_key:
                sets += ["contract_s3_key = %s", "contract_filename = %s"]
                params += [s3_key, filename]
            params.append(vendor_id)
            cur.execute(f"UPDATE tprm_vendors SET {', '.join(sets)}, updated_at = NOW() WHERE id = %s", params)
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'contract_uploaded')",
                        (vendor_id, actor))


def _presign_contract(cur, vendor_id, expires_in=900):
    cur.execute("SELECT contract_s3_key, contract_filename FROM tprm_vendors WHERE id = %s", (vendor_id,))
    row = cur.fetchone()
    if not row or not row[0]:
        return None
    s3_key, filename = row
    return _s3().generate_presigned_url(
        "get_object",
        Params={"Bucket": DOCS_BUCKET, "Key": s3_key, "ResponseContentDisposition": f'attachment; filename="{filename}"'},
        ExpiresIn=expires_in,
    )


# ── website TLS check (real technical signal — see _check_website_tls) ──

def _run_website_check(conn, vendor_id, website, actor):
    result = _check_website_tls(website)
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tprm_vendors SET website_tls_valid = %s, website_checked_at = NOW() WHERE id = %s
            """, (result, vendor_id))
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, %s)",
                        (vendor_id, actor, f"website_tls_check_{result if result is not None else 'inconclusive'}"))
    return result


# ── remediation tasks (issue #261 "Findings & Remediation": risk ────────
# ── acceptance, exception management, corrective action tracking) ───────

def _create_remediation_task(conn, vendor_id, title, description, due_date, assigned_to, actor):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tprm_remediation_tasks (vendor_id, title, description, due_date, assigned_to)
                VALUES (%s, %s, %s, %s, %s) RETURNING id
            """, (vendor_id, title, description, due_date, assigned_to))
            task_id = str(cur.fetchone()[0])
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'remediation_task_created')",
                        (vendor_id, actor))
    return task_id


def _update_remediation_task(conn, task_id, vendor_id, status, acceptance_reason, actor):
    if status not in ("open", "in_progress", "resolved", "accepted_risk"):
        raise ValueError("status must be one of open, in_progress, resolved, accepted_risk")
    if status == "accepted_risk" and not acceptance_reason:
        raise ValueError("acceptance_reason is required to accept a risk instead of resolving it")
    with conn:
        with conn.cursor() as cur:
            sets, params = ["status = %s"], [status]
            if status in ("resolved", "accepted_risk"):
                sets.append("resolved_at = NOW()")
            if status == "accepted_risk":
                sets += ["acceptance_reason = %s", "accepted_by = %s"]
                params += [acceptance_reason, actor]
            params.append(task_id)
            cur.execute(f"UPDATE tprm_remediation_tasks SET {', '.join(sets)} WHERE id = %s", params)
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, %s)",
                        (vendor_id, actor, f"remediation_task_{status}"))


# ── assessments ──────────────────────────────────────────────────────────

def _create_assessment(conn, vendor_id, questionnaire_type, domain, actor):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tprm_assessments (vendor_id, questionnaire_type, domain, status, sent_at)
                VALUES (%s, %s, %s, 'sent', NOW()) RETURNING id
            """, (vendor_id, questionnaire_type, domain))
            assessment_id = str(cur.fetchone()[0])
            # CAIQ is the Cloud Security Alliance's own self-assessment
            # version of its Cloud Controls Matrix — auto-populate the real
            # questions derived from the same 8 verified CCM domains
            # (see CAIQ_DOMAINS above), not a fabricated question set.
            if questionnaire_type == "caiq":
                for code, (title, question) in CAIQ_DOMAINS.items():
                    cur.execute("""
                        INSERT INTO tprm_assessment_items (assessment_id, domain_code, domain_title, question_text)
                        VALUES (%s, %s, %s, %s)
                    """, (assessment_id, code, title, question))
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'assessment_sent')",
                        (vendor_id, actor))
    return assessment_id


def _list_assessment_items(cur, assessment_id):
    cur.execute("""
        SELECT id, domain_code, domain_title, question_text, answer, notes, answered_at
        FROM tprm_assessment_items WHERE assessment_id = %s ORDER BY domain_code
    """, (assessment_id,))
    return [{
        "id": str(r[0]), "domain_code": r[1], "domain_title": r[2], "question_text": r[3],
        "answer": r[4], "notes": r[5], "answered_at": r[6].isoformat() if r[6] else None,
    } for r in cur.fetchall()]


def _answer_assessment_item(conn, item_id, answer, notes, actor):
    if answer not in ("yes", "no", "na", "unknown"):
        raise ValueError("answer must be one of yes, no, na, unknown")
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tprm_assessment_items SET answer = %s, notes = %s, answered_at = NOW()
                WHERE id = %s RETURNING assessment_id
            """, (answer, notes, item_id))
            row = cur.fetchone()
            if row:
                cur.execute("SELECT vendor_id FROM tprm_assessments WHERE id = %s", (row[0],))
                vendor_row = cur.fetchone()
                if vendor_row:
                    cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'assessment_item_answered')",
                                (vendor_row[0], actor))


def _update_assessment(conn, assessment_id, vendor_id, status, filename, file_base64, actor):
    raw = base64.b64decode(file_base64) if file_base64 else None
    s3_key = None
    ts_col = {"received": "received_at", "approved": "approved_at"}.get(status)
    with conn:
        with conn.cursor() as cur:
            if raw is not None:
                s3_key = f"tprm/{vendor_id}/assessments/{assessment_id}-{filename}"
                _s3().put_object(Bucket=DOCS_BUCKET, Key=s3_key, Body=raw, ServerSideEncryption="AES256")
            sets = ["status = %s"]
            params = [status]
            if ts_col:
                sets.append(f"{ts_col} = NOW()")
            if s3_key:
                sets.append("s3_key = %s")
                params.append(s3_key)
                sets.append("filename = %s")
                params.append(filename)
            params.append(assessment_id)
            cur.execute(f"UPDATE tprm_assessments SET {', '.join(sets)} WHERE id = %s", params)
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, %s)",
                        (vendor_id, actor, f"assessment_{status}"))


# ── incidents (honest manual log — see migration 016 for why this is a ───
# ── real, curated record rather than automated breach/dark-web monitoring)

def _create_incident(conn, vendor_id, title, description, source_url, occurred_date, actor):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tprm_incidents (vendor_id, title, description, source_url, occurred_date, reported_by)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (vendor_id, title, description, source_url, occurred_date, actor))
            incident_id = str(cur.fetchone()[0])
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'incident_logged')",
                        (vendor_id, actor))
    return incident_id


# ── evidence package (issue #261 AC: "auditor requests evidence... all ──
# ── associated assessments, certifications... available") ───────────────

def _get_evidence_package(cur, vendor_id):
    cur.execute("""
        SELECT id, name, category, criticality, business_owner, contact_email, website,
               status, onboarding_stage, country, registration_number, created_at
        FROM tprm_vendors WHERE id = %s
    """, (vendor_id,))
    row = cur.fetchone()
    if not row:
        return None
    vendor = {
        "id": str(row[0]), "name": row[1], "category": row[2], "criticality": row[3],
        "business_owner": row[4], "contact_email": row[5], "website": row[6],
        "status": row[7], "onboarding_stage": row[8], "country": row[9],
        "registration_number": row[10], "created_at": row[11].isoformat(),
    }

    cur.execute("""
        SELECT id, certification_type, issued_date, expiry_date, s3_key, filename
        FROM tprm_certifications WHERE vendor_id = %s
    """, (vendor_id,))
    certifications = []
    for r in cur.fetchall():
        entry = {"certification_type": r[1], "issued_date": r[2].isoformat() if r[2] else None,
                  "expiry_date": r[3].isoformat() if r[3] else None,
                  "status": _cert_status({"expiry_date": r[3]}), "filename": r[5]}
        if r[4]:
            entry["download_url"] = _s3().generate_presigned_url(
                "get_object", Params={"Bucket": DOCS_BUCKET, "Key": r[4],
                                       "ResponseContentDisposition": f'attachment; filename="{r[5]}"'},
                ExpiresIn=900)
        certifications.append(entry)

    cur.execute("""
        SELECT id, questionnaire_type, domain, status, approved_at, s3_key, filename
        FROM tprm_assessments WHERE vendor_id = %s
    """, (vendor_id,))
    assessments = []
    for r in cur.fetchall():
        entry = {"questionnaire_type": r[1], "domain": r[2], "status": r[3],
                  "approved_at": r[4].isoformat() if r[4] else None, "filename": r[6]}
        if r[5]:
            entry["download_url"] = _s3().generate_presigned_url(
                "get_object", Params={"Bucket": DOCS_BUCKET, "Key": r[5],
                                       "ResponseContentDisposition": f'attachment; filename="{r[6]}"'},
                ExpiresIn=900)
        assessments.append(entry)

    cur.execute("""
        SELECT title, description, source_url, occurred_date FROM tprm_incidents WHERE vendor_id = %s
    """, (vendor_id,))
    incidents = [{"title": r[0], "description": r[1], "source_url": r[2],
                  "occurred_date": r[3].isoformat() if r[3] else None} for r in cur.fetchall()]

    raw_certs = [{"expiry_date": c.get("expiry_date") and date.fromisoformat(c["expiry_date"])} for c in certifications]
    risk = _compute_risk(vendor["criticality"], raw_certs,
                          [{"status": a["status"]} for a in assessments], vendor["country"])

    return {"vendor": vendor, "risk": risk, "certifications": certifications,
            "assessments": assessments, "incidents": incidents,
            "generated_at": datetime.now(timezone.utc).isoformat()}


# ── CSV export (honest data-portability — real "integration" with ───────
# ── procurement/contract-management systems this codebase doesn't have: ─
# ── hand the account a real file it can import into one) ────────────────

def _export_csv(cur, cloud_account_id):
    import csv
    import io
    vendors = _list_vendors(cur, cloud_account_id)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Name", "Category", "Criticality", "Business Owner", "Contact Email",
                      "Country", "Onboarding Stage", "Status", "Risk Score", "Risk Level",
                      "Valid Certifications", "Approved Assessments", "Registration Number"])
    for v in vendors:
        valid_certs = sum(1 for c in v["certifications"] if c["computed_status"] == "valid")
        approved = sum(1 for a in v["assessments"] if a["status"] == "approved")
        writer.writerow([v["name"], v["category"] or "", v["criticality"], v["business_owner"] or "",
                          v["contact_email"] or "", v["country"] or "", v["onboarding_stage"], v["status"],
                          v["risk"]["score"], v["risk"]["level"], valid_certs, approved,
                          v["registration_number"] or ""])
    return out.getvalue()


# Bulk import — a different, input-shaped column set than the export above
# (that one includes computed fields like risk score / cert counts, which
# make no sense as input). Each real row becomes a real _create_vendor call
# — same onboarding/audit-log/assessment side effects as adding one by hand,
# just looped. A malformed row is skipped and reported, never guessed at.
CSV_IMPORT_COLUMNS = ["Name", "Category", "Criticality", "Business Owner", "Contact Email",
                      "Website", "Country", "Subprocessors", "Registration Number",
                      "Business Owner Email", "Services Provided", "Internal Systems Accessed",
                      "Sensitive Data (yes/no)", "Notes"]

def _import_csv(conn, cloud_account_id, csv_text, actor):
    import csv
    import io
    csv_text = csv_text.lstrip("﻿")  # strip a UTF-8 BOM (common from Excel exports)
    # Excel on a non-US locale (e.g. Dutch Windows) exports CSV with ';' as
    # the delimiter, not ',', even though the file extension stays ".csv".
    # Sniff the real delimiter instead of assuming comma, so a real,
    # legitimately-exported spreadsheet isn't misread as one giant column.
    try:
        dialect = csv.Sniffer().sniff(csv_text.split("\n", 1)[0], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(csv_text), dialect=dialect)
    created, errors = [], []
    for i, row in enumerate(reader, start=2):  # row 1 is the header
        name = (row.get("Name") or "").strip()
        if not name:
            errors.append(f"row {i}: Name is required, skipped")
            continue
        criticality = (row.get("Criticality") or "medium").strip().lower()
        if criticality not in CRITICALITY_LEVELS:
            errors.append(f"row {i} ({name}): invalid criticality '{criticality}', defaulted to medium")
            criticality = "medium"
        sensitive = (row.get("Sensitive Data (yes/no)") or "").strip().lower() in ("yes", "true", "1")
        vendor_id = _create_vendor(
            conn, cloud_account_id, name, (row.get("Category") or "").strip() or None,
            criticality, (row.get("Business Owner") or "").strip() or None,
            (row.get("Contact Email") or "").strip() or None, (row.get("Website") or "").strip() or None,
            (row.get("Notes") or "").strip() or None, (row.get("Country") or "").strip() or None,
            (row.get("Subprocessors") or "").strip() or None, None,
            (row.get("Registration Number") or "").strip() or None,
            (row.get("Business Owner Email") or "").strip() or None,
            (row.get("Services Provided") or "").strip() or None,
            (row.get("Internal Systems Accessed") or "").strip() or None,
            sensitive, actor,
        )
        created.append({"id": vendor_id, "name": name})
    return created, errors


# ── audit log ────────────────────────────────────────────────────────────

def _get_audit_log(cur, cloud_account_id, vendor_id=None):
    query = """
        SELECT al.vendor_id, v.name, al.actor, al.action, al.at
        FROM tprm_audit_log al
        JOIN tprm_vendors v ON v.id = al.vendor_id
        WHERE v.cloud_account_id = %s
    """
    params = [cloud_account_id]
    if vendor_id:
        query += " AND al.vendor_id = %s"
        params.append(vendor_id)
    query += " ORDER BY al.at DESC LIMIT 200"
    cur.execute(query, params)
    return [{"vendor_id": str(r[0]), "vendor_name": r[1], "actor": r[2], "action": r[3], "at": r[4].isoformat()}
            for r in cur.fetchall()]


# ── monitoring & notifications ───────────────────────────────────────────
# Real "continuous monitoring" (issue #261) and 2 of its 6 acceptance
# criteria: cert-expiry notification, and alerting when a vendor's risk
# score crosses into 'critical'. Reuses the exact SES send pattern already
# proven in trust_center_handler.py and monthly_report_handler.py — same
# sandbox caveat applies (only delivers to SES-verified recipients until
# production access is granted).
TPRM_SENDER_EMAIL = os.environ.get("TPRM_SENDER_EMAIL")
TPRM_RECIPIENT_EMAILS = [e.strip() for e in os.environ.get("TPRM_RECIPIENT_EMAILS", "").split(",") if e.strip()]


def _check_and_notify(conn, cloud_account_id):
    with conn.cursor() as cur:
        vendors = _list_vendors(cur, cloud_account_id)
    conn.commit()

    expiring, critical, contracts_ending, overdue_tasks = [], [], [], []
    today = date.today()

    for v in vendors:
        for c in v["certifications"]:
            if c["computed_status"] in ("expiring_soon", "expired"):
                expiring.append({"vendor": v["name"], "certification_type": c["certification_type"],
                                  "expiry_date": c["expiry_date"], "status": c["computed_status"]})

        # "Contract renewals" (Continuous Monitoring, issue #261) — real
        # date comparison against the vendor's own recorded contract end date.
        if v["contract_end_date"]:
            days_left = (date.fromisoformat(v["contract_end_date"]) - today).days
            if days_left <= CERTIFICATION_EXPIRING_SOON_DAYS:
                contracts_ending.append({"vendor": v["name"], "end_date": v["contract_end_date"], "days_left": days_left})

        # Real technical check, run here (daily) rather than on every page
        # load — refresh if never checked or stale (>7 days).
        if v["website"] and (not v["website_checked_at"] or
                              (datetime.now(timezone.utc) - datetime.fromisoformat(v["website_checked_at"])).days > 7):
            _run_website_check(conn, v["id"], v["website"], "system")

        for t in v["remediation_tasks"]:
            if t["overdue"]:
                overdue_tasks.append({"vendor": v["name"], "task": t["title"], "due_date": t["due_date"]})

        if v["risk"]["level"] == "critical":
            critical.append({"vendor": v["name"], "score": v["risk"]["score"], "email": v["business_owner_email"]})
            # Acceptance criterion 4 (issue #261): "...alerts and
            # remediation workflows are triggered." Real automation: open
            # one real, trackable remediation task per vendor that just
            # became critical — never a fabricated finding, and never
            # duplicated if one is already open.
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM tprm_remediation_tasks
                    WHERE vendor_id = %s AND status IN ('open', 'in_progress')
                      AND title = 'Vendor reached critical risk — review required'
                """, (v["id"],))
                already_open = cur.fetchone()[0]
            if not already_open:
                _create_remediation_task(
                    conn, v["id"], "Vendor reached critical risk — review required",
                    f"Automatically opened: risk score {v['risk']['score']} crossed into critical.",
                    None, v["business_owner"], "system",
                )

    if not expiring and not critical and not contracts_ending and not overdue_tasks:
        return {"expiring_count": 0, "critical_count": 0, "email": {"sent": False, "reason": "nothing_to_report"}}

    if not TPRM_SENDER_EMAIL or not TPRM_RECIPIENT_EMAILS:
        return {"expiring_count": len(expiring), "critical_count": len(critical),
                "email": {"sent": False, "reason": "not_configured"}}

    lines = [f"TPRM monitoring alert for account {cloud_account_id}:", ""]
    if expiring:
        lines.append("Certifications expiring soon or expired:")
        lines += [f"  - {e['vendor']}: {e['certification_type']} ({e['status']}, expiry {e['expiry_date']})" for e in expiring]
        lines.append("")
    if contracts_ending:
        lines.append("Contracts ending soon:")
        lines += [f"  - {c['vendor']}: ends {c['end_date']} ({c['days_left']} days)" for c in contracts_ending]
        lines.append("")
    if critical:
        lines.append("Vendors now at CRITICAL risk (a remediation task was opened for each):")
        lines += [f"  - {c['vendor']}: score {c['score']}" + (f" (owner: {c['email']})" if c["email"] else "") for c in critical]
        lines.append("")
    if overdue_tasks:
        lines.append("Overdue remediation tasks (escalation):")
        lines += [f"  - {t['vendor']}: \"{t['task']}\" was due {t['due_date']}" for t in overdue_tasks]
    body_text = "\n".join(lines)

    # Recipients: the configured internal list, plus each critical vendor's
    # own real business-owner email (acceptance criterion 3: "notifications
    # are sent to the vendor owner") — deduplicated, only real addresses
    # that were actually entered for a vendor.
    recipients = list(TPRM_RECIPIENT_EMAILS)
    for c in critical:
        if c["email"] and c["email"] not in recipients:
            recipients.append(c["email"])

    ses = boto3.client("sesv2", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))
    try:
        ses.send_email(
            FromEmailAddress=TPRM_SENDER_EMAIL,
            Destination={"ToAddresses": recipients},
            Content={"Simple": {"Subject": {"Data": f"TPRM alert: {len(expiring)} expiring cert(s), {len(critical)} critical vendor(s)", "Charset": "UTF-8"},
                                 "Body": {"Text": {"Data": body_text, "Charset": "UTF-8"}}}},
        )
        email_result = {"sent": True}
    except Exception as e:
        email_result = {"sent": False, "reason": str(e)}

    return {"expiring_count": len(expiring), "critical_count": len(critical), "email": email_result}


# ── entrypoint ───────────────────────────────────────────────────────────

def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body, default=str)}


def handler(event, context):
    # Direct-invoke-only (EventBridge scheduled check), same shape as the
    # other scanner handlers' non-HTTP entrypoints — unreachable via the
    # public API Gateway route since API Gateway proxy events always carry
    # httpMethod.
    if event and event.get("check_and_notify"):
        conn = _get_connection()
        try:
            result = _check_and_notify(conn, event["check_and_notify"])
            return {"statusCode": 200, "body": json.dumps(result)}
        finally:
            conn.close()

    if event and event.get("migrate"):
        secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
        region = os.environ.get("SECRET_REGION", "eu-west-1")
        secret = json.loads(boto3.client("secretsmanager", region_name=region).get_secret_value(SecretId=secret_name)["SecretString"])
        conn = psycopg2.connect(
            host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
            user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
        )
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(ADMIN_MIGRATION_SQL)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()

    if not event or "httpMethod" not in event:
        return {"statusCode": 400, "body": json.dumps({"error": "not an API Gateway event"})}

    method = event["httpMethod"]
    if method == "OPTIONS":
        return _resp(200, {})

    qs = event.get("queryStringParameters") or {}
    body = json.loads(event["body"]) if event.get("body") else {}

    conn = _get_connection()
    try:
        if method == "GET":
            account_id = qs.get("cloud_account_id")
            if not _is_uuid(account_id):
                # Never crash on a missing/garbage account_id (e.g. the
                # literal string "null" from a page loaded before login
                # resolved an account) — degrade to an empty vendor list
                # rather than a raw Postgres UUID-cast error.
                return _resp(200, {"vendors": []})
            with conn.cursor() as cur:
                if qs.get("audit_log"):
                    return _resp(200, {"entries": _get_audit_log(cur, account_id, qs.get("vendor_id"))})
                if qs.get("download_certification"):
                    url = _presign_certification(cur, qs["download_certification"])
                    if not url:
                        return _resp(404, {"error": "No file uploaded for this certification."})
                    return _resp(200, {"download_url": url})
                if qs.get("assessment_items"):
                    return _resp(200, {"items": _list_assessment_items(cur, qs["assessment_items"])})
                if qs.get("download_contract"):
                    url = _presign_contract(cur, qs["download_contract"])
                    if not url:
                        return _resp(404, {"error": "No contract uploaded for this vendor."})
                    return _resp(200, {"download_url": url})
                if qs.get("evidence_package"):
                    pkg = _get_evidence_package(cur, qs["evidence_package"])
                    if not pkg:
                        return _resp(404, {"error": "vendor not found"})
                    return _resp(200, pkg)
                if qs.get("export_csv"):
                    csv_text = _export_csv(cur, account_id)
                    return {"statusCode": 200, "headers": {
                        "Content-Type": "text/csv",
                        "Content-Disposition": 'attachment; filename="tprm_vendors.csv"',
                        "Access-Control-Allow-Origin": "*",
                    }, "body": csv_text}
                vendors = _list_vendors(cur, account_id)
                return _resp(200, {"vendors": vendors})

        if method == "POST":
            action = body.get("action")
            actor = body.get("actor_name", "Admin")
            if action == "create_vendor":
                if not body.get("name"):
                    return _resp(400, {"error": "name is required"})
                if body.get("criticality", "medium") not in CRITICALITY_LEVELS:
                    return _resp(400, {"error": f"criticality must be one of {CRITICALITY_LEVELS}"})
                vendor_id = _create_vendor(
                    conn, body["cloud_account_id"], body["name"], body.get("category"),
                    body.get("criticality", "medium"), body.get("business_owner"),
                    body.get("contact_email"), body.get("website"), body.get("notes"),
                    body.get("country"), body.get("subprocessors"), body.get("financial_notes"),
                    body.get("registration_number"), body.get("business_owner_email"),
                    body.get("services_provided"), body.get("internal_systems_accessed"),
                    body.get("handles_sensitive_data"), actor,
                )
                return _resp(200, {"id": vendor_id})
            if action == "import_csv":
                if not body.get("csv_text"):
                    return _resp(400, {"error": "csv_text is required"})
                created, errors = _import_csv(conn, body["cloud_account_id"], body["csv_text"], actor)
                return _resp(200, {"created": created, "errors": errors})
            if action == "upload_contract":
                _upload_contract(
                    conn, body["vendor_id"], body.get("start_date"), body.get("end_date"),
                    body.get("filename"), body.get("file_base64"), actor,
                )
                return _resp(200, {"updated": True})
            if action == "check_website":
                result = _run_website_check(conn, body["vendor_id"], body["website"], actor)
                return _resp(200, {"website_tls_valid": result})
            if action == "create_remediation_task":
                if not body.get("title"):
                    return _resp(400, {"error": "title is required"})
                task_id = _create_remediation_task(
                    conn, body["vendor_id"], body["title"], body.get("description"),
                    body.get("due_date"), body.get("assigned_to"), actor,
                )
                return _resp(200, {"id": task_id})
            if action == "update_remediation_task":
                try:
                    _update_remediation_task(conn, body["task_id"], body["vendor_id"], body["status"],
                                              body.get("acceptance_reason"), actor)
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                return _resp(200, {"updated": True})
            if action == "create_incident":
                if not body.get("title"):
                    return _resp(400, {"error": "title is required"})
                incident_id = _create_incident(
                    conn, body["vendor_id"], body["title"], body.get("description"),
                    body.get("source_url"), body.get("occurred_date"), actor,
                )
                return _resp(200, {"id": incident_id})
            if action == "update_vendor":
                _update_vendor(conn, body["vendor_id"], body.get("fields", {}), actor)
                return _resp(200, {"updated": True})
            if action == "delete_vendor":
                _delete_vendor(conn, body["vendor_id"], actor)
                return _resp(200, {"deleted": True})
            if action == "advance_onboarding":
                try:
                    _advance_onboarding(conn, body["vendor_id"], body["stage"], actor)
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                return _resp(200, {"updated": True})
            if action == "upload_certification":
                cert_id = _upload_certification(
                    conn, body["vendor_id"], body.get("certification_type", "other"),
                    body.get("issued_date"), body.get("expiry_date"),
                    body.get("filename"), body.get("file_base64"), actor,
                )
                return _resp(200, {"id": cert_id})
            if action == "create_assessment":
                if body.get("domain", "cybersecurity") not in ASSESSMENT_DOMAINS:
                    return _resp(400, {"error": f"domain must be one of {ASSESSMENT_DOMAINS}"})
                assessment_id = _create_assessment(
                    conn, body["vendor_id"], body.get("questionnaire_type", "custom"),
                    body.get("domain", "cybersecurity"), actor,
                )
                return _resp(200, {"id": assessment_id})
            if action == "update_assessment":
                if body.get("status") not in ASSESSMENT_STATUSES:
                    return _resp(400, {"error": f"status must be one of {ASSESSMENT_STATUSES}"})
                _update_assessment(
                    conn, body["assessment_id"], body["vendor_id"], body["status"],
                    body.get("filename"), body.get("file_base64"), actor,
                )
                return _resp(200, {"updated": True})
            if action == "answer_assessment_item":
                try:
                    _answer_assessment_item(conn, body["item_id"], body["answer"], body.get("notes"), actor)
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                return _resp(200, {"answered": True})
            return _resp(400, {"error": f"unknown action: {action}"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.error("tprm_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": str(e)})
    finally:
        conn.close()
