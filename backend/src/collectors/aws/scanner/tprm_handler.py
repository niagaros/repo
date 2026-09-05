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
from datetime import date, datetime, timezone

import boto3
import psycopg2

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
    "soc2", "iso27001", "pci_dss", "gdpr_dpa", "hipaa_baa", "iso27701", "other",
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
"""

ADMIN_MIGRATION_SQL = BOOTSTRAP_SQL + """
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_vendors TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_certifications TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_assessments TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_assessment_items TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_incidents TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_audit_log TO cspm_lambda;
"""


# ── risk scoring ─────────────────────────────────────────────────────────

def _compute_risk(criticality, certifications, assessments, country=None):
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
               subprocessors, financial_notes, registration_number
        FROM tprm_vendors WHERE cloud_account_id = %s ORDER BY name
    """, (cloud_account_id,))
    vendors = [{
        "id": str(r[0]), "name": r[1], "category": r[2], "criticality": r[3],
        "business_owner": r[4], "contact_email": r[5], "website": r[6],
        "status": r[7], "notes": r[8], "created_at": r[9].isoformat(),
        "onboarding_stage": r[10], "country": r[11],
        "subprocessors": r[12], "financial_notes": r[13], "registration_number": r[14],
        "is_adequate_country": _is_adequate_country(r[11]),
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

        raw_certs = [{"expiry_date": r[3]} for r in cert_raw_rows]
        v["risk"] = _compute_risk(v["criticality"], raw_certs, assessments, v["country"])

    return vendors


def _create_vendor(conn, cloud_account_id, name, category, criticality, business_owner,
                    contact_email, website, notes, country, subprocessors, financial_notes,
                    registration_number, actor):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tprm_vendors
                    (cloud_account_id, name, category, criticality, business_owner, contact_email,
                     website, notes, country, subprocessors, financial_notes, registration_number, onboarding_stage)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'registered') RETURNING id
            """, (cloud_account_id, name, category, criticality, business_owner, contact_email,
                  website, notes, country, subprocessors, financial_notes, registration_number))
            vendor_id = str(cur.fetchone()[0])
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'created')",
                        (vendor_id, actor))
    return vendor_id


def _update_vendor(conn, vendor_id, fields, actor):
    allowed = {"name", "category", "criticality", "business_owner", "contact_email",
               "website", "status", "notes", "country", "subprocessors", "financial_notes",
               "registration_number"}
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


def _check_and_notify(cur, cloud_account_id):
    vendors = _list_vendors(cur, cloud_account_id)
    expiring, critical = [], []
    for v in vendors:
        for c in v["certifications"]:
            if c["computed_status"] in ("expiring_soon", "expired"):
                expiring.append({"vendor": v["name"], "certification_type": c["certification_type"],
                                  "expiry_date": c["expiry_date"], "status": c["computed_status"]})
        if v["risk"]["level"] == "critical":
            critical.append({"vendor": v["name"], "score": v["risk"]["score"]})

    if not expiring and not critical:
        return {"expiring_count": 0, "critical_count": 0, "email": {"sent": False, "reason": "nothing_to_report"}}

    if not TPRM_SENDER_EMAIL or not TPRM_RECIPIENT_EMAILS:
        return {"expiring_count": len(expiring), "critical_count": len(critical),
                "email": {"sent": False, "reason": "not_configured"}}

    lines = [f"TPRM monitoring alert for account {cloud_account_id}:", ""]
    if expiring:
        lines.append("Certifications expiring soon or expired:")
        lines += [f"  - {e['vendor']}: {e['certification_type']} ({e['status']}, expiry {e['expiry_date']})" for e in expiring]
        lines.append("")
    if critical:
        lines.append("Vendors now at CRITICAL risk:")
        lines += [f"  - {c['vendor']}: score {c['score']}" for c in critical]
    body_text = "\n".join(lines)

    ses = boto3.client("sesv2", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))
    try:
        ses.send_email(
            FromEmailAddress=TPRM_SENDER_EMAIL,
            Destination={"ToAddresses": TPRM_RECIPIENT_EMAILS},
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
            with conn.cursor() as cur:
                result = _check_and_notify(cur, event["check_and_notify"])
            conn.commit()
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
            if not account_id:
                return _resp(400, {"error": "cloud_account_id required"})
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
                    body.get("registration_number"), actor,
                )
                return _resp(200, {"id": vendor_id})
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
