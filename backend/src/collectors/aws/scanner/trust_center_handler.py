"""
trust_center_handler.py

Trust Center (GitHub issue #258), v1.

Same dispatch pattern as questionnaire_handler.py: API Gateway proxy events
for CRUD, {"migrate": true} for one-time admin setup.

Honesty constraints this file is built around:
  - Compliance status shown is the account's real, live per-framework score
    — the exact same credit-based query get-dashboard-data uses (copied
    verbatim, not reimplemented), so this can never disagree with the
    dashboard the way an independently-written query risks doing. Each
    framework also carries a real "last verified" timestamp (MAX(detected_at)
    across its findings), which is the honest analogue of "this certificate
    hasn't expired" — continuous scan data replacing a point-in-time
    certificate is literally the problem the issue describes solving.
  - Documents are real files the account uploads itself (security policies,
    DPAs, whitepapers they actually have) stored in S3. Nothing here
    fabricates a SOC report, a penetration-test summary, an uptime history,
    or an incident history — this codebase has no real data source for any
    of those, and no plausible-looking placeholder is generated in their
    place. See docs/internal/architecture/aws/trust_center.md for the full
    scope decision (what's built vs. explicitly not built and why).
  - Every document access (public download, restricted-access request,
    approval, denial, version upload) is written to
    trust_document_audit_log — real audit logging, not a checkbox.
"""

import base64
import json
import logging
import os
import secrets
from datetime import datetime, timezone

import boto3
import psycopg2
from botocore.exceptions import ClientError
from psycopg2.extras import Json

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}

DOCS_BUCKET = os.environ.get("TRUST_CENTER_BUCKET", "niagaros-trust-center-documents")
ACCESS_TOKEN_DAYS = 30

# Real SES sending. The account's SES production access request was
# submitted and denied (case 178854954000928) because no sending domain is
# verified yet — only this one personal address. Until a verified
# niagaros.com identity + a re-approved production access request land,
# this can only deliver to SES-verified recipients; every attempt's real
# outcome (sent/failed + AWS's own error) is recorded rather than assumed.
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL", "bottomclipzz@gmail.com")
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "https://main.d3joqokkaynfaq.amplifyapp.com")

# Matches the "Trust Documents" list in issue #258's proposed solution.
DOCUMENT_CATEGORIES = {
    "policy": "Security Policy",
    "privacy": "Privacy Policy",
    "dpa": "Data Processing Agreement (DPA)",
    "whitepaper": "Security Whitepaper",
    "pentest": "Penetration Test Summary",
    "soc_report": "SOC Report",
    "iso_certificate": "ISO Certificate",
    "subprocessor_list": "Subprocessor List",
    "bcdr": "Business Continuity & Disaster Recovery",
    "other": "Other",
}

# "Security Posture" section from issue #258 — built only from real,
# already-published security documentation (the same evidence_documents
# table Questionnaire Automation seeds from docs/public/security/**/*.md).
# A topic with no matching real document shows as not yet published
# instead of guessing at content that doesn't exist.
SECURITY_POSTURE_TOPICS = [
    ("Encryption & Data Protection", "docs/public/security/data_protection/data_protection.md"),
    ("Identity & Access Management", "docs/public/security/identity_and_access_management/identity_and_access_management.md"),
    ("Infrastructure Security", "docs/public/security/blue_team/infrastructure_protection.md"),
    ("Vulnerability Management", "docs/public/security/red_team/penetration_tests.md"),
]

# Identical to the CASE mapping in get-dashboard-data's per-service query —
# copied verbatim rather than reimplemented, so a Trust Center score can
# never silently disagree with the dashboard's own number for the same
# account. Only real, named compliance frameworks are included; the raw
# per-service buckets (S3/IAM/CloudWatch/etc.) are internal detail, not
# something an external auditor or prospect needs to see.
FRAMEWORK_CASE_SQL = """
    CASE
        WHEN f.framework = 'ISO 27001:2022' THEN 'ISO27001'
        WHEN f.framework = 'NIST CSF v2.0'  THEN 'NIST'
        WHEN f.framework = 'GDPR'            THEN 'GDPR'
        WHEN f.framework = 'SOC2'            THEN 'SOC2'
        WHEN f.framework = 'PCI DSS v4.0'   THEN 'PCIDSS'
        WHEN f.framework = 'NIS2'            THEN 'NIS2'
        WHEN f.framework = 'HIPAA'           THEN 'HIPAA'
        WHEN f.framework = 'NIST 800-53 Rev 5' THEN 'NIST80053'
        WHEN f.framework = 'BSI-C5'          THEN 'BSIC5'
        WHEN f.framework = 'CSA CCM 4.0'     THEN 'CSACCM'
        WHEN f.framework = 'FedRAMP Moderate Rev 4' THEN 'FEDRAMP'
        WHEN f.framework = 'ISO 42001'       THEN 'ISO42001'
        WHEN f.framework = 'ISO 27017'       THEN 'ISO27017'
        WHEN f.framework = 'AWS FTR'         THEN 'AWSFTR'
        WHEN f.framework = 'MVSP'            THEN 'MVSP'
        WHEN f.framework = 'TISAX'           THEN 'TISAX'
        WHEN f.framework = 'HITRUST CSF'     THEN 'HITRUST'
        WHEN f.framework = 'DORA'            THEN 'DORA'
        WHEN f.framework = 'CRI Profile'     THEN 'CRIPROFILE'
        WHEN f.framework = 'EU AI Act'       THEN 'EUAIACT'
        WHEN f.framework = 'NIST AI RMF'     THEN 'NISTAIRMF'
        WHEN f.framework = 'ISO 27701'       THEN 'ISO27701'
        WHEN f.framework = 'ISO 27018'       THEN 'ISO27018'
        WHEN f.framework = 'Microsoft SSPA'  THEN 'SSPA'
        WHEN f.framework = 'CIS Controls v8.1' THEN 'CISCTRL'
        WHEN f.framework = '23 NYCRR 500 (NYDFS)' THEN 'NYDFS'
        WHEN f.framework = 'NIST Privacy Framework' THEN 'NISTPRIV'
        WHEN f.framework = 'CIS AWS Foundations Benchmark v5.0.0' THEN 'CISAWS'
        WHEN f.framework = 'AWS Foundational Security Best Practices' THEN 'FSBP'
        ELSE NULL
    END
"""

FRAMEWORK_LABELS = {
    "ISO27001": "ISO/IEC 27001:2022", "NIST": "NIST CSF v2.0", "GDPR": "GDPR", "SOC2": "SOC 2",
    "PCIDSS": "PCI DSS v4.0", "NIS2": "NIS2", "HIPAA": "HIPAA", "NIST80053": "NIST SP 800-53 Rev 5",
    "BSIC5": "BSI C5", "CSACCM": "CSA CCM 4.0", "FEDRAMP": "FedRAMP Moderate", "ISO42001": "ISO 42001:2023",
    "ISO27017": "ISO 27017:2015", "AWSFTR": "AWS FTR", "MVSP": "MVSP", "TISAX": "TISAX",
    "HITRUST": "HITRUST CSF", "DORA": "DORA", "CRIPROFILE": "CRI Profile", "EUAIACT": "EU AI Act",
    "NISTAIRMF": "NIST AI RMF", "ISO27701": "ISO 27701", "ISO27018": "ISO 27018", "SSPA": "Microsoft SSPA",
    "CISCTRL": "CIS Controls v8.1", "NYDFS": "23 NYCRR 500 (NYDFS)", "NISTPRIV": "NIST Privacy Framework",
    "CISAWS": "CIS AWS Foundations Benchmark", "FSBP": "AWS Foundational Security Best Practices",
}

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS trust_center_settings (
    cloud_account_id UUID         PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    is_public        BOOLEAN      NOT NULL DEFAULT FALSE,
    public_slug      VARCHAR(64)  NOT NULL UNIQUE,
    company_name     VARCHAR(255),
    intro_text       TEXT,
    contact_email    VARCHAR(255),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS trust_documents (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    title            VARCHAR(255) NOT NULL,
    category         VARCHAR(50)  NOT NULL DEFAULT 'other',
    visibility       VARCHAR(20)  NOT NULL DEFAULT 'restricted',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
-- category values: policy, privacy, dpa, whitepaper, pentest, soc_report,
-- iso_certificate, subprocessor_list, bcdr, other -- see DOCUMENT_CATEGORIES
CREATE TABLE IF NOT EXISTS trust_document_versions (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id    UUID         NOT NULL REFERENCES trust_documents(id) ON DELETE CASCADE,
    version_number INT          NOT NULL,
    s3_key         VARCHAR(500) NOT NULL,
    filename       VARCHAR(255) NOT NULL,
    changelog      TEXT,
    uploaded_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS trust_document_access_requests (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id      UUID         NOT NULL REFERENCES trust_documents(id) ON DELETE CASCADE,
    requester_name   VARCHAR(255) NOT NULL,
    requester_email  VARCHAR(255) NOT NULL,
    reason           TEXT,
    status           VARCHAR(20)  NOT NULL DEFAULT 'pending',
    access_token     VARCHAR(64),
    token_expires_at TIMESTAMPTZ,
    requested_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    decided_at       TIMESTAMPTZ,
    decided_by       VARCHAR(255)
);
CREATE TABLE IF NOT EXISTS trust_document_audit_log (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID         NOT NULL REFERENCES trust_documents(id) ON DELETE CASCADE,
    actor       VARCHAR(255),
    action      VARCHAR(30)  NOT NULL,
    at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS trust_documents_account_idx ON trust_documents(cloud_account_id);
CREATE INDEX IF NOT EXISTS trust_document_versions_doc_idx ON trust_document_versions(document_id);
CREATE INDEX IF NOT EXISTS trust_document_access_requests_doc_idx ON trust_document_access_requests(document_id);
CREATE INDEX IF NOT EXISTS trust_document_access_requests_token_idx ON trust_document_access_requests(access_token);
CREATE INDEX IF NOT EXISTS trust_document_audit_log_doc_idx ON trust_document_audit_log(document_id);
"""

ADMIN_MIGRATION_SQL = BOOTSTRAP_SQL + """
ALTER TABLE trust_document_access_requests
    ADD COLUMN IF NOT EXISTS nda_accepted_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS nda_accepted_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS email_status      VARCHAR(20),
    ADD COLUMN IF NOT EXISTS email_error       TEXT;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_center_settings TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_documents TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_document_versions TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_document_access_requests TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_document_audit_log TO cspm_lambda;
"""


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


def _ses():
    return boto3.client("ses", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))


def _send_approval_email(requester_email, requester_name, document_title, company_name, download_url):
    """Real SES send attempt. Returns (status, error) — never fakes success;
    a sandbox rejection is recorded as 'failed' with AWS's own error text so
    the admin UI can fall back to the manual copy-link honestly."""
    subject = f"Access approved: {document_title}"
    body = (
        f"Hi {requester_name},\n\n"
        f"Your request to access \"{document_title}\" from the "
        f"{company_name or 'Trust Center'} has been approved.\n\n"
        f"Download it here (link expires in {ACCESS_TOKEN_DAYS} days):\n{download_url}\n\n"
        f"If you didn't request this, you can ignore this email.\n"
    )
    try:
        _ses().send_email(
            Source=SES_SENDER_EMAIL,
            Destination={"ToAddresses": [requester_email]},
            Message={"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}},
        )
        return "sent", None
    except ClientError as e:
        return "failed", e.response.get("Error", {}).get("Message", str(e))


# ── settings ──────────────────────────────────────────────────────────

def _get_or_create_settings(cur, cloud_account_id):
    cur.execute("""
        SELECT cloud_account_id, is_public, public_slug, company_name, intro_text, contact_email
        FROM trust_center_settings WHERE cloud_account_id = %s
    """, (cloud_account_id,))
    row = cur.fetchone()
    if row:
        return {"cloud_account_id": str(row[0]), "is_public": row[1], "public_slug": row[2],
                "company_name": row[3], "intro_text": row[4], "contact_email": row[5]}
    slug = secrets.token_urlsafe(6).lower().replace("_", "").replace("-", "")
    cur.execute("""
        INSERT INTO trust_center_settings (cloud_account_id, public_slug)
        VALUES (%s, %s)
        RETURNING cloud_account_id, is_public, public_slug, company_name, intro_text, contact_email
    """, (cloud_account_id, slug))
    row = cur.fetchone()
    return {"cloud_account_id": str(row[0]), "is_public": row[1], "public_slug": row[2],
            "company_name": row[3], "intro_text": row[4], "contact_email": row[5]}


def _update_settings(conn, cloud_account_id, is_public=None, company_name=None, intro_text=None, contact_email=None):
    with conn:
        with conn.cursor() as cur:
            _get_or_create_settings(cur, cloud_account_id)
            sets, params = [], []
            if is_public is not None:
                sets.append("is_public = %s"); params.append(is_public)
            if company_name is not None:
                sets.append("company_name = %s"); params.append(company_name)
            if intro_text is not None:
                sets.append("intro_text = %s"); params.append(intro_text)
            if contact_email is not None:
                sets.append("contact_email = %s"); params.append(contact_email)
            if sets:
                sets.append("updated_at = NOW()")
                params.append(cloud_account_id)
                cur.execute(f"UPDATE trust_center_settings SET {', '.join(sets)} WHERE cloud_account_id = %s", params)


# ── compliance status (reused verbatim from get-dashboard-data) ─────────

def _get_compliance_status(cur, cloud_account_id):
    cur.execute(f"""
        SELECT service, SUM(passed_credit) AS passed, SUM(passed_credit + failed_credit) AS total,
               MAX(detected_at) AS last_verified
        FROM (
            SELECT
                {FRAMEWORK_CASE_SQL} AS service,
                COALESCE((f.details->>'passed')::int, CASE WHEN f.result = 'PASS' THEN 1 ELSE 0 END) AS passed_credit,
                COALESCE((f.details->>'failed')::int, CASE WHEN f.result = 'FAIL' THEN 1 ELSE 0 END) AS failed_credit,
                f.detected_at
            FROM findings f
            JOIN resources r ON f.resource_id = r.id
            WHERE r.cloud_account_id = %s
        ) sub
        WHERE service IS NOT NULL
        GROUP BY service
        ORDER BY SUM(passed_credit) * 100.0 / NULLIF(SUM(passed_credit + failed_credit), 0) DESC NULLS LAST
    """, (cloud_account_id,))
    out = []
    for service, passed, total, last_verified in cur.fetchall():
        if not total:
            continue
        out.append({
            "framework": FRAMEWORK_LABELS.get(service, service),
            "score": round(passed * 100.0 / total, 1),
            "last_verified": last_verified.isoformat() if last_verified else None,
        })
    return out


# ── documents ─────────────────────────────────────────────────────────

def _list_documents_admin(cur, cloud_account_id):
    cur.execute("""
        SELECT id, title, category, visibility, created_at FROM trust_documents
        WHERE cloud_account_id = %s ORDER BY created_at DESC
    """, (cloud_account_id,))
    docs = [{"id": str(r[0]), "title": r[1], "category": r[2], "visibility": r[3], "created_at": r[4].isoformat()}
            for r in cur.fetchall()]
    for d in docs:
        cur.execute("""
            SELECT version_number, filename, changelog, uploaded_at FROM trust_document_versions
            WHERE document_id = %s ORDER BY version_number DESC
        """, (d["id"],))
        d["versions"] = [{"version_number": r[0], "filename": r[1], "changelog": r[2], "uploaded_at": r[3].isoformat()}
                          for r in cur.fetchall()]
    return docs


def _upload_document(conn, cloud_account_id, title, category, visibility, filename, file_base64, actor):
    raw = base64.b64decode(file_base64)
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO trust_documents (cloud_account_id, title, category, visibility)
                VALUES (%s, %s, %s, %s) RETURNING id
            """, (cloud_account_id, title, category, visibility))
            document_id = str(cur.fetchone()[0])
            s3_key = f"trust-center/{cloud_account_id}/{document_id}/v1-{filename}"
            _s3().put_object(Bucket=DOCS_BUCKET, Key=s3_key, Body=raw, ServerSideEncryption="AES256")
            cur.execute("""
                INSERT INTO trust_document_versions (document_id, version_number, s3_key, filename)
                VALUES (%s, 1, %s, %s)
            """, (document_id, s3_key, filename))
            cur.execute("""
                INSERT INTO trust_document_audit_log (document_id, actor, action) VALUES (%s, %s, 'uploaded_version')
            """, (document_id, actor))
    return document_id


def _upload_new_version(conn, cloud_account_id, document_id, filename, file_base64, changelog, actor):
    raw = base64.b64decode(file_base64)
    with conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(version_number), 0) + 1 FROM trust_document_versions WHERE document_id = %s",
                        (document_id,))
            version_number = cur.fetchone()[0]
            s3_key = f"trust-center/{cloud_account_id}/{document_id}/v{version_number}-{filename}"
            _s3().put_object(Bucket=DOCS_BUCKET, Key=s3_key, Body=raw, ServerSideEncryption="AES256")
            cur.execute("""
                INSERT INTO trust_document_versions (document_id, version_number, s3_key, filename, changelog)
                VALUES (%s, %s, %s, %s, %s)
            """, (document_id, version_number, s3_key, filename, changelog))
            cur.execute("""
                INSERT INTO trust_document_audit_log (document_id, actor, action) VALUES (%s, %s, 'uploaded_version')
            """, (document_id, actor))
    return version_number


def _presign_latest(cur, document_id, expires_in=900):
    cur.execute("""
        SELECT s3_key, filename FROM trust_document_versions
        WHERE document_id = %s ORDER BY version_number DESC LIMIT 1
    """, (document_id,))
    row = cur.fetchone()
    if not row:
        return None
    s3_key, filename = row
    url = _s3().generate_presigned_url(
        "get_object",
        Params={"Bucket": DOCS_BUCKET, "Key": s3_key, "ResponseContentDisposition": f'attachment; filename="{filename}"'},
        ExpiresIn=expires_in,
    )
    return url


# ── access requests ───────────────────────────────────────────────────

def _request_access(conn, document_id, requester_name, requester_email, reason, nda_accepted_name):
    """nda_accepted_name is the requester's typed full legal name, captured as
    a real, timestamped confidentiality acknowledgement — the click-through
    step issue #258's restricted-document flow was missing entirely."""
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO trust_document_access_requests
                    (document_id, requester_name, requester_email, reason, nda_accepted_name, nda_accepted_at)
                VALUES (%s, %s, %s, %s, %s, NOW()) RETURNING id
            """, (document_id, requester_name, requester_email, reason, nda_accepted_name))
            request_id = str(cur.fetchone()[0])
            cur.execute("""
                INSERT INTO trust_document_audit_log (document_id, actor, action) VALUES (%s, %s, 'requested')
            """, (document_id, requester_email))
            cur.execute("""
                INSERT INTO trust_document_audit_log (document_id, actor, action) VALUES (%s, %s, 'nda_accepted')
            """, (document_id, requester_email))
    return request_id


def _list_access_requests(cur, cloud_account_id):
    cur.execute("""
        SELECT ar.id, ar.document_id, td.title, ar.requester_name, ar.requester_email, ar.reason,
               ar.status, ar.requested_at, ar.access_token, ar.token_expires_at,
               ar.nda_accepted_name, ar.nda_accepted_at, ar.email_status, ar.email_error
        FROM trust_document_access_requests ar
        JOIN trust_documents td ON td.id = ar.document_id
        WHERE td.cloud_account_id = %s
        ORDER BY ar.requested_at DESC
    """, (cloud_account_id,))
    return [{
        "id": str(r[0]), "document_id": str(r[1]), "document_title": r[2], "requester_name": r[3],
        "requester_email": r[4], "reason": r[5], "status": r[6], "requested_at": r[7].isoformat(),
        "access_token": r[8], "token_expires_at": r[9].isoformat() if r[9] else None,
        "nda_accepted_name": r[10], "nda_accepted_at": r[11].isoformat() if r[11] else None,
        "email_status": r[12], "email_error": r[13],
    } for r in cur.fetchall()]


def _decide_access_request(conn, request_id, approve, decided_by):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT ar.document_id, ar.requester_name, ar.requester_email, td.title, tcs.company_name
                FROM trust_document_access_requests ar
                JOIN trust_documents td ON td.id = ar.document_id
                LEFT JOIN trust_center_settings tcs ON tcs.cloud_account_id = td.cloud_account_id
                WHERE ar.id = %s
            """, (request_id,))
            row = cur.fetchone()
            if not row:
                return None
            document_id, requester_name, requester_email, doc_title, company_name = row
            token, email_status, email_error = None, None, None
            if approve:
                token = secrets.token_urlsafe(24)
                cur.execute("""
                    UPDATE trust_document_access_requests
                    SET status = 'approved', decided_at = NOW(), decided_by = %s,
                        access_token = %s, token_expires_at = NOW() + (%s || ' days')::interval
                    WHERE id = %s
                """, (decided_by, token, ACCESS_TOKEN_DAYS, request_id))
                download_url = f"{FRONTEND_BASE_URL}/trust_center_public.html?download={document_id}&token={token}"
                email_status, email_error = _send_approval_email(
                    requester_email, requester_name, doc_title, company_name, download_url)
                cur.execute("""
                    UPDATE trust_document_access_requests SET email_status = %s, email_error = %s WHERE id = %s
                """, (email_status, email_error, request_id))
                action = "approved_email_sent" if email_status == "sent" else "approved_email_failed"
            else:
                cur.execute("""
                    UPDATE trust_document_access_requests
                    SET status = 'denied', decided_at = NOW(), decided_by = %s
                    WHERE id = %s
                """, (decided_by, request_id))
                action = "denied"
            cur.execute("""
                INSERT INTO trust_document_audit_log (document_id, actor, action) VALUES (%s, %s, %s)
            """, (document_id, decided_by, action))
    return {"access_token": token, "email_status": email_status, "email_error": email_error}


def _get_audit_log(cur, cloud_account_id, document_id=None):
    query = """
        SELECT al.document_id, td.title, al.actor, al.action, al.at
        FROM trust_document_audit_log al
        JOIN trust_documents td ON td.id = al.document_id
        WHERE td.cloud_account_id = %s
    """
    params = [cloud_account_id]
    if document_id:
        query += " AND al.document_id = %s"
        params.append(document_id)
    query += " ORDER BY al.at DESC LIMIT 200"
    cur.execute(query, params)
    return [{"document_id": str(r[0]), "document_title": r[1], "actor": r[2], "action": r[3], "at": r[4].isoformat()}
            for r in cur.fetchall()]


# ── security posture (reused from evidence_documents) ───────────────────

def _get_security_posture(cur):
    out = []
    for topic, source_path in SECURITY_POSTURE_TOPICS:
        cur.execute("""
            SELECT content FROM evidence_documents
            WHERE source_path = %s
            ORDER BY (section_title = '(intro)') DESC, id
            LIMIT 1
        """, (source_path,))
        row = cur.fetchone()
        out.append({"topic": topic, "content": row[0] if row else None})
    return out


# ── questionnaire answer reuse (AC #5) ──────────────────────────────────
# Reuses the same grouping shape as questionnaire_handler.py's answer
# library (group approved answers by exact question, newest first) rather
# than importing across Lambdas — each mapper/handler in this codebase is
# already self-contained. Only ever approved, human-reviewed answers;
# never a draft.

def _get_public_qa_highlights(cur, cloud_account_id, limit=12):
    cur.execute("""
        SELECT DISTINCT ON (qi.question_text) qi.question_text, qi.answer_text, qi.reviewed_at
        FROM questionnaire_items qi
        JOIN questionnaires q ON q.id = qi.questionnaire_id
        WHERE q.cloud_account_id = %s AND qi.answer_status = 'approved' AND qi.answer_text IS NOT NULL
        ORDER BY qi.question_text, qi.reviewed_at DESC NULLS LAST
        LIMIT %s
    """, (cloud_account_id, limit))
    return [{"question": r[0], "answer": r[1], "approved_at": r[2].isoformat() if r[2] else None}
            for r in cur.fetchall()]


# ── public view ───────────────────────────────────────────────────────

def _get_public_view(cur, slug):
    cur.execute("""
        SELECT cloud_account_id, is_public, company_name, intro_text, contact_email
        FROM trust_center_settings WHERE public_slug = %s
    """, (slug,))
    row = cur.fetchone()
    if not row or not row[1]:
        return None
    cloud_account_id, _, company_name, intro_text, contact_email = row

    compliance = _get_compliance_status(cur, cloud_account_id)

    cur.execute("""
        SELECT id, title, category, visibility FROM trust_documents
        WHERE cloud_account_id = %s ORDER BY category, title
    """, (cloud_account_id,))
    documents = []
    for doc_id, title, category, visibility in cur.fetchall():
        entry = {"id": str(doc_id), "title": title, "category": DOCUMENT_CATEGORIES.get(category, category),
                  "visibility": visibility}
        if visibility == "public":
            entry["download_url"] = _presign_latest(cur, doc_id)
            cur.execute("INSERT INTO trust_document_audit_log (document_id, actor, action) VALUES (%s, %s, 'viewed')",
                        (doc_id, "public"))
        documents.append(entry)

    security_posture = _get_security_posture(cur)
    qa_highlights = _get_public_qa_highlights(cur, cloud_account_id)

    return {
        "company_name": company_name, "intro_text": intro_text, "contact_email": contact_email,
        "compliance": compliance, "documents": documents,
        "security_posture": security_posture, "qa_highlights": qa_highlights,
    }


def _download_restricted(cur, document_id, access_token):
    cur.execute("""
        SELECT status, token_expires_at FROM trust_document_access_requests
        WHERE document_id = %s AND access_token = %s
    """, (document_id, access_token))
    row = cur.fetchone()
    if not row or row[0] != "approved" or row[1] < datetime.now(timezone.utc):
        return None
    url = _presign_latest(cur, document_id)
    if url:
        cur.execute("INSERT INTO trust_document_audit_log (document_id, actor, action) VALUES (%s, %s, 'downloaded')",
                    (document_id, f"token:{access_token[:8]}..."))
    return url


# ── entrypoint ────────────────────────────────────────────────────────

def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body)}


def handler(event, context):
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
            if qs.get("slug"):
                view = _get_public_view(conn.cursor(), qs["slug"])
                conn.commit()
                if not view:
                    return _resp(404, {"error": "Deze Trust Center-pagina bestaat niet of is niet openbaar."})
                return _resp(200, view)

            if qs.get("download_document") and qs.get("access_token"):
                with conn.cursor() as cur:
                    url = _download_restricted(cur, qs["download_document"], qs["access_token"])
                conn.commit()
                if not url:
                    return _resp(403, {"error": "Deze link is ongeldig, verlopen, of nog niet goedgekeurd."})
                return _resp(200, {"download_url": url})

            account_id = qs.get("cloud_account_id")
            if not account_id:
                return _resp(400, {"error": "cloud_account_id required"})
            with conn.cursor() as cur:
                if qs.get("audit_log"):
                    return _resp(200, {"entries": _get_audit_log(cur, account_id, qs.get("document_id"))})
                if qs.get("access_requests"):
                    return _resp(200, {"requests": _list_access_requests(cur, account_id)})
                settings = _get_or_create_settings(cur, account_id)
                conn.commit()
                documents = _list_documents_admin(cur, account_id)
                compliance = _get_compliance_status(cur, account_id)
                return _resp(200, {"settings": settings, "documents": documents, "compliance": compliance})

        if method == "POST":
            action = body.get("action")
            if action == "update_settings":
                _update_settings(conn, body["cloud_account_id"], body.get("is_public"), body.get("company_name"),
                                  body.get("intro_text"), body.get("contact_email"))
                return _resp(200, {"updated": True})
            if action == "upload_document":
                doc_id = _upload_document(conn, body["cloud_account_id"], body["title"], body.get("category", "other"),
                                           body.get("visibility", "restricted"), body["filename"], body["file_base64"],
                                           body.get("actor_name", "Admin"))
                return _resp(200, {"id": doc_id})
            if action == "upload_new_version":
                v = _upload_new_version(conn, body["cloud_account_id"], body["document_id"], body["filename"],
                                         body["file_base64"], body.get("changelog"), body.get("actor_name", "Admin"))
                return _resp(200, {"version_number": v})
            if action == "request_access":
                nda_name = (body.get("nda_accepted_name") or "").strip()
                if not nda_name:
                    return _resp(400, {"error": "Confidentiality acknowledgement (typed full name) is required."})
                req_id = _request_access(conn, body["document_id"], body["requester_name"], body["requester_email"],
                                          body.get("reason", ""), nda_name)
                return _resp(200, {"id": req_id})
            if action == "decide_access_request":
                result = _decide_access_request(conn, body["request_id"], body["approve"], body.get("actor_name", "Admin"))
                if result is None:
                    return _resp(404, {"error": "access request not found"})
                return _resp(200, result)
            return _resp(400, {"error": f"unknown action: {action}"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.error("trust_center_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": str(e)})
    finally:
        conn.close()
