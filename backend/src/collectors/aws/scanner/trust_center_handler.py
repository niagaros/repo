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
import re
import secrets
import urllib.parse
import urllib.request
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

# Custom Trust Center domain (#272), e.g. trust.domits.com. A domain only serves an account's Trust Center after the
# account proved it controls that domain's DNS with a TXT record holding a per-account token, so no tenant can claim
# another company's hostname. Niagaros's own application hosts can never be claimed.
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
RESERVED_HOSTS = {"niagaros.com", "www.niagaros.com", "app.niagaros.com", "auth.niagaros.com", "api.niagaros.com",
                  "developers.niagaros.com", "docs.niagaros.com", "status.niagaros.com", "security.niagaros.com"}
DOMAIN_TXT_PREFIX = "_niagaros-trust"
DOMAIN_TXT_VALUE = "niagaros-verify={token}"
DOH_URL = os.environ.get("DOH_URL", "https://cloudflare-dns.com/dns-query")

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
ALTER TABLE trust_center_settings
    ADD COLUMN IF NOT EXISTS custom_domain             VARCHAR(253),
    ADD COLUMN IF NOT EXISTS custom_domain_token       VARCHAR(64),
    ADD COLUMN IF NOT EXISTS custom_domain_verified_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS trust_center_settings_verified_domain_uq
    ON trust_center_settings (custom_domain) WHERE custom_domain_verified_at IS NOT NULL;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_center_settings TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_documents TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_document_versions TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_document_access_requests TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_document_audit_log TO cspm_lambda;
-- migration 040 (validity, notices, branding, disclosure, analytics, settings history); kept identical to the file
ALTER TABLE trust_documents
    ADD COLUMN IF NOT EXISTS valid_from   DATE,
    ADD COLUMN IF NOT EXISTS valid_until  DATE,
    ADD COLUMN IF NOT EXISTS issuer       VARCHAR(255);
DO $$ BEGIN
    ALTER TABLE trust_documents ADD CONSTRAINT trust_documents_validity_order
        CHECK (valid_from IS NULL OR valid_until IS NULL OR valid_from <= valid_until);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE trust_center_settings
    ADD COLUMN IF NOT EXISTS brand_color        VARCHAR(7),
    ADD COLUMN IF NOT EXISTS logo_s3_key        VARCHAR(500),
    ADD COLUMN IF NOT EXISTS status_page_url    VARCHAR(500),
    ADD COLUMN IF NOT EXISTS security_contact   VARCHAR(255),
    ADD COLUMN IF NOT EXISTS disclosure_policy  TEXT;
DO $$ BEGIN
    ALTER TABLE trust_center_settings ADD CONSTRAINT trust_center_brand_color_hex
        CHECK (brand_color IS NULL OR brand_color ~ '^#[0-9a-fA-F]{6}$');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS trust_center_updates (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    kind             VARCHAR(12)  NOT NULL CHECK (kind IN ('incident', 'maintenance', 'notice')),
    title            VARCHAR(200) NOT NULL,
    body             TEXT,
    starts_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at      TIMESTAMPTZ,
    published_by     VARCHAR(255) NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS trust_center_updates_account_idx ON trust_center_updates (cloud_account_id, starts_at DESC);

CREATE TABLE IF NOT EXISTS trust_center_page_views (
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    day              DATE         NOT NULL,
    views            INTEGER      NOT NULL DEFAULT 0,
    PRIMARY KEY (cloud_account_id, day)
);

CREATE TABLE IF NOT EXISTS trust_center_events (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    actor            VARCHAR(255) NOT NULL,
    action           VARCHAR(40)  NOT NULL,
    detail           JSONB        NOT NULL DEFAULT '{}'::jsonb,
    at               TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS trust_center_events_account_idx ON trust_center_events (cloud_account_id, at DESC);

GRANT SELECT, INSERT, UPDATE ON trust_center_updates, trust_center_page_views TO cspm_lambda;
GRANT SELECT, INSERT ON trust_center_events TO cspm_lambda;
REVOKE UPDATE, DELETE, TRUNCATE ON trust_center_events FROM cspm_lambda;
REVOKE DELETE, TRUNCATE ON trust_center_updates, trust_center_page_views FROM cspm_lambda;
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

SETTINGS_COLUMNS = ("cloud_account_id, is_public, public_slug, company_name, intro_text, contact_email, "
                    "custom_domain, custom_domain_token, custom_domain_verified_at, brand_color, logo_s3_key, "
                    "status_page_url, security_contact, disclosure_policy")
EXPIRY_WARNING_DAYS = 30
UPDATE_KINDS = ("incident", "maintenance", "notice")
LOGO_MAX_BYTES = 300_000
_HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def _settings_dict(row):
    domain, token, verified_at = row[6], row[7], row[8]
    return {"cloud_account_id": str(row[0]), "is_public": row[1], "public_slug": row[2],
            "company_name": row[3], "intro_text": row[4], "contact_email": row[5],
            "custom_domain": _domain_info(domain, token, verified_at),
            "brand_color": row[9], "logo_url": _presign_key(row[10]) if row[10] else None,
            "status_page_url": row[11], "security_contact": row[12], "disclosure_policy": row[13]}


def _presign_key(key, expires_in=3600):
    try:
        return _s3().generate_presigned_url("get_object", Params={"Bucket": DOCS_BUCKET, "Key": key}, ExpiresIn=expires_in)
    except Exception:  # noqa: BLE001 - a logo that cannot be signed is simply not shown
        return None


def _doc_status(valid_until, today=None, valid_from=None):
    """Validity of a certificate or report, recalculated at every read (never stored), so an expired document can
    never keep showing as current, and one that has not started yet never shows as valid."""
    today = today or datetime.now(timezone.utc).date()
    if valid_from and valid_from > today:
        return "not_yet_valid"
    if not valid_until:
        return "no_expiry"
    if valid_until < today:
        return "expired"
    if (valid_until - today).days <= EXPIRY_WARNING_DAYS:
        return "expiring_soon"
    return "valid"


def _account_event(cur, cloud_account_id, actor, action, detail=None):
    cur.execute("INSERT INTO trust_center_events (cloud_account_id, actor, action, detail) VALUES (%s, %s, %s, %s)",
                (cloud_account_id, actor, action, Json(detail or {})))


def _get_or_create_settings(cur, cloud_account_id):
    cur.execute(f"SELECT {SETTINGS_COLUMNS} FROM trust_center_settings WHERE cloud_account_id = %s", (cloud_account_id,))
    row = cur.fetchone()
    if row:
        return _settings_dict(row)
    slug = secrets.token_urlsafe(6).lower().replace("_", "").replace("-", "")
    cur.execute(f"""
        INSERT INTO trust_center_settings (cloud_account_id, public_slug)
        VALUES (%s, %s)
        RETURNING {SETTINGS_COLUMNS}
    """, (cloud_account_id, slug))
    return _settings_dict(cur.fetchone())


# ── custom domain ─────────────────────────────────────────────────────

def normalise_domain(value):
    """'Trust.Domits.com.' -> 'trust.domits.com'; None when it is not a plain hostname Niagaros may serve."""
    if not isinstance(value, str):
        return None
    host = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(host) or host in RESERVED_HOSTS or host.endswith(".amplifyapp.com"):
        return None
    return host


def _domain_info(domain, token, verified_at):
    if not domain:
        return None
    return {"domain": domain, "verified": verified_at is not None,
            "verified_at": verified_at.isoformat() if verified_at else None,
            "txt_name": f"{DOMAIN_TXT_PREFIX}.{domain}", "txt_value": DOMAIN_TXT_VALUE.format(token=token)}


def _dns_lookup(name, rtype):
    """Answers for one DNS name over DNS-over-HTTPS (the Lambda has no resolver library). Raises on a lookup failure,
    so 'could not check' is never reported as 'record absent'."""
    req = urllib.request.Request(f"{DOH_URL}?name={urllib.parse.quote(name)}&type={rtype}",
                                 headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        data = json.loads(r.read())
    if data.get("Status") not in (0, 3):          # 0 NOERROR, 3 NXDOMAIN (no such name: a real "absent")
        raise RuntimeError(f"DNS lookup failed with status {data.get('Status')}")
    want = {"TXT": 16, "CNAME": 5}[rtype]
    return [a.get("data", "").strip('"') for a in data.get("Answer") or [] if a.get("type") == want]


def _set_custom_domain(conn, cloud_account_id, raw):
    """Set (or with an empty value remove) the account's custom domain. A new domain always starts unverified with a
    fresh token."""
    with conn:
        with conn.cursor() as cur:
            _get_or_create_settings(cur, cloud_account_id)
            if not (raw or "").strip():
                cur.execute("""UPDATE trust_center_settings SET custom_domain = NULL, custom_domain_token = NULL,
                               custom_domain_verified_at = NULL, updated_at = NOW() WHERE cloud_account_id = %s""",
                            (cloud_account_id,))
                return None
            domain = normalise_domain(raw)
            if not domain:
                raise ValueError("Enter a hostname such as trust.yourcompany.com, without https:// or a path.")
            cur.execute("SELECT custom_domain FROM trust_center_settings WHERE cloud_account_id = %s", (cloud_account_id,))
            if cur.fetchone()[0] == domain:
                return _get_or_create_settings(cur, cloud_account_id)["custom_domain"]
            cur.execute("""UPDATE trust_center_settings SET custom_domain = %s, custom_domain_token = %s,
                           custom_domain_verified_at = NULL, updated_at = NOW() WHERE cloud_account_id = %s""",
                        (domain, secrets.token_hex(16), cloud_account_id))
            return _get_or_create_settings(cur, cloud_account_id)["custom_domain"]


def _verify_custom_domain(conn, cloud_account_id):
    """Check the TXT record. Returns (http_status, body)."""
    with conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT custom_domain, custom_domain_token FROM trust_center_settings
                           WHERE cloud_account_id = %s FOR UPDATE""", (cloud_account_id,))
            row = cur.fetchone()
            if not row or not row[0]:
                return 400, {"error": "Set a custom domain first."}
            domain, token = row
            info = _domain_info(domain, token, None)
            try:
                txt = _dns_lookup(info["txt_name"], "TXT")
            except Exception as e:
                logger.warning("DNS lookup for %s failed: %s", info["txt_name"], e)
                return 503, {"error": "The DNS check could not be completed right now. Please try again in a minute."}
            if info["txt_value"] not in txt:
                # a removed record ends the verification, so the stored state always matches what DNS shows now
                cur.execute("""UPDATE trust_center_settings SET custom_domain_verified_at = NULL, updated_at = NOW()
                               WHERE cloud_account_id = %s AND custom_domain_verified_at IS NOT NULL""", (cloud_account_id,))
                return 200, {"verified": False, "custom_domain": info,
                             "message": f"The TXT record {info['txt_name']} was not found yet. DNS changes can take up to an hour."}
            cur.execute("""SELECT 1 FROM trust_center_settings WHERE custom_domain = %s
                           AND custom_domain_verified_at IS NOT NULL AND cloud_account_id <> %s""", (domain, cloud_account_id))
            if cur.fetchone():
                return 409, {"error": "This domain is already connected to another Trust Center."}
            cur.execute("""UPDATE trust_center_settings SET custom_domain_verified_at = NOW(), updated_at = NOW()
                           WHERE cloud_account_id = %s AND custom_domain_verified_at IS NULL""", (cloud_account_id,))
            return 200, {"verified": True, "custom_domain": _get_or_create_settings(cur, cloud_account_id)["custom_domain"]}


def _slug_for_domain(cur, host):
    domain = normalise_domain(host)
    if not domain:
        return None
    cur.execute("""SELECT public_slug FROM trust_center_settings
                   WHERE custom_domain = %s AND custom_domain_verified_at IS NOT NULL""", (domain,))
    row = cur.fetchone()
    return row[0] if row else None


def _validate_settings(body):
    """Raises ValueError with a user-facing message; returns the cleaned optional fields."""
    out = {}
    if body.get("brand_color") not in (None, ""):
        if not _HEX_RE.match(str(body["brand_color"])):
            raise ValueError("Brand colour must look like #1D4ED8")
        out["brand_color"] = body["brand_color"]
    elif "brand_color" in body:
        out["brand_color"] = None
    if body.get("status_page_url") not in (None, ""):
        u = urllib.parse.urlparse(str(body["status_page_url"]).strip())
        if u.scheme != "https" or not u.netloc or len(body["status_page_url"]) > 500:
            raise ValueError("Status page must be an https:// address")
        out["status_page_url"] = str(body["status_page_url"]).strip()
    elif "status_page_url" in body:
        out["status_page_url"] = None
    if body.get("security_contact") not in (None, ""):
        if not _EMAIL_RE.match(str(body["security_contact"]).strip()):
            raise ValueError("Security contact must be an email address")
        out["security_contact"] = str(body["security_contact"]).strip()
    elif "security_contact" in body:
        out["security_contact"] = None
    if "disclosure_policy" in body:
        dp = (body.get("disclosure_policy") or "").strip()
        if len(dp) > 5000:
            raise ValueError("The disclosure policy can be at most 5000 characters")
        out["disclosure_policy"] = dp or None
    return out


def _update_settings(conn, cloud_account_id, is_public=None, company_name=None, intro_text=None, contact_email=None,
                     extra=None, actor="Admin"):
    with conn:
        with conn.cursor() as cur:
            _get_or_create_settings(cur, cloud_account_id)
            sets, params = [], []
            for k, v in (extra or {}).items():
                sets.append(f"{k} = %s"); params.append(v)
            if is_public is not None:
                sets.append("is_public = %s"); params.append(is_public)
            if company_name is not None:
                sets.append("company_name = %s"); params.append(company_name)
            if intro_text is not None:
                sets.append("intro_text = %s"); params.append(intro_text)
            if contact_email is not None:
                sets.append("contact_email = %s"); params.append(contact_email)
            if sets:
                changed = [s.split(" = ")[0] for s in sets]
                sets.append("updated_at = NOW()")
                params.append(cloud_account_id)
                cur.execute(f"UPDATE trust_center_settings SET {', '.join(sets)} WHERE cloud_account_id = %s", params)
                _account_event(cur, cloud_account_id, actor, "settings_updated", {"fields": changed})


# ── compliance status ────────────────────────────────────────────────────
#
# Corrected 2026-09-08: this used to give "credit" for the underlying raw
# checks embedded in a control's own details.passed/details.failed (e.g. a
# CIS Controls v8.1 row that FAILS overall because 1 of its 5 underlying
# checks failed still contributed 4 "passed" credits) — a fundamentally
# different, more lenient scoring method than every other place in this
# product (the dashboard's own services aggregation, and every standalone
# framework page), which count one control row as one pass/fail, full
# stop. That made Trust Center — the one page an external auditor or
# prospect actually sees — show a meaningfully HIGHER, rosier score
# (e.g. 88.5%) than the real, control-level number (52.9%) shown
# everywhere else for the exact same account and framework. Fixed to use
# the same plain per-row COUNT(*) FILTER the rest of the app uses, so this
# can never again silently disagree with the dashboard's own number.
def _get_compliance_status(cur, cloud_account_id):
    cur.execute(f"""
        SELECT service, COUNT(*) FILTER (WHERE result = 'PASS') AS passed,
               COUNT(*) AS total, MAX(detected_at) AS last_verified
        FROM (
            SELECT
                {FRAMEWORK_CASE_SQL} AS service,
                f.result,
                f.detected_at
            FROM findings f
            JOIN resources r ON f.resource_id = r.id
            WHERE r.cloud_account_id = %s
        ) sub
        WHERE service IS NOT NULL
        GROUP BY service
        ORDER BY COUNT(*) FILTER (WHERE result = 'PASS') * 100.0 / NULLIF(COUNT(*), 0) DESC NULLS LAST
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
        SELECT id, title, category, visibility, created_at, valid_from, valid_until, issuer FROM trust_documents
        WHERE cloud_account_id = %s ORDER BY created_at DESC
    """, (cloud_account_id,))
    docs = [{"id": str(r[0]), "title": r[1], "category": r[2], "visibility": r[3], "created_at": r[4].isoformat(),
             "valid_from": r[5].isoformat() if r[5] else None, "valid_until": r[6].isoformat() if r[6] else None,
             "issuer": r[7], "validity_status": _doc_status(r[6], valid_from=r[5])}
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
                # Always the Niagaros host: a verified custom domain may not serve HTTPS yet
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


# ── validity, logo, notices, analytics ────────────────────────────────

def _set_document_validity(conn, cloud_account_id, document_id, valid_from, valid_until, issuer, actor):
    from datetime import date as _date

    def d(v, what):
        if v in (None, ""):
            return None
        try:
            return _date.fromisoformat(str(v)[:10])
        except ValueError:
            raise ValueError(f"{what} must be a date (YYYY-MM-DD)")
    vf, vu = d(valid_from, "Valid from"), d(valid_until, "Valid until")
    if vf and vu and vf > vu:
        raise ValueError("Valid from must be before valid until")
    issuer = (issuer or "").strip()[:255] or None
    with conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE trust_documents SET valid_from = %s, valid_until = %s, issuer = %s
                           WHERE id = %s AND cloud_account_id = %s""", (vf, vu, issuer, document_id, cloud_account_id))
            if cur.rowcount != 1:
                return None
            cur.execute("INSERT INTO trust_document_audit_log (document_id, actor, action) VALUES (%s, %s, 'validity_updated')",
                        (document_id, actor))
    return {"valid_from": vf.isoformat() if vf else None, "valid_until": vu.isoformat() if vu else None,
            "validity_status": _doc_status(vu, valid_from=vf)}


def _upload_logo(conn, cloud_account_id, filename, file_base64, actor):
    try:
        raw = base64.b64decode(file_base64 or "", validate=True)
    except Exception:
        raise ValueError("The logo could not be read")
    if len(raw) > LOGO_MAX_BYTES:
        raise ValueError("The logo can be at most 300 KB")
    # Only raster formats (an SVG can carry script), checked by their structure, not only the first bytes.
    import struct
    if raw[:8] == b"\x89PNG\r\n\x1a\n" and raw[12:16] == b"IHDR" and b"IEND" in raw[-12:]:
        w, h = struct.unpack(">II", raw[16:24])
        if not (0 < w <= 4096 and 0 < h <= 4096):
            raise ValueError("The logo must be at most 4096 x 4096 pixels")
        ext, ctype = "png", "image/png"
    elif raw[:3] == b"\xff\xd8\xff" and raw[-2:] == b"\xff\xd9" and (b"\xff\xc0" in raw or b"\xff\xc2" in raw):
        ext, ctype = "jpg", "image/jpeg"
    else:
        raise ValueError("Upload the logo as a complete PNG or JPEG image")
    key = f"trust-center/{cloud_account_id}/branding/logo-{secrets.token_hex(6)}.{ext}"
    _s3().put_object(Bucket=DOCS_BUCKET, Key=key, Body=raw, ContentType=ctype, ServerSideEncryption="AES256")
    with conn:
        with conn.cursor() as cur:
            _get_or_create_settings(cur, cloud_account_id)
            cur.execute("UPDATE trust_center_settings SET logo_s3_key = %s, updated_at = NOW() WHERE cloud_account_id = %s",
                        (key, cloud_account_id))
            _account_event(cur, cloud_account_id, actor, "logo_uploaded", {"bytes": len(raw), "type": ctype})
    return _presign_key(key)


def _create_update(conn, cloud_account_id, body, actor):
    kind = body.get("kind")
    title = (body.get("title") or "").strip()
    text = (body.get("body") or "").strip()
    if kind not in UPDATE_KINDS:
        raise ValueError("Choose incident, maintenance or notice")
    if not title or len(title) > 200:
        raise ValueError("A title of at most 200 characters is required")
    if len(text) > 5000:
        raise ValueError("The text can be at most 5000 characters")
    starts = body.get("starts_at")
    try:
        starts = datetime.fromisoformat(str(starts).replace("Z", "+00:00")) if starts else datetime.now(timezone.utc)
    except ValueError:
        raise ValueError("Start must be a date and time")
    if starts.tzinfo is None:
        starts = starts.replace(tzinfo=timezone.utc)
    with conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO trust_center_updates (cloud_account_id, kind, title, body, starts_at, published_by)
                           VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""", (cloud_account_id, kind, title, text or None, starts, actor))
            uid = str(cur.fetchone()[0])
            _account_event(cur, cloud_account_id, actor, "update_published", {"id": uid, "kind": kind, "title": title})
    return uid


def _resolve_update(conn, cloud_account_id, update_id, note, actor):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE trust_center_updates SET resolved_at = NOW(), updated_at = NOW(),
                           body = CASE WHEN %s <> '' THEN COALESCE(body || E'\n\n', '') || 'Resolved: ' || %s ELSE body END
                           WHERE id = %s AND cloud_account_id = %s AND resolved_at IS NULL""",
                        (note or "", note or "", update_id, cloud_account_id))
            if cur.rowcount != 1:
                return False
            _account_event(cur, cloud_account_id, actor, "update_resolved", {"id": update_id})
    return True


def _list_updates(cur, cloud_account_id, public=False):
    cur.execute(f"""SELECT id, kind, title, body, starts_at, resolved_at, published_by FROM trust_center_updates
                    WHERE cloud_account_id = %s {"AND (resolved_at IS NULL OR starts_at > NOW() - interval '90 days')" if public else ""}
                    ORDER BY (resolved_at IS NULL) DESC, starts_at DESC LIMIT 50""", (cloud_account_id,))
    return [{"id": str(r[0]), "kind": r[1], "title": r[2], "body": r[3], "starts_at": r[4].isoformat(),
             "resolved_at": r[5].isoformat() if r[5] else None, **({} if public else {"published_by": r[6]})}
            for r in cur.fetchall()]


def _analytics(cur, cloud_account_id):
    cur.execute("""SELECT day, views FROM trust_center_page_views WHERE cloud_account_id = %s AND day > CURRENT_DATE - 30
                   ORDER BY day""", (cloud_account_id,))
    views = [{"day": d.isoformat(), "views": v} for d, v in cur.fetchall()]
    cur.execute("""SELECT d.title, count(*) FILTER (WHERE l.action = 'downloaded'), count(*) FILTER (WHERE l.action = 'viewed')
                   FROM trust_document_audit_log l JOIN trust_documents d ON d.id = l.document_id
                   WHERE d.cloud_account_id = %s AND l.at > NOW() - interval '30 days' GROUP BY d.title
                   ORDER BY 2 DESC, 3 DESC LIMIT 10""", (cloud_account_id,))
    docs = [{"title": a, "restricted_downloads": b, "listed_on_public_page": c} for a, b, c in cur.fetchall()]
    cur.execute("""SELECT r.status, count(*) FROM trust_document_access_requests r JOIN trust_documents d ON d.id = r.document_id
                   WHERE d.cloud_account_id = %s AND r.requested_at > NOW() - interval '90 days' GROUP BY 1""", (cloud_account_id,))
    reqs = dict(cur.fetchall())
    decided = reqs.get("approved", 0) + reqs.get("denied", 0)
    cur.execute("""SELECT count(*) FROM questionnaire_items qi JOIN questionnaires q ON q.id = qi.questionnaire_id
                   WHERE q.cloud_account_id = %s AND qi.answer_status = 'approved'""", (cloud_account_id,))
    approved_answers = cur.fetchone()[0]
    return {"page_loads_30d": views, "page_loads_total_30d": sum(v["views"] for v in views), "documents_30d": docs,
            "access_requests_90d": reqs,
            "approval_rate_pct": round(100 * reqs.get("approved", 0) / decided) if decided else None,
            "approved_answers_shown": min(approved_answers, 12), "approved_answers_total": approved_answers,
            "method": "Page loads are counted per request to the public page (a reload counts again); no visitor "
                      "identity, IP address or cookie is stored."}


def _events(cur, cloud_account_id):
    cur.execute("""SELECT at, actor, action, detail FROM trust_center_events WHERE cloud_account_id = %s
                   ORDER BY at DESC LIMIT 100""", (cloud_account_id,))
    return [{"at": a.isoformat(), "actor": b, "action": c, "detail": d} for a, b, c, d in cur.fetchall()]


# ── public view ───────────────────────────────────────────────────────

def _granted_documents(cur, cloud_account_id, viewer_email):
    """Restricted documents this signed-in visitor was approved for (approved request, token not expired), so they
    can download them after signing in instead of keeping the e-mailed link."""
    if not viewer_email:
        return {}
    cur.execute("""SELECT DISTINCT ON (r.document_id) r.document_id, r.token_expires_at FROM trust_document_access_requests r
                   JOIN trust_documents d ON d.id = r.document_id
                   WHERE d.cloud_account_id = %s AND lower(r.requester_email) = lower(%s) AND r.status = 'approved'
                     AND r.token_expires_at > NOW()
                   ORDER BY r.document_id, r.token_expires_at DESC""", (cloud_account_id, viewer_email))
    return {str(d): exp for d, exp in cur.fetchall()}


def _get_public_view(cur, slug, viewer_email=None):
    cur.execute("""
        SELECT cloud_account_id, is_public, company_name, intro_text, contact_email, brand_color, logo_s3_key,
               status_page_url, security_contact, disclosure_policy
        FROM trust_center_settings WHERE public_slug = %s
    """, (slug,))
    row = cur.fetchone()
    if not row or not row[1]:
        return None
    (cloud_account_id, _, company_name, intro_text, contact_email, brand_color, logo_key,
     status_page_url, security_contact, disclosure_policy) = row
    cur.execute("""INSERT INTO trust_center_page_views (cloud_account_id, day, views) VALUES (%s, CURRENT_DATE, 1)
                   ON CONFLICT (cloud_account_id, day) DO UPDATE SET views = trust_center_page_views.views + 1""",
                (cloud_account_id,))

    compliance = _get_compliance_status(cur, cloud_account_id)

    granted = _granted_documents(cur, cloud_account_id, viewer_email)
    cur.execute("""
        SELECT id, title, category, visibility, valid_from, valid_until, issuer FROM trust_documents
        WHERE cloud_account_id = %s ORDER BY category, title
    """, (cloud_account_id,))
    documents = []
    for doc_id, title, category, visibility, valid_from, valid_until, issuer in cur.fetchall():
        entry = {"id": str(doc_id), "title": title, "category": DOCUMENT_CATEGORIES.get(category, category),
                  "visibility": visibility, "valid_from": valid_from.isoformat() if valid_from else None,
                  "valid_until": valid_until.isoformat() if valid_until else None, "issuer": issuer,
                  "validity_status": _doc_status(valid_until, valid_from=valid_from)}
        if visibility == "public":
            entry["download_url"] = _presign_latest(cur, doc_id)
            cur.execute("INSERT INTO trust_document_audit_log (document_id, actor, action) VALUES (%s, %s, 'viewed')",
                        (doc_id, "public"))
        elif str(doc_id) in granted:
            entry["download_url"] = _presign_latest(cur, doc_id)
            entry["granted_until"] = granted[str(doc_id)].isoformat()
            cur.execute("INSERT INTO trust_document_audit_log (document_id, actor, action) VALUES (%s, %s, 'granted_view')",
                        (doc_id, viewer_email))
        documents.append(entry)

    security_posture = _get_security_posture(cur)
    qa_highlights = _get_public_qa_highlights(cur, cloud_account_id)

    return {
        "company_name": company_name, "intro_text": intro_text, "contact_email": contact_email,
        "compliance": compliance, "documents": documents,
        "security_posture": security_posture, "qa_highlights": qa_highlights,
        "branding": {"brand_color": brand_color, "logo_url": _presign_key(logo_key) if logo_key else None},
        "status": {"status_page_url": status_page_url, "updates": _list_updates(cur, cloud_account_id, public=True)},
        "disclosure": {"security_contact": security_contact, "policy": disclosure_policy},
        "viewer": {"signed_in": bool(viewer_email), "granted_documents": len(granted)},
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

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _is_uuid(value):
    return isinstance(value, str) and bool(_UUID_RE.match(value))


def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body)}


from collectors.aws.scanner.tenant_auth import authenticate, email_verified, guard

REFS = {
    "document_id": (
        "SELECT cloud_account_id FROM trust_documents WHERE id = %s"
    ),
    "request_id": (
        "SELECT d.cloud_account_id FROM trust_document_access_requests r JOIN trust_documents d ON d.id = r.document_id WHERE r.id = %s"
    ),
    "update_id": "SELECT cloud_account_id FROM trust_center_updates WHERE id = %s",
}


def _bearer_present(event):
    h = (event or {}).get("headers") or {}
    return (h.get("Authorization") or h.get("authorization") or "").startswith("Bearer ")


def _is_public(event, qs, body):
    return (event.get("httpMethod") == "GET" and (bool(qs.get("slug")) or bool(qs.get("domain")) or (bool(qs.get("download_document")) and bool(qs.get("access_token"))))) or (event.get("httpMethod") == "POST" and body.get("action") == "request_access")


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
    try:
        body = json.loads(event["body"]) if event.get("body") else {}
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
    except (ValueError, TypeError):
        return _resp(400, {"error": "Invalid JSON"})

    # guard() skips ids that are not canonical UUIDs, while PostgreSQL also accepts other spellings (no hyphens,
    # braces); refuse those here so an id can never reach the SQL below without the guard having checked it.
    for src in (qs, body):
        for key in ("cloud_account_id", "download_document", *REFS):
            if src.get(key) not in (None, "") and not _is_uuid(src.get(key)):
                return _resp(400, {"error": f"{key} must be a valid id"})

    conn = _get_connection()
    try:
        denied = guard(event, conn, qs, body, REFS, _is_public)
        if denied:
            return _resp(denied[0], {"error": denied[1]})
        # Admin actions are attributed to the signed-in person (verified by Cognito), not to a name the browser sends.
        actor = None
        if not _is_public(event, qs, body):
            actor = authenticate(event)
            if not actor:
                # Fail closed: never fall back to a name the browser sent while enforcement is on.
                if os.environ.get("TENANT_AUTH_ENFORCE", "1") != "0":
                    return _resp(401, {"error": "Unauthorized"})
                actor = "Admin"
        if method == "GET":
            if qs.get("slug") or qs.get("domain"):
                slug = qs.get("slug") or _slug_for_domain(conn.cursor(), qs["domain"])
                # Optional sign-in: a valid token unlocks documents this person was approved for; an invalid or
                # missing one simply gives the anonymous view (never an error on a public page).
                viewer = authenticate(event) if _bearer_present(event) else None
                if viewer and not email_verified(event):
                    viewer = None  # access by email needs a verified mailbox, like the e-mailed link
                view = _get_public_view(conn.cursor(), slug, viewer) if slug else None
                conn.commit()
                if not view:
                    return _resp(404, {"error": "This Trust Center page does not exist or is not public."})
                return _resp(200, view)

            if qs.get("download_document") and qs.get("access_token"):
                with conn.cursor() as cur:
                    url = _download_restricted(cur, qs["download_document"], qs["access_token"])
                conn.commit()
                if not url:
                    return _resp(403, {"error": "This link is invalid, has expired, or has not been approved yet."})
                return _resp(200, {"download_url": url})

            account_id = qs.get("cloud_account_id")
            if not _is_uuid(account_id):
                return _resp(400, {"error": "cloud_account_id must be a valid id"})
            with conn.cursor() as cur:
                if qs.get("audit_log"):
                    return _resp(200, {"entries": _get_audit_log(cur, account_id, qs.get("document_id"))})
                if qs.get("access_requests"):
                    return _resp(200, {"requests": _list_access_requests(cur, account_id)})
                if qs.get("analytics"):
                    return _resp(200, _analytics(cur, account_id))
                if qs.get("updates"):
                    return _resp(200, {"updates": _list_updates(cur, account_id)})
                if qs.get("events"):
                    return _resp(200, {"events": _events(cur, account_id)})
                settings = _get_or_create_settings(cur, account_id)
                conn.commit()
                documents = _list_documents_admin(cur, account_id)
                compliance = _get_compliance_status(cur, account_id)
                return _resp(200, {"settings": settings, "documents": documents, "compliance": compliance})

        if method == "POST":
            action = body.get("action")
            if action == "update_settings":
                try:
                    extra = _validate_settings(body)
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                _update_settings(conn, body["cloud_account_id"], body.get("is_public"), body.get("company_name"),
                                  body.get("intro_text"), body.get("contact_email"), extra, actor)
                return _resp(200, {"updated": True})
            if action == "set_document_validity":
                try:
                    res = _set_document_validity(conn, body["cloud_account_id"], body.get("document_id"), body.get("valid_from"),
                                                 body.get("valid_until"), body.get("issuer"), actor)
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                return _resp(200, res) if res else _resp(404, {"error": "document not found"})
            if action == "upload_logo":
                try:
                    url = _upload_logo(conn, body["cloud_account_id"], body.get("filename"), body.get("file_base64"), actor)
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                return _resp(200, {"logo_url": url})
            if action == "remove_logo":
                with conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE trust_center_settings SET logo_s3_key = NULL WHERE cloud_account_id = %s", (body["cloud_account_id"],))
                        _account_event(cur, body["cloud_account_id"], actor, "logo_removed")
                return _resp(200, {"removed": True})
            if action == "create_update":
                try:
                    uid = _create_update(conn, body["cloud_account_id"], body, actor)
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                return _resp(200, {"id": uid})
            if action == "resolve_update":
                note = (body.get("note") or "").strip()[:2000]
                ok = _resolve_update(conn, body["cloud_account_id"], body.get("update_id"), note, actor)
                return _resp(200, {"resolved": True}) if ok else _resp(404, {"error": "open notice not found"})
            if action == "set_custom_domain":
                try:
                    info = _set_custom_domain(conn, body["cloud_account_id"], body.get("custom_domain"))
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                return _resp(200, {"custom_domain": info})
            if action == "verify_custom_domain":
                try:
                    status, result = _verify_custom_domain(conn, body["cloud_account_id"])
                except psycopg2.IntegrityError:
                    return _resp(409, {"error": "This domain is already connected to another Trust Center."})
                return _resp(status, result)
            if action == "upload_document":
                doc_id = _upload_document(conn, body["cloud_account_id"], body["title"], body.get("category", "other"),
                                           body.get("visibility", "restricted"), body["filename"], body["file_base64"],
                                           actor)
                return _resp(200, {"id": doc_id})
            if action == "upload_new_version":
                v = _upload_new_version(conn, body["cloud_account_id"], body["document_id"], body["filename"],
                                         body["file_base64"], body.get("changelog"), actor)
                return _resp(200, {"version_number": v})
            if action == "request_access":
                nda_name = (body.get("nda_accepted_name") or "").strip()
                if not nda_name:
                    return _resp(400, {"error": "Confidentiality acknowledgement (typed full name) is required."})
                req_id = _request_access(conn, body["document_id"], body["requester_name"], body["requester_email"],
                                          body.get("reason", ""), nda_name)
                return _resp(200, {"id": req_id})
            if action == "decide_access_request":
                result = _decide_access_request(conn, body["request_id"], body["approve"], actor)
                if result is None:
                    return _resp(404, {"error": "access request not found"})
                return _resp(200, result)
            return _resp(400, {"error": f"unknown action: {action}"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.error("trust_center_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": "An unexpected error occurred. Please try again, or contact support if this keeps happening."})
    finally:
        conn.close()
