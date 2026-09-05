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
from datetime import date

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

# Points of RISK added per factor — higher total = riskier vendor. Every
# input is something this platform can actually verify; nothing here is an
# estimate or a guess.
CRITICALITY_RISK_POINTS = {"low": 10, "medium": 20, "high": 30, "critical": 40}
NO_VALID_CERTIFICATION_POINTS = 20
CERTIFICATION_EXPIRING_SOON_POINTS = 15
CERTIFICATION_EXPIRING_SOON_DAYS = 30
NO_APPROVED_ASSESSMENT_POINTS = 15


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
"""

ADMIN_MIGRATION_SQL = BOOTSTRAP_SQL + """
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_vendors TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_certifications TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_assessments TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON tprm_audit_log TO cspm_lambda;
"""


# ── risk scoring ─────────────────────────────────────────────────────────

def _compute_risk(criticality, certifications, assessments):
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
               website, status, notes, created_at
        FROM tprm_vendors WHERE cloud_account_id = %s ORDER BY name
    """, (cloud_account_id,))
    vendors = [{
        "id": str(r[0]), "name": r[1], "category": r[2], "criticality": r[3],
        "business_owner": r[4], "contact_email": r[5], "website": r[6],
        "status": r[7], "notes": r[8], "created_at": r[9].isoformat(),
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
            SELECT id, questionnaire_type, status, sent_at, received_at, approved_at, filename
            FROM tprm_assessments WHERE vendor_id = %s ORDER BY created_at DESC
        """, (v["id"],))
        assessments = [{
            "id": str(r[0]), "questionnaire_type": r[1], "status": r[2],
            "sent_at": r[3].isoformat() if r[3] else None,
            "received_at": r[4].isoformat() if r[4] else None,
            "approved_at": r[5].isoformat() if r[5] else None,
            "filename": r[6],
        } for r in cur.fetchall()]
        v["assessments"] = assessments

        raw_certs = [{"expiry_date": r[3]} for r in cert_raw_rows]
        v["risk"] = _compute_risk(v["criticality"], raw_certs, assessments)

    return vendors


def _create_vendor(conn, cloud_account_id, name, category, criticality, business_owner,
                    contact_email, website, notes, actor):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tprm_vendors
                    (cloud_account_id, name, category, criticality, business_owner, contact_email, website, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (cloud_account_id, name, category, criticality, business_owner, contact_email, website, notes))
            vendor_id = str(cur.fetchone()[0])
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'created')",
                        (vendor_id, actor))
    return vendor_id


def _update_vendor(conn, vendor_id, fields, actor):
    allowed = {"name", "category", "criticality", "business_owner", "contact_email",
               "website", "status", "notes"}
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

def _create_assessment(conn, vendor_id, questionnaire_type, actor):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tprm_assessments (vendor_id, questionnaire_type, status, sent_at)
                VALUES (%s, %s, 'sent', NOW()) RETURNING id
            """, (vendor_id, questionnaire_type))
            assessment_id = str(cur.fetchone()[0])
            cur.execute("INSERT INTO tprm_audit_log (vendor_id, actor, action) VALUES (%s, %s, 'assessment_sent')",
                        (vendor_id, actor))
    return assessment_id


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


# ── entrypoint ───────────────────────────────────────────────────────────

def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body, default=str)}


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
                    body.get("contact_email"), body.get("website"), body.get("notes"), actor,
                )
                return _resp(200, {"id": vendor_id})
            if action == "update_vendor":
                _update_vendor(conn, body["vendor_id"], body.get("fields", {}), actor)
                return _resp(200, {"updated": True})
            if action == "delete_vendor":
                _delete_vendor(conn, body["vendor_id"], actor)
                return _resp(200, {"deleted": True})
            if action == "upload_certification":
                cert_id = _upload_certification(
                    conn, body["vendor_id"], body.get("certification_type", "other"),
                    body.get("issued_date"), body.get("expiry_date"),
                    body.get("filename"), body.get("file_base64"), actor,
                )
                return _resp(200, {"id": cert_id})
            if action == "create_assessment":
                assessment_id = _create_assessment(conn, body["vendor_id"], body.get("questionnaire_type", "custom"), actor)
                return _resp(200, {"id": assessment_id})
            if action == "update_assessment":
                if body.get("status") not in ASSESSMENT_STATUSES:
                    return _resp(400, {"error": f"status must be one of {ASSESSMENT_STATUSES}"})
                _update_assessment(
                    conn, body["assessment_id"], body["vendor_id"], body["status"],
                    body.get("filename"), body.get("file_base64"), actor,
                )
                return _resp(200, {"updated": True})
            return _resp(400, {"error": f"unknown action: {action}"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.error("tprm_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": str(e)})
    finally:
        conn.close()
