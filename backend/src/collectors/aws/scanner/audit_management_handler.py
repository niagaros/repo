"""
audit_management_handler.py

Audit Management (GitHub issue #260), v1.

Scope decision: issue #260 describes a full standalone audit-GRC platform —
an annual audit calendar with calendar-app integration, real-time multi-user
collaboration, formal sampling/interview tooling, automated escalation
workflows, and support for a framework named "OFDSS" that does not
correspond to any real, recognized standard. Building all of that in one
pass would mean either faking integrations this codebase has no real
connection to, or inventing a framework this platform cannot actually
verify anything against — both violate this codebase's standing rule
against fabricated evidence.

What's built here instead, for real:
  - Audit records (title, type, framework, scope, dates, lead auditor,
    stakeholders) — plain user-entered data.
  - A findings register auto-seeded, at audit-creation time, from this
    account's own real, currently-failing scan findings for the audit's
    framework (same data already verified elsewhere in this product — a new
    lens on real data, not a new measurement). Manual findings can be added
    for non-technical auditor observations.
  - Remediation tracking per finding, mirroring the already-built,
    already-tested TPRM remediation-task pattern (tprm_handler.py):
    owner, due date, status, and a required verification note before a
    task can be marked verified.
  - Evidence: either a real uploaded file, or a real link to a document
    that already exists in the Trust Center vault (trust_documents) —
    never a second, disconnected copy of the same file.
  - Daily monitoring (upcoming audits, overdue remediation) with a real
    email alert via SES, reusing the exact pattern already live-tested in
    tprm_handler.py's _check_and_notify.

v2 (2026-09-08), closing gaps against the literal userstory:
  - Immediate SES notification when a remediation task is assigned (AC3
    previously only had the daily digest, not an at-assignment notice).
  - Verifying a remediation task now auto-closes its finding with status
    'closed' (AC4 literally says "closed"; it previously set 'verified').
  - Audit readiness score and evidence completeness (% of findings with
    >=1 linked evidence item) computed and surfaced by name (Reporting &
    Dashboards section of the issue).
  - Notes/comments per finding (audit_finding_comments) — a plain log,
    not real-time collaboration (still no presence/live-sync infra here).
  - Root cause is now editable on any finding at any time, not just at
    manual-finding creation.

Declined, explicitly, rather than silently invented:
  - Calendar-app integration, real-time multi-user collaboration, formal
    sampling/interview/testing-procedure tooling, automated escalation
    chains — no real system in this codebase to integrate with.
  - "OFDSS" framework support — not a recognized standard; left out of the
    framework picklist rather than guessed at or invented.

FRAMEWORK_CASE_SQL / FRAMEWORK_LABELS below are copied verbatim from
trust_center_handler.py (same pattern already reused in monthly_report_
handler.py) so the audit framework picklist matches the exact same real
framework set the rest of the product already tracks.
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

DOCS_BUCKET = os.environ.get("AUDIT_BUCKET", "niagaros-audit-documents")

AUDIT_TYPES = (
    "internal", "external", "certification", "surveillance",
    "regulatory", "supplier", "customer", "third_party",
)
AUDIT_STATUSES = ("planned", "in_progress", "completed", "closed")
FINDING_STATUSES = ("open", "in_remediation", "verified", "closed")
REMEDIATION_STATUSES = ("open", "in_progress", "completed", "verified")

# Copied verbatim from trust_center_handler.py (see module docstring).
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

# Reverse of FRAMEWORK_CASE_SQL — short code -> the real findings.framework
# value(s) to filter by when seeding an audit's findings register.
FRAMEWORK_DB_VALUES = {
    "ISO27001": ["ISO 27001:2022"], "NIST": ["NIST CSF v2.0"], "GDPR": ["GDPR"], "SOC2": ["SOC2"],
    "PCIDSS": ["PCI DSS v4.0"], "NIS2": ["NIS2"], "HIPAA": ["HIPAA"], "NIST80053": ["NIST 800-53 Rev 5"],
    "BSIC5": ["BSI-C5"], "CSACCM": ["CSA CCM 4.0"], "FEDRAMP": ["FedRAMP Moderate Rev 4"], "ISO42001": ["ISO 42001"],
    "ISO27017": ["ISO 27017"], "AWSFTR": ["AWS FTR"], "MVSP": ["MVSP"], "TISAX": ["TISAX"],
    "HITRUST": ["HITRUST CSF"], "DORA": ["DORA"], "CRIPROFILE": ["CRI Profile"], "EUAIACT": ["EU AI Act"],
    "NISTAIRMF": ["NIST AI RMF"], "ISO27701": ["ISO 27701"], "ISO27018": ["ISO 27018"], "SSPA": ["Microsoft SSPA"],
    "CISCTRL": ["CIS Controls v8.1"], "NYDFS": ["23 NYCRR 500 (NYDFS)"], "NISTPRIV": ["NIST Privacy Framework"],
    "CISAWS": ["CIS AWS Foundations Benchmark v5.0.0", "AWS Foundational Security Best Practices"],
}

REMEDIATION_OVERDUE_DAYS = 0  # a task is "overdue" once due_date < today


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


ADMIN_MIGRATION_SQL = """
CREATE TABLE IF NOT EXISTS audits (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    title              VARCHAR(255) NOT NULL,
    audit_type         VARCHAR(30)  NOT NULL DEFAULT 'internal',
    framework          VARCHAR(100),
    scope_description  TEXT,
    status             VARCHAR(20)  NOT NULL DEFAULT 'planned',
    lead_auditor_name  VARCHAR(255),
    lead_auditor_org   VARCHAR(255),
    stakeholders       TEXT,
    start_date         DATE,
    end_date           DATE,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS audit_findings (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id      UUID         NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    source        VARCHAR(10)  NOT NULL DEFAULT 'manual',
    check_id      VARCHAR(100),
    resource_name VARCHAR(255),
    title         VARCHAR(500) NOT NULL,
    description   TEXT,
    remediation   TEXT,
    severity      VARCHAR(20)  NOT NULL DEFAULT 'MEDIUM',
    risk_rating   VARCHAR(20),
    root_cause    TEXT,
    status        VARCHAR(20)  NOT NULL DEFAULT 'open',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at   TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS audit_remediation_tasks (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_finding_id    UUID         NOT NULL REFERENCES audit_findings(id) ON DELETE CASCADE,
    title               VARCHAR(500) NOT NULL,
    owner_name          VARCHAR(255),
    owner_email         VARCHAR(255),
    due_date            DATE,
    status              VARCHAR(20)  NOT NULL DEFAULT 'open',
    verification_notes  TEXT,
    verified_by         VARCHAR(255),
    verified_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS audit_evidence (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id             UUID         NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    audit_finding_id     UUID         REFERENCES audit_findings(id) ON DELETE SET NULL,
    title                VARCHAR(255) NOT NULL,
    source               VARCHAR(20)  NOT NULL DEFAULT 'upload',
    s3_key               VARCHAR(500),
    trust_document_id    UUID         REFERENCES trust_documents(id) ON DELETE SET NULL,
    filename             VARCHAR(255),
    uploaded_by          VARCHAR(255),
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS audit_finding_comments (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_finding_id  UUID         NOT NULL REFERENCES audit_findings(id) ON DELETE CASCADE,
    author            VARCHAR(255),
    body              TEXT         NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS audits_account_idx ON audits(cloud_account_id);
CREATE INDEX IF NOT EXISTS audit_findings_audit_idx ON audit_findings(audit_id);
CREATE INDEX IF NOT EXISTS audit_remediation_finding_idx ON audit_remediation_tasks(audit_finding_id);
CREATE INDEX IF NOT EXISTS audit_evidence_audit_idx ON audit_evidence(audit_id);
CREATE INDEX IF NOT EXISTS audit_finding_comments_finding_idx ON audit_finding_comments(audit_finding_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON audits TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_findings TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_remediation_tasks TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_evidence TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_finding_comments TO cspm_lambda;
"""


# ── audits ────────────────────────────────────────────────────────────────

def _create_audit(conn, cloud_account_id, title, audit_type, framework, scope_description,
                   lead_auditor_name, lead_auditor_org, stakeholders, start_date, end_date):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audits (cloud_account_id, title, audit_type, framework, scope_description,
                                     lead_auditor_name, lead_auditor_org, stakeholders, start_date, end_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (cloud_account_id, title, audit_type, framework, scope_description,
                  lead_auditor_name, lead_auditor_org, stakeholders, start_date, end_date))
            audit_id = str(cur.fetchone()[0])

            seeded = 0
            db_values = FRAMEWORK_DB_VALUES.get(framework)
            if db_values:
                cur.execute("""
                    SELECT f.check_id, r.resource_name, f.title, f.description, f.remediation, f.severity
                    FROM findings f JOIN resources r ON f.resource_id = r.id
                    WHERE r.cloud_account_id = %s AND f.result = 'FAIL' AND f.framework = ANY(%s)
                """, (cloud_account_id, db_values))
                rows = cur.fetchall()
                for check_id, resource_name, ftitle, description, remediation, severity in rows:
                    cur.execute("""
                        INSERT INTO audit_findings (audit_id, source, check_id, resource_name, title,
                                                     description, remediation, severity, status)
                        VALUES (%s, 'scan', %s, %s, %s, %s, %s, %s, 'open')
                    """, (audit_id, check_id, resource_name, ftitle or check_id, description, remediation,
                          (severity or "MEDIUM").upper()))
                    seeded += 1
    return audit_id, seeded


def _list_audits(cur, cloud_account_id):
    cur.execute("""
        SELECT id, title, audit_type, framework, scope_description, status, lead_auditor_name,
               lead_auditor_org, stakeholders, start_date, end_date, created_at
        FROM audits WHERE cloud_account_id = %s ORDER BY created_at DESC
    """, (cloud_account_id,))
    audits = []
    for row in cur.fetchall():
        audit_id = str(row[0])
        cur.execute("""
            SELECT status, COUNT(*) FROM audit_findings WHERE audit_id = %s GROUP BY status
        """, (audit_id,))
        by_status = {s: c for s, c in cur.fetchall()}
        total = sum(by_status.values())
        closed = by_status.get("closed", 0) + by_status.get("verified", 0)
        cur.execute("""
            SELECT COUNT(*) FROM audit_remediation_tasks t
            JOIN audit_findings f ON t.audit_finding_id = f.id
            WHERE f.audit_id = %s AND t.status NOT IN ('completed', 'verified') AND t.due_date < CURRENT_DATE
        """, (audit_id,))
        overdue = cur.fetchone()[0]
        cur.execute("""
            SELECT COUNT(DISTINCT audit_finding_id) FROM audit_evidence
            WHERE audit_id = %s AND audit_finding_id IS NOT NULL
        """, (audit_id,))
        findings_with_evidence = cur.fetchone()[0]
        audits.append({
            "id": audit_id, "title": row[1], "audit_type": row[2], "framework": row[3],
            "framework_label": FRAMEWORK_LABELS.get(row[3], row[3]),
            "scope_description": row[4], "status": row[5],
            "lead_auditor_name": row[6], "lead_auditor_org": row[7], "stakeholders": row[8],
            "start_date": row[9].isoformat() if row[9] else None,
            "end_date": row[10].isoformat() if row[10] else None,
            "created_at": row[11].isoformat() if row[11] else None,
            "findings_total": total, "findings_open": total - closed, "findings_closed": closed,
            # "Audit readiness score" (issue #260, Reporting & Dashboards) —
            # % of the findings register that's closed/verified. Kept under
            # the old key too so nothing already reading progress_pct breaks.
            "progress_pct": round(closed * 100.0 / total) if total else 0,
            "audit_readiness_score": round(closed * 100.0 / total) if total else 0,
            "overdue_remediation": overdue,
            # % of findings with at least one linked evidence item.
            "evidence_completeness_pct": round(findings_with_evidence * 100.0 / total) if total else 0,
        })
    return audits


def _get_audit_detail(cur, audit_id):
    cur.execute("""
        SELECT id, cloud_account_id, title, audit_type, framework, scope_description, status,
               lead_auditor_name, lead_auditor_org, stakeholders, start_date, end_date, created_at
        FROM audits WHERE id = %s
    """, (audit_id,))
    row = cur.fetchone()
    if not row:
        return None
    audit = {
        "id": str(row[0]), "cloud_account_id": str(row[1]), "title": row[2], "audit_type": row[3],
        "framework": row[4], "framework_label": FRAMEWORK_LABELS.get(row[4], row[4]),
        "scope_description": row[5], "status": row[6], "lead_auditor_name": row[7],
        "lead_auditor_org": row[8], "stakeholders": row[9],
        "start_date": row[10].isoformat() if row[10] else None,
        "end_date": row[11].isoformat() if row[11] else None,
        "created_at": row[12].isoformat() if row[12] else None,
    }

    cur.execute("SELECT status, COUNT(*) FROM audit_findings WHERE audit_id = %s GROUP BY status", (audit_id,))
    by_status = {s: c for s, c in cur.fetchall()}
    total = sum(by_status.values())
    closed = by_status.get("closed", 0) + by_status.get("verified", 0)
    cur.execute("""
        SELECT COUNT(*) FROM audit_remediation_tasks t
        JOIN audit_findings f ON t.audit_finding_id = f.id
        WHERE f.audit_id = %s AND t.status NOT IN ('completed', 'verified') AND t.due_date < CURRENT_DATE
    """, (audit_id,))
    overdue = cur.fetchone()[0]
    cur.execute("""
        SELECT COUNT(DISTINCT audit_finding_id) FROM audit_evidence
        WHERE audit_id = %s AND audit_finding_id IS NOT NULL
    """, (audit_id,))
    findings_with_evidence = cur.fetchone()[0]
    audit["findings_total"] = total
    audit["findings_open"] = total - closed
    audit["findings_closed"] = closed
    audit["audit_readiness_score"] = round(closed * 100.0 / total) if total else 0
    audit["overdue_remediation"] = overdue
    audit["evidence_completeness_pct"] = round(findings_with_evidence * 100.0 / total) if total else 0

    cur.execute("""
        SELECT id, source, check_id, resource_name, title, description, remediation, severity,
               risk_rating, root_cause, status, created_at, resolved_at
        FROM audit_findings WHERE audit_id = %s
        ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, created_at
    """, (audit_id,))
    findings = []
    for f in cur.fetchall():
        finding_id = str(f[0])
        cur.execute("""
            SELECT id, title, owner_name, owner_email, due_date, status, verification_notes,
                   verified_by, verified_at, created_at
            FROM audit_remediation_tasks WHERE audit_finding_id = %s ORDER BY created_at
        """, (finding_id,))
        tasks = [{
            "id": str(t[0]), "title": t[1], "owner_name": t[2], "owner_email": t[3],
            "due_date": t[4].isoformat() if t[4] else None, "status": t[5],
            "verification_notes": t[6], "verified_by": t[7],
            "verified_at": t[8].isoformat() if t[8] else None,
            "overdue": bool(t[4] and t[5] not in ("completed", "verified") and t[4] < date.today()),
        } for t in cur.fetchall()]
        cur.execute("""
            SELECT id, author, body, created_at FROM audit_finding_comments
            WHERE audit_finding_id = %s ORDER BY created_at
        """, (finding_id,))
        comments = [{
            "id": str(c[0]), "author": c[1], "body": c[2], "created_at": c[3].isoformat() if c[3] else None,
        } for c in cur.fetchall()]
        findings.append({
            "id": finding_id, "source": f[1], "check_id": f[2], "resource_name": f[3], "title": f[4],
            "description": f[5], "remediation": f[6], "severity": f[7], "risk_rating": f[8],
            "root_cause": f[9], "status": f[10], "created_at": f[11].isoformat() if f[11] else None,
            "resolved_at": f[12].isoformat() if f[12] else None, "remediation_tasks": tasks,
            "comments": comments,
        })
    audit["findings"] = findings

    cur.execute("""
        SELECT id, audit_finding_id, title, source, s3_key, trust_document_id, filename, uploaded_by, created_at
        FROM audit_evidence WHERE audit_id = %s ORDER BY created_at DESC
    """, (audit_id,))
    audit["evidence"] = [{
        "id": str(e[0]), "audit_finding_id": str(e[1]) if e[1] else None, "title": e[2], "source": e[3],
        "has_file": bool(e[4]), "trust_document_id": str(e[5]) if e[5] else None,
        "filename": e[6], "uploaded_by": e[7], "created_at": e[8].isoformat() if e[8] else None,
    } for e in cur.fetchall()]
    return audit


def _update_audit(conn, audit_id, status, start_date, end_date):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE audits SET status = COALESCE(%s, status), start_date = COALESCE(%s, start_date),
                                   end_date = COALESCE(%s, end_date), updated_at = NOW()
                WHERE id = %s
            """, (status, start_date, end_date, audit_id))


def _delete_audit(conn, audit_id):
    with conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM audits WHERE id = %s", (audit_id,))


# ── findings ──────────────────────────────────────────────────────────────

def _add_manual_finding(conn, audit_id, title, description, severity, risk_rating, root_cause):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_findings (audit_id, source, title, description, severity, risk_rating,
                                             root_cause, status)
                VALUES (%s, 'manual', %s, %s, %s, %s, %s, 'open') RETURNING id
            """, (audit_id, title, description, (severity or "MEDIUM").upper(), risk_rating, root_cause))
            return str(cur.fetchone()[0])


def _update_finding_status(conn, finding_id, status):
    if status not in FINDING_STATUSES:
        raise ValueError(f"status must be one of {FINDING_STATUSES}")
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE audit_findings SET status = %s, resolved_at = CASE WHEN %s IN ('verified','closed') THEN NOW() ELSE NULL END
                WHERE id = %s
            """, (status, status, finding_id))


# Root cause analysis (issue #260, Findings Management) — originally only
# settable when a manual finding was first created. Now editable on any
# finding, scan-seeded or manual, at any point in its lifecycle.
def _update_finding_root_cause(conn, finding_id, root_cause):
    with conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE audit_findings SET root_cause = %s WHERE id = %s", (root_cause, finding_id))


# Notes and comments (issue #260, Audit Execution) — a plain running log
# per finding, not real-time multi-user collaboration (no presence/live
# sync infra exists in this codebase to back that with).
def _add_finding_comment(conn, finding_id, author, body):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_finding_comments (audit_finding_id, author, body)
                VALUES (%s, %s, %s) RETURNING id
            """, (finding_id, author, body))
            return str(cur.fetchone()[0])


# ── remediation (mirrors tprm_handler.py's pattern) ──────────────────────

def _create_remediation_task(conn, finding_id, title, owner_name, owner_email, due_date):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_remediation_tasks (audit_finding_id, title, owner_name, owner_email, due_date)
                VALUES (%s, %s, %s, %s, %s) RETURNING id
            """, (finding_id, title, owner_name, owner_email, due_date))
            task_id = str(cur.fetchone()[0])
            cur.execute("UPDATE audit_findings SET status = 'in_remediation' WHERE id = %s AND status = 'open'",
                        (finding_id,))
            cur.execute("""
                SELECT f.title, a.title FROM audit_findings f JOIN audits a ON f.audit_id = a.id WHERE f.id = %s
            """, (finding_id,))
            finding_title, audit_title = cur.fetchone()
    email_result = _notify_task_assigned(owner_email, owner_name, title, finding_title, audit_title, due_date)
    return task_id, email_result


# Acceptance criterion 3 (issue #260): "...the responsible owner receives
# a notification and due date." Real, immediate email at assignment time —
# not just the daily digest, which only covers already-overdue tasks.
def _notify_task_assigned(owner_email, owner_name, task_title, finding_title, audit_title, due_date):
    if not owner_email:
        return {"sent": False, "reason": "no_owner_email"}
    if not AUDIT_SENDER_EMAIL:
        return {"sent": False, "reason": "not_configured"}
    body = (
        f"Hi {owner_name or ''},\n\n"
        f"You've been assigned a remediation task in Niagaros Audit Management:\n\n"
        f"  Audit: {audit_title}\n"
        f"  Finding: {finding_title}\n"
        f"  Task: {task_title}\n"
        f"  Due: {due_date or 'no due date set'}\n"
    ).strip()
    ses = boto3.client("sesv2", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))
    try:
        ses.send_email(
            FromEmailAddress=AUDIT_SENDER_EMAIL,
            Destination={"ToAddresses": [owner_email]},
            Content={"Simple": {"Subject": {"Data": f"Remediation assigned: {task_title}", "Charset": "UTF-8"},
                                 "Body": {"Text": {"Data": body, "Charset": "UTF-8"}}}},
        )
        return {"sent": True}
    except Exception as e:
        return {"sent": False, "reason": str(e)}


def _update_remediation_task(conn, task_id, status, verification_notes, verified_by):
    if status not in REMEDIATION_STATUSES:
        raise ValueError(f"status must be one of {REMEDIATION_STATUSES}")
    if status == "verified" and not verification_notes:
        raise ValueError("verification_notes is required to mark a remediation task verified")
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE audit_remediation_tasks
                SET status = %s, verification_notes = COALESCE(%s, verification_notes),
                    verified_by = CASE WHEN %s = 'verified' THEN %s ELSE verified_by END,
                    verified_at = CASE WHEN %s = 'verified' THEN NOW() ELSE verified_at END
                WHERE id = %s
            """, (status, verification_notes, status, verified_by, status, task_id))
            if status == "verified":
                # AC (issue #260): "when verification is approved, then the
                # finding is automatically marked as closed" — literally
                # 'closed', not 'verified' (that status stays available for
                # manual use via update_finding_status).
                cur.execute("""
                    UPDATE audit_findings SET status = 'closed', resolved_at = NOW()
                    WHERE id = (SELECT audit_finding_id FROM audit_remediation_tasks WHERE id = %s)
                """, (task_id,))


# ── evidence ──────────────────────────────────────────────────────────────

def _upload_evidence(conn, audit_id, finding_id, title, filename, file_base64, uploaded_by):
    raw = base64.b64decode(file_base64) if file_base64 else None
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_evidence (audit_id, audit_finding_id, title, source, filename, uploaded_by)
                VALUES (%s, %s, %s, 'upload', %s, %s) RETURNING id
            """, (audit_id, finding_id, title, filename, uploaded_by))
            evidence_id = str(cur.fetchone()[0])
            s3_key = None
            if raw is not None:
                s3_key = f"audits/{audit_id}/evidence/{evidence_id}-{filename}"
                _s3().put_object(Bucket=DOCS_BUCKET, Key=s3_key, Body=raw, ServerSideEncryption="AES256")
                cur.execute("UPDATE audit_evidence SET s3_key = %s WHERE id = %s", (s3_key, evidence_id))
    return evidence_id


def _link_trust_document(conn, audit_id, finding_id, trust_document_id, uploaded_by):
    with conn:
        with conn.cursor() as cur:
            cur.execute("SELECT title FROM trust_documents WHERE id = %s", (trust_document_id,))
            row = cur.fetchone()
            if not row:
                raise ValueError("trust document not found")
            cur.execute("""
                INSERT INTO audit_evidence (audit_id, audit_finding_id, title, source, trust_document_id, uploaded_by)
                VALUES (%s, %s, %s, 'trust_center', %s, %s) RETURNING id
            """, (audit_id, finding_id, row[0], trust_document_id, uploaded_by))
            return str(cur.fetchone()[0])


def _presign_evidence(cur, evidence_id, expires_in=900):
    cur.execute("SELECT s3_key, filename FROM audit_evidence WHERE id = %s", (evidence_id,))
    row = cur.fetchone()
    if not row or not row[0]:
        return None
    s3_key, filename = row
    return _s3().generate_presigned_url(
        "get_object",
        Params={"Bucket": DOCS_BUCKET, "Key": s3_key, "ResponseContentDisposition": f'attachment; filename="{filename}"'},
        ExpiresIn=expires_in,
    )


# ── daily monitoring (mirrors tprm_handler.py's _check_and_notify) ───────

AUDIT_SENDER_EMAIL = os.environ.get("AUDIT_SENDER_EMAIL")
AUDIT_RECIPIENT_EMAILS = [e.strip() for e in os.environ.get("AUDIT_RECIPIENT_EMAILS", "").split(",") if e.strip()]
UPCOMING_AUDIT_DAYS = 7


def _check_and_notify(conn, cloud_account_id):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT title, start_date FROM audits
            WHERE cloud_account_id = %s AND status = 'planned'
              AND start_date IS NOT NULL AND start_date <= CURRENT_DATE + INTERVAL '%s days'
        """, (cloud_account_id, UPCOMING_AUDIT_DAYS))
        upcoming = [{"title": r[0], "start_date": r[1].isoformat()} for r in cur.fetchall()]

        cur.execute("""
            SELECT a.title, t.title, t.owner_name, t.due_date
            FROM audit_remediation_tasks t
            JOIN audit_findings f ON t.audit_finding_id = f.id
            JOIN audits a ON f.audit_id = a.id
            WHERE a.cloud_account_id = %s AND t.status NOT IN ('completed', 'verified')
              AND t.due_date < CURRENT_DATE
        """, (cloud_account_id,))
        overdue = [{"audit": r[0], "task": r[1], "owner": r[2], "due_date": r[3].isoformat()} for r in cur.fetchall()]
    conn.commit()

    if not upcoming and not overdue:
        return {"upcoming_count": 0, "overdue_count": 0, "email": {"sent": False, "reason": "nothing_to_report"}}
    if not AUDIT_SENDER_EMAIL or not AUDIT_RECIPIENT_EMAILS:
        return {"upcoming_count": len(upcoming), "overdue_count": len(overdue),
                "email": {"sent": False, "reason": "not_configured"}}

    lines = [f"Audit Management alert for account {cloud_account_id}:", ""]
    if upcoming:
        lines.append(f"Audits starting within {UPCOMING_AUDIT_DAYS} days:")
        lines += [f"  - {u['title']}: starts {u['start_date']}" for u in upcoming]
        lines.append("")
    if overdue:
        lines.append("Overdue remediation tasks:")
        lines += [f"  - [{o['audit']}] \"{o['task']}\" (owner: {o['owner'] or 'unassigned'}) was due {o['due_date']}" for o in overdue]
    body_text = "\n".join(lines)

    ses = boto3.client("sesv2", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))
    try:
        ses.send_email(
            FromEmailAddress=AUDIT_SENDER_EMAIL,
            Destination={"ToAddresses": AUDIT_RECIPIENT_EMAILS},
            Content={"Simple": {"Subject": {"Data": f"Audit alert: {len(upcoming)} upcoming, {len(overdue)} overdue task(s)", "Charset": "UTF-8"},
                                 "Body": {"Text": {"Data": body_text, "Charset": "UTF-8"}}}},
        )
        email_result = {"sent": True}
    except Exception as e:
        email_result = {"sent": False, "reason": str(e)}

    return {"upcoming_count": len(upcoming), "overdue_count": len(overdue), "email": email_result}


# ── HTTP handler ──────────────────────────────────────────────────────────

def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body, default=str)}


def handler(event, context):
    if event and event.get("check_and_notify"):
        conn = _get_connection()
        try:
            return {"statusCode": 200, "body": json.dumps(_check_and_notify(conn, event["check_and_notify"]))}
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
            with conn.cursor() as cur:
                if qs.get("audit_detail"):
                    detail = _get_audit_detail(cur, qs["audit_detail"])
                    if not detail:
                        return _resp(404, {"error": "audit not found"})
                    return _resp(200, detail)
                if qs.get("download_evidence"):
                    url = _presign_evidence(cur, qs["download_evidence"])
                    if not url:
                        return _resp(404, {"error": "no file for this evidence entry"})
                    return _resp(200, {"download_url": url})
                if qs.get("trust_documents"):
                    cur.execute("SELECT id, title, category FROM trust_documents WHERE cloud_account_id = %s ORDER BY title",
                                (qs["trust_documents"],))
                    return _resp(200, {"documents": [{"id": str(r[0]), "title": r[1], "category": r[2]} for r in cur.fetchall()]})
                account_id = qs.get("cloud_account_id")
                if not _is_uuid(account_id):
                    # Never crash on a missing/garbage account_id (e.g. the
                    # literal string "null" from a page loaded before login
                    # resolved an account) — the framework list is static
                    # and still useful even with no account context yet.
                    return _resp(200, {
                        "audits": [],
                        "framework_options": [{"value": k, "label": v} for k, v in FRAMEWORK_LABELS.items()],
                        "audit_types": list(AUDIT_TYPES),
                    })
                return _resp(200, {
                    "audits": _list_audits(cur, account_id),
                    "framework_options": [{"value": k, "label": v} for k, v in FRAMEWORK_LABELS.items()],
                    "audit_types": list(AUDIT_TYPES),
                })

        if method == "POST":
            action = body.get("action")

            if action == "create_audit":
                if not body.get("title"):
                    return _resp(400, {"error": "title is required"})
                if body.get("audit_type", "internal") not in AUDIT_TYPES:
                    return _resp(400, {"error": f"audit_type must be one of {AUDIT_TYPES}"})
                audit_id, seeded = _create_audit(
                    conn, body["cloud_account_id"], body["title"], body.get("audit_type", "internal"),
                    body.get("framework"), body.get("scope_description"),
                    body.get("lead_auditor_name"), body.get("lead_auditor_org"), body.get("stakeholders"),
                    body.get("start_date"), body.get("end_date"),
                )
                return _resp(200, {"id": audit_id, "findings_seeded": seeded})

            if action == "update_audit":
                _update_audit(conn, body["audit_id"], body.get("status"), body.get("start_date"), body.get("end_date"))
                return _resp(200, {"updated": True})

            if action == "delete_audit":
                _delete_audit(conn, body["audit_id"])
                return _resp(200, {"deleted": True})

            if action == "add_manual_finding":
                if not body.get("title"):
                    return _resp(400, {"error": "title is required"})
                finding_id = _add_manual_finding(
                    conn, body["audit_id"], body["title"], body.get("description"),
                    body.get("severity"), body.get("risk_rating"), body.get("root_cause"),
                )
                return _resp(200, {"id": finding_id})

            if action == "update_finding_status":
                try:
                    _update_finding_status(conn, body["finding_id"], body["status"])
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                return _resp(200, {"updated": True})

            if action == "update_finding_root_cause":
                _update_finding_root_cause(conn, body["finding_id"], body.get("root_cause"))
                return _resp(200, {"updated": True})

            if action == "add_finding_comment":
                if not body.get("body"):
                    return _resp(400, {"error": "body is required"})
                comment_id = _add_finding_comment(conn, body["finding_id"], body.get("author") or "Admin", body["body"])
                return _resp(200, {"id": comment_id})

            if action == "create_remediation_task":
                if not body.get("title"):
                    return _resp(400, {"error": "title is required"})
                task_id, email_result = _create_remediation_task(
                    conn, body["finding_id"], body["title"], body.get("owner_name"),
                    body.get("owner_email"), body.get("due_date"),
                )
                return _resp(200, {"id": task_id, "notification": email_result})

            if action == "update_remediation_task":
                try:
                    _update_remediation_task(conn, body["task_id"], body["status"],
                                              body.get("verification_notes"), body.get("verified_by"))
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                return _resp(200, {"updated": True})

            if action == "upload_evidence":
                evidence_id = _upload_evidence(
                    conn, body["audit_id"], body.get("finding_id"), body.get("title", body.get("filename", "Evidence")),
                    body.get("filename"), body.get("file_base64"), body.get("uploaded_by", "Admin"),
                )
                return _resp(200, {"id": evidence_id})

            if action == "link_trust_document":
                try:
                    evidence_id = _link_trust_document(
                        conn, body["audit_id"], body.get("finding_id"), body["trust_document_id"],
                        body.get("uploaded_by", "Admin"),
                    )
                except ValueError as e:
                    return _resp(400, {"error": str(e)})
                return _resp(200, {"id": evidence_id})

            return _resp(400, {"error": f"unknown action: {action}"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.exception("audit_management_handler error")
        return _resp(500, {"error": str(e)})
    finally:
        conn.close()
