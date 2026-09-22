"""
Local, zero-AWS proof that api/auditor_handler.py's real business logic
works end-to-end against a REAL (if lightweight) database — same approach
as local_team_demo.py, just for issue #266 ("Invite Auditors").

SqliteAuditorDb extends local_team_demo's SqliteTeamDb with the
audit_engagements tables, so it inherits get_user_by_email,
list_organization_cloud_accounts, etc. for free instead of duplicating
them — auditor_handler.py needs both team and engagement methods on the
same db object (handle_create_engagement calls _get_caller, which needs
get_user_by_email).

Run from the repo root:
    .venv-test/Scripts/python.exe backend/scripts/local_auditor_demo.py
"""
import json
import sys
import uuid
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(BACKEND_SRC))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import api.auditor_handler as auditor_handler  # noqa: E402
import api.team_handler as team_handler  # noqa: E402
from local_team_demo import SqliteTeamDb  # noqa: E402

TODAY = date.today()


class SqliteAuditorDb(SqliteTeamDb):
    def __init__(self, path: str):
        super().__init__(path)
        self.conn.execute("""
            CREATE TABLE audit_engagements (
                id TEXT PRIMARY KEY, organization_id TEXT, name TEXT,
                end_date TEXT, created_by TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE engagement_scope (
                engagement_id TEXT, cloud_account_id TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE engagement_auditors (
                id TEXT PRIMARY KEY, engagement_id TEXT, email TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE engagement_evidence_requests (
                id TEXT PRIMARY KEY, engagement_id TEXT, auditor_email TEXT,
                cloud_account_id TEXT, status TEXT DEFAULT 'pending'
            )
        """)
        self.conn.execute("""
            CREATE TABLE engagement_activity_log (
                id TEXT PRIMARY KEY, engagement_id TEXT, auditor_email TEXT,
                action TEXT, details TEXT, rowid_order INTEGER
            )
        """)
        self.conn.commit()

    def list_organization_cloud_accounts(self, organization_id):
        rows = self.conn.execute("""
            SELECT ca.id, ca.account_name, ca.account_id
            FROM cloud_accounts ca
            JOIN users u ON u.email = ca.owner_email
            WHERE u.organization_id = ? AND ca.status = 'active'
        """, (organization_id,)).fetchall()
        return [{"id": r[0], "account_name": r[1], "account_id": r[2]} for r in rows]

    def create_audit_engagement(self, organization_id, name, end_date, created_by, cloud_account_ids, auditor_emails):
        engagement_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO audit_engagements VALUES (?, ?, ?, ?, ?)",
            (engagement_id, organization_id, name, end_date, created_by),
        )
        for cloud_account_id in cloud_account_ids:
            self.conn.execute(
                "INSERT INTO engagement_scope VALUES (?, ?)", (engagement_id, cloud_account_id),
            )
        for email in auditor_emails:
            self.conn.execute(
                "INSERT INTO engagement_auditors VALUES (?, ?, ?)",
                (str(uuid.uuid4()), engagement_id, email.strip().lower()),
            )
        self.conn.commit()
        return engagement_id

    def list_organization_engagements(self, organization_id):
        rows = self.conn.execute(
            "SELECT id, name, end_date FROM audit_engagements WHERE organization_id = ?",
            (organization_id,),
        ).fetchall()
        return [{"id": r[0], "name": r[1], "end_date": r[2], "active": r[2] >= str(TODAY)} for r in rows]

    def get_active_engagement_for_auditor(self, email):
        row = self.conn.execute("""
            SELECT ae.id, ae.organization_id, ae.name, ae.end_date
            FROM engagement_auditors ea
            JOIN audit_engagements ae ON ae.id = ea.engagement_id
            WHERE ea.email = ? AND ae.end_date >= ?
            ORDER BY ae.end_date ASC
            LIMIT 1
        """, (email, str(TODAY))).fetchone()
        if not row:
            return None
        return {"id": row[0], "organization_id": row[1], "name": row[2], "end_date": row[3]}

    def list_engagement_scope(self, engagement_id):
        rows = self.conn.execute("""
            SELECT ca.id, ca.account_name, ca.account_id
            FROM engagement_scope es
            JOIN cloud_accounts ca ON ca.id = es.cloud_account_id
            WHERE es.engagement_id = ?
        """, (engagement_id,)).fetchall()
        return [{"id": r[0], "account_name": r[1], "account_id": r[2]} for r in rows]

    def is_cloud_account_in_engagement_scope(self, engagement_id, cloud_account_id):
        row = self.conn.execute(
            "SELECT 1 FROM engagement_scope WHERE engagement_id = ? AND cloud_account_id = ?",
            (engagement_id, cloud_account_id),
        ).fetchone()
        return row is not None

    def create_evidence_request(self, engagement_id, auditor_email, cloud_account_id):
        request_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO engagement_evidence_requests VALUES (?, ?, ?, ?, 'pending')",
            (request_id, engagement_id, auditor_email, cloud_account_id),
        )
        self.conn.commit()
        return request_id

    def list_evidence_requests(self, engagement_id):
        rows = self.conn.execute(
            "SELECT id, auditor_email, cloud_account_id, status FROM engagement_evidence_requests WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchall()
        return [{"id": r[0], "auditor_email": r[1], "cloud_account_id": r[2], "status": r[3]} for r in rows]

    def resolve_evidence_request(self, request_id, engagement_id, approve):
        cur = self.conn.execute(
            "SELECT cloud_account_id FROM engagement_evidence_requests WHERE id = ? AND engagement_id = ? AND status = 'pending'",
            (request_id, engagement_id),
        )
        row = cur.fetchone()
        if not row:
            return False
        self.conn.execute(
            "UPDATE engagement_evidence_requests SET status = ? WHERE id = ?",
            ("approved" if approve else "denied", request_id),
        )
        if approve:
            self.conn.execute("INSERT INTO engagement_scope VALUES (?, ?)", (engagement_id, row[0]))
        self.conn.commit()
        return True

    def log_engagement_activity(self, engagement_id, auditor_email, action, details=None):
        n = self.conn.execute("SELECT COUNT(*) FROM engagement_activity_log").fetchone()[0]
        self.conn.execute(
            "INSERT INTO engagement_activity_log VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), engagement_id, auditor_email, action, json.dumps(details or {}), n),
        )
        self.conn.commit()

    def get_engagement_activity(self, engagement_id, limit=100):
        rows = self.conn.execute(
            "SELECT auditor_email, action, details FROM engagement_activity_log WHERE engagement_id = ? ORDER BY rowid_order DESC LIMIT ?",
            (engagement_id, limit),
        ).fetchall()
        return [{"auditor_email": r[0], "action": r[1], "details": json.loads(r[2])} for r in rows]

    def get_cloud_account_compliance(self, cloud_account_id):
        row = self.conn.execute(
            "SELECT account_name FROM cloud_accounts WHERE id = ?", (cloud_account_id,),
        ).fetchone()
        if not row:
            return None
        return {"account_name": row[0], "compliance_score": {"score": 88}, "last_scan_at": None}


def call_auditor(method, path, path_params=None, body=None):
    event = {
        "requestContext": {"http": {"method": method}},
        "rawPath": path,
        "pathParameters": path_params or {},
        "body": json.dumps(body) if body is not None else None,
    }
    resp = auditor_handler.lambda_handler(event, None)
    print(f"\n>>> {method} {path}" + (f"  body={body}" if body else ""))
    print(f"    status={resp['statusCode']}  body={resp['body']}")
    return resp


def main():
    import os
    import tempfile
    db_path = tempfile.mktemp(suffix=".sqlite")

    bootstrap = SqliteAuditorDb(db_path)
    org_id, admin_id = bootstrap.seed("Acme BV", "admin@acme.com")
    prod_account_id = bootstrap.add_cloud_account("admin@acme.com", "Acme prod-aws")
    staging_account_id = bootstrap.add_cloud_account("admin@acme.com", "Acme staging-aws")
    bootstrap.close()
    print(f"Seeded org={org_id[:8]}…  prod_account={prod_account_id[:8]}…  staging_account={staging_account_id[:8]}…")

    def fresh_db():
        c = SqliteAuditorDb.__new__(SqliteAuditorDb)
        import sqlite3
        c.conn = sqlite3.connect(db_path)
        return c

    # Acceptance criterion #1: admin creates an engagement scoped to only
    # the prod account, and assigns one external auditor.
    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="admin@acme.com"):
        resp = call_auditor("POST", "/auditors/engagements", body={
            "name": "Q4 SOC2 Audit", "end_date": str(TODAY + timedelta(days=7)),
            "cloud_account_ids": [prod_account_id], "auditor_emails": ["auditor@bigfour.com"],
        })
        engagement_id = json.loads(resp["body"])["engagement_id"]

    # AC1, read side: the auditor only sees the prod account — staging is
    # NOT in scope, proving "only the approved audit scope is accessible".
    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="auditor@bigfour.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="auditor@bigfour.com"):
        call_auditor("GET", "/auditor/scope")

    # An unrelated auditor with no engagement at all is rejected outright.
    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="stranger@nowhere.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="stranger@nowhere.com"):
        call_auditor("GET", "/auditor/scope")  # expect 401

    # The auditor tries to download evidence for staging — out of scope,
    # correctly rejected, nothing logged.
    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="auditor@bigfour.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="auditor@bigfour.com"):
        call_auditor("GET", f"/auditor/evidence/{staging_account_id}",
                     path_params={"cloud_account_id": staging_account_id})  # expect 403

    # Acceptance criterion #2: the auditor requests staging be added too.
    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="auditor@bigfour.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="auditor@bigfour.com"):
        resp = call_auditor("POST", "/auditor/evidence-requests", body={"cloud_account_id": staging_account_id})
        request_id = json.loads(resp["body"])["request_id"]

    # Admin approves it — staging now becomes accessible, nothing else changes.
    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="admin@acme.com"):
        call_auditor("PATCH", f"/auditors/engagements/{engagement_id}/requests/{request_id}",
                     path_params={"engagement_id": engagement_id, "request_id": request_id},
                     body={"approve": True})

    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="auditor@bigfour.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="auditor@bigfour.com"):
        call_auditor("GET", "/auditor/scope")  # now includes staging too

    # Acceptance criterion #4: downloading evidence for the now-approved
    # staging account succeeds and is logged.
    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="auditor@bigfour.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="auditor@bigfour.com"):
        call_auditor("GET", f"/auditor/evidence/{staging_account_id}",
                     path_params={"cloud_account_id": staging_account_id})

    # Acceptance criterion #5: admin opens the activity dashboard and sees
    # both the evidence request and the download.
    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="admin@acme.com"):
        call_auditor("GET", f"/auditors/engagements/{engagement_id}/activity",
                     path_params={"engagement_id": engagement_id})

    # Acceptance criterion #3: fast-forward past the engagement's end date
    # by creating a second, already-closed engagement — no revocation
    # action is ever taken, the auditor simply stops matching.
    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="admin@acme.com"):
        resp = call_auditor("POST", "/auditors/engagements", body={
            "name": "Already-closed engagement", "end_date": str(TODAY - timedelta(days=1)),
            "cloud_account_ids": [prod_account_id], "auditor_emails": ["expired.auditor@bigfour.com"],
        })

    with patch.object(auditor_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="expired.auditor@bigfour.com"), \
         patch.object(auditor_handler, "_get_authenticated_email", return_value="expired.auditor@bigfour.com"):
        call_auditor("GET", "/auditor/scope")  # expect 401 — engagement already ended

    os.remove(db_path)
    print("\nDone — every response above came from real SQL against a real (SQLite) database,")
    print("through the actual, unmodified api/auditor_handler.py code.")


if __name__ == "__main__":
    main()
