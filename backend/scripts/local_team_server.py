"""
local_team_server.py

⚠️ LOCAL DEV TOOL ONLY — NEVER DEPLOY THIS. It hardcodes an auth bypass
(every request is treated as the seeded admin, regardless of the
Authorization header) so the real Team.tsx page can be clicked around in
a real browser without a real backend deployment. That's fine on your
own machine for a few minutes; it would be a serious security hole
anywhere else.

What this does: runs a tiny local HTTP server on localhost:8787 that
forwards GET/POST/PATCH/DELETE /team* requests into the real,
unmodified api/team_handler.py — backed by a throwaway SQLite database,
same approach as local_team_demo.py, just reachable from a browser
instead of only from a Python script.

Setup (one-time, per test session):
  1. Run this script:
       .venv-test/Scripts/python.exe backend/scripts/local_team_server.py
     Leave it running in its own terminal.
  2. Point the frontend at it — temporarily edit
     frontend/public/config.json's REACT_APP_API_BASE_URL to
     "http://localhost:8787", OR just run:
       git checkout -- frontend/public/config.json   # to undo afterwards
  3. npm run dev, log in with your real account, go to /settings/team.
  4. When done: Ctrl+C this server, then
       git checkout -- frontend/public/config.json
     to restore the real API URL.
"""
import json
import sqlite3
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(BACKEND_SRC))

import api.team_handler as team_handler  # noqa: E402
import api.auditor_handler as auditor_handler  # noqa: E402

PORT = 8787
DB_PATH = str(Path(__file__).resolve().parent / "_local_team_server.sqlite")

# Change this if you log into Niagaros with a different address.
ADMIN_EMAIL = "hicham.bellahlal2@hotmail.com"


def _today() -> str:
    from datetime import date
    return date.today().isoformat()


def _in_days(n: int) -> str:
    from datetime import date, timedelta
    return (date.today() + timedelta(days=n)).isoformat()


class SqliteTeamDb:
    """Same shape as backend/scripts/local_team_demo.py's stand-in."""

    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)

    def get_user_by_email(self, email):
        row = self.conn.execute(
            "SELECT id, email, full_name, organization_id, role, status FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row:
            return None
        return dict(zip(["id", "email", "full_name", "organization_id", "role", "status"], row))

    def get_organization(self, organization_id):
        row = self.conn.execute(
            "SELECT id, name, mfa_required FROM organizations WHERE id = ?", (organization_id,)
        ).fetchone()
        if not row:
            return None
        return {"id": row[0], "name": row[1], "mfa_required": bool(row[2])}

    def set_organization_mfa_policy(self, organization_id, required):
        self.conn.execute("UPDATE organizations SET mfa_required = ? WHERE id = ?",
                           (1 if required else 0, organization_id))
        self.conn.commit()
        return True

    def get_organization_members(self, organization_id):
        rows = self.conn.execute(
            "SELECT id, email, full_name, role, status FROM users WHERE organization_id = ?",
            (organization_id,),
        ).fetchall()
        return [dict(zip(["id", "email", "full_name", "role", "status"], r)) for r in rows]

    def create_team_invite(self, organization_id, email, role, invited_by):
        existing = self.conn.execute(
            "SELECT 1 FROM team_invites WHERE organization_id = ? AND email = ?",
            (organization_id, email),
        ).fetchone()
        if existing:
            raise Exception("duplicate key value violates unique constraint")
        invite_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO team_invites VALUES (?, ?, ?, ?, ?, 'pending')",
            (invite_id, organization_id, email, role, invited_by),
        )
        self.conn.commit()
        return invite_id

    def list_pending_invites(self, organization_id):
        rows = self.conn.execute(
            "SELECT id, email, role FROM team_invites WHERE organization_id = ? AND status = 'pending'",
            (organization_id,),
        ).fetchall()
        return [dict(zip(["id", "email", "role"], r)) for r in rows]

    def revoke_team_invite(self, invite_id, organization_id):
        cur = self.conn.execute(
            "UPDATE team_invites SET status = 'revoked' WHERE id = ? AND organization_id = ? AND status = 'pending' RETURNING email",
            (invite_id, organization_id),
        )
        row = cur.fetchone()
        self.conn.commit()
        return row[0] if row else None

    def accept_pending_invite(self, user_id, email):
        row = self.conn.execute(
            "SELECT id, organization_id, role FROM team_invites WHERE email = ? AND status = 'pending'",
            (email,),
        ).fetchone()
        if not row:
            return None
        invite_id, organization_id, role = row
        self.conn.execute("UPDATE users SET organization_id = ?, role = ? WHERE id = ?",
                           (organization_id, role, user_id))
        self.conn.execute("UPDATE team_invites SET status = 'accepted' WHERE id = ?", (invite_id,))
        self.conn.commit()
        return {"organization_id": organization_id, "role": role}

    def get_user_by_id(self, user_id, organization_id):
        row = self.conn.execute(
            "SELECT id, email, full_name, role, status FROM users WHERE id = ? AND organization_id = ?",
            (user_id, organization_id),
        ).fetchone()
        if not row:
            return None
        return {"id": row[0], "email": row[1], "cognito_sub": f"fake-sub-{row[0][:8]}", "role": row[3], "status": row[4]}

    def reassign_owned_cloud_accounts(self, from_email, to_email):
        cur = self.conn.execute("UPDATE cloud_accounts SET owner_email = ? WHERE owner_email = ?",
                                 (to_email, from_email))
        self.conn.commit()
        return cur.rowcount

    def deactivate_user(self, user_id, organization_id):
        cur = self.conn.execute(
            "UPDATE users SET status = 'deactivated' WHERE id = ? AND organization_id = ?",
            (user_id, organization_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def update_user_role(self, user_id, organization_id, new_role):
        cur = self.conn.execute(
            "UPDATE users SET role = ? WHERE id = ? AND organization_id = ?",
            (new_role, user_id, organization_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def log_audit_event(self, organization_id, actor_user_id, action, target_user_id=None, details=None):
        self.conn.execute(
            "INSERT INTO team_audit_log VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), organization_id, actor_user_id, action, target_user_id, json.dumps(details or {})),
        )
        self.conn.commit()

    def get_audit_log(self, organization_id, limit=100):
        rows = self.conn.execute("""
            SELECT al.action, al.details, al.rowid, actor.email, target.email
            FROM team_audit_log al
            LEFT JOIN users actor  ON actor.id  = al.actor_user_id
            LEFT JOIN users target ON target.id = al.target_user_id
            WHERE al.organization_id = ?
            ORDER BY al.rowid DESC
            LIMIT ?
        """, (organization_id, limit)).fetchall()
        return [
            {
                "action": r[0], "details": json.loads(r[1]) if isinstance(r[1], str) else r[1],
                "created_at": f"entry #{r[2]}",
                "actor_email": r[3], "target_email": r[4],
            }
            for r in rows
        ]

    def list_organization_cloud_accounts(self, organization_id):
        rows = self.conn.execute("""
            SELECT ca.id, ca.account_name, ca.account_id
            FROM cloud_accounts ca
            JOIN users u ON u.email = ca.owner_email
            WHERE u.organization_id = ? AND ca.status = 'active'
        """, (organization_id,)).fetchall()
        return [{"id": r[0], "account_name": r[1], "account_id": r[2]} for r in rows]

    def create_shared_resource(self, organization_id, resource_name, created_by, cloud_account_id):
        resource_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO shared_resources VALUES (?, ?, 'dashboard', ?, ?, ?)",
            (resource_id, organization_id, resource_name, created_by, cloud_account_id),
        )
        self.conn.commit()
        return resource_id

    def list_shared_resources(self, organization_id):
        rows = self.conn.execute(
            "SELECT id, resource_name, resource_type, cloud_account_id FROM shared_resources WHERE organization_id = ?",
            (organization_id,),
        ).fetchall()
        return [
            {"id": r[0], "resource_name": r[1], "resource_type": r[2], "cloud_account_id": r[3]}
            for r in rows
        ]

    def delete_shared_resource(self, resource_id, organization_id):
        cur = self.conn.execute(
            "DELETE FROM shared_resources WHERE id = ? AND organization_id = ?",
            (resource_id, organization_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    # ── audit engagements (issue #266, "Invite Auditors") ────────────

    def list_organization_engagements(self, organization_id):
        rows = self.conn.execute(
            "SELECT id, name, start_date, end_date FROM audit_engagements WHERE organization_id = ?",
            (organization_id,),
        ).fetchall()
        today = _today()
        return [
            {"id": r[0], "name": r[1], "start_date": r[2], "end_date": r[3], "active": r[3] >= today}
            for r in rows
        ]

    def create_audit_engagement(self, organization_id, name, end_date, created_by, cloud_account_ids, auditor_emails):
        engagement_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO audit_engagements VALUES (?, ?, ?, ?, ?, ?)",
            (engagement_id, organization_id, name, _today(), end_date, created_by),
        )
        for cloud_account_id in cloud_account_ids:
            self.conn.execute("INSERT INTO engagement_scope VALUES (?, ?)", (engagement_id, cloud_account_id))
        for email in auditor_emails:
            self.conn.execute(
                "INSERT INTO engagement_auditors VALUES (?, ?, ?)",
                (str(uuid.uuid4()), engagement_id, email.strip().lower()),
            )
        self.conn.commit()
        return engagement_id

    def get_active_engagement_for_auditor(self, email):
        row = self.conn.execute("""
            SELECT ae.id, ae.organization_id, ae.name, ae.end_date
            FROM engagement_auditors ea
            JOIN audit_engagements ae ON ae.id = ea.engagement_id
            WHERE ea.email = ? AND ae.end_date >= ?
            ORDER BY ae.end_date ASC
            LIMIT 1
        """, (email, _today())).fetchone()
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
            "INSERT INTO engagement_evidence_requests VALUES (?, ?, ?, ?, 'pending', NULL)",
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
        row = self.conn.execute(
            "SELECT cloud_account_id FROM engagement_evidence_requests WHERE id = ? AND engagement_id = ? AND status = 'pending'",
            (request_id, engagement_id),
        ).fetchone()
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
            "SELECT auditor_email, action, details FROM engagement_activity_log "
            "WHERE engagement_id = ? ORDER BY rowid_order DESC LIMIT ?",
            (engagement_id, limit),
        ).fetchall()
        return [{"auditor_email": r[0], "action": r[1], "details": json.loads(r[2]), "created_at": ""} for r in rows]

    def get_cloud_account_compliance(self, cloud_account_id):
        row = self.conn.execute(
            "SELECT account_name FROM cloud_accounts WHERE id = ?", (cloud_account_id,),
        ).fetchone()
        if not row:
            return None
        return {"account_name": row[0], "compliance_score": {"score": 88}, "last_scan_at": None}

    def close(self):
        self.conn.close()


def seed_database():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, mfa_required INTEGER DEFAULT 0)")
    conn.execute("""CREATE TABLE users (
        id TEXT PRIMARY KEY, email TEXT, full_name TEXT, organization_id TEXT, role TEXT, status TEXT
    )""")
    conn.execute("""CREATE TABLE team_invites (
        id TEXT PRIMARY KEY, organization_id TEXT, email TEXT, role TEXT, invited_by TEXT, status TEXT
    )""")
    conn.execute("""CREATE TABLE team_audit_log (
        id TEXT PRIMARY KEY, organization_id TEXT, actor_user_id TEXT,
        action TEXT, target_user_id TEXT, details TEXT
    )""")
    conn.execute("""CREATE TABLE cloud_accounts (
        id TEXT PRIMARY KEY, owner_email TEXT, account_name TEXT,
        account_id TEXT, status TEXT DEFAULT 'active'
    )""")
    conn.execute("""CREATE TABLE shared_resources (
        id TEXT PRIMARY KEY, organization_id TEXT, resource_type TEXT,
        resource_name TEXT, created_by TEXT, cloud_account_id TEXT
    )""")
    conn.execute("""CREATE TABLE audit_engagements (
        id TEXT PRIMARY KEY, organization_id TEXT, name TEXT,
        start_date TEXT, end_date TEXT, created_by TEXT
    )""")
    conn.execute("CREATE TABLE engagement_scope (engagement_id TEXT, cloud_account_id TEXT)")
    conn.execute("CREATE TABLE engagement_auditors (id TEXT PRIMARY KEY, engagement_id TEXT, email TEXT)")
    conn.execute("""CREATE TABLE engagement_evidence_requests (
        id TEXT PRIMARY KEY, engagement_id TEXT, auditor_email TEXT,
        cloud_account_id TEXT, status TEXT DEFAULT 'pending', resolved_at TEXT
    )""")
    conn.execute("""CREATE TABLE engagement_activity_log (
        id TEXT PRIMARY KEY, engagement_id TEXT, auditor_email TEXT,
        action TEXT, details TEXT, rowid_order INTEGER
    )""")

    org_id, admin_id, colleague_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    cloud_account_id = str(uuid.uuid4())
    conn.execute("INSERT INTO organizations (id, name) VALUES (?, ?)", (org_id, "Jouw testbedrijf"))
    conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, 'admin', 'active')",
                 (admin_id, ADMIN_EMAIL, "Jij (admin)", org_id))
    conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, 'viewer', 'active')",
                 (colleague_id, "test.collega@example.com", "Test Collega", org_id))
    conn.execute("INSERT INTO cloud_accounts VALUES (?, ?, ?, ?, 'active')",
                 (cloud_account_id, "test.collega@example.com", "test-aws-account", "123456789012"))
    conn.execute("INSERT INTO shared_resources VALUES (?, ?, 'dashboard', ?, ?, ?)",
                 (str(uuid.uuid4()), org_id, "test-aws-account", admin_id, cloud_account_id))

    # A couple of pre-seeded audit log entries so /settings/team shows
    # something in the "Audit log" section immediately, without you
    # having to click anything first.
    conn.execute("INSERT INTO team_audit_log VALUES (?, ?, ?, 'invite_created', NULL, ?)",
                 (str(uuid.uuid4()), org_id, admin_id, json.dumps({"email": "test.collega@example.com", "role": "viewer"})))
    conn.execute("INSERT INTO team_audit_log VALUES (?, ?, ?, 'role_changed', ?, ?)",
                 (str(uuid.uuid4()), org_id, admin_id, colleague_id, json.dumps({"new_role": "viewer"})))

    # Pre-seeded active engagement so /settings/auditor and /auditor both
    # show something immediately, without you having to click anything first.
    engagement_id = str(uuid.uuid4())
    conn.execute("INSERT INTO audit_engagements VALUES (?, ?, ?, ?, ?, ?)",
                 (engagement_id, org_id, "Q4 Compliance Audit", _today(), _in_days(7), admin_id))
    conn.execute("INSERT INTO engagement_scope VALUES (?, ?)", (engagement_id, cloud_account_id))
    conn.execute("INSERT INTO engagement_auditors VALUES (?, ?, ?)",
                 (str(uuid.uuid4()), engagement_id, "external.auditor@example.com"))

    conn.commit()
    conn.close()
    print(f"Testdata klaar: jij ({ADMIN_EMAIL}) bent admin, 'Test Collega' staat klaar om te deactiveren.")


def fresh_db():
    db = SqliteTeamDb.__new__(SqliteTeamDb)
    db.conn = sqlite3.connect(DB_PATH)
    return db


# Mutable "who is calling right now" — lets you flip between admin and
# Test Collega from the SAME real browser login, without needing a second
# real Cognito account. See /_test/act-as below.
current_actor = {"email": ADMIN_EMAIL}


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _dispatch(self, method):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length else None

        path = self.path.split("?")[0]

        # Test-only meta-route: switch who subsequent requests act as.
        # Not part of the real API — never touches team_handler.py.
        if path.rstrip("/") == "/_test/act-as":
            new_email = json.loads(body or "{}").get("email", ADMIN_EMAIL)
            current_actor["email"] = new_email
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"acting_as": new_email}).encode())
            print(f"[now acting as {new_email}]")
            return

        path_params = {}
        if path.startswith("/team/member/"):
            path_params["id"] = path.rsplit("/", 1)[-1]
        elif path.startswith("/team/invite/"):
            path_params["id"] = path.rsplit("/", 1)[-1]
        elif path.startswith("/team/shared-resources/"):
            path_params["id"] = path.rsplit("/", 1)[-1]
        elif path.startswith("/auditor/evidence/"):
            path_params["cloud_account_id"] = path.rsplit("/", 1)[-1]
        elif path.startswith("/auditors/engagements/") and "/requests/" in path:
            parts = path.split("/")  # ["", "auditors", "engagements", "{eid}", "requests", "{rid}"]
            path_params["engagement_id"] = parts[3]
            path_params["request_id"] = parts[5]
        elif path.startswith("/auditors/engagements/") and path.endswith("/requests"):
            path_params["engagement_id"] = path.split("/")[3]
        elif path.startswith("/auditors/engagements/") and path.endswith("/activity"):
            path_params["engagement_id"] = path.split("/")[3]

        event = {
            "requestContext": {"http": {"method": method}},
            "rawPath": path,
            "pathParameters": path_params,
            "body": body,
        }

        is_auditor_route = path.startswith("/auditors/") or path.startswith("/auditor/")
        handler_module = auditor_handler if is_auditor_route else team_handler

        with patch.object(team_handler, "Database", side_effect=fresh_db), \
             patch.object(auditor_handler, "Database", side_effect=fresh_db), \
             patch.object(team_handler, "_get_authenticated_email", side_effect=lambda *_: current_actor["email"]), \
             patch.object(auditor_handler, "_get_authenticated_email", side_effect=lambda *_: current_actor["email"]), \
             patch.object(team_handler, "terminate_all_sessions", return_value=True):
            resp = handler_module.lambda_handler(event, None)

        self.send_response(resp["statusCode"])
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp["body"].encode())
        print(f"{method} {path} -> {resp['statusCode']}")

    def do_GET(self):    self._dispatch("GET")
    def do_POST(self):   self._dispatch("POST")
    def do_PATCH(self):  self._dispatch("PATCH")
    def do_DELETE(self): self._dispatch("DELETE")

    def log_message(self, *args):
        pass  # our own print() above is quieter


if __name__ == "__main__":
    db_file = Path(DB_PATH)
    if db_file.exists():
        db_file.unlink()
    seed_database()
    print(f"Serving /team* on http://localhost:{PORT} — Ctrl+C to stop.")
    ThreadingHTTPServer(("localhost", PORT), Handler).serve_forever()
