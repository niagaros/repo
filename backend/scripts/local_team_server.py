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

PORT = 8787
DB_PATH = str(Path(__file__).resolve().parent / "_local_team_server.sqlite")

# Change this if you log into Niagaros with a different address.
ADMIN_EMAIL = "hicham.bellahlal2@hotmail.com"


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
            "UPDATE team_invites SET status = 'revoked' WHERE id = ? AND organization_id = ? AND status = 'pending'",
            (invite_id, organization_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

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
    conn.execute("CREATE TABLE cloud_accounts (id TEXT PRIMARY KEY, owner_email TEXT, account_name TEXT)")

    org_id, admin_id, colleague_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    conn.execute("INSERT INTO organizations (id, name) VALUES (?, ?)", (org_id, "Jouw testbedrijf"))
    conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, 'admin', 'active')",
                 (admin_id, ADMIN_EMAIL, "Jij (admin)", org_id))
    conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, 'viewer', 'active')",
                 (colleague_id, "test.collega@example.com", "Test Collega", org_id))
    conn.execute("INSERT INTO cloud_accounts VALUES (?, ?, ?)",
                 (str(uuid.uuid4()), "test.collega@example.com", "test-aws-account"))
    conn.commit()
    conn.close()
    print(f"Testdata klaar: jij ({ADMIN_EMAIL}) bent admin, 'Test Collega' staat klaar om te deactiveren.")


def fresh_db():
    db = SqliteTeamDb.__new__(SqliteTeamDb)
    db.conn = sqlite3.connect(DB_PATH)
    return db


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
        path_params = {}
        if path.startswith("/team/member/"):
            path_params["id"] = path.rsplit("/", 1)[-1]
        elif path.startswith("/team/invite/"):
            path_params["id"] = path.rsplit("/", 1)[-1]

        event = {
            "requestContext": {"http": {"method": method}},
            "rawPath": path,
            "pathParameters": path_params,
            "body": body,
        }

        with patch.object(team_handler, "Database", side_effect=fresh_db), \
             patch.object(team_handler, "_get_authenticated_email", return_value=ADMIN_EMAIL), \
             patch.object(team_handler, "terminate_all_sessions", return_value=True):
            resp = team_handler.lambda_handler(event, None)

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
