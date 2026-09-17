"""
Local, zero-AWS proof that api/team_handler.py's real business logic works
end-to-end against a REAL (if lightweight) database — not the mocked
pytest suite, an actual SQLite file getting written to and read back.

This does NOT use the production Database class (that's psycopg2/Postgres-
specific and needs real AWS credentials) or the real 002_organizations_and_team.sql
migration (Postgres-only syntax). Instead it's a small SQLite stand-in with
the exact same method signatures team_handler.py calls, so the handler code
itself is exercised completely unmodified and unmocked.

Run from the repo root:
    .venv-test/Scripts/python.exe backend/scripts/local_team_demo.py
"""
import json
import sqlite3
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(BACKEND_SRC))

import api.team_handler as team_handler  # noqa: E402


class SqliteTeamDb:
    """Same public methods as config.database.Database's team section,
    backed by a throwaway SQLite file instead of real Postgres."""

    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.execute("""
            CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, mfa_required INTEGER DEFAULT 0)
        """)
        self.conn.execute("""
            CREATE TABLE users (
                id TEXT PRIMARY KEY, email TEXT, full_name TEXT,
                organization_id TEXT, role TEXT, status TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE team_invites (
                id TEXT PRIMARY KEY, organization_id TEXT, email TEXT,
                role TEXT, invited_by TEXT, status TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE team_audit_log (
                id TEXT PRIMARY KEY, organization_id TEXT, actor_user_id TEXT,
                action TEXT, target_user_id TEXT, details TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE cloud_accounts (id TEXT PRIMARY KEY, owner_email TEXT, account_name TEXT)
        """)
        self.conn.execute("""
            CREATE TABLE shared_resources (
                id TEXT PRIMARY KEY, organization_id TEXT, resource_type TEXT,
                resource_name TEXT, created_by TEXT
            )
        """)
        self.conn.commit()

    def add_cloud_account(self, owner_email: str, account_name: str) -> str:
        account_id = str(uuid.uuid4())
        self.conn.execute("INSERT INTO cloud_accounts VALUES (?, ?, ?)", (account_id, owner_email, account_name))
        self.conn.commit()
        return account_id

    def cloud_accounts_owned_by(self, email: str):
        return self.conn.execute(
            "SELECT id, account_name, owner_email FROM cloud_accounts WHERE owner_email = ?", (email,)
        ).fetchall()

    def seed(self, org_name: str, admin_email: str) -> tuple[str, str]:
        org_id, user_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.conn.execute("INSERT INTO organizations (id, name) VALUES (?, ?)", (org_id, org_name))
        self.conn.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?, 'admin', 'active')",
            (user_id, admin_email, "Test Admin", org_id),
        )
        self.conn.commit()
        return org_id, user_id

    def add_viewer(self, org_id: str, email: str) -> str:
        user_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?, 'viewer', 'active')",
            (user_id, email, "Some Viewer", org_id),
        )
        self.conn.commit()
        return user_id

    def simulate_fresh_signup(self, email: str) -> tuple[str, str]:
        """
        Mimics what the (unmodified, not-in-this-repo) Cognito signup
        trigger + the new assign_default_organization() Postgres trigger
        do together: a brand new user lands in their own solo org, with
        no idea an invite exists for them yet.
        """
        user_id, org_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.conn.execute("INSERT INTO organizations (id, name) VALUES (?, ?)", (org_id, f"{email}'s org"))
        self.conn.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?, 'admin', 'active')",
            (user_id, email, None, org_id),
        )
        self.conn.commit()
        return user_id, org_id

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
            "SELECT id, name, mfa_required FROM organizations WHERE id = ?",
            (organization_id,),
        ).fetchone()
        if not row:
            return None
        return {"id": row[0], "name": row[1], "mfa_required": bool(row[2])}

    def set_organization_mfa_policy(self, organization_id, required):
        cur = self.conn.execute(
            "UPDATE organizations SET mfa_required = ? WHERE id = ?",
            (1 if required else 0, organization_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

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
        # No real cognito_sub in this stand-in — see main()'s comment on
        # why session termination is faked rather than exercised for real.
        return {"id": row[0], "email": row[1], "cognito_sub": f"fake-sub-{row[0][:8]}", "role": row[3], "status": row[4]}

    def reassign_owned_cloud_accounts(self, from_email, to_email):
        cur = self.conn.execute(
            "UPDATE cloud_accounts SET owner_email = ? WHERE owner_email = ?",
            (to_email, from_email),
        )
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
                "created_at": f"entry #{r[2]}",  # no real timestamp column in this stand-in
                "actor_email": r[3], "target_email": r[4],
            }
            for r in rows
        ]

    def create_shared_resource(self, organization_id, resource_name, created_by):
        resource_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO shared_resources VALUES (?, ?, 'dashboard', ?, ?)",
            (resource_id, organization_id, resource_name, created_by),
        )
        self.conn.commit()
        return resource_id

    def list_shared_resources(self, organization_id):
        rows = self.conn.execute(
            "SELECT id, resource_name, resource_type FROM shared_resources WHERE organization_id = ?",
            (organization_id,),
        ).fetchall()
        return [{"id": r[0], "resource_name": r[1], "resource_type": r[2]} for r in rows]

    def delete_shared_resource(self, resource_id, organization_id):
        cur = self.conn.execute(
            "DELETE FROM shared_resources WHERE id = ? AND organization_id = ?",
            (resource_id, organization_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def close(self):
        self.conn.close()


def call(method, path, path_params=None, body=None):
    event = {
        "requestContext": {"http": {"method": method}},
        "rawPath": path,
        "pathParameters": path_params or {},
        "body": json.dumps(body) if body is not None else None,
    }
    resp = team_handler.lambda_handler(event, None)
    print(f"\n>>> {method} {path}" + (f"  body={body}" if body else ""))
    print(f"    status={resp['statusCode']}  body={resp['body']}")
    return resp


def main():
    import os
    import tempfile
    db_path = tempfile.mktemp(suffix=".sqlite")

    bootstrap = SqliteTeamDb(db_path)
    org_id, admin_id = bootstrap.seed("Acme BV", "admin@acme.com")
    viewer_id = bootstrap.add_viewer(org_id, "existing.viewer@acme.com")
    bootstrap.close()
    print(f"Seeded org={org_id[:8]}…  admin_id={admin_id[:8]}…  viewer_id={viewer_id[:8]}…")

    # Every call below opens a FRESH connection to the same on-disk file and
    # closes it afterwards — exactly matching how the real Lambda opens/
    # closes a Database() per invocation. team_handler.py itself is
    # completely unaware this isn't real Postgres.
    def fresh_db():
        c = SqliteTeamDb.__new__(SqliteTeamDb)
        c.conn = sqlite3.connect(db_path)
        return c

    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"):

        call("GET", "/team")

        resp = call("POST", "/team/invite", body={"email": "new.colleague@acme.com", "role": "security"})
        invite_id = json.loads(resp["body"])["invite_id"]

        call("GET", "/team")

        call("POST", "/team/invite", body={"email": "new.colleague@acme.com", "role": "viewer"})

    # The invited person now signs up completely normally — landing in
    # their own solo organization, same as anyone who signs up unrelated
    # to an invite. They have no idea an invite is waiting for them.
    signup_conn = fresh_db()
    _, colleague_solo_org = signup_conn.simulate_fresh_signup("new.colleague@acme.com")
    signup_conn.close()
    print(f"\n[new.colleague@acme.com just signed up — landed in solo org {colleague_solo_org[:8]}…, unaware of the pending invite]")

    # Their very first authenticated page load fires this automatically
    # (see useRequireAuth.ts) — no click required from them.
    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="new.colleague@acme.com"):
        call("POST", "/team/accept-invite")

    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"):
        resp = call("GET", "/team")  # new.colleague should now show up as an Acme BV member
        colleague_id = next(
            m["id"] for m in json.loads(resp["body"])["members"] if m["email"] == "new.colleague@acme.com"
        )

        call("DELETE", f"/team/invite/{invite_id}", path_params={"id": invite_id})

        # Acceptance criterion #2: an admin changes someone's role.
        call("PATCH", f"/team/member/{colleague_id}", path_params={"id": colleague_id}, body={"role": "compliance"})

        call("GET", "/team")  # new.colleague's role should now read 'compliance'

    # Now try the exact same invite request, but authenticated as the
    # non-admin viewer — should be forbidden.
    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="existing.viewer@acme.com"):
        call("POST", "/team/invite", body={"email": "someone@acme.com", "role": "viewer"})

    # A completely unrelated second company. Its admin should NOT be able
    # to touch Acme BV's people, even by guessing/reusing a real user_id.
    other_conn = fresh_db()
    other_org_id, other_admin_id = other_conn.seed("Contoso Inc", "boss@contoso.com")
    other_conn.close()
    print(f"\n[Contoso Inc is a totally separate organization — org={other_org_id[:8]}…]")

    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="boss@contoso.com"):
        call("PATCH", f"/team/member/{colleague_id}",
             path_params={"id": colleague_id}, body={"role": "admin"})  # colleague_id belongs to Acme BV, not Contoso

    # Acceptance criterion #3: an admin turns on the MFA policy for Acme BV.
    # (Actually enforcing this — blocking a real login without MFA
    # configured — is a client-side Amplify/Cognito check that can't be
    # exercised against SQLite; only the policy toggle + its audit trail
    # are provable here.)
    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="existing.viewer@acme.com"):
        call("PATCH", "/team/mfa-policy", body={"required": True})  # non-admin -> forbidden

    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"):
        call("PATCH", "/team/mfa-policy", body={"required": True})
        call("GET", "/team")  # mfa_required should now read true

    # Acceptance criterion #5: admin shares a dashboard with the team.
    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"):
        resp = call("POST", "/team/shared-resources", body={"resource_name": "Q1 Compliance Dashboard"})
        shared_resource_id = json.loads(resp["body"])["resource_id"]

    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="existing.viewer@acme.com"):
        call("GET", "/team/shared-resources")  # existing.viewer can see it — still an active member

    # Now existing.viewer is offboarded — no one ever "unshared" anything
    # from them specifically. This is the actual proof of AC5: access was
    # never a stored grant, only ever computed from current membership.
    viewer_conn = fresh_db()
    viewer = viewer_conn.get_user_by_email("existing.viewer@acme.com")
    viewer_conn.close()

    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"):
        call("DELETE", f"/team/member/{viewer['id']}", path_params={"id": viewer["id"]})

    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="existing.viewer@acme.com"):
        call("GET", "/team/shared-resources")  # same token as before -> now 401, automatically

    # Acceptance criterion #4: new.colleague owns an AWS account and then
    # leaves the organization.
    setup_conn = fresh_db()
    cloud_account_id = setup_conn.add_cloud_account("new.colleague@acme.com", "prod-aws-account")
    setup_conn.close()
    print(f"\n[new.colleague@acme.com owns a connected AWS account: {cloud_account_id[:8]}…]")

    # terminate_all_sessions() makes a real boto3 Cognito call — can't be
    # exercised here without a real user pool. Patched to a fake success so
    # the rest of the offboarding flow (deactivation, reassignment, audit
    # log) can still be proven end-to-end; see
    # backend/tests/test_cognito_admin.py for that function tested on its
    # own terms (including failure handling).
    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"), \
         patch.object(team_handler, "terminate_all_sessions", return_value=True) as fake_terminate:
        call("DELETE", f"/team/member/{colleague_id}", path_params={"id": colleague_id})
        print(f"    (terminate_all_sessions called with: {fake_terminate.call_args})")

    verify_conn = fresh_db()
    still_owned = verify_conn.cloud_accounts_owned_by("new.colleague@acme.com")
    now_owned_by_admin = verify_conn.cloud_accounts_owned_by("admin@acme.com")
    verify_conn.close()
    print(f"    accounts still owned by new.colleague: {len(still_owned)} (should be 0)")
    print(f"    accounts now owned by admin@acme.com: {[a[1] for a in now_owned_by_admin]}")

    # Acceptance criterion #6: view the audit log through the real
    # endpoint (GET /team/audit-log), not just a direct DB query — proves
    # the whole trail (invites, role change, MFA policy, offboarding) is
    # visible with actor/target emails and not just to admins.
    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="existing.viewer@acme.com"):
        call("GET", "/team/audit-log")  # non-admin -> forbidden

    with patch.object(team_handler, "Database", side_effect=fresh_db), \
         patch.object(team_handler, "_get_authenticated_email", return_value="admin@acme.com"):
        resp = call("GET", "/team/audit-log")
        print("\n[audit log entries, oldest last]")
        for entry in json.loads(resp["body"])["entries"]:
            print(f"    {entry}")

    os.remove(db_path)
    print("\nDone — every response above came from real SQL against a real (SQLite) database,")
    print("through the actual, unmodified api/team_handler.py code.")


if __name__ == "__main__":
    main()
