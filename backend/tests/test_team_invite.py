"""
Tests for issue #265 ("Invite Team") — the new organizations/team_invites
schema (Database methods) and api/team_handler.py business logic.

The one deliberately-unsolved piece, _get_authenticated_email(), is mocked
out here so the rest of the logic (role checks, validation, routing) can be
verified independently of it — see the NotImplementedError docstring in
team_handler.py for why it's unsolved rather than guessed at.

Run from the repo root:
    .venv-test/Scripts/python.exe -I -m pytest backend/tests -v
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(BACKEND_SRC))


# ── config/database.py new methods ──────────────────────────────────────

class TestDatabaseTeamMethods:
    def _make_db(self):
        from config import database
        with patch.object(database, "_get_credentials", return_value={
            "host": "x", "database": "x", "username": "x", "password": "x",
        }), patch.object(database, "psycopg2") as mock_pg:
            mock_conn = MagicMock()
            mock_pg.connect.return_value = mock_conn
            db = database.Database()
        return db, mock_conn

    def test_get_user_by_email_found(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("u1", "a@x.com", "Alice", "org1", "admin", "active")

        result = db.get_user_by_email("a@x.com")

        assert result == {
            "id": "u1", "email": "a@x.com", "full_name": "Alice",
            "organization_id": "org1", "role": "admin", "status": "active",
        }

    def test_get_user_by_email_not_found(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = None

        assert db.get_user_by_email("nobody@x.com") is None

    def test_get_organization_members_maps_rows(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [
            ("u1", "a@x.com", "Alice", "admin", "active", "2026-01-01"),
            ("u2", "b@x.com", "Bob",   "viewer", "active", "2026-01-02"),
        ]

        members = db.get_organization_members("org1")

        assert len(members) == 2
        assert members[0]["email"] == "a@x.com"
        assert members[1]["role"] == "viewer"

    def test_create_team_invite_returns_id_and_commits(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("invite-1",)

        invite_id = db.create_team_invite("org1", "new@x.com", "viewer", "u1")

        assert invite_id == "invite-1"
        mock_conn.commit.assert_called_once()

    def test_revoke_team_invite_true_when_row_affected(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.rowcount = 1

        assert db.revoke_team_invite("invite-1", "org1") is True

    def test_revoke_team_invite_false_when_no_row_affected(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.rowcount = 0

        assert db.revoke_team_invite("does-not-exist", "org1") is False

    def test_deactivate_user_scoped_to_organization(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.rowcount = 1

        assert db.deactivate_user("u2", "org1") is True
        sql, params = cur.execute.call_args[0]
        assert "SET status = 'deactivated'" in sql
        assert params == ("u2", "org1")


# ── api/team_handler.py ──────────────────────────────────────────────────

ADMIN = {"id": "u1", "email": "admin@x.com", "organization_id": "org1", "role": "admin", "status": "active"}
VIEWER = {"id": "u2", "email": "viewer@x.com", "organization_id": "org1", "role": "viewer", "status": "active"}


class TestHandleListTeam:
    def test_unauthorized_without_caller(self):
        import api.team_handler as th
        with patch.object(th, "_get_authenticated_email", return_value=None):
            resp = th.handle_list_team({}, MagicMock())
        assert resp["statusCode"] == 401

    def test_lists_members_and_invites_for_callers_org(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.get_organization_members.return_value = [ADMIN, VIEWER]
        db.list_pending_invites.return_value = [{"email": "pending@x.com", "role": "viewer"}]

        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_list_team({}, db)

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert len(body["members"]) == 2
        assert body["pending_invites"][0]["email"] == "pending@x.com"
        db.get_organization_members.assert_called_once_with("org1")


class TestHandleInviteMember:
    def _event(self, email="new@x.com", role="viewer"):
        return {"body": json.dumps({"email": email, "role": role})}

    def test_only_admin_can_invite(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_invite_member(self._event(), db)
        assert resp["statusCode"] == 403

    def test_rejects_missing_email(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_invite_member(self._event(email=""), db)
        assert resp["statusCode"] == 400

    def test_rejects_invalid_role(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_invite_member(self._event(role="superuser"), db)
        assert resp["statusCode"] == 400

    def test_duplicate_invite_returns_409(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.create_team_invite.side_effect = Exception('duplicate key value violates unique constraint')
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_invite_member(self._event(), db)
        assert resp["statusCode"] == 409

    def test_successful_invite_returns_201(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.create_team_invite.return_value = "invite-123"
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_invite_member(self._event(email="New@X.com", role="Viewer"), db)
        assert resp["statusCode"] == 201
        # email/role normalized to lowercase before hitting the DB layer
        db.create_team_invite.assert_called_once_with(
            organization_id="org1", email="new@x.com", role="viewer", invited_by="u1",
        )


class TestHandleDeactivateMember:
    def test_cannot_deactivate_self(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_deactivate_member({}, db, ADMIN["id"])
        assert resp["statusCode"] == 400
        db.deactivate_user.assert_not_called()

    def test_not_found_returns_404(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.deactivate_user.return_value = False
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_deactivate_member({}, db, "someone-else")
        assert resp["statusCode"] == 404

    def test_successful_deactivation(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.deactivate_user.return_value = True
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_deactivate_member({}, db, VIEWER["id"])
        assert resp["statusCode"] == 200


class TestLambdaHandlerRouting:
    def _event(self, method, path, path_params=None, body=None):
        return {
            "requestContext": {"http": {"method": method}},
            "rawPath": path,
            "pathParameters": path_params or {},
            "body": json.dumps(body) if body is not None else None,
        }

    def test_unknown_route_is_404(self):
        import importlib
        import api.team_handler as th
        importlib.reload(th)
        with patch.object(th, "Database") as MockDatabase:
            MockDatabase.return_value.get_user_by_email.return_value = ADMIN
            resp = th.lambda_handler(self._event("PATCH", "/team/nonsense"), None)
        assert resp["statusCode"] == 404

    def test_auth_not_implemented_surfaces_as_501_not_a_crash(self):
        import importlib
        import api.team_handler as th
        importlib.reload(th)
        with patch.object(th, "Database") as MockDatabase:
            MockDatabase.return_value.get_user_by_email.return_value = ADMIN
            resp = th.lambda_handler(self._event("GET", "/team"), None)
        assert resp["statusCode"] == 501
