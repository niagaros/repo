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

    def test_revoke_team_invite_returns_email_when_row_affected(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("revoked@x.com",)

        assert db.revoke_team_invite("invite-1", "org1") == "revoked@x.com"

    def test_revoke_team_invite_none_when_no_row_affected(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = None

        assert db.revoke_team_invite("does-not-exist", "org1") is None

    def test_get_audit_log_maps_rows_with_resolved_emails(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [
            ("role_changed", {"new_role": "security"}, "2026-01-01T00:00:00", "admin@x.com", "viewer@x.com"),
        ]

        entries = db.get_audit_log("org1")

        assert entries == [{
            "action": "role_changed", "details": {"new_role": "security"},
            "created_at": "2026-01-01T00:00:00",
            "actor_email": "admin@x.com", "target_email": "viewer@x.com",
        }]

    def test_accept_pending_invite_moves_user_and_marks_accepted(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("invite-1", "org-target", "security")

        result = db.accept_pending_invite("user-1", "new@x.com")

        assert result == {"organization_id": "org-target", "role": "security"}
        # two UPDATEs: move the user, then mark the invite accepted
        update_calls = [c for c in cur.execute.call_args_list if "UPDATE" in c[0][0]]
        assert len(update_calls) == 2
        assert "UPDATE users SET organization_id" in update_calls[0][0][0]
        assert update_calls[0][0][1] == ("org-target", "security", "user-1")
        assert "UPDATE team_invites SET status = 'accepted'" in update_calls[1][0][0]
        mock_conn.commit.assert_called_once()

    def test_accept_pending_invite_returns_none_when_nothing_pending(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = None

        assert db.accept_pending_invite("user-1", "nobody-invited@x.com") is None

    def test_get_user_by_id_found_and_scoped(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("u2", "b@x.com", "sub-abc", "viewer", "active")

        result = db.get_user_by_id("u2", "org1")

        assert result == {"id": "u2", "email": "b@x.com", "cognito_sub": "sub-abc", "role": "viewer", "status": "active"}
        sql, params = cur.execute.call_args[0]
        assert params == ("u2", "org1")

    def test_get_user_by_id_not_found(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = None

        assert db.get_user_by_id("u2", "org1") is None

    def test_reassign_owned_cloud_accounts(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.rowcount = 3

        count = db.reassign_owned_cloud_accounts("leaving@x.com", "admin@x.com")

        assert count == 3
        sql, params = cur.execute.call_args[0]
        assert "SET owner_email = " in sql
        assert params == ("admin@x.com", "leaving@x.com")
        mock_conn.commit.assert_called_once()

    def test_deactivate_user_scoped_to_organization(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.rowcount = 1

        assert db.deactivate_user("u2", "org1") is True
        sql, params = cur.execute.call_args[0]
        assert "SET status = 'deactivated'" in sql
        assert params == ("u2", "org1")

    def test_update_user_role_scoped_to_organization(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.rowcount = 1

        assert db.update_user_role("u2", "org1", "security") is True
        sql, params = cur.execute.call_args[0]
        assert "SET role = " in sql
        assert params == ("security", "u2", "org1")

    def test_update_user_role_false_when_no_row_affected(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.rowcount = 0

        assert db.update_user_role("does-not-exist", "org1", "viewer") is False

    def test_get_organization_found(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("org1", "Acme", True)

        assert db.get_organization("org1") == {"id": "org1", "name": "Acme", "mfa_required": True}

    def test_get_organization_not_found(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = None

        assert db.get_organization("does-not-exist") is None

    def test_set_organization_mfa_policy(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.rowcount = 1

        assert db.set_organization_mfa_policy("org1", True) is True
        sql, params = cur.execute.call_args[0]
        assert "SET mfa_required = " in sql
        assert params == (True, "org1")

    def test_log_audit_event_inserts_and_commits(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value

        db.log_audit_event("org1", "u1", "role_changed", "u2", {"new_role": "security"})

        sql, params = cur.execute.call_args[0]
        assert "INSERT INTO team_audit_log" in sql
        assert params[:4] == ("org1", "u1", "role_changed", "u2")
        assert json.loads(params[4]) == {"new_role": "security"}
        mock_conn.commit.assert_called_once()

    def test_list_organization_cloud_accounts_maps_rows(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [("acct-1", "Prod AWS", "123456789012")]

        accounts = db.list_organization_cloud_accounts("org1")

        assert accounts == [{"id": "acct-1", "account_name": "Prod AWS", "account_id": "123456789012"}]

    def test_create_shared_resource_returns_id_and_commits(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("resource-1",)

        resource_id = db.create_shared_resource("org1", "Prod AWS", "u1", "acct-1")

        assert resource_id == "resource-1"
        mock_conn.commit.assert_called_once()

    def test_list_shared_resources_maps_rows(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [("r1", "Prod AWS", "dashboard", "2026-01-01", "acct-1")]

        resources = db.list_shared_resources("org1")

        assert resources == [{
            "id": "r1", "resource_name": "Prod AWS",
            "resource_type": "dashboard", "created_at": "2026-01-01",
            "cloud_account_id": "acct-1",
        }]

    def test_delete_shared_resource_scoped_to_organization(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.rowcount = 1

        assert db.delete_shared_resource("r1", "org1") is True
        sql, params = cur.execute.call_args[0]
        assert params == ("r1", "org1")

    def test_delete_shared_resource_false_when_not_found(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.rowcount = 0

        assert db.delete_shared_resource("does-not-exist", "org1") is False


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
        db.get_organization.return_value = {"id": "org1", "name": "Acme", "mfa_required": True}

        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_list_team({}, db)

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert len(body["members"]) == 2
        assert body["pending_invites"][0]["email"] == "pending@x.com"
        assert body["mfa_required"] is True
        db.get_organization_members.assert_called_once_with("org1")

    def test_mfa_required_defaults_to_false_when_org_lookup_fails(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.get_organization_members.return_value = []
        db.list_pending_invites.return_value = []
        db.get_organization.return_value = None

        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_list_team({}, db)

        assert json.loads(resp["body"])["mfa_required"] is False


class TestGetCallerRejectsDeactivated:
    """
    Issue #265, acceptance criterion #5's real mechanism: this is what
    makes 'access is updated automatically based on current membership'
    true everywhere, not just for shared resources — a deactivated
    member's existing, still-valid Cognito token stops granting *any*
    API access the moment their row flips to 'deactivated', with no
    separate cleanup step needed.
    """

    def test_deactivated_user_is_treated_as_unauthenticated(self):
        import api.team_handler as th
        deactivated_admin = {**ADMIN, "status": "deactivated"}
        db = MagicMock()
        db.get_user_by_email.return_value = deactivated_admin

        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_list_team({}, db)

        assert resp["statusCode"] == 401

    def test_active_user_is_accepted(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.get_organization_members.return_value = []
        db.list_pending_invites.return_value = []
        db.get_organization.return_value = None

        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_list_team({}, db)

        assert resp["statusCode"] == 200


ORG_ACCOUNT = {"id": "acct-1", "account_name": "Prod AWS", "account_id": "123456789012"}


class TestHandleListOrganizationCloudAccounts:
    def test_only_admin_can_view(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_list_organization_cloud_accounts({}, db)
        assert resp["statusCode"] == 403

    def test_admin_gets_the_orgs_accounts(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.list_organization_cloud_accounts.return_value = [ORG_ACCOUNT]
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_list_organization_cloud_accounts({}, db)
        assert resp["statusCode"] == 200
        assert json.loads(resp["body"])["accounts"] == [ORG_ACCOUNT]


class TestHandleShareResource:
    def _event(self, cloud_account_id="acct-1"):
        return {"body": json.dumps({"cloud_account_id": cloud_account_id})}

    def test_only_admin_can_share(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_share_resource(self._event(), db)
        assert resp["statusCode"] == 403

    def test_rejects_missing_cloud_account_id(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_share_resource(self._event(cloud_account_id="  "), db)
        assert resp["statusCode"] == 400

    def test_rejects_account_not_in_organization(self):
        """Prevents sharing — or even confirming the existence of — a
        cloud account belonging to a different organization by guessing
        its id."""
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.list_organization_cloud_accounts.return_value = [ORG_ACCOUNT]
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_share_resource(self._event(cloud_account_id="someone-elses-account"), db)
        assert resp["statusCode"] == 404
        db.create_shared_resource.assert_not_called()

    def test_successful_share_logs_event(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.list_organization_cloud_accounts.return_value = [ORG_ACCOUNT]
        db.create_shared_resource.return_value = "resource-1"
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_share_resource(self._event(), db)
        assert resp["statusCode"] == 201
        assert json.loads(resp["body"])["cloud_account_id"] == "acct-1"
        db.create_shared_resource.assert_called_once_with("org1", "Prod AWS", "u1", "acct-1")
        db.log_audit_event.assert_called_once_with(
            organization_id="org1", actor_user_id="u1",
            action="resource_shared", details={"resource_name": "Prod AWS"},
        )


class TestHandleListSharedResources:
    def test_any_active_member_can_view_not_just_admins(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER  # not an admin
        db.list_shared_resources.return_value = [{"id": "r1", "resource_name": "Q1 Dashboard"}]
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_list_shared_resources({}, db)
        assert resp["statusCode"] == 200
        assert json.loads(resp["body"])["resources"] == [{"id": "r1", "resource_name": "Q1 Dashboard"}]

    def test_deactivated_member_sees_nothing_not_even_an_error_response_with_data(self):
        """The literal proof of AC5: no unshare action was ever taken —
        this member simply stopped being an active part of the org."""
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = {**VIEWER, "status": "deactivated"}
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_list_shared_resources({}, db)
        assert resp["statusCode"] == 401
        db.list_shared_resources.assert_not_called()


class TestHandleUnshareResource:
    def test_only_admin_can_unshare(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_unshare_resource({}, db, "r1")
        assert resp["statusCode"] == 403

    def test_not_found_returns_404(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.delete_shared_resource.return_value = False
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_unshare_resource({}, db, "r1")
        assert resp["statusCode"] == 404
        db.log_audit_event.assert_not_called()

    def test_successful_unshare_logs_event(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.delete_shared_resource.return_value = True
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_unshare_resource({}, db, "r1")
        assert resp["statusCode"] == 200
        db.log_audit_event.assert_called_once_with(
            organization_id="org1", actor_user_id="u1",
            action="resource_unshared", details={"resource_id": "r1"},
        )


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
        db.log_audit_event.assert_called_once_with(
            organization_id="org1", actor_user_id="u1",
            action="invite_created", details={"email": "new@x.com", "role": "viewer"},
        )


class TestHandleRevokeInvite:
    def test_only_admin_can_revoke(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_revoke_invite({}, db, "invite-1")
        assert resp["statusCode"] == 403

    def test_not_found_returns_404_and_does_not_log(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.revoke_team_invite.return_value = None
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_revoke_invite({}, db, "invite-1")
        assert resp["statusCode"] == 404
        db.log_audit_event.assert_not_called()

    def test_successful_revoke_logs_the_invited_email(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.revoke_team_invite.return_value = "revoked@x.com"
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_revoke_invite({}, db, "invite-1")
        assert resp["statusCode"] == 200
        db.log_audit_event.assert_called_once_with(
            organization_id="org1", actor_user_id="u1",
            action="invite_revoked", details={"email": "revoked@x.com"},
        )


class TestHandleAcceptInvite:
    def test_unauthorized_without_caller(self):
        import api.team_handler as th
        with patch.object(th, "_get_authenticated_email", return_value=None):
            resp = th.handle_accept_invite({}, MagicMock())
        assert resp["statusCode"] == 401

    def test_no_pending_invite_is_a_harmless_noop(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        db.accept_pending_invite.return_value = None
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_accept_invite({}, db)
        assert resp["statusCode"] == 200
        assert json.loads(resp["body"]) == {"accepted": False}

    def test_pending_invite_is_accepted(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        db.accept_pending_invite.return_value = {"organization_id": "org-new", "role": "security"}
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_accept_invite({}, db)
        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body == {"accepted": True, "organization_id": "org-new", "role": "security"}
        db.accept_pending_invite.assert_called_once_with(VIEWER["id"], VIEWER["email"])
        db.log_audit_event.assert_called_once_with(
            organization_id="org-new", actor_user_id=VIEWER["id"],
            action="invite_accepted", target_user_id=VIEWER["id"], details={"role": "security"},
        )

    def test_noop_does_not_log(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        db.accept_pending_invite.return_value = None
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            th.handle_accept_invite({}, db)
        db.log_audit_event.assert_not_called()


class TestHandleViewAuditLog:
    def test_only_admin_can_view(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_view_audit_log({}, db)
        assert resp["statusCode"] == 403

    def test_admin_gets_the_orgs_entries(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.get_audit_log.return_value = [
            {"action": "role_changed", "actor_email": "admin@x.com", "target_email": "viewer@x.com",
             "details": {"new_role": "security"}, "created_at": "2026-01-01T00:00:00"},
        ]
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_view_audit_log({}, db)
        assert resp["statusCode"] == 200
        assert len(json.loads(resp["body"])["entries"]) == 1
        db.get_audit_log.assert_called_once_with("org1")


class TestHandleUpdateRole:
    def _event(self, role="security"):
        return {"body": json.dumps({"role": role})}

    def test_only_admin_can_change_roles(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_update_role(self._event(), db, ADMIN["id"])
        assert resp["statusCode"] == 403

    def test_cannot_change_own_role(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_update_role(self._event(), db, ADMIN["id"])
        assert resp["statusCode"] == 400
        db.update_user_role.assert_not_called()

    def test_rejects_invalid_role(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_update_role(self._event(role="superuser"), db, VIEWER["id"])
        assert resp["statusCode"] == 400

    def test_not_found_returns_404(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.update_user_role.return_value = False
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_update_role(self._event(), db, "someone-else")
        assert resp["statusCode"] == 404
        db.log_audit_event.assert_not_called()

    def test_admin_cannot_change_role_of_user_in_a_different_organization(self):
        """
        The SQL in update_user_role scopes by the CALLER's organization_id,
        not whatever organization the target user_id actually belongs to —
        so an admin guessing/enumerating a user_id from another company's
        team hits 0 affected rows, not someone else's data.
        """
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN  # organization_id: "org1"
        db.update_user_role.return_value = False   # target belongs to "org2", not "org1"

        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_update_role(self._event(), db, "user-in-a-different-org")

        assert resp["statusCode"] == 404
        db.update_user_role.assert_called_once_with("user-in-a-different-org", "org1", "security")
        db.log_audit_event.assert_not_called()

    def test_successful_change_updates_and_logs(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.update_user_role.return_value = True
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_update_role(self._event(role="Security"), db, VIEWER["id"])

        assert resp["statusCode"] == 200
        assert json.loads(resp["body"]) == {"user_id": VIEWER["id"], "role": "security"}
        db.update_user_role.assert_called_once_with(VIEWER["id"], "org1", "security")
        db.log_audit_event.assert_called_once_with(
            organization_id="org1", actor_user_id=ADMIN["id"],
            action="role_changed", target_user_id=VIEWER["id"], details={"new_role": "security"},
        )


class TestHandleUpdateMfaPolicy:
    def test_only_admin_can_change_policy(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = th.handle_update_mfa_policy({"body": json.dumps({"required": True})}, db)
        assert resp["statusCode"] == 403

    def test_rejects_non_boolean_required(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_update_mfa_policy({"body": json.dumps({"required": "yes"})}, db)
        assert resp["statusCode"] == 400

    def test_enables_policy_and_logs(self):
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_update_mfa_policy({"body": json.dumps({"required": True})}, db)
        assert resp["statusCode"] == 200
        assert json.loads(resp["body"]) == {"mfa_required": True}
        db.set_organization_mfa_policy.assert_called_once_with("org1", True)
        db.log_audit_event.assert_called_once_with(
            organization_id="org1", actor_user_id="u1",
            action="mfa_policy_changed", details={"required": True},
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
        db.get_user_by_id.return_value = None
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = th.handle_deactivate_member({}, db, "someone-else")
        assert resp["statusCode"] == 404
        db.deactivate_user.assert_not_called()

    def test_successful_offboarding_revokes_reassigns_and_terminates(self):
        """Issue #265, acceptance criterion #4 — all three parts."""
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.get_user_by_id.return_value = {
            "id": VIEWER["id"], "email": VIEWER["email"], "cognito_sub": "sub-123",
            "role": "viewer", "status": "active",
        }
        db.reassign_owned_cloud_accounts.return_value = 2

        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]), \
             patch.object(th, "terminate_all_sessions", return_value=True) as mock_terminate:
            resp = th.handle_deactivate_member({}, db, VIEWER["id"])

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body == {"deactivated": VIEWER["id"], "reassigned_cloud_accounts": 2, "sessions_terminated": True}

        db.deactivate_user.assert_called_once_with(VIEWER["id"], "org1")
        db.reassign_owned_cloud_accounts.assert_called_once_with(VIEWER["email"], ADMIN["email"])
        mock_terminate.assert_called_once_with("sub-123")
        db.log_audit_event.assert_called_once_with(
            organization_id="org1", actor_user_id=ADMIN["id"], action="member_offboarded",
            target_user_id=VIEWER["id"],
            details={"reassigned_cloud_accounts": 2, "sessions_terminated": True},
        )

    def test_offboarding_succeeds_even_if_session_termination_fails(self):
        """A Cognito hiccup must not block deactivation/reassignment."""
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.get_user_by_id.return_value = {
            "id": VIEWER["id"], "email": VIEWER["email"], "cognito_sub": "sub-123",
            "role": "viewer", "status": "active",
        }
        db.reassign_owned_cloud_accounts.return_value = 0

        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]), \
             patch.object(th, "terminate_all_sessions", return_value=False):
            resp = th.handle_deactivate_member({}, db, VIEWER["id"])

        assert resp["statusCode"] == 200
        assert json.loads(resp["body"])["sessions_terminated"] is False
        db.deactivate_user.assert_called_once()


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

    def test_audit_log_route_dispatches_correctly(self):
        """Not a 404 confirms it hit handle_view_audit_log, not the
        catch-all — the 501 comes from the same unimplemented auth check
        as every other route, not from a routing mistake."""
        import importlib
        import api.team_handler as th
        importlib.reload(th)
        with patch.object(th, "Database") as MockDatabase:
            MockDatabase.return_value.get_user_by_email.return_value = ADMIN
            resp = th.lambda_handler(self._event("GET", "/team/audit-log"), None)
        assert resp["statusCode"] == 501

    def test_unhandled_error_does_not_leak_exception_details(self):
        """An unhandled exception must not return its raw message to the
        caller — that could leak internal details (e.g. database error
        text containing connection info or constraint names). The full
        detail still goes to the logs; the response body is generic."""
        import api.team_handler as th
        with patch.object(th, "Database", side_effect=RuntimeError("password=hunter2 host=internal-db.local")):
            resp = th.lambda_handler(self._event("GET", "/team"), None)
        assert resp["statusCode"] == 500
        assert "hunter2" not in resp["body"]
        assert json.loads(resp["body"]) == {"error": "internal server error"}
