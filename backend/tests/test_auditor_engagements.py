"""
Tests for issue #266 ("Invite Auditors") — audit_engagements schema
(Database methods) and api/auditor_handler.py business logic.

Same deliberately-unsolved _get_authenticated_email() as
test_team_invite.py — mocked out here so the rest of the logic can be
verified independently of it.

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

class TestDatabaseEngagementMethods:
    def _make_db(self):
        from config import database
        with patch.object(database, "_get_credentials", return_value={
            "host": "x", "database": "x", "username": "x", "password": "x",
        }), patch.object(database, "psycopg2") as mock_pg:
            mock_conn = MagicMock()
            mock_pg.connect.return_value = mock_conn
            db = database.Database()
        return db, mock_conn

    def test_create_audit_engagement_inserts_scope_and_auditors(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("engagement-1",)

        engagement_id = db.create_audit_engagement(
            organization_id="org1", name="Q4 SOC2 Audit", end_date="2026-12-31",
            created_by="u1", cloud_account_ids=["acct-1", "acct-2"],
            auditor_emails=["Auditor@Firm.com"],
        )

        assert engagement_id == "engagement-1"
        insert_calls = [c for c in cur.execute.call_args_list if "INSERT" in c[0][0]]
        assert len(insert_calls) == 4  # engagement + 2 scope rows + 1 auditor row
        # emails are normalized (stripped/lowered) before storage
        assert insert_calls[-1][0][1] == ("engagement-1", "auditor@firm.com")
        mock_conn.commit.assert_called_once()

    def test_list_organization_engagements_maps_active_flag(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [
            ("e1", "Q4 Audit", "2026-01-01", "2026-12-31", True),
            ("e2", "Old Audit", "2025-01-01", "2025-06-01", False),
        ]

        engagements = db.list_organization_engagements("org1")

        assert engagements[0]["active"] is True
        assert engagements[1]["active"] is False

    def test_get_active_engagement_for_auditor_found(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("e1", "org1", "Q4 Audit", "2026-12-31")

        engagement = db.get_active_engagement_for_auditor("auditor@firm.com")

        assert engagement == {"id": "e1", "organization_id": "org1", "name": "Q4 Audit", "end_date": "2026-12-31"}

    def test_get_active_engagement_for_auditor_none_when_expired_or_unknown(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = None

        assert db.get_active_engagement_for_auditor("nobody@firm.com") is None

    def test_list_engagement_scope_maps_rows(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [("acct-1", "Prod AWS", "123456789012")]

        scope = db.list_engagement_scope("e1")

        assert scope == [{"id": "acct-1", "account_name": "Prod AWS", "account_id": "123456789012"}]

    def test_is_cloud_account_in_engagement_scope(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = (1,)

        assert db.is_cloud_account_in_engagement_scope("e1", "acct-1") is True

    def test_is_cloud_account_not_in_engagement_scope(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = None

        assert db.is_cloud_account_in_engagement_scope("e1", "acct-2") is False

    def test_create_evidence_request_returns_id_and_commits(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("req-1",)

        request_id = db.create_evidence_request("e1", "auditor@firm.com", "acct-2")

        assert request_id == "req-1"
        mock_conn.commit.assert_called_once()

    def test_resolve_evidence_request_approve_adds_to_scope(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("acct-2",)

        resolved = db.resolve_evidence_request("req-1", "e1", approve=True)

        assert resolved is True
        insert_calls = [c for c in cur.execute.call_args_list if "INSERT INTO engagement_scope" in c[0][0]]
        assert len(insert_calls) == 1
        assert insert_calls[0][0][1] == ("e1", "acct-2")

    def test_resolve_evidence_request_deny_does_not_touch_scope(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("acct-2",)

        resolved = db.resolve_evidence_request("req-1", "e1", approve=False)

        assert resolved is True
        insert_calls = [c for c in cur.execute.call_args_list if "INSERT INTO engagement_scope" in c[0][0]]
        assert len(insert_calls) == 0

    def test_resolve_evidence_request_false_when_not_pending(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = None

        assert db.resolve_evidence_request("req-1", "e1", approve=True) is False

    def test_log_and_get_engagement_activity(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [
            ("auditor@firm.com", "evidence_downloaded", {"cloud_account_id": "acct-1"}, "2026-01-01T00:00:00"),
        ]

        db.log_engagement_activity("e1", "auditor@firm.com", "evidence_downloaded", {"cloud_account_id": "acct-1"})
        entries = db.get_engagement_activity("e1")

        assert entries == [{
            "auditor_email": "auditor@firm.com", "action": "evidence_downloaded",
            "details": {"cloud_account_id": "acct-1"}, "created_at": "2026-01-01T00:00:00",
        }]

    def test_get_cloud_account_compliance_found(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = ("Prod AWS", {"score": 82}, "2026-01-01T00:00:00")

        result = db.get_cloud_account_compliance("acct-1")

        assert result == {"account_name": "Prod AWS", "compliance_score": {"score": 82}, "last_scan_at": "2026-01-01T00:00:00"}

    def test_get_cloud_account_compliance_not_found(self):
        db, mock_conn = self._make_db()
        cur = mock_conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = None

        assert db.get_cloud_account_compliance("does-not-exist") is None


# ── api/auditor_handler.py ────────────────────────────────────────────

ADMIN = {"id": "u1", "email": "admin@acme.com", "organization_id": "org1", "role": "admin", "status": "active"}
VIEWER = {"id": "u2", "email": "viewer@acme.com", "organization_id": "org1", "role": "viewer", "status": "active"}
ORG_ACCOUNT_1 = {"id": "acct-1", "account_name": "Prod AWS", "account_id": "111111111111"}
ORG_ACCOUNT_2 = {"id": "acct-2", "account_name": "Staging AWS", "account_id": "222222222222"}
ACTIVE_ENGAGEMENT = {"id": "e1", "organization_id": "org1", "name": "Q4 Audit", "end_date": "2026-12-31"}


class TestHandleCreateEngagement:
    def _event(self, **overrides):
        body = {
            "name": "Q4 Audit", "end_date": "2026-12-31",
            "cloud_account_ids": ["acct-1"], "auditor_emails": ["auditor@firm.com"],
        }
        body.update(overrides)
        return {"body": json.dumps(body)}

    def test_only_admin_can_create(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = ah.handle_create_engagement(self._event(), db)
        assert resp["statusCode"] == 403

    def test_rejects_missing_name(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = ah.handle_create_engagement(self._event(name=""), db)
        assert resp["statusCode"] == 400

    def test_rejects_no_cloud_accounts(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = ah.handle_create_engagement(self._event(cloud_account_ids=[]), db)
        assert resp["statusCode"] == 400

    def test_rejects_no_auditor_emails(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = ah.handle_create_engagement(self._event(auditor_emails=[]), db)
        assert resp["statusCode"] == 400

    def test_rejects_cloud_account_not_in_organization(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.list_organization_cloud_accounts.return_value = [ORG_ACCOUNT_1]
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = ah.handle_create_engagement(self._event(cloud_account_ids=["someone-elses-account"]), db)
        assert resp["statusCode"] == 404
        db.create_audit_engagement.assert_not_called()

    def test_successful_creation(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.list_organization_cloud_accounts.return_value = [ORG_ACCOUNT_1, ORG_ACCOUNT_2]
        db.create_audit_engagement.return_value = "e1"
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = ah.handle_create_engagement(self._event(), db)
        assert resp["statusCode"] == 201
        db.create_audit_engagement.assert_called_once_with(
            organization_id="org1", name="Q4 Audit", end_date="2026-12-31",
            created_by="u1", cloud_account_ids=["acct-1"], auditor_emails=["auditor@firm.com"],
        )


class TestHandleListEngagements:
    def test_only_admin_can_view(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = ah.handle_list_engagements({}, db)
        assert resp["statusCode"] == 403


class TestGetAuditorRejectsClosedOrUnknown:
    """Issue #266, acceptance criterion #3's real mechanism."""

    def test_no_active_engagement_is_unauthorized(self):
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = None
        with patch.object(ah, "_get_authenticated_email", return_value="nobody@firm.com"):
            resp = ah.handle_auditor_view_scope({}, db)
        assert resp["statusCode"] == 401

    def test_active_engagement_is_accepted(self):
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = ACTIVE_ENGAGEMENT
        db.list_engagement_scope.return_value = [ORG_ACCOUNT_1]
        with patch.object(ah, "_get_authenticated_email", return_value="auditor@firm.com"):
            resp = ah.handle_auditor_view_scope({}, db)
        assert resp["statusCode"] == 200
        assert json.loads(resp["body"])["scope"] == [ORG_ACCOUNT_1]

    def test_active_engagement_logs_a_login(self):
        """Issue #266, acceptance criterion #5: the activity dashboard
        must show logins, not just downloads and evidence requests."""
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = ACTIVE_ENGAGEMENT
        db.list_engagement_scope.return_value = [ORG_ACCOUNT_1]
        with patch.object(ah, "_get_authenticated_email", return_value="auditor@firm.com"):
            ah.handle_auditor_view_scope({}, db)
        db.log_engagement_activity.assert_called_once_with("e1", "auditor@firm.com", "login")

    def test_no_active_engagement_does_not_log_a_login(self):
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = None
        with patch.object(ah, "_get_authenticated_email", return_value="nobody@firm.com"):
            ah.handle_auditor_view_scope({}, db)
        db.log_engagement_activity.assert_not_called()


class TestHandleRequestEvidence:
    def test_unauthorized_without_active_engagement(self):
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = None
        with patch.object(ah, "_get_authenticated_email", return_value="nobody@firm.com"):
            resp = ah.handle_request_evidence({"body": json.dumps({"cloud_account_id": "acct-2"})}, db)
        assert resp["statusCode"] == 401

    def test_rejects_cloud_account_not_in_organization(self):
        """Without this, an auditor could request — and an admin could
        then unknowingly approve — access to an id that isn't a real
        account in this organization at all."""
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = ACTIVE_ENGAGEMENT
        db.list_organization_cloud_accounts.return_value = [ORG_ACCOUNT_1]
        with patch.object(ah, "_get_authenticated_email", return_value="auditor@firm.com"):
            resp = ah.handle_request_evidence({"body": json.dumps({"cloud_account_id": "not-a-real-account"})}, db)
        assert resp["statusCode"] == 404
        db.create_evidence_request.assert_not_called()

    def test_successful_request_logs_activity(self):
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = ACTIVE_ENGAGEMENT
        db.list_organization_cloud_accounts.return_value = [ORG_ACCOUNT_1, ORG_ACCOUNT_2]
        db.create_evidence_request.return_value = "req-1"
        with patch.object(ah, "_get_authenticated_email", return_value="auditor@firm.com"):
            resp = ah.handle_request_evidence({"body": json.dumps({"cloud_account_id": "acct-2"})}, db)
        assert resp["statusCode"] == 201
        db.create_evidence_request.assert_called_once_with("e1", "auditor@firm.com", "acct-2")
        db.log_engagement_activity.assert_called_once_with(
            "e1", "auditor@firm.com", "evidence_requested", details={"cloud_account_id": "acct-2"},
        )


class TestHandleResolveEvidenceRequest:
    def _event(self, approve=True):
        return {"body": json.dumps({"approve": approve})}

    def test_only_admin_can_resolve(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = ah.handle_resolve_evidence_request(self._event(), db, "e1", "req-1")
        assert resp["statusCode"] == 403

    def test_not_found_returns_404(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.resolve_evidence_request.return_value = False
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = ah.handle_resolve_evidence_request(self._event(), db, "e1", "req-1")
        assert resp["statusCode"] == 404

    def test_successful_approval(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.resolve_evidence_request.return_value = True
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = ah.handle_resolve_evidence_request(self._event(approve=True), db, "e1", "req-1")
        assert resp["statusCode"] == 200
        db.resolve_evidence_request.assert_called_once_with("req-1", "e1", True)


class TestHandleDownloadEvidence:
    def test_unauthorized_without_active_engagement(self):
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = None
        with patch.object(ah, "_get_authenticated_email", return_value="nobody@firm.com"):
            resp = ah.handle_download_evidence({}, db, "acct-1")
        assert resp["statusCode"] == 401

    def test_rejects_account_outside_scope(self):
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = ACTIVE_ENGAGEMENT
        db.is_cloud_account_in_engagement_scope.return_value = False
        with patch.object(ah, "_get_authenticated_email", return_value="auditor@firm.com"):
            resp = ah.handle_download_evidence({}, db, "acct-not-in-scope")
        assert resp["statusCode"] == 403
        db.log_engagement_activity.assert_not_called()

    def test_successful_download_logs_activity(self):
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = ACTIVE_ENGAGEMENT
        db.is_cloud_account_in_engagement_scope.return_value = True
        db.get_cloud_account_compliance.return_value = {"account_name": "Prod AWS", "compliance_score": {"score": 90}}
        with patch.object(ah, "_get_authenticated_email", return_value="auditor@firm.com"):
            resp = ah.handle_download_evidence({}, db, "acct-1")
        assert resp["statusCode"] == 200
        db.log_engagement_activity.assert_called_once_with(
            "e1", "auditor@firm.com", "evidence_downloaded", details={"cloud_account_id": "acct-1"},
        )

    def test_download_stops_working_once_engagement_is_closed(self):
        """The literal proof of AC3: no separate revocation action was
        ever taken — the engagement's own end_date passing is enough."""
        import api.auditor_handler as ah
        db = MagicMock()
        db.get_active_engagement_for_auditor.return_value = None  # end_date has passed
        with patch.object(ah, "_get_authenticated_email", return_value="auditor@firm.com"):
            resp = ah.handle_download_evidence({}, db, "acct-1")
        assert resp["statusCode"] == 401
        db.is_cloud_account_in_engagement_scope.assert_not_called()


class TestHandleViewEngagementActivity:
    def test_only_admin_can_view(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = VIEWER
        with patch.object(th, "_get_authenticated_email", return_value=VIEWER["email"]):
            resp = ah.handle_view_engagement_activity({}, db, "e1")
        assert resp["statusCode"] == 403

    def test_admin_gets_the_engagements_entries(self):
        import api.auditor_handler as ah
        import api.team_handler as th
        db = MagicMock()
        db.get_user_by_email.return_value = ADMIN
        db.get_engagement_activity.return_value = [
            {"auditor_email": "auditor@firm.com", "action": "evidence_downloaded",
             "details": {"cloud_account_id": "acct-1"}, "created_at": "2026-01-01T00:00:00"},
        ]
        with patch.object(th, "_get_authenticated_email", return_value=ADMIN["email"]):
            resp = ah.handle_view_engagement_activity({}, db, "e1")
        assert resp["statusCode"] == 200
        assert len(json.loads(resp["body"])["entries"]) == 1
        db.get_engagement_activity.assert_called_once_with("e1")


class TestLambdaHandlerRouting:
    def _event(self, method, path, path_params=None, body=None):
        return {
            "requestContext": {"http": {"method": method}},
            "rawPath": path,
            "pathParameters": path_params or {},
            "body": json.dumps(body) if body is not None else None,
        }

    def test_unknown_route_is_404(self):
        import api.auditor_handler as ah
        with patch.object(ah, "Database") as MockDatabase:
            MockDatabase.return_value.get_user_by_email.return_value = ADMIN
            resp = ah.lambda_handler(self._event("GET", "/nonsense"), None)
        assert resp["statusCode"] == 404

    def test_auth_not_implemented_surfaces_as_501_not_a_crash(self):
        import api.auditor_handler as ah
        with patch.object(ah, "Database") as MockDatabase:
            MockDatabase.return_value.get_user_by_email.return_value = ADMIN
            resp = ah.lambda_handler(self._event("GET", "/auditors/engagements"), None)
        assert resp["statusCode"] == 501

    def test_auditor_scope_route_dispatches_correctly(self):
        """Not a 404 confirms it hit handle_auditor_view_scope, not the
        catch-all — the 501 comes from the same unimplemented auth check
        as every other route, not from a routing mistake."""
        import api.auditor_handler as ah
        with patch.object(ah, "Database") as MockDatabase:
            MockDatabase.return_value.get_user_by_email.return_value = ADMIN
            resp = ah.lambda_handler(self._event("GET", "/auditor/scope"), None)
        assert resp["statusCode"] == 501

    def test_download_evidence_route_dispatches_with_path_param(self):
        import api.auditor_handler as ah
        with patch.object(ah, "Database") as MockDatabase:
            MockDatabase.return_value.get_user_by_email.return_value = ADMIN
            resp = ah.lambda_handler(
                self._event("GET", "/auditor/evidence/acct-1", path_params={"cloud_account_id": "acct-1"}), None,
            )
        assert resp["statusCode"] == 501
