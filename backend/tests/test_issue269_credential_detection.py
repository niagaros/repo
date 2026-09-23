"""
Standalone verification tests for issue #269 acceptance criterion #4
("credential revoked/expired -> ingestion paused + admin notified").

Everything here is mocked: no real AWS call, no real database connection.
Run from the repo root with a venv that has boto3, psycopg2-binary and
pytest installed:
    .venv-test/Scripts/python.exe -I -m pytest backend/tests -v

The -I (isolated mode) matters: the repo root also contains leftover,
unpacked Lambda deployment folders named `psycopg2/` etc. (see
docs/internal/architecture — worth cleaning up separately). Without -I,
`python -m` prepends the current directory to sys.path and those stray
folders shadow the real, pip-installed psycopg2 package, breaking the
Database tests below with a confusing "No module named psycopg2._psycopg"
error that has nothing to do with the test itself.
"""
import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

# Make backend/src importable regardless of cwd — resolved relative to this
# file's own location, not hardcoded to one machine/user.
BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(BACKEND_SRC))


def _client_error(code: str, message: str = "boom") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "AssumeRole",
    )


# ── notifications/email.py ──────────────────────────────────────────────

class TestSendAccountDisconnectedAlert:
    def test_no_recipient_skips_send(self):
        from notifications.email import send_account_disconnected_alert
        with patch("notifications.email.boto3") as mock_boto3:
            result = send_account_disconnected_alert(None, "acct-1", "123456789012", "role deleted")
        assert result is False
        mock_boto3.client.assert_not_called()

    def test_sends_via_ses_with_expected_fields(self):
        from notifications.email import send_account_disconnected_alert
        mock_ses = MagicMock()
        with patch("notifications.email.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_ses
            result = send_account_disconnected_alert(
                "owner@example.com", "acct-1", "123456789012", "AccessDenied: role deleted"
            )
        assert result is True
        mock_boto3.client.assert_called_once_with("ses", region_name="eu-west-1")
        _, kwargs = mock_ses.send_email.call_args
        assert kwargs["Destination"] == {"ToAddresses": ["owner@example.com"]}
        assert "123456789012" in kwargs["Message"]["Body"]["Text"]["Data"]
        assert "AccessDenied" in kwargs["Message"]["Body"]["Text"]["Data"]

    def test_ses_failure_is_swallowed_not_raised(self):
        from notifications.email import send_account_disconnected_alert
        mock_ses = MagicMock()
        mock_ses.send_email.side_effect = _client_error("MessageRejected")
        with patch("notifications.email.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_ses
            result = send_account_disconnected_alert("owner@example.com", "acct-1", "123456789012", "reason")
        assert result is False  # must not raise


# ── config/database.py new methods ──────────────────────────────────────

class TestDatabaseAccountConnectivity:
    def _make_db(self):
        from config import database
        with patch.object(database, "_get_credentials", return_value={
            "host": "x", "database": "x", "username": "x", "password": "x",
        }), patch.object(database, "psycopg2") as mock_pg:
            mock_conn = MagicMock()
            mock_pg.connect.return_value = mock_conn
            db = database.Database()
        return db, mock_conn

    def test_mark_account_disconnected_issues_update(self):
        db, mock_conn = self._make_db()
        mock_cur = mock_conn.cursor.return_value.__enter__.return_value

        db.mark_account_disconnected("acct-123", "role deleted")

        sql, params = mock_cur.execute.call_args[0]
        assert "UPDATE cloud_accounts" in sql
        assert "status = 'disconnected'" in sql
        assert params == ("acct-123",)
        mock_conn.commit.assert_called_once()

    def test_get_account_contact_returns_dict(self):
        db, mock_conn = self._make_db()
        mock_cur = mock_conn.cursor.return_value.__enter__.return_value
        mock_cur.fetchone.return_value = ("owner@example.com", "123456789012")

        result = db.get_account_contact("acct-123")

        assert result == {"owner_email": "owner@example.com", "aws_account_id": "123456789012"}

    def test_get_account_contact_returns_none_when_missing(self):
        db, mock_conn = self._make_db()
        mock_cur = mock_conn.cursor.return_value.__enter__.return_value
        mock_cur.fetchone.return_value = None

        assert db.get_account_contact("does-not-exist") is None


# ── api/lambda_handler.py ────────────────────────────────────────────────

class TestApiLambdaHandlerCredentialFailure:
    def _import_handler(self):
        import importlib
        import api.lambda_handler as mod
        importlib.reload(mod)
        return mod

    def test_credential_failure_marks_disconnected_and_notifies(self):
        mod = self._import_handler()
        event = {"cloud_account_id": "acct-1", "role_arn": "arn:aws:iam::123456789012:role/X", "external_id": "ext"}

        with patch.object(mod, "Scanner") as MockScanner, \
             patch.object(mod, "Database") as MockDatabase, \
             patch.object(mod, "send_account_disconnected_alert") as mock_notify:

            MockScanner.return_value.run.side_effect = _client_error("AccessDenied", "role deleted")
            mock_db = MockDatabase.return_value
            mock_db.get_account_contact.return_value = {"owner_email": "owner@example.com", "aws_account_id": "123456789012"}

            response = mod.lambda_handler(event, None)

        assert response["statusCode"] == 401
        body = json.loads(response["body"])
        assert body["error"] == "credentials_revoked"
        mock_db.mark_account_disconnected.assert_called_once()
        assert mock_db.mark_account_disconnected.call_args[0][0] == "acct-1"
        mock_notify.assert_called_once()
        assert mock_notify.call_args.kwargs["to_email"] == "owner@example.com"

    def test_non_credential_client_error_is_not_swallowed(self):
        mod = self._import_handler()
        event = {"cloud_account_id": "acct-1", "role_arn": "arn:aws:iam::123456789012:role/X", "external_id": "ext"}

        with patch.object(mod, "Scanner") as MockScanner, \
             patch.object(mod, "Database"):
            MockScanner.return_value.run.side_effect = _client_error("Throttling", "slow down")
            response = mod.lambda_handler(event, None)

        # Falls through to the generic exception handler -> 500, not 401.
        # The response body is deliberately generic (not the raw
        # exception text, which could leak internal details) — the exact
        # error is logged server-side instead.
        assert response["statusCode"] == 500
        assert "Throttling" not in response["body"]
        assert json.loads(response["body"]) == {"error": "internal server error"}

    def test_successful_scan_is_unaffected(self):
        mod = self._import_handler()
        event = {"cloud_account_id": "acct-1", "role_arn": "arn:aws:iam::123456789012:role/X", "external_id": "ext"}

        with patch.object(mod, "Scanner") as MockScanner, \
             patch.object(mod, "Database"):
            MockScanner.return_value.run.return_value = {"resources_collected": 3}
            response = mod.lambda_handler(event, None)

        assert response["statusCode"] == 200
        assert json.loads(response["body"]) == {"resources_collected": 3}


# ── orchestrator/lambda_handler.py ──────────────────────────────────────

def _fake_invoke_response(status_code: int, body: str = "{}", function_error: str | None = None) -> dict:
    payload = json.dumps({"statusCode": status_code, "body": body}).encode()
    resp = {"Payload": io.BytesIO(payload)}
    if function_error:
        resp["FunctionError"] = function_error
    return resp


class TestOrchestratorInvoke:
    def _get_invoke(self):
        import importlib
        import orchestrator.lambda_handler as mod
        importlib.reload(mod)
        return mod._invoke

    def test_synchronous_error_payload_is_reported_as_failed(self):
        invoke = self._get_invoke()
        client = MagicMock()
        client.invoke.return_value = _fake_invoke_response(401, '{"error":"credentials_revoked"}')

        triggered, error = invoke(client, "cis_s3_scanner", {"cloud_account_id": "acct-1"}, synchronous=True)

        assert triggered is False
        assert "credentials_revoked" in error
        client.invoke.assert_called_once()  # no pointless retries on a clean error payload

    def test_synchronous_success_is_reported_as_triggered(self):
        invoke = self._get_invoke()
        client = MagicMock()
        client.invoke.return_value = _fake_invoke_response(200, '{"ok":true}')

        triggered, error = invoke(client, "cis_s3_scanner", {"cloud_account_id": "acct-1"}, synchronous=True)

        assert triggered is True
        assert error is None

    def test_async_invoke_does_not_inspect_payload(self):
        invoke = self._get_invoke()
        client = MagicMock()
        client.invoke.return_value = {}  # Event invocations return no Payload worth reading

        triggered, error = invoke(client, "some-mapper", {}, synchronous=False)

        assert triggered is True
        assert error is None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
