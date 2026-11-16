"""
Issue #268, criteria 9 and 11 — the two halves of keeping a workspace
integration accountable: a record of every change, and a credential that says
so when the provider stops accepting it.

Everything here is mocked: no provider call, no database, no Secrets Manager.
Run from backend/ with the test venv:
    ../.venv-test/Scripts/python.exe -m pytest tests

These are the first tests this handler has. It arrived with issue #279 and had
no coverage at all, which is also why neither criterion was noticed as missing:
there was nothing asserting that anything was written down.
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(BACKEND_SRC))

ACCOUNT = "11111111-1111-1111-1111-111111111111"
INTEG = {
    "id": "22222222-2222-2222-2222-222222222222",
    "cloud_account_id": ACCOUNT,
    "provider": "jira",
    "site_url": "https://example.atlassian.net",
    "email": "someone@example.com",
    "project": "ABC",
    "secret_name": "cspm/integrations/whatever",
}


def _conn():
    """A connection whose cursor works as a context manager, like psycopg2's."""
    conn = MagicMock()
    cur = MagicMock()
    cur.rowcount = 1
    conn.cursor.return_value.__enter__.return_value = cur
    return conn, cur


# ── Criterion 11: every change leaves a record ──────────────────────────

class TestIntegrationAuditLog:
    def test_writes_who_what_and_when(self):
        import collectors.aws.scanner.integrations_handler as ih
        conn, cur = _conn()
        ih._log(conn, ACCOUNT, "disconnected", "admin@klant.nl", integration=INTEG, site_url=INTEG["site_url"])

        sql, params = cur.execute.call_args[0]
        assert "INSERT INTO integration_audit_log" in sql
        assert params[0] == ACCOUNT
        assert params[1] == INTEG["id"]
        assert params[2] == "jira"
        assert params[3] == "admin@klant.nl"
        assert params[4] == "disconnected"
        assert json.loads(params[5]) == {"site_url": INTEG["site_url"]}

    def test_a_failing_log_never_breaks_the_action(self):
        """The whole point of disconnecting is that the token stops working.
        Refusing to do that because the log could not be written would leave a
        live credential in place for the sake of a log line."""
        import collectors.aws.scanner.integrations_handler as ih
        conn, cur = _conn()
        cur.execute.side_effect = RuntimeError("database is gone")
        ih._log(conn, ACCOUNT, "disconnected", "admin@klant.nl", integration=INTEG)  # must not raise

    def test_entry_does_not_hang_off_the_integration_row(self):
        """Disconnecting deletes the integration, and that is exactly the event
        most worth keeping. The table therefore carries the id without a foreign
        key, so nothing cascades the record away with the thing it describes."""
        import collectors.aws.scanner.integrations_handler as ih
        schema = ih.BOOTSTRAP_SQL
        table = schema[schema.index("CREATE TABLE IF NOT EXISTS integration_audit_log"):]
        table = table[:table.index(");")]
        assert "integration_id   UUID," in table
        assert "REFERENCES workspace_integrations" not in table


# ── Criterion 9: a credential that is no longer accepted says so ────────

class TestProviderError:
    def test_carries_the_status_code(self):
        """Read from the exception, not parsed back out of its message — the
        message is there for a human and may be reworded."""
        import collectors.aws.scanner.integrations_handler as ih
        assert ih.ProviderError("nope", 401).status_code == 401
        assert ih.ProviderError("nope").status_code is None


class TestCredentialState:
    def _call(self, status_code=None, raises=True):
        import collectors.aws.scanner.integrations_handler as ih
        conn, cur = _conn()

        def fn():
            if raises:
                raise ih.ProviderError("rejected", status_code)
            return "fine"

        return ih, conn, cur, fn

    def test_401_marks_the_integration(self):
        ih, conn, cur, fn = self._call(401)
        try:
            ih._provider_call(conn, INTEG, "admin@klant.nl", fn)
        except ih.ProviderError:
            pass
        sql = " ".join(str(c[0][0]) for c in cur.execute.call_args_list)
        assert "needs_reauth" in sql

    def test_403_marks_the_integration(self):
        ih, conn, cur, fn = self._call(403)
        try:
            ih._provider_call(conn, INTEG, "admin@klant.nl", fn)
        except ih.ProviderError:
            pass
        sql = " ".join(str(c[0][0]) for c in cur.execute.call_args_list)
        assert "needs_reauth" in sql

    def test_a_provider_being_down_is_not_a_bad_credential(self):
        """A 500 or a timeout says nothing about the token. Marking it would
        send an admin off to re-authorise something that was never broken."""
        ih, conn, cur, fn = self._call(500)
        try:
            ih._provider_call(conn, INTEG, "admin@klant.nl", fn)
        except ih.ProviderError:
            pass
        sql = " ".join(str(c[0][0]) for c in cur.execute.call_args_list)
        assert "needs_reauth" not in sql

    def test_the_error_is_still_raised_to_the_caller(self):
        """Marking the integration is bookkeeping on the side; the caller still
        has to be told their request failed."""
        ih, conn, cur, fn = self._call(401)
        raised = False
        try:
            ih._provider_call(conn, INTEG, "admin@klant.nl", fn)
        except ih.ProviderError:
            raised = True
        assert raised

    def test_a_successful_call_clears_the_state(self):
        """A token that starts working again recovers on its own. Without this
        the hub would keep asking someone to reconnect something that is fine."""
        ih, conn, cur, fn = self._call(raises=False)
        assert ih._provider_call(conn, INTEG, "admin@klant.nl", fn) == "fine"
        sql = " ".join(str(c[0][0]) for c in cur.execute.call_args_list)
        assert "status = 'active'" in sql

    def test_the_rejection_is_recorded_once_not_on_every_retry(self):
        """_set_credential_state reports whether it changed anything. A second
        failed call must not add a second line to the log, or one expired token
        fills the record with repeats of itself."""
        import collectors.aws.scanner.integrations_handler as ih
        conn, cur = _conn()
        cur.rowcount = 0  # already marked by an earlier failure

        def fn():
            raise ih.ProviderError("rejected", 401)

        with patch.object(ih, "_log") as mock_log:
            try:
                ih._provider_call(conn, INTEG, "admin@klant.nl", fn)
            except ih.ProviderError:
                pass
            mock_log.assert_not_called()


class TestIntegrationStateIsReadable:
    def test_the_list_route_returns_the_credential_state(self):
        """Criterion 9 asks for a signal, and a signal nobody can see is not
        one. This is the route the hub reads, so the state has to come out of
        here or the screen cannot show it."""
        import collectors.aws.scanner.integrations_handler as ih
        conn, cur = _conn()
        cur.fetchall.side_effect = [
            [(INTEG["id"], "jira", INTEG["site_url"], "Example", "ABC",
              "2026-10-01T00:00:00+00:00", None,
              "needs_reauth", "2026-10-27T09:00:00+00:00", "HTTP 401: token revoked")],
            [],  # no tickets
        ]
        event = {"httpMethod": "GET", "queryStringParameters": {"cloud_account_id": ACCOUNT}}

        with patch.object(ih, "_get_connection", return_value=conn), \
             patch.object(ih, "guard", return_value=None), \
             patch.object(ih, "authenticate", return_value="admin@klant.nl"):
            resp = ih.handler(event, None)

        assert resp["statusCode"] == 200
        integration = json.loads(resp["body"])["integrations"][0]
        assert integration["status"] == "needs_reauth"
        assert integration["credential_failed_at"] == "2026-10-27T09:00:00+00:00"
        assert "401" in integration["credential_error"]

    def test_a_healthy_integration_reads_as_active(self):
        import collectors.aws.scanner.integrations_handler as ih
        conn, cur = _conn()
        cur.fetchall.side_effect = [
            [(INTEG["id"], "jira", INTEG["site_url"], "Example", "ABC",
              "2026-10-01T00:00:00+00:00", "2026-10-27T08:00:00+00:00",
              "active", None, None)],
            [],
        ]
        event = {"httpMethod": "GET", "queryStringParameters": {"cloud_account_id": ACCOUNT}}

        with patch.object(ih, "_get_connection", return_value=conn), \
             patch.object(ih, "guard", return_value=None), \
             patch.object(ih, "authenticate", return_value="admin@klant.nl"):
            resp = ih.handler(event, None)

        integration = json.loads(resp["body"])["integrations"][0]
        assert integration["status"] == "active"
        assert integration["credential_failed_at"] is None
