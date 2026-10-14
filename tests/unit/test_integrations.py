"""Jira / Monday workspace integration: provider adapters are contract-tested against local stand-ins that speak the
providers' real HTTP/GraphQL shapes, the status sync is checked against a recording database, and the SSRF guard is verified.
(Live verification needs the customer's own Jira/Monday credentials - see tests/api/test_integrations_live.py.)"""
import base64
import http.server
import json
import threading

import pytest

from collectors.aws.scanner import integrations_handler as ih

pytestmark = [pytest.mark.flow("E2E-WS-001"), pytest.mark.severity("P1")]


# ── local stand-ins for the two providers ───────────────────────────────
class _Stub(http.server.BaseHTTPRequestHandler):
    state = {}

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _auth_ok(self):
        return self.headers.get("Authorization") in self.state["accept_auth"]

    def do_GET(self):
        if not self._auth_ok():
            return self._send(401, {"errorMessages": ["bad credentials"]})
        if self.path.startswith("/rest/api/3/myself"):
            return self._send(200, {"accountId": "a1", "displayName": "Test User", "emailAddress": "t@example.com"})
        if self.path.startswith("/rest/api/3/project/search"):
            return self._send(200, {"values": [{"key": "NIA", "name": "Niagaros"}, {"key": "OPS", "name": "Ops"}]})
        if self.path.startswith("/rest/api/3/issue/"):
            return self._send(200, {"fields": {"status": self.state["jira_status"]}})
        self._send(404, {})

    def do_POST(self):
        if not self._auth_ok():
            return self._send(401, {"errors": "bad credentials"})
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        self.state.setdefault("posts", []).append((self.path, body))
        if self.path.startswith("/rest/api/3/issue"):
            return self._send(201, {"id": "10001", "key": "NIA-1"})
        q = body.get("query", "")
        if "me {" in q:
            return self._send(200, {"data": {"me": {"id": "9", "name": "Monday User", "email": "m@example.com"}}})
        if "boards(" in q:
            return self._send(200, {"data": {"boards": [{"id": "111", "name": "Security"}]}})
        if "create_item" in q:
            return self._send(200, {"data": {"create_item": {"id": "555"}}})
        if "create_update" in q:
            return self._send(200, {"data": {"create_update": {"id": "777"}}})
        if "items(" in q:
            return self._send(200, {"data": {"items": [{"id": "555", "state": "active", "column_values": [{"type": "status", "text": self.state["monday_status"]}]}]}})
        self._send(200, {"errors": [{"message": "unknown"}]})


@pytest.fixture
def stub():
    _Stub.state = {"accept_auth": set(), "jira_status": {"name": "To Do", "statusCategory": {"key": "new"}}, "monday_status": "Working on it"}
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", _Stub.state
    srv.shutdown()


def _basic(email, token):
    return "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()


# ── Jira ────────────────────────────────────────────────────────────────
def test_jira_authenticates_lists_projects_creates_ticket_and_reads_status(stub):
    url, state = stub
    state["accept_auth"].add(_basic("t@example.com", "tok"))
    j = ih.Jira(url, "t@example.com", "tok")
    assert j.whoami()["label"] == "Test User"
    assert [p["id"] for p in j.projects()] == ["NIA", "OPS"]
    t = j.create_ticket("NIA", "S3 bucket public", "Bucket allows public reads", "HIGH")
    assert t["key"] == "NIA-1" and t["url"].endswith("/browse/NIA-1")
    path, sent = next(p for p in state["posts"] if p[0].startswith("/rest/api/3/issue"))
    assert sent["fields"]["project"]["key"] == "NIA" and sent["fields"]["priority"]["name"] == "High" and sent["fields"]["summary"] == "S3 bucket public"
    assert j.status({"id": "10001", "key": "NIA-1"}) == {"name": "To Do", "done": False}
    state["jira_status"] = {"name": "Done", "statusCategory": {"key": "done"}}
    assert j.status({"id": "10001", "key": "NIA-1"})["done"] is True


def test_jira_bad_credentials_are_reported_not_swallowed(stub):
    url, _ = stub
    with pytest.raises(ih.ProviderError, match="401"):
        ih.Jira(url, "t@example.com", "wrong").whoami()


# ── Monday ──────────────────────────────────────────────────────────────
def test_monday_authenticates_lists_boards_creates_item_and_reads_status(stub):
    url, state = stub
    state["accept_auth"].add("mtoken")
    m = ih.Monday("mtoken", api_url=url + "/v2")
    assert m.whoami()["label"] == "Monday User"
    assert m.projects() == [{"id": "111", "name": "Security"}]
    t = m.create_ticket("111", "Open port 22", "Restrict SSH", "HIGH")
    assert t["id"] == "555"
    assert any("create_update" in p[1].get("query", "") for p in state["posts"]), "the finding description must be attached as an update"
    assert m.status({"id": "555", "key": "555"}) == {"name": "Working on it", "done": False}
    state["monday_status"] = "Done"
    assert m.status({"id": "555", "key": "555"})["done"] is True


def test_monday_api_errors_are_raised(stub):
    url, state = stub
    state["accept_auth"].add("mtoken")
    with pytest.raises(ih.ProviderError):
        ih.Monday("mtoken", api_url=url + "/v2")._q("query { nothing }")


# ── SSRF guard ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("site", ["http://169.254.169.254", "https://evil.example.com", "https://x.atlassian.net.evil.com",
                                  "https://atlassian.net", "http://x.atlassian.net", "https://x.atlassian.net/path", "", None,
                                  "https://127.0.0.1", "https://localhost"])
def test_jira_site_must_be_a_real_atlassian_cloud_address(site):
    with pytest.raises(ih.ProviderError, match="atlassian.net"):
        ih.make_client("jira", site, "e", "t")


def test_valid_jira_site_and_unknown_provider():
    assert isinstance(ih.make_client("jira", "https://acme.atlassian.net", "e", "t"), ih.Jira)
    with pytest.raises(ih.ProviderError):
        ih.make_client("trello", "", "", "t")


# ── status sync updates the Niagaros finding ────────────────────────────
class _Cur:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        self.db.executed.append((" ".join(sql.split()), params))

    def fetchall(self):
        return self.db.tickets


class _Conn:
    def __init__(self, tickets):
        self.tickets, self.executed = tickets, []

    def cursor(self):
        return _Cur(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Client:
    def __init__(self, statuses):
        self.statuses = statuses

    def status(self, ext):
        return self.statuses[ext["key"]]


def test_sync_closes_findings_whose_ticket_is_done_and_marks_active_ones_in_remediation():
    conn = _Conn([("t1", "f1", "10001", "NIA-1"), ("t2", "f2", "10002", "NIA-2")])
    result = ih.sync_tickets(conn, {"id": "i1"}, _Client({"NIA-1": {"name": "Done", "done": True}, "NIA-2": {"name": "In Progress", "done": False}}))
    assert result == [
        {"finding_id": "f1", "ticket": "NIA-1", "external_status": "Done", "finding_status": "closed"},
        {"finding_id": "f2", "ticket": "NIA-2", "external_status": "In Progress", "finding_status": "in_remediation"},
    ]
    updates = [(sql, p) for sql, p in conn.executed if sql.startswith("UPDATE audit_findings")]
    assert [p[0] for _, p in updates] == ["closed", "in_remediation"] and [p[2] for _, p in updates] == ["f1", "f2"]
    assert any(sql.startswith("UPDATE workspace_integrations SET last_sync_at") for sql, _ in conn.executed)


def test_tokens_are_never_stored_in_the_database_or_returned():
    src = open(ih.__file__, encoding="utf-8").read()
    assert "create_secret" in src and "api_token" in src
    assert "INSERT INTO workspace_integrations (cloud_account_id, provider, site_url, account_label, account_email, secret_name)" in src
    for forbidden in ("token_hash", "api_token TEXT", "SELECT api_token"):
        assert forbidden not in src
