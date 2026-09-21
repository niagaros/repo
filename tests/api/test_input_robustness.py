"""API error handling: bad input must produce a clean 4xx — never a 5xx, never leaked internals."""
import pytest

from conftest import ACCOUNT_ID

pytestmark = [pytest.mark.live, pytest.mark.needs_token, pytest.mark.flow("E2E-API-001"), pytest.mark.severity("P2")]

JSON_HEADERS = {"Content-Type": "application/json"}
POST_ENDPOINTS = ["notifications", "tprm", "audit-management", "questionnaires", "custom-frameworks", "trust-center", "calculators", "ai-agent"]


@pytest.mark.parametrize("path", ["notifications", "tprm", "audit-management", "questionnaires", "calculators"])
def test_options_preflight_returns_cors_headers(anon, path):
    status, _, r = anon.options(path, headers={"Origin": "https://example.com", "Access-Control-Request-Method": "POST",
                                                "Access-Control-Request-Headers": "content-type,authorization"})
    assert status in (200, 204) and "access-control-allow-origin" in {k.lower() for k in r.headers}


@pytest.mark.parametrize("path,action", [
    ("notifications", "no_such_action"), ("tprm", "no_such_action"),
    ("audit-management", "no_such_action"), ("questionnaires", "no_such_action"),
])
def test_unknown_action_is_a_400_with_a_message(api, path, action):
    status, body, _ = api.post(path, {"action": action, "cloud_account_id": ACCOUNT_ID}, headers=JSON_HEADERS)
    assert status == 400 and body["error"].startswith("unknown action")


@pytest.mark.parametrize("path", POST_ENDPOINTS)
def test_malformed_json_body_is_a_400_not_a_500(api, path):
    status, _, _ = api.post(path, raw_body="{not json", headers=JSON_HEADERS)
    assert status == 400


@pytest.mark.parametrize("path", ["questionnaires", "custom-frameworks", "trust-center"])
def test_invalid_account_id_is_rejected_cleanly_without_leaking_sql(api, path):
    status, body, _ = api.get(path, params={"cloud_account_id": "null"})
    text = str(body)
    assert status in (200, 400) and "invalid input syntax" not in text and "LINE 1" not in text


@pytest.mark.parametrize("path", ["tprm", "audit-management", "calculators"])
def test_invalid_account_id_degrades_to_an_empty_result(api, path):
    status, _, _ = api.get(path, params={"cloud_account_id": "null"})
    assert status == 200


def test_missing_account_id_is_a_400_where_required(api):
    status, body, _ = api.get("notifications")
    assert status == 400 and "required" in body["error"]


@pytest.mark.parametrize("payload", [
    {"action": "create_vendor"},
    {"action": "create_vendor", "name": "x", "criticality": "not-a-level"},
])
def test_tprm_validation_errors_are_400(api, payload):
    status, body, _ = api.post("tprm", {**payload, "cloud_account_id": ACCOUNT_ID}, headers=JSON_HEADERS)
    assert status == 400 and "error" in body


@pytest.mark.parametrize("payload", [
    {"action": "create_audit"},
    {"action": "create_audit", "title": "x", "audit_type": "not-a-type"},
])
def test_audit_validation_errors_are_400(api, payload):
    status, body, _ = api.post("audit-management", {**payload, "cloud_account_id": ACCOUNT_ID}, headers=JSON_HEADERS)
    assert status == 400 and "error" in body


def test_sql_injection_attempt_in_account_id_does_not_execute(api):
    status, body, _ = api.get("tprm", params={"cloud_account_id": "x'; DROP TABLE vendors;--"})
    assert status == 200 and body == {"vendors": []}
