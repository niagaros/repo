"""Connecting an AWS account: the connection is validated with the real role, failures are reported precisely, scans are
account-scoped and owner-only. (A scan itself is not started here: the test tenants use placeholder AWS account ids.)"""
import pytest

from conftest import ACCOUNT_B_ID, ACCOUNT_ID

pytestmark = [pytest.mark.live, pytest.mark.flow("E2E-INFRA-002"), pytest.mark.severity("P1")]
JSON = {"Content-Type": "application/json"}


def test_scan_endpoints_require_a_session(anon):
    assert anon.get("scan", params={"cloud_account_id": ACCOUNT_ID})[0] == 401
    assert anon.post("scan", {"action": "validate_connection", "cloud_account_id": ACCOUNT_ID}, headers=JSON)[0] == 401


@pytest.mark.needs_token
def test_validate_connection_reports_exactly_why_a_connection_fails(api):
    """Tenant A points at a placeholder AWS account: the role cannot be assumed, and the answer says so - it never claims success."""
    s, b, _ = api.post("scan", {"action": "validate_connection", "cloud_account_id": ACCOUNT_ID}, headers=JSON)
    assert s == 200 and b["connected"] is False
    assert b["expected_aws_account_id"] == "000000000000" and b["role_arn"].endswith(":role/CSPMScannerRole")
    assert "Could not assume the scanner role" in b["error"] and b["checks"] == []


@pytest.mark.needs_token
@pytest.mark.parametrize("body,status,fragment", [
    ({"action": "no_such_action"}, 400, "unknown action"),
    ({}, 400, "unknown action"),
])
def test_scan_input_is_validated_without_starting_anything(api, body, status, fragment):
    s, b, _ = api.post("scan", {"cloud_account_id": ACCOUNT_ID, **body}, headers=JSON)
    assert s == status and fragment in b["error"]


@pytest.mark.needs_token
def test_missing_account_is_a_400_and_unknown_account_a_403(api):
    assert api.post("scan", {"action": "scan"}, headers=JSON)[0] == 400
    assert api.get("scan", params={"cloud_account_id": "00000000-0000-4000-8000-000000000000"})[0] == 403


@pytest.mark.needs_token
def test_scan_status_is_readable_by_the_owner(api):
    s, b, _ = api.get("scan", params={"cloud_account_id": ACCOUNT_ID})
    assert s == 200 and "last_scan_at" in b and "last_request" in b


@pytest.mark.needs_two_tenants
def test_another_tenant_cannot_validate_or_scan_my_account(api_b):
    for body in ({"action": "validate_connection"}, {"action": "scan"}):
        s, _, _ = api_b.post("scan", {**body, "cloud_account_id": ACCOUNT_ID}, headers=JSON)
        assert s == 403, body
    assert api_b.get("scan", params={"cloud_account_id": ACCOUNT_ID})[0] == 403
