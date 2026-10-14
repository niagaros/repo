"""Account onboarding (POST /onboard): tied to a verified identity, validated, idempotent. Uses the already-created
test tenants, so no new accounts are created."""
import pytest

from conftest import ACCOUNT_ID, USER_A, USER_B

pytestmark = [pytest.mark.live, pytest.mark.flow("E2E-ONB-002"), pytest.mark.severity("P1")]
JSON = {"Content-Type": "application/json"}
VALID = {"company_name": "[E2E] Test Tenant", "aws_account_id": "000000000000", "region": "eu-west-1"}


@pytest.mark.severity("P0")
def test_onboarding_requires_a_signed_in_user(anon):
    s, b, _ = anon.post("onboard", {**VALID, "email": USER_A}, headers=JSON)
    assert s == 401 and b == {"error": "Unauthorized"}


@pytest.mark.severity("P0")
@pytest.mark.needs_token
def test_you_cannot_onboard_an_account_for_someone_elses_email(api):
    s, b, _ = api.post("onboard", {**VALID, "email": USER_B}, headers=JSON)
    assert s == 403


@pytest.mark.needs_token
def test_onboarding_is_idempotent_for_an_existing_owner(api):
    s, b, _ = api.post("onboard", {**VALID, "email": USER_A}, headers=JSON)
    assert s == 200 and b["already_exists"] is True and b["account_id"] == ACCOUNT_ID
    assert b["role_arn"].endswith(":role/CSPMScannerRole") and b["external_id"]


@pytest.mark.needs_token
@pytest.mark.parametrize("payload", [
    {"company_name": "x", "aws_account_id": "123"},
    {"company_name": "x", "aws_account_id": "12345678901a"},
    {"company_name": "", "aws_account_id": "123456789012"},
    {"company_name": "x"},
])
def test_onboarding_validates_input(api, payload):
    s, b, _ = api.post("onboard", {"email": USER_A, **payload}, headers=JSON)
    assert s == 400 and "error" in b


def test_onboarding_rejects_malformed_json(api):
    s, b, _ = api.post("onboard", raw_body="{oops", headers=JSON)
    assert s == 400 and b["error"] == "Invalid JSON"
