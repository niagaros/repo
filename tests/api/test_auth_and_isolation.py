"""Authentication gate, tenant isolation, and sensitive-data-exposure checks against the deployed API.

Two kinds of tests live here:
  * tests that PASS today  -> regression protection for controls that really work;
  * tests marked known_failure -> REAL, tracked defects found by this framework. They are strict-xfail:
    they keep the suite green while the defect is open, and turn red the moment someone fixes it
    (so the marker gets removed and the fix is locked in).
"""
import base64
import json

import pytest

from conftest import ACCOUNT_ID

pytestmark = [pytest.mark.live]

# Endpoints that return one tenant's private data when given only that tenant's account id.
PRIVATE_DATA_ENDPOINTS = [
    ("notifications", {"cloud_account_id": ACCOUNT_ID, "preferences": "1"}),
    ("tprm", {"cloud_account_id": ACCOUNT_ID}),
    ("questionnaires", {"cloud_account_id": ACCOUNT_ID}),
    ("audit-management", {"cloud_account_id": ACCOUNT_ID}),
    ("trust-center", {"cloud_account_id": ACCOUNT_ID, "audit_log": "1"}),
    ("custom-frameworks", {"cloud_account_id": ACCOUNT_ID}),
    ("ai-agent", {"cloud_account_id": ACCOUNT_ID}),
]
ISOLATION_ISSUE = "tenant isolation: endpoint serves account data with no authentication"


def _forged_jwt():
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'email': 'admin@niagaros.com', 'sub': 'x'})}."


# ── Authentication (E2E-AUTH-001) ───────────────────────────────────────
@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
@pytest.mark.parametrize("path", ["get-dashboard-data", "profile", "github-integration"])
def test_protected_endpoints_reject_missing_credentials(anon, path):
    status, body, _ = anon.get(path, params={"account_id": ACCOUNT_ID})
    assert status == 401 and body == {"error": "Unauthorized"}


@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
@pytest.mark.parametrize("token", ["garbage", "Bearer", "a.b.c", "null"])
def test_dashboard_rejects_invalid_tokens(anon, token):
    status, _, _ = anon.get("get-dashboard-data", headers={"Authorization": f"Bearer {token}"})
    assert status == 401


@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
def test_dashboard_rejects_forged_unsigned_jwt(anon):
    """alg=none JWT claiming to be an admin must not be accepted."""
    status, _, _ = anon.get("get-dashboard-data", headers={"Authorization": f"Bearer {_forged_jwt()}"})
    assert status == 401


@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
@pytest.mark.needs_token
def test_dashboard_accepts_a_valid_session(api):
    status, body, _ = api.get("get-dashboard-data")
    assert status == 200 and isinstance(body, dict)


# ── Tenant isolation / authorization (E2E-PERM-001) ─────────────────────
@pytest.mark.flow("E2E-PERM-001")
@pytest.mark.severity("P0")
@pytest.mark.needs_token
def test_user_cannot_read_an_account_they_do_not_own(api):
    """A valid session for user X asking for an account owned by someone else must be denied (BOLA/IDOR)."""
    other = "00000000-0000-4000-8000-000000000001"
    status, body, _ = api.get("get-dashboard-data", params={"account_id": other})
    assert status in (403, 404) or (status == 200 and not (body or {}).get("total_resources"))


@pytest.mark.flow("E2E-PERM-001")
@pytest.mark.severity("P0")
@pytest.mark.parametrize(
    "path,params",
    [pytest.param(p, q, id=p, marks=pytest.mark.known_failure(issue="TENANT-ISOLATION", reason=ISOLATION_ISSUE))
     for p, q in PRIVATE_DATA_ENDPOINTS],
)
def test_private_data_endpoints_require_authentication(anon, path, params):
    status, _, _ = anon.get(path, params=params)
    assert status in (401, 403), f"{path} answered {status} to an anonymous caller"


@pytest.mark.flow("E2E-PERM-001")
@pytest.mark.severity("P0")
@pytest.mark.known_failure(issue="TENANT-ISOLATION", reason="destructive actions are not owner-scoped or authenticated")
def test_anonymous_delete_is_rejected(anon):
    """Uses a random, non-existent id so the check is safe to run against any environment."""
    status, _, _ = anon.delete("questionnaires", params={"questionnaire_id": "00000000-0000-4000-8000-00000000dead"})
    assert status in (401, 403)


@pytest.mark.flow("E2E-PERM-001")
@pytest.mark.severity("P0")
@pytest.mark.known_failure(issue="TENANT-ISOLATION", reason="AI agent chat history readable without a session")
def test_ai_agent_history_is_not_public(anon):
    status, body, _ = anon.get("ai-agent", params={"cloud_account_id": ACCOUNT_ID})
    assert status in (401, 403) or not (body or {}).get("history")


# ── Public surfaces that must stay public ───────────────────────────────
@pytest.mark.flow("E2E-TRUST-001")
@pytest.mark.severity("P2")
def test_unknown_public_trust_center_slug_is_a_clean_404(anon):
    status, body, _ = anon.get("trust-center", params={"slug": "this-slug-does-not-exist-e2e"})
    assert status == 404 and "error" in body


@pytest.mark.flow("E2E-QST-001")
@pytest.mark.severity("P2")
def test_invalid_questionnaire_share_token_is_a_clean_404(anon):
    status, body, _ = anon.get("questionnaires", params={"share_token": "not-a-real-token"})
    assert status == 404 and "invalid, expired, or has been revoked" in body["error"]
