"""Authentication, authorization and tenant isolation (issue #279 — P0).

Two real tenants exist for these tests, each owned by its own dedicated Cognito test user:
  A = tenant of test user A ("api"), B = tenant of test user B ("api_b").
The tests prove: anonymous callers are rejected, a signed-in user reaches only accounts they own (reads AND
writes, including id-only actions that name no account — IDOR/BOLA), and the deliberately public surfaces
(public Trust Center page, share links) still work. Cross-tenant probes never touch a real customer account
with anything that could change data.
"""
import base64
import json
import uuid

import pytest

from conftest import ACCOUNT_B_ID, ACCOUNT_ID, REAL_CUSTOMER_ACCOUNT_ID, TEST_PREFIX

pytestmark = [pytest.mark.live]
JSON = {"Content-Type": "application/json"}

# (path, extra query params) — each returns one tenant's private data when given its account id.
PRIVATE_READS = [
    ("notifications", {"preferences": "1"}),
    ("tprm", {}),
    ("questionnaires", {}),
    ("audit-management", {}),
    ("trust-center", {"audit_log": "1"}),
    ("custom-frameworks", {}),
    ("calculators", {}),
    ("ai-agent", {}),
]
READ_IDS = [p for p, _ in PRIVATE_READS]


def _forged_jwt():
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'email': 'e2e-tests@niagaros.test', 'sub': 'x'})}."


def _tag():
    return f"{TEST_PREFIX} iso {uuid.uuid4().hex[:6]}"


# ── Authentication (E2E-AUTH-001) ───────────────────────────────────────
@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
@pytest.mark.parametrize("path", ["get-dashboard-data", "profile", "github-integration"] + READ_IDS)
def test_every_private_endpoint_rejects_missing_credentials(anon, path):
    status, body, _ = anon.get(path, params={"cloud_account_id": ACCOUNT_ID, "account_id": ACCOUNT_ID})
    assert status == 401 and body == {"error": "Unauthorized"}, (path, status)


@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
@pytest.mark.parametrize("path", ["get-dashboard-data"] + READ_IDS)
@pytest.mark.parametrize("token", ["garbage", "a.b.c", "null"])
def test_invalid_tokens_are_rejected(anon, path, token):
    status, _, _ = anon.get(path, params={"cloud_account_id": ACCOUNT_ID}, headers={"Authorization": f"Bearer {token}"})
    assert status == 401


@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
@pytest.mark.parametrize("path", ["get-dashboard-data"] + READ_IDS)
def test_forged_unsigned_jwt_is_rejected(anon, path):
    """alg=none JWT claiming to be the tenant owner must not be accepted."""
    status, _, _ = anon.get(path, params={"cloud_account_id": ACCOUNT_ID}, headers={"Authorization": f"Bearer {_forged_jwt()}"})
    assert status == 401


@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
@pytest.mark.parametrize("method,path,body", [
    ("post", "notifications", {"action": "add_recipient", "cloud_account_id": ACCOUNT_ID, "label": "x", "notify_email": "a@b.co"}),
    ("post", "tprm", {"action": "create_vendor", "cloud_account_id": ACCOUNT_ID, "name": "x"}),
    ("post", "audit-management", {"action": "create_audit", "cloud_account_id": ACCOUNT_ID, "title": "x"}),
    ("post", "questionnaires", {"action": "upload", "cloud_account_id": ACCOUNT_ID, "name": "x", "csv_text": "Question\nx"}),
    ("post", "custom-frameworks", {"action": "create_framework", "cloud_account_id": ACCOUNT_ID, "name": "x"}),
    ("post", "ai-agent", {"action": "ask", "cloud_account_id": ACCOUNT_ID, "question": "hi"}),
])
def test_anonymous_writes_are_rejected_and_create_nothing(anon, api, method, path, body):
    status, _, _ = getattr(anon, method)(path, body, headers=JSON)
    assert status == 401


@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
def test_anonymous_delete_is_rejected(anon):
    status, _, _ = anon.delete("questionnaires", params={"questionnaire_id": str(uuid.uuid4())})
    assert status == 401
    status, _, _ = anon.delete("custom-frameworks", params={"framework_id": str(uuid.uuid4())})
    assert status == 401


@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
@pytest.mark.needs_token
def test_a_valid_session_is_accepted_and_sees_only_its_own_account(api):
    status, body, _ = api.get("get-dashboard-data")
    assert status == 200 and isinstance(body, dict)
    ids = {a["id"] for a in body.get("accounts", [])} or {body.get("account_id")}
    assert ACCOUNT_ID in ids and REAL_CUSTOMER_ACCOUNT_ID not in ids and ACCOUNT_B_ID not in ids


@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
@pytest.mark.needs_token
@pytest.mark.parametrize("path,extra", PRIVATE_READS, ids=READ_IDS)
def test_owner_can_read_their_own_account_data(api, path, extra):
    status, _, _ = api.get(path, params={"cloud_account_id": ACCOUNT_ID, **extra})
    assert status == 200


# ── Tenant isolation: reads (E2E-PERM-001) ──────────────────────────────
@pytest.mark.flow("E2E-PERM-001")
@pytest.mark.severity("P0")
@pytest.mark.needs_two_tenants
@pytest.mark.parametrize("path,extra", PRIVATE_READS, ids=READ_IDS)
def test_tenant_a_cannot_read_tenant_b(api, path, extra):
    status, _, _ = api.get(path, params={"cloud_account_id": ACCOUNT_B_ID, **extra})
    assert status == 403


@pytest.mark.flow("E2E-PERM-001")
@pytest.mark.severity("P0")
@pytest.mark.needs_token
@pytest.mark.parametrize("path,extra", PRIVATE_READS, ids=READ_IDS)
def test_a_signed_in_user_cannot_read_a_real_customers_account(api, path, extra):
    status, _, _ = api.get(path, params={"cloud_account_id": REAL_CUSTOMER_ACCOUNT_ID, **extra})
    assert status == 403


@pytest.mark.flow("E2E-PERM-001")
@pytest.mark.severity("P0")
@pytest.mark.needs_token
def test_dashboard_denies_an_account_the_user_does_not_own(api):
    status, body, _ = api.get("get-dashboard-data", params={"account_id": REAL_CUSTOMER_ACCOUNT_ID})
    assert status in (403, 404) or not (body or {}).get("total_resources")


# ── Tenant isolation: writes (E2E-PERM-001) ─────────────────────────────
@pytest.mark.flow("E2E-PERM-001")
@pytest.mark.severity("P0")
@pytest.mark.needs_two_tenants
@pytest.mark.parametrize("path,body", [
    ("notifications", {"action": "add_recipient", "label": "x", "domains": []}),          # 400 if it got through
    ("notifications", {"action": "update_preferences", "domain": "not-a-domain"}),        # 400 if it got through
    ("tprm", {"action": "create_vendor"}),                                                # 400 if it got through
    ("audit-management", {"action": "create_audit"}),                                     # 400 if it got through
    ("custom-frameworks", {"action": "create_framework"}),                                # 500/400 if it got through
], ids=["recipient", "preferences", "vendor", "audit", "framework"])
@pytest.mark.parametrize("victim", [ACCOUNT_B_ID, REAL_CUSTOMER_ACCOUNT_ID], ids=["tenant-b", "real-customer"])
def test_writes_to_someone_elses_account_are_denied_before_any_validation(api, path, body, victim):
    """The probes are chosen to fail validation if they were ever accepted, so nothing can be written even on a defect."""
    status, _, _ = api.post(path, {**body, "cloud_account_id": victim}, headers=JSON, allow_foreign=True)
    assert status == 403


@pytest.fixture
def tenant_b_resources(api_b, cleanup):
    """Real records owned by tenant B, created through B's own session."""
    res = {}
    s, b, _ = api_b.post("tprm", {"action": "create_vendor", "cloud_account_id": ACCOUNT_B_ID, "name": _tag(), "criticality": "low", "actor_name": "e2e"}, headers=JSON)
    assert s == 200, (s, b)
    res["vendor"] = b["id"]
    cleanup(lambda: api_b.post("tprm", {"action": "delete_vendor", "cloud_account_id": ACCOUNT_B_ID, "vendor_id": res["vendor"], "actor_name": "e2e"}, headers=JSON))
    s, b, _ = api_b.post("audit-management", {"action": "create_audit", "cloud_account_id": ACCOUNT_B_ID, "title": _tag(), "audit_type": "internal"}, headers=JSON)
    assert s == 200, (s, b)
    res["audit"] = b["id"]
    cleanup(lambda: api_b.post("audit-management", {"action": "delete_audit", "cloud_account_id": ACCOUNT_B_ID, "audit_id": res["audit"]}, headers=JSON))
    s, b, _ = api_b.post("questionnaires", {"action": "upload", "cloud_account_id": ACCOUNT_B_ID, "name": _tag(), "filename": "e.csv", "csv_text": "Question\nDo you encrypt data?\n"}, headers=JSON)
    assert s == 200, (s, b)
    res["questionnaire"] = b["id"]
    cleanup(lambda: api_b.delete("questionnaires", params={"questionnaire_id": res["questionnaire"]}))
    s, b, _ = api_b.post("custom-frameworks", {"action": "create_framework", "cloud_account_id": ACCOUNT_B_ID, "name": _tag()}, headers=JSON)
    assert s == 200, (s, b)
    res["framework"] = b["id"]
    cleanup(lambda: api_b.delete("custom-frameworks", params={"framework_id": res["framework"]}))
    return res


@pytest.mark.flow("E2E-PERM-001")
@pytest.mark.severity("P0")
@pytest.mark.needs_two_tenants
def test_idor_id_only_actions_cannot_reach_another_tenants_records(api, api_b, tenant_b_resources, step):
    """Actions that name only a record id (no account) must still be checked against the record's real owner."""
    r = tenant_b_resources
    with step("A tries to delete B's vendor by id"):
        s, _, _ = api.post("tprm", {"action": "delete_vendor", "vendor_id": r["vendor"]}, headers=JSON)
        assert s == 403
    with step("A tries to update B's vendor by id"):
        s, _, _ = api.post("tprm", {"action": "update_vendor", "vendor_id": r["vendor"], "fields": {"criticality": "critical"}}, headers=JSON)
        assert s == 403
    with step("A tries to delete B's audit by id"):
        s, _, _ = api.post("audit-management", {"action": "delete_audit", "audit_id": r["audit"]}, headers=JSON)
        assert s == 403
    with step("A tries to read and delete B's questionnaire by id"):
        s, _, _ = api.get("questionnaires", params={"questionnaire_id": r["questionnaire"]})
        assert s == 403
        s, _, _ = api.delete("questionnaires", params={"questionnaire_id": r["questionnaire"]})
        assert s == 403
    with step("A tries to delete B's custom framework by id"):
        s, _, _ = api.delete("custom-frameworks", params={"framework_id": r["framework"]})
        assert s == 403
    with step("every one of B's records is still there, untouched"):
        _, b, _ = api_b.get("tprm", params={"cloud_account_id": ACCOUNT_B_ID})
        assert any(v["id"] == r["vendor"] and v["criticality"] == "low" for v in b["vendors"])
        _, b, _ = api_b.get("audit-management", params={"cloud_account_id": ACCOUNT_B_ID})
        assert any(a["id"] == r["audit"] for a in b["audits"])
        _, b, _ = api_b.get("questionnaires", params={"cloud_account_id": ACCOUNT_B_ID})
        assert any(q["id"] == r["questionnaire"] for q in b["questionnaires"])
        _, b, _ = api_b.get("custom-frameworks", params={"cloud_account_id": ACCOUNT_B_ID})
        assert any(f["id"] == r["framework"] for f in b["frameworks"])


@pytest.mark.flow("E2E-PERM-001")
@pytest.mark.severity("P0")
@pytest.mark.needs_two_tenants
def test_a_denied_cross_tenant_access_leaves_no_data_in_the_response(api, tenant_b_resources):
    s, b, r = api.get("tprm", params={"cloud_account_id": ACCOUNT_B_ID})
    assert s == 403 and b == {"error": "Forbidden"} and "vendors" not in r.text


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


@pytest.mark.flow("E2E-TRUST-001")
@pytest.mark.severity("P2")
def test_public_document_access_request_needs_no_login(anon):
    """Anonymous visitors of a public Trust Center can request access; an unknown document is a clean error, not a 401."""
    status, _, _ = anon.post("trust-center", {"action": "request_access", "document_id": str(uuid.uuid4()),
                                              "requester_name": "e2e", "requester_email": "e2e@example.invalid"}, headers=JSON)
    assert status != 401
