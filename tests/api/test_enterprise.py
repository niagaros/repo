"""Enterprise onboarding and permissions, on the live system.

Enterprise Onboarding: create organization -> business units -> assign accounts (each account's owner consents) ->
invite team with roles.
Enterprise Permissions: admin invites a user -> assigns a role and a scope -> the user signs in -> sees ONLY the authorized
resources -> everything outside the scope stays inaccessible, and viewers can never change anything."""
import uuid

import pytest

from conftest import ACCOUNT_B_ID, ACCOUNT_ID, TEST_PREFIX, USER_B, USER_D

pytestmark = [pytest.mark.live]
JSON = {"Content-Type": "application/json"}


def _post(client, body, expect=200):
    s, b, _ = client.post("enterprise", body, headers=JSON)
    assert s == expect, (body.get("action"), s, b)
    return b


def _visible_accounts(client):
    s, b, _ = client.get("get-dashboard-data")
    assert s == 200
    return {a["id"] for a in b.get("accounts", [])}


@pytest.fixture
def org(api, api_b, cleanup):
    """A organizes the enterprise: org owner A, unit alpha (tenant A), unit beta (tenant B, assigned by B)."""
    o = _post(api, {"action": "create_organization", "name": f"{TEST_PREFIX} org {uuid.uuid4().hex[:5]}"})["id"]
    cleanup(lambda: api.post("enterprise", {"action": "delete_organization", "organization_id": o}, headers=JSON))
    alpha = _post(api, {"action": "create_business_unit", "organization_id": o, "name": "alpha"})["id"]
    beta = _post(api, {"action": "create_business_unit", "organization_id": o, "name": "beta"})["id"]
    _post(api, {"action": "assign_account", "business_unit_id": alpha, "cloud_account_id": ACCOUNT_ID})
    return {"id": o, "alpha": alpha, "beta": beta}


@pytest.mark.flow("E2E-ONB-001")
@pytest.mark.severity("P1")
@pytest.mark.needs_team
def test_enterprise_onboarding_flow(api, api_b, api_d, org, step):
    o = org["id"]
    with step("input is validated"):
        _post(api, {"action": "create_organization", "name": ""}, expect=400)
        _post(api, {"action": "create_business_unit", "organization_id": o, "name": "alpha"}, expect=409)
        _post(api, {"action": "invite_member", "organization_id": o, "email": "nope", "role": "viewer", "business_unit_id": org["alpha"]}, expect=400)
        _post(api, {"action": "invite_member", "organization_id": o, "email": USER_D, "role": "god", "business_unit_id": org["alpha"]}, expect=400)
        _post(api, {"action": "invite_member", "organization_id": o, "email": USER_D, "role": "viewer"}, expect=400)          # viewer needs a unit
        _post(api, {"action": "invite_member", "organization_id": o, "email": USER_D, "role": "org_admin", "business_unit_id": org["alpha"]}, expect=400)

    with step("an account can only be assigned by its OWN owner, and only by someone allowed to add to that unit"):
        _post(api, {"action": "assign_account", "business_unit_id": org["beta"], "cloud_account_id": ACCOUNT_B_ID}, expect=403)   # A does not own B's account
        _post(api_b, {"action": "assign_account", "business_unit_id": org["beta"], "cloud_account_id": ACCOUNT_B_ID}, expect=403)  # B is not (yet) a member

    with step("invite B as business-unit admin of beta; B can then assign their own account to beta but not to alpha"):
        r = _post(api, {"action": "invite_member", "organization_id": o, "email": USER_B, "role": "bu_admin", "business_unit_id": org["beta"]})
        assert "sent" in r["email"]
        _post(api, {"action": "invite_member", "organization_id": o, "email": USER_B, "role": "bu_admin", "business_unit_id": org["beta"]}, expect=409)
        _post(api_b, {"action": "assign_account", "business_unit_id": org["alpha"], "cloud_account_id": ACCOUNT_B_ID}, expect=403)
        _post(api_b, {"action": "assign_account", "business_unit_id": org["beta"], "cloud_account_id": ACCOUNT_B_ID})

    with step("the organization overview shows the structure to its owner, and only their own unit to a scoped admin"):
        s, b, _ = api.get("enterprise")
        mine = next(x for x in b["organizations"] if x["id"] == o)
        assert mine["my_role"] == "owner" and {u["name"] for u in mine["business_units"]} == {"alpha", "beta"}
        assert {m["email"] for m in mine["members"]} == {USER_B}
        s, b, _ = api_b.get("enterprise")
        theirs = next(x for x in b["organizations"] if x["id"] == o)
        assert theirs["my_role"] == "bu_admin" and [u["name"] for u in theirs["business_units"]] == ["beta"] and theirs["members"] == []


@pytest.mark.flow("E2E-PERM-002")
@pytest.mark.severity("P0")
@pytest.mark.needs_team
def test_enterprise_permissions_scope_and_roles(api, api_b, api_d, org, step):
    o, alpha, beta = org["id"], org["alpha"], org["beta"]
    _post(api, {"action": "invite_member", "organization_id": o, "email": USER_B, "role": "bu_admin", "business_unit_id": beta})
    _post(api_b, {"action": "assign_account", "business_unit_id": beta, "cloud_account_id": ACCOUNT_B_ID})

    with step("before being invited, D sees and can do nothing"):
        assert _visible_accounts(api_d) == set()
        assert api_d.get("tprm", params={"cloud_account_id": ACCOUNT_ID})[0] == 403

    with step("A invites D as a VIEWER of unit alpha only"):
        m = _post(api, {"action": "invite_member", "organization_id": o, "email": USER_D, "role": "viewer", "business_unit_id": alpha})
        member_id = m["id"]

    with step("D signs in and sees ONLY the account of unit alpha"):
        assert _visible_accounts(api_d) == {ACCOUNT_ID}
        s, b, _ = api_d.get("enterprise")
        assert [u["name"] for u in b["organizations"][0]["business_units"]] == ["alpha"] and b["organizations"][0]["my_role"] == "viewer"

    with step("D can read alpha's data but everything outside the scope stays inaccessible"):
        for path in ("tprm", "audit-management", "notifications", "questionnaires"):
            assert api_d.get(path, params={"cloud_account_id": ACCOUNT_ID})[0] == 200, path
        for path in ("tprm", "audit-management", "notifications", "questionnaires"):
            assert api_d.get(path, params={"cloud_account_id": ACCOUNT_B_ID}, )[0] == 403, path

    with step("a viewer can never change anything, not even inside their own unit"):
        s, _, _ = api_d.post("tprm", {"action": "create_vendor", "cloud_account_id": ACCOUNT_ID, "name": "viewer must not create this"}, headers=JSON)
        assert s == 403
        _, v, _ = api.get("tprm", params={"cloud_account_id": ACCOUNT_ID})
        assert all("viewer must not create" not in x["name"] for x in v["vendors"])
        _post(api_d, {"action": "invite_member", "organization_id": o, "email": "x@y.zz", "role": "viewer", "business_unit_id": alpha}, expect=403)
        _post(api_d, {"action": "create_business_unit", "organization_id": o, "name": "sneaky"}, expect=403)

    with step("the denied attempts are audited for the account they targeted"):
        s, b, _ = api_b.get("notifications", params={"cloud_account_id": ACCOUNT_B_ID, "security_audit": "1"})
        assert any(e["actor_email"] == USER_D for e in b["events"])

    with step("promoting D to bu_admin lets them change alpha's data, still nothing outside it"):
        _post(api, {"action": "update_member", "member_id": member_id, "role": "bu_admin"})
        s, b, _ = api_d.post("tprm", {"action": "create_vendor", "cloud_account_id": ACCOUNT_ID, "name": f"{TEST_PREFIX} by D", "criticality": "low"}, headers=JSON)
        assert s == 200, (s, b)
        vid = b["id"]
        s, _, _ = api_d.post("tprm", {"action": "delete_vendor", "vendor_id": vid}, headers=JSON)
        assert s == 200
        s, _, _ = api_d.post("tprm", {"action": "create_vendor", "cloud_account_id": ACCOUNT_B_ID, "name": "x"}, headers=JSON, allow_foreign=True)
        assert s == 403

    with step("the organization's owner reaches every unit; a scoped admin only their own"):
        assert api.get("tprm", params={"cloud_account_id": ACCOUNT_B_ID})[0] == 200
        assert api_b.get("tprm", params={"cloud_account_id": ACCOUNT_ID})[0] == 403

    with step("removing D revokes access immediately"):
        _post(api, {"action": "remove_member", "member_id": member_id})
        assert _visible_accounts(api_d) == set()
        assert api_d.get("tprm", params={"cloud_account_id": ACCOUNT_ID})[0] == 403

    with step("unassigning an account removes everyone's org-based access to it"):
        _post(api_b, {"action": "unassign_account", "business_unit_id": beta, "cloud_account_id": ACCOUNT_B_ID})
        assert api.get("tprm", params={"cloud_account_id": ACCOUNT_B_ID})[0] == 403


@pytest.mark.flow("E2E-PERM-002")
@pytest.mark.severity("P0")
@pytest.mark.needs_team
def test_deleting_the_organization_ends_all_org_based_access(api, api_d, cleanup):
    o = _post(api, {"action": "create_organization", "name": f"{TEST_PREFIX} temp"})["id"]
    u = _post(api, {"action": "create_business_unit", "organization_id": o, "name": "u"})["id"]
    _post(api, {"action": "assign_account", "business_unit_id": u, "cloud_account_id": ACCOUNT_ID})
    _post(api, {"action": "invite_member", "organization_id": o, "email": USER_D, "role": "viewer", "business_unit_id": u})
    assert _visible_accounts(api_d) == {ACCOUNT_ID}
    _post(api_d, {"action": "delete_organization", "organization_id": o}, expect=403)          # only the owner may delete
    _post(api, {"action": "delete_organization", "organization_id": o})
    assert _visible_accounts(api_d) == set()


@pytest.mark.flow("E2E-AUTH-001")
@pytest.mark.severity("P0")
def test_enterprise_endpoint_requires_a_session(anon):
    assert anon.get("enterprise")[0] == 401
    assert anon.post("enterprise", {"action": "create_organization", "name": "x"}, headers=JSON)[0] == 401
