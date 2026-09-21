"""Workspace integrations on the live API: authentication, validation (nothing is stored when the provider rejects the
credentials), tenant isolation, and - when real Jira credentials are supplied - the full connect -> ticket -> sync flow."""
import base64
import os
import uuid

import pytest

from conftest import ACCOUNT_B_ID, ACCOUNT_ID, TEST_PREFIX

pytestmark = [pytest.mark.live, pytest.mark.flow("E2E-WS-001"), pytest.mark.severity("P1")]
JSON = {"Content-Type": "application/json"}


def test_integrations_require_a_session(anon):
    assert anon.get("integrations", params={"cloud_account_id": ACCOUNT_ID})[0] == 401
    assert anon.post("integrations", {"action": "connect", "cloud_account_id": ACCOUNT_ID}, headers=JSON)[0] == 401


@pytest.mark.needs_token
@pytest.mark.parametrize("body,fragment", [
    ({"provider": "jira", "site_url": "https://evil.example.com", "email": "a@b.co", "api_token": "x"}, "atlassian.net"),
    ({"provider": "jira", "site_url": "http://169.254.169.254", "email": "a@b.co", "api_token": "x"}, "atlassian.net"),
    ({"provider": "trello", "api_token": "x"}, "provider"),
    ({"provider": "jira", "site_url": "https://acme.atlassian.net", "email": "a@b.co"}, "api_token is required"),
])
def test_connect_validates_input_and_never_reaches_arbitrary_hosts(api, body, fragment):
    s, b, _ = api.post("integrations", {"action": "connect", "cloud_account_id": ACCOUNT_ID, **body}, headers=JSON)
    assert s == 400 and fragment in b["error"]
    _, lst, _ = api.get("integrations", params={"cloud_account_id": ACCOUNT_ID})
    assert lst["integrations"] == [], "a rejected connection must not leave anything behind"


@pytest.mark.needs_token
def test_wrong_monday_credentials_are_rejected_by_the_provider_and_nothing_is_stored(api):
    s, b, _ = api.post("integrations", {"action": "connect", "cloud_account_id": ACCOUNT_ID, "provider": "monday", "api_token": "definitely-not-a-valid-token"}, headers=JSON)
    assert s == 400 and "Could not connect to monday" in b["error"]
    assert api.get("integrations", params={"cloud_account_id": ACCOUNT_ID})[1]["integrations"] == []


@pytest.mark.needs_two_tenants
def test_another_tenant_cannot_use_my_integrations(api, api_b):
    assert api_b.get("integrations", params={"cloud_account_id": ACCOUNT_ID})[0] == 403
    assert api_b.post("integrations", {"action": "sync", "cloud_account_id": ACCOUNT_B_ID, "integration_id": str(uuid.uuid4())}, headers=JSON)[0] == 404


JIRA = {k: os.environ.get(f"E2E_JIRA_{k.upper()}", "") for k in ("site", "email", "token", "project")}


@pytest.mark.needs_token
@pytest.mark.skipif(not all(JIRA.values()), reason="blocked: set E2E_JIRA_SITE, E2E_JIRA_EMAIL, E2E_JIRA_TOKEN, E2E_JIRA_PROJECT to run against a real Jira Cloud")
def test_real_jira_connect_ticket_and_sync(api, step, cleanup):
    tag = f"{TEST_PREFIX} jira {uuid.uuid4().hex[:6]}"
    s, b, _ = api.post("audit-management", {"action": "create_audit", "cloud_account_id": ACCOUNT_ID, "title": tag, "audit_type": "internal"}, headers=JSON)
    audit_id = b["id"]
    cleanup(lambda: api.post("audit-management", {"action": "delete_audit", "cloud_account_id": ACCOUNT_ID, "audit_id": audit_id}, headers=JSON))
    s, b, _ = api.post("audit-management", {"action": "add_manual_finding", "audit_id": audit_id, "title": tag, "severity": "low"}, headers=JSON)
    finding_id = b["id"]
    with step("connect: credentials are verified against the real Jira"):
        s, b, _ = api.post("integrations", {"action": "connect", "cloud_account_id": ACCOUNT_ID, "provider": "jira", "site_url": JIRA["site"],
                                            "email": JIRA["email"], "api_token": JIRA["token"]}, headers=JSON)
        assert s == 200 and b["authenticated_as"], (s, b)
        iid = b["id"]
        cleanup(lambda: api.post("integrations", {"action": "disconnect", "cloud_account_id": ACCOUNT_ID, "integration_id": iid}, headers=JSON))
        assert JIRA["project"] in [p["id"] for p in b["projects"]]
    with step("map the project, create the ticket, and sync"):
        assert api.post("integrations", {"action": "select_project", "cloud_account_id": ACCOUNT_ID, "integration_id": iid, "project": JIRA["project"]}, headers=JSON)[0] == 200
        s, b, _ = api.post("integrations", {"action": "create_ticket", "cloud_account_id": ACCOUNT_ID, "integration_id": iid, "finding_id": finding_id}, headers=JSON)
        assert s == 200 and b["ticket"]["key"].startswith(JIRA["project"] + "-")
        s, b, _ = api.post("integrations", {"action": "sync", "cloud_account_id": ACCOUNT_ID, "integration_id": iid}, headers=JSON)
        assert s == 200 and b["synced"][0]["finding_id"] == finding_id
