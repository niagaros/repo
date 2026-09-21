"""The pages that expose the enterprise, auditor and integration features - real files, real browser, recording fake backend."""
import json

import pytest

from ui_support import ACCOUNT, CORS

pytestmark = [pytest.mark.severity("P1")]


def _fulfill(route, payload, status=200):
    route.fulfill(status=status, content_type="application/json", headers=CORS, body=json.dumps(payload))


AUDIT = {"audit": {"id": "a1", "title": "<img src=x onerror=alert(1)> ISO 27001 audit", "framework_label": "ISO 27001", "audit_type": "external", "status": "in_progress",
                   "start_date": None, "end_date": None, "scope_description": "Production account", "findings_total": 1, "findings_open": 1, "audit_readiness_score": 0,
                   "evidence_completeness_pct": 0, "findings": [{"id": "f1", "title": "Open port", "severity": "HIGH", "status": "open", "description": "x", "remediation_tasks": [], "comments": []}],
                   "evidence": [{"id": "e1", "title": "Policy", "has_file": True}]},
         "auditor": {"email": "aud@firm.com", "name": "Ann Auditor"}}


@pytest.mark.flow("E2E-AUD-002")
def test_auditor_view_shows_only_the_invited_audit_renders_text_safely_and_sends_the_token(page, site):
    posts = []

    def handle(route):
        if route.request.method == "POST":
            posts.append(json.loads(route.request.post_data))
            return _fulfill(route, {"id": "new"})
        return _fulfill(route, AUDIT)

    page.route("**/default/audit-management**", handle)
    page.goto(f"{site}/auditor_view.html?token=abc123")
    page.wait_for_selector(".finding")
    body = page.inner_text("body")
    assert "Ann Auditor" in body and "Open port" in body and "Policy" in body and "private, read-and-comment workspace" in body
    assert page.locator("main img").count() == 0 and not page.dialogs and not page.errors
    page.fill("#nf-title", "New auditor finding")
    page.click("#nf-add")
    page.wait_for_timeout(300)
    assert posts and posts[0]["auditor_token"] == "abc123" and posts[0]["action"] == "auditor_add_finding" and posts[0]["title"] == "New auditor finding"
    assert "cloud_account_id" not in posts[0]


@pytest.mark.flow("E2E-AUD-002")
def test_auditor_view_explains_an_invalid_or_missing_link(page, site):
    page.goto(f"{site}/auditor_view.html")
    assert "private link from your invitation" in page.inner_text("body")
    page.route("**/default/audit-management**", lambda r: _fulfill(r, {"error": "This auditor link is invalid, expired, or has been revoked."}, 403))
    page.goto(f"{site}/auditor_view.html?token=bad")
    page.wait_for_selector(".err")
    assert "revoked" in page.inner_text("body")


@pytest.mark.flow("E2E-ONB-001")
def test_enterprise_page_shows_structure_and_invites_with_scope(page, site):
    posts = []
    org = {"id": "o1", "name": "Acme <b>Corp</b>", "owner_email": "me@x.io", "my_role": "owner", "my_scope_business_unit_id": None,
           "business_units": [{"id": "u1", "name": "alpha", "accounts": [{"id": ACCOUNT, "name": "Domits"}]}], "members": []}

    def handle(route):
        u = route.request.url
        if route.request.method == "POST":
            posts.append(json.loads(route.request.post_data))
            return _fulfill(route, {"id": "m1", "email": {"sent": False}})
        if "get-dashboard-data" in u:
            return _fulfill(route, {"accounts": [{"id": ACCOUNT, "name": "Domits"}]})
        return _fulfill(route, {"organizations": [org], "caller": "me@x.io"})

    page.route("**/default/get-dashboard-data**", handle)
    page.route("**/default/enterprise**", handle)
    page.goto(f"{site}/enterprise.html?account_id={ACCOUNT}")
    page.wait_for_selector(".card h2")
    assert "alpha" in page.inner_text("body") and "Domits" in page.inner_text("body")
    assert "Acme <b>Corp</b>" in page.inner_text("body") and page.locator(".card h2 b").count() == 0, "the organization name must be shown as text, not markup"
    assert not page.errors
    page.fill('[data-inv-email="o1"]', "viewer@x.io")
    page.click('[data-invite="o1"]')
    page.wait_for_timeout(300)
    inv = next(p for p in posts if p["action"] == "invite_member")
    assert inv["email"] == "viewer@x.io" and inv["role"] == "viewer" and inv["business_unit_id"] == "u1" and inv["organization_id"] == "o1"


@pytest.mark.flow("E2E-WS-001")
def test_integrations_page_connects_with_the_right_payload_and_clears_the_token(page, site):
    posts = []

    def handle(route):
        u = route.request.url
        if route.request.method == "POST":
            posts.append(json.loads(route.request.post_data))
            return _fulfill(route, {"id": "i1", "authenticated_as": "Test User", "projects": []})
        if "audit-management" in u:
            return _fulfill(route, {"audits": []})
        return _fulfill(route, {"integrations": []})

    page.route("**/default/integrations**", handle)
    page.route("**/default/audit-management**", handle)
    page.goto(f"{site}/integrations.html?account_id={ACCOUNT}")
    page.wait_for_selector("#connect")
    page.fill("#site", "https://acme.atlassian.net")
    page.fill("#email", "me@acme.com")
    page.fill("#tok", "secret-token")
    page.click("#connect")
    page.wait_for_timeout(400)
    assert posts[0] == {"cloud_account_id": ACCOUNT, "action": "connect", "provider": "jira", "api_token": "secret-token", "site_url": "https://acme.atlassian.net", "email": "me@acme.com"}
    assert page.input_value("#tok") == "" and not page.errors
