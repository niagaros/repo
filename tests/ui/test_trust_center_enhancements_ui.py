"""Trust Center second pass (#258) in a real browser: certificate validity on the public page, status notices with a
link to the company's own status page, responsible disclosure, branding, and the admin forms that set them.
The API is mocked; titles, notices and policy text carry XSS payloads."""
import json
from datetime import date, timedelta
from urllib.parse import parse_qs, urlparse

import pytest

from ui_support import ACCOUNT, CORS

pytestmark = [pytest.mark.flow("E2E-TRUST-001"), pytest.mark.severity("P2")]

XSS = '<img src=x onerror="window.__xss=1">'
TODAY = date.today()


def _json(route, payload, status=200):
    route.fulfill(status=status, content_type="application/json", headers=CORS, body=json.dumps(payload))


PUBLIC_VIEW = {
    "company_name": "Acme", "intro_text": "", "contact_email": "", "compliance": [], "security_posture": [], "qa_highlights": [],
    "documents": [
        {"id": "d1", "title": "ISO 27001 certificate", "category": "ISO Certificate", "visibility": "public",
         "download_url": "https://s3.example/iso.pdf", "valid_until": str(TODAY - timedelta(days=3)), "issuer": XSS,
         "validity_status": "expired"},
        {"id": "d2", "title": "SOC 2 report", "category": "SOC Report", "visibility": "restricted",
         "valid_until": str(TODAY + timedelta(days=200)), "issuer": "Auditor LLP", "validity_status": "valid"}],
    "branding": {"brand_color": "#7c3aed", "logo_url": "https://s3.example/logo.png"},
    "status": {"status_page_url": "https://status.acme.test", "updates": [
        {"id": "u1", "kind": "incident", "title": XSS, "body": "Some API requests failed.", "starts_at": "2026-11-15T10:00:00+00:00", "resolved_at": None}]},
    "disclosure": {"security_contact": "security@acme.test", "policy": "Report issues to us. " + XSS},
}


def test_public_page_shows_validity_status_and_disclosure(page, site):
    page.route("**/default/trust-center**", lambda r: _json(r, PUBLIC_VIEW))
    page.route("https://s3.example/**", lambda r: r.fulfill(status=200, content_type="image/png", body=b""))
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{site}/trust_center_public.html?slug=abc")
    page.wait_for_selector("#status", timeout=15000)
    docs = page.locator("#doc-list").inner_text()
    assert "Expired since" in docs and "Valid until" in docs and "issued by Auditor LLP" in docs
    status = page.locator("#status").inner_text()
    assert "1 open notice" in status and "Open since" in status
    assert page.locator('#status a[href="https://status.acme.test/"]').count() == 1
    assert "security@acme.test" in page.locator("#disclosure").inner_text()
    assert page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()") == "#7c3aed"
    assert page.locator('img.logo[src="https://s3.example/logo.png"]').count() == 1
    assert page.locator("[data-nav=status]").count() == 1
    assert page.evaluate("window.__xss") is None and not errors


def test_unsafe_status_link_is_not_rendered(page, site):
    view = {**PUBLIC_VIEW, "status": {"status_page_url": "javascript:alert(1)", "updates": []}, "branding": {"brand_color": "red;}", "logo_url": "http://x"}}
    page.route("**/default/trust-center**", lambda r: _json(r, view))
    page.goto(f"{site}/trust_center_public.html?slug=abc")
    page.wait_for_selector("#documents", timeout=15000)
    assert page.locator("#status").count() == 0 and page.locator("img.logo").count() == 0
    assert page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()") == "#2563eb"


class FakeAdmin:
    def __init__(self):
        self.posts = []

    def handle(self, route):
        req = route.request
        if req.method == "OPTIONS":
            return route.fulfill(status=200, headers=CORS, body="")
        if req.method == "GET":
            qs = parse_qs(urlparse(req.url).query)
            if "access_requests" in qs:
                return _json(route, {"requests": []})
            if "audit_log" in qs:
                return _json(route, {"entries": []})
            if "updates" in qs:
                return _json(route, {"updates": [{"id": "u1", "kind": "maintenance", "title": XSS, "body": "", "starts_at": "2026-11-16T08:00:00+00:00",
                                                  "resolved_at": None, "published_by": "owner@acme.test"}]})
            if "analytics" in qs:
                return _json(route, {"page_loads_30d": [{"day": "2026-11-15", "views": 4}, {"day": "2026-11-16", "views": 9}],
                                     "page_loads_total_30d": 13, "documents_30d": [], "access_requests_90d": {"approved": 2, "denied": 1},
                                     "approval_rate_pct": 67, "approved_answers_total": 5, "approved_answers_shown": 5, "method": "Counted per request; no visitor identity."})
            if "events" in qs:
                return _json(route, {"events": [{"at": "2026-11-16T08:00:00+00:00", "actor": "owner@acme.test", "action": "settings_updated"}]})
            return _json(route, {"settings": {"cloud_account_id": ACCOUNT, "is_public": True, "public_slug": "abc", "company_name": "Acme",
                                              "intro_text": "", "contact_email": "", "custom_domain": None, "brand_color": "#7c3aed",
                                              "logo_url": None, "status_page_url": None, "security_contact": None, "disclosure_policy": None},
                                 "compliance": [],
                                 "documents": [{"id": "11111111-1111-1111-1111-111111111111", "title": "ISO cert", "category": "iso_certificate", "visibility": "public",
                                                "created_at": "2026-11-01T00:00:00+00:00", "versions": [{"version_number": 1}],
                                                "valid_from": None, "valid_until": None, "issuer": None, "validity_status": "no_expiry"}]})
        body = json.loads(req.post_data or "{}")
        self.posts.append(body)
        return _json(route, {"ok": True})


def test_admin_sets_validity_publishes_notice_and_sees_analytics(page, site):
    backend = FakeAdmin()
    page.route("**/default/trust-center**", backend.handle)
    page.route("**/get-dashboard-data**", lambda r: _json(r, {"account_name": "Acme", "accounts": [{"id": ACCOUNT, "name": "Acme"}]}))
    page.route("**/default/notifications**", lambda r: _json(r, {"notifications": []}))
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{site}/trust_center.html?account_id={ACCOUNT}")
    page.wait_for_selector("text=13", timeout=15000)
    assert "67% approved" in page.locator("#analytics").inner_text()
    page.click("text=Validity (for certificates and reports)")
    page.fill('[data-vu="11111111-1111-1111-1111-111111111111"]', "2027-06-30")
    page.fill('[data-vi="11111111-1111-1111-1111-111111111111"]', "BSI")
    page.click('[data-tc="save-validity"]')
    page.wait_for_function("document.getElementById('toast').textContent.includes('Validity saved')")
    assert backend.posts[-1] == {"cloud_account_id": ACCOUNT, "action": "set_document_validity", "document_id": "11111111-1111-1111-1111-111111111111",
                                 "valid_from": None, "valid_until": "2027-06-30", "issuer": "BSI"}
    page.select_option("#up-kind", "maintenance")
    page.fill("#up-ntitle", "Database upgrade")
    page.fill("#up-nbody", "Short downtime on Sunday.")
    page.click('[data-tc="publish-update"]')
    page.wait_for_function("document.getElementById('toast').textContent.includes('Notice published')")
    assert backend.posts[-1]["action"] == "create_update" and backend.posts[-1]["kind"] == "maintenance"
    assert page.evaluate("window.__xss") is None and not errors
