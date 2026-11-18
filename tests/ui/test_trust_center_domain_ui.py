"""Trust Center custom domains (#272) in a real browser: on a company's own domain the public page asks the API for
that hostname, and the settings page walks the admin through the TXT verification. The API is mocked."""
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from ui_support import ACCOUNT, CORS

pytestmark = [pytest.mark.flow("E2E-TRUST-001"), pytest.mark.severity("P2")]

PUBLIC = Path(__file__).resolve().parents[2] / "frontend" / "public"
XSS = '<img src=x onerror="window.__xss=1">'
VIEW = {"company_name": "Domits", "intro_text": "", "contact_email": "", "compliance": [], "documents": [],
        "security_posture": [], "qa_highlights": []}


def _json(route, payload, status=200):
    route.fulfill(status=status, content_type="application/json", headers=CORS, body=json.dumps(payload))


def test_a_custom_domain_loads_its_own_trust_center(page):
    asked = []

    def api(route):
        if route.request.method == "OPTIONS":
            return route.fulfill(status=200, headers=CORS, body="")
        asked.append({k: v[0] for k, v in parse_qs(urlparse(route.request.url).query).items()})
        _json(route, VIEW)
    page.route("**/default/trust-center**", api)
    page.route("https://trust.domits.com/**", lambda r: r.fulfill(
        status=200, content_type="text/html", body=(PUBLIC / "trust_center_public.html").read_text(encoding="utf-8")))
    page.goto("https://trust.domits.com/trust_center_public.html")
    page.wait_for_selector("text=Domits", timeout=15000)
    assert asked == [{"domain": "trust.domits.com"}]


def test_the_app_host_without_a_slug_does_not_guess_a_trust_center(page, site):
    page.route("**/default/trust-center**", lambda r: pytest.fail("no API call expected"))
    page.goto(f"{site}/trust_center_public.html")
    page.wait_for_selector("text=No Trust Center specified", timeout=15000)


class FakeTrust:
    def __init__(self):
        self.domain = None
        self.posts = []

    def settings(self):
        return {"cloud_account_id": ACCOUNT, "is_public": True, "public_slug": "abc", "company_name": "Acme",
                "intro_text": "", "contact_email": "", "custom_domain": self.domain}

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
            return _json(route, {"settings": self.settings(), "documents": [], "compliance": []})
        body = json.loads(req.post_data or "{}")
        self.posts.append(body)
        if body["action"] == "set_custom_domain":
            d = body["custom_domain"].strip().lower()
            self.domain = {"domain": d, "verified": False, "verified_at": None, "txt_name": f"_niagaros-trust.{d}",
                           "txt_value": "niagaros-verify=" + XSS}
            return _json(route, {"custom_domain": self.domain})
        if body["action"] == "verify_custom_domain":
            self.domain = {**self.domain, "verified": True}
            return _json(route, {"verified": True, "custom_domain": self.domain})
        return _json(route, {"ok": True})


def test_settings_walk_through_domain_verification(page, site):
    backend = FakeTrust()
    page.route("**/default/trust-center**", backend.handle)
    page.route("**/get-dashboard-data**", lambda r: _json(r, {"account_name": "Acme", "accounts": [{"id": ACCOUNT, "name": "Acme"}]}))
    page.route("**/default/notifications**", lambda r: _json(r, {"notifications": []}))
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{site}/trust_center.html?account_id={ACCOUNT}")
    page.wait_for_selector("text=No custom domain set", timeout=15000)

    page.fill("#in-domain", "Trust.Acme.com")
    page.click("text=Save domain")
    page.wait_for_selector("text=Waiting for DNS verification")
    assert page.locator("#domain-status").inner_text().count("_niagaros-trust.trust.acme.com") == 1
    assert page.evaluate("window.__xss") is None

    page.click("#domain-status button")
    page.wait_for_selector("text=trust.acme.com is verified")
    assert [p["action"] for p in backend.posts] == ["set_custom_domain", "verify_custom_domain"]
    assert not errors


def test_a_slug_cannot_override_the_custom_domain(page):
    asked = []
    page.route("**/default/trust-center**", lambda r: (asked.append(r.request.url), _json(r, VIEW)))
    page.route("https://trust.domits.com/**", lambda r: r.fulfill(
        status=200, content_type="text/html", body=(PUBLIC / "trust_center_public.html").read_text(encoding="utf-8")))
    page.goto("https://trust.domits.com/trust_center_public.html?slug=attacker")
    page.wait_for_selector("text=Domits", timeout=15000)
    assert len(asked) == 1 and "domain=trust.domits.com" in asked[0] and "attacker" not in asked[0]
