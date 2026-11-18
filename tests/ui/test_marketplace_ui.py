"""Marketplace page (#90) in a real browser against a fake backend built from the real catalog.
Checks search/category/filters, the honest detail of unbuilt integrations, the guided connect that needs the
permission review first, health, requests, reviews, compare, escaping and the phone layout."""
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from collectors.aws.scanner import marketplace_lib as M
from ui_support import ACCOUNT, CORS

pytestmark = [pytest.mark.flow("E2E-MKT-001"), pytest.mark.severity("P2")]

NOW = datetime.now(timezone.utc).isoformat()
XSS = '<img src=x onerror="window.__xss=1">'


class Fake:
    def __init__(self):
        self.posts = []
        self.requested = set()
        self.state = {"amazon-web-services": {"connected": True, "health": "ok", "health_reason": "Scanned within the expected interval",
                                              "last_sync": NOW, "items": 1},
                      "jira": {"connected": True, "health": "needs_reauth", "health_reason": "The provider no longer accepts the token: " + XSS,
                               "last_sync": None, "items": 1}}

    def _json(self, route, payload, status=200):
        route.fulfill(status=status, content_type="application/json", headers=CORS, body=json.dumps(payload, default=str))

    def overview(self):
        items = []
        for e in M.catalog():
            d = e["detail"] or {}
            items.append({**{k: e[k] for k in ("slug", "name", "vendor", "category", "delivers", "objects", "status", "maintained_by", "certification")},
                          "auth_methods": d.get("auth_methods", []), "deployment": d.get("deployment"), "frameworks": d.get("frameworks", []),
                          "installs": 3 if e["status"] == "Available" else None, "requests": 2 if e["slug"] == "okta" else 0,
                          "rating": {"average": 4.3, "count": 3} if e["slug"] == "slack" else None,
                          "requested": e["slug"] in self.requested, "connection": self.state.get(e["slug"])})
        cats = {}
        for i in items:
            cats[i["category"]] = cats.get(i["category"], 0) + 1
        return {"integrations": items, "categories": [{"name": k, "count": v} for k, v in sorted(cats.items())],
                "counts": {"total": len(items), "Available": 8, "Planned": 3, "On request": len(items) - 11, "connected": len(self.state)},
                "connected": [{"slug": s, "name": M.by_slug()[s]["name"], **v} for s, v in self.state.items()],
                "recommendations": [{"slug": "jira", "name": "Jira", "kind": "fix", "reason": "Jira is connected but not working", "alternatives": []},
                                    {"slug": "slack", "name": "Slack", "kind": "connect", "reason": "No chat channel " + XSS, "alternatives": ["microsoft-teams"]},
                                    {"slug": "okta", "name": "Okta", "kind": "request", "reason": "3 open identity checks", "alternatives": []}],
                "my_requests": [], "audit": [{"at": NOW, "actor": XSS, "action": "marketplace_request", "integration": "okta", "details": {}}],
                "notes": {"ratings": "Shown once 3 accounts have reviewed.", "installs": "x", "health": "Worked out from real data.", "partners": "x"}}

    def handle(self, route):
        req = route.request
        if req.method == "OPTIONS":
            return route.fulfill(status=200, headers=CORS, body="")
        if req.method == "POST":
            body = json.loads(req.post_data or "{}")
            self.posts.append(body)
            if body["action"] == "request":
                self.requested.add(body.get("slug") or "new:x")
                return self._json(route, {"requested": True, "note": "Your request is recorded."})
            if body["action"] == "review" and body["slug"] not in self.state:
                return self._json(route, {"error": "Only accounts that have connected an integration can review it."}, 400)
            return self._json(route, {"saved": True})
        qs = {k: v[0] for k, v in parse_qs(urlparse(req.url).query).items()}
        if qs.get("slug"):
            e = M.by_slug()[qs["slug"]]
            return self._json(route, {**e, "connection": self.state.get(e["slug"]), "installs": 3, "requests": 2, "rating": None,
                                      "reviews": [{"own": False, "rating": 2, "message": XSS, "at": NOW, "author": None}],
                                      "my_issues": [], "my_request": {"note": "SOC 2", "by": "o", "at": NOW} if e["slug"] in self.requested else None})
        return self._json(route, self.overview())


def _open(page, site, fake):
    page.route("**/default/marketplace**", fake.handle)
    page.goto(f"{site}/marketplace.html?account_id={ACCOUNT}")
    page.wait_for_selector(".ic")


def test_search_categories_and_filters(page, site):
    _open(page, site, Fake())
    total = len(M.catalog())
    assert page.locator(".ic").count() == total
    assert page.locator("#metrics .metric .v").first.inner_text() == str(total)
    # Available integrations come first.
    assert page.locator(".ic .nm").first.inner_text() == "Amazon Web Services"
    page.fill("#q", "okta")
    assert "Okta" in page.locator("#cards").inner_text() and page.locator(".ic").count() < 10
    page.fill("#q", "")
    page.click("[data-cat='Ticketing & ITSM']")
    assert all("Ticketing & ITSM" in t for t in page.locator(".ic .vd").all_inner_texts())
    page.click("[data-cat='']")
    page.select_option("#f-status", "Available")
    assert page.locator(".ic").count() == 8
    page.select_option("#f-auth", "Webhooks")
    assert page.locator(".ic").count() == 4
    page.select_option("#f-auth", "")
    page.select_option("#f-fw", "CIS GitHub Benchmark v1.0.0")
    assert page.locator(".ic .nm").all_inner_texts() == ["GitHub"]
    assert page.evaluate("window.__xss") is None and not page.errors


def test_unbuilt_integration_is_requested_not_connected(page, site):
    fake = Fake()
    _open(page, site, fake)
    page.fill("#q", "okta")
    page.click(".ic[data-open='okta']")
    page.wait_for_selector("#rq-go")
    text = page.locator("#drawer").inner_text()
    assert "On request" in text and "not guessed" in text and "Required permissions" not in text
    page.fill("#rq-note", "Needed for SOC 2 access reviews")
    page.click("#rq-go")
    page.wait_for_selector("text=You requested this")
    assert fake.posts[-1] == {"cloud_account_id": ACCOUNT, "action": "request", "slug": "okta", "note": "Needed for SOC 2 access reviews"}
    # A tool that is not in the catalog can be requested too.
    page.click("[data-close]")
    page.fill("#new-name", "Acme Tool")
    page.click("#new-go")
    page.wait_for_function("document.getElementById('toast').textContent.includes('recorded')")
    assert fake.posts[-1]["name"] == "Acme Tool"
    assert page.evaluate("window.__xss") is None and not page.errors


def test_guided_connect_needs_the_permission_review_first(page, site):
    _open(page, site, Fake())
    page.click(".ic[data-open='github']")
    page.wait_for_selector("#wiz-go")
    text = page.locator("#drawer").inner_text()
    assert "read:org" in text and "Secrets Manager" in text and "CIS GitHub Benchmark" in text
    assert page.is_disabled("#wiz-go")
    page.check("#wiz-ok")
    assert page.is_enabled("#wiz-go")
    with page.expect_navigation():
        page.click("#wiz-go")
    assert page.url.endswith("/settings/github")


def test_health_review_and_compare(page, site):
    fake = Fake()
    _open(page, site, fake)
    page.click("[data-tab=connected]")
    t = page.locator("#connected").inner_text()
    assert "Needs re-authorization" in t and "Healthy" in t
    page.click("#connected [data-open='jira']")
    page.wait_for_selector("#rv-go")
    assert "Manage, re-authorize or disconnect" in page.locator("#drawer").inner_text()
    page.click("#rv-go")
    page.wait_for_function("document.getElementById('toast').textContent.includes('stars')")
    page.click("[data-star='4']")
    page.fill("#rv-msg", "Fine")
    page.click("#rv-go")
    page.wait_for_function("document.getElementById('toast').textContent.includes('saved')")
    assert fake.posts[-1] == {"cloud_account_id": ACCOUNT, "action": "review", "slug": "jira", "rating": 4, "message": "Fine"}
    page.click("[data-close]")
    page.click("[data-tab=browse]")
    for s in ("jira", "monday-com", "slack"):
        page.check(f"[data-cmp='{s}']")
    page.click("[data-cmp='github']")
    assert page.locator("[data-cmp]:checked").count() == 3  # at most three
    page.click("#cmpgo")
    t = page.locator("#drawer").inner_text()
    assert "Jira" in t and "Monday.com" in t and "Slack" in t and "API keys" in t
    assert page.evaluate("window.__xss") is None and not page.errors


def test_every_tab_on_a_phone_and_errors_shown(page, site):
    page.set_viewport_size({"width": 390, "height": 800})
    _open(page, site, Fake())
    for t in ("connected", "activity", "browse"):
        page.click(f"[data-tab={t}]")
        assert page.evaluate("document.documentElement.scrollWidth") <= 392, t
    page.click(".ic[data-open='amazon-web-services']")
    page.wait_for_selector("#drawer.open .kv")
    assert page.evaluate("document.documentElement.scrollWidth") <= 392
    assert page.evaluate("window.__xss") is None and not page.errors


def test_backend_failure_is_shown_plainly(page, site):
    page.route("**/default/marketplace**", lambda r: r.fulfill(status=403, headers=CORS, content_type="application/json", body='{"error": "Forbidden"}'))
    page.goto(f"{site}/marketplace.html?account_id={ACCOUNT}")
    page.wait_for_selector("#error:not([hidden])")
    assert "Forbidden" in page.locator("#error").inner_text()
