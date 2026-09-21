"""The frontend must send the signed-in user's token to the API on every page (otherwise tenant isolation
would lock real users out), and must send an expired session back to the login page."""
import json

import pytest

from conftest import PUBLIC_DIR
from ui_support import ACCOUNT, CORS, FakeBackend

pytestmark = [pytest.mark.flow("E2E-AUTH-001"), pytest.mark.severity("P0")]
PUBLIC_PAGES = {"index.html", "status.html", "questionnaire_share_view.html", "trust_center_public.html", "test_dashboard.html", "auditor_view.html"}


def test_every_page_that_calls_the_api_loads_the_token_forwarder():
    missing = []
    for p in sorted(PUBLIC_DIR.glob("*.html")):
        text = p.read_text(encoding="utf-8", errors="replace")
        if p.name in PUBLIC_PAGES or ("execute-api" not in text and "ai-agent-widget" not in text):
            continue
        if "auth-fetch.js" not in text:
            missing.append(p.name)
    assert not missing, f"pages calling the API without sending the session token: {missing}"


def test_token_is_attached_to_api_requests(page, site):
    seen = []
    backend = FakeBackend()
    original = backend.handle

    def spy(route):
        seen.append((route.request.url, route.request.headers.get("authorization")))
        return original(route)

    page.add_init_script("localStorage.setItem('niagaros_token', 'test-token-123')")
    page.route("**/get-dashboard-data**", spy)
    page.route("**/default/notifications**", spy)
    page.goto(f"http://{site.split('//')[1]}/notification_settings.html?account_id={ACCOUNT}")
    page.wait_for_selector("#v-content:not([hidden])", timeout=15000)
    api_calls = [(u, a) for u, a in seen if "execute-api" in u]
    assert api_calls and all(a == "Bearer test-token-123" for _, a in api_calls), api_calls


def test_an_expired_session_returns_the_user_to_login(page, site):
    navigations = []
    page.on("framenavigated", lambda f: navigations.append(f.url))
    page.add_init_script("if(!sessionStorage.getItem('seeded')){localStorage.setItem('niagaros_token','expired');sessionStorage.setItem('seeded','1')}")
    page.route("**/get-dashboard-data**", lambda r: r.fulfill(status=401, headers=CORS, content_type="application/json", body=json.dumps({"error": "Unauthorized"})))
    try:
        page.goto(f"{site}/notification_settings.html?account_id={ACCOUNT}")
    except Exception:
        pass  # the page navigates away to the login page while loading — that is the behaviour under test
    import time
    deadline = time.time() + 10
    while time.time() < deadline and f"{site}/" not in navigations:
        page.wait_for_timeout(200)
    assert f"{site}/" in navigations, navigations
