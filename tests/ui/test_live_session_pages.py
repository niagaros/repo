"""The deployed frontend, in a real browser, signed in as a real test user, against the real enforcing API.
Nothing is mocked: this proves the token forwarding and the backend guard work together on every page that
talks to an account-scoped endpoint (the exact regression tenant isolation could cause for real users)."""
import pytest

from conftest import ACCOUNT_ID, SITE_BASE, TOKEN

pytestmark = [pytest.mark.live, pytest.mark.needs_token, pytest.mark.flow("E2E-UI-003"), pytest.mark.severity("P0")]
NETWORK_NOISE = ("Failed to fetch", "NetworkError", "Load failed", "aborted", "net::ERR")

PAGES = ["notification_settings.html", "tprm.html", "questionnaire_automation.html", "audit_management.html",
         "trust_center.html", "custom_frameworks.html", "calculators.html", "ai_agent.html", "niagaros-dashboard.html", "soc2.html"]


@pytest.mark.parametrize("name", PAGES)
def test_page_works_with_a_real_session_against_the_enforcing_api(browser, name):
    ctx = browser.new_context()
    ctx.route("**/fonts.g*/**", lambda r: r.abort())
    ctx.add_init_script(f"localStorage.setItem('niagaros_token', {TOKEN!r})")
    page = ctx.new_page()
    errors, bad = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("response", lambda r: bad.append((r.status, r.url.split("/default/")[-1][:60]))
            if "execute-api" in r.url and r.status in (401, 403, 500, 502, 503) else None)
    page.goto(f"{SITE_BASE}/{name}?account_id={ACCOUNT_ID}", wait_until="domcontentloaded")
    page.wait_for_timeout(4000)
    try:
        assert page.url.split("?")[0].endswith(name), f"redirected away from the page: {page.url}"
        assert not bad, f"API refused or failed the page's own requests: {bad}"
        assert not [e for e in errors if not any(n in e for n in NETWORK_NOISE)], errors
    finally:
        ctx.close()
