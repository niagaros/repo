"""Every shipped page must load without a JavaScript error, and the public status page must show the real platform state."""
import re

import pytest

from conftest import PUBLIC_DIR

PAGES = sorted(p.name for p in PUBLIC_DIR.glob("*.html"))
NETWORK_NOISE = ("Failed to fetch", "NetworkError", "Load failed", "aborted")


@pytest.mark.flow("E2E-UI-002")
@pytest.mark.severity("P1")
@pytest.mark.parametrize("name", PAGES)
def test_page_loads_without_script_errors(page, site, name):
    """Backend calls are blocked, so this catches syntax/reference errors in the page's own code only."""
    page.route(re.compile(r"https://.*execute-api.*"), lambda r: r.abort())
    page.goto(f"{site}/{name}", wait_until="domcontentloaded")
    page.wait_for_timeout(500)
    real = [e for e in page.errors if not any(n in e for n in NETWORK_NOISE)]
    assert not real, real


@pytest.mark.flow("E2E-SEC-002")
@pytest.mark.severity("P0")
def test_no_page_puts_an_escaped_value_inside_an_inline_handler_string():
    """HTML-escaping does not protect a JavaScript string literal inside an on*= attribute:
    the browser decodes entities first, so an escaped quote still ends the string."""
    bad = re.compile(r"""on[a-z]+="[^"]*'\$\{[^}]*\b(esc|escape|escapeHtml|escHtml)\(""")
    offenders = [f"{p.name}:{i}" for p in PUBLIC_DIR.glob("*.html")
                 for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1) if bad.search(line)]
    assert not offenders, offenders


@pytest.mark.flow("E2E-PLAT-001")
@pytest.mark.severity("P0")
@pytest.mark.live
def test_public_status_page_renders_the_real_platform_state(page, site):
    page.goto(f"{site}/status.html")
    page.wait_for_function("document.body.innerText.toLowerCase().includes('operational') || document.body.innerText.toLowerCase().includes('degraded')", timeout=20000)
    body = page.inner_text("body").lower()
    assert "database" in body and "notification queue" in body
    for label in ("security dashboard", "notifications", "questionnaire automation", "ai agent", "third-party risk management", "audit management"):
        assert label in body, f"status page does not show {label}"
    assert not page.errors, page.errors
