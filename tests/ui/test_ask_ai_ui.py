"""Research Niagaros with AI (#297): the website footer section in a real browser.
Checks the six assistants and their destinations, prompt prefilling where the assistant supports it, copy-to-clipboard,
that the prompt names only public Niagaros pages and asks for sources, the disclaimer, and the phone layout."""
from urllib.parse import parse_qs, urlparse

import pytest

pytestmark = [pytest.mark.flow("E2E-WEB-001"), pytest.mark.severity("P3")]

EXPECTED = {"chatgpt": ("chatgpt.com", "/", True), "claude": ("claude.ai", "/new", True), "gemini": ("gemini.google.com", "/app", False),
            "perplexity": ("www.perplexity.ai", "/search", True), "grok": ("grok.com", "/", True), "deepseek": ("chat.deepseek.com", "/", False)}


def _clip(page):
    return page.evaluate("navigator.clipboard.readText()").replace(chr(13), "")  # Windows clipboard uses CRLF


def _open(page, site):
    page.context.grant_permissions(["clipboard-read", "clipboard-write"])
    page.goto(f"{site}/ask-ai-demo.html")
    page.wait_for_selector(".nai a.nai-btn")
    return page.evaluate("window.NiagarosAskAI.prompt")


def test_six_assistants_with_https_destinations_and_prefill(page, site):
    prompt = _open(page, site)
    links = page.locator(".nai a.nai-btn")
    assert links.count() == 6
    for i in range(6):
        a = links.nth(i)
        aid, href = a.get_attribute("data-assistant"), a.get_attribute("href")
        host, path, prefill = EXPECTED[aid]
        u = urlparse(href)
        assert u.scheme == "https" and u.netloc == host and u.path == path, href
        assert a.get_attribute("rel") == "noopener noreferrer" and a.get_attribute("target") == "_blank"
        if prefill:
            assert parse_qs(u.query)["q"][0] == prompt, aid  # the complete prompt, correctly encoded
            assert len(href) < 8000, (aid, len(href))  # stays under common URL limits
        else:
            assert not u.query and a.get_attribute("data-prefill") == "no"
    assert "Research Niagaros with AI" in page.locator(".nai h3").inner_text()
    assert not page.errors


def test_copy_prompt_copies_the_complete_prompt(page, site):
    prompt = _open(page, site)
    page.click(".nai button.nai-copy")
    page.wait_for_function("document.querySelector('.nai-status').textContent.includes('copied')")
    assert _clip(page) == prompt


def test_assistant_without_prefill_copies_before_opening(page, site):
    prompt = _open(page, site)
    page.evaluate("navigator.clipboard.writeText('')")
    with page.context.expect_page() as popup:
        page.click(".nai a[data-assistant=gemini]")
    popup.value.close()
    page.wait_for_function("document.querySelector('.nai-status').textContent.includes('Paste it into Gemini')")
    assert _clip(page) == prompt
    assert popup.value.url.startswith("https://gemini.google.com/app") or popup.value.url == "about:blank"


def test_failed_copy_does_not_open_an_empty_assistant(page, site):
    _open(page, site)
    page.evaluate("""() => { navigator.clipboard.writeText = () => Promise.reject(new Error('denied'));
                             window.__opened = []; window.open = (u) => { window.__opened.push(u); return null; }; }""")
    page.click(".nai a[data-assistant=deepseek]")
    page.wait_for_function("document.querySelector('.nai-status').textContent.includes('was not opened')")
    assert page.evaluate("window.__opened") == [] and page.evaluate("document.querySelector('.nai details').open")
    # The second click opens the assistant normally, so the visitor can continue after copying by hand.
    with page.context.expect_page() as popup:
        page.click(".nai a[data-assistant=deepseek]")
    assert popup.value.url.startswith("https://chat.deepseek.com") or popup.value.url == "about:blank"
    popup.value.close()


def test_prompt_uses_only_public_sources_and_demands_evidence(page, site):
    prompt = _open(page, site)
    hosts = {urlparse(w.rstrip(").,")).netloc for w in prompt.split() if w.startswith(("http", "(http"))
             for w in [w.lstrip("(")]}
    assert hosts == {"niagaros.com", "trust.niagaros.com"}
    for must in ("Distinguish implemented capabilities from announced, planned or unverified",
                 "Do not assume that a framework is certified", "Include source links",
                 "Do not invent product features"):
        assert must in prompt
    assert "app.niagaros.com" not in prompt  # no authenticated routes
    note = page.locator(".nai-note").inner_text()
    assert "third-party" in note and "not an official Niagaros assessment" in note
    # The full prompt is readable on the page for anyone who cannot use the clipboard.
    page.click(".nai summary")
    assert page.locator(".nai pre").inner_text().strip() == prompt.strip()


def test_phone_and_tablet_layout(page, site):
    for width in (360, 768):
        page.set_viewport_size({"width": width, "height": 800})
        _open(page, site)
        assert page.evaluate("document.documentElement.scrollWidth") <= width + 2, width
        assert all(b["height"] >= 40 for b in page.locator(".nai .nai-btn").evaluate_all("els => els.map(e => e.getBoundingClientRect())"))
    assert not page.errors


def test_renders_once_and_keeps_ids_unique_when_loaded_twice(page, site):
    _open(page, site)
    page.add_script_tag(url=f"{site}/ask-ai.js")
    page.evaluate("window.NiagarosAskAI.init()")
    assert page.locator(".nai").count() == 1 and page.locator("#nai-style").count() == 1
    page.evaluate("document.body.appendChild(Object.assign(document.createElement('div'), {}))")
    page.evaluate("document.body.lastElementChild.setAttribute('data-niagaros-ask-ai', '')")
    page.evaluate("window.NiagarosAskAI.init()")
    ids = page.locator(".nai h3").evaluate_all("els => els.map(e => e.id)")
    assert len(ids) == 2 and len(set(ids)) == 2


def test_styles_do_not_leak_into_the_host_page(page, site):
    _open(page, site)
    page.evaluate("document.body.insertAdjacentHTML('beforeend', '<p class=\"nai-note\" id=host>host</p><ul class=\"nai-list\" id=hl></ul>')")
    assert page.evaluate("getComputedStyle(document.getElementById('host')).opacity") == "1"
    assert page.evaluate("getComputedStyle(document.getElementById('hl')).display") != "flex"


def test_keyboard_focus_is_visible(page, site):
    _open(page, site)
    page.focus(".nai button.nai-copy")
    page.keyboard.press("Shift+Tab"); page.keyboard.press("Tab")
    assert page.evaluate("getComputedStyle(document.querySelector('.nai button.nai-copy')).outlineStyle") == "solid"
