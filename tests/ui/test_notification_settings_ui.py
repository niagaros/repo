"""Notification Settings page — the real frontend file, driven in a real browser against a recording fake backend."""
import pytest

from ui_support import FakeBackend, open_settings

pytestmark = [pytest.mark.flow("E2E-UI-001"), pytest.mark.severity("P1")]


def test_page_structure_and_tab_switching(page, site):
    open_settings(page, site, FakeBackend())
    tabs = [t.strip() for t in page.locator(".tab").all_text_contents()]
    assert tabs[0] == "Default / Fallback" and tabs[1].startswith("People") and "Categories" in tabs and any("Analytics" in t for t in tabs)
    assert page.is_visible("#pane-channels") and not page.is_visible("#pane-people")
    page.click('.tab[data-tab="people"]')
    assert page.is_visible("#pane-people") and not page.is_visible("#pane-channels")
    assert not page.errors, page.errors


def test_explanation_card_tells_users_how_the_three_tabs_relate(page, site):
    open_settings(page, site, FakeBackend())
    text = page.locator("#pane-channels .card").first.text_content()
    assert "safety net" in text and "Categories" in text and "People" in text


def test_add_person_wizard_requires_name_then_a_channel_and_validates_input(page, site):
    backend = open_settings(page, site, FakeBackend())
    page.click('.tab[data-tab="people"]')
    page.click('button[onclick="openAddPerson()"]')
    page.click("#ap-next")  # no name yet
    assert page.is_visible("#step-1") and not backend.posts
    page.fill("#ap-label", "Jan - Security Lead")
    page.click("#ap-next")
    assert page.is_visible("#step-2")
    page.click("#ap-next")  # no channel picked
    assert "at least one channel" in page.text_content("#ap-error").lower() and not backend.posts
    page.check("#ap-use-email")
    page.fill("#ap-email", "not-an-email")
    page.click("#ap-next")
    assert "not valid" in page.text_content("#ap-error") and not backend.posts
    page.check("#ap-use-sms")
    page.fill("#ap-email", "jan@example.com")
    page.fill("#ap-sms", "0612345678")
    page.click("#ap-next")
    assert "E.164" in page.text_content("#ap-error") and not backend.posts


def test_add_person_sends_multi_channel_multi_category_payload(page, site):
    backend = open_settings(page, site, FakeBackend())
    page.click('.tab[data-tab="people"]')
    page.click('button[onclick="openAddPerson()"]')
    page.fill("#ap-label", "Jan - Security Lead")
    page.uncheck("#ap-all-domains")
    page.check('.ap-domain-cb[value="security"]')
    page.check('.ap-domain-cb[value="billing"]')
    page.click("#ap-next")
    page.check("#ap-use-email")
    page.fill("#ap-email", "jan@example.com")
    page.check("#ap-use-sms")
    page.fill("#ap-sms", "+31612345678")
    page.click("#ap-next")
    page.wait_for_selector("#recipients-body tr")
    post = next(p for p in backend.posts if p["action"] == "add_recipient")
    assert post["label"] == "Jan - Security Lead" and post["cloud_account_id"]
    assert sorted(post["domains"]) == ["billing", "security"]
    assert post["notify_email"] == "jan@example.com" and post["sms_number"] == "+31612345678"
    assert page.text_content("#people-count") == "1"
    row = page.text_content("#recipients-body tr")
    assert "Email" in row and "SMS" in row and "security" in row and "billing" in row


def test_all_categories_person_sends_empty_domain_list(page, site):
    backend = open_settings(page, site, FakeBackend())
    page.click('.tab[data-tab="people"]')
    page.click('button[onclick="openAddPerson()"]')
    page.fill("#ap-label", "Everything person")
    page.click("#ap-next")
    page.check("#ap-use-email")
    page.fill("#ap-email", "all@example.com")
    page.click("#ap-next")
    page.wait_for_selector("#recipients-body tr")
    assert next(p for p in backend.posts if p["action"] == "add_recipient")["domains"] == []
    assert "All categories" in page.text_content("#recipients-body tr")


def test_remove_asks_for_confirmation_and_only_then_deletes(page, site):
    backend = open_settings(page, site, FakeBackend(recipients=[{"id": "r1", "label": "Jan", "domains": None, "notify_email": "j@x.io"}]))
    page.click('.tab[data-tab="people"]')
    page.click("[data-remove-id]")  # dialog is dismissed by the fixture -> must NOT delete
    page.wait_for_timeout(300)
    assert page.dialogs and page.dialogs[0][0] == "confirm" and not any(p["action"] == "remove_recipient" for p in backend.posts)


@pytest.mark.flow("E2E-SEC-002")
@pytest.mark.severity("P0")
def test_recipient_name_with_script_payload_cannot_execute_javascript(page, site):
    """Regression: a name like x'); alert(1); // used to break out of the inline onclick string."""
    evil = "x'); alert(1); //"
    open_settings(page, site, FakeBackend(recipients=[{"id": "r1", "label": evil, "domains": None, "notify_email": "j@x.io"}]))
    page.click('.tab[data-tab="people"]')
    page.click("[data-remove-id]")
    page.wait_for_timeout(300)
    kinds = [k for k, _ in page.dialogs]
    assert kinds == ["confirm"], f"unexpected dialogs (script executed?): {page.dialogs}"
    assert evil in page.dialogs[0][1] and not page.errors


@pytest.mark.flow("E2E-SEC-002")
@pytest.mark.severity("P0")
def test_html_in_recipient_name_is_rendered_as_text_not_markup(page, site):
    open_settings(page, site, FakeBackend(recipients=[{"id": "r1", "label": "<img src=x onerror=alert(1)>", "domains": None, "notify_email": "j@x.io"}]))
    page.click('.tab[data-tab="people"]')
    page.wait_for_timeout(300)
    assert page.locator("#recipients-body img").count() == 0 and not page.dialogs


def test_test_button_reports_failure_and_success_honestly(page, site):
    backend = open_settings(page, site, FakeBackend(test_result={"sent": False, "reason": "connection refused"}))
    page.fill("#ch-webhook", "https://example.invalid/hook")
    page.click("button[onclick=\"testChannel('webhook','ch-webhook')\"]")
    page.wait_for_function("document.getElementById('res-webhook').textContent.includes('connection refused')")
    assert "fail" in page.get_attribute("#res-webhook", "class")
    backend.test_result = {"sent": True}
    page.click("button[onclick=\"testChannel('webhook','ch-webhook')\"]")
    page.wait_for_function("document.getElementById('res-webhook').textContent.includes('Test sent')")
    assert "ok" in page.get_attribute("#res-webhook", "class")


def test_save_channels_blocks_invalid_values_before_calling_the_api(page, site):
    backend = open_settings(page, site, FakeBackend())
    page.fill("#ch-email", "nope")
    page.fill("#ch-sms", "12345")
    page.fill("#ch-slack", "ftp://wrong")
    page.click("button[onclick=\"saveChannels()\"]")
    assert page.text_content("#err-email") and page.text_content("#err-sms") and page.text_content("#err-slack")
    assert not any(p["action"] == "update_channels" for p in backend.posts)


def test_save_channels_sends_all_channel_fields_when_valid(page, site):
    backend = open_settings(page, site, FakeBackend())
    page.fill("#ch-email", "ops@example.com")
    page.fill("#ch-sms", "+31612345678")
    page.fill("#ch-discord", "https://discord.com/api/webhooks/1/abc")
    page.click("button[onclick=\"saveChannels()\"]")
    page.wait_for_function("document.getElementById('toast').classList.contains('show')")
    post = next(p for p in backend.posts if p["action"] == "update_channels")
    assert post["notify_email"] == "ops@example.com" and post["sms_number"] == "+31612345678"
    assert post["discord_webhook_url"] == "https://discord.com/api/webhooks/1/abc"
