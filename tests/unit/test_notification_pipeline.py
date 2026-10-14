"""Notification delivery logic — routing, failure reporting, admin gating (no third-party network calls)."""
import pytest

from collectors.aws.scanner import notification_lib as nl

pytestmark = [pytest.mark.flow("E2E-NOT-002"), pytest.mark.severity("P1")]


@pytest.fixture
def spy(monkeypatch):
    calls = []
    monkeypatch.setattr(nl, "_send_email", lambda *a, **k: calls.append(("email", a)) or {"sent": True})
    monkeypatch.setattr(nl, "_send_sms", lambda *a, **k: calls.append(("sms", a)) or {"sent": True})
    monkeypatch.setattr(nl, "_post_webhook", lambda url, payload: calls.append(("webhook", url, payload)) or {"sent": True})
    return calls


def _dispatch(channel, target="t"):
    return nl.dispatch_to_channel(channel, target, "Title", "Desc", "CRITICAL", "security", "nid-1", "evt", None)


def test_email_channel_routes_to_email_sender(spy):
    assert _dispatch("email", "a@b.co")["sent"] is True
    assert spy[0][0] == "email"


def test_sms_channel_routes_to_sms_sender(spy):
    _dispatch("sms", "+31612345678")
    assert spy[0][0] == "sms"


@pytest.mark.parametrize("channel", ["slack", "teams", "discord", "webhook"])
def test_webhook_family_posts_to_the_given_url(spy, channel):
    _dispatch(channel, "https://example.invalid/hook")
    kind, url, payload = spy[0]
    assert kind == "webhook" and url == "https://example.invalid/hook" and isinstance(payload, dict)


def test_slack_payload_contains_severity_and_title(spy):
    _dispatch("slack", "https://x.invalid")
    assert "[CRITICAL] Title" in spy[0][2]["text"]


def test_discord_uses_embed_format_with_severity_colour(spy):
    _dispatch("discord", "https://x.invalid")
    embed = spy[0][2]["embeds"][0]
    assert embed["title"] == "[CRITICAL] Title" and isinstance(embed["color"], int)


def test_generic_webhook_carries_full_event_context(spy):
    _dispatch("webhook", "https://x.invalid")
    assert {"id", "domain", "event_type", "severity", "title"} <= set(spy[0][2])


def test_unknown_channel_is_reported_not_raised():
    r = _dispatch("carrier-pigeon")
    assert r["sent"] is False and "unknown channel" in r["reason"]


def test_unreachable_webhook_reports_failure_instead_of_crashing():
    """External integration fails -> the failure is detected and reported (issue #279)."""
    r = nl._post_webhook("http://127.0.0.1:9/nothing-listens-here", {"x": 1})
    assert r["sent"] is False and r["reason"]


def test_admin_check_is_false_without_credentials():
    assert nl.is_admin_caller({"headers": {}}) is False
    assert nl.is_admin_caller({"headers": {"Authorization": "Bearer "}}) is False
    assert nl.is_admin_caller(None) is False
