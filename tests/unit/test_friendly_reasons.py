"""Notification delivery failures must be explained in plain language to a real customer — never raw Python/AWS
exception text (issue #279: notification center must be client-ready)."""
import pytest

from collectors.aws.scanner.notification_lib import _friendly_reason

pytestmark = [pytest.mark.flow("E2E-NOT-002"), pytest.mark.severity("P2")]


@pytest.mark.parametrize("raw,expected_phrase", [
    ("An error occurred (MessageRejected) when calling the SendEmail operation: Email address is not verified.", "not verified"),
    ("<urlopen error [Errno 111] Connection refused>", "refused"),
    ("<urlopen error [Errno -2] Name or service not known>", "resolved"),
    ("HTTP Error 404: Not Found", "not found"),
    ("HTTP Error 401: Unauthorized", "credentials"),
    ("HTTP Error 403: Forbidden", "credentials"),
    ("<urlopen error timed out>", "not respond"),
    ("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", "secure connection"),
    ("some completely unrecognised low-level error", "Double-check"),
])
def test_common_failures_are_translated_to_plain_language(raw, expected_phrase):
    msg = _friendly_reason(Exception(raw))
    assert expected_phrase.lower() in msg.lower()
    assert "Traceback" not in msg and "Errno" not in msg and "urlopen" not in msg
