"""Privacy & Security (#291) rules without a database: the status never claims more than the enrolled methods and
policy support, PINs and recovery codes are hashed and checked as designed, and the step-up window is enforced."""
import hashlib
import time
from unittest.mock import MagicMock

import pytest

from collectors.aws.scanner import account_security_handler as A

pytestmark = [pytest.mark.flow("E2E-ACCTSEC-001"), pytest.mark.severity("P0")]


def test_verified_email_alone_is_never_protected():
    assert A.assess(True, False, False, 0, None)["status"] == "review_recommended"
    assert A.assess(False, True, True, 10, None)["status"] == "action_required"


def test_passkey_without_authenticator_does_not_protect_the_password_path():
    a = A.assess(True, False, True, 10, None)
    assert a["status"] == "review_recommended" and "password alone" in a["recommendations"][0]


def test_authenticator_plus_recovery_codes_is_protected():
    assert A.assess(True, True, False, 5, None)["status"] == "protected"
    assert A.assess(True, True, False, 0, None)["status"] == "review_recommended"


def test_organization_policy_takes_precedence():
    a = A.assess(True, False, True, 10, {"organization": "Acme", "mfa_required": True})
    assert a["status"] == "action_required" and "Acme requires" in a["required"][0]


def test_unknown_when_passkeys_cannot_be_read_and_nothing_else_is_known():
    assert A.assess(True, False, None, 0, None, passkeys_known=False)["status"] == "unknown"


@pytest.mark.parametrize("pin,ok", [("482916", True), ("12345678", False), ("111111", False), ("12345", False),
                                    ("abcdef", False), ("98765432", False), ("5029371", True)])
def test_pin_format(pin, ok):
    assert (A._pin_ok_format(pin) is None) is ok


def test_pin_hash_is_salted_and_slow():
    salt1, salt2 = b"a" * 16, b"b" * 16
    h1, h2 = A._hash_pin("482916", salt1), A._hash_pin("482916", salt2)
    assert h1 != h2 and b"482916" not in h1 and A.PIN_ITERATIONS >= 300_000


def test_recovery_codes_are_random_and_hashed_case_insensitively():
    codes = {A._new_code() for _ in range(200)}
    assert len(codes) == 200 and all(A.CODE_RE.match(c) for c in codes)
    salt = b"s" * 16
    assert A._hash_code("abcd-efgh", salt) == A._hash_code("ABCD-EFGH", salt) == hashlib.sha256(salt + b"ABCD-EFGH").digest()


def test_step_up_window(monkeypatch):
    monkeypatch.setattr(A, "_event", lambda *a, **k: None)
    cur = MagicMock()
    old = {"sub": "s", "email": "e", "claims": {"auth_time": int(time.time()) - 3600}}
    with pytest.raises(A.BadRequest) as e:
        A._step_up(cur, old, {}, (None, None, None), row={"pin_hash": None})
    assert e.value.status == 403 and "sign in again" in e.value.message
    fresh = {"sub": "s", "email": "e", "claims": {"auth_time": int(time.time()) - 60}}
    assert A._step_up(cur, fresh, {}, (None, None, None), row={"pin_hash": None}) == {"pin_hash": None}
