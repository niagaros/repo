"""
Privacy & Security (#291) against a real PostgreSQL with the real migration and a fake Cognito: status rules, step-up
(recent sign-in + PIN), PIN hashing and lockout, one-time recovery codes and the public recovery flow (generic answer,
rate limit, reuse refused), organization policy precedence, observed changes and sessions in the audit history.
Needs NIAGAROS_PGTEST_DSN (see test_governance_handler.py).
"""
import json
import os
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND / "src"))

psycopg2 = pytest.importorskip("psycopg2")
DSN = os.environ.get("NIAGAROS_PGTEST_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="blocked: set NIAGAROS_PGTEST_DSN to a throwaway PostgreSQL")

from collectors.aws.scanner import account_security_handler as H  # noqa: E402

SCHEMA = ["tests/fixtures/ciem_schema.sql", "migrations/039_account_security.sql", "migrations/039_account_security.sql"]


@pytest.fixture(scope="module")
def conn():
    name = f"acctsec_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    c = psycopg2.connect(DSN.rsplit("/", 1)[0] + "/" + name)
    c.autocommit = True
    for f in SCHEMA:
        c.cursor().execute((BACKEND / f).read_text(encoding="utf-8"))
    c.cursor().execute("""CREATE TABLE organizations (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT, mfa_required BOOLEAN DEFAULT false);
                          CREATE TABLE users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT, organization_id UUID, role TEXT, status TEXT DEFAULT 'active');""")
    c.autocommit = False
    yield c
    c.close()
    admin.cursor().execute(f"DROP DATABASE {name} WITH (FORCE)")
    admin.close()


class _NoClose:
    def __init__(self, c):
        self._c = c

    def __getattr__(self, k):
        return getattr(self._c, k)

    def close(self):
        pass


class FakeCognito:
    def __init__(self):
        self.calls = []
        self.passkeys = []

    def list_web_authn_credentials(self, AccessToken, **kw):
        return {"Credentials": self.passkeys}

    def set_user_mfa_preference(self, **kw):
        self.calls.append(("set_user_mfa_preference", kw))

    def delete_web_authn_credential(self, **kw):
        self.calls.append(("delete_web_authn_credential", kw))

    def global_sign_out(self, **kw):
        self.calls.append(("global_sign_out", kw))

    def list_users(self, UserPoolId, Filter, Limit):
        email = Filter.split('"')[1]
        if email == "alice@a.test":
            return {"Users": [{"Username": "sub-alice", "Attributes": [{"Name": "sub", "Value": "sub-alice"}]}]}
        return {"Users": []}

    def admin_set_user_mfa_preference(self, **kw):
        self.calls.append(("admin_set_user_mfa_preference", kw))

    def admin_user_global_sign_out(self, **kw):
        self.calls.append(("admin_user_global_sign_out", kw))


def who(totp=False, verified=True, auth_age=60, jti="s1"):
    now = int(time.time())
    return {"token": "t", "sub": "sub-alice", "username": "sub-alice", "email": "alice@a.test",
            "attrs": {"email_verified": "true" if verified else "false"},
            "mfa": ["SOFTWARE_TOKEN_MFA"] if totp else [], "preferred_mfa": "SOFTWARE_TOKEN_MFA" if totp else None,
            "claims": {"auth_time": now - auth_age, "exp": now + 3600, "origin_jti": jti}}


def call(conn, cog, caller, method="GET", body=None, ip="1.2.3.4"):
    event = {"httpMethod": method, "headers": {"Authorization": "Bearer t", "User-Agent": "pytest"},
             "requestContext": {"identity": {"sourceIp": ip}, "requestId": "r1"},
             "body": json.dumps(body) if body is not None else None}
    with patch.object(H, "_get_connection", return_value=_NoClose(conn)), patch.object(H, "_cognito", return_value=cog), \
            patch.object(H, "_caller", return_value=caller):
        r = H.handler(event, None)
    return r["statusCode"], json.loads(r["body"])


@pytest.fixture(scope="module")
def cog():
    return FakeCognito()


def test_status_never_protected_on_email_alone(conn, cog):
    s, b = call(conn, cog, who(verified=False))
    assert s == 200 and b["assessment"]["status"] == "action_required"
    s, b = call(conn, cog, who())
    assert b["assessment"]["status"] == "review_recommended"
    assert any("password alone is enough" in r for r in b["assessment"]["recommendations"])
    assert b["phone"]["available"] is False and "sandbox" in b["phone"]["reason"]
    assert b["sessions"][0]["current"] is True and b["sessions"][0]["ip"] == "1.2.3.4"


def test_org_policy_takes_precedence(conn, cog):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO organizations (name, mfa_required) VALUES ('Acme', true) RETURNING id")
        org = cur.fetchone()[0]
        cur.execute("INSERT INTO users (email, organization_id, role) VALUES ('alice@a.test', %s, 'viewer')", (org,))
    conn.commit()
    s, b = call(conn, cog, who())
    assert b["assessment"]["status"] == "action_required" and "Acme requires" in b["assessment"]["required"][0]
    s, b = call(conn, cog, who(totp=True), "POST", {"action": "disable_totp"})
    assert s == 403 and "requires two-step" in b["error"] and not cog.calls
    with conn.cursor() as cur:
        cur.execute("UPDATE organizations SET mfa_required = false")
    conn.commit()


def test_step_up_needs_recent_sign_in_and_is_recorded(conn, cog):
    s, b = call(conn, cog, who(auth_age=3600), "POST", {"action": "set_pin", "new_pin": "482916"})
    assert s == 403 and "sign in again" in b["error"]
    s, b = call(conn, cog, who())
    assert b["events"][0]["event"] == "step_up_required" and b["events"][0]["outcome"] == "failure"


def test_pin_is_hashed_validated_and_locks(conn, cog):
    assert call(conn, cog, who(), "POST", {"action": "set_pin", "new_pin": "111111"})[0] == 400
    assert call(conn, cog, who(), "POST", {"action": "set_pin", "new_pin": "123456"})[0] == 400
    assert call(conn, cog, who(), "POST", {"action": "set_pin", "new_pin": "482916"})[0] == 200
    with conn.cursor() as cur:
        cur.execute("SELECT pin_hash, pin_iterations FROM account_security WHERE user_sub = 'sub-alice'")
        h, it = cur.fetchone()
        assert b"482916" not in bytes(h) and it == H.PIN_ITERATIONS
    # Changing it needs the current PIN.
    assert call(conn, cog, who(), "POST", {"action": "set_pin", "new_pin": "593027", "current_pin": "000000"})[0] == 403
    for _ in range(H.PIN_MAX_FAILURES - 1):
        assert call(conn, cog, who(), "POST", {"action": "verify_pin", "pin": "000000"})[0] == 403
    s, b = call(conn, cog, who(), "POST", {"action": "verify_pin", "pin": "482916"})
    assert s == 429, "the fifth failure (counted above plus the wrong current_pin) locked it"
    s, b = call(conn, cog, who())
    assert b["pin"]["locked_until"] and "pin_locked" in [e["event"] for e in b["events"]]
    with conn.cursor() as cur:
        cur.execute("UPDATE account_security SET pin_locked_until = NULL, pin_failed = 0")
    conn.commit()
    assert call(conn, cog, who(), "POST", {"action": "verify_pin", "pin": "482916"})[0] == 200


def test_recovery_codes_and_public_recovery(conn, cog):
    assert call(conn, cog, who(totp=True), "POST", {"action": "generate_recovery_codes"})[0] == 403  # PIN missing
    s, b = call(conn, cog, who(totp=True), "POST", {"action": "generate_recovery_codes", "pin": "482916"})
    codes = b["codes"]
    assert s == 200 and len(codes) == 10 and all(H.CODE_RE.match(c) for c in codes)
    s, ov = call(conn, cog, who(totp=True))
    assert ov["recovery_codes"]["remaining"] == 10 and ov["assessment"]["status"] == "protected"
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM account_recovery_codes WHERE code_hash::text LIKE %s", ("%" + codes[0] + "%",))
        assert cur.fetchone()[0] == 0
    # Wrong code and unknown email get the same answer.
    a = call(conn, cog, None, "POST", {"action": "recover", "email": "alice@a.test", "code": "AAAA-AAAA"}, ip="9.9.9.1")
    b2 = call(conn, cog, None, "POST", {"action": "recover", "email": "nobody@x.test", "code": codes[0]}, ip="9.9.9.1")
    assert a == b2 == (200, {"message": H.GENERIC_RECOVERY}) and not cog.calls
    s, out = call(conn, cog, None, "POST", {"action": "recover", "email": "Alice@A.test", "code": codes[0].lower()}, ip="9.9.9.2")
    assert s == 200 and [c[0] for c in cog.calls] == ["admin_user_global_sign_out", "admin_set_user_mfa_preference"]
    cog.calls.clear()
    call(conn, cog, None, "POST", {"action": "recover", "email": "alice@a.test", "code": codes[0]}, ip="9.9.9.3")
    assert not cog.calls, "a used code cannot be used again"
    s, ov = call(conn, cog, who(totp=True))
    assert ov["recovery_codes"]["remaining"] == 9 and "recovery_code_used" in [e["event"] for e in ov["events"]]


def test_recovery_is_rate_limited_without_letting_strangers_block_it(conn, cog):
    for _ in range(H.RECOVERY_LIMIT_PER_EMAIL_IP_HOUR):
        call(conn, cog, None, "POST", {"action": "recover", "email": "bob@b.test", "code": "AAAA-AAAA"}, ip="8.8.8.8")
    s, _ = call(conn, cog, None, "POST", {"action": "recover", "email": "bob@b.test", "code": "AAAA-AAAA"}, ip="8.8.8.8")
    assert s == 429, "same address keeps guessing"
    s, _ = call(conn, cog, None, "POST", {"action": "recover", "email": "bob@b.test", "code": "AAAA-AAAA"}, ip="7.7.7.7")
    assert s == 200, "the real owner, from another address, is not locked out by those failures"


def test_recovery_also_clears_a_forgotten_pin(conn, cog):
    s, b = call(conn, cog, who(totp=True), "POST", {"action": "generate_recovery_codes", "pin": "482916"})
    code = b["codes"][0]
    call(conn, cog, None, "POST", {"action": "recover", "email": "alice@a.test", "code": code}, ip="6.6.6.6")
    s, ov = call(conn, cog, who())
    assert ov["pin"]["set"] is False
    assert call(conn, cog, who(), "POST", {"action": "set_pin", "new_pin": "482916"})[0] == 200


def test_observed_changes_and_sign_out_everywhere(conn, cog):
    call(conn, cog, who(totp=True))
    s, b = call(conn, cog, who(totp=False))
    assert b["events"][0]["event"] == "authenticator_app_changed" and b["events"][0]["outcome"] == "observed"
    s, b = call(conn, cog, who(jti="s2"))
    assert len(b["sessions"]) == 2
    s, b = call(conn, cog, who(), "POST", {"action": "sign_out_everywhere", "pin": "482916"})
    assert s == 200 and cog.calls[-1][0] == "global_sign_out"
    with conn.cursor() as cur:
        cur.execute("SELECT has_table_privilege('cspm_lambda', 'account_security_events', 'UPDATE')")
        assert cur.fetchone()[0] is False


def test_passkey_removal_respects_policy(conn, cog):
    cog.passkeys = [{"CredentialId": "cred-1", "FriendlyCredentialName": "Laptop"}]
    with conn.cursor() as cur:
        cur.execute("UPDATE organizations SET mfa_required = true")
    conn.commit()
    s, b = call(conn, cog, who(), "POST", {"action": "delete_passkey", "credential_id": "cred-1", "pin": "482916"})
    assert s == 403 and "only second factor" in b["error"]
    s, b = call(conn, cog, who(totp=True), "POST", {"action": "delete_passkey", "credential_id": "cred-1", "pin": "482916"})
    assert s == 200 and cog.calls[-1][0] == "delete_web_authn_credential"


def test_a_passkey_alone_does_not_count_as_protected(conn, cog):
    a = H.assess(True, False, True, 10, None)
    assert a["status"] == "review_recommended" and "password alone" in a["recommendations"][0]
    assert H.assess(True, True, True, 10, None)["status"] == "protected"


def test_replaced_passkey_is_noticed_and_step_up_is_checked_at_click_time(conn, cog):
    cog.passkeys = [{"CredentialId": "cred-A"}]
    call(conn, cog, who(totp=True))
    cog.passkeys = [{"CredentialId": "cred-B"}]
    s, b = call(conn, cog, who(totp=True))
    ev = [e for e in b["events"] if e["event"] == "passkeys_changed"][0]
    assert ev["detail"] == {"added": 1, "removed": 1, "now": 1}
    assert call(conn, cog, who(auth_age=3600), "POST", {"action": "confirm_step_up", "purpose": "passkey"})[0] == 403
    assert call(conn, cog, who(), "POST", {"action": "confirm_step_up", "purpose": "passkey"})[0] == 403, "PIN is set: needed too"
    assert call(conn, cog, who(), "POST", {"action": "confirm_step_up", "purpose": "passkey", "pin": "482916"})[0] == 200


def test_unauthenticated_requests_are_refused(conn, cog):
    s, _ = call(conn, cog, None)
    assert s == 401
    s, _ = call(conn, cog, None, "POST", {"action": "set_pin", "new_pin": "482916"})
    assert s == 401
