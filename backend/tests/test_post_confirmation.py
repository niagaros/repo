"""
Tests for auth/post_confirmation.py (Cognito PostConfirmation trigger) against a real PostgreSQL —
same throwaway-database setup as test_governance_handler.py (needs NIAGAROS_PGTEST_DSN).
"""
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND / "src"))

psycopg2 = pytest.importorskip("psycopg2")
DSN = os.environ.get("NIAGAROS_PGTEST_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="blocked: set NIAGAROS_PGTEST_DSN to a throwaway PostgreSQL")

SCHEMA_FILES = [
    BACKEND / "tests" / "fixtures" / "base_schema.sql",
    BACKEND / "migrations" / "002_organizations_and_team.sql",
]


@pytest.fixture(scope="module")
def dsn():
    name = f"pc_test_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    url = DSN.rsplit("/", 1)[0] + "/" + name
    c = psycopg2.connect(url)
    c.autocommit = True
    for f in SCHEMA_FILES:
        c.cursor().execute(f.read_text(encoding="utf-8"))
    c.close()
    yield url
    admin.cursor().execute(f"DROP DATABASE {name} WITH (FORCE)")
    admin.close()


def _event(sub, email, source="PostConfirmation_ConfirmSignUp", name="New Person"):
    return {"triggerSource": source, "userPoolId": "eu-west-1_x",
            "request": {"userAttributes": {"sub": sub, "email": email, "name": name, "email_verified": "true"}},
            "response": {}}


def _run(dsn, event):
    from auth import post_confirmation as pc
    with patch.object(pc, "_connect", lambda: psycopg2.connect(dsn)), patch.object(pc, "_credentials", lambda: {}):
        return pc.lambda_handler(event, None)


def _rows(dsn, sql, args=()):
    c = psycopg2.connect(dsn)
    try:
        cur = c.cursor()
        cur.execute(sql, args)
        return cur.fetchall()
    finally:
        c.close()


def test_confirmed_sign_up_creates_user_in_own_organization_as_admin(dsn):
    ev = _event("sub-1", "First@Example.test")
    assert _run(dsn, ev) is ev  # Cognito needs the event back unchanged
    rows = _rows(dsn, """SELECT u.email, u.role, u.status, o.owner_email, o.name FROM users u
                         JOIN organizations o ON o.id = u.organization_id WHERE u.cognito_sub = 'sub-1'""")
    assert rows == [("First@Example.test", "admin", "active", "First@Example.test", "New Person")]


def test_running_twice_creates_nothing_extra(dsn):
    before = _rows(dsn, "SELECT count(*) FROM organizations")[0][0]
    _run(dsn, _event("sub-1", "First@Example.test"))
    assert _rows(dsn, "SELECT count(*) FROM users WHERE cognito_sub = 'sub-1'")[0][0] == 1
    assert _rows(dsn, "SELECT count(*) FROM organizations")[0][0] == before


def test_email_of_another_identity_is_never_adopted(dsn):
    before = _rows(dsn, "SELECT count(*) FROM organizations")[0][0]
    _run(dsn, _event("sub-attacker", "first@example.TEST"))
    assert _rows(dsn, "SELECT count(*) FROM users WHERE cognito_sub = 'sub-attacker'")[0][0] == 0
    assert _rows(dsn, "SELECT count(*) FROM organizations")[0][0] == before


def test_password_reset_confirmation_does_nothing(dsn):
    _run(dsn, _event("sub-2", "reset@example.test", source="PostConfirmation_ConfirmForgotPassword"))
    assert _rows(dsn, "SELECT count(*) FROM users WHERE cognito_sub = 'sub-2'")[0][0] == 0


def test_database_failure_never_blocks_the_sign_up(dsn):
    from auth import post_confirmation as pc

    def broken():
        raise psycopg2.OperationalError("db down")

    ev = _event("sub-3", "down@example.test")
    with patch.object(pc, "_connect", broken), patch.object(pc, "_credentials", lambda: {}):
        assert pc.lambda_handler(ev, None) is ev


def test_unverified_email_is_not_provisioned(dsn):
    ev = _event("sub-4", "unverified@example.test")
    ev["request"]["userAttributes"]["email_verified"] = "false"
    assert _run(dsn, ev) is ev
    assert _rows(dsn, "SELECT count(*) FROM users WHERE cognito_sub = 'sub-4'")[0][0] == 0


def test_too_little_time_left_skips_instead_of_failing_the_sign_up(dsn):
    from auth import post_confirmation as pc

    class Ctx:
        def get_remaining_time_in_millis(self):
            return 500

    ev = _event("sub-5", "late@example.test")
    with patch.object(pc, "_connect", lambda: psycopg2.connect(dsn)), patch.object(pc, "_credentials", lambda: {}):
        assert pc.lambda_handler(ev, Ctx()) is ev
    assert _rows(dsn, "SELECT count(*) FROM users WHERE cognito_sub = 'sub-5'")[0][0] == 0


def test_missing_attributes_are_ignored(dsn):
    ev = {"triggerSource": "PostConfirmation_ConfirmSignUp", "request": {"userAttributes": {}}}
    assert _run(dsn, ev) is ev
