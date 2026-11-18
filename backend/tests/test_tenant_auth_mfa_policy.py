"""
Organization MFA policy enforced by the API (#291): tenant_auth.guard refuses a caller whose organization requires
two-step verification when Cognito reports no authenticator app for that token. Real PostgreSQL, fake Cognito.
Needs NIAGAROS_PGTEST_DSN (see test_governance_handler.py).
"""
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND / "src"))
psycopg2 = pytest.importorskip("psycopg2")
DSN = os.environ.get("NIAGAROS_PGTEST_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="blocked: set NIAGAROS_PGTEST_DSN to a throwaway PostgreSQL")

from collectors.aws.scanner import tenant_auth as TA  # noqa: E402


@pytest.fixture(scope="module")
def conn():
    name = f"mfa_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    c = psycopg2.connect(DSN.rsplit("/", 1)[0] + "/" + name)
    c.autocommit = True
    c.cursor().execute((BACKEND / "tests/fixtures/ciem_schema.sql").read_text(encoding="utf-8"))
    c.cursor().execute("""CREATE TABLE organizations (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT, owner_email TEXT,
                                                      mfa_required BOOLEAN DEFAULT false);
                          CREATE TABLE users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT, organization_id UUID, role TEXT,
                                              status TEXT DEFAULT 'active');
                          CREATE TABLE business_units (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), organization_id UUID, name TEXT);
                          CREATE TABLE bu_accounts (business_unit_id UUID, cloud_account_id UUID);
                          CREATE TABLE org_members (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), organization_id UUID, email TEXT, role TEXT,
                                                    business_unit_id UUID);
                          CREATE TABLE security_audit_log (id UUID DEFAULT gen_random_uuid(), event_type TEXT, actor_email TEXT,
                                                           cloud_account_ids UUID[], http_method TEXT, path TEXT, source_ip TEXT, detail JSONB);""")
    cur = c.cursor()
    cur.execute("INSERT INTO organizations (name, mfa_required) VALUES ('Strict', true) RETURNING id")
    strict = cur.fetchone()[0]
    cur.execute("INSERT INTO organizations (name, mfa_required) VALUES ('Relaxed', false) RETURNING id")
    relaxed = cur.fetchone()[0]
    cur.execute("INSERT INTO users (email, organization_id, role) VALUES ('a@strict.test', %s, 'admin'), ('b@relaxed.test', %s, 'admin')",
                (strict, relaxed))
    cur.execute("INSERT INTO cloud_accounts (owner_email, account_id) VALUES ('a@strict.test', '1'), ('b@relaxed.test', '2') RETURNING id")
    c.autocommit = False
    yield c
    c.close()
    admin.cursor().execute(f"DROP DATABASE {name} WITH (FORCE)")
    admin.close()


def run(conn, email, mfa, env=None):
    user = {"Username": "u", "UserAttributes": [{"Name": "email", "Value": email}], "UserMFASettingList": mfa}
    cog = MagicMock()
    cog.get_user.return_value = user
    event = {"httpMethod": "GET", "headers": {"Authorization": "Bearer tok"}}
    with patch.object(TA.boto3, "client", return_value=cog), patch.object(TA, "_issued_by_our_pool", return_value=True), \
            patch.dict(os.environ, env or {}, clear=False):
        r = TA.guard(event, conn, {}, {}, {})
    conn.rollback()
    return r


def test_org_requiring_mfa_refuses_callers_without_an_authenticator(conn):
    assert run(conn, "a@strict.test", []) == (403, TA.MFA_REQUIRED_MESSAGE)
    assert run(conn, "a@strict.test", ["SOFTWARE_TOKEN_MFA"]) is None


def test_other_orgs_and_users_without_org_are_unaffected(conn):
    assert run(conn, "b@relaxed.test", []) is None
    assert run(conn, "nobody@x.test", []) is None


def test_database_errors_do_not_switch_enforcement_off(conn):
    with patch.object(TA, "_org_requires_mfa", side_effect=RuntimeError("timeout")):
        with pytest.raises(RuntimeError):
            run(conn, "a@strict.test", [])


def test_missing_policy_column_means_no_policy(conn):
    with conn.cursor() as cur:
        cur.execute("ALTER TABLE organizations RENAME COLUMN mfa_required TO mfa_required_old")
    try:
        assert TA._org_requires_mfa(conn, "a@strict.test") is False
    finally:
        conn.rollback()


def test_emergency_switch(conn):
    assert run(conn, "a@strict.test", [], {"TENANT_AUTH_ENFORCE_MFA": "0"}) is None
