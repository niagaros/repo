"""
Tests for api/governance_handler.py — onboarding steps 5, 6 and 7 (#270, #281, #282).

These run the real SQL against a real PostgreSQL, because most of what can go
wrong here (organization scoping, separation-of-duties constraints, version
history) lives in the queries. A throwaway database is created per run from
tests/fixtures/base_schema.sql plus the real migrations, and dropped again.

    docker run -d --rm --name niagaros-pgtest -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16
    set NIAGAROS_PGTEST_DSN=postgresql://postgres:test@localhost:55432/postgres
    python -m pytest tests/test_governance_handler.py      (from backend/)

Without NIAGAROS_PGTEST_DSN the module is skipped (reported, not passed).
"""
import base64
import json
import os
import sys
import uuid
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND / "src"))

psycopg2 = pytest.importorskip("psycopg2")
DSN = os.environ.get("NIAGAROS_PGTEST_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="blocked: set NIAGAROS_PGTEST_DSN to a throwaway PostgreSQL")

POOL = "eu-west-1_TestPool1"
SCHEMA_FILES = [
    BACKEND / "tests" / "fixtures" / "base_schema.sql",
    BACKEND / "migrations" / "002_organizations_and_team.sql",
    BACKEND / "migrations" / "003_role_changes_audit_log.sql",
    BACKEND / "migrations" / "004_mfa_policy.sql",
    BACKEND / "migrations" / "031_compliance_governance_training.sql",
]


@pytest.fixture(scope="module")
def conn():
    name = f"gov_test_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    dsn = DSN.rsplit("/", 1)[0] + "/" + name
    c = psycopg2.connect(dsn)
    c.autocommit = True
    for f in SCHEMA_FILES + [SCHEMA_FILES[-1]]:  # 031 twice: the migration must be re-runnable
        c.cursor().execute(f.read_text(encoding="utf-8"))
    c.autocommit = False
    yield c
    c.close()
    admin.cursor().execute(f"DROP DATABASE {name}")
    admin.close()


@pytest.fixture(scope="module")
def db(conn):
    from config.database import Database
    d = Database.__new__(Database)
    d.conn = conn
    return d


def _user(conn, email, role="admin", org=None):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO users (cognito_sub, email) VALUES (%s, %s) RETURNING id, organization_id",
                    (uuid.uuid4().hex, email))
        uid, own_org = cur.fetchone()
        if org:
            cur.execute("UPDATE users SET organization_id = %s, role = %s WHERE id = %s", (org, role, uid))
        else:
            cur.execute("UPDATE users SET role = %s WHERE id = %s", (role, uid))
    conn.commit()
    return {"id": str(uid), "email": email, "org": str(org or own_org)}


@pytest.fixture(scope="module")
def team(conn):
    admin = _user(conn, "admin@a.test")
    org = admin["org"]
    return {
        "admin": admin,
        "admin2": _user(conn, "admin2@a.test", "admin", org),
        "compliance": _user(conn, "comp@a.test", "compliance", org),
        "viewer": _user(conn, "viewer@a.test", "viewer", org),
        "outsider": _user(conn, "boss@b.test"),  # admin of another organization
    }


def _token(email, pool=POOL, token_use="access"):
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    claims = {"iss": f"https://cognito-idp.eu-west-1.amazonaws.com/{pool}", "token_use": token_use,
              "test_email": email}
    return f"{seg({'alg': 'none'})}.{seg(claims)}.sig"


@pytest.fixture
def call(db):
    from api import governance_handler as gh

    def fake_caller(event, d):
        # Stands in for Cognito GetUser: the email comes from the (already pool-checked) token.
        auth = (event.get("headers") or {}).get("authorization", "")
        payload = auth[7:].split(".")[1]
        email = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["test_email"]
        user = d.get_user_by_email(email)
        return user if user and user["status"] == "active" else None

    def _call(who, method, path, body=None, token=None):
        event = {
            "rawPath": "/default" + path,
            "requestContext": {"stage": "default", "http": {"method": method}},
            "headers": {"authorization": "Bearer " + (token or _token(who["email"]))},
            "body": json.dumps(body) if body is not None else None,
        }
        with patch.object(gh, "_get_caller", fake_caller), patch.dict(os.environ, {"COGNITO_USER_POOL_ID": POOL}):
            r = gh.handle(event, db)
        return r["statusCode"], json.loads(r["body"])

    return _call


# ── authentication / routing ─────────────────────────────────────────────

def test_token_from_another_user_pool_is_rejected(call, team):
    s, b = call(team["admin"], "GET", "/compliance", token=_token("admin@a.test", pool="eu-west-1_Attacker1"))
    assert s == 401


def test_id_token_instead_of_access_token_is_rejected(call, team):
    s, _ = call(team["admin"], "GET", "/compliance", token=_token("admin@a.test", token_use="id"))
    assert s == 401


def test_missing_pool_configuration_fails_closed(db, team):
    from api import governance_handler as gh
    event = {"rawPath": "/default/compliance", "requestContext": {"stage": "default", "http": {"method": "GET"}},
             "headers": {"authorization": "Bearer " + _token("admin@a.test")}}
    with patch.dict(os.environ, {"COGNITO_USER_POOL_ID": ""}):
        assert gh.handle(event, db)["statusCode"] == 401


def test_unknown_route_is_404(call, team):
    s, _ = call(team["admin"], "GET", "/governance/nothing-here")
    assert s == 404


# ── step 5: compliance ───────────────────────────────────────────────────

def test_compliance_starts_empty_with_the_real_framework_catalog(call, team):
    from config.database import MAPPED_FRAMEWORK_NAMES
    s, b = call(team["viewer"], "GET", "/compliance")
    assert s == 200 and b["step_complete"] is False and b["frameworks"] == []
    assert set(b["catalog"]) == set(MAPPED_FRAMEWORK_NAMES) and b["can_edit"] is False


def test_viewer_cannot_change_frameworks(call, team):
    s, b = call(team["viewer"], "POST", "/compliance/frameworks", {"framework_name": "SOC2"})
    assert s == 403


def test_only_frameworks_niagaros_can_check_are_accepted(call, team):
    s, b = call(team["admin"], "POST", "/compliance/frameworks", {"framework_name": "Made Up Framework"})
    assert s == 400


def test_framework_owner_must_be_a_team_member(call, team):
    s, b = call(team["admin"], "POST", "/compliance/frameworks",
                {"framework_name": "SOC2", "owner_email": "boss@b.test"})
    assert s == 400 and "member" in b["error"]


def test_dates_are_validated(call, team):
    s, _ = call(team["admin"], "POST", "/compliance/frameworks",
                {"framework_name": "SOC2", "effective_date": "2026-05-01", "expiration_date": "2026-01-01"})
    assert s == 400


def test_enabling_a_framework_completes_step_5_and_is_audited(call, team, conn):
    s, b = call(team["compliance"], "POST", "/compliance/frameworks", {
        "framework_name": "ISO 27001:2022", "enabled": True, "version": "2022", "owner_email": "COMP@a.test",
        "certification_status": "in_progress", "effective_date": "2026-01-01", "expiration_date": "2027-01-01"})
    assert s == 200 and b["step_complete"] is True and b["framework"]["owner_email"] == "comp@a.test"
    s, b = call(team["compliance"], "POST", "/compliance/frameworks",
                {"framework_name": "ISO 27001:2022", "enabled": True, "certification_status": "certified"})
    assert s == 200
    _, g = call(team["admin"], "GET", "/governance")
    saved = [a for a in g["audit"] if a["action"] == "compliance_framework_saved"]
    assert saved[0]["details"]["previous"]["certification_status"] == "in_progress"
    assert saved[0]["details"]["new"]["certification_status"] == "certified"


def test_certifications_add_list_and_remove_within_the_organization_only(call, team):
    s, b = call(team["admin"], "POST", "/compliance/certifications", {
        "name": "ISO 27001 certificate", "standard": "ISO 27001:2022", "certification_body": "BSI",
        "issue_date": str(date.today()), "expiration_date": str(date.today() + timedelta(days=10))})
    assert s == 201
    cert_id = b["id"]
    _, c = call(team["viewer"], "GET", "/compliance")
    assert c["certifications"][0]["expires_in_days"] == 10
    s, _ = call(team["outsider"], "DELETE", f"/compliance/certifications/{cert_id}")
    assert s == 404
    s, _ = call(team["admin"], "DELETE", f"/compliance/certifications/{cert_id}")
    assert s == 200
    s, _ = call(team["admin"], "DELETE", "/compliance/certifications/not-a-uuid")
    assert s == 404


def test_another_organization_sees_none_of_this(call, team):
    _, b = call(team["outsider"], "GET", "/compliance")
    assert b["frameworks"] == [] and b["step_complete"] is False


# ── step 6: governance ───────────────────────────────────────────────────

POLICY = {"name": "Access Control Policy", "category": "Access Control", "owner_email": "comp@a.test",
          "approver_email": "admin@a.test", "content": "All access is least-privilege and reviewed quarterly.",
          "review_date": str(date.today() + timedelta(days=200))}


@pytest.fixture(scope="module")
def policy_id(db, team):
    return {}


def test_policy_approver_cannot_be_its_author(call, team):
    s, b = call(team["admin"], "POST", "/governance/policies", POLICY)
    assert s == 400 and "approve" in b["error"]


def test_viewer_cannot_write_policies(call, team):
    s, _ = call(team["viewer"], "POST", "/governance/policies", POLICY)
    assert s == 403


def test_policy_lifecycle_with_separation_of_duties(call, team, policy_id):
    s, b = call(team["compliance"], "POST", "/governance/policies", POLICY)
    assert s == 201
    pid = policy_id["id"] = b["id"]
    s, _ = call(team["compliance"], "POST", "/governance/policies", POLICY)
    assert s == 409  # duplicate name

    _, g = call(team["viewer"], "GET", "/governance")
    assert g["step_complete"] is False  # nothing published until approved

    s, _ = call(team["compliance"], "POST", f"/governance/policies/{pid}/decision", {"approve": True, "version": 1})
    assert s == 403  # not the approver, and the author anyway
    s, _ = call(team["viewer"], "POST", f"/governance/policies/{pid}/decision", {"approve": True, "version": 1})
    assert s == 403
    s, _ = call(team["outsider"], "POST", f"/governance/policies/{pid}/decision", {"approve": True, "version": 1})
    assert s == 404  # another organization cannot even see it
    s, _ = call(team["admin"], "POST", f"/governance/policies/{pid}/decision", {"approve": True})
    assert s == 400  # must say which version was reviewed
    s, b = call(team["admin"], "POST", f"/governance/policies/{pid}/decision", {"approve": True, "version": 1})
    assert s == 200 and b["status"] == "approved"

    _, g = call(team["viewer"], "GET", "/governance")
    p = next(x for x in g["policies"] if x["id"] == pid)
    assert g["step_complete"] is True and p["published_version"] == 1
    assert p["versions"][0]["author_email"] == "comp@a.test" and p["versions"][0]["decided_by_email"] == "admin@a.test"


def test_new_version_keeps_history_and_needs_its_own_approval(call, team, policy_id):
    pid = policy_id["id"]
    s, b = call(team["admin"], "POST", f"/governance/policies/{pid}/versions",
                {"content": "Access is least-privilege, reviewed monthly.", "change_summary": "Monthly reviews"})
    assert s == 201 and b["version"] == 2
    s, _ = call(team["admin"], "POST", f"/governance/policies/{pid}/versions",
                {"content": "x", "change_summary": "y"})
    assert s == 409  # one pending version at a time
    s, _ = call(team["admin"], "POST", f"/governance/policies/{pid}/decision", {"approve": True, "version": 2})
    assert s == 403  # admin wrote v2, so the named approver (admin) is blocked for this version
    s, b = call(team["admin2"], "POST", f"/governance/policies/{pid}/decision", {"approve": False, "version": 2})
    assert s == 400  # a rejection needs a reason
    s, b = call(team["admin2"], "POST", f"/governance/policies/{pid}/decision", {"approve": True, "version": 1})
    assert s == 409  # a stale screen (reviewed v1) can never publish the newer, unread v2
    s, b = call(team["admin2"], "POST", f"/governance/policies/{pid}/decision",
                {"approve": True, "note": "ok", "version": 2})
    assert s == 200
    _, g = call(team["viewer"], "GET", "/governance")
    p = next(x for x in g["policies"] if x["id"] == pid)
    assert p["published_version"] == 2 and [v["version"] for v in p["versions"]] == [2, 1]
    assert p["versions"][1]["content"].startswith("All access")  # v1 text preserved


def test_a_failed_audit_write_rolls_the_change_back(call, team, conn):
    from api import governance_handler as gh
    real = gh._audit

    def broken(*a, **k):
        real(*a, **k)
        raise RuntimeError("audit store down")

    with patch.object(gh, "_audit", broken), pytest.raises(RuntimeError):
        call(team["admin"], "POST", "/compliance/certifications", {"name": "Ghost cert", "standard": "SOC2"})
    conn.rollback()  # what lambda_handler does implicitly by closing the connection
    _, c = call(team["admin"], "GET", "/compliance")
    assert all(x["name"] != "Ghost cert" for x in c["certifications"])


def test_database_itself_refuses_self_approval(conn, team, policy_id):
    with conn.cursor() as cur, pytest.raises(psycopg2.errors.CheckViolation):
        cur.execute("""UPDATE governance_policy_versions SET decided_by = author_id
                       WHERE policy_id = %s AND version = 1""", (policy_id["id"],))
    conn.rollback()


# ── exceptions ───────────────────────────────────────────────────────────

def _exception(**over):
    body = {"requirement": "MFA for break-glass account", "justification": "Hardware token on order",
            "risk": "medium", "owner_email": "comp@a.test",
            "expiration_date": str(date.today() + timedelta(days=30))}
    body.update(over)
    return body


def test_exception_requires_justification_risk_owner_and_end_date(call, team):
    for missing in ("justification", "risk", "owner_email", "expiration_date"):
        body = _exception()
        body.pop(missing)
        s, _ = call(team["compliance"], "POST", "/governance/exceptions", body)
        assert s == 400, missing
    s, _ = call(team["compliance"], "POST", "/governance/exceptions",
                _exception(expiration_date=str(date.today() + timedelta(days=400))))
    assert s == 400


def test_exception_approval_and_revocation(call, team, policy_id):
    s, b = call(team["admin"], "POST", "/governance/exceptions", _exception(policy_id=policy_id["id"]))
    assert s == 201
    eid = b["id"]
    s, _ = call(team["admin"], "POST", f"/governance/exceptions/{eid}/decision", {"approve": True})
    assert s == 403  # requester cannot approve their own exception
    s, _ = call(team["compliance"], "POST", f"/governance/exceptions/{eid}/decision", {"approve": True})
    assert s == 403  # only admins decide
    s, _ = call(team["admin2"], "POST", f"/governance/exceptions/{eid}/decision", {"approve": True})
    assert s == 200
    _, g = call(team["viewer"], "GET", "/governance")
    e = next(x for x in g["exceptions"] if x["id"] == eid)
    assert e["active"] is True and e["policy_name"] == "Access Control Policy"
    s, _ = call(team["admin2"], "POST", f"/governance/exceptions/{eid}/revoke", {})
    assert s == 400  # reason required
    s, _ = call(team["admin2"], "POST", f"/governance/exceptions/{eid}/revoke", {"note": "Token arrived"})
    assert s == 200
    _, g = call(team["viewer"], "GET", "/governance")
    assert next(x for x in g["exceptions"] if x["id"] == eid)["active"] is False


def test_expired_exception_is_not_active(call, team, conn):
    s, b = call(team["compliance"], "POST", "/governance/exceptions", _exception())
    eid = b["id"]
    call(team["admin"], "POST", f"/governance/exceptions/{eid}/decision", {"approve": True})
    with conn.cursor() as cur:
        cur.execute("""UPDATE governance_exceptions SET start_date = CURRENT_DATE - 10,
                       expiration_date = CURRENT_DATE - 1 WHERE id = %s""", (eid,))
    conn.commit()
    _, g = call(team["viewer"], "GET", "/governance")
    e = next(x for x in g["exceptions"] if x["id"] == eid)
    assert e["status"] == "approved" and e["expired"] is True and e["active"] is False


# ── step 7: training ─────────────────────────────────────────────────────

def test_training_is_complete_only_when_everyone_acknowledged_the_current_version(call, team, policy_id):
    pid = policy_id["id"]
    _, t = call(team["viewer"], "GET", "/training")
    assert t["step_complete"] is False and t["progress"] is None  # viewers don't see others' progress
    item = next(p for p in t["policies"] if p["policy_id"] == pid)
    assert item["version"] == 2 and item["acknowledged_by_me"] is False

    s, _ = call(team["viewer"], "POST", "/training/acknowledge", {"policy_id": pid, "version": 1})
    assert s == 409  # old version
    s, _ = call(team["outsider"], "POST", "/training/acknowledge", {"policy_id": pid, "version": 2})
    assert s == 404
    for who in ("admin", "admin2", "compliance"):
        s, b = call(team[who], "POST", "/training/acknowledge", {"policy_id": pid, "version": 2})
        assert s == 200 and b["step_complete"] is False
    s, b = call(team["viewer"], "POST", "/training/acknowledge", {"policy_id": pid, "version": 2})
    assert s == 200 and b["step_complete"] is True
    s, b = call(team["viewer"], "POST", "/training/acknowledge", {"policy_id": pid, "version": 2})
    assert s == 200  # idempotent

    _, t = call(team["admin"], "GET", "/training")
    assert all(p["done"] == p["total"] == 1 for p in t["progress"])


def test_a_new_published_version_reopens_training(call, team, policy_id):
    pid = policy_id["id"]
    call(team["compliance"], "POST", f"/governance/policies/{pid}/versions",
         {"content": "v3 text", "change_summary": "v3"})
    s, _ = call(team["admin"], "POST", f"/governance/policies/{pid}/decision", {"approve": True, "version": 3})
    assert s == 200
    _, t = call(team["admin"], "GET", "/training")
    assert t["step_complete"] is False and t["policies"][0]["version"] == 3


def test_retiring_the_only_policy_reopens_step_6(call, team, policy_id):
    s, _ = call(team["compliance"], "POST", f"/governance/policies/{policy_id['id']}/retire")
    assert s == 403
    s, _ = call(team["admin"], "POST", f"/governance/policies/{policy_id['id']}/retire")
    assert s == 200
    _, g = call(team["viewer"], "GET", "/governance")
    assert g["step_complete"] is False


def test_deactivated_member_loses_access(call, team, conn):
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET status = 'deactivated' WHERE id = %s", (team["viewer"]["id"],))
    conn.commit()
    s, _ = call(team["viewer"], "GET", "/governance")
    assert s == 401
