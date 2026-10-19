"""
CIEM storage (finding lifecycle across scans) and API (tenant isolation, validation, reviews, exports) against a
real PostgreSQL with the real migrations. Needs NIAGAROS_PGTEST_DSN (see test_governance_handler.py).
"""
import json
import os
import sys
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND / "src"))

psycopg2 = pytest.importorskip("psycopg2")
DSN = os.environ.get("NIAGAROS_PGTEST_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="blocked: set NIAGAROS_PGTEST_DSN to a throwaway PostgreSQL")

SCHEMA = ["tests/fixtures/ciem_schema.sql", "migrations/024_security_audit_log.sql", "migrations/026_enterprise.sql",
          "migrations/032_ciem.sql", "migrations/032_ciem.sql"]  # 032 twice: must be re-runnable
ACCT_AWS = "111122223333"
NOW = datetime.now(timezone.utc)


@pytest.fixture(scope="module")
def conn():
    name = f"ciem_test_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    c = psycopg2.connect(DSN.rsplit("/", 1)[0] + "/" + name)
    c.autocommit = True
    for f in SCHEMA:
        c.cursor().execute((BACKEND / f).read_text(encoding="utf-8"))
    c.autocommit = False
    yield c
    c.close()
    admin.cursor().execute(f"DROP DATABASE {name} WITH (FORCE)")
    admin.close()


@pytest.fixture(scope="module")
def accounts(conn):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id) VALUES ('owner@a.test', %s) RETURNING id", (ACCT_AWS,))
        a = str(cur.fetchone()[0])
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id) VALUES ('other@b.test', '444455556666') RETURNING id")
        b = str(cur.fetchone()[0])
    conn.commit()
    return {"a": a, "b": b}


def _raw(drop_vendor=False, admin_user=True):
    admin_doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    pol = {"Arn": "arn:aws:iam::aws:policy/AdministratorAccess", "name": "AdministratorAccess", "document": admin_doc, "aws_managed": True}
    roles = [{"RoleName": "vendor", "Arn": f"arn:aws:iam::{ACCT_AWS}:role/vendor", "Path": "/", "CreateDate": NOW - timedelta(days=500),
              "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}]},
              "AttachedManagedPolicies": [], "RolePolicyList": [{"PolicyName": "inline-read", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}}], "Tags": []}]
    users = [{"UserName": "alice", "Arn": f"arn:aws:iam::{ACCT_AWS}:user/alice", "Path": "/", "CreateDate": NOW - timedelta(days=500),
              "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": pol["Arn"]}] if admin_user else [],
              "UserPolicyList": [], "GroupList": [], "Tags": []}]
    return {"policies": [pol], "users": users, "groups": [], "roles": [] if drop_vendor else roles,
            "credential_report": {"alice": {"password_enabled": True, "mfa_active": True, "keys": [], "access_keys_active": False}},
            "root": None, "access_advisor": {}, "external_access": [], "limitations": [],
            "coverage": {"authorization": {"ok": True}}}


def _scan(conn, account, raw, complete=True, resolvable=None, settings=None):
    from collectors.aws.scanner import ciem_engine, ciem_scanner_handler as h
    with conn.cursor() as cur:
        cur.execute("INSERT INTO ciem_scans (cloud_account_id) VALUES (%s) RETURNING id", (account,))
        sid = cur.fetchone()[0]
    conn.commit()
    ids, findings, summary = ciem_engine.analyze(raw, ACCT_AWS, 90, settings or {})
    if resolvable is None:
        resolvable = h.ALL_CATEGORIES if complete else []
    new_high, resolved = h.store(conn, account, sid, ids, findings, summary, raw, resolvable,
                                 ciem_engine.disabled_rules(settings or {}), "eu-west-1")
    with conn.cursor() as cur:
        cur.execute("UPDATE ciem_scans SET status = %s, finished_at = NOW(), summary = %s WHERE id = %s",
                    ("succeeded" if complete else "partial", json.dumps(summary, default=str), sid))
    conn.commit()
    return new_high, resolved


def _status(conn, account, rule):
    with conn.cursor() as cur:
        cur.execute("SELECT status, status_reason FROM ciem_findings WHERE cloud_account_id = %s AND rule = %s", (account, rule))
        return cur.fetchone()


# ── lifecycle ───────────────────────────────────────────────────────────────

def test_first_scan_stores_inventory_and_findings(conn, accounts):
    new_high, _ = _scan(conn, accounts["a"], _raw())
    assert {f["rule"] for f in new_high} >= {"no_permanent_admin", "external_trust_controls"}
    with conn.cursor() as cur:
        cur.execute("SELECT name, data->'policy_documents' FROM ciem_identities WHERE cloud_account_id = %s", (accounts["a"],))
        rows = dict(cur.fetchall())
    conn.rollback()
    assert set(rows) == {"alice", "vendor"}
    assert rows["vendor"]["inline-read"]["inline"] is True        # inline policy text kept for the detail view
    assert rows["alice"] == {}                                     # AWS-managed policy text not copied


def test_partial_scan_never_resolves_and_complete_scan_does(conn, accounts):
    _, resolved = _scan(conn, accounts["a"], _raw(drop_vendor=True), complete=False)
    assert resolved == 0 and _status(conn, accounts["a"], "external_trust_controls")[0] == "open"
    _, resolved = _scan(conn, accounts["a"], _raw(drop_vendor=True), complete=True)
    st = _status(conn, accounts["a"], "external_trust_controls")
    assert resolved >= 1 and st[0] == "resolved" and "re-collection" in st[1]


def test_resolved_finding_reopens_when_it_comes_back(conn, accounts):
    new_high, _ = _scan(conn, accounts["a"], _raw())
    st = _status(conn, accounts["a"], "external_trust_controls")
    assert st[0] == "open" and "Re-opened" in st[1]
    assert not any(f["rule"] == "external_trust_controls" for f in new_high)  # not 'new': no duplicate alert


def test_expired_risk_acceptance_reopens(conn, accounts):
    with conn.cursor() as cur:
        cur.execute("""UPDATE ciem_findings SET status = 'accepted', status_reason = 'vendor contract', accepted_until = CURRENT_DATE - 1
                       WHERE cloud_account_id = %s AND rule = 'external_trust_controls'""", (accounts["a"],))
    conn.commit()
    _scan(conn, accounts["a"], _raw())
    assert _status(conn, accounts["a"], "external_trust_controls")[0] == "open"


def test_missing_data_source_never_resolves_its_findings(conn, accounts):
    from collectors.aws.scanner import ciem_scanner_handler as h
    cov = {"authorization": {"ok": True}, "credential_report": {"ok": True}, "access_advisor": {"ok": True},
           "access_analyzer": {"ok": False, "error": "AccessDenied"}}
    assert "external_resource_access" not in h.resolvable_categories(cov)
    assert "external_access" in h.resolvable_categories(cov)
    assert h.resolvable_categories({"authorization": {"ok": False}}) == []
    no_cred = {**cov, "credential_report": {"ok": False}}
    assert "ownership" not in h.resolvable_categories(no_cred)   # user classification depends on it
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO ciem_findings (cloud_account_id, fingerprint, rule, category, severity, title)
                       VALUES (%s, 'aa-1', 'external_trust_controls', 'external_resource_access', 'high', 'bucket shared')""",
                    (accounts["a"],))
    conn.commit()
    _scan(conn, accounts["a"], _raw(), resolvable=h.resolvable_categories(cov))
    with conn.cursor() as cur:
        cur.execute("SELECT status FROM ciem_findings WHERE fingerprint = 'aa-1'")
        assert cur.fetchone()[0] == "open"   # Access Analyzer was not read: absence proves nothing
    conn.rollback()


def test_switching_a_rule_off_suppresses_instead_of_resolving(conn, accounts):
    off = {"external_trust_controls": {"enabled": False}}
    _scan(conn, accounts["a"], _raw(), settings=off)
    st = _status(conn, accounts["a"], "external_trust_controls")
    assert st[0] == "suppressed" and "switched off" in st[1]
    _scan(conn, accounts["a"], _raw())
    st = _status(conn, accounts["a"], "external_trust_controls")
    assert st[0] == "open" and "switched on again" in st[1]


def test_suppressed_finding_fixed_meanwhile_resolves_when_rule_returns(conn, accounts):
    off = {"external_trust_controls": {"enabled": False}}
    _scan(conn, accounts["a"], _raw(), settings=off)
    assert _status(conn, accounts["a"], "external_trust_controls")[0] == "suppressed"
    _scan(conn, accounts["a"], _raw(drop_vendor=True))          # rule back on, vendor role removed meanwhile
    assert _status(conn, accounts["a"], "external_trust_controls")[0] == "resolved"
    _scan(conn, accounts["a"], _raw())                          # restore for later tests


def test_access_analyzer_findings_resolve_only_in_their_own_region(conn, accounts):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO ciem_findings (cloud_account_id, fingerprint, rule, category, severity, title, details)
                       VALUES (%s, 'aa-us', 'external_trust_controls', 'external_resource_access', 'high', 'bucket (us)',
                               '{"region": "us-east-1"}')""", (accounts["a"],))
    conn.commit()
    _scan(conn, accounts["a"], _raw())   # a eu-west-1 scan
    with conn.cursor() as cur:
        cur.execute("SELECT status FROM ciem_findings WHERE fingerprint = 'aa-us'")
        assert cur.fetchone()[0] == "open"
    conn.rollback()


def test_expired_acceptance_reopens_even_if_not_seen_again(conn, accounts):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO ciem_findings (cloud_account_id, fingerprint, rule, category, severity, title, status,
                                                  status_reason, accepted_until)
                       VALUES (%s, 'gone-1', 'key_rotation', 'stale_credential', 'medium', 'old key', 'accepted', 'ok', CURRENT_DATE - 2)""",
                    (accounts["a"],))
    conn.commit()
    _scan(conn, accounts["a"], _raw(), resolvable=[])
    with conn.cursor() as cur:
        cur.execute("SELECT status, status_reason FROM ciem_findings WHERE fingerprint = 'gone-1'")
        assert cur.fetchone() == ("open", "Re-opened: risk acceptance expired")
    conn.rollback()


def test_accepted_requires_reason_and_end_date_in_the_database(conn, accounts):
    with conn.cursor() as cur, pytest.raises(psycopg2.errors.CheckViolation):
        cur.execute("UPDATE ciem_findings SET status = 'accepted' WHERE cloud_account_id = %s", (accounts["a"],))
    conn.rollback()


# ── API ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def api(conn):
    from collectors.aws.scanner import ciem_handler as h

    def call(email, method, qs=None, body=None):
        event = {"httpMethod": method, "path": "/ciem", "queryStringParameters": qs,
                 "body": json.dumps(body) if body is not None else None, "headers": {"Authorization": "Bearer t"}}
        with patch("collectors.aws.scanner.tenant_auth.authenticate", return_value=email), \
             patch.object(h, "authenticate", return_value=email):
            r = h.handle(event, conn)
        try:
            return r["statusCode"], json.loads(r["body"])
        except ValueError:
            return r["statusCode"], r["body"]
    return call


def test_owner_reads_every_view(api, accounts):
    a = accounts["a"]
    for view in ("overview", "identities", "findings", "paths", "external", "reviews", "settings", "audit", "scans"):
        s, b = api("owner@a.test", "GET", {"cloud_account_id": a, "view": view})
        assert s == 200, (view, b)
    s, b = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "overview"})
    assert b["latest_scan"]["status"] == "succeeded" and b["top_identities"]
    s, b = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "identity", "arn": f"arn:aws:iam::{ACCT_AWS}:user/alice"})
    assert s == 200 and b["identity"]["admin"] == "admin" and len(b["risk_history"]) >= 3


def test_another_tenant_is_refused_including_by_record_id(api, accounts, conn):
    s, _ = api("other@b.test", "GET", {"cloud_account_id": accounts["a"], "view": "findings"})
    assert s == 403
    _, b = api("owner@a.test", "GET", {"cloud_account_id": accounts["a"], "view": "findings"})
    fid = b["findings"][0]["id"]
    # other tenant names its own account but account A's finding id: the guard resolves the id to A -> refused
    s, _ = api("other@b.test", "POST", body={"cloud_account_id": accounts["b"], "action": "set_finding_status",
                                             "finding_id": fid, "status": "false_positive", "reason": "x"})
    assert s == 403
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM security_audit_log WHERE event_type = 'access_denied'")
        assert cur.fetchone()[0] >= 2
    conn.rollback()


def test_finding_status_validation_and_audit(api, accounts):
    a = accounts["a"]
    _, b = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "findings"})
    fid = next(f["id"] for f in b["findings"] if f["status"] == "open")
    base = {"cloud_account_id": a, "action": "set_finding_status", "finding_id": fid}
    assert api("owner@a.test", "POST", body={**base, "status": "accepted", "reason": "ok"})[0] == 400       # no end date
    assert api("owner@a.test", "POST", body={**base, "status": "accepted", "accepted_until": str(date.today() + timedelta(days=30))})[0] == 400  # no reason
    assert api("owner@a.test", "POST", body={**base, "status": "accepted", "reason": "x",
                                             "accepted_until": str(date.today() + timedelta(days=500))})[0] == 400  # > 1 year
    assert api("owner@a.test", "POST", body={**base, "status": "bogus"})[0] == 400
    s, _ = api("owner@a.test", "POST", body={**base, "status": "accepted", "reason": "compensating control: SCP",
                                             "accepted_until": str(date.today() + timedelta(days=30))})
    assert s == 200
    _, au = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "audit"})
    assert au["audit"][0]["action"] == "finding_status" and au["audit"][0]["details"]["to"] == "accepted"


def test_unknown_or_malformed_ids_are_404(api, accounts):
    a = accounts["a"]
    assert api("owner@a.test", "GET", {"cloud_account_id": a, "view": "finding", "finding_id": "nope"})[0] == 404
    assert api("owner@a.test", "GET", {"cloud_account_id": a, "view": "finding", "finding_id": str(uuid.uuid4())})[0] == 404
    assert api("owner@a.test", "GET", {"cloud_account_id": "not-a-uuid", "view": "overview"})[0] == 400


def test_settings_validation(api, accounts):
    a = accounts["a"]
    assert api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "save_settings", "observation_days": 45})[0] == 400
    assert api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "save_settings", "observation_days": 90,
                                             "rules": {"made_up": {"enabled": False}}})[0] == 400
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "save_settings", "observation_days": 180,
                                             "rules": {"machine_identity_owner": {"enabled": False}, "human_mfa": {"severity": "critical"}}})
    assert s == 200
    _, st = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "settings"})
    rules = {r["id"]: r for r in st["rules"]}
    assert st["observation_days"] == 180 and rules["machine_identity_owner"]["enabled"] is False and rules["human_mfa"]["severity"] == "critical"


def test_access_review_flow(api, accounts):
    a = accounts["a"]
    base = {"cloud_account_id": a, "action": "create_review", "name": "Q4 privileged review", "scope": "privileged",
            "reviewer_email": "sec@a.test", "due_date": str(date.today() + timedelta(days=14))}
    assert api("owner@a.test", "POST", body={**base, "due_date": "2020-01-01"})[0] == 400
    assert api("owner@a.test", "POST", body={**base, "reviewer_email": "nope"})[0] == 400
    with patch("collectors.aws.scanner.notification_lib.create_notification") as notify:
        s, b = api("owner@a.test", "POST", body=base)
    assert s == 200 and b["items"] >= 1 and notify.called
    rid = b["review_id"]
    _, r = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "review", "review_id": rid})
    items = r["items"]
    assert any(i["identity_name"] == "alice" for i in items)
    for it in items:
        bad = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "decide_review_item", "review_id": rid,
                                                "item_id": it["id"], "decision": "reduce"})
        assert bad[0] == 400  # needs a note
        s, d = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "decide_review_item", "review_id": rid,
                                                 "item_id": it["id"], "decision": "keep"})
        assert s == 200
    assert d["completed"] is True
    _, rv = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "reviews"})
    assert rv["reviews"][0]["status"] == "completed"


def test_export_csv_and_json_are_scoped_and_audited(api, accounts):
    a = accounts["a"]
    s, body = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "export", "what": "findings", "format": "csv"})
    assert s == 200 and body.splitlines()[0].startswith("severity,status,category")
    s, b = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "export", "what": "identities", "format": "json"})
    assert s == 200 and {r["name"] for r in b["rows"]} == {"alice", "vendor"}
    assert api("other@b.test", "GET", {"cloud_account_id": a, "view": "export", "what": "findings", "format": "csv"})[0] == 403
    _, au = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "audit"})
    assert sum(1 for x in au["audit"] if x["action"] == "export") >= 2


def test_csv_cells_cannot_become_formulas():
    from collectors.aws.scanner.ciem_handler import _csv_cell
    assert _csv_cell("=HYPERLINK(\"x\")") == "'=HYPERLINK(\"x\")"
    assert _csv_cell("+1") == "'+1" and _csv_cell("@sum") == "'@sum" and _csv_cell("normal") == "normal"
    assert _csv_cell(None) == "" and _csv_cell({"a": 1}) == '{"a": 1}'


def test_ticket_needs_an_integration_of_the_same_account(api, accounts, conn):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO workspace_integrations (cloud_account_id, provider, project, secret_name) VALUES (%s, 'jira', 'SEC', 's') RETURNING id",
                    (accounts["b"],))
        foreign = str(cur.fetchone()[0])
    conn.commit()
    _, b = api("owner@a.test", "GET", {"cloud_account_id": accounts["a"], "view": "findings"})
    fid = b["findings"][0]["id"]
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": accounts["a"], "action": "create_ticket",
                                             "finding_id": fid, "integration_id": foreign})
    assert s == 403  # guard resolves the integration to account B


def test_audit_log_is_append_only_for_the_app_role(conn):
    with conn.cursor() as cur:
        cur.execute("""SELECT privilege_type FROM information_schema.role_table_grants
                       WHERE grantee = 'cspm_lambda' AND table_name = 'ciem_audit_log' ORDER BY 1""")
        assert [r[0] for r in cur.fetchall()] == ["INSERT", "SELECT"]
    conn.rollback()
