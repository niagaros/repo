"""
Zero Critical Issues (#296): lifecycle sync with the scanners, zero-critical status rules, two-person risk acceptance,
escalation, tenant isolation and export — against a real PostgreSQL with the real migration.
Needs NIAGAROS_PGTEST_DSN (see test_governance_handler.py).
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

SCHEMA = ["tests/fixtures/ciem_schema.sql", "tests/fixtures/ai_inventory_schema.sql",
          "tests/fixtures/security_agents_schema.sql", "migrations/024_security_audit_log.sql",
          "migrations/026_enterprise.sql", "migrations/032_ciem.sql", "migrations/033_ai_inventory.sql",
          "migrations/037_critical_issues.sql", "migrations/037_critical_issues.sql"]  # twice: must be re-runnable
NOW = datetime.now(timezone.utc)

from collectors.aws.scanner import critical_issues_handler as h  # noqa: E402


@pytest.fixture(scope="module")
def conn():
    name = f"crit_test_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    c = psycopg2.connect(DSN.rsplit("/", 1)[0] + "/" + name)
    c.autocommit = True
    c.cursor().execute("ALTER TABLE IF EXISTS cloud_accounts ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMP")
    for f in SCHEMA:
        c.cursor().execute((BACKEND / f).read_text(encoding="utf-8"))
    c.cursor().execute("ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMP")
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


@pytest.fixture(scope="module")
def world(conn):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id, account_name, last_scan_at) VALUES ('owner@a.test', '111122223333', 'A', NOW()) RETURNING id")
        a = str(cur.fetchone()[0])
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id, account_name) VALUES ('other@b.test', '444455556666', 'B') RETURNING id")
        b = str(cur.fetchone()[0])
        # A second person with write access to account A (org admin), so two-person approval can be tested.
        cur.execute("INSERT INTO organizations (name, owner_email) VALUES ('Org A', 'owner@a.test') RETURNING id")
        org = cur.fetchone()[0]
        cur.execute("INSERT INTO business_units (organization_id, name) VALUES (%s, 'Payments') RETURNING id", (org,))
        bu = cur.fetchone()[0]
        cur.execute("INSERT INTO bu_accounts (business_unit_id, cloud_account_id) VALUES (%s, %s)", (bu, a))
        cur.execute("INSERT INTO org_members (organization_id, email, role) VALUES (%s, 'admin2@a.test', 'org_admin')", (org,))
        cur.execute("INSERT INTO org_members (organization_id, email, role) VALUES (%s, 'viewer@a.test', 'viewer')", (org,))
        cur.execute("""INSERT INTO resources (cloud_account_id, resource_type, resource_id, resource_name, last_scanned_at)
                       VALUES (%s, 'iam-account', 'account', 'account', NOW()) RETURNING id""", (a,))
        res = cur.fetchone()[0]
        cur.execute("""INSERT INTO findings (resource_id, check_id, title, severity, status, framework, remediation, details, detected_at)
                       VALUES (%s, 'IAM.6', 'Hardware MFA should be enabled for the root user', 'CRITICAL', 'open',
                               'AWS Foundational Security Best Practices', 'Enable hardware MFA', '{"failed":1}', NOW() - interval '1 hour')
                       RETURNING id""", (res,))
        f1 = str(cur.fetchone()[0])
        # A mapped-framework copy of the same problem must not become a second issue.
        cur.execute("""INSERT INTO findings (resource_id, check_id, title, severity, status, framework, detected_at)
                       VALUES (%s, 'NIST-IA-2.1', 'MFA for Privileged Accounts', 'CRITICAL', 'open', 'NIST 800-53 Rev 5', NOW())""", (res,))
    conn.commit()
    return {"a": a, "b": b, "f1": f1, "res": str(res)}


def call(conn, email, method="GET", qs=None, body=None):
    event = {"httpMethod": method, "headers": {"Authorization": "Bearer t"}, "queryStringParameters": qs,
             "body": json.dumps(body) if body is not None else None}
    with patch.object(h, "_get_connection", return_value=_NoClose(conn)), \
            patch("collectors.aws.scanner.tenant_auth.authenticate", return_value=email), \
            patch.object(h, "authenticate", return_value=email), \
            patch.object(h, "_flush_notifications", side_effect=lambda c: h._PENDING_NOTIFICATIONS.clear()):
        r = h.handler(event, None)
    try:
        return r["statusCode"], json.loads(r["body"])
    except ValueError:
        return r["statusCode"], r["body"]


def overview(conn, acct, email="owner@a.test"):
    s, b = call(conn, email, qs={"cloud_account_id": acct, "view": "overview"})
    assert s == 200, b
    return b


def the_issue(conn, acct):
    s, b = call(conn, "owner@a.test", qs={"cloud_account_id": acct, "view": "issues", "status": ""})
    assert s == 200, b
    assert len(b["issues"]) == 1, [i["title"] for i in b["issues"]]
    return b["issues"][0]


def test_detection_counts_each_problem_once_and_says_why_not_zero(conn, world):
    b = overview(conn, world["a"])
    assert b["counts"]["open"] == 1
    assert b["posture"]["status"] == "critical_issues_present"
    i = the_issue(conn, world["a"])
    assert i["check_id"] == "IAM.6" and i["source"] == "findings"
    assert i["due_date"] == str(date.today() + timedelta(days=7))
    assert i["risk_score"] >= 70 and any("Severity" in f["factor"] for f in i["risk_factors"])


def test_remediation_needs_scan_verification_and_failed_fix_stays_visible(conn, world):
    i = the_issue(conn, world["a"])
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "mark_remediated",
                                                    "issue_id": i["id"], "note": "Added hardware key"})
    assert s == 200 and "next scan" in b["note"]
    # The scanner has not run since: still marked fixed, status needs validation, not zero.
    with conn.cursor() as cur:
        cur.execute("UPDATE findings SET detected_at = NOW() - interval '1 hour' WHERE id = %s", (world["f1"],))
    conn.commit()
    assert overview(conn, world["a"])["posture"]["status"] == "validation_required"
    # A later scan still reports it -> the fix failed, back to in progress, with a history event.
    with conn.cursor() as cur:
        cur.execute("UPDATE findings SET detected_at = (NOW() AT TIME ZONE 'utc') + interval '1 minute' WHERE id = %s", (world["f1"],))
    conn.commit()
    overview(conn, world["a"])
    s, d = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "issue", "issue_id": i["id"]})
    assert d["issue"]["status"] == "in_progress"
    assert [e["event"] for e in d["history"]][-1] == "verification_failed"


def test_resolved_only_by_scan_and_zero_needs_coverage(conn, world):
    with conn.cursor() as cur:
        # A real scan that finds the problem fixed writes 'pass' with its own, newer evaluation time.
        cur.execute("UPDATE findings SET status = 'pass', detected_at = (NOW() AT TIME ZONE 'utc') + interval '2 minutes' WHERE id = %s",
                    (world["f1"],))
        cur.execute("UPDATE findings SET status = 'pass' WHERE check_id = 'NIST-IA-2.1'")
    conn.commit()
    b = overview(conn, world["a"])
    assert b["counts"]["resolved"] == 1
    # No CIEM scan yet: a zero may not be claimed.
    assert b["posture"]["status"] == "coverage_incomplete" and "CIEM" in b["posture"]["reason"]
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO ciem_scans (cloud_account_id, status, finished_at) VALUES (%s, 'succeeded', NOW())""", (world["a"],))
    conn.commit()
    b = overview(conn, world["a"])
    assert b["posture"]["status"] == "zero_critical" and b["posture"]["verified_zero"] is True
    # Stale evidence blocks the claim again.
    with conn.cursor() as cur:
        cur.execute("UPDATE resources SET last_scanned_at = NOW() - interval '30 days' WHERE id = %s", (world["res"],))
    conn.commit()
    assert overview(conn, world["a"])["posture"]["status"] == "evidence_stale"
    with conn.cursor() as cur:
        cur.execute("UPDATE resources SET last_scanned_at = NOW() WHERE id = %s", (world["res"],))
    conn.commit()


def test_problem_coming_back_reopens_and_counts_again(conn, world):
    with conn.cursor() as cur:
        cur.execute("UPDATE findings SET status = 'open', detected_at = NOW() WHERE id = %s", (world["f1"],))
    conn.commit()
    b = overview(conn, world["a"])
    assert b["counts"]["open"] == 1 and b["counts"]["reopened"] == 1
    assert the_issue(conn, world["a"])["reopen_count"] == 1


def test_owner_must_have_access_and_viewer_cannot_change(conn, world):
    i = the_issue(conn, world["a"])
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "assign", "issue_id": i["id"],
                                                    "owner_email": "stranger@x.test"})
    assert s == 400 and "access" in b["error"]
    s, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "assign", "issue_id": i["id"],
                                                    "owner_email": "viewer@a.test"})
    assert s == 200
    s, _ = call(conn, "viewer@a.test", "POST", body={"cloud_account_id": world["a"], "action": "start", "issue_id": i["id"]})
    assert s == 403


def test_risk_acceptance_needs_second_person_and_expires(conn, world):
    i = the_issue(conn, world["a"])
    req = {"cloud_account_id": world["a"], "action": "request_risk_acceptance", "issue_id": i["id"],
           "justification": "Root is break-glass only", "rationale": "Key in safe", "risk_owner": "CISO",
           "compensating_controls": "Root login alarm", "residual_risk": "Low", "expires_on": str(date.today() + timedelta(days=30))}
    assert call(conn, "owner@a.test", "POST", body={**req, "compensating_controls": ""})[0] == 400
    assert call(conn, "owner@a.test", "POST", body=req)[0] == 200
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "decide_risk", "issue_id": i["id"], "decision": "approve"})
    assert s == 403 and "cannot approve" in b["error"]
    s, _ = call(conn, "admin2@a.test", "POST", body={"cloud_account_id": world["a"], "action": "decide_risk", "issue_id": i["id"], "decision": "approve"})
    assert s == 200
    b = overview(conn, world["a"])
    assert b["counts"]["accepted"] == 1 and b["counts"]["open"] == 0
    assert b["posture"]["status"] == "accepted_risk" and b["posture"]["verified_zero"] is False
    # Expiry puts it back.
    with conn.cursor() as cur:
        cur.execute("UPDATE critical_issues SET risk_expires_on = CURRENT_DATE - 1 WHERE id = %s", (i["id"],))
    conn.commit()
    b = overview(conn, world["a"])
    assert b["counts"]["open"] == 1 and b["counts"]["accepted"] == 0


def test_overdue_issue_escalates_once(conn, world):
    i = the_issue(conn, world["a"])
    with conn.cursor() as cur:
        cur.execute("UPDATE critical_issues SET due_date = CURRENT_DATE - 1, escalated_at = NULL WHERE id = %s", (i["id"],))
    conn.commit()
    sent = []
    with patch.object(h, "_PENDING_NOTIFICATIONS", sent):
        with conn.cursor() as cur:
            h.sync_issues(cur, world["a"], notify=h._notify_overdue(conn))
            h.sync_issues(cur, world["a"], notify=h._notify_overdue(conn))
        conn.commit()
    assert len(sent) == 1
    b = overview(conn, world["a"])
    assert b["counts"]["overdue"] == 1 and b["counts"]["escalated"] == 1


def test_tenant_isolation(conn, world):
    i = the_issue(conn, world["a"])
    s, _ = call(conn, "other@b.test", qs={"cloud_account_id": world["a"], "view": "overview"})
    assert s == 403
    # Naming its own account but another tenant's issue id is refused too.
    s, _ = call(conn, "other@b.test", "POST", body={"cloud_account_id": world["b"], "action": "start", "issue_id": i["id"]})
    assert s == 403
    s, b = call(conn, "other@b.test", qs={"view": "portfolio"})
    assert s == 200 and [a["account_name"] for a in b["accounts"]] == ["B"]
    s, b = call(conn, "admin2@a.test", qs={"view": "portfolio"})
    assert [a["business_units"] for a in b["accounts"]] == ["Payments"]


def test_export_is_spreadsheet_safe_and_keeps_history(conn, world):
    i = the_issue(conn, world["a"])
    call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "set_plan", "issue_id": i["id"],
                                             "remediation_plan": "=HYPERLINK(\"x\")"})
    s, csv_text = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "export", "format": "csv"})
    assert s == 200 and "'=HYPERLINK" in csv_text and "zero_critical_status" in csv_text
    s, b = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "history"})
    events = [e["event"] for e in b["events"]]
    for e in ("detected", "remediated", "verification_failed", "verified_resolved", "reopened", "risk_accepted",
              "risk_acceptance_expired", "escalated", "plan_updated"):
        assert e in events, e
    assert b["snapshots"] and b["snapshots"][0]["day"] == str(date.today())
    # History is append-only for the runtime role (grant check).
    with conn.cursor() as cur:
        cur.execute("SELECT has_table_privilege('cspm_lambda', 'critical_issue_events', 'UPDATE')")
        assert cur.fetchone()[0] is False


def test_bad_input_is_refused_cleanly(conn, world):
    i = the_issue(conn, world["a"])
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "nope", "issue_id": i["id"]})[0] == 400
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "start", "issue_id": "x"})[0] == 404
    assert call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "issue", "issue_id": str(uuid.uuid4())})[0] == 404
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "save_settings", "sla_days": 500, "freshness_days": 5})
    assert s == 400


def test_partial_scan_never_certifies_zero(conn, world):
    with conn.cursor() as cur:
        cur.execute("UPDATE cloud_accounts SET last_scan_at = NOW() WHERE id = %s", (world["b"],))
        cur.execute("""INSERT INTO resources (cloud_account_id, resource_type, resource_id, resource_name, last_scanned_at)
                       VALUES (%s, 'iam-account', 'account', 'account', NOW())""", (world["b"],))
        cur.execute("INSERT INTO ciem_scans (cloud_account_id, status, finished_at) VALUES (%s, 'partial', NOW())", (world["b"],))
    conn.commit()
    b = overview(conn, world["b"], "other@b.test")
    assert b["counts"]["open"] == 0
    assert b["posture"]["status"] == "coverage_incomplete" and "partial" in b["posture"]["reason"]
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO ciem_scans (cloud_account_id, status, started_at, finished_at)
                       VALUES (%s, 'succeeded', NOW() + interval '1 second', NOW())""", (world["b"],))
    conn.commit()
    assert overview(conn, world["b"], "other@b.test")["posture"]["status"] == "zero_critical"


def test_removed_resource_is_only_verified_by_a_later_complete_scan(conn, world):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO resources (cloud_account_id, resource_type, resource_id, resource_name, last_scanned_at)
                       VALUES (%s, 's3-bucket', 'b1', 'b1', NOW()) RETURNING id""", (world["b"],))
        rid = cur.fetchone()[0]
        cur.execute("""INSERT INTO findings (resource_id, check_id, title, severity, status, framework, detected_at)
                       VALUES (%s, 'S3.1', 'Public bucket', 'CRITICAL', 'open', 'CIS AWS Foundations Benchmark v5.0.0',
                               (NOW() AT TIME ZONE 'utc') + interval '5 minutes')""", (rid,))
    conn.commit()
    assert overview(conn, world["b"], "other@b.test")["counts"]["open"] == 1
    with conn.cursor() as cur:
        cur.execute("DELETE FROM resources WHERE id = %s", (rid,))
    conn.commit()
    b = overview(conn, world["b"], "other@b.test")
    assert b["counts"]["resolved"] == 0 and b["counts"]["open"] == 1, "no scan after the problem was last seen"
    with conn.cursor() as cur:
        cur.execute("UPDATE cloud_accounts SET last_scan_at = (NOW() AT TIME ZONE 'utc') + interval '10 minutes' WHERE id = %s", (world["b"],))
    conn.commit()
    assert overview(conn, world["b"], "other@b.test")["counts"]["resolved"] == 1
