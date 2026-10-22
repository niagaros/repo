"""
Security Agents runner (real workflow against PostgreSQL with mocked CloudTrail) and API (lifecycle gates,
execution-time authorisation, approvals with separation of duties, state machine, verification, tenant
isolation, exports) with the real migrations. Needs NIAGAROS_PGTEST_DSN (see test_governance_handler.py).
"""
import json
import os
import sys
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND / "src"))

psycopg2 = pytest.importorskip("psycopg2")
DSN = os.environ.get("NIAGAROS_PGTEST_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="blocked: set NIAGAROS_PGTEST_DSN to a throwaway PostgreSQL")

SCHEMA = ["tests/fixtures/ciem_schema.sql", "tests/fixtures/ai_inventory_schema.sql", "tests/fixtures/security_agents_schema.sql",
          "migrations/024_security_audit_log.sql", "migrations/026_enterprise.sql", "migrations/032_ciem.sql",
          "migrations/033_ai_inventory.sql", "migrations/034_security_agents.sql", "migrations/034_security_agents.sql"]
NOW = datetime.now(timezone.utc)
ADMIN_ARN = "arn:aws:iam::111122223333:user/dev"


@pytest.fixture(scope="module")
def conn():
    name = f"sa_test_{uuid.uuid4().hex[:8]}"
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
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id) VALUES ('owner@a.test', '111122223333') RETURNING id")
        a = str(cur.fetchone()[0])
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id) VALUES ('other@b.test', '444455556666') RETURNING id")
        b = str(cur.fetchone()[0])
        # source data the agents read
        cur.execute("INSERT INTO ciem_scans (cloud_account_id, status, finished_at) VALUES (%s, 'succeeded', NOW()) RETURNING id", (a,))
        sid = cur.fetchone()[0]
        cur.execute("""INSERT INTO ciem_identities (cloud_account_id, scan_id, arn, name, kind, classification, risk_score, risk_severity, admin, data)
                       VALUES (%s, %s, %s, 'dev', 'user', 'human', 70, 'high', NULL, '{}')""", (a, sid, ADMIN_ARN))
        cur.execute("""INSERT INTO ciem_findings (cloud_account_id, fingerprint, rule, category, severity, title, identity_arn, details, recommendation)
                       VALUES (%s, 'ciem-esc', 'escalation_paths', 'privilege_escalation', 'high', 'Potential privilege escalation (dev)', %s,
                               %s, '{"current": "PassRole", "proposed": "Remove PassRole", "rollback": "Restore"}') RETURNING id""",
                    (a, ADMIN_ARN, json.dumps({"path": {"how": "Create a Lambda with an admin role", "required_permissions": ["iam:PassRole"],
                                                        "gains": ["full administrator access"]}})))
        cur.execute("INSERT INTO resources (cloud_account_id, resource_type, resource_id) VALUES (%s, 's3-bucket', 'arn:aws:s3:::public') RETURNING id", (a,))
        rid = cur.fetchone()[0]
        cur.execute("""INSERT INTO findings (resource_id, check_id, title, severity, status, framework, remediation, details)
                       VALUES (%s, 'S3.1', 'Bucket allows public read', 'CRITICAL', 'open', 'CIS AWS Foundations Benchmark v5.0.0', 'Block public access', '{"public": true}'),
                              (%s, 'S3.1', 'Bucket allows public read', 'CRITICAL', 'open', 'SOC2', 'dup', '{}')""", (rid, rid))
    conn.commit()
    return {"a": a, "b": b}


def _ct_session(events):
    ct = MagicMock()
    ct.lookup_events.side_effect = lambda **kw: {"Events": [e for e in events if e["EventName"] == kw["LookupAttributes"][0]["AttributeValue"]]}
    s = MagicMock()
    s.client.return_value = ct
    return s, ct


def _ev(name, minute=0, params=None, arn=ADMIN_ARN, eid=None):
    ct = {"userIdentity": {"type": "IAMUser", "arn": arn}, "sourceIPAddress": "203.0.113.9", "requestParameters": params}
    return {"EventId": eid or f"{name}-{minute}", "EventName": name, "EventTime": NOW - timedelta(minutes=30 - minute),
            "CloudTrailEvent": json.dumps(ct), "Resources": []}


EVENTS = [_ev("CreateAccessKey", 0), _ev("AttachUserPolicy", 3, {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
          _ev("StopLogging", 6)]


@pytest.fixture
def api(conn):
    from collectors.aws.scanner import security_agents_handler as h

    def call(email, method, qs=None, body=None):
        event = {"httpMethod": method, "path": "/security-agents", "queryStringParameters": qs,
                 "body": json.dumps(body) if body is not None else None, "headers": {"Authorization": "Bearer t"}}
        with patch("collectors.aws.scanner.tenant_auth.authenticate", return_value=email), patch.object(h, "authenticate", return_value=email):
            r = h.handle(event, conn)
        try:
            return r["statusCode"], json.loads(r["body"])
        except ValueError:
            return r["statusCode"], r["body"]
    return call


def _run(conn, account, events=EVENTS, initiated_by=None):
    from collectors.aws.scanner import security_agents_runner_handler as R
    session, ct = _ct_session(events)
    with patch.object(R, "_notify"):
        out = R.run(conn, account, session, "manual", "eu-west-1", initiated_by)
    conn.commit()
    return out, ct


def _items(conn, account, **where):
    q = "SELECT source_type, state, title, id, priority, active_threat, plan IS NOT NULL FROM sa_work_items WHERE cloud_account_id = %s"
    with conn.cursor() as cur:
        cur.execute(q, (account,))
        rows = cur.fetchall()
    conn.rollback()
    return [dict(zip(("source_type", "state", "title", "id", "priority", "active_threat", "planned"), r)) for r in rows]


# ── lifecycle gates ─────────────────────────────────────────────────────────

def test_nothing_runs_until_agents_are_activated(conn, accounts, api):
    out, ct = _run(conn, accounts["a"])
    assert out["active_agents"] == [] and "No agent is active" in out["note"] and not ct.lookup_events.called
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": accounts["a"], "action": "approve_agent", "agent_id": "red-identity-attack-path"})
    assert s == 409 and "owner" in b["error"] and "authorisation" in b["error"] and "evaluation" in b["error"]


def test_step_by_step_activation(api, accounts):
    a, ag = accounts["a"], "red-identity-attack-path"
    assert api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "configure_agent", "agent_id": ag, "owner": "sec@a.test"})[1]["status"] == "configured"
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "authorize_agent", "agent_id": ag, "environments": ["production"],
                                             "valid_days": 400, "reason": "x"})
    assert s == 400
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "authorize_agent", "agent_id": ag, "environments": ["production"],
                                             "valid_days": 30, "reason": "quarterly review"})
    assert s == 200
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "run_evaluation", "agent_id": ag})
    assert b["evaluation"]["passed"] and b["status"] == "tested"
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "approve_agent", "agent_id": ag})
    assert s == 200 and b["status"] == "active"


def test_activate_recommended_activates_everything_with_recorded_steps(api, accounts):
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": accounts["a"], "action": "activate_recommended"})
    assert s == 200 and len(b["activated"]) == 8              # the one activated by hand above is skipped
    s, ag = api("owner@a.test", "GET", {"cloud_account_id": accounts["a"], "view": "agents"})
    assert all(x["status"] == "active" and x["evaluation_current"] for x in ag["agents"])
    s, au = api("owner@a.test", "GET", {"cloud_account_id": accounts["a"], "view": "audit"})
    acts = [x["action"] for x in au["audit"]]
    assert acts.count("agent_approved") == 9 and acts.count("authorization_granted") == 9


# ── the workflow ────────────────────────────────────────────────────────────

def test_full_workflow_red_blue_triage_green(conn, accounts):
    a = accounts["a"]
    out, ct = _run(conn, a)
    items = _items(conn, a)
    kinds = {i["source_type"] for i in items}
    assert {"ciem_finding", "scanner_finding", "detection"} <= kinds
    scanner = [i for i in items if i["source_type"] == "scanner_finding"]
    assert len(scanner) == 1                                    # the mapped SOC2 duplicate is not counted
    esc = next(i for i in items if i["source_type"] == "ciem_finding")
    assert esc["active_threat"]                                 # admin grant by the same identity -> incident correlated
    assert all(i["planned"] for i in items if i["source_type"] != "detection")
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM sa_detections WHERE cloud_account_id = %s", (a,))
        assert cur.fetchone()[0] == 3
        cur.execute("SELECT summary, related_work_items FROM sa_incidents WHERE cloud_account_id = %s", (a,))
        summary, related = cur.fetchone()
        assert "3 detection(s)" in summary and related
        cur.execute("SELECT DISTINCT decision FROM sa_actions WHERE cloud_account_id = %s", (a,))
        assert {r[0] for r in cur.fetchall()} == {"allow"}
        cur.execute("SELECT count(*) FROM sa_runs WHERE cloud_account_id = %s AND workflow_id = %s", (a, out["workflow_id"]))
        assert cur.fetchone()[0] == 9
        cur.execute("SELECT coverage->>'window_end' FROM sa_runs WHERE cloud_account_id = %s AND agent_id = 'blue-cloud-threat' ORDER BY started_at DESC LIMIT 1", (a,))
        assert cur.fetchone()[0]
    conn.rollback()


def test_second_run_is_idempotent(conn, accounts):
    before = len(_items(conn, accounts["a"]))
    _run(conn, accounts["a"])
    assert len(_items(conn, accounts["a"])) == before
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM sa_detections WHERE cloud_account_id = %s", (accounts["a"],))
        assert cur.fetchone()[0] == 3
    conn.rollback()


def test_unreadable_cloudtrail_is_a_coverage_gap_not_all_clear(conn, accounts):
    from collectors.aws.scanner import security_agents_runner_handler as R
    session = MagicMock()
    session.client.return_value.lookup_events.side_effect = RuntimeError("AccessDenied")
    with patch.object(R, "_notify"):
        R.run(conn, accounts["a"], session, "manual", "eu-west-1", None, ["blue-cloud-threat"])
    conn.commit()
    with conn.cursor() as cur:
        cur.execute("SELECT status, limitations FROM sa_runs WHERE cloud_account_id = %s AND agent_id = 'blue-cloud-threat' ORDER BY started_at DESC LIMIT 1",
                    (accounts["a"],))
        status, lim = cur.fetchone()
    conn.rollback()
    assert status == "partial" and any("not readable" in l for l in lim)


def test_human_cannot_resolve_and_remediation_needs_a_later_scan(api, conn, accounts):
    a = accounts["a"]
    esc = next(i for i in _items(conn, a) if i["source_type"] == "ciem_finding")
    iid = str(esc["id"])
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "transition_item", "work_item_id": iid, "to": "resolved"})
    assert s == 409 and "Verification Agent" in b["error"]
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "assign_item", "work_item_id": iid, "owner": "dev-team"})
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "record_remediation", "work_item_id": iid, "change_reference": "PR #42"})
    assert s == 200 and b["state"] == "remediated"
    _run(conn, a)                                               # CIEM finding still open (last_seen older than the remediation)
    assert next(i for i in _items(conn, a) if i["id"] == esc["id"])["state"] == "remediated"
    with conn.cursor() as cur:                                  # a later CIEM scan still sees it
        cur.execute("UPDATE ciem_findings SET last_seen = NOW() + INTERVAL '1 minute' WHERE fingerprint = 'ciem-esc'")
    conn.commit()
    _run(conn, a)
    assert next(i for i in _items(conn, a) if i["id"] == esc["id"])["state"] == "reopened"
    with conn.cursor() as cur:                                  # fixed for real: a later scan resolves it
        cur.execute("UPDATE ciem_findings SET status = 'resolved', resolved_at = NOW() + INTERVAL '2 minutes' WHERE fingerprint = 'ciem-esc'")
    conn.commit()
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "transition_item", "work_item_id": iid, "to": "in_progress"})
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "record_remediation", "work_item_id": iid, "change_reference": "PR #43"})
    _run(conn, a)
    s, d = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "item", "work_item_id": iid})
    assert d["state"] == "resolved" and d["verification"]["result"] == "passed"
    assert [h["to"] for h in d["history"]][-1] == "resolved" and d["history"][-1]["actor"] == "green-verification"
    with conn.cursor() as cur:                                  # it comes back
        cur.execute("UPDATE ciem_findings SET status = 'open', resolved_at = NULL WHERE fingerprint = 'ciem-esc'")
    conn.commit()
    _run(conn, a)
    assert next(i for i in _items(conn, a) if i["id"] == esc["id"])["state"] == "reopened"


def test_rescan_in_production_needs_approval_with_separation_of_duties(api, conn, accounts):
    a = accounts["a"]
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM sa_work_items WHERE cloud_account_id = %s AND source_type = 'ciem_finding'", (a,))
        iid = str(cur.fetchone()[0])
        cur.execute("UPDATE ciem_findings SET status = 'open', last_seen = NOW() - INTERVAL '1 day' WHERE fingerprint = 'ciem-esc'")
    conn.commit()
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "transition_item", "work_item_id": iid, "to": "in_progress"})
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "record_remediation", "work_item_id": iid, "change_reference": "PR #44"})
    _run(conn, a)
    s, ap = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "approvals"})
    req = next(x for x in ap["approvals"] if x["action"] == "request_rescan" and x["decision"] == "pending")
    assert req["target"] == "ciem-scanner" and req["requested_by"] == "green-verification"
    lam = MagicMock()
    with patch("collectors.aws.scanner.security_agents_handler.boto3.client", return_value=lam):
        s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "decide_approval", "approval_id": req["id"], "decision": "approved",
                                                 "reason": "verify PR #44"})
    assert s == 200 and b["result"]["executed"] and json.loads(lam.invoke.call_args.kwargs["Payload"])["cloud_account_id"] == a


def test_containment_is_approved_but_never_executed_by_niagaros(api, conn, accounts):
    a = accounts["a"]
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM sa_work_items WHERE cloud_account_id = %s AND source_type = 'detection' LIMIT 1", (a,))
        iid = str(cur.fetchone()[0])
        # a second administrator exists: the requester may not approve their own request
        cur.execute("INSERT INTO organizations (name, owner_email) VALUES ('Org A', 'owner@a.test') RETURNING id")
        org = cur.fetchone()[0]
        cur.execute("INSERT INTO business_units (organization_id, name) VALUES (%s, 'BU') RETURNING id", (org,))
        bu = cur.fetchone()[0]
        cur.execute("INSERT INTO bu_accounts (business_unit_id, cloud_account_id) VALUES (%s, %s)", (bu, a))
        cur.execute("INSERT INTO org_members (organization_id, email, role) VALUES (%s, 'second@a.test', 'org_admin')", (org,))
    conn.commit()
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "request_containment", "work_item_id": iid,
                                             "plan": "Deactivate the new access key of dev", "rollback": "Reactivate the key"})
    assert s == 200
    apr = b["approval_id"]
    s, e = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "decide_approval", "approval_id": apr, "decision": "approved", "reason": "ok"})
    assert s == 403 and "another administrator" in e["error"]
    s, b = api("second@a.test", "POST", body={"cloud_account_id": a, "action": "decide_approval", "approval_id": apr, "decision": "approved", "reason": "confirmed with dev"})
    assert s == 200 and b["result"]["executed"] is False and "your team" in b["result"]["note"].lower()


def test_revoked_authorisation_blocks_the_next_run(api, conn, accounts):
    a = accounts["a"]
    s, ag = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "agent", "agent_id": "red-ai-security"})
    for z in ag["authorizations"]:
        if not z["revoked_at"]:
            api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "revoke_authorization", "authorization_id": z["id"]})
    out, _ = _run(conn, a)
    assert out["runs"]["red-ai-security"] == "blocked"
    with conn.cursor() as cur:
        cur.execute("""SELECT reason FROM sa_actions WHERE cloud_account_id = %s AND agent_id = 'red-ai-security' AND decision = 'block'
                       ORDER BY created_at DESC LIMIT 1""", (a,))
        assert "No authorisation" in cur.fetchone()[0]
    conn.rollback()


def test_offensive_technique_request_is_refused_and_audited(api, accounts):
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": accounts["a"], "action": "request_technique",
                                             "agent_id": "red-vulnerability-assessment", "technique": "active_exploitation"})
    assert s == 200 and b["decision"] == "block"
    s, au = api("owner@a.test", "GET", {"cloud_account_id": accounts["a"], "view": "audit"})
    assert any(x["action"] == "technique_blocked" for x in au["audit"])
    assert any(x["decision"] == "block" and "passive analysis" in x["reason"] for x in au["policy_decisions"])


def test_policy_rules(api, accounts):
    a = accounts["a"]
    pol = lambda **kw: api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "set_policy", "environment": "production", **kw})
    assert pol(agent_id="blue-identity-defense", policy_action="containment", level="L5", requires_approval=True)[0] == 400
    assert pol(agent_id="blue-identity-defense", policy_action="containment", level="L4", requires_approval=False)[0] == 400
    assert pol(agent_id="red-identity-attack-path", policy_action="containment", level="L3", requires_approval=True)[0] == 400
    s, _ = pol(agent_id="green-verification", policy_action="request_rescan", level="L4", requires_approval=False)
    assert s == 200
    s, p = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "policies"})
    row = next(x for x in p["policies"] if x["agent_id"] == "green-verification" and x["action"] == "request_rescan" and x["environment"] == "production")
    assert row["custom"] and row["level"] == "L4" and not row["requires_approval"]


def test_detection_item_is_closed_by_a_person_with_a_reason(api, conn, accounts):
    a = accounts["a"]
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM sa_work_items WHERE cloud_account_id = %s AND source_type = 'detection' AND state <> 'resolved' LIMIT 1", (a,))
        iid = str(cur.fetchone()[0])
    conn.rollback()
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "transition_item", "work_item_id": iid, "to": "resolved"})
    assert s == 400
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "transition_item", "work_item_id": iid, "to": "resolved",
                                             "reason": "Planned key rotation by dev; confirmed in change CHG-12"})
    assert s == 200
    s, d = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "item", "work_item_id": iid})
    assert d["verification"]["result"] == "closed_by_person"


def test_accepted_risk_needs_reason_and_end_date(api, conn, accounts):
    a = accounts["a"]
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM sa_work_items WHERE cloud_account_id = %s AND source_type = 'scanner_finding'", (a,))
        iid = str(cur.fetchone()[0])
    conn.rollback()
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "transition_item", "work_item_id": iid, "to": "accepted_risk", "reason": "x"})
    assert s == 400
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "transition_item", "work_item_id": iid, "to": "accepted_risk",
                                             "reason": "public website bucket", "accepted_until": (date.today() + timedelta(days=30)).isoformat()})
    assert s == 200


def test_tenant_isolation(api, conn, accounts):
    a, b = accounts["a"], accounts["b"]
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM sa_work_items WHERE cloud_account_id = %s LIMIT 1", (a,))
        iid = str(cur.fetchone()[0])
        cur.execute("SELECT id FROM sa_incidents WHERE cloud_account_id = %s LIMIT 1", (a,))
        inc = str(cur.fetchone()[0])
        cur.execute("SELECT id FROM sa_approvals WHERE cloud_account_id = %s LIMIT 1", (a,))
        apr = str(cur.fetchone()[0])
    conn.rollback()
    assert api("other@b.test", "GET", {"cloud_account_id": a, "view": "overview"})[0] == 403
    assert api("other@b.test", "GET", {"cloud_account_id": b, "view": "item", "work_item_id": iid})[0] == 403
    assert api("other@b.test", "GET", {"cloud_account_id": b, "view": "incident", "incident_id": inc})[0] == 403
    assert api("other@b.test", "POST", body={"cloud_account_id": b, "action": "decide_approval", "approval_id": apr, "decision": "approved", "reason": "x"})[0] == 403
    assert api("other@b.test", "POST", body={"cloud_account_id": b, "action": "transition_item", "work_item_id": iid, "to": "false_positive", "reason": "x"})[0] == 403
    assert api(None, "GET", {"cloud_account_id": a, "view": "overview"})[0] == 401


def test_every_view_and_export(api, accounts):
    a = accounts["a"]
    for view in ("overview", "agents", "runs", "queue", "detections", "incidents", "attack_paths", "approvals", "policies", "settings", "audit"):
        s, b = api("owner@a.test", "GET", {"cloud_account_id": a, "view": view})
        assert s == 200, (view, b)
    s, o = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "overview"})
    assert o["metrics"]["closed_after_investigation"] >= 1 and o["actions_30d"]["blocked"] >= 1
    assert o["metrics"]["verified_resolved"] == 0           # the scan-verified item came back; a person's closure is not 'verified'
    s, csv_text = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "export", "what": "queue", "format": "csv"})
    assert s == 200 and csv_text.startswith("category,")


def test_history_evidence_and_audit_are_append_only(conn):
    with conn.cursor() as cur:
        cur.execute("""SELECT table_name, string_agg(privilege_type, ',' ORDER BY privilege_type) FROM information_schema.role_table_grants
                       WHERE grantee = 'cspm_lambda' AND table_name IN ('sa_work_item_events', 'sa_evidence', 'sa_audit_log') GROUP BY 1""")
        assert dict(cur.fetchall()) == {t: "INSERT,SELECT" for t in ("sa_work_item_events", "sa_evidence", "sa_audit_log")}
    conn.rollback()


def test_api_rejects_unauthenticated_calls_before_the_database():
    from collectors.aws.scanner import security_agents_handler as h
    with patch.object(h, "authenticate", return_value=None), patch.object(h, "_get_connection") as gc:
        r = h.handler({"httpMethod": "GET", "queryStringParameters": {"cloud_account_id": str(uuid.uuid4())}, "headers": {}}, None)
    assert r["statusCode"] == 401 and not gc.called


def test_authorisation_is_reloaded_before_every_action(conn, accounts):
    from collectors.aws.scanner import security_agents_runner_handler as R
    a = accounts["a"]
    with conn.cursor() as cur:
        ctx = R.load_context(cur, a)
        wf = R.Workflow(conn, a, ctx, "manual", None)
        assert wf.check(cur, None, "red-vulnerability-assessment", "analyze")["decision"] == "allow"
        cur.execute("UPDATE sa_agents SET status = 'paused' WHERE cloud_account_id = %s AND agent_id = 'red-vulnerability-assessment'", (a,))
        assert wf.check(cur, None, "red-vulnerability-assessment", "analyze")["decision"] == "block"
    conn.rollback()


def test_notifications_respect_the_notify_policy(conn, accounts):
    from collectors.aws.scanner import security_agents_runner_handler as R
    a = accounts["a"]
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO sa_authorizations (cloud_account_id, agent_id, scope_reference, environments, prohibited_actions, valid_until, approved_by)
                       SELECT cloud_account_id, agent_id, scope_reference, environments, '["notify"]', valid_until, 'owner@a.test'
                       FROM sa_authorizations WHERE cloud_account_id = %s AND agent_id = 'red-vulnerability-assessment' AND revoked_at IS NULL LIMIT 1""", (a,))
        cur.execute("UPDATE sa_authorizations SET revoked_at = NOW() WHERE cloud_account_id = %s AND agent_id = 'red-vulnerability-assessment' AND prohibited_actions = '[]'", (a,))
        ctx = R.load_context(cur, a)
    conn.commit()
    wf = R.Workflow(conn, a, ctx, "manual", None)
    wf.notifications.append(("red", "red-vulnerability-assessment", [{"severity": "critical", "title": "x"}]))
    with patch("collectors.aws.scanner.notification_lib.create_notification") as notify:
        R._notify(conn, wf)
    assert not notify.called


def test_blocked_api_action_keeps_its_denial_record(api, conn, accounts):
    a = accounts["a"]
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO workspace_integrations (cloud_account_id, provider, project, secret_name) VALUES (%s, 'jira', 'SEC', 'x') RETURNING id""", (a,))
        integ = str(cur.fetchone()[0])
        cur.execute("SELECT id FROM sa_work_items WHERE cloud_account_id = %s AND source_type = 'scanner_finding'", (a,))
        iid = str(cur.fetchone()[0])
    conn.commit()
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "set_policy", "agent_id": "green-remediation-planner", "policy_action": "create_ticket",
                                      "environment": "production", "level": "L1", "requires_approval": False})
    with patch("collectors.aws.scanner.integrations_handler._load", return_value={"id": integ, "cloud_account_id": a, "project": "SEC", "provider": "jira"}):
        s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "create_ticket", "work_item_id": iid, "integration_id": integ})
    assert s == 403 and "Blocked by policy" in b["error"]
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM sa_actions WHERE cloud_account_id = %s AND action = 'create_ticket' AND decision = 'block'", (a,))
        assert cur.fetchone()[0] == 1
    conn.rollback()


def test_partial_blue_read_does_not_move_the_cursor(conn, accounts):
    from collectors.aws.scanner import security_agents_runner_handler as R
    a = accounts["a"]
    session = MagicMock()
    session.client.return_value.lookup_events.side_effect = RuntimeError("Throttled")
    with patch.object(R, "_notify"):
        R.run(conn, a, session, "manual", "eu-west-1", None, ["blue-ai-threat-defense"])
    conn.commit()
    with conn.cursor() as cur:
        cur.execute("""SELECT status, coverage->>'window_end' FROM sa_runs WHERE cloud_account_id = %s AND agent_id = 'blue-ai-threat-defense'
                       ORDER BY started_at DESC LIMIT 1""", (a,))
        status, end = cur.fetchone()
    conn.rollback()
    assert status == "partial" and end is None
