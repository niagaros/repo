"""
Cloud Cost (#295) against a real PostgreSQL with the real migration: ingestion from a fake AWS session (shapes as
Cost Explorer / EC2 return them), late billing revisions, budgets and anomalies -> alerts, opportunity lifecycle with
two-person approval and verification by a later ingestion, opt-in for paid requests, tenant isolation, exports.
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

SCHEMA = ["tests/fixtures/ciem_schema.sql", "tests/fixtures/security_agents_schema.sql", "migrations/024_security_audit_log.sql",
          "migrations/026_enterprise.sql", "migrations/038_cloud_cost.sql", "migrations/038_cloud_cost.sql", "migrations/042_cloud_cost_extras.sql"]
TODAY = date.today()

from collectors.aws.scanner import cost_handler as H  # noqa: E402
from collectors.aws.scanner import cost_scanner_handler as S  # noqa: E402


@pytest.fixture(scope="module")
def conn():
    name = f"cost_test_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    c = psycopg2.connect(DSN.rsplit("/", 1)[0] + "/" + name)
    c.autocommit = True
    for f in SCHEMA:
        c.cursor().execute((BACKEND / f).read_text(encoding="utf-8"))
    c.cursor().execute("ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS region VARCHAR(32)")
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
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id, account_name, region) VALUES ('owner@a.test', '111122223333', 'A', 'eu-west-1') RETURNING id")
        a = str(cur.fetchone()[0])
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id, account_name) VALUES ('other@b.test', '444455556666', 'B') RETURNING id")
        b = str(cur.fetchone()[0])
        cur.execute("INSERT INTO organizations (name, owner_email) VALUES ('Org A', 'owner@a.test') RETURNING id")
        org = cur.fetchone()[0]
        cur.execute("INSERT INTO business_units (organization_id, name) VALUES (%s, 'Payments') RETURNING id", (org,))
        cur.execute("INSERT INTO bu_accounts (business_unit_id, cloud_account_id) VALUES (%s, %s)", (cur.fetchone()[0], a))
        cur.execute("INSERT INTO org_members (organization_id, email, role) VALUES (%s, 'admin2@a.test', 'org_admin')", (org,))
        cur.execute("INSERT INTO org_members (organization_id, email, role) VALUES (%s, 'viewer@a.test', 'viewer')", (org,))
    conn.commit()
    return {"a": a, "b": b}


# ── fake AWS ────────────────────────────────────────────────────────────────

class FakeAWS:
    def __init__(self):
        self.daily = {}          # (day, service, record_type) -> amount
        self.volumes = [{"VolumeId": "vol-1", "State": "available", "Size": 100, "VolumeType": "gp3",
                         "CreateTime": datetime.now(timezone.utc) - timedelta(days=30)}]
        self.ce_calls = 0
        for i in range(1, 20):
            d = (TODAY - timedelta(days=i)).isoformat()
            self.daily[(d, "Amazon Elastic Compute Cloud - Compute", "Usage")] = 10.0
            self.daily[(d, "Amazon Simple Storage Service", "Usage")] = 1.0
        self.daily[((TODAY - timedelta(days=1)).isoformat(), "Amazon Elastic Compute Cloud - Compute", "Usage")] = 80.0
        self.daily[((TODAY - timedelta(days=2)).isoformat(), "Tax", "Tax")] = 3.0

    savings_plans = []
    reserved = []
    clusters = []
    sp_rec = {"SavingsPlansPurchaseRecommendation": {"SavingsPlansType": "COMPUTE_SP", "TermInYears": "ONE_YEAR",
              "PaymentOption": "NO_UPFRONT", "SavingsPlansPurchaseRecommendationSummary": {
                  "HourlyCommitmentToPurchase": "0.12", "EstimatedMonthlySavingsAmount": "21.5", "EstimatedSavingsPercentage": "18",
                  "EstimatedROI": "22", "CurrencyCode": "USD"}}, "Metadata": {"RecommendationId": "rec-1"}}

    def client(self, name, region_name=None):
        return {"ce": FakeCE, "ec2": FakeEC2, "elbv2": FakeELB, "savingsplans": FakeSP, "rds": FakeRDS, "eks": FakeEKS}[name](self)


class _Pag:
    def __init__(self, fn, key):
        self.fn, self.key = fn, key

    def paginate(self, **kw):
        return [{self.key: self.fn()}]


class FakeCE:
    def __init__(self, aws):
        self.aws = aws

    def get_cost_and_usage(self, TimePeriod, Granularity, Metrics, GroupBy, **kw):
        self.aws.ce_calls += 1
        keys = [g["Key"] for g in GroupBy]
        if keys == ["REGION"]:
            return {"ResultsByTime": [{"TimePeriod": TimePeriod, "Groups": [
                {"Keys": ["eu-west-1"], "Metrics": {"UnblendedCost": {"Amount": "12", "Unit": "USD"}}}]}]}
        if GroupBy[0]["Type"] == "TAG":
            return {"ResultsByTime": [{"TimePeriod": {"Start": (TODAY - timedelta(days=1)).isoformat()}, "Estimated": True, "Groups": [
                {"Keys": ["team$"], "Metrics": {"UnblendedCost": {"Amount": "5", "Unit": "USD"}}},
                {"Keys": ["team$payments"], "Metrics": {"UnblendedCost": {"Amount": "15", "Unit": "USD"}}}]}]}
        by_day = {}
        for (d, s, t), amt in self.aws.daily.items():
            by_day.setdefault(d, []).append({"Keys": [s, t], "Metrics": {"UnblendedCost": {"Amount": str(amt), "Unit": "USD"}}})
        return {"ResultsByTime": [{"TimePeriod": {"Start": d}, "Estimated": d >= (TODAY - timedelta(days=2)).isoformat(), "Groups": g}
                                  for d, g in sorted(by_day.items())]}

    def get_cost_forecast(self, **kw):
        self.aws.ce_calls += 1
        return {"Total": {"Amount": "400", "Unit": "USD"}}

    def get_anomalies(self, **kw):
        self.aws.ce_calls += 1
        return {"Anomalies": []}

    def get_reservation_utilization(self, **kw):
        self.aws.ce_calls += 1
        return {"Total": {"UtilizationPercentage": "0"}}

    def get_savings_plans_purchase_recommendation(self, **kw):
        self.aws.ce_calls += 1
        return self.aws.sp_rec

    def get_reservation_purchase_recommendation(self, **kw):
        self.aws.ce_calls += 1
        return {"Recommendations": []}

    def get_savings_plans_utilization(self, **kw):
        self.aws.ce_calls += 1
        from botocore.exceptions import ClientError
        raise ClientError({"Error": {"Code": "DataUnavailableException", "Message": ""}}, "GetSavingsPlansUtilization")


class FakeSP:
    def __init__(self, aws):
        self.aws = aws

    def describe_savings_plans(self, **kw):
        return {"savingsPlans": self.aws.savings_plans}


class FakeRDS:
    def __init__(self, aws):
        self.aws = aws

    def describe_reserved_db_instances(self, **kw):
        return {"ReservedDBInstances": []}


class FakeEKS:
    def __init__(self, aws):
        self.aws = aws

    def list_clusters(self, **kw):
        return {"clusters": [c["name"] for c in self.aws.clusters]}

    def describe_cluster(self, name):
        return {"cluster": next(c for c in self.aws.clusters if c["name"] == name)}


class FakeEC2:
    def __init__(self, aws):
        self.aws = aws

    def get_paginator(self, op):
        return {"describe_volumes": _Pag(lambda: self.aws.volumes, "Volumes"),
                "describe_instances": _Pag(lambda: [], "Reservations")}[op]

    def describe_reserved_instances(self):
        return {"ReservedInstances": self.aws.reserved}

    def describe_addresses(self):
        return {"Addresses": []}


class FakeELB:
    def __init__(self, aws):
        self.aws = aws

    def get_paginator(self, op):
        return _Pag(lambda: [], "LoadBalancers")


PRICES = {"ebs": {"gp3": 0.088}, "ipv4_month": 3.65, "alb_month": 18.4, "nlb_month": 18.4}


def ingest(conn, account, aws):
    """Like the async scanner: claim the run the API reserved, or start a scheduled one."""
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM cost_ingestions WHERE cloud_account_id = %s AND status = 'running' AND claimed_at IS NULL", (account,))
        row = cur.fetchone()
    conn.commit()
    with patch.object(S, "region_prices", return_value=PRICES), patch.object(S, "_send"):
        return S.run(_NoClose(conn), account, aws, "manual", "owner@a.test", ingestion_id=str(row[0]) if row else None)


def test_a_reserved_run_is_claimed_once(conn, world):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO cost_ingestions (cloud_account_id, trigger) VALUES (%s, 'manual') RETURNING id", (world["b"],))
        rid = str(cur.fetchone()[0])
    conn.commit()
    with patch.object(S, "region_prices", return_value=PRICES), patch.object(S, "_send"):
        first = S.run(_NoClose(conn), world["b"], FakeAWS(), "manual", None, ingestion_id=rid)
        second = S.run(_NoClose(conn), world["b"], FakeAWS(), "manual", None, ingestion_id=rid)
    assert first["status"] in ("succeeded", "partial") and second["status"] == "skipped"


def call(conn, email, method="GET", qs=None, body=None):
    event = {"httpMethod": method, "headers": {"Authorization": "Bearer t"}, "queryStringParameters": qs,
             "body": json.dumps(body) if body is not None else None}
    with patch.object(H, "_get_connection", return_value=_NoClose(conn)), \
            patch("collectors.aws.scanner.tenant_auth.authenticate", return_value=email), \
            patch.object(H, "authenticate", return_value=email), \
            patch.object(H, "_start_refresh") as start:
        r = H.handler(event, None)
    try:
        return r["statusCode"], json.loads(r["body"]), start
    except ValueError:
        return r["statusCode"], r["body"], start


# ── tests ───────────────────────────────────────────────────────────────────

def test_paid_ingestion_needs_explicit_opt_in_by_a_writer(conn, world):
    s, b, start = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "enable"})
    assert s == 400 and "$0.01" in b["error"] and not start.called
    s, _, _ = call(conn, "viewer@a.test", "POST", body={"cloud_account_id": world["a"], "action": "enable", "accept_charges": True})
    assert s == 403
    s, b, start = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "enable", "accept_charges": True})
    assert s == 200 and start.called
    s, _, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "save_settings",
                                                       "allocation_tag_key": "team", "anomaly_min_amount": 5})
    assert s == 200
    s, _, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "create_budget",
                                                       "name": "Monthly", "monthly_amount": 100, "thresholds": [50, 100]})
    assert s == 200


def test_scanner_refuses_accounts_without_opt_in(conn, world):
    with patch.object(S, "_get_connection", return_value=_NoClose(conn)):
        r = S.handler({"cloud_account_id": world["b"]}, None)
    assert r["statusCode"] == 409


def test_ingestion_stores_costs_alerts_and_opportunities(conn, world):
    aws = FakeAWS()
    r = ingest(conn, world["a"], aws)
    assert r["status"] == "succeeded", r
    # 7 base requests + 2 purchase recommendations (there is EC2 compute usage)
    assert r["ce_requests"] == aws.ce_calls == 9
    s, ov, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "overview"})
    assert s == 200
    assert ov["summary"]["by_service"][0]["service"] == "Amazon Elastic Compute Cloud - Compute"
    assert ov["forecast"]["remaining_month"] == 400 and "AWS Cost Explorer forecast" in ov["forecast"]["basis"]
    assert ov["allocation"]["unallocated"] == 5 and ov["allocation"]["unallocated_pct"] == 25
    assert ov["opportunities"]["monthly_savings_known"] == 8.8
    assert ov["latest_ingestion"]["coverage"]["commitments"]["savings_plans"] == "no_data"
    assert ov["latest_ingestion"]["coverage"]["rightsizing"]["state"] == "not_enabled"
    s, al, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "alerts"})
    kinds = sorted(a["kind"] for a in al["alerts"])
    assert "anomaly" in kinds and "budget_forecast" in kinds
    # Re-ingesting the same data creates no duplicate alerts.
    ingest(conn, world["a"], aws)
    s, al2, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "alerts"})
    assert len(al2["alerts"]) == len(al["alerts"])


def test_late_billing_adjustment_is_kept_as_a_revision(conn, world):
    aws = FakeAWS()
    d = (TODAY - timedelta(days=3)).isoformat()
    aws.daily[(d, "Amazon Simple Storage Service", "Usage")] = 1.25
    del aws.daily[((TODAY - timedelta(days=2)).isoformat(), "Tax", "Tax")]
    ingest(conn, world["a"], aws)
    s, b, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "ingestions"})
    revs = {(r["service"], r["old"], r["new"]) for r in b["revisions"]}
    assert ("Amazon Simple Storage Service", 1.0, 1.25) in revs and ("Tax", 3.0, 0.0) in revs
    s, csv_text, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "export", "what": "daily", "format": "csv"})
    assert s == 200 and "estimated" in csv_text.splitlines()[0]


def test_opportunity_needs_two_people_and_is_verified_by_the_next_ingestion(conn, world):
    s, b, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "opportunities"})
    opp = b["opportunities"][0]
    oid = opp["id"]
    assert opp["kind"] == "idle_ebs" and opp["status"] == "observed"
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "mark_executed", "opportunity_id": oid, "note": "x"})[0] == 409
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "request_approval", "opportunity_id": oid})[0] == 200
    s, b, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "decide_opportunity", "opportunity_id": oid, "decision": "approve"})
    assert s == 403
    assert call(conn, "admin2@a.test", "POST", body={"cloud_account_id": world["a"], "action": "decide_opportunity", "opportunity_id": oid, "decision": "approve"})[0] == 200
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "mark_executed", "opportunity_id": oid, "note": "Deleted after snapshot"})[0] == 200
    # Still there at the next ingestion -> not verified, back to approved, visible in history.
    aws = FakeAWS()
    ingest(conn, world["a"], aws)
    s, o, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "opportunity", "opportunity_id": oid})
    assert o["status"] == "approved" and "opportunity_verification_failed" in [h["action"] for h in o["history"]]
    call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "mark_executed", "opportunity_id": oid, "note": "Really deleted"})
    aws.volumes = []
    ingest(conn, world["a"], aws)
    s, o, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "opportunity", "opportunity_id": oid})
    assert o["status"] == "verified" and o["verified_at"] and o["baseline_monthly"] == 8.8
    s, ov, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "overview"})
    assert ov["opportunities"]["verified_monthly_savings"] == 8.8


def test_attached_volume_is_not_a_verified_saving(conn, world):
    """A resource that is no longer idle but still exists (and is still billed) never verifies a saving."""
    aws = FakeAWS()
    aws.volumes = [{"VolumeId": "vol-9", "State": "available", "Size": 10, "VolumeType": "gp3"}]
    ingest(conn, world["a"], aws)
    s, b, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "opportunities"})
    oid = next(o["id"] for o in b["opportunities"] if o["resource_id"] == "vol-9")
    call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "request_approval", "opportunity_id": oid})
    call(conn, "admin2@a.test", "POST", body={"cloud_account_id": world["a"], "action": "decide_opportunity", "opportunity_id": oid, "decision": "approve"})
    call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "mark_executed", "opportunity_id": oid, "note": "done"})
    aws.volumes = [{"VolumeId": "vol-9", "State": "in-use", "Size": 10, "VolumeType": "gp3"}]
    ingest(conn, world["a"], aws)
    s, o, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "opportunity", "opportunity_id": oid})
    assert o["status"] == "approved" and o["verified_at"] is None


def test_enable_twice_starts_one_paid_run(conn, world):
    with conn.cursor() as cur:
        cur.execute("UPDATE cost_ingestions SET status = 'succeeded', finished_at = NOW() WHERE cloud_account_id = %s", (world["a"],))
    conn.commit()
    s, b, start = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "enable", "accept_charges": True})
    assert s == 200 and "already on" in b["note"] and not start.called


def test_alert_workflow_and_audit(conn, world):
    s, al, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "alerts"})
    aid = al["alerts"][0]["id"]
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "resolve_alert", "alert_id": aid})[0] == 400
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "acknowledge_alert", "alert_id": aid})[0] == 200
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "resolve_alert", "alert_id": aid, "note": "Expected batch job"})[0] == 200
    s, au, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "audit"})
    actions = [a["action"] for a in au["audit"]]
    for x in ("enable_cost_ingestion", "create_budget", "acknowledge_alert", "resolve_alert", "opportunity_decide_opportunity", "export"):
        assert x in actions, x
    with conn.cursor() as cur:
        cur.execute("SELECT has_table_privilege('cspm_lambda', 'cost_audit_log', 'UPDATE'), has_table_privilege('cspm_lambda', 'cost_daily_revisions', 'DELETE')")
        assert cur.fetchone() == (False, False)


def test_refresh_is_rate_limited(conn, world):
    with conn.cursor() as cur:
        cur.execute("UPDATE cost_ingestions SET status = 'succeeded' WHERE cloud_account_id = %s", (world["a"],))
    conn.commit()
    s, b, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "refresh"})
    assert s == 429  # manual ingestions just ran in this test module


def test_tenant_isolation_and_portfolio(conn, world):
    s, _, _ = call(conn, "other@b.test", qs={"cloud_account_id": world["a"], "view": "overview"})
    assert s == 403
    s, b, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "opportunities"})
    oid = b["opportunities"][0]["id"]
    s, _, _ = call(conn, "other@b.test", "POST", body={"cloud_account_id": world["b"], "action": "dismiss", "opportunity_id": oid, "reason": "x"})
    assert s == 403
    s, b, _ = call(conn, "admin2@a.test", qs={"view": "portfolio"})
    assert [(a["account_name"], a["business_units"]) for a in b["accounts"]] == [("A", "Payments")]
    assert b["accounts"][0]["month_to_date"] is not None


def test_ai_and_kubernetes_views_state_their_limits(conn, world):
    s, b, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "ai"})
    assert s == 200 and b["summary"]["month_to_date"] == 0 and b["limitations"]
    s, b, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "kubernetes"})
    assert s == 200 and "namespace" in b["limitations"][0]


def test_bad_input(conn, world):
    for body in ({"action": "create_budget", "name": "x", "monthly_amount": -1},
                 {"action": "create_budget", "name": "x", "monthly_amount": 5, "thresholds": [500]},
                 {"action": "save_settings", "allocation_tag_key": "<script>"},
                 {"action": "nope"}):
        s, _, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], **body})
        assert s == 400, body
    assert call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "explorer", "from": "2026-01-01", "to": "2025-01-01"})[0] == 400



def test_commitments_expiry_purchase_proposal_and_verification(conn, world):
    aws = FakeAWS()
    soon = (datetime.now(timezone.utc) + timedelta(days=20)).isoformat()
    aws.savings_plans = [{"savingsPlanId": "sp-old", "savingsPlanType": "Compute", "state": "active", "start": "2025-12-01T00:00:00Z",
                          "end": soon, "commitment": "0.10", "currency": "USD", "paymentOption": "No Upfront", "termDurationInSeconds": 31536000}]
    ingest(conn, world["a"], aws)
    s, c, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "commitments"})
    assert c["inventory"][0]["id"] == "sp-old" and c["inventory"][0]["days_left"] in (19, 20)
    assert c["recommendations"]["savings_plans"]["estimated_monthly_savings"] == 21.5
    assert c["recommendations"]["reservations"]["available"] is False
    s, al, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "alerts"})
    assert any(a["kind"] == "commitment_expiry" and "sp-old" in a["title"] for a in al["alerts"])
    s, b, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "propose_commitment_purchase", "which": "savings_plans"})
    assert s == 200
    oid = b["opportunity_id"]
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "propose_commitment_purchase", "which": "savings_plans"})[0] == 409
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "propose_commitment_purchase", "which": "reservations"})[0] == 409
    call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "request_approval", "opportunity_id": oid})
    call(conn, "admin2@a.test", "POST", body={"cloud_account_id": world["a"], "action": "decide_opportunity", "opportunity_id": oid, "decision": "approve"})
    call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "mark_executed", "opportunity_id": oid, "note": "Bought in console"})
    ingest(conn, world["a"], aws)  # nothing new bought yet
    s, o, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "opportunity", "opportunity_id": oid})
    assert o["status"] == "executed"
    aws.savings_plans = aws.savings_plans + [{"savingsPlanId": "sp-new", "savingsPlanType": "Compute", "state": "active",
                                               "start": (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat(),  # bought after approval
                                               "end": "2027-11-17T00:00:00Z", "commitment": "0.12", "termDurationInSeconds": 31536000}]
    ingest(conn, world["a"], aws)
    s, o, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "opportunity", "opportunity_id": oid})
    assert o["status"] == "verified"


def test_ai_cost_per_model_and_eks_clusters(conn, world):
    aws = FakeAWS()
    d = (TODAY - timedelta(days=3)).isoformat()
    aws.daily[(d, "Amazon Bedrock", "Usage")] = 6.0
    aws.daily[(d, "Amazon Elastic Container Service for Kubernetes", "Usage")] = 2.4
    aws.clusters = [{"name": "prod", "status": "ACTIVE", "version": "1.31"}]
    orig = FakeCE.get_cost_and_usage

    def with_usage_types(self, TimePeriod, Granularity, Metrics, GroupBy, **kw):
        if [g["Key"] for g in GroupBy] == ["SERVICE", "USAGE_TYPE"]:
            self.aws.ce_calls += 1
            assert kw["Filter"]["Dimensions"]["Values"] == ["Amazon Bedrock"]
            return {"ResultsByTime": [{"TimePeriod": {"Start": TODAY.replace(day=1).isoformat()}, "Estimated": True, "Groups": [
                {"Keys": ["Amazon Bedrock", "EUC1-Claude3Haiku-input-tokens"],
                 "Metrics": {"UnblendedCost": {"Amount": "4", "Unit": "USD"}, "UsageQuantity": {"Amount": "1600000", "Unit": "Tokens"}}},
                {"Keys": ["Amazon Bedrock", "EUC1-Claude3Haiku-output-tokens"],
                 "Metrics": {"UnblendedCost": {"Amount": "2", "Unit": "USD"}, "UsageQuantity": {"Amount": "160000", "Unit": "Tokens"}}}]}]}
        if GroupBy[0]["Type"] == "TAG" and GroupBy[0]["Key"] == "aws:eks:cluster-name":
            self.aws.ce_calls += 1
            return {"ResultsByTime": [{"TimePeriod": {"Start": d}, "Estimated": False, "Groups": [
                {"Keys": ["aws:eks:cluster-name$prod"], "Metrics": {"UnblendedCost": {"Amount": "2.4", "Unit": "USD"}}}]}]}
        return orig(self, TimePeriod, Granularity, Metrics, GroupBy, **kw)
    with patch.object(FakeCE, "get_cost_and_usage", with_usage_types):
        ingest(conn, world["a"], aws)
    s, ai, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "ai"})
    assert ai["by_model"][0] == {"model": "Claude3Haiku", "amount": 6.0}
    assert {r["direction"] for r in ai["by_usage_type"]} == {"input tokens", "output tokens"}
    s, k8, _ = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "view": "kubernetes"})
    assert k8["clusters"][0]["name"] == "prod" and k8["cost_by_cluster"][0]["cluster"] == "prod"
