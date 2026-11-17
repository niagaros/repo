"""Cloud Cost engine (#295): normalisation keeps record types and estimates apart, anomalies need real history,
idle-resource savings come only from a known list price, opportunity lifecycle never verifies without evidence."""
from datetime import date, datetime, timedelta, timezone

import pytest

from collectors.aws.scanner import cost_engine as E

pytestmark = [pytest.mark.flow("E2E-COST-001"), pytest.mark.severity("P1")]

TODAY = date(2026, 11, 16)


def _period(day, groups, estimated=False):
    return {"TimePeriod": {"Start": day, "End": day}, "Estimated": estimated,
            "Groups": [{"Keys": list(k), "Metrics": {"UnblendedCost": {"Amount": str(a), "Unit": "USD"}}} for k, a in groups]}


def test_normalize_keeps_record_types_and_estimates_and_drops_zero():
    recs = E.normalize_daily([_period("2026-11-14", [(("Amazon S3", "Usage"), 1.5), (("Tax", "Tax"), 0.3), (("AWS KMS", "Usage"), 0)], True)])
    assert recs == [{"day": "2026-11-14", "service": "Amazon S3", "record_type": "Usage", "amount": 1.5, "currency": "USD", "estimated": True},
                    {"day": "2026-11-14", "service": "Tax", "record_type": "Tax", "amount": 0.3, "currency": "USD", "estimated": True}]


def test_untagged_spend_stays_unallocated():
    rows = E.normalize_tag_daily([_period("2026-11-01", [(("team$",), 4.0), (("team$payments",), 6.0)])], "team")
    assert {r["tag_value"]: r["amount"] for r in rows} == {"": 4.0, "payments": 6.0}


def test_revisions_are_detected():
    revs = E.diff_records({("2026-11-01", "S3", "Usage"): 1.0}, [{"day": "2026-11-01", "service": "S3", "record_type": "Usage", "amount": 1.2}])
    assert revs == [{"key": ("2026-11-01", "S3", "Usage"), "old": 1.0, "new": 1.2}]


def test_summary_splits_month_previous_month_and_types():
    recs = [{"day": "2026-11-02", "service": "S3", "record_type": "Usage", "amount": 10, "estimated": False, "currency": "USD"},
            {"day": "2026-11-02", "service": "Tax", "record_type": "Tax", "amount": 2, "estimated": False, "currency": "USD"},
            {"day": "2026-11-03", "service": "S3", "record_type": "Credit", "amount": -3, "estimated": True, "currency": "USD"},
            {"day": "2026-10-31", "service": "S3", "record_type": "Usage", "amount": 7, "estimated": False, "currency": "USD"}]
    s = E.summarize(recs, TODAY)
    assert s["month_to_date"] == 9 and s["month_to_date_usage"] == 10 and s["previous_month"] == 7
    assert {r["record_type"] for r in s["by_record_type"]} == {"Usage", "Tax", "Credit"}
    assert s["estimated_days"] == 1 and s["latest_day_with_data"] == "2026-11-03"


def _series(svc, values, end=TODAY):
    return [{"day": (end - timedelta(days=len(values) - i)).isoformat(), "service": svc, "record_type": "Usage",
             "amount": v, "estimated": False} for i, v in enumerate(values)]


def test_anomaly_needs_a_real_jump_and_history():
    steady = _series("EC2", [10, 11, 9, 10, 10, 11, 9, 10, 10, 11, 9, 10, 10, 11, 10, 60])
    a = E.detect_anomalies(steady, min_amount=5, today=TODAY)
    assert len(a) == 1 and a[0]["service"] == "EC2" and a[0]["actual"] == 60 and a[0]["expected"] < 11
    assert not E.detect_anomalies(_series("EC2", [10, 60]), today=TODAY), "too little history"
    small = _series("S3", [0.1] * 15 + [2.0])
    assert not E.detect_anomalies(small, min_amount=5, today=TODAY), "below the minimum amount"
    tax = [{**r, "record_type": "Tax"} for r in steady]
    assert not E.detect_anomalies(tax, today=TODAY), "tax lines are not usage"


def test_budget_thresholds_and_forecast():
    ev = E.evaluate_budget({"monthly_amount": 100, "thresholds": [50, 80, 100], "forecast_alert": True}, 85, 130)
    assert ev["crossed"] == [50, 80] and ev["forecast_over"] is True and ev["remaining"] == 15
    assert E.evaluate_budget({"monthly_amount": 100, "thresholds": [80], "forecast_alert": True}, 10, None)["forecast_over"] is False


NOW = datetime(2026, 11, 16, tzinfo=timezone.utc)
PRICES = {"ebs": {"gp3": 0.088}, "ipv4_month": 3.65, "alb_month": 18.4, "nlb_month": 18.4}


def test_idle_resources_with_and_without_known_prices():
    vols = [{"VolumeId": "vol-1", "State": "available", "Size": 100, "VolumeType": "gp3", "CreateTime": NOW - timedelta(days=40)},
            {"VolumeId": "vol-2", "State": "available", "Size": 10, "VolumeType": "io2"},
            {"VolumeId": "vol-3", "State": "in-use", "Size": 8, "VolumeType": "gp3"}]
    addrs = [{"AllocationId": "eipalloc-1", "PublicIp": "1.2.3.4"}, {"AllocationId": "eipalloc-2", "AssociationId": "x"}]
    insts = [{"InstanceId": "i-1", "InstanceType": "t3.micro", "State": {"Name": "stopped"},
              "StateTransitionReason": "User initiated (2026-09-01 10:00:00 GMT)",
              "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-3"}}]},
             {"InstanceId": "i-2", "State": {"Name": "stopped"}, "StateTransitionReason": "User initiated (2026-11-10 10:00:00 GMT)"}]
    lbs = [{"LoadBalancerArn": "arn:lb/1", "LoadBalancerName": "old", "Type": "application"},
           {"LoadBalancerArn": "arn:lb/2", "LoadBalancerName": "unknown", "Type": "application"}]
    out = {o["resource_id"]: o for o in E.find_idle("eu-west-1", vols, addrs, insts, lbs, {"arn:lb/1": 0, "arn:lb/2": None}, PRICES, NOW)}
    assert out["vol-1"]["monthly_savings"] == 8.8 and "list price" in out["vol-1"]["savings_basis"]
    assert out["vol-2"]["monthly_savings"] is None and "unknown" in out["vol-2"]["savings_basis"]
    assert "vol-3" not in out and "eipalloc-2" not in out
    assert out["eipalloc-1"]["monthly_savings"] == 3.65
    assert out["i-1"]["monthly_savings"] == round(0.088 * 8, 2) and out["i-1"]["detail"]["stopped_days"] == 75
    assert "i-2" not in out, "stopped for less than 14 days"
    assert "arn:lb/1" in out and "arn:lb/2" not in out, "unknown target health is never called idle"


@pytest.mark.parametrize("status,idle,exists,expected", [
    ("executed", False, False, ("verified", "verified_by_ingestion")),
    ("executed", False, True, ("approved", "verification_failed")),   # attached / started again: still billed
    ("executed", True, True, ("approved", "verification_failed")),
    ("observed", False, False, ("gone", "resource_no_longer_found")),
    ("observed", False, True, ("gone", "no_longer_idle")),
    ("gone", True, True, ("observed", "found_again")),
    ("dismissed", False, False, ("dismissed", None)),
    ("verified", True, True, ("verified", None)),
])
def test_opportunity_lifecycle(status, idle, exists, expected):
    assert E.opportunity_transition(status, idle, exists) == expected


def test_inventory_lists_every_resource_not_only_idle_ones():
    ids = E.inventory_ids([{"VolumeId": "vol-1"}], [{"AllocationId": "e1", "AssociationId": "x"}],
                          [{"InstanceId": "i-1", "State": {"Name": "running"}}, {"InstanceId": "i-2", "State": {"Name": "terminated"}}],
                          [{"LoadBalancerArn": "arn:lb"}])
    assert ids == {"vol-1", "e1", "i-1", "arn:lb"}


def test_aws_anomalies_are_normalised():
    a = E.normalize_aws_anomalies({"Anomalies": [{"AnomalyId": "x", "AnomalyStartDate": "2026-11-12", "DimensionValue": "S3",
                                                  "Impact": {"TotalImpact": 4.2, "MaxImpact": 2}, "RootCauses": [{"Service": "S3", "Region": "eu-west-1"}]}]})
    assert a[0]["impact"] == 4.2 and a[0]["root_causes"][0]["Region"] == "eu-west-1"


def test_commitment_inventory_and_expiry_windows():
    today = date(2026, 11, 17)
    items = E.commitment_inventory(
        [{"savingsPlanId": "sp1", "savingsPlanType": "Compute", "state": "active", "start": "2025-11-20T00:00:00Z", "end": "2026-12-10T00:00:00Z",
          "commitment": "0.1", "termDurationInSeconds": 31536000}],
        [{"ReservedInstancesId": "ri1", "InstanceType": "t3.micro", "State": "retired", "Start": "2024-01-01T00:00:00Z",
          "End": "2026-11-20T00:00:00Z", "InstanceCount": 1, "Duration": 31536000, "_region": "eu-west-1"}],
        [{"ReservedDBInstanceId": "db1", "DBInstanceClass": "db.t3.micro", "State": "active", "StartTime": "2026-01-01T00:00:00Z",
          "Duration": 31536000, "DBInstanceCount": 1, "_region": "eu-west-1"}], today)
    by = {i["id"]: i for i in items}
    assert by["sp1"]["days_left"] == 23 and by["db1"]["end"] == date(2027, 1, 1)
    alerts = {a["id"]: a["window"] for a in E.expiry_alerts(items)}
    assert alerts == {"sp1": 30, "db1": 60}, "retired ri1 is never warned about; each active one in its smallest window"


def test_ai_usage_types_are_read_not_guessed():
    d = E.describe_ai_usage_type("EUC1-Claude3Haiku-input-tokens")
    assert d == {"model": "Claude3Haiku", "direction": "input tokens", "basis": "parsed from the AWS usage type"}
    assert E.describe_ai_usage_type("USE1-TitanEmbeddings-output-tokens")["direction"] == "output tokens"
    assert E.describe_ai_usage_type("SomethingElse")["model"] == "SomethingElse"


def test_recommendations_without_data_say_so():
    assert E.normalize_sp_recommendation({})["available"] is False
    assert E.normalize_ri_recommendation({"Recommendations": []})["available"] is False


def test_purchase_is_only_verified_by_a_matching_new_commitment():
    done = datetime(2026, 11, 17, 18, 0, tzinfo=timezone.utc)  # approval time
    items = [{"kind": "rds_reservation", "id": "db-morning", "state": "active", "start_ts": "2026-11-17T09:00:00Z"},
             {"kind": "savings_plan", "id": "sp-morning", "state": "active", "start_ts": "2026-11-17T09:00:00Z"},
             {"kind": "savings_plan", "id": "sp-evening", "state": "active", "start_ts": "2026-11-17T18:05:00Z"},
             {"kind": "savings_plan", "id": "sp-queued", "state": "queued", "start_ts": "2026-11-18T00:00:00Z"}]
    assert E.match_purchase("savings_plans", done, items, set())["id"] == "sp-evening"
    assert E.match_purchase("savings_plans", done, items, {"sp-evening"}) is None, "one commitment verifies one purchase"
    assert E.match_purchase("reservations", done, items, set()) is None, "an RDS reservation never verifies an EC2 one"
