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
