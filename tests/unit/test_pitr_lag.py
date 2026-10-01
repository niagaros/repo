"""RPO rules (RDS.DR.4, DynamoDB.DR.3) must measure point-in-time-recovery lag against the
moment AWS answered, and must never turn missing or untrustworthy timestamps into a PASS."""
import datetime as dt

import pytest

from rules.cis.dynamodb.dynamodb_dr_3 import DynamoDB_DR_3
from rules.cis.rds.rds_dr_4 import RDS_DR_4

pytestmark = [pytest.mark.flow("E2E-INFRA-001"), pytest.mark.severity("P2")]

OBSERVED = dt.datetime(2026, 10, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
RULES = [RDS_DR_4(), DynamoDB_DR_3()]


def _resource(lag_seconds=None, observed=True, naive=False):
    config = {}
    if lag_seconds is not None:
        restorable = OBSERVED - dt.timedelta(seconds=lag_seconds)
        if naive:
            restorable = restorable.replace(tzinfo=None)
        config["latest_restorable_time"] = restorable.isoformat()
    if observed:
        config["observed_at"] = OBSERVED.isoformat()
    return {"config": config}


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.get_metadata()["check_id"])
@pytest.mark.parametrize("lag,expected", [(0, "PASS"), (192, "PASS"), (300, "PASS"), (301, "FAIL"), (3600, "FAIL")])
def test_lag_is_measured_against_api_response(rule, lag, expected):
    result = rule.run(_resource(lag))
    assert result.status == expected
    assert result.details["measured_rpo_seconds"] == lag
    assert result.details["measured_from"] == "api_response"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.get_metadata()["check_id"])
@pytest.mark.parametrize("resource", [
    _resource(None),                 # no restore point: PITR off
    _resource(100, naive=True),      # timestamp without timezone
    _resource(-600),                 # restore point 10 minutes in the future
], ids=["missing", "naive", "future"])
def test_untrustworthy_evidence_fails(rule, resource):
    assert rule.run(resource).status == "FAIL"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.get_metadata()["check_id"])
def test_small_clock_skew_is_tolerated(rule):
    result = rule.run(_resource(-20))
    assert result.status == "PASS"
    assert result.details["measured_rpo_seconds"] == 0


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.get_metadata()["check_id"])
def test_old_config_without_observed_at_falls_back_to_now(rule):
    # Restore point long before "now": the fallback may only overstate the lag.
    result = rule.run(_resource(10, observed=False))
    assert result.status == "FAIL"
    assert result.details["measured_from"] == "rule_execution"
