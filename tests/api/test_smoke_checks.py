"""Production smoke: the checks themselves pass against the real platform, and the AWS-side schedule really runs
(a stored smoke run must be recent, and the two EventBridge rules must exist)."""
import os
from datetime import datetime, timezone

import pytest

from conftest import ROOT  # noqa: F401
from collectors.aws.scanner import smoke_handler

pytestmark = [pytest.mark.live, pytest.mark.flow("E2E-SMOKE-001"), pytest.mark.severity("P0")]
INGEST = os.environ.get("E2E_INGEST_TOKEN", "")


def test_every_smoke_check_passes_against_production():
    bad = [c for c in smoke_handler.run_checks() if not c["ok"]]
    assert not bad, bad


@pytest.mark.skipif(not INGEST, reason="blocked: E2E_INGEST_TOKEN not set")
def test_the_scheduled_smoke_run_is_recent(anon):
    s, b, _ = anon.get("test-results", headers={"X-Ingest-Token": INGEST})
    assert s == 200 and b["smoke"], "no smoke run has ever been stored"
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(str(b["smoke"]["run_at"]).replace("Z", "+00:00"))).total_seconds()
    assert age < 45 * 60, f"the last smoke run is {int(age / 60)} minutes old; the 30-minute schedule is not running"


def test_the_schedule_and_the_after_deployment_trigger_exist_and_are_enabled():
    boto3 = pytest.importorskip("boto3")
    try:
        ev = boto3.client("events", region_name="eu-west-1")
        rules = {r["Name"]: r for r in ev.list_rules(NamePrefix="niagaros-smoke")["Rules"]}
    except Exception as e:
        pytest.skip(f"blocked: needs AWS credentials to read the EventBridge rules ({type(e).__name__})")
    assert rules["niagaros-smoke-schedule"]["State"] == "ENABLED" and rules["niagaros-smoke-schedule"]["ScheduleExpression"] == "rate(30 minutes)"
    assert rules["niagaros-smoke-after-deploy"]["State"] == "ENABLED" and "Amplify Deployment Status Change" in rules["niagaros-smoke-after-deploy"]["EventPattern"]
