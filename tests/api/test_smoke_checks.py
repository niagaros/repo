"""Production smoke: the AWS-side schedule really runs, its real result is healthy, and it stays fresh.

These tests deliberately read the result of the check that ALREADY ran for real inside AWS (via the ingest
token, which needs no AWS credentials) rather than re-running smoke_handler.run_checks() locally — a local
re-run would need its own AWS credentials, which CI does not have, and would only prove the CI runner's own
network/IAM reach, not the thing this flow actually needs to prove: that the real, scheduled, in-AWS check
is healthy right now."""
import os
from datetime import datetime, timezone

import pytest

from conftest import ROOT  # noqa: F401

pytestmark = [pytest.mark.live, pytest.mark.flow("E2E-SMOKE-001"), pytest.mark.severity("P0")]
INGEST = os.environ.get("E2E_INGEST_TOKEN", "")
needs_ingest = pytest.mark.skipif(not INGEST, reason="blocked: E2E_INGEST_TOKEN not set")


@needs_ingest
def test_the_real_scheduled_smoke_run_is_healthy(anon):
    s, b, _ = anon.get("test-results", headers={"X-Ingest-Token": INGEST})
    assert s == 200 and b["smoke"], "no smoke run has ever been stored"
    smoke = b["smoke"]
    assert smoke["totals"]["failed"] == 0, smoke["failing"]


@needs_ingest
def test_the_scheduled_smoke_run_is_recent(anon):
    s, b, _ = anon.get("test-results", headers={"X-Ingest-Token": INGEST})
    assert s == 200 and b["smoke"], "no smoke run has ever been stored"
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(str(b["smoke"]["run_at"]).replace("Z", "+00:00"))).total_seconds()
    assert age < 45 * 60, f"the last smoke run is {int(age / 60)} minutes old; the 30-minute schedule is not running"


def test_the_smoke_checks_also_pass_when_run_directly_with_real_aws_access():
    """Local/admin-only: proves the checks work standalone too (not just as deployed), using real credentials."""
    boto3 = pytest.importorskip("boto3")
    try:
        boto3.client("sts", region_name="eu-west-1").get_caller_identity()
    except Exception as e:
        pytest.skip(f"blocked: needs AWS credentials to run the checks directly ({type(e).__name__})")
    from collectors.aws.scanner import smoke_handler
    bad = [c for c in smoke_handler.run_checks() if not c["ok"]]
    assert not bad, bad


def test_the_schedule_and_the_after_deployment_trigger_exist_and_are_enabled():
    boto3 = pytest.importorskip("boto3")
    try:
        ev = boto3.client("events", region_name="eu-west-1")
        rules = {r["Name"]: r for r in ev.list_rules(NamePrefix="niagaros-smoke")["Rules"]}
    except Exception as e:
        pytest.skip(f"blocked: needs AWS credentials to read the EventBridge rules ({type(e).__name__})")
    assert rules["niagaros-smoke-schedule"]["State"] == "ENABLED" and rules["niagaros-smoke-schedule"]["ScheduleExpression"] == "rate(30 minutes)"
    assert rules["niagaros-smoke-after-deploy"]["State"] == "ENABLED" and "Amplify Deployment Status Change" in rules["niagaros-smoke-after-deploy"]["EventPattern"]
