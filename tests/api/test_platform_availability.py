"""Platform availability — the independent public status endpoint, and the production smoke set."""
import pytest

pytestmark = [pytest.mark.live, pytest.mark.flow("E2E-PLAT-001"), pytest.mark.severity("P0")]


@pytest.fixture(scope="module")
def status_payload(anon):
    s, b, _ = anon.get("status")
    assert s == 200, f"status endpoint answered {s}"
    return b


def test_platform_is_reported_operational(status_payload):
    assert status_payload["overall_status"] == "operational", status_payload


def test_database_is_available_and_queue_backlog_is_healthy(status_payload):
    assert status_payload["database"]["status"] == "operational", status_payload["database"]
    assert status_payload["notification_queue"]["status"] == "operational", status_payload["notification_queue"]


def test_every_business_critical_lambda_is_monitored_and_not_failing(status_payload):
    expected = {"get-dashboard-data", "notification-handler", "questionnaire-handler",
                "ai-agent-handler", "tprm-handler", "audit-management-handler"}
    lam = status_payload["lambdas"]
    names = {x["name"] for x in lam} if isinstance(lam, list) else set(lam)
    assert expected <= names, f"unmonitored: {expected - names}"
    rows = lam if isinstance(lam, list) else [dict(name=k, **v) for k, v in lam.items()]
    assert not [r["name"] for r in rows if r.get("status") not in ("operational", "no_recent_activity")], rows


def test_status_check_is_fresh(status_payload):
    from datetime import datetime, timezone
    checked = datetime.fromisoformat(status_payload["checked_at"])
    assert (datetime.now(timezone.utc) - checked).total_seconds() < 120
