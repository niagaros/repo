"""The coverage dashboard renders exactly what the API returns (Admin-only data stored in the database)."""
import json
import re

import pytest

from conftest import ROOT
from ui_support import CORS

pytestmark = [pytest.mark.flow("E2E-UI-002"), pytest.mark.severity("P2")]
REGISTRY = json.loads((ROOT / "tests" / "registry" / "critical_flows.json").read_text(encoding="utf-8"))["flows"]


def _run():
    flows = [{**f, "automated": f["exists"], "status": "passing" if f["exists"] else "not_built", "tests": 2, "passed": 2, "failed": 0,
              "known_failures": 0, "blocked": 0, "flaky": 0, "duration_s": 1.5, "last_run": "2026-09-21T10:00:00Z",
              "failure_count_history": 3} for f in REGISTRY]
    return {"run_at": "2026-09-21T10:00:00Z", "commit": "abc1234", "branch": "b", "trigger": "ci", "environment": {"token_provided": True},
            "full_run_duration_s": 12.5,
            "totals": {"critical_flows_in_inventory": len(flows), "flows_that_exist_in_product": 1, "flows_automated": 1,
                       "coverage_of_inventory_pct": 42.5, "coverage_of_existing_flows_pct": 77.7, "tests": 123, "passed": 120,
                       "failed": 1, "known_failure": 2, "blocked": 0, "skipped": 0, "flaky": 0},
            "by_severity": {"P0": {"flows": 2, "automated": 1, "coverage_pct": 50, "passing": 1, "known_defect": 0, "failing": 1}},
            "flows": flows, "flaky_tests": [],
            "failures": [{"test_id": "tests/api/x.py::test_y", "flow": "E2E-X-001", "severity": "P0", "status": "failed", "layer": "api",
                          "failed_step": "step 7 - status update", "message": "assert 'open' == 'resolved'", "commit": "abc1234",
                          "request_id": "req-123", "screenshot": "screenshots/test_y.png",
                          "last_exchange": {"request": {"method": "GET", "url": "https://x/default/tprm?cloud_account_id=1"}, "response": {"status": 500, "body": "boom"}}}]}


def _open(page, site, status, payload):
    page.route("**/default/test-results**", lambda r: r.fulfill(status=status, headers=CORS, content_type="application/json", body=json.dumps(payload)))
    page.goto(f"{site}/test_dashboard.html")


def test_dashboard_shows_the_numbers_and_failure_diagnostics_from_the_api(page, site):
    _open(page, site, 200, {"run": _run(), "history": [{"run_at": "2026-09-21T10:00:00Z", "trigger": "ci", "commit": "abc1234", "tests": 123, "passed": 120, "failed": 1}],
                            "failure_counts": {}, "flaky_by_history": ["tests/api/x.py::test_flaky"],
                            "failure_history": {"tests/api/x.py::test_y": ["2026-09-20T10:00:00Z", "2026-09-19T10:00:00Z"]},
                            "smoke": {"run_at": "2026-09-21T10:05:00Z", "trigger_detail": "amplify:sofyan-dev#11", "totals": {"tests": 24, "passed": 23, "failed": 1},
                                      "failing": [{"name": "status endpoint answers", "severity": "P0", "detail": "503"}], "history": [{"run_at": "2026-09-21T10:05:00Z", "passed": 23, "failed": 1}]}})
    page.wait_for_selector(".tile")
    body = page.inner_text("body")
    for expected in ("123", "77.7%", "step 7 - status update", "assert 'open' == 'resolved'", "abc1234", "Recent runs", "test_flaky", "req-123", "Failed before2 times", "screenshots/test_y.png", "HTTP 500",
                     "Production smoke", "1 failing", "amplify:sofyan-dev#11", "23/24 checks passed", "status endpoint answers"):
        assert re.sub(r"\s+", "", expected) in re.sub(r"\s+", "", body), expected
    for f in REGISTRY:
        assert f["id"] in body
    assert not page.errors


def test_dashboard_explains_when_nothing_has_been_stored_yet(page, site):
    _open(page, site, 200, {"run": None, "history": [], "failure_counts": {}, "flaky_by_history": []})
    page.wait_for_selector(".empty")
    assert "No test run has been stored yet" in page.inner_text("body")


def test_non_admins_get_a_clear_message_not_a_login_loop(page, site):
    _open(page, site, 403, {"error": "Test results are visible to Admins only."})
    page.wait_for_selector(".empty")
    assert "Admins only" in page.inner_text("body") and page.url.endswith("test_dashboard.html")
