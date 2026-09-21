"""The coverage dashboard renders exactly what the last real run produced."""
import json

import pytest

from conftest import PUBLIC_DIR

pytestmark = [pytest.mark.flow("E2E-UI-002"), pytest.mark.severity("P2")]


def test_dashboard_shows_the_numbers_from_test_results_json(page, site):
    data = json.loads((PUBLIC_DIR / "test_results.json").read_text(encoding="utf-8"))
    page.goto(f"{site}/test_dashboard.html")
    page.wait_for_selector(".tile")
    body = page.inner_text("body")
    t = data["totals"]
    assert str(t["tests"]) in body and f'{t["coverage_of_existing_flows_pct"]:g}%' in body
    for f in data["flows"]:
        assert f["id"] in body
    assert page.locator("table").count() >= 3 and not page.errors
