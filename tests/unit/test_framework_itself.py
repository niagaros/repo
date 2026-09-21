"""The test framework's own logic: the registry, coverage maths, and what is safe to publish."""
import importlib.util
import json
import re

import pytest

from conftest import ROOT

REGISTRY = json.loads((ROOT / "tests" / "registry" / "critical_flows.json").read_text(encoding="utf-8"))["flows"]
spec = importlib.util.spec_from_file_location("build_report", ROOT / "tests" / "tools" / "build_report.py")
br = importlib.util.module_from_spec(spec)
spec.loader.exec_module(br)


def test_registry_ids_are_unique_and_severities_valid():
    ids = [f["id"] for f in REGISTRY]
    assert len(ids) == len(set(ids))
    assert all(f["severity"] in br.SEV for f in REGISTRY)
    for f in REGISTRY:
        assert {"id", "domain", "name", "severity", "environment", "owner", "frequency", "dependencies", "exists"} <= set(f)


def test_every_flow_that_cannot_be_automated_says_honestly_why():
    tagged = set()
    for p in (ROOT / "tests").rglob("test_*.py"):
        tagged |= set(re.findall(r'flow\("([A-Z0-9\-]+)"\)', p.read_text(encoding="utf-8")))
    for f in REGISTRY:
        if f["id"] not in tagged:
            assert f.get("gap_reason"), f"{f['id']} has no test and no documented reason"


def test_every_flow_id_used_by_a_test_is_registered():
    tagged = set()
    for p in (ROOT / "tests").rglob("test_*.py"):
        tagged |= set(re.findall(r'flow\("([A-Z0-9\-]+)"\)', p.read_text(encoding="utf-8")))
    assert tagged - {f["id"] for f in REGISTRY} == set()


@pytest.mark.parametrize("statuses,expected", [
    (["passed", "passed"], "passing"),
    (["passed", "failed"], "failing"),
    (["passed", "known_failure"], "known_defect"),
    (["passed", "blocked"], "partially_blocked"),
    (["blocked"], "blocked"),
    (["failed", "known_failure"], "failing"),
])
def test_flow_status_is_the_most_severe_honest_state(statuses, expected):
    assert br.flow_status([{"status": s} for s in statuses]) == expected


def test_a_dashboard_page_exists_and_reads_the_stored_results_from_the_api():
    html = (ROOT / "frontend" / "public" / "test_dashboard.html").read_text(encoding="utf-8")
    assert "/test-results" in html and "test_results.json" not in html


def test_results_are_no_longer_published_as_a_public_file():
    assert not (ROOT / "frontend" / "public" / "test_results.json").exists()


def test_ingest_validation_accepts_a_real_run_and_rejects_malformed_ones():
    from collectors.aws.scanner.test_results_handler import validate_run
    ok = {"summary": {"run_at": "2026-09-21T10:00:00Z", "totals": {"tests": 1}}, "results": [{"test_id": "t::a", "status": "passed"}]}
    assert validate_run(ok) is None
    assert validate_run([]) and validate_run({}) and validate_run({**ok, "results": []})
    assert validate_run({**ok, "results": [{"test_id": "t", "status": "great"}]})
    assert validate_run({**ok, "results": [{"status": "passed"}]})
    assert validate_run({**ok, "summary": {"totals": {}}})
    assert validate_run({**ok, "results": [{"test_id": "t", "status": "passed"}] * 5001})
