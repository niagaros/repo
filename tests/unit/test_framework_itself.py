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


def test_public_view_never_contains_request_response_bodies_or_the_api_url():
    summary = {"environment": {"api": "https://secret.example/default", "account": "acct", "token_provided": False},
               "failures": [{"message": "E   assert 200 in (401, 403)\nresponse body with private data", "last_exchange": {"response": {"body": "private"}},
                             "environment": "https://secret.example/default"}]}
    pub = br.public_view(summary)
    text = json.dumps(pub)
    assert "private" not in text and "secret.example" not in text and "acct" not in text
    assert pub["failures"][0]["message"] == "assert 200 in (401, 403)"


def test_a_dashboard_file_exists_and_reads_the_generated_results():
    html = (ROOT / "frontend" / "public" / "test_dashboard.html").read_text(encoding="utf-8")
    assert "test_results.json" in html
