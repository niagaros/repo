"""A test that fails and then passes is reported as FLAKY, never silently as a clean pass (issue #279 AC: flaky tests are identified)."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT

spec = importlib.util.spec_from_file_location("run_suite", ROOT / "tests" / "tools" / "run_suite.py")
rs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rs)


def _run(data):
    return {"results": data}


def test_fail_then_pass_is_flagged_flaky_and_stays_visible():
    data = _run([{"test_id": "t::flaky", "status": "failed", "message": "boom"}, {"test_id": "t::ok", "status": "passed", "message": ""}])
    rs.apply_reruns(data, lambda ids: {"t::flaky": "passed"})
    flaky = data["results"][0]
    assert flaky["status"] == "passed" and flaky["flaky"] is True and flaky["attempts"] == ["failed", "passed"] and "FLAKY" in flaky["message"]
    assert data["results"][1]["flaky"] is False


def test_a_consistently_failing_test_stays_failed_and_is_not_flaky():
    data = _run([{"test_id": "t::bad", "status": "failed", "message": "boom"}])
    rs.apply_reruns(data, lambda ids: {"t::bad": "failed"})
    r = data["results"][0]
    assert r["status"] == "failed" and r["flaky"] is False and r["attempts"] == ["failed", "failed", "failed"]


def test_passing_tests_are_never_rerun():
    calls = []
    rs.apply_reruns(_run([{"test_id": "t::ok", "status": "passed", "message": ""}]), lambda ids: calls.append(ids) or {})
    assert calls == []


def test_a_really_flaky_test_is_detected_by_the_real_runner():
    """End to end with real pytest: a test that fails on its first execution and passes on the second."""
    tmp = ROOT / "tests" / "_flaky_tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()
    state = tmp / "state.txt"
    (tmp / "test_flaky_demo.py").write_text(
        "import pathlib, pytest\n"
        "pytestmark = [pytest.mark.flow('E2E-DATA-001'), pytest.mark.severity('P4')]\n"
        f"S = pathlib.Path({str(state)!r})\n"
        "def test_flaky_demo():\n"
        "    first = not S.exists()\n"
        "    S.write_text('seen')\n"
        "    assert not first, 'fails on the very first execution only'\n", encoding="utf-8")
    try:
        def pytest_run(args, report):
            subprocess.run([sys.executable, "-m", "pytest", *args], cwd=ROOT, env=dict(os.environ, E2E_REPORT_PATH=str(report)), capture_output=True)
            return json.loads(report.read_text(encoding="utf-8"))["results"]
        rep = tmp / "r.json"
        data = {"results": pytest_run(["tests/_flaky_tmp"], rep)}
        assert data["results"][0]["status"] == "failed"
        rs.apply_reruns(data, lambda ids: {x["test_id"]: x["status"] for x in pytest_run(ids, tmp / "r2.json")})
        r = data["results"][0]
        assert r["status"] == "passed" and r["flaky"] is True and r["attempts"] == ["failed", "passed"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
