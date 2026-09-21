"""Run the whole suite, re-run failures to detect flaky tests, then build the coverage summary.

    python tests/tools/run_suite.py [--layers unit api ui] [--no-rerun]

A test that fails and then passes on an immediate re-run is reported as FLAKY (and still shown as
a warning) — never silently treated as either a clean pass or a hard failure.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "tests" / "reports"
RERUNS = 2


def pytest(args, report):
    env = dict(os.environ, E2E_REPORT_PATH=str(report))
    return subprocess.run([sys.executable, "-m", "pytest", *args], cwd=ROOT, env=env).returncode


def apply_reruns(data, run_again, attempts=RERUNS):
    """Re-run failed tests; a test that fails and then passes is FLAKY (kept visible), never silently 'passed'.
    `run_again(test_ids) -> {test_id: status}` is injected so the logic is testable."""
    for r in data["results"]:
        r.setdefault("attempts", [r["status"]])
        r.setdefault("flaky", False)
    for _ in range(attempts):
        still = [r for r in data["results"] if r["status"] == "failed"]
        if not still:
            break
        again = run_again(sorted({r["test_id"] for r in still}))
        for r in still:
            st = again.get(r["test_id"])
            if st:
                r["attempts"].append(st)
                if st == "passed":
                    r["status"] = "passed"
                    r["flaky"] = True
                    r["message"] = "FLAKY: failed first, passed on re-run. First failure: " + r["message"][-500:]
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--layers", nargs="*", default=["unit", "api", "ui"])
    ap.add_argument("--no-rerun", action="store_true")
    ap.add_argument("--flows", default="", help="only these flows (P0 always runs); default: everything")
    a = ap.parse_args()

    latest = REPORTS / "latest.json"
    extra = ["--flows", a.flows] if a.flows else []
    pytest([f"tests/{l}" for l in a.layers] + extra, latest)
    data = json.loads(latest.read_text(encoding="utf-8"))

    def run_again(ids):
        rr = REPORTS / "rerun.json"
        pytest(ids, rr)
        out = {x["test_id"]: x["status"] for x in json.loads(rr.read_text(encoding="utf-8"))["results"]}
        rr.unlink(missing_ok=True)
        return out

    if a.no_rerun:
        for r in data["results"]:
            r.setdefault("attempts", [r["status"]])
            r.setdefault("flaky", False)
    else:
        apply_reruns(data, run_again)
    latest.write_text(json.dumps(data, indent=2), encoding="utf-8")
    code = subprocess.run([sys.executable, str(ROOT / "tests" / "tools" / "build_report.py")], cwd=ROOT).returncode
    subprocess.run([sys.executable, str(ROOT / "tests" / "tools" / "upload_results.py")], cwd=ROOT)
    return code


if __name__ == "__main__":
    sys.exit(main())
