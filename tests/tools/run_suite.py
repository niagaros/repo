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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--layers", nargs="*", default=["unit", "api", "ui"])
    ap.add_argument("--no-rerun", action="store_true")
    a = ap.parse_args()

    latest = REPORTS / "latest.json"
    pytest([f"tests/{l}" for l in a.layers], latest)
    data = json.loads(latest.read_text(encoding="utf-8"))
    for r in data["results"]:
        r["attempts"] = [r["status"]]
        r["flaky"] = False

    failed = [r for r in data["results"] if r["status"] == "failed"]
    if failed and not a.no_rerun:
        for n in range(RERUNS):
            still = [r for r in data["results"] if r["status"] == "failed"]
            if not still:
                break
            rr = REPORTS / f"rerun_{n}.json"
            pytest(sorted({r["test_id"] for r in still}), rr)
            again = {x["test_id"]: x for x in json.loads(rr.read_text(encoding="utf-8"))["results"]}
            rr.unlink(missing_ok=True)
            for r in still:
                x = again.get(r["test_id"])
                if x:
                    r["attempts"].append(x["status"])
                    if x["status"] == "passed":
                        r["status"] = "passed"
                        r["flaky"] = True
                        r["message"] = "FLAKY: failed first, passed on re-run. First failure: " + r["message"][-500:]
    latest.write_text(json.dumps(data, indent=2), encoding="utf-8")
    code = subprocess.run([sys.executable, str(ROOT / "tests" / "tools" / "build_report.py")], cwd=ROOT).returncode
    subprocess.run([sys.executable, str(ROOT / "tests" / "tools" / "upload_results.py")], cwd=ROOT)
    return code


if __name__ == "__main__":
    sys.exit(main())
