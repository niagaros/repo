"""Join the latest real test run with the critical-flow registry into the coverage dashboard data.

Reads  tests/reports/latest.json  (written by pytest) and tests/registry/critical_flows.json.
Writes tests/reports/summary.json and appends to tests/reports/history.json; upload_results.py then stores the run
in the database, which the dashboard page reads. Nothing here invents a number:
every figure is computed from the run that produced latest.json.

Exit code 1 when a P0 test FAILED (a known, tracked defect does not count — it is shown, not hidden).
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "tests" / "reports"
SEV = ["P0", "P1", "P2", "P3", "P4"]
HISTORY_LIMIT = 60


def flow_status(tests):
    st = [t["status"] for t in tests]
    if "failed" in st:
        return "failing"
    if "known_failure" in st:
        return "known_defect"
    if "passed" in st and "blocked" in st:
        return "partially_blocked"
    if "passed" in st:
        return "passing"
    if "blocked" in st:
        return "blocked"
    return "no_result"


def main():
    run = json.loads((REPORTS / "latest.json").read_text(encoding="utf-8"))
    reg = json.loads((ROOT / "tests" / "registry" / "critical_flows.json").read_text(encoding="utf-8"))["flows"]
    by_flow = defaultdict(list)
    for t in run["results"]:
        if t.get("flow"):
            by_flow[t["flow"]].append(t)
    unregistered = sorted(set(by_flow) - {f["id"] for f in reg})

    hist_path = REPORTS / "history.json"
    history = json.loads(hist_path.read_text(encoding="utf-8")) if hist_path.exists() else []
    fail_counts = defaultdict(int)
    for h in history:
        for fid, n in h.get("failed_by_flow", {}).items():
            fail_counts[fid] += n

    flows = []
    for f in reg:
        tests = by_flow.get(f["id"], [])
        status = flow_status(tests) if tests else ("not_built" if not f["exists"] else "gap")
        flows.append({
            **f,
            "automated": bool(tests),
            "status": status,
            "tests": len(tests),
            "passed": sum(t["status"] == "passed" for t in tests),
            "failed": sum(t["status"] == "failed" for t in tests),
            "known_failures": sum(t["status"] == "known_failure" for t in tests),
            "blocked": sum(t["status"] == "blocked" for t in tests),
            "flaky": sum(bool(t.get("flaky")) for t in tests),
            "duration_s": round(sum(t["duration_s"] for t in tests), 1),
            "last_run": run["run_at"],
            "failure_count_history": fail_counts.get(f["id"], 0),
        })

    def pct(n, d):
        return round(100 * n / d, 1) if d else None

    applicable = [f for f in flows if f["exists"]]
    covered = [f for f in flows if f["automated"]]
    by_sev = {}
    for s in SEV:
        fs = [f for f in flows if f["severity"] == s]
        if not fs:
            continue
        by_sev[s] = {
            "flows": len(fs), "automated": sum(f["automated"] for f in fs),
            "coverage_pct": pct(sum(f["automated"] for f in fs), len(fs)),
            "passing": sum(f["status"] == "passing" for f in fs),
            "known_defect": sum(f["status"] == "known_defect" for f in fs),
            "failing": sum(f["status"] == "failing" for f in fs),
        }

    results = run["results"]
    counts = {k: sum(t["status"] == k for t in results) for k in ("passed", "failed", "known_failure", "blocked", "skipped")}
    problems = [t for t in results if t["status"] in ("failed", "known_failure")]
    summary = {
        "run_at": run["run_at"], "commit": run.get("commit"), "branch": run.get("branch"), "trigger": run.get("trigger"),
        "environment": run.get("environment"), "full_run_duration_s": run["duration_s"],
        "totals": {"critical_flows_in_inventory": len(flows), "flows_that_exist_in_product": len(applicable),
                   "flows_automated": len(covered),
                   "coverage_of_inventory_pct": pct(len(covered), len(flows)),
                   "coverage_of_existing_flows_pct": pct(sum(f["automated"] for f in applicable), len(applicable)),
                   "tests": len(results), **counts,
                   "flaky": sum(bool(t.get("flaky")) for t in results)},
        "by_severity": by_sev,
        "flows": flows,
        "failures": [{"test_id": t["test_id"], "flow": t["flow"], "severity": t["severity"], "status": t["status"],
                      "failed_step": t["failed_step"], "message": t["message"][-900:], "last_exchange": t["last_exchange"],
                      "request_id": t.get("request_id"), "screenshot": t.get("screenshot"), "layer": t.get("layer"),
                      "commit": run.get("commit"), "environment": run.get("environment", {}).get("api")} for t in problems],
        "flaky_tests": [{"test_id": t["test_id"], "attempts": t.get("attempts")} for t in results if t.get("flaky")],
        "unregistered_flows_in_tests": unregistered,
    }
    (REPORTS / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    history.append({"run_at": run["run_at"], "commit": run.get("commit"), "passed": counts["passed"], "failed": counts["failed"],
                    "failed_by_flow": {fid: sum(t["status"] == "failed" for t in ts) for fid, ts in by_flow.items() if any(t["status"] == "failed" for t in ts)}})
    hist_path.write_text(json.dumps(history[-HISTORY_LIMIT:], indent=2), encoding="utf-8")

    t = summary["totals"]
    print(f"\nCritical flows: {t['critical_flows_in_inventory']} in inventory, {t['flows_that_exist_in_product']} exist in the product, {t['flows_automated']} automated")
    print(f"Coverage: {t['coverage_of_existing_flows_pct']}% of existing flows, {t['coverage_of_inventory_pct']}% of the full inventory")
    print(f"Tests: {t['tests']} | passed {counts['passed']} | failed {counts['failed']} | known defects {counts['known_failure']} | blocked {counts['blocked']} | not applicable {counts['skipped']} | flaky {t['flaky']}")
    for s, d in by_sev.items():
        print(f"  {s}: {d['automated']}/{d['flows']} flows automated ({d['coverage_pct']}%), passing {d['passing']}, known defects {d['known_defect']}, failing {d['failing']}")
    if unregistered:
        print("WARNING: tests tagged with unregistered flow ids:", unregistered)
    p0_failed = [x for x in problems if x["status"] == "failed" and x["severity"] == "P0"]
    if p0_failed:
        print("P0 FAILURES (deployment-blocking):", [x["test_id"] for x in p0_failed])
    # A P0 test that never ran at all — "blocked" (missing credentials/prerequisites),
    # not "skipped" as genuinely not-applicable — must gate the suite exactly like a
    # failure. Real bug this fixes: a run missing e.g. E2E_PASSWORD_C silently reported
    # 0 failures and exit code 0, even though a mandatory P0 flow was never executed.
    p0_blocked = [t for t in results if t["status"] == "blocked" and t["severity"] == "P0"]
    if p0_blocked:
        print("P0 BLOCKED — never ran (deployment-blocking):", [t["test_id"] for t in p0_blocked])
    return 1 if any(x["status"] == "failed" for x in problems) or unregistered or p0_blocked else 0


if __name__ == "__main__":
    sys.exit(main())
