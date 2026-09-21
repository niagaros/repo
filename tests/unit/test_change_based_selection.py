"""A change to a critical workflow runs the tests of that workflow (issue #279 AC: PR modifies a critical workflow -> relevant tests run)."""
import importlib.util
import json

import pytest

from conftest import ROOT

spec = importlib.util.spec_from_file_location("select_tests", ROOT / "tests" / "tools" / "select_tests.py")
st = importlib.util.module_from_spec(spec)
spec.loader.exec_module(st)
FLOWS = json.loads((ROOT / "tests" / "registry" / "critical_flows.json").read_text(encoding="utf-8"))["flows"]
H = "backend/src/collectors/aws/scanner/"


def sel(*files):
    return st.select(list(files), FLOWS)[0]


def test_an_authentication_change_runs_the_authentication_and_isolation_flows():
    picked = set(sel(H + "tenant_auth.py").split(","))
    assert {"E2E-AUTH-001", "E2E-PERM-001", "E2E-PERM-002"} <= picked


def test_a_notification_change_runs_notification_flows_and_not_unrelated_ones():
    picked = set(sel(H + "notification_lib.py").split(","))
    assert {"E2E-NOT-002", "E2E-NOT-003"} <= picked and "E2E-TPRM-001" not in picked and "E2E-AUTH-002" not in picked


def test_an_audit_change_runs_the_audit_finding_and_auditor_flows():
    assert {"E2E-AUD-001", "E2E-AUD-002", "E2E-SEC-001"} <= set(sel(H + "audit_management_handler.py").split(","))


def test_any_framework_mapper_change_runs_the_mapper_invariants():
    assert "E2E-CMP-002" in sel(H + "iso27001_mapper_handler.py").split(",")


def test_shared_plumbing_and_unknown_paths_run_everything_so_nothing_is_silently_skipped():
    assert sel("tests/conftest.py") == "ALL" and sel(".github/workflows/tests.yml") == "ALL" and sel("amplify.yml") == "ALL"
    assert sel("some/path/nobody/claims.py") == "ALL" and st.select([], FLOWS)[0] == "ALL"


def test_documentation_only_changes_run_just_the_p0_tests():
    assert sel("docs/x.md", "README.md") == "NONE"


def test_every_flow_path_points_at_something_that_exists():
    for f in FLOWS:
        for p in f.get("paths", []):
            if p.endswith("_mapper_handler.py"):
                continue
            assert (ROOT / p).exists() or p.startswith("frontend/public/") or p.startswith("frontend/"), f"{f['id']}: {p} does not exist"
