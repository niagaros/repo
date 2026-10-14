"""Cloud infrastructure integration, end to end on the REAL Niagaros AWS account (read-only):
   Connect AWS -> authenticate -> validate permissions -> discover resources -> run a security scan -> findings created -> results displayed.

Test tenant C is owned by its own test user and linked (through the real onboarding endpoint) to AWS account 225989360315.
The scan takes a few minutes; it runs on this one account only."""
import time

import pytest

from conftest import ACCOUNT_C_ID, ACCOUNT_ID, USER_C

pytestmark = [pytest.mark.live, pytest.mark.needs_aws_tenant, pytest.mark.flow("E2E-INFRA-001"), pytest.mark.severity("P1")]
JSON = {"Content-Type": "application/json"}
NIAGAROS_AWS_ACCOUNT = "225989360315"
SCAN_TIMEOUT_S = 12 * 60


def _dash(api):
    s, b, _ = api.get("get-dashboard-data", params={"account_id": ACCOUNT_C_ID})
    assert s == 200, (s, b)
    return b


def test_connect_validate_scan_and_see_the_results(api_c, api, step):
    with step("connect: the tenant is linked to the Niagaros AWS account by the real onboarding endpoint"):
        s, b, _ = api_c.post("onboard", {"email": USER_C, "company_name": "[E2E] Niagaros AWS Test Tenant", "aws_account_id": NIAGAROS_AWS_ACCOUNT}, headers=JSON)
        assert s == 200 and b["already_exists"] is True and b["account_id"] == ACCOUNT_C_ID
        assert b["role_arn"] == f"arn:aws:iam::{NIAGAROS_AWS_ACCOUNT}:role/CSPMScannerRole"

    with step("authenticate + validate permissions: the scanner role is assumed and every read permission is probed"):
        s, b, _ = api_c.post("scan", {"action": "validate_connection", "cloud_account_id": ACCOUNT_C_ID}, headers=JSON)
        assert s == 200, (s, b)
        assert b["connected"] is True, b
        assert b["aws_account_id"] == NIAGAROS_AWS_ACCOUNT and b["account_matches"] is True
        assert b["checks"] and all(c["ok"] for c in b["checks"]), [c for c in b["checks"] if not c["ok"]]

    with step("nothing has been scanned yet, or a previous scan exists: remember the current scan time"):
        before = _dash(api_c)["last_scan_at"]

    with step("scan: start a scan for THIS account only"):
        s, b, _ = api_c.post("scan", {"action": "scan", "cloud_account_id": ACCOUNT_C_ID}, headers=JSON)
        assert s == 202, (s, b)

    with step("a second scan request right away is throttled instead of piling up"):
        s, b, _ = api_c.post("scan", {"action": "scan", "cloud_account_id": ACCOUNT_C_ID}, headers=JSON)
        assert s == 429 and "wait" in b["error"]

    with step("discover + findings: resources are discovered and findings are created (waits for the scan to finish)"):
        deadline, data = time.time() + SCAN_TIMEOUT_S, None
        while time.time() < deadline:
            data = _dash(api_c)
            if data["last_scan_at"] not in ("Unknown", before) and (data.get("total") or {}).get("total"):
                break
            time.sleep(20)
        else:
            pytest.fail(f"the scan did not complete within {SCAN_TIMEOUT_S // 60} minutes (last_scan_at={data and data['last_scan_at']})")

    with step("display: the results are internally consistent and belong to the connected AWS account"):
        t = data["total"]
        assert data["aws_account_id"] == NIAGAROS_AWS_ACCOUNT
        assert t["total"] > 0 and t["passed"] + t["failed"] == t["total"] and 0 <= t["score"] <= 100
        assert data["services"], "no services were discovered"
        assert data["findings"] and {"check_id", "service", "severity", "result", "title"} <= set(data["findings"][0])
        assert all(f["result"] in ("PASS", "FAIL") for f in data["findings"])

    with step("the results of this account are not visible to another tenant"):
        s, other, _ = api.get("get-dashboard-data", params={"account_id": ACCOUNT_C_ID})
        assert s in (403, 404) or not (other or {}).get("findings")
