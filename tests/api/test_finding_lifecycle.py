"""The issue's Security Finding flow, end to end on the live system:
   Finding detected -> risk calculated -> finding created -> owner assigned -> notification sent -> remediation created ->
   remediation executed -> finding re-tested (verified) -> finding resolved -> audit trail updated."""
import time
import uuid

import pytest

from conftest import ACCOUNT_ID, TEST_PREFIX

pytestmark = [pytest.mark.live, pytest.mark.needs_token, pytest.mark.flow("E2E-SEC-001"), pytest.mark.severity("P1")]
JSON = {"Content-Type": "application/json"}
OWNER = "success@simulator.amazonses.com"


def _poll(fn, seconds=40):
    end = time.time() + seconds
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(2)


def test_finding_goes_from_detected_to_resolved_with_owner_notification_and_trail(api, step, cleanup):
    tag = f"{TEST_PREFIX} finding {uuid.uuid4().hex[:6]}"
    s, b, _ = api.post("audit-management", {"action": "create_audit", "cloud_account_id": ACCOUNT_ID, "title": tag, "audit_type": "internal"}, headers=JSON)
    assert s == 200
    audit_id = b["id"]
    cleanup(lambda: api.post("audit-management", {"action": "delete_audit", "cloud_account_id": ACCOUNT_ID, "audit_id": audit_id}, headers=JSON))

    def finding(fid):
        _, det, _ = api.get("audit-management", params={"audit_detail": audit_id})
        return next(f for f in det["findings"] if f["id"] == fid)

    with step("finding detected and created; its risk is calculated"):
        s, b, _ = api.post("audit-management", {"action": "add_manual_finding", "audit_id": audit_id, "title": f"{tag} S3 bucket public", "severity": "high",
                                                "description": "Bucket allows public reads"}, headers=JSON)
        assert s == 200
        fid = b["id"]
        f = finding(fid)
        assert f["status"] == "open" and f["severity"] == "HIGH" and f["risk_rating"] == "High (7/10)"
        s, b, _ = api.post("audit-management", {"action": "add_manual_finding", "audit_id": audit_id, "title": "explicit rating", "risk_rating": "Custom"}, headers=JSON)
        assert finding(b["id"])["risk_rating"] == "Custom", "an explicitly supplied rating must not be overwritten"

    with step("owner assigned with a due date: the owner is emailed and a notification event is raised"):
        s, b, _ = api.post("audit-management", {"action": "create_remediation_task", "finding_id": fid, "title": "Block public access", "owner_name": "E2E Owner",
                                                "owner_email": OWNER, "due_date": "2030-01-01"}, headers=JSON)
        assert s == 200 and b["notification"]["sent"] is True, (s, b)
        task_id = b["id"]
        assert finding(fid)["status"] == "in_remediation"

        def event():
            _, n, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "domain": "workflow"})
            return next((x for x in n["notifications"] if x["event_type"] == "remediation_task_assigned" and "Block public access" in x["title"]), None)
        e = _poll(event)
        assert e and e["severity"] == "P2" and f"finding_id={fid}" in e["resource_link"]

    with step("remediation is executed"):
        for status in ("in_progress", "completed"):
            s, _, _ = api.post("audit-management", {"action": "update_remediation_task", "task_id": task_id, "status": status}, headers=JSON)
            assert s == 200
        assert finding(fid)["status"] == "in_remediation", "completing the task must not resolve the finding before it is re-tested"

    with step("re-test: verification needs evidence of the check, and only then is the finding resolved"):
        s, b, _ = api.post("audit-management", {"action": "update_remediation_task", "task_id": task_id, "status": "verified"}, headers=JSON)
        assert s == 400 and "verification_notes" in b["error"]
        s, _, _ = api.post("audit-management", {"action": "update_remediation_task", "task_id": task_id, "status": "verified",
                                                "verification_notes": "Re-scanned: bucket is private", "verified_by": "E2E Reviewer"}, headers=JSON)
        assert s == 200
        f = finding(fid)
        assert f["status"] == "closed" and f["resolved_at"]
        task = f["remediation_tasks"][0]
        assert task["status"] == "verified" and task["verified_by"] == "E2E Reviewer" and task["verification_notes"] == "Re-scanned: bucket is private"

    with step("audit trail: comments stay attached to the finding"):
        s, _, _ = api.post("audit-management", {"action": "add_finding_comment", "finding_id": fid, "author": "E2E Reviewer", "body": "Confirmed resolved"}, headers=JSON)
        assert s == 200
        assert finding(fid)["comments"][-1]["body"] == "Confirmed resolved"
