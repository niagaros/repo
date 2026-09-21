"""The issue's Notification flow, end to end on the live system:
   Critical event -> event created -> severity -> audience determined -> policy applied -> delivered -> user acknowledges -> trail.
The event is a real one (an audit is completed), delivery goes through the real SQS queue and real SES using the SES
mailbox simulator (accepted in sandbox mode, no mailbox involved), and the audience is two named people with different scopes."""
import time
import uuid

import pytest

from conftest import ACCOUNT_ID, TEST_PREFIX

pytestmark = [pytest.mark.live, pytest.mark.needs_token, pytest.mark.flow("E2E-NOT-003"), pytest.mark.severity("P1")]
JSON = {"Content-Type": "application/json"}
SIMULATOR = "success@simulator.amazonses.com"


def _poll(fn, seconds=45, every=2):
    end = time.time() + seconds
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    return None


def test_completed_audit_becomes_a_scoped_delivered_acknowledged_notification(api, step, cleanup):
    tag = f"{TEST_PREFIX} audit {uuid.uuid4().hex[:6]}"

    with step("policy: the account's default channel is a real (simulated-mailbox) email; restored afterwards"):
        s, _, _ = api.post("notifications", {"action": "update_channels", "cloud_account_id": ACCOUNT_ID, "notify_email": SIMULATOR}, headers=JSON)
        assert s == 200
        cleanup(lambda: api.post("notifications", {"action": "update_channels", "cloud_account_id": ACCOUNT_ID, "notify_email": ""}, headers=JSON))

    with step("audience: one person scoped to the audit category, one scoped to billing"):
        ids = {}
        for label, domain in (("audit-person", "audit"), ("billing-person", "billing")):
            s, b, _ = api.post("notifications", {"action": "add_recipient", "cloud_account_id": ACCOUNT_ID, "label": f"{TEST_PREFIX} {label}",
                                                 "domains": [domain], "notify_email": f"success+{label}@simulator.amazonses.com"}, headers=JSON)
            assert s == 200, (s, b)
            ids[label] = b["id"]
            cleanup(lambda rid=b["id"]: api.post("notifications", {"action": "remove_recipient", "cloud_account_id": ACCOUNT_ID, "id": rid}, headers=JSON))

    with step("event: completing an audit raises a real audit_completed event"):
        s, b, _ = api.post("audit-management", {"action": "create_audit", "cloud_account_id": ACCOUNT_ID, "title": tag, "audit_type": "internal"}, headers=JSON)
        assert s == 200
        audit_id = b["id"]
        cleanup(lambda: api.post("audit-management", {"action": "delete_audit", "cloud_account_id": ACCOUNT_ID, "audit_id": audit_id}, headers=JSON))
        s, _, _ = api.post("audit-management", {"action": "update_audit", "audit_id": audit_id, "status": "completed"}, headers=JSON)
        assert s == 200

    with step("event created with the right severity and category"):
        def find():
            _, b, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "domain": "audit"})
            return next((n for n in b["notifications"] if tag in n["title"]), None)
        n = _poll(find)
        assert n, "no notification was created for the completed audit"
        assert n["event_type"] == "audit_completed" and n["domain"] == "audit" and n["severity"] == "P3" and n["mandatory"] is False

    with step("delivered: the default channel and ONLY the audience member scoped to 'audit' were delivered to"):
        def delivered():
            _, b, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "domain": "audit"})
            cur = next((x for x in b["notifications"] if x["id"] == n["id"]), None)
            d = (cur or {}).get("delivery") or {}
            return cur if (d.get("email") or {}).get("sent") is True and d.get("additional_recipients") else None
        cur = _poll(delivered)
        assert cur, f"delivery was not recorded as sent: {n.get('delivery')}"
        extra = cur["delivery"]["additional_recipients"]
        assert [e["label"] for e in extra] == [f"{TEST_PREFIX} audit-person"] and extra[0]["sent"] is True, extra

    with step("acknowledge, and the trail shows it"):
        s, _, _ = api.post("notifications", {"action": "acknowledge", "cloud_account_id": ACCOUNT_ID, "id": n["id"]}, headers=JSON)
        assert s == 200
        _, b, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "domain": "audit"})
        acked = next(x for x in b["notifications"] if x["id"] == n["id"])
        assert acked["acknowledged"] is True and acked["read"] is True
        _, an, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "analytics": "1"})
        assert an["acknowledged"] >= 1 and an["acknowledgement_rate_pct"] > 0
        assert an["integration_health"]["email"]["attempts"] >= 1 and an["integration_health"]["email"]["failures"] == 0
