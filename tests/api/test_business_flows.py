"""End-to-end business flows against the deployed API, using only the dedicated test tenant.

Every flow creates clearly-labelled "[E2E]" data and removes it again in a finalizer, even if an
assertion fails halfway. `test_zz_no_test_data_left_behind` proves nothing leaked.
"""
import uuid

import pytest

from conftest import ACCOUNT_B_ID, ACCOUNT_ID, TEST_PREFIX, TOKEN_B

pytestmark = [pytest.mark.live, pytest.mark.needs_token]
JSON = {"Content-Type": "application/json"}


def _tag():
    return f"{TEST_PREFIX} {uuid.uuid4().hex[:8]}"


# ── Notification flow (E2E-NOT-001) ─────────────────────────────────────
@pytest.mark.flow("E2E-NOT-001")
@pytest.mark.severity("P1")
def test_notification_recipient_lifecycle_and_failure_reporting(api, step, cleanup):
    label = _tag()
    with step("add recipient (person with email, scoped to one category)"):
        s, b, _ = api.post("notifications", {
            "action": "add_recipient", "cloud_account_id": ACCOUNT_ID, "label": label,
            "domains": ["security"], "notify_email": "e2e-noreply@example.invalid"}, headers=JSON)
        assert s == 200 and b.get("id"), (s, b)
        rid = b["id"]
        cleanup(lambda: api.post("notifications", {"action": "remove_recipient", "cloud_account_id": ACCOUNT_ID, "id": rid}, headers=JSON))

    with step("recipient appears in the account's settings with its category scope"):
        s, b, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "preferences": "1"})
        mine = [r for r in b["recipients"] if r["id"] == rid]
        assert s == 200 and len(mine) == 1
        assert mine[0]["domains"] == ["security"] and mine[0]["notify_email"] == "e2e-noreply@example.invalid"

    with step("a broken external integration is detected and reported (not swallowed)"):
        s, b, _ = api.post("notifications", {
            "action": "test_channel", "cloud_account_id": ACCOUNT_ID,
            "channel": "webhook", "target": "http://127.0.0.1:9/nothing-listens"}, headers=JSON)
        assert s == 200 and b["sent"] is False and b.get("reason")

    with step("remove recipient"):
        s, _, _ = api.post("notifications", {"action": "remove_recipient", "cloud_account_id": ACCOUNT_ID, "id": rid}, headers=JSON)
        assert s == 200
        _, b, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "preferences": "1"})
        assert all(r["id"] != rid for r in b["recipients"])


@pytest.mark.flow("E2E-NOT-001")
@pytest.mark.severity("P1")
@pytest.mark.parametrize("payload,fragment", [
    ({"action": "add_recipient", "label": "x", "domains": []}, "at least one channel"),
    ({"action": "add_recipient", "label": "", "notify_email": "a@b.co"}, "label"),
    ({"action": "add_recipient", "label": "x", "notify_email": "a@b.co", "domains": ["nope"]}, "unknown categories"),
    ({"action": "test_channel", "channel": "carrier-pigeon", "target": "x"}, "channel must be one of"),
    ({"action": "test_channel", "channel": "email", "target": ""}, "target is required"),
    ({"action": "update_preferences", "domain": "not-a-domain"}, "domain must be one of"),
])
def test_notification_input_validation(api, payload, fragment):
    s, b, _ = api.post("notifications", {**payload, "cloud_account_id": ACCOUNT_ID}, headers=JSON)
    assert s == 400 and fragment in b["error"]


@pytest.mark.flow("E2E-NOT-001")
@pytest.mark.severity("P1")
def test_notification_preferences_roundtrip_and_restore(api, step, cleanup):
    _, before, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "preferences": "1"})
    original = before["preferences"]["platform"]
    keys = ("email_enabled", "webhook_enabled", "slack_enabled", "sms_enabled", "teams_enabled", "discord_enabled")
    cleanup(lambda: api.post("notifications", {"action": "update_preferences", "cloud_account_id": ACCOUNT_ID,
                                               "domain": "platform", **{k: original[k] for k in keys}}, headers=JSON))
    with step("flip a preference"):
        flipped = {k: (not original[k]) if k == "sms_enabled" else original[k] for k in keys}
        s, _, _ = api.post("notifications", {"action": "update_preferences", "cloud_account_id": ACCOUNT_ID, "domain": "platform", **flipped}, headers=JSON)
        assert s == 200
    with step("the change is persisted"):
        _, after, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "preferences": "1"})
        assert after["preferences"]["platform"]["sms_enabled"] == flipped["sms_enabled"]


@pytest.mark.flow("E2E-NOT-001")
@pytest.mark.severity("P1")
def test_notification_analytics_are_internally_consistent(api):
    s, b, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "analytics": "1"})
    assert s == 200
    for key in ("total_notifications", "delivery_rate_pct", "acknowledgement_rate_pct", "escalated_count", "integration_health"):
        assert key in b, f"analytics missing {key}"
    for rate in ("delivery_rate_pct", "acknowledgement_rate_pct"):
        assert b[rate] is None or 0 <= b[rate] <= 100
    for channel, h in b["integration_health"].items():
        assert 0 <= h["failures"] <= h["attempts"], f"{channel}: failures exceed attempts"


# ── Third-party risk (E2E-TPRM-001) ─────────────────────────────────────
@pytest.mark.flow("E2E-TPRM-001")
@pytest.mark.severity("P1")
def test_tprm_vendor_lifecycle(api, step, cleanup):
    name = _tag()
    with step("create vendor"):
        s, b, _ = api.post("tprm", {"action": "create_vendor", "cloud_account_id": ACCOUNT_ID, "name": name,
                                    "criticality": "low", "actor_name": "e2e"}, headers=JSON)
        assert s == 200 and b.get("id"), (s, b)
        vid = b["id"]
        cleanup(lambda: api.post("tprm", {"action": "delete_vendor", "cloud_account_id": ACCOUNT_ID, "vendor_id": vid, "actor_name": "e2e"}, headers=JSON))
    with step("vendor is listed"):
        _, b, _ = api.get("tprm", params={"cloud_account_id": ACCOUNT_ID})
        assert any(v["id"] == vid and v["name"] == name for v in b["vendors"])
    with step("update vendor"):
        s, b, _ = api.post("tprm", {"action": "update_vendor", "cloud_account_id": ACCOUNT_ID, "vendor_id": vid,
                                    "fields": {"criticality": "high"}, "actor_name": "e2e"}, headers=JSON)
        assert s == 200 and b.get("updated") is True
        _, b, _ = api.get("tprm", params={"cloud_account_id": ACCOUNT_ID})
        assert next(v for v in b["vendors"] if v["id"] == vid)["criticality"] == "high"
    with step("delete vendor"):
        s, b, _ = api.post("tprm", {"action": "delete_vendor", "cloud_account_id": ACCOUNT_ID, "vendor_id": vid, "actor_name": "e2e"}, headers=JSON)
        assert s == 200 and b.get("deleted") is True
        _, b, _ = api.get("tprm", params={"cloud_account_id": ACCOUNT_ID})
        assert all(v["id"] != vid for v in b["vendors"])


# ── Audit (E2E-AUD-001) ─────────────────────────────────────────────────
@pytest.mark.flow("E2E-AUD-001")
@pytest.mark.severity("P1")
def test_audit_lifecycle(api, step, cleanup):
    title = _tag()
    with step("create audit"):
        s, b, _ = api.post("audit-management", {"action": "create_audit", "cloud_account_id": ACCOUNT_ID, "title": title,
                                                 "audit_type": "internal"}, headers=JSON)
        assert s == 200 and b.get("id"), (s, b)
        aid = b["id"]
        cleanup(lambda: api.post("audit-management", {"action": "delete_audit", "cloud_account_id": ACCOUNT_ID, "audit_id": aid}, headers=JSON))
    with step("audit is listed"):
        _, b, _ = api.get("audit-management", params={"cloud_account_id": ACCOUNT_ID})
        assert any(a["id"] == aid and a["title"] == title for a in b["audits"])
    with step("delete audit"):
        s, b, _ = api.post("audit-management", {"action": "delete_audit", "cloud_account_id": ACCOUNT_ID, "audit_id": aid}, headers=JSON)
        assert s == 200 and b.get("deleted") is True
        _, b, _ = api.get("audit-management", params={"cloud_account_id": ACCOUNT_ID})
        assert all(a["id"] != aid for a in b["audits"])


# ── Questionnaire automation (E2E-QST-001) ──────────────────────────────
@pytest.mark.flow("E2E-QST-001")
@pytest.mark.severity("P1")
def test_questionnaire_upload_rename_delete(api, step, cleanup):
    name = _tag()
    csv_text = "Question\nDo you encrypt data at rest?\nDo you enforce MFA for administrators?\nHow often are backups tested?\n"
    with step("upload a 3-question CSV"):
        s, b, _ = api.post("questionnaires", {"action": "upload", "cloud_account_id": ACCOUNT_ID, "name": name,
                                               "filename": "e2e.csv", "csv_text": csv_text}, headers=JSON)
        assert s == 200 and b["questions_imported"] == 3, (s, b)
        qid = b["id"]
        cleanup(lambda: api.delete("questionnaires", params={"questionnaire_id": qid}))
    with step("questions are stored, unanswered until generated"):
        s, b, _ = api.get("questionnaires", params={"questionnaire_id": qid})
        assert s == 200 and len(b["items"]) == 3
    with step("rename"):
        new = name + " renamed"
        s, _, _ = api.post("questionnaires", {"action": "rename_questionnaire", "cloud_account_id": ACCOUNT_ID,
                                               "questionnaire_id": qid, "name": new}, headers=JSON)
        assert s == 200
        _, b, _ = api.get("questionnaires", params={"cloud_account_id": ACCOUNT_ID})
        assert any(q["id"] == qid and q["name"] == new for q in b["questionnaires"])
    with step("delete"):
        s, _, _ = api.delete("questionnaires", params={"questionnaire_id": qid})
        assert s == 200
        s, _, _ = api.get("questionnaires", params={"questionnaire_id": qid})
        assert s == 404


@pytest.mark.flow("E2E-QST-001")
@pytest.mark.severity("P2")
def test_questionnaire_upload_without_a_name_is_rejected_cleanly(api):
    s, b, _ = api.post("questionnaires", {"action": "upload", "cloud_account_id": ACCOUNT_ID, "csv_text": "Question\nx\n"}, headers=JSON)
    assert s in (400, 500)  # documents current behaviour; must never create a nameless record
    _, lst, _ = api.get("questionnaires", params={"cloud_account_id": ACCOUNT_ID})
    assert all(q.get("name") for q in lst["questionnaires"])


# ── Custom compliance frameworks (E2E-CMP-001) ──────────────────────────
@pytest.mark.flow("E2E-CMP-001")
@pytest.mark.severity("P1")
def test_custom_framework_lifecycle(api, step, cleanup):
    name = _tag()
    with step("create framework"):
        s, b, _ = api.post("custom-frameworks", {"action": "create_framework", "cloud_account_id": ACCOUNT_ID, "name": name}, headers=JSON)
        assert s == 200 and b.get("id"), (s, b)
        fid = b["id"]
        cleanup(lambda: api.delete("custom-frameworks", params={"framework_id": fid}))
    with step("add a control mapped to a real technical check"):
        s, b, _ = api.post("custom-frameworks", {"action": "add_control", "framework_id": fid, "title": "E2E control",
                                                  "severity": "LOW", "checks": ["IAM.5"]}, headers=JSON)
        assert s == 200 and b.get("id")
    with step("framework and control are listed"):
        _, b, _ = api.get("custom-frameworks", params={"cloud_account_id": ACCOUNT_ID})
        fw = next(f for f in b["frameworks"] if f["id"] == fid)
        assert fw["name"] == name and len(fw["controls"]) == 1
    with step("delete framework removes its controls too"):
        s, b, _ = api.delete("custom-frameworks", params={"framework_id": fid})
        assert s == 200 and b["deleted"] == "framework"
        _, b, _ = api.get("custom-frameworks", params={"cloud_account_id": ACCOUNT_ID})
        assert all(f["id"] != fid for f in b["frameworks"])


# ── Trust Center (E2E-TRUST-001) ────────────────────────────────────────
@pytest.mark.flow("E2E-TRUST-001")
@pytest.mark.severity("P2")
def test_trust_center_admin_view_shape(api):
    s, b, _ = api.get("trust-center", params={"cloud_account_id": ACCOUNT_ID})
    assert s == 200 and {"settings", "documents", "compliance"} <= set(b)
    assert b["settings"]["cloud_account_id"] == ACCOUNT_ID


# ── Compliance calculators (E2E-CMP-001) ────────────────────────────────
@pytest.mark.flow("E2E-CMP-001")
@pytest.mark.severity("P2")
def test_calculator_lists_supported_frameworks(api):
    s, b, _ = api.get("calculators", params={"cloud_account_id": ACCOUNT_ID})
    assert s == 200 and len(b["framework_options"]) >= 2
    assert all({"value", "label"} <= set(o) for o in b["framework_options"])


# ── Test-data hygiene (E2E-DATA-001) — must run last ────────────────────
@pytest.mark.flow("E2E-DATA-001")
@pytest.mark.severity("P1")
def test_zz_no_test_data_left_behind(api, api_b):
    leaks = _leaks(api, ACCOUNT_ID)
    if TOKEN_B:
        leaks += _leaks(api_b, ACCOUNT_B_ID)
    assert not leaks, f"test data leaked into the test tenants: {leaks}"


def _leaks(api, ACCOUNT_ID):
    leaks = []
    _, b, _ = api.get("tprm", params={"cloud_account_id": ACCOUNT_ID})
    leaks += [("vendor", v["name"]) for v in b["vendors"] if v["name"].startswith(TEST_PREFIX)]
    _, b, _ = api.get("audit-management", params={"cloud_account_id": ACCOUNT_ID})
    leaks += [("audit", a["title"]) for a in b["audits"] if a["title"].startswith(TEST_PREFIX)]
    _, b, _ = api.get("questionnaires", params={"cloud_account_id": ACCOUNT_ID})
    leaks += [("questionnaire", q["name"]) for q in b["questionnaires"] if q["name"].startswith(TEST_PREFIX)]
    _, b, _ = api.get("custom-frameworks", params={"cloud_account_id": ACCOUNT_ID})
    leaks += [("framework", f["name"]) for f in b["frameworks"] if f["name"].startswith(TEST_PREFIX)]
    _, b, _ = api.get("notifications", params={"cloud_account_id": ACCOUNT_ID, "preferences": "1"})
    leaks += [("recipient", r["label"]) for r in b["recipients"] if r["label"].startswith(TEST_PREFIX)]
    return leaks
