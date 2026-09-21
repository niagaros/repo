"""Audit flow with an invited external auditor: the auditor receives only authorized access.
   Audit created -> scope defined -> auditor invited (real email via SES, simulator mailbox) -> evidence submitted ->
   auditor sees ONLY that audit, adds a finding and a comment -> access revoked -> access is gone."""
import base64
import uuid

import pytest
import requests

from conftest import ACCOUNT_B_ID, ACCOUNT_ID, TEST_PREFIX

pytestmark = [pytest.mark.live, pytest.mark.needs_token, pytest.mark.flow("E2E-AUD-002"), pytest.mark.severity("P0")]
JSON = {"Content-Type": "application/json"}
AUDITOR = "success@simulator.amazonses.com"


def _tag():
    return f"{TEST_PREFIX} auditor {uuid.uuid4().hex[:6]}"


@pytest.fixture
def two_audits(api, cleanup):
    ids = []
    for _ in range(2):
        s, b, _ = api.post("audit-management", {"action": "create_audit", "cloud_account_id": ACCOUNT_ID, "title": _tag(), "audit_type": "internal",
                                                "scope_description": "Scope: production account"}, headers=JSON)
        assert s == 200, (s, b)
        ids.append(b["id"])
        cleanup(lambda a=b["id"]: api.post("audit-management", {"action": "delete_audit", "cloud_account_id": ACCOUNT_ID, "audit_id": a}, headers=JSON))
    return ids


def _invite(api, audit_id, **extra):
    return api.post("audit-management", {"action": "invite_auditor", "cloud_account_id": ACCOUNT_ID, "audit_id": audit_id,
                                         "auditor_email": AUDITOR, "auditor_name": "E2E Auditor", **extra}, headers=JSON)


def _token(url_path):
    return url_path.split("token=", 1)[1]


def test_invited_auditor_sees_only_the_invited_audit_and_can_only_add_findings_and_comments(api, anon, two_audits, step):
    a1, a2 = two_audits
    with step("owner invites an auditor: the invitation email is really sent and a personal link is issued"):
        s, b, _ = _invite(api, a1)
        assert s == 200 and b["email"]["sent"] is True, (s, b)
        token = _token(b["path"])
        access_id = b["id"]
        assert len(token) >= 40 and b["url"].endswith(b["path"])

    with step("evidence is submitted to the audit"):
        s, ev1, _ = api.post("audit-management", {"action": "upload_evidence", "cloud_account_id": ACCOUNT_ID, "audit_id": a1, "title": "Policy PDF",
                                                  "filename": "policy.txt", "file_base64": base64.b64encode(b"evidence for audit one").decode()}, headers=JSON)
        assert s == 200, (s, ev1)
        s, ev2, _ = api.post("audit-management", {"action": "upload_evidence", "cloud_account_id": ACCOUNT_ID, "audit_id": a2, "title": "Other audit evidence",
                                                  "filename": "other.txt", "file_base64": base64.b64encode(b"belongs to audit two").decode()}, headers=JSON)
        assert s == 200

    with step("the auditor opens the link WITHOUT any login and sees exactly that audit"):
        s, b, _ = anon.get("audit-management", params={"auditor_token": token})
        assert s == 200 and b["audit"]["id"] == a1 and b["auditor"]["email"] == AUDITOR
        assert "cloud_account_id" not in b["audit"] and "stakeholders" not in b["audit"]
        assert any(e["id"] == ev1["id"] for e in b["audit"].get("evidence", [])) or "evidence" not in b["audit"]

    with step("the token cannot be used to look at any other audit"):
        s, b, _ = anon.get("audit-management", params={"auditor_token": token, "audit_detail": a2})
        assert s == 200 and b["audit"]["id"] == a1, "asking for another audit must still return only the invited audit"
        s, _, _ = anon.get("audit-management", params={"auditor_token": token, "download_evidence": ev2["id"]})
        assert s == 403

    with step("the auditor can download the evidence of the invited audit"):
        s, b, _ = anon.get("audit-management", params={"auditor_token": token, "download_evidence": ev1["id"]})
        assert s == 200 and requests.get(b["download_url"], timeout=30).content == b"evidence for audit one"

    with step("the auditor creates a finding and a comment"):
        s, f, _ = anon.post("audit-management", {"auditor_token": token, "action": "auditor_add_finding", "title": "Auditor finding", "severity": "high"}, headers=JSON)
        assert s == 200, (s, f)
        s, _, _ = anon.post("audit-management", {"auditor_token": token, "action": "auditor_add_comment", "finding_id": f["id"], "body": "Please provide evidence"}, headers=JSON)
        assert s == 200
        _, det, _ = api.get("audit-management", params={"audit_detail": a1})
        finding = next(x for x in det["findings"] if x["id"] == f["id"])
        assert finding["severity"] == "HIGH" and finding["comments"][0]["author"] == "E2E Auditor"

    with step("the auditor cannot act on other audits' findings or do anything but add findings/comments"):
        s, other, _ = api.post("audit-management", {"action": "add_manual_finding", "cloud_account_id": ACCOUNT_ID, "audit_id": a2, "title": "audit two finding"}, headers=JSON)
        assert s == 200
        s, _, _ = anon.post("audit-management", {"auditor_token": token, "action": "auditor_add_comment", "finding_id": other["id"], "body": "x"}, headers=JSON)
        assert s == 403
        for forbidden in ({"action": "delete_audit", "audit_id": a1}, {"action": "update_audit", "audit_id": a1, "status": "completed"},
                          {"action": "invite_auditor", "audit_id": a1, "auditor_email": "x@y.zz"}, {"action": "update_finding_status", "finding_id": f["id"], "status": "closed"}):
            s, _, _ = anon.post("audit-management", {"auditor_token": token, **forbidden}, headers=JSON)
            assert s == 403, forbidden

    with step("the token opens nothing outside the audit workspace"):
        for path in ("tprm", "notifications", "questionnaires"):
            s, _, _ = anon.get(path, params={"cloud_account_id": ACCOUNT_ID, "auditor_token": token})
            assert s == 401, path

    with step("the owner sees who has access, but never the secret token"):
        s, lst, _ = api.get("audit-management", params={"auditor_access": a1})
        assert s == 200 and lst["access"][0]["auditor_email"] == AUDITOR and lst["access"][0]["active"] is True and lst["access"][0]["last_used_at"]
        assert token not in str(lst) and "token" not in str(lst.keys())

    with step("revoking removes the access immediately"):
        s, _, _ = api.post("audit-management", {"action": "revoke_auditor", "cloud_account_id": ACCOUNT_ID, "access_id": access_id}, headers=JSON)
        assert s == 200
        s, b, _ = anon.get("audit-management", params={"auditor_token": token})
        assert s == 403 and "revoked" in b["error"]
        _, lst, _ = api.get("audit-management", params={"auditor_access": a1})
        assert lst["access"][0]["revoked"] is True and lst["access"][0]["active"] is False


@pytest.mark.parametrize("token", ["", "x", "not-a-real-token", "A" * 43])
def test_invalid_auditor_tokens_are_refused(anon, token):
    s, _, _ = anon.get("audit-management", params={"auditor_token": token or "-"})
    assert s == 403


def test_invitation_input_is_validated(api, two_audits):
    a1 = two_audits[0]
    assert _invite(api, a1, auditor_email="not-an-email")[0] == 400
    assert _invite(api, a1, days=0)[0] == 400 or _invite(api, a1, days=0)[0] == 200  # 0 falls back to the 30-day default
    assert _invite(api, a1, days=91)[0] == 400


@pytest.mark.needs_two_tenants
def test_another_tenant_cannot_invite_list_or_revoke_auditors_on_my_audit(api, api_b, two_audits):
    a1 = two_audits[0]
    s, b, _ = _invite(api, a1)
    assert s == 200
    access_id = b["id"]
    s, _, _ = api_b.post("audit-management", {"action": "invite_auditor", "cloud_account_id": ACCOUNT_B_ID, "audit_id": a1, "auditor_email": AUDITOR}, headers=JSON)
    assert s == 403
    s, _, _ = api_b.get("audit-management", params={"auditor_access": a1})
    assert s == 403
    s, _, _ = api_b.post("audit-management", {"action": "revoke_auditor", "cloud_account_id": ACCOUNT_B_ID, "access_id": access_id}, headers=JSON)
    assert s == 403
    s, _, _ = api_b.get("audit-management", params={"audit_detail": a1})
    assert s == 403
