"""IDOR / BOLA matrix: every action that names only a record id (no account) must be checked against the record's
real owner. Tenant B owns real records of every kind; tenant A tries every mutating or reading action on them and
must get 403 each time — and B's records must be unchanged afterwards."""
import uuid

import pytest

from conftest import ACCOUNT_B_ID, ACCOUNT_ID, TEST_PREFIX

pytestmark = [pytest.mark.live, pytest.mark.needs_two_tenants, pytest.mark.flow("E2E-PERM-001"), pytest.mark.severity("P0")]
JSON = {"Content-Type": "application/json"}


def _tag():
    return f"{TEST_PREFIX} idor {uuid.uuid4().hex[:6]}"


@pytest.fixture(scope="module")
def b(api_b):
    """Records of every kind owned by tenant B, created through B's own session and removed afterwards."""
    ids, undo = {}, []

    def post(path, body):
        s, r, _ = api_b.post(path, {"cloud_account_id": ACCOUNT_B_ID, **body}, headers=JSON)
        assert s == 200, (path, body.get("action"), s, r)
        return r

    v = post("tprm", {"action": "create_vendor", "name": _tag(), "criticality": "low", "actor_name": "e2e"})["id"]
    ids["vendor"] = v
    undo.append(lambda: api_b.post("tprm", {"action": "delete_vendor", "cloud_account_id": ACCOUNT_B_ID, "vendor_id": v, "actor_name": "e2e"}, headers=JSON))
    ids["vendor_task"] = post("tprm", {"action": "create_remediation_task", "vendor_id": v, "title": "e2e task", "actor_name": "e2e"})["id"]
    ids["assessment"] = post("tprm", {"action": "create_assessment", "vendor_id": v, "actor_name": "e2e"})["id"]
    import base64 as _b64
    ids["certification"] = post("tprm", {"action": "upload_certification", "vendor_id": v, "certification_type": "ISO27001",
                                          "filename": "cert.pdf", "file_base64": _b64.b64encode(b"e2e certificate").decode(),
                                          "actor_name": "e2e"})["id"]

    a = post("audit-management", {"action": "create_audit", "title": _tag(), "audit_type": "internal"})["id"]
    ids["audit"] = a
    undo.append(lambda: api_b.post("audit-management", {"action": "delete_audit", "cloud_account_id": ACCOUNT_B_ID, "audit_id": a}, headers=JSON))
    ids["finding"] = post("audit-management", {"action": "add_manual_finding", "audit_id": a, "title": "e2e finding", "severity": "LOW"})["id"]
    ids["audit_task"] = post("audit-management", {"action": "create_remediation_task", "finding_id": ids["finding"], "title": "e2e fix"})["id"]
    import base64
    ids["evidence"] = post("audit-management", {"action": "upload_evidence", "audit_id": a, "title": "e2e evidence", "filename": "e.txt",
                                                "file_base64": base64.b64encode(b"private evidence").decode()})["id"]
    ids["auditor_access"] = post("audit-management", {"action": "invite_auditor", "audit_id": a, "auditor_email": "success@simulator.amazonses.com"})["id"]

    q = post("questionnaires", {"action": "upload", "name": _tag(), "filename": "e.csv", "csv_text": "Question\nDo you encrypt data?\n"})["id"]
    ids["questionnaire"] = q
    undo.append(lambda: api_b.delete("questionnaires", params={"questionnaire_id": q}))
    _, detail, _ = api_b.get("questionnaires", params={"questionnaire_id": q})
    ids["q_item"] = detail["items"][0]["id"]

    f = post("custom-frameworks", {"action": "create_framework", "name": _tag()})["id"]
    ids["framework"] = f
    undo.append(lambda: api_b.delete("custom-frameworks", params={"framework_id": f}))
    ids["control"] = post("custom-frameworks", {"action": "add_control", "framework_id": f, "title": "c", "severity": "LOW", "checks": ["IAM.5"]})["id"]

    ids["scenario"] = post("calculators", {"action": "save_scenario", "calculator_type": "compliance_effort", "title": _tag()})["id"]
    yield ids
    cleanup_failures = []
    for fn in reversed(undo):
        try:
            fn()
        except Exception as e:
            cleanup_failures.append(str(e))
    api_b.post("calculators", {"action": "delete_scenario", "cloud_account_id": ACCOUNT_B_ID, "scenario_id": ids["scenario"]}, headers=JSON)
    # A swallowed cleanup failure here leaves a real record behind in tenant B under a
    # test fixture nobody is watching — it must be visible, not silent, even though the
    # test itself already yielded and can't turn this into a failed assertion.
    if cleanup_failures:
        print(f"WARNING: {len(cleanup_failures)} teardown cleanup call(s) failed for fixture 'b': {cleanup_failures}")


def _cases(ids):
    """(id, method, path, params, body) — every id-only action in the API surface."""
    return [
        ("tprm.update_vendor", "post", "tprm", None, {"action": "update_vendor", "vendor_id": ids["vendor"], "fields": {"criticality": "critical"}}),
        ("tprm.delete_vendor", "post", "tprm", None, {"action": "delete_vendor", "vendor_id": ids["vendor"]}),
        ("tprm.create_remediation_task", "post", "tprm", None, {"action": "create_remediation_task", "vendor_id": ids["vendor"], "title": "x"}),
        ("tprm.update_remediation_task", "post", "tprm", None, {"action": "update_remediation_task", "vendor_id": ids["vendor"], "task_id": ids["vendor_task"], "status": "in_progress"}),
        ("tprm.update_remediation_task_by_task_id_only", "post", "tprm", None, {"action": "update_remediation_task", "task_id": ids["vendor_task"], "vendor_id": str(uuid.uuid4()), "status": "in_progress"}),
        ("tprm.create_incident", "post", "tprm", None, {"action": "create_incident", "vendor_id": ids["vendor"], "title": "x"}),
        ("tprm.create_assessment", "post", "tprm", None, {"action": "create_assessment", "vendor_id": ids["vendor"]}),
        ("tprm.update_assessment", "post", "tprm", None, {"action": "update_assessment", "assessment_id": ids["assessment"], "vendor_id": str(uuid.uuid4()), "status": "in_progress"}),
        ("tprm.get_vendor_detail", "get", "tprm", {"vendor_id": ids["vendor"]}, None),
        ("audit.get_detail_by_audit_detail_param", "get", "audit-management", {"audit_detail": ids["audit"]}, None),
        ("audit.download_evidence_param", "get", "audit-management", {"download_evidence": ids["evidence"]}, None),
        ("audit.list_trust_documents_param", "get", "audit-management", {"trust_documents": ACCOUNT_B_ID}, None),
        ("audit.list_auditor_access", "get", "audit-management", {"auditor_access": ids["audit"]}, None),
        ("audit.revoke_auditor", "post", "audit-management", None, {"action": "revoke_auditor", "access_id": ids["auditor_access"]}),
        ("audit.invite_auditor", "post", "audit-management", None, {"action": "invite_auditor", "audit_id": ids["audit"], "auditor_email": "success@simulator.amazonses.com"}),
        ("audit.update_audit", "post", "audit-management", None, {"action": "update_audit", "audit_id": ids["audit"], "status": "completed"}),
        ("audit.delete_audit", "post", "audit-management", None, {"action": "delete_audit", "audit_id": ids["audit"]}),
        ("audit.add_manual_finding", "post", "audit-management", None, {"action": "add_manual_finding", "audit_id": ids["audit"], "title": "x"}),
        ("audit.update_finding_status", "post", "audit-management", None, {"action": "update_finding_status", "finding_id": ids["finding"], "status": "closed"}),
        ("audit.update_finding_root_cause", "post", "audit-management", None, {"action": "update_finding_root_cause", "finding_id": ids["finding"], "root_cause": "x"}),
        ("audit.add_finding_comment", "post", "audit-management", None, {"action": "add_finding_comment", "finding_id": ids["finding"], "body": "x"}),
        ("audit.create_remediation_task", "post", "audit-management", None, {"action": "create_remediation_task", "finding_id": ids["finding"], "title": "x"}),
        ("audit.update_remediation_task", "post", "audit-management", None, {"action": "update_remediation_task", "task_id": ids["audit_task"], "status": "completed"}),
        ("questionnaires.get_detail", "get", "questionnaires", {"questionnaire_id": ids["questionnaire"]}, None),
        ("questionnaires.update_item", "post", "questionnaires", None, {"action": "update_item", "item_id": ids["q_item"], "answer_text": "hijacked"}),
        ("questionnaires.add_comment", "post", "questionnaires", None, {"action": "add_comment", "item_id": ids["q_item"], "author_name": "x", "comment_text": "x"}),
        ("questionnaires.rename", "post", "questionnaires", None, {"action": "rename_questionnaire", "questionnaire_id": ids["questionnaire"], "name": "hijacked"}),
        ("questionnaires.create_share_link", "post", "questionnaires", None, {"action": "create_share_link", "questionnaire_id": ids["questionnaire"]}),
        ("questionnaires.delete", "delete", "questionnaires", {"questionnaire_id": ids["questionnaire"]}, None),
        ("custom_frameworks.add_control", "post", "custom-frameworks", None, {"action": "add_control", "framework_id": ids["framework"], "title": "x", "checks": ["IAM.5"]}),
        ("custom_frameworks.delete_control", "delete", "custom-frameworks", {"control_id": ids["control"]}, None),
        ("custom_frameworks.delete_framework", "delete", "custom-frameworks", {"framework_id": ids["framework"]}, None),
        ("calculators.delete_scenario", "post", "calculators", None, {"action": "delete_scenario", "scenario_id": ids["scenario"]}),
        # Alias query-param IDOR paths (found in the pre-livegang review, C01/T01): these
        # carry the real id under the action's own name instead of cloud_account_id/
        # vendor_id. Tenant A's OWN real, owned account_id is deliberately included
        # alongside the alias — without the fix, guard() only ever checked that
        # (correctly owned) account and let the request through regardless of whose
        # record the alias actually named; that's the exact shape of the real bug.
        ("calculators.gap_data_alias", "get", "calculators", {"cloud_account_id": ACCOUNT_ID, "gap_data": ACCOUNT_B_ID, "framework": "ISO27001"}, None),
        ("calculators.list_scenarios_alias", "get", "calculators", {"cloud_account_id": ACCOUNT_ID, "list_scenarios": ACCOUNT_B_ID}, None),
        ("tprm.download_certification_alias", "get", "tprm", {"cloud_account_id": ACCOUNT_ID, "download_certification": ids["certification"]}, None),
        ("tprm.download_contract_alias", "get", "tprm", {"cloud_account_id": ACCOUNT_ID, "download_contract": ids["vendor"]}, None),
        ("tprm.assessment_items_alias", "get", "tprm", {"cloud_account_id": ACCOUNT_ID, "assessment_items": ids["assessment"]}, None),
        ("tprm.evidence_package_alias", "get", "tprm", {"cloud_account_id": ACCOUNT_ID, "evidence_package": ids["vendor"]}, None),
    ]


CASE_IDS = [c[0] for c in _cases({k: "00000000-0000-4000-8000-000000000000" for k in
            ("vendor", "vendor_task", "assessment", "audit", "finding", "audit_task", "evidence", "auditor_access",
             "questionnaire", "q_item", "framework", "control", "scenario", "certification")})]


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_tenant_a_cannot_use_an_id_only_action_on_tenant_bs_record(api, b, case_id):
    _, method, path, params, body = next(c for c in _cases(b) if c[0] == case_id)
    status, _, _ = getattr(api, method)(path, *( [body] if method == "post" else []), **({"headers": JSON} if method == "post" else {}), **({"params": params} if params else {}))
    assert status == 403, f"{case_id} answered {status} instead of 403"


def test_after_every_attempt_tenant_bs_records_are_untouched(api_b, b):
    _, v, _ = api_b.get("tprm", params={"cloud_account_id": ACCOUNT_B_ID})
    vendor = next(x for x in v["vendors"] if x["id"] == b["vendor"])
    assert vendor["criticality"] == "low"
    _, a, _ = api_b.get("audit-management", params={"cloud_account_id": ACCOUNT_B_ID})
    assert any(x["id"] == b["audit"] for x in a["audits"])
    _, q, _ = api_b.get("questionnaires", params={"questionnaire_id": b["questionnaire"]})
    assert q["items"][0]["id"] == b["q_item"] and (q["items"][0].get("answer_text") or "") != "hijacked"
    _, f, _ = api_b.get("custom-frameworks", params={"cloud_account_id": ACCOUNT_B_ID})
    fw = next(x for x in f["frameworks"] if x["id"] == b["framework"])
    assert len(fw["controls"]) == 1
    _, c, _ = api_b.get("calculators", params={"cloud_account_id": ACCOUNT_B_ID})
    assert any(x.get("id") == b["scenario"] for x in c.get("scenarios", [])) or "scenarios" not in c
