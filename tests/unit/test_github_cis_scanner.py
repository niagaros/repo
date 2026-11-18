"""CIS GitHub Benchmark scanner: a check whose data the connected token cannot read is NOT CHECKED, never a PASS
or FAIL made from missing data. The GitHub API is simulated with the status codes GitHub returns to an organisation
member (no owner rights, no repository admin) and to an owner/admin."""
from unittest.mock import MagicMock

import pytest

pytest.importorskip("requests")
from collectors.github import lambda_handler as G  # noqa: E402

pytestmark = [pytest.mark.flow("E2E-GITHUB-CIS-001"), pytest.mark.severity("P1")]

ORG = "acme"
ORG_PUBLIC = {"login": ORG, "is_verified": False}
ORG_OWNER = {**ORG_PUBLIC, "two_factor_requirement_enabled": True, "members_can_create_repositories": False,
             "members_can_delete_repositories": False, "default_repository_permission": "read"}
BP = {"required_pull_request_reviews": {"required_approving_review_count": 2, "dismiss_stale_reviews": True,
                                        "require_code_owner_reviews": True},
      "enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": False}}


def resp(status, body=None):
    r = MagicMock(status_code=status)
    r.content = b"x" if body is not None else b""
    r.json.return_value = body
    return r


def api(owner):
    """Route table: what GitHub answers to an owner/admin (owner=True) or to an ordinary member."""
    repo = {"name": "app", "full_name": f"{ORG}/app", "private": True, "default_branch": "main", "permissions": {"admin": owner, "pull": True}}

    def get(url, headers=None, timeout=None, params=None):
        path = url.replace(G.GITHUB_API, "")
        if path == f"/orgs/{ORG}":
            return resp(200, ORG_OWNER if owner else ORG_PUBLIC)
        if path == f"/orgs/{ORG}/repos":
            return resp(200, [repo])
        if path == f"/orgs/{ORG}/members":
            return resp(200, []) if owner else resp(422, {"message": "Only owners can use this filter."})
        if path == f"/orgs/{ORG}/outside_collaborators":
            return resp(200, []) if owner else resp(403, {"message": "Must be an org owner"})
        if path.endswith("/branches/main/protection"):
            return resp(200, BP) if owner else resp(404, {"message": "Not Found"})
        if path.endswith("/contents/CODEOWNERS"):
            return resp(200, {})
        if "/contents/" in path:
            return resp(404, {"message": "Not Found"})
        if path.endswith("/vulnerability-alerts"):
            return resp(204) if owner else resp(404)
        if path == f"/repos/{ORG}/app":
            return resp(200, {**repo, **({"security_and_analysis": {"secret_scanning": {"status": "enabled"}}} if owner else {})})
        return resp(404, {"message": "Not Found"})
    return get


def scan(owner):
    c = G.GitHubClient("t", ORG)
    c.s = MagicMock()
    c.s.get.side_effect = api(owner)
    snapshot = c.collect_snapshot()
    return snapshot, *G.run_checks(snapshot)


def test_member_token_never_produces_a_pass_from_refused_data():
    snapshot, findings, not_checked = scan(owner=False)
    scored = {f["control_id"] for f in findings}
    skipped = {n["control_id"] for n in not_checked}
    # the MFA checks used to PASS on a 403/422 ("0 members without MFA")
    assert {"github_1.3.4", "github_1.3.5", "github_1.2.2", "github_1.2.3", "github_1.3.8"} <= skipped
    # branch protection, Dependabot and secret scanning used to FAIL for a non-admin
    assert {"github_1.1.20", "github_1.1.3", "github_1.5.5", "github_1.5.1"} <= skipped
    assert not scored & skipped
    # what a member CAN read is still scored
    assert {"github_1.1.6", "github_1.3.9"} <= scored
    mfa = next(n for n in not_checked if n["control_id"] == "github_1.3.5")
    assert "organisation owners" in mfa["reason"]


def test_owner_token_scores_everything():
    snapshot, findings, not_checked = scan(owner=True)
    assert not_checked == []
    by = {f["control_id"]: f["status"] for f in findings}
    assert by["github_1.3.5"] == "PASS" and by["github_1.1.20"] == "PASS" and by["github_1.5.5"] == "PASS"
    assert "github_1.2.1" not in by                    # private repository: SECURITY.md does not apply


def test_unprotected_branch_is_a_real_fail_for_an_admin():
    c = G.GitHubClient("t", ORG)
    c.s = MagicMock()
    base = api(True)
    c.s.get.side_effect = lambda url, **kw: resp(404, {"message": "Branch not protected"}) if url.endswith("/protection") else base(url, **kw)
    findings, not_checked = G.run_checks(c.collect_snapshot())
    assert {f["control_id"]: f["status"] for f in findings}["github_1.1.20"] == "FAIL" and not not_checked


def test_an_unreadable_organisation_stops_the_scan():
    c = G.GitHubClient("t", ORG)
    c.s = MagicMock()
    c.s.get.return_value = resp(401, {"message": "Bad credentials"})
    with pytest.raises(RuntimeError, match="could not be read"):
        c.collect_snapshot()


def test_a_failing_page_is_not_an_empty_list():
    c = G.GitHubClient("t", ORG)
    c.s = MagicMock()
    c.s.get.side_effect = [resp(200, [{"login": f"u{i}"} for i in range(100)]), resp(502, None)]
    items, ok = c._pages_checked("/orgs/acme/members")
    assert len(items) == 100 and ok is False


def test_an_earlier_result_is_kept_but_marked_not_rechecked():
    snapshot, findings, not_checked = scan(owner=False)
    cur = MagicMock()
    cur.fetchone.return_value = ["00000000-0000-0000-0000-000000000001"]
    cur.rowcount = 1
    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cur
    stats = G.save_results(conn, findings, snapshot, "acc", not_checked)
    sql = [c.args for c in cur.execute.call_args_list]
    marked = [a for a in sql if a[0].lstrip().startswith("UPDATE findings SET details")]
    assert {a[1][2] for a in marked} >= {"github_1.3.5", "github_1.1.20"} and stats["results_marked_not_rechecked"] == len(marked)
    assert not any(a[0].startswith("DELETE FROM findings") and a[1][1] != G.FRAMEWORK and "github_1.2.1" not in a[0] for a in sql)
    assert any("github_1.2.1" in a[0] for a in sql if a[0].startswith("DELETE"))     # private repo: SECURITY.md does not apply
