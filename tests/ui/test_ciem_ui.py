"""CIEM page (issue #17) in a real browser. The fake backend serves output of the real ciem_engine, so the page
is exercised with the data shapes it will get in production. Includes an identity whose name is an XSS payload."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from collectors.aws.scanner import ciem_engine as E
from ui_support import ACCOUNT, CORS

pytestmark = [pytest.mark.flow("E2E-CIEM-001"), pytest.mark.severity("P1")]

AWS = "111122223333"
NOW = datetime.now(timezone.utc)
XSS = '<img src=x onerror="window.__xss=1">'


def _engine_output():
    admin = {"Arn": "arn:aws:iam::aws:policy/AdministratorAccess", "name": "AdministratorAccess",
             "document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}, "aws_managed": True}
    raw = {
        "policies": [admin],
        "users": [{"UserName": XSS, "Arn": f"arn:aws:iam::{AWS}:user/evil", "Path": "/", "CreateDate": NOW - timedelta(days=400),
                   "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": admin["Arn"]}],
                   "UserPolicyList": [], "GroupList": [], "Tags": []}],
        "groups": [],
        "roles": [{"RoleName": "vendor", "Arn": f"arn:aws:iam::{AWS}:role/vendor", "Path": "/", "CreateDate": NOW - timedelta(days=400),
                   "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}]},
                   "AttachedManagedPolicies": [], "RolePolicyList": [], "Tags": []}],
        "credential_report": {XSS: {"password_enabled": True, "mfa_active": False, "keys": [], "access_keys_active": False}},
        "access_advisor": {}, "external_access": [], "limitations": ["IAM Access Analyzer is not enabled in eu-west-1"],
    }
    ids, findings, summary = E.analyze(raw, AWS, 90, {})
    summary["least_privilege"] = E.least_privilege_score(ids, findings)
    for n, f in enumerate(findings):
        f["id"] = f"00000000-0000-0000-0000-{n:012d}"
        f["status"] = "open"
        f["first_seen"] = f["last_seen"] = NOW.isoformat()
    return [E.public_view(i) for i in ids], findings, summary, raw["limitations"]


class FakeCiem:
    def __init__(self):
        self.ids, self.findings, self.summary, self.limits = _engine_output()
        self.posts = []

    def _json(self, route, payload, status=200):
        route.fulfill(status=status, content_type="application/json", headers=CORS, body=json.dumps(payload, default=str))

    def handle(self, route):
        req = route.request
        if req.method == "OPTIONS":
            return route.fulfill(status=200, headers=CORS, body="")
        if req.method == "POST":
            body = json.loads(req.post_data or "{}")
            self.posts.append(body)
            return self._json(route, {"ok": True, "status": body.get("status")})
        from urllib.parse import parse_qs, urlparse
        qs = {k: v[0] for k, v in parse_qs(urlparse(req.url).query).items()}
        assert qs.get("cloud_account_id") == ACCOUNT
        v = qs.get("view")
        scan = {"id": "s1", "status": "succeeded", "started_at": NOW.isoformat(), "finished_at": NOW.isoformat(),
                "observation_days": 90, "summary": self.summary, "limitations": self.limits, "coverage": {}}
        if v == "overview":
            top = sorted([i for i in self.ids if i["kind"] != "group"], key=lambda i: -i["risk_score"])
            return self._json(route, {"latest_scan": scan, "last_attempt": scan, "trend": [],
                                      "finding_counts": {"open": self.summary["findings_by_severity"]},
                                      "remediation": {"resolved": 0, "open": len(self.findings), "resolved_last_30_days": 0},
                                      "top_identities": [{k: i[k] for k in ("arn", "name", "kind", "classification", "risk_score", "risk_severity", "risk_reasons")} for i in top]})
        if v == "identities":
            return self._json(route, {"latest_scan": scan, "identities": [
                {"arn": i["arn"], "name": i["name"], "kind": i["kind"], "classification": i["classification"],
                 "classification_basis": i.get("classification_basis"), "risk_score": i["risk_score"], "risk_severity": i["risk_severity"],
                 "admin": i.get("admin"), "owner": i.get("owner"), "open_findings": 1} for i in self.ids]})
        if v == "identity":
            i = next(x for x in self.ids if x["arn"] == qs["arn"])
            return self._json(route, {"identity": {**i, "policy_documents": {}}, "risk_history": [],
                                      "findings": [{"id": f["id"], "severity": f["severity"], "title": f["title"], "status": "open", "category": f["category"]}
                                                   for f in self.findings if f["identity_arn"] == i["arn"]]})
        if v == "findings":
            return self._json(route, {"findings": [{k: f.get(k) for k in ("id", "rule", "category", "severity", "title", "identity_arn", "status", "first_seen")} for f in self.findings]})
        if v == "finding":
            f = next(x for x in self.findings if x["id"] == qs["finding_id"])
            return self._json(route, {"finding": {**f, "integrations": []}})
        if v == "settings":
            return self._json(route, {"observation_days": 90, "observation_choices": [30, 60, 90, 180, 365],
                                      "rules": [{"id": k, "title": t, "enabled": True, "severity": s, "default_severity": s} for k, (t, s) in E.POLICY_RULES.items()]})
        if v == "paths":
            return self._json(route, {"paths": [{"arn": i["arn"], "name": i["name"], "kind": i["kind"], "escalation": i.get("escalation", []), "can_assume": i.get("can_assume", [])} for i in self.ids]})
        if v == "external":
            return self._json(route, {"trusts": [{"role_arn": i["arn"], "role": i["name"], **t} for i in self.ids for t in i.get("trust", [])],
                                      "resources": [], "coverage": {"ok": False, "error": "no active analyzer"}})
        if v == "reviews":
            return self._json(route, {"reviews": []})
        if v in ("audit", "scans"):
            return self._json(route, {"audit": [], "scans": []})
        return self._json(route, {"error": "unknown view"}, 400)


@pytest.fixture
def ciem(page, site):
    backend = FakeCiem()
    page.route("**/default/ciem**", backend.handle)
    page.route("**/default/notifications**", lambda r: r.fulfill(status=200, headers=CORS, content_type="application/json", body='{"notifications": []}'))
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{site}/ciem.html?account_id={ACCOUNT}")
    page.wait_for_selector("text=Last collection", timeout=15000)
    return page, backend, errors


def test_overview_shows_real_metrics_and_limitations(ciem):
    page, backend, errors = ciem
    assert page.locator("text=IAM Access Analyzer is not enabled").is_visible()
    assert page.locator(".metric").count() >= 10
    assert page.locator("text=Coming later").is_visible()
    assert not errors


def test_identity_names_are_escaped(ciem):
    page, _, errors = ciem
    page.click("[data-tab=identities]")
    page.wait_for_selector("#id-table table")
    assert page.locator("#id-table").inner_text().count("<img") == 1          # shown as text
    assert page.evaluate("window.__xss") is None                               # never executed
    page.locator("#id-table tr.click", has_text="<img").click()
    page.wait_for_selector("text=Effective access")
    assert page.evaluate("window.__xss") is None and not errors


def test_identity_detail_shows_evidence_and_unknown_unused(ciem):
    page, _, _ = ciem
    page.click("[data-tab=identities]")
    page.locator("#id-table tr.click", has_text="vendor").click()
    page.wait_for_selector("text=Who can assume this role")
    drawer = page.locator("#drawer").inner_text()
    assert "999988887777" in drawer and "external_account" in drawer
    assert "Niagaros does not call access “unused” without activity data" in drawer


def test_accepting_a_risk_sends_reason_and_end_date(ciem):
    page, backend, _ = ciem
    page.click("[data-tab=findings]")
    page.wait_for_selector("#f-table table")
    page.locator("#f-table tr.click").first.click()
    page.wait_for_selector("text=Recommendation")
    assert page.locator("#drawer").inner_text().count("Rollback") == 1
    page.select_option("#st-new", "accepted")
    page.fill("#st-reason", "Compensating control documented")
    page.fill("#st-until", "2027-01-31")
    page.click("[data-act=status]")
    page.wait_for_function("document.getElementById('toast').textContent.length > 0")
    assert backend.posts[-1] == {"cloud_account_id": ACCOUNT, "action": "set_finding_status", "finding_id": backend.findings[0]["id"],
                                 "status": "accepted", "reason": "Compensating control documented", "accepted_until": "2027-01-31"}


def test_settings_save_posts_rules(ciem):
    page, backend, _ = ciem
    page.click("[data-tab=settings]")
    page.wait_for_selector("[data-rule-on=machine_identity_owner]")
    page.uncheck("[data-rule-on=machine_identity_owner]")
    page.select_option("#obs", "180")
    page.click("[data-act=settings-save]")
    page.wait_for_function("document.getElementById('toast').textContent.length > 0")
    body = backend.posts[-1]
    assert body["observation_days"] == 180 and body["rules"]["machine_identity_owner"]["enabled"] is False


def test_every_tab_renders_without_errors_on_a_phone(page, site):
    backend = FakeCiem()
    page.route("**/default/ciem**", backend.handle)
    page.route("**/default/notifications**", lambda r: r.fulfill(status=200, headers=CORS, content_type="application/json", body='{"notifications": []}'))
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.set_viewport_size({"width": 390, "height": 800})
    page.goto(f"{site}/ciem.html?account_id={ACCOUNT}")
    page.wait_for_selector("text=Last collection", timeout=15000)
    for tab in ("identities", "findings", "paths", "external", "reviews", "settings", "reports"):
        page.click(f"[data-tab={tab}]")
        page.wait_for_function("!document.getElementById('view').textContent.includes('Loading…')")
        assert "error" not in page.locator("#view .err").all_inner_texts().__str__().lower() or tab == "reports"
        assert page.evaluate("document.documentElement.scrollWidth") <= 392, tab
    assert not errors


def test_backend_error_is_shown_not_swallowed(page, site):
    page.route("**/default/ciem**", lambda r: r.fulfill(status=403, headers=CORS, content_type="application/json", body='{"error": "Forbidden"}'))
    page.goto(f"{site}/ciem.html?account_id={ACCOUNT}")
    page.wait_for_selector(".err")
    assert "Forbidden" in page.locator(".err").inner_text()
