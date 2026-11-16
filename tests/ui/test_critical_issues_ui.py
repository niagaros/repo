"""Zero Critical Issues page (#296) in a real browser. The fake backend builds its answers with the real handler's
posture() and _counts(), so the page is exercised with production data shapes. One issue title is an XSS payload."""
import json
from datetime import date, datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from collectors.aws.scanner import critical_issues_handler as H
from ui_support import ACCOUNT, CORS

pytestmark = [pytest.mark.flow("E2E-CRIT-001"), pytest.mark.severity("P1")]

NOW = datetime.now(timezone.utc)
XSS = '<img src=x onerror="window.__xss=1">'


def _issue(n, title, status, **kw):
    base = {"id": f"00000000-0000-0000-0000-{n:012d}", "source": "findings", "source_id": f"10000000-0000-0000-0000-{n:012d}",
            "title": title, "status": status, "display_status": "verification_pending" if status == "remediated" else status,
            "owner_email": None, "due_date": str(date.today() + timedelta(days=3)), "remediation_plan": None,
            "first_detected_at": (NOW - timedelta(days=12)).isoformat(), "last_observed_at": NOW.isoformat(),
            "remediated_at": None, "remediated_by": None, "resolved_at": None, "verified_by_scan_at": None, "reopen_count": 0,
            "escalated_at": None, "risk_justification": None, "risk_rationale": None, "risk_owner": None, "risk_approver": None,
            "compensating_controls": None, "residual_risk": None, "risk_expires_on": None, "risk_review_every_days": None,
            "risk_approval": None, "risk_requested_by": None, "risk_requested_at": None, "risk_decided_at": None,
            "false_positive_evidence": None, "created_at": (NOW - timedelta(days=12)).isoformat(), "updated_at": NOW.isoformat(),
            "source_label": "Cloud posture", "source_page": "niagaros-dashboard.html", "still_reported": True,
            "asset": {"type": "iam-account", "id": "account", "name": "account", "region": None}, "check_id": "IAM.6",
            "framework": "AWS Foundational Security Best Practices", "overdue": False, "age_days": 12,
            "risk_score": 80, "risk_factors": [{"factor": "Severity: critical (from the scanner)", "points": 70},
                                              {"factor": "Affects identity and access for the whole account", "points": 10}],
            "pending_risk_request": False}
    base.update(kw)
    return base


class FakeBackend:
    def __init__(self):
        self.issues = [
            _issue(1, XSS, "open", overdue=True, due_date=str(date.today() - timedelta(days=2)), escalated_at=NOW.isoformat()),
            _issue(2, "S3.1: Bucket is public", "remediated", owner_email="owner@a.test", risk_score=72),
            _issue(3, "Root access key exists", "accepted_risk", risk_score=None, risk_factors=[], risk_justification="Break-glass",
                   risk_owner="CISO", risk_requested_by="a@a.test", risk_approver="b@a.test", risk_approval="approved",
                   compensating_controls="Alarm on root login", risk_expires_on=str(date.today() + timedelta(days=60))),
        ]
        self.posts = []

    def _json(self, route, payload, status=200):
        route.fulfill(status=status, content_type="application/json", headers=CORS, body=json.dumps(payload, default=str))

    def _coverage(self):
        return {"account_status": "active", "account_name": "Test account", "last_scan_at": NOW.isoformat(), "freshness_days": 10,
                "domains": [{"domain": "Cloud posture (AWS configuration)", "required": True, "evidence_at": NOW.isoformat(),
                             "state": "fresh", "detail": "40 resources across 5 resource types"},
                            {"domain": "Identity & entitlements (CIEM)", "required": True, "evidence_at": None, "state": "missing",
                             "detail": "Never scanned"},
                            {"domain": "AI assets", "required": False, "evidence_at": None, "state": "missing", "detail": "Never scanned"}],
                "required_covered": 1, "required_total": 2, "coverage_pct": 50, "complete": False, "stale": False,
                "not_assessed": ["Workload runtime", "Kubernetes"]}

    def handle(self, route):
        req = route.request
        if req.method == "OPTIONS":
            return route.fulfill(status=200, headers=CORS, body="")
        if req.method == "POST":
            body = json.loads(req.post_data or "{}")
            self.posts.append(body)
            if body.get("action") == "assign" and "@" not in (body.get("owner_email") or ""):
                return self._json(route, {"error": "Owner must be an email address"}, 400)
            return self._json(route, {"saved": True})
        qs = {k: v[0] for k, v in parse_qs(urlparse(req.url).query).items()}
        v = qs.get("view")
        if v != "portfolio":
            assert qs.get("cloud_account_id") == ACCOUNT
        counts = H._counts([{**i, "created_at": datetime.fromisoformat(i["created_at"]),
                             "escalated_at": i["escalated_at"]} for i in self.issues])
        if v == "overview":
            cov = self._coverage()
            return self._json(route, {"posture": H.posture(counts, cov), "counts": counts, "coverage": cov,
                                      "metrics": {"mean_time_to_remediate_days": None, "oldest_open_days": 12,
                                                  "remediation_success_rate_pct": None},
                                      "by_domain": {"Cloud posture": 2}, "by_asset_type": {}, "top": self.issues[:2],
                                      "settings": {"sla_days": 7, "freshness_days": 10}, "accepted_in_modules": [],
                                      "scope": {"account_name": "Test account", "provider": "AWS", "rule": "Critical = severity CRITICAL."},
                                      "calculated_at": NOW.isoformat()})
        if v == "issues":
            return self._json(route, {"issues": self.issues})
        if v == "issue":
            i = next(x for x in self.issues if x["id"] == qs["issue_id"])
            return self._json(route, {"issue": i, "evidence": {"failed": 1}, "description": None, "recommendation": "Enable hardware MFA",
                                      "recommendation_detail": None,
                                      "history": [{"at": NOW.isoformat(), "actor": "scanner", "event": "detected", "detail": {}},
                                                  {"at": NOW.isoformat(), "actor": "system", "event": "escalated", "detail": {"reason": "deadline passed"}}]})
        if v == "history":
            return self._json(route, {"snapshots": [{"day": str(date.today()), "status": "critical_issues_present", "open": 1,
                                                     "accepted": 1, "overdue": 1, "evidence": {"coverage_pct": 50}}],
                                      "events": [{"at": NOW.isoformat(), "actor": "scanner", "event": "detected", "title": XSS,
                                                  "issue_id": self.issues[0]["id"]}]})
        if v == "portfolio":
            return self._json(route, {"accounts": [{"cloud_account_id": ACCOUNT, "account_name": XSS, "account_status": "active",
                                                    "last_scan_at": NOW.isoformat(), "business_units": "Payments",
                                                    "last_status": "critical_issues_present", "unresolved": 2, "accepted": 1}],
                                      "note": "Daily snapshot."})
        if v == "settings":
            return self._json(route, {"sla_days": 7, "freshness_days": 10, "default": True})
        if v == "export":
            if qs.get("format") == "csv":
                return route.fulfill(status=200, headers={**CORS, "content-type": "text/csv"}, body="id,title\n")
            return self._json(route, {"issues": self.issues})
        return self._json(route, {"error": "unknown view"}, 400)


@pytest.fixture
def crit(page, site):
    backend = FakeBackend()
    page.route("**/default/critical-issues**", backend.handle)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{site}/critical_issues.html?account_id={ACCOUNT}")
    page.wait_for_selector(".status h2", timeout=15000)
    return page, backend, errors


def test_status_is_not_zero_and_says_why(crit):
    page, _, errors = crit
    head = page.locator(".status").inner_text()
    assert "Critical Issues Present" in head and "unresolved critical issue" in head
    assert page.locator("text=Accepted risk (still counted here)").is_visible()
    assert page.locator("text=Never scanned").first.is_visible()
    assert "A zero here says nothing about these areas" in page.locator("main").inner_text()
    assert page.evaluate("window.__xss") is None and not errors


def test_issue_detail_explains_risk_and_shows_history(crit):
    page, backend, errors = crit
    page.click("[data-tab=issues]")
    page.wait_for_selector("tr.click")
    page.locator("tr.click", has_text="<img").click()
    page.wait_for_selector("text=How the risk score is built")
    d = page.locator("#drawer").inner_text()
    assert "Affects identity and access" in d and "Escalated: deadline passed" in d and "Enable hardware MFA" in d
    assert page.evaluate("window.__xss") is None
    page.fill("#f-owner", "nobody")
    page.click("[data-act=assign]")
    page.wait_for_function("document.getElementById('toast').textContent.includes('email')")
    page.fill("#f-owner", "owner@a.test")
    page.fill("#f-due", (date.today() + timedelta(days=5)).isoformat())
    page.click("[data-act=assign]")
    page.wait_for_function("document.getElementById('toast').textContent.includes('Owner saved')")
    assert backend.posts[-1] == {"cloud_account_id": ACCOUNT, "action": "assign", "issue_id": backend.issues[0]["id"],
                                 "owner_email": "owner@a.test", "due_date": (date.today() + timedelta(days=5)).isoformat()}
    assert not errors


def test_risk_exception_request_sends_every_required_field(crit):
    page, backend, _ = crit
    page.click("[data-tab=issues]")
    page.locator("tr.click", has_text="<img").click()
    page.wait_for_selector("text=Request a risk exception")
    page.locator("#drawer summary", has_text="Request a risk exception").click()
    page.wait_for_selector("#r-just", state="visible")
    for sel, v in (("#r-just", "Legacy system"), ("#r-rat", "Isolated network"), ("#r-owner", "CISO"),
                   ("#r-comp", "WAF rule"), ("#r-res", "Low"), ("#r-exp", "2027-03-01")):
        page.fill(sel, v)
    page.click("[data-act=request-risk]")
    page.wait_for_function("document.getElementById('toast').textContent.length > 0")
    body = backend.posts[-1]
    assert body["action"] == "request_risk_acceptance" and body["expires_on"] == "2027-03-01" and body["review_every_days"] == 90
    assert all(body[k] for k in ("justification", "rationale", "risk_owner", "compensating_controls", "residual_risk"))


def test_every_tab_renders_without_errors_on_a_phone(page, site):
    backend = FakeBackend()
    page.route("**/default/critical-issues**", backend.handle)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.set_viewport_size({"width": 390, "height": 800})
    page.goto(f"{site}/critical_issues.html?account_id={ACCOUNT}")
    page.wait_for_selector(".status h2", timeout=15000)
    for tab in ("issues", "history", "accounts", "settings", "overview"):
        page.click(f"[data-tab={tab}]")
        page.wait_for_function("!document.getElementById('view').textContent.includes('Loading…')")
        assert not page.locator("#view .err").count(), tab
        assert page.evaluate("document.documentElement.scrollWidth") <= 392, tab
    assert page.evaluate("window.__xss") is None and not errors


def test_backend_error_is_shown_plainly(page, site):
    page.route("**/default/critical-issues**", lambda r: r.fulfill(status=500, headers=CORS, content_type="application/json",
                                                                    body='{"error": "Something went wrong while loading critical issues. Please try again."}'))
    page.goto(f"{site}/critical_issues.html?account_id={ACCOUNT}")
    page.wait_for_selector("#view .err")
    assert "Please try again" in page.locator("#view .err").inner_text()
