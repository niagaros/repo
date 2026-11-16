"""Cloud Cost page (#295) in a real browser against a fake backend whose numbers are built with the real cost_engine.
Checks the opt-in for paid AWS requests, honest 'unknown' savings, the approval flow, escaping and the phone layout."""
import json
from datetime import date, datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from collectors.aws.scanner import cost_engine as E
from ui_support import ACCOUNT, CORS

pytestmark = [pytest.mark.flow("E2E-COST-001"), pytest.mark.severity("P1")]

NOW = datetime.now(timezone.utc)
TODAY = date.today()
XSS = '<img src=x onerror="window.__xss=1">'


def _records():
    out = []
    for i in range(1, 40):
        d = (TODAY - timedelta(days=i)).isoformat()
        out.append({"day": d, "service": "Amazon Elastic Compute Cloud - Compute", "record_type": "Usage", "amount": 3.0,
                    "estimated": i < 3, "currency": "USD"})
        out.append({"day": d, "service": XSS, "record_type": "Usage", "amount": 0.5, "estimated": False, "currency": "USD"})
    out.append({"day": (TODAY - timedelta(days=1)).isoformat(), "service": "Tax", "record_type": "Tax", "amount": 1.2, "estimated": True, "currency": "USD"})
    return out


class Fake:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.posts = []
        self.opp_status = "observed"

    def _json(self, route, payload, status=200):
        route.fulfill(status=status, content_type="application/json", headers=CORS, body=json.dumps(payload, default=str))

    def handle(self, route):
        req = route.request
        if req.method == "OPTIONS":
            return route.fulfill(status=200, headers=CORS, body="")
        if req.method == "POST":
            body = json.loads(req.post_data or "{}")
            self.posts.append(body)
            if body["action"] == "enable":
                self.enabled = True
            if body["action"] == "request_approval":
                self.opp_status = "approval_requested"
            if body["action"] == "decide_opportunity":
                return self._json(route, {"error": "The person who asked for approval cannot approve it"}, 403)
            return self._json(route, {"saved": True, "note": "Saved"})
        qs = {k: v[0] for k, v in parse_qs(urlparse(req.url).query).items()}
        v = qs.get("view")
        s = E.summarize(_records(), TODAY)
        ing = {"id": "i1", "status": "succeeded", "started_at": NOW.isoformat(), "finished_at": NOW.isoformat(), "ce_requests": 7,
               "coverage": {"daily_cost": {"state": "ok"}, "rightsizing": {"state": "not_enabled", "reason": "AWS keeps this opt-in"},
                            "allocation": {"state": "not_configured", "reason": "No tag chosen"},
                            "idle_resources": {"eu-west-1": {"state": "ok", "volumes": 3, "addresses": 1, "instances": 2, "load_balancers": 0}}}}
        settings = {"enabled": self.enabled, "enabled_by": "owner@a.test", "enabled_at": NOW.isoformat(), "allocation_tag_key": None,
                    "anomaly_min_amount": 5.0}
        if v == "overview":
            if not self.enabled:
                return self._json(route, {"settings": settings, "latest_ingestion": None, "last_successful_ingestion": None,
                                          "summary": E.summarize([], TODAY), "forecast": None, "alerts": {"open": 0, "acknowledged": 0},
                                          "opportunities": {"count": 0, "monthly_savings_known": 0, "savings_unknown": 0, "verified_monthly_savings": 0},
                                          "allocation": None, "freshness": {"latest_day_with_data": None, "note": "delay"}, "charges_note": "x"})
            s["by_service"][0]["open_findings"] = {"CRITICAL": 2}
            return self._json(route, {"settings": settings, "latest_ingestion": ing, "last_successful_ingestion": ing, "summary": s,
                                      "forecast": {"remaining_month": 40, "month_total": s["month_to_date"] + 40, "basis": "AWS"},
                                      "alerts": {"open": 1, "acknowledged": 0},
                                      "opportunities": {"count": 2, "monthly_savings_known": 8.8, "savings_unknown": 1, "verified_monthly_savings": 0},
                                      "allocation": None, "freshness": {"latest_day_with_data": s["latest_day_with_data"], "note": "AWS billing data arrives with a delay."},
                                      "charges_note": "Each refresh makes about 8 AWS Cost Explorer requests."})
        if v == "explorer":
            return self._json(route, {"group": qs["group"], "rows": [{"key": XSS, "amount": 12.5, "estimated": True, "currency": "USD"}], "total": 12.5})
        if v == "opportunities":
            return self._json(route, {"opportunities": [
                {"id": "o1", "kind": "idle_ebs", "region": "eu-west-1", "resource_id": "vol-1", "title": "Unattached EBS volume vol-1 (100 GiB gp3)",
                 "monthly_savings": 8.8, "savings_basis": "AWS list price for gp3 in eu-west-1 × 100 GiB", "confidence": "high", "risk": "medium", "status": self.opp_status},
                {"id": "o2", "kind": "idle_ebs", "region": "eu-west-1", "resource_id": "vol-2", "title": "Unattached EBS volume vol-2 (10 GiB io2)",
                 "monthly_savings": None, "savings_basis": "No public price found for this volume type; savings unknown", "confidence": "high", "risk": "medium", "status": "observed"}],
                "coverage": ing["coverage"]["idle_resources"], "not_covered": ["EC2 rightsizing (opt-in at AWS)"], "related_findings_note": "No EC2 scanner."})
        if v == "opportunity":
            return self._json(route, {"id": "o1", "title": "Unattached EBS volume vol-1", "resource_id": "vol-1", "region": "eu-west-1",
                                      "monthly_savings": 8.8, "savings_basis": "AWS list price", "confidence": "high", "risk": "medium",
                                      "status": self.opp_status, "first_seen": NOW.isoformat(), "last_seen": NOW.isoformat(),
                                      "requested_by": "owner@a.test" if self.opp_status != "observed" else None,
                                      "recommendation": "Snapshot, then delete.", "rollback": "Restore from snapshot.",
                                      "detail": {"size_gib": 100, "state": "available"}, "history": []})
        if v == "budgets":
            return self._json(route, {"budgets": [{"id": "b1", "name": XSS, "monthly_amount": 100, "currency": "USD", "thresholds": [50, 100],
                                                   "forecast_alert": True, "active": True, "used_pct": 60, "crossed": [50], "forecast_over": True, "remaining": 40}],
                                      "month_to_date": 60, "currency": "USD", "forecast_month_total": 120})
        if v == "alerts":
            return self._json(route, {"alerts": [{"id": "a1", "kind": "anomaly", "title": "Unusual spend on EC2", "status": "open",
                                                  "created_at": NOW.isoformat(), "detail": {"method": "actual > mean + 3σ"}, "amount": 50}]})
        if v == "commitments":
            return self._json(route, {"commitments": [{"kind": "savings_plans", "available": False, "data": {"state": "no_data", "reason": "No Savings Plans"}, "read_at": NOW.isoformat()},
                                                      {"kind": "reservations", "available": True, "data": {"UtilizationPercentage": "0"}, "read_at": NOW.isoformat()}],
                                      "period": "last 30 days", "not_covered": ["Purchase recommendations"]})
        if v in ("ai", "kubernetes"):
            return self._json(route, {"label": v, "services_considered": ["Amazon Bedrock"], "summary": E.summarize([], TODAY), "limitations": ["Provider usage not ingested"]})
        if v == "portfolio":
            return self._json(route, {"accounts": [{"cloud_account_id": ACCOUNT, "account_name": XSS, "enabled": True, "business_units": "Payments",
                                                    "month_to_date": 60, "currency": "USD", "last_ingested": NOW.isoformat()}]})
        if v == "ingestions":
            return self._json(route, {"ingestions": [{**ing, "trigger": "manual", "requested_by": "owner@a.test", "error": None}],
                                      "revisions": [{"day": str(TODAY), "service": "Amazon S3", "record_type": "Usage", "old": 1, "new": 1.25, "at": NOW.isoformat()}]})
        if v == "audit":
            return self._json(route, {"audit": [{"at": NOW.isoformat(), "actor": "owner@a.test", "action": "enable_cost_ingestion"}]})
        return self._json(route, {"error": "unknown"}, 400)


def _open(page, site, fake):
    page.route("**/default/cloud-cost**", fake.handle)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{site}/cloud_cost.html?account_id={ACCOUNT}")
    return errors


def test_opt_in_requires_accepting_the_aws_charges(page, site):
    fake = Fake(enabled=False)
    errors = _open(page, site, fake)
    page.wait_for_selector("text=Turn on cost data for this account")
    assert "$0.01 per Cost Explorer request" in page.locator("main").inner_text()
    page.click("[data-act=enable]")
    page.wait_for_function("document.getElementById('toast').textContent.includes('Tick the box')")
    assert not fake.posts
    page.check("#accept")
    page.click("[data-act=enable]")
    page.wait_for_selector("text=Daily cost, last 90 days")
    assert fake.posts == [{"cloud_account_id": ACCOUNT, "action": "enable", "accept_charges": True}]
    assert not errors


def test_overview_shows_sources_estimates_and_security_next_to_cost(page, site):
    errors = _open(page, site, Fake())
    page.wait_for_selector("text=Daily cost, last 90 days")
    text = page.locator("main").inner_text()
    assert "AWS estimate (may still change)" in text and "critical 2" in text and "not enabled at AWS" in text
    assert "Tax" in text and "kept apart from usage" in text
    assert page.locator("svg.chart rect").count() > 30
    assert page.evaluate("window.__xss") is None and not errors


def test_unknown_savings_stay_unknown_and_approval_is_two_person(page, site):
    fake = Fake()
    errors = _open(page, site, fake)
    page.wait_for_selector("text=Daily cost, last 90 days")
    page.click("[data-tab=optimize]")
    page.wait_for_selector("tr[data-opp]")
    rows = page.locator("tr[data-opp]").all_inner_texts()
    assert any("unknown" in r and "vol-2" in r for r in rows)
    page.locator("tr[data-opp]").first.click()
    page.wait_for_selector("[data-act=req]")
    page.click("[data-act=req]")
    page.wait_for_selector("[data-act=approve]")
    page.click("[data-act=approve]")
    page.wait_for_function("document.getElementById('toast').textContent.includes('cannot approve')")
    assert [p["action"] for p in fake.posts] == ["request_approval", "decide_opportunity"]
    assert not errors


def test_every_tab_renders_on_a_phone_without_errors(page, site):
    page.set_viewport_size({"width": 390, "height": 800})
    errors = _open(page, site, Fake())
    page.wait_for_selector("text=Daily cost, last 90 days")
    for t in ("explorer", "optimize", "monitors", "commitments", "ai", "k8s", "accounts", "settings", "overview"):
        page.click(f"[data-tab={t}]")
        page.wait_for_function("!document.getElementById('view').textContent.includes('Loading…')")
        assert not page.locator("#view .err").count(), t
        assert page.evaluate("document.documentElement.scrollWidth") <= 392, t
    assert page.evaluate("window.__xss") is None and not errors


def test_backend_failure_is_shown_plainly(page, site):
    page.route("**/default/cloud-cost**", lambda r: r.fulfill(status=500, headers=CORS, content_type="application/json",
                                                               body='{"error": "Something went wrong while loading cloud cost. Please try again."}'))
    page.goto(f"{site}/cloud_cost.html?account_id={ACCOUNT}")
    page.wait_for_selector("#view .err")
    assert "Please try again" in page.locator("#view .err").inner_text()
