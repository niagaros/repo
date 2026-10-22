"""Security Agents page (issue #239) in a real browser. The fake backend serves work items built by the real
security_agents_engine (Red analysis + Blue detections) in the API's response shapes. One work item title is an
XSS payload."""
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from collectors.aws.scanner import security_agents_engine as E
from ui_support import ACCOUNT, CORS

pytestmark = [pytest.mark.flow("E2E-SECAGENTS-001"), pytest.mark.severity("P1")]

NOW = datetime.now(timezone.utc)
XSS = '<img src=x onerror="window.__xss=1">'


def _data():
    ciem = [{"id": "c1", "status": "open", "rule": "escalation_paths", "category": "privilege_escalation", "severity": "high",
             "title": XSS, "identity_arn": "arn:aws:iam::1:user/dev",
             "details": {"path": {"how": "Create a Lambda with an admin role", "required_permissions": ["iam:PassRole"], "gains": ["full administrator access"]}},
             "recommendation": {"current": "PassRole on *", "proposed": "Scope PassRole", "rollback": "Restore"}}]
    red = E.red_identity([], ciem)
    ev = {"EventId": "e1", "EventName": "StopLogging", "EventTime": NOW.isoformat(), "Resources": [],
          "CloudTrailEvent": json.dumps({"userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/dev"}, "sourceIPAddress": "203.0.113.9"})}
    det = E.detect([ev], "eu-west-1")
    items = []
    for n, it in enumerate(red):
        items.append({**it, "id": f"00000000-0000-0000-0000-{n:012d}", "agent_name": E.AGENTS[it["agent_id"]]["name"], "state": "new",
                      "owner": None, "due_at": None, "plan": E.remediation_plan(it), "change_reference": None, "remediated_at": None,
                      "verification": None, "ticket": None, "active_threat": True, "first_seen": NOW.isoformat(), "last_seen": NOW.isoformat(),
                      "state_reason": None})
    return items, det


class Fake:
    def __init__(self, active=True):
        self.items, self.det = _data()
        self.active = active
        self.posts = []

    def _json(self, route, payload, status=200):
        route.fulfill(status=status, content_type="application/json", headers=CORS, body=json.dumps(payload, default=str))

    def agents(self):
        return [{"agent_id": k, **v, "category_label": E.CATEGORY_LABEL[v["category"]], "status": "active" if self.active else "registered",
                 "last_run_at": NOW.isoformat() if self.active else None, "last_run_status": "succeeded" if self.active else None,
                 "authorized_until": (NOW + timedelta(days=90)).isoformat() if self.active else None, "evaluation_current": self.active,
                 "evaluation": {"passed": True, "agent_version": E.ENGINE_VERSION} if self.active else None, "owner": "sec@a.test" if self.active else None}
                for k, v in E.AGENTS.items()]

    def handle(self, route):
        req = route.request
        if req.method == "OPTIONS":
            return route.fulfill(status=200, headers=CORS, body="")
        if req.method == "POST":
            body = json.loads(req.post_data or "{}")
            assert body["cloud_account_id"] == ACCOUNT
            self.posts.append(body)
            if body["action"] == "activate_recommended":
                self.active = True
                return self._json(route, {"activated": list(E.AGENTS), "environment": "production", "authorization_days": 90})
            if body["action"] == "run_agents":
                return self._json(route, {"started": True, "note": "The agents run in the background; refresh in a minute."})
            if body["action"] == "decide_approval":
                return self._json(route, {"decision": body["decision"], "result": {"executed": False, "note": "Your team carries it out."}})
            return self._json(route, {"ok": True, "state": body.get("to")})
        qs = {k: v[0] for k, v in parse_qs(urlparse(req.url).query).items()}
        assert qs["cloud_account_id"] == ACCOUNT
        v = qs.get("view")
        if v == "overview":
            return self._json(route, {"agents": self.agents(), "agents_by_status": {}, "latest_runs": {}, "pending_approvals": 1,
                                      "queue": {"by_state": {"new": 1}, "open_by_severity": {"high": 1}, "open_by_category": {"red": 1, "blue": 1}},
                                      "incidents": {"open": {"high": 1}}, "actions_30d": {"allowed": 40, "approval_required": 1, "blocked": 2},
                                      "metrics": {"open": 2, "recommended": 1, "remediation_recorded": 0, "verified_resolved": 0, "verified_after_recorded_fix": 0,
                                                  "pct_remediations_verified": None, "pct_open_with_owner": 0, "false_positive_rate_pct": 0, "recurred": 0,
                                                  "mean_days_to_verified_resolution": None, "note": "Only verified counts as fixed."},
                                      "settings": {"environment": "production", "lookback_hours": 24},
                                      "boundaries": {"red": "Analysis only.", "blue": "CloudTrail only.", "green": "Plans and verification.", "model": "No LLM."},
                                      "levels": E.LEVELS})
        if v == "agents":
            return self._json(route, {"agents": self.agents(), "levels": E.LEVELS, "lifecycle": E.AGENT_LIFECYCLE})
        if v == "agent":
            a = next(x for x in self.agents() if x["agent_id"] == qs["agent_id"])
            ev = E.evaluate(a["agent_id"])
            pols = [{"agent_id": a["agent_id"], "action": ac, "action_label": E.ACTIONS[ac]["label"], "environment": "production",
                     "needs": E.ACTIONS[ac]["level"], "executable": E.ACTIONS[ac]["executable"], **E.default_policy(a["agent_id"], ac, "production"),
                     "custom": False} for ac in a["actions"]]
            return self._json(route, {**a, "model": "none — deterministic rules", "framework": "Niagaros security-agents",
                                      "engine_version": E.ENGINE_VERSION, "business_purpose": a["specialization"], "approved_by": "sec@a.test",
                                      "approved_at": NOW.isoformat(),
                                      "authorizations": [{"id": "30000000-0000-0000-0000-000000000001", "environments": ["production"], "valid_from": NOW.isoformat(),
                                                          "valid_until": (NOW + timedelta(days=90)).isoformat(), "reason": "Recommended setup",
                                                          "approved_by": "sec@a.test", "revoked_at": None}],
                                      "evaluations": [{"agent_version": E.ENGINE_VERSION, "passed": ev["passed"], "result": ev, "run_by": "sec@a.test", "at": NOW.isoformat()}],
                                      "runs": [], "policies": pols})
        if v == "queue":
            return self._json(route, {"items": self.items, "states": E.STATES})
        if v == "item":
            it = next(x for x in self.items if x["id"] == qs["work_item_id"])
            return self._json(route, {**it, "history": [{"from": None, "to": "new", "actor": it["agent_id"], "actor_kind": "agent", "note": "Published", "at": NOW.isoformat()}],
                                      "evidence_log": [], "approvals": [], "incidents": [], "integrations": [],
                                      "allowed_transitions": sorted(E.HUMAN_TRANSITIONS["new"])})
        if v == "attack_paths":
            return self._json(route, {"paths": self.items, "note": "Potential paths. None has been tested or exploited."})
        if v == "incidents":
            return self._json(route, {"incidents": []})
        if v == "detections":
            return self._json(route, {"detections": [{**d, "id": "10000000-0000-0000-0000-000000000001", "status": "open"} for d in self.det],
                                      "rules": [{k: d[k] for k in ("id", "agent", "severity", "title", "mitre", "events", "why")} for d in E.DETECTIONS],
                                      "recent_coverage": [{"coverage": {}, "limitations": ["CloudTrail management events in eu-west-1 only."], "at": NOW.isoformat()}]})
        if v == "approvals":
            return self._json(route, {"approvals": [{"id": "20000000-0000-0000-0000-000000000001", "agent_id": "blue-identity-defense", "action": "containment",
                                                     "action_label": "Contain a threat", "executable": False, "payload": {"plan": "Deactivate key", "rollback": "Reactivate"},
                                                     "requested_by": "a@a.test", "decision": "pending", "created_at": NOW.isoformat(),
                                                     "expires_at": (NOW + timedelta(days=7)).isoformat(), "work_item_id": None, "incident_id": None, "target": "x"}]})
        if v == "policies":
            pols = [{"agent_id": a, "action": ac, "action_label": E.ACTIONS[ac]["label"], "environment": "production", "needs": E.ACTIONS[ac]["level"],
                     "executable": E.ACTIONS[ac]["executable"], **E.default_policy(a, ac, "production"), "custom": False}
                    for a, m in E.AGENTS.items() for ac in m["actions"]]
            return self._json(route, {"policies": pols, "levels": E.LEVELS, "prohibited_techniques": E.PROHIBITED_TECHNIQUES, "environment": "production"})
        if v in ("audit", "runs", "settings"):
            return self._json(route, {"audit": [], "policy_decisions": [], "runs": [], "environment": "production", "lookback_hours": 24})
        return self._json(route, {"error": "unknown view"}, 400)


def _open(page, site, active=True):
    backend = Fake(active)
    page.route("**/default/security-agents**", backend.handle)
    page.route("**/default/notifications**", lambda r: r.fulfill(status=200, headers=CORS, content_type="application/json", body='{"notifications": []}'))
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{site}/security_agents.html?account_id={ACCOUNT}")
    page.wait_for_selector("text=Workforce", timeout=15000)
    return backend, errors


def test_setup_is_offered_until_agents_are_active(page, site):
    backend, errors = _open(page, site, active=False)
    assert page.locator("text=No agent is active yet").is_visible()
    assert page.locator("[data-act='run']").is_disabled()
    page.click("[data-act='activate']")
    page.wait_for_selector("text=agents activated")
    assert backend.posts[-1]["action"] == "activate_recommended"
    assert not errors


def test_lanes_metrics_and_boundaries(page, site):
    backend, errors = _open(page, site)
    for t in ("Red — Offensive", "Blue — Defensive", "Green — Resolution", "Not done by these agents"):
        assert page.locator(f"text={t}").first.is_visible()
    assert page.locator("text=verified resolved by a later scan").is_visible()
    assert not errors


def test_work_item_shows_path_validation_note_and_no_manual_resolve(page, site):
    backend, errors = _open(page, site)
    page.click(".tab[data-tab='queue']")
    page.click("tr[data-item]")
    page.wait_for_selector("#drawer >> text=Potential attack path")
    assert page.locator("#drawer >> text=not a confirmed exploit").is_visible()
    options = page.eval_on_selector_all("#it-to option", "els => els.map(e => e.value)")
    assert "resolved" not in options and "reopened" not in options
    assert page.evaluate("window.__xss") is None
    assert not errors


def test_approval_needs_a_reason_and_is_sent(page, site):
    backend, errors = _open(page, site)
    page.click(".tab[data-tab='approvals']")
    page.wait_for_selector("text=executed by your team")
    page.fill("[data-areason]", "confirmed with the key owner")
    page.click("[data-act='approve-req'][data-decision='approved']")
    page.wait_for_timeout(300)
    assert backend.posts[-1] == {"cloud_account_id": ACCOUNT, "action": "decide_approval", "approval_id": "20000000-0000-0000-0000-000000000001",
                                 "decision": "approved", "reason": "confirmed with the key owner"}
    assert not errors


def test_policy_save_uses_policy_action(page, site):
    backend, errors = _open(page, site)
    page.click(".tab[data-tab='policies']")
    page.wait_for_selector("text=Techniques that are never run")
    page.locator("[data-act='policy']").first.click()
    page.wait_for_timeout(300)
    p = backend.posts[-1]
    assert p["action"] == "set_policy" and p["policy_action"] in E.ACTIONS and p["environment"] == "production"
    assert not errors


def test_threats_show_coverage_and_detection_evidence(page, site):
    backend, errors = _open(page, site)
    page.click(".tab[data-tab='threats']")
    page.wait_for_selector("text=Coverage:")
    page.click("tr[data-detection]")
    page.wait_for_selector("#drawer >> text=Observed in CloudTrail")
    assert page.locator("#drawer >> text=e1").count() >= 1
    assert not errors


def test_phone_width_has_no_horizontal_scroll(page, site):
    _open(page, site)
    page.set_viewport_size({"width": 390, "height": 800})
    page.wait_for_timeout(200)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
