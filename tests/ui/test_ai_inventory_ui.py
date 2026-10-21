"""AI Inventory page (issue #236) in a real browser. The fake backend serves output of the real
ai_inventory_engine in the API's response shapes. One MCP server is named with an XSS payload."""
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from collectors.aws.scanner import ai_inventory_engine as E
from ui_support import ACCOUNT, CORS

pytestmark = [pytest.mark.flow("E2E-AIINV-001"), pytest.mark.severity("P1")]

NOW = datetime.now(timezone.utc).isoformat()
XSS = '<img src=x onerror="window.__xss=1">'


def _inventory():
    code = 'URL = "https://api.groq.com/openai/v1/chat/completions"\nMODEL = "openai/gpt-oss-120b"\n'
    mcp = json.dumps({"mcpServers": {XSS: {"url": "http://mcp.example.net/sse"}}})
    repo = {"full_name": "acme/app", "url": "https://github.com/acme/app", "commit": "c0ffee",
            "files": [{"path": "svc/agent.py", "text": code}, {"path": "mcp.json", "text": mcp}]}
    assets, rels, findings, summary = E.build("111122223333", None, [repo], {})
    ids = {}
    out = []
    for n, a in enumerate(assets):
        ids[a["asset_key"]] = f"00000000-0000-0000-0000-{n:012d}"
        out.append({"id": ids[a["asset_key"]], **{k: a[k] for k in ("asset_key", "asset_type", "name", "provider", "verification", "metadata")},
                    "type_label": E.ASSET_TYPES[a["asset_type"]], "origin": "discovered", "owner": None, "business_purpose": None,
                    "environment": "unknown", "criticality": "unknown", "approval_status": "unreviewed", "approval_reason": None,
                    "approval_by": None, "approval_at": None, "approval_until": None, "lifecycle_status": "active", "next_review_at": None,
                    "first_seen": NOW, "last_seen": NOW, "last_synced": NOW, "last_verified": None, "open_findings": 0, "relationships": 1})
    edges = [{"id": f"10000000-0000-0000-0000-{n:012d}", "source": ids[r["source_key"]], "target": ids[r["target_key"]], "type": r["type"],
              "verification": r["verification"], "confidence": r["confidence"], "origin": "discovered"} for n, r in enumerate(rels)]
    fs = [{"id": f"20000000-0000-0000-0000-{n:012d}", **{k: f[k] for k in ("rule", "severity", "title", "details", "recommendation", "compliance")},
           "status": "open", "status_reason": None, "status_by": None, "status_at": None, "accepted_until": None, "ticket": None,
           "first_seen": NOW, "last_seen": NOW, "resolved_at": None,
           "asset": {"id": ids[f["asset_key"]], "name": next(a["name"] for a in assets if a["asset_key"] == f["asset_key"]), "asset_type": "x", "type_label": "x"}}
          for n, f in enumerate(findings)]
    return out, edges, fs, summary


class FakeInventory:
    def __init__(self):
        self.assets, self.edges, self.findings, self.summary = _inventory()
        self.posts = []

    def _json(self, route, payload, status=200):
        route.fulfill(status=status, content_type="application/json", headers=CORS, body=json.dumps(payload, default=str))

    def handle(self, route):
        req = route.request
        if req.method == "OPTIONS":
            return route.fulfill(status=200, headers=CORS, body="")
        if req.method == "POST":
            body = json.loads(req.post_data or "{}")
            assert body.get("cloud_account_id") == ACCOUNT
            self.posts.append(body)
            if body["action"] == "update_asset":
                return self._json(route, {"asset_id": body["asset_id"], "changed": [k for k in body if k not in ("action", "asset_id", "cloud_account_id")]})
            if body["action"] == "run_scan":
                return self._json(route, {"started": True, "note": "The scan runs in the background; refresh in a minute or two."})
            return self._json(route, {"ok": True})
        qs = {k: v[0] for k, v in parse_qs(urlparse(req.url).query).items()}
        assert qs.get("cloud_account_id") == ACCOUNT
        v = qs.get("view")
        scan = {"id": "s1", "status": "partial", "trigger": "schedule", "started_at": NOW, "finished_at": NOW, "error": None,
                "coverage": {}, "summary": {**self.summary, "sources_read": {"aws_parts": [], "repositories": ["acme/app"], "github_connected": True}},
                "limitations": ["Bedrock agents could not be read in eu-west-1 (AccessDenied)."]}
        by_type = {}
        for a in self.assets:
            by_type[a["asset_type"]] = by_type.get(a["asset_type"], 0) + 1
        if v == "overview":
            return self._json(route, {"latest_scan": scan, "last_attempt": scan, "assets_total": len(self.assets), "identities": 0,
                                      "by_type": {E.ASSET_TYPES[k]: n for k, n in by_type.items()}, "by_type_ids": by_type,
                                      "by_verification": {"declared": len(self.assets)}, "by_lifecycle": {"active": len(self.assets)},
                                      "by_approval": {"unreviewed": len(self.assets)},
                                      "governance": {"denominator": len(self.assets), "with_owner": 0, "with_purpose": 0, "with_environment": 0,
                                                     "with_criticality": 0, "reviewed": 0, "approved": 0, "review_overdue": 0, "exceptions_expired": 0,
                                                     "note": "AI identities are excluded."},
                                      "findings": {"open": {"high": 1, "medium": 1}}, "shadow_ai": len(self.assets),
                                      "changes_30d": {"high_impact": 0, "total": 3}, "trend": [], "verification_levels": {"declared": "in code"}})
        if v == "assets":
            rows = [a for a in self.assets if not qs.get("type") or a["asset_type"] == qs["type"]]
            return self._json(route, {"assets": rows, "truncated": False, "types": E.ASSET_TYPES})
        if v == "asset":
            a = next(x for x in self.assets if x["id"] == qs["asset_id"])
            rel = [{"id": e["id"], "type": e["type"], "verification": e["verification"], "confidence": e["confidence"], "sources": ["github:acme/app@c0ffee"],
                    "note": None, "origin": "discovered", "first_seen": NOW, "last_seen": NOW, "direction": "out" if e["source"] == a["id"] else "in",
                    "other": next({"id": o["id"], "name": o["name"], "asset_type": o["asset_type"], "type_label": o["type_label"]}
                                  for o in self.assets if o["id"] == (e["target"] if e["source"] == a["id"] else e["source"]))}
                   for e in self.edges if a["id"] in (e["source"], e["target"])]
            return self._json(route, {**a, "observations": [{"source": "github:acme/app@c0ffee", "ref": "svc/agent.py", "verification": "declared", "at": NOW}],
                                      "relationships": rel, "changes": [{"type": "discovered", "previous": None, "new": {"type": a["asset_type"]},
                                                                         "source": "github", "actor": None, "risk_impact": None, "at": NOW}],
                                      "findings": [], "impact": {"downstream": [], "upstream": [], "depth": 3, "note": "Downstream: what this asset uses."}})
        if v == "graph":
            return self._json(route, {"nodes": [{k: a[k] for k in ("id", "name", "asset_type", "type_label", "verification", "lifecycle_status", "approval_status")}
                                                for a in self.assets], "edges": self.edges})
        if v == "shadow":
            return self._json(route, {"items": self.assets, "approved_providers": [], "definition": "AI in use that nobody has reviewed yet."})
        if v == "findings":
            return self._json(route, {"findings": self.findings, "integrations": []})
        if v == "changes":
            return self._json(route, {"changes": []})
        if v == "settings":
            return self._json(route, {"approved_providers": [], "github_repos": [], "inactive_after_days": 30, "github_org": "acme",
                                      "providers": [{"id": k, "name": p["name"]} for k, p in E.PROVIDERS.items()]})
        if v in ("audit", "scans"):
            return self._json(route, {"audit": [], "scans": []})
        return self._json(route, {"error": "unknown view"}, 400)


@pytest.fixture
def inv(page, site):
    backend = FakeInventory()
    page.route("**/default/ai-inventory**", backend.handle)
    page.route("**/default/notifications**", lambda r: r.fulfill(status=200, headers=CORS, content_type="application/json", body='{"notifications": []}'))
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{site}/ai_inventory.html?account_id={ACCOUNT}")
    page.wait_for_selector("text=Last inventory run", timeout=15000)
    return page, backend, errors


def test_overview_shows_coverage_limitations_and_denominators(inv):
    page, _, errors = inv
    assert page.locator("text=Bedrock agents could not be read").is_visible()
    assert page.locator("text=Governance coverage").is_visible()
    assert page.locator("text=Not covered yet").is_visible()
    assert not errors


def test_names_are_escaped_everywhere(inv):
    page, _, errors = inv
    for t in ("assets", "shadow", "graph", "findings"):
        page.click(f".tab[data-tab='{t}']")
        page.wait_for_timeout(300)
    assert page.evaluate("window.__xss") is None
    page.click(".tab[data-tab='assets']")
    page.wait_for_selector("tr[data-asset]")
    assert page.locator("td", has_text="<img src=x").count() >= 1      # shown as text
    assert not errors


def test_asset_drawer_shows_provenance_and_saves_governance(inv):
    page, backend, errors = inv
    page.click(".tab[data-tab='assets']")
    page.click("tr[data-asset]:has-text('Groq')")
    page.wait_for_selector("#g-owner")
    assert page.locator("#drawer >> text=Where it was seen").is_visible()
    assert page.locator("#drawer >> text=served by").count() + page.locator("#drawer >> text=calls provider").count() >= 1
    page.fill("#g-owner", "ai-team@acme.test")
    page.select_option("#g-appr", "approved")
    page.click("[data-act='save-asset']")
    page.wait_for_selector("text=Saved.")
    p = backend.posts[-1]
    assert p["action"] == "update_asset" and p["owner"] == "ai-team@acme.test" and p["approval_status"] == "approved"
    assert "environment" not in p                                       # unchanged fields are not sent
    assert not errors


def test_graph_renders_every_asset_and_opens_detail(inv):
    page, backend, errors = inv
    page.click(".tab[data-tab='graph']")
    page.wait_for_selector("svg g.node")
    assert page.locator("svg g.node").count() == len(backend.assets)
    assert page.locator("svg path[marker-end]").count() == len(backend.edges)
    page.locator("svg g.node").first.click()
    page.wait_for_selector("#g-owner")
    assert not errors


def test_finding_detail_has_evidence_recommendation_and_compliance(inv):
    page, _, errors = inv
    page.click(".tab[data-tab='findings']")
    page.click("tr[data-finding]:has-text('plain HTTP')")
    page.wait_for_selector("#drawer >> text=Recommendation")
    assert page.locator("#drawer >> text=ISO 27001:2022").count() >= 1
    assert page.locator("#drawer >> text=not proof of non-compliance").is_visible()
    assert not errors


def test_settings_and_manual_scan(inv):
    page, backend, errors = inv
    page.click("[data-act='scan']")
    page.wait_for_selector("text=runs in the background")
    page.click(".tab[data-tab='settings']")
    page.check("[data-provider='groq']")
    page.fill("#s-repos", "app\nacme/other")
    page.click("[data-act='settings-save']")
    page.wait_for_timeout(300)
    p = backend.posts[-1]
    assert p == {"cloud_account_id": ACCOUNT, "action": "save_settings", "approved_providers": ["groq"],
                 "github_repos": ["app", "acme/other"], "inactive_after_days": 30}
    assert not errors


def test_csv_import_is_parsed_with_quotes(inv, tmp_path):
    page, backend, errors = inv
    page.click(".tab[data-tab='register']")
    f = tmp_path / "ai.csv"
    f.write_text('name,asset_type,description\n"Chat, internal",application,"says ""hi"""\n', encoding="utf-8")
    page.set_input_files("#imp-file", str(f))
    page.click("[data-act='import']")
    page.wait_for_timeout(300)
    assert backend.posts[-1]["rows"] == [{"name": "Chat, internal", "asset_type": "application", "description": 'says "hi"'}]
    assert not errors


def test_phone_width_has_no_horizontal_scroll(inv):
    page, _, _ = inv
    page.set_viewport_size({"width": 390, "height": 800})
    page.wait_for_timeout(200)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
