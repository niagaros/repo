"""
AI Inventory storage (asset lifecycle, provenance, change history, finding lifecycle across runs) and API (tenant
isolation, governance, registration, links, exports) against a real PostgreSQL with the real migrations.
Needs NIAGAROS_PGTEST_DSN (see test_governance_handler.py).
"""
import json
import os
import sys
import uuid
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND / "src"))

psycopg2 = pytest.importorskip("psycopg2")
DSN = os.environ.get("NIAGAROS_PGTEST_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="blocked: set NIAGAROS_PGTEST_DSN to a throwaway PostgreSQL")

SCHEMA = ["tests/fixtures/ciem_schema.sql", "tests/fixtures/ai_inventory_schema.sql", "migrations/024_security_audit_log.sql",
          "migrations/026_enterprise.sql", "migrations/032_ciem.sql", "migrations/033_ai_inventory.sql",
          "migrations/033_ai_inventory.sql"]  # 033 twice: must be re-runnable
ACCT = "111122223333"
ROLE = f"arn:aws:iam::{ACCT}:role/agent-role"
FN_ARN = f"arn:aws:lambda:eu-west-1:{ACCT}:function:agent"
KEY = "gsk_" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4"
AGENT_PY = 'URL = "https://api.groq.com/openai/v1/chat/completions"\nMODEL = "openai/gpt-oss-120b"\n'
ALL_PARTS = ("bedrock_guardrails", "bedrock_models", "bedrock_invocation_logging", "bedrock_knowledge_bases", "bedrock_agents",
             "bedrock_usage_metrics", "sagemaker", "opensearch_vector_collections", "lambda_functions")


@pytest.fixture(scope="module")
def conn():
    name = f"aiinv_test_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    c = psycopg2.connect(DSN.rsplit("/", 1)[0] + "/" + name)
    c.autocommit = True
    for f in SCHEMA:
        c.cursor().execute((BACKEND / f).read_text(encoding="utf-8"))
    c.autocommit = False
    yield c
    c.close()
    admin.cursor().execute(f"DROP DATABASE {name} WITH (FORCE)")
    admin.close()


@pytest.fixture(scope="module")
def accounts(conn):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id) VALUES ('owner@a.test', %s) RETURNING id", (ACCT,))
        a = str(cur.fetchone()[0])
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id) VALUES ('other@b.test', '444455556666') RETURNING id")
        b = str(cur.fetchone()[0])
    conn.commit()
    return {"a": a, "b": b}


def _aws(functions=True, parts_ok=ALL_PARTS):
    fn = {"arn": FN_ARN, "name": "agent", "handler": "svc.agent.handler", "runtime": "python3.12", "role_arn": ROLE,
          "ai_env_names": ["GROQ_API_KEY"], "ai_env_plaintext_secrets": ["GROQ_API_KEY"]}
    return {"region": "eu-west-1", "coverage": {p: {"ok": p in parts_ok} for p in ALL_PARTS}, "limitations": [],
            "functions": [fn] if functions else [], "bedrock_usage": {}, "invocation_logging": None}


def _repo(with_key=True, extra=""):
    text = AGENT_PY + (f'KEY = "{KEY}"\n' if with_key else "") + extra
    return {"full_name": "acme/app", "url": "https://github.com/acme/app", "default_branch": "main", "commit": "c0ffee",
            "files": [{"path": "svc/agent.py", "text": text}]}


def _run(conn, account, aws, repos, read_repos=("acme/app",), complete=True, ciem=None, inactive=30):
    from collectors.aws.scanner import ai_inventory_engine as E, ai_inventory_scanner_handler as h
    with conn.cursor() as cur:
        cur.execute("INSERT INTO ai_inventory_scans (cloud_account_id) VALUES (%s) RETURNING id", (account,))
        sid = cur.fetchone()[0]
    conn.commit()
    assets, rels, findings, _ = E.build(ACCT, aws, repos, ciem or {}, {})
    parts = {k for k, v in aws["coverage"].items() if v["ok"]}
    read = {"aws_parts": parts, "aws_parts_by_region": {"eu-west-1": parts}, "repos": set(read_repos),
            "github_complete": complete, "ciem": bool(ciem)}
    out = h.store(conn, account, sid, assets, rels, findings, read, inactive)
    with conn.cursor() as cur:
        cur.execute("UPDATE ai_inventory_scans SET status = 'succeeded', finished_at = NOW() WHERE id = %s", (sid,))
    conn.commit()
    return out


def _asset(conn, account, key):
    with conn.cursor() as cur:
        cur.execute("""SELECT id, lifecycle_status, verification, owner, approval_status, next_review_at FROM ai_assets
                       WHERE cloud_account_id = %s AND asset_key = %s""", (account, key))
        r = cur.fetchone()
    conn.rollback()
    return dict(zip(("id", "lifecycle", "verification", "owner", "approval", "next_review_at"), r)) if r else None


def _finding(conn, account, rule):
    with conn.cursor() as cur:
        cur.execute("SELECT id, status, status_reason FROM ai_inventory_findings WHERE cloud_account_id = %s AND rule = %s", (account, rule))
        r = cur.fetchone()
    conn.rollback()
    return r


# ── storage and lifecycle ───────────────────────────────────────────────────

def test_first_run_stores_assets_provenance_relationships_and_findings(conn, accounts):
    a = accounts["a"]
    new_assets, new_high, _ = _run(conn, a, _aws(), [_repo()])
    keys = {x["asset_key"] for x in new_assets}
    assert {"github:acme/app", "provider:groq", "model:openai/gpt-oss-120b", f"aws:{FN_ARN}", f"aws:{ROLE}"} <= keys
    assert {"secret_in_code", "ai_key_in_lambda_env"} <= {f["rule"] for f in new_high}
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM ai_asset_relationships WHERE cloud_account_id = %s AND rel_type = 'DEPLOYED_ON'", (a,))
        assert cur.fetchone()[0] == 1
        cur.execute("""SELECT count(*) FROM ai_asset_observations o JOIN ai_assets s ON s.id = o.asset_id
                       WHERE s.cloud_account_id = %s AND o.source LIKE 'github:acme/app@%%'""", (a,))
        assert cur.fetchone()[0] >= 3
        cur.execute("SELECT count(*) FROM ai_asset_changes WHERE cloud_account_id = %s AND change_type = 'discovered'", (a,))
        assert cur.fetchone()[0] == len(new_assets)
        cur.execute("SELECT string_agg(details::text || metadata::text, '') FROM ai_inventory_findings f JOIN ai_assets s ON s.id = f.asset_id WHERE f.cloud_account_id = %s", (a,))
        assert KEY not in cur.fetchone()[0]                      # the key value is never stored
    conn.rollback()


def test_second_identical_run_is_quiet(conn, accounts):
    new_assets, new_high, resolved = _run(conn, accounts["a"], _aws(), [_repo()])
    assert new_assets == [] and new_high == [] and resolved == 0


def test_partially_read_repository_never_marks_assets_stale_or_resolves(conn, accounts):
    a = accounts["a"]
    _run(conn, a, _aws(), [_repo(with_key=False)], read_repos=(), complete=False)   # repo truncated
    assert _finding(conn, a, "secret_in_code")[1] == "open"
    assert _asset(conn, a, "github:acme/app")["lifecycle"] == "active"


def test_fully_read_repository_resolves_a_removed_secret_with_reason(conn, accounts):
    a = accounts["a"]
    _, _, resolved = _run(conn, a, _aws(), [_repo(with_key=False)])
    f = _finding(conn, a, "secret_in_code")
    assert resolved >= 1 and f[1] == "resolved" and "re-collection" in f[2]


def test_resolved_finding_reopens_without_a_new_alert(conn, accounts):
    a = accounts["a"]
    _, new_high, _ = _run(conn, a, _aws(), [_repo()])
    f = _finding(conn, a, "secret_in_code")
    assert f[1] == "open" and "Re-opened" in f[2]
    assert not any(x["rule"] == "secret_in_code" for x in new_high)


def test_aws_asset_only_goes_stale_when_its_service_was_read(conn, accounts):
    a = accounts["a"]
    no_lambda = tuple(p for p in ALL_PARTS if p != "lambda_functions")
    _run(conn, a, _aws(functions=False, parts_ok=no_lambda), [_repo()])
    assert _asset(conn, a, f"aws:{FN_ARN}")["lifecycle"] == "active"
    assert _finding(conn, a, "ai_key_in_lambda_env")[1] == "open"
    _run(conn, a, _aws(functions=False), [_repo()])
    assert _asset(conn, a, f"aws:{FN_ARN}")["lifecycle"] == "stale"
    assert _finding(conn, a, "ai_key_in_lambda_env")[1] == "resolved"


def test_stale_becomes_inactive_after_the_configured_days_and_active_when_seen_again(conn, accounts):
    a = accounts["a"]
    with conn.cursor() as cur:
        cur.execute("UPDATE ai_assets SET last_seen = NOW() - INTERVAL '40 days' WHERE cloud_account_id = %s AND asset_key = %s", (a, f"aws:{FN_ARN}"))
    conn.commit()
    _run(conn, a, _aws(functions=False), [_repo()], inactive=30)
    assert _asset(conn, a, f"aws:{FN_ARN}")["lifecycle"] == "inactive"
    _run(conn, a, _aws(), [_repo()])
    assert _asset(conn, a, f"aws:{FN_ARN}")["lifecycle"] == "active"
    with conn.cursor() as cur:
        cur.execute("""SELECT new->>'lifecycle_status' FROM ai_asset_changes c JOIN ai_assets s ON s.id = c.asset_id
                       WHERE s.asset_key = %s AND c.change_type = 'lifecycle' ORDER BY detected_at""", (f"aws:{FN_ARN}",))
        assert [r[0] for r in cur.fetchall()] == ["stale", "inactive"]
    conn.rollback()


def test_model_seen_in_code_is_kept_while_github_is_unread(conn, accounts):
    a = accounts["a"]
    _run(conn, a, _aws(), [], read_repos=(), complete=False)     # GitHub failed this time
    assert _asset(conn, a, "model:openai/gpt-oss-120b")["lifecycle"] == "active"
    _run(conn, a, _aws(), [_repo()])


def test_scan_never_overwrites_governance_and_high_impact_change_needs_review(conn, accounts):
    a = accounts["a"]
    with conn.cursor() as cur:
        cur.execute("""UPDATE ai_assets SET owner = 'team-ai', approval_status = 'approved', verification = 'verified'
                       WHERE cloud_account_id = %s AND asset_key = %s""", (a, f"aws:{FN_ARN}"))
    conn.commit()
    _run(conn, a, _aws(), [_repo()])
    x = _asset(conn, a, f"aws:{FN_ARN}")
    assert x["owner"] == "team-ai" and x["approval"] == "approved" and x["verification"] == "verified"
    aws = _aws()
    aws["functions"][0]["role_arn"] = f"arn:aws:iam::{ACCT}:role/other"       # medium impact: review stays
    _run(conn, a, aws, [_repo()])
    assert _asset(conn, a, f"aws:{FN_ARN}")["verification"] == "verified"
    with conn.cursor() as cur:
        cur.execute("""SELECT previous->>'role_arn', new->>'role_arn', risk_impact FROM ai_asset_changes c JOIN ai_assets s ON s.id = c.asset_id
                       WHERE s.asset_key = %s AND c.change_type = 'configuration_changed'""", (f"aws:{FN_ARN}",))
        assert cur.fetchone() == (ROLE, f"arn:aws:iam::{ACCT}:role/other", "medium")
        # a high-impact change (guardrail removed) withdraws the review
        cur.execute("""UPDATE ai_assets SET metadata = metadata || '{"guardrail": {"id": "g1"}}'::jsonb, metadata_hash = 'x'
                       WHERE asset_key = %s""", (f"aws:{FN_ARN}",))
    conn.commit()
    _run(conn, a, _aws(), [_repo()])
    x = _asset(conn, a, f"aws:{FN_ARN}")
    with conn.cursor() as cur:
        cur.execute("SELECT CURRENT_DATE")                              # the database's date, not this machine's
        db_today = cur.fetchone()[0]
    conn.rollback()
    assert x["verification"] == "discovered" and x["next_review_at"] == db_today and x["owner"] == "team-ai"


def test_relationship_that_disappears_is_removed_only_after_a_full_re_read(conn, accounts):
    a = accounts["a"]
    other_model = _repo()
    other_model["files"][0]["text"] = other_model["files"][0]["text"].replace("openai/gpt-oss-120b", "openai/gpt-oss-20b")

    def uses(model):
        with conn.cursor() as cur:
            cur.execute("""SELECT count(*) FROM ai_asset_relationships r JOIN ai_assets s ON s.id = r.source_asset_id JOIN ai_assets t ON t.id = r.target_asset_id
                           WHERE s.asset_key = 'github:acme/app' AND t.asset_key = %s AND r.rel_type = 'USES_MODEL' AND r.cloud_account_id = %s""", (model, a))
            n = cur.fetchone()[0]
        conn.rollback()
        return n
    _run(conn, a, _aws(), [other_model], read_repos=(), complete=False)
    assert uses("model:openai/gpt-oss-120b") == 1                       # repo not read in full: keep
    _run(conn, a, _aws(), [other_model])
    assert uses("model:openai/gpt-oss-120b") == 0 and uses("model:openai/gpt-oss-20b") == 1
    with conn.cursor() as cur:
        cur.execute("""SELECT previous->>'target' FROM ai_asset_changes c JOIN ai_assets s ON s.id = c.asset_id
                       WHERE s.asset_key = 'github:acme/app' AND c.change_type = 'relationship_removed'""")
        assert "openai/gpt-oss-120b" in [r[0] for r in cur.fetchall()]
    conn.rollback()
    _run(conn, a, _aws(), [_repo()])


def test_change_history_and_audit_log_are_append_only_for_the_lambda_role(conn):
    with conn.cursor() as cur:
        cur.execute("""SELECT table_name, string_agg(privilege_type, ',' ORDER BY privilege_type) FROM information_schema.role_table_grants
                       WHERE grantee = 'cspm_lambda' AND table_name IN ('ai_asset_changes', 'ai_inventory_audit_log') GROUP BY 1""")
        assert dict(cur.fetchall()) == {"ai_asset_changes": "INSERT,SELECT", "ai_inventory_audit_log": "INSERT,SELECT"}
    conn.rollback()


def test_full_scanner_run_with_mocked_sources(conn, accounts):
    from collectors.aws.scanner import ai_inventory_scanner_handler as h
    b = accounts["b"]
    with conn.cursor() as cur:
        cur.execute("INSERT INTO github_integrations (cloud_account_id, org_name, github_token_secret) VALUES (%s, 'acme', 'niagaros/github/x/token')", (b,))
    conn.commit()
    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {"Account": ACCT}
    gh = {"repos": [_repo()], "coverage": {"acme/app": {"ok": True, "truncated": False}}, "limitations": [], "complete": True}
    with patch.object(h, "collect_aws_regions", return_value=([_aws()], ["eu-west-1"], [])), patch.object(h, "collect_github", return_value=gh) as cg, \
         patch.object(h, "_github_token", return_value="tok"), patch.object(h, "_notify") as notify:
        out = h.run(conn, b, session)
    assert out["status"] == "succeeded" and out["summary"]["new_assets"] >= 5
    assert cg.call_args[0][:2] == ("acme", "tok")
    assert notify.call_args[0][3]                                       # new high-risk findings were passed on
    with patch.object(h, "collect_aws_regions", return_value=([_aws()], ["eu-west-1"], [])), patch.object(h, "collect_github", side_effect=RuntimeError("down")), \
         patch.object(h, "_github_token", return_value="tok"), patch.object(h, "_notify"):
        out = h.run(conn, b, session)
    assert out["status"] == "partial"
    assert _finding(conn, b, "secret_in_code")[1] == "open"            # GitHub down: nothing resolved
    with conn.cursor() as cur:
        cur.execute("SELECT limitations FROM ai_inventory_scans WHERE id = %s", (out["scan_id"],))
        assert any("could not be read" in l for l in cur.fetchone()[0])
    conn.rollback()


# ── API ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def api(conn):
    from collectors.aws.scanner import ai_inventory_handler as h

    def call(email, method, qs=None, body=None):
        event = {"httpMethod": method, "path": "/ai-inventory", "queryStringParameters": qs,
                 "body": json.dumps(body) if body is not None else None, "headers": {"Authorization": "Bearer t"}}
        with patch("collectors.aws.scanner.tenant_auth.authenticate", return_value=email), \
             patch.object(h, "authenticate", return_value=email):
            r = h.handle(event, conn)
        try:
            return r["statusCode"], json.loads(r["body"])
        except ValueError:
            return r["statusCode"], r["body"]
    return call


def _aid(conn, account, key):
    return str(_asset(conn, account, key)["id"])


def test_owner_reads_every_view(api, accounts, conn):
    a = accounts["a"]
    for view in ("overview", "assets", "graph", "shadow", "findings", "changes", "settings", "audit", "scans"):
        s, b = api("owner@a.test", "GET", {"cloud_account_id": a, "view": view})
        assert s == 200, (view, b)
    s, o = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "overview"})
    assert o["governance"]["denominator"] == o["assets_total"] and o["identities"] >= 1
    s, d = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "asset", "asset_id": _aid(conn, a, "provider:groq")})
    assert s == 200 and any(x["name"] == "acme/app" for x in d["impact"]["upstream"])
    assert d["observations"] and d["changes"]


def test_other_tenant_is_denied_by_account_and_by_referenced_id(api, accounts, conn):
    a = accounts["a"]
    s, _ = api("other@b.test", "GET", {"cloud_account_id": a, "view": "assets"})
    assert s == 403
    aid = _aid(conn, a, "provider:groq")
    s, _ = api("other@b.test", "GET", {"cloud_account_id": accounts["b"], "view": "asset", "asset_id": aid})
    assert s == 403                                                     # IDOR through asset_id
    s, _ = api("other@b.test", "POST", body={"cloud_account_id": accounts["b"], "action": "update_asset", "asset_id": aid, "owner": "x"})
    assert s == 403
    fid = str(_finding(conn, a, "secret_in_code")[0])
    s, _ = api("other@b.test", "POST", body={"cloud_account_id": accounts["b"], "action": "set_finding_status", "finding_id": fid,
                                             "status": "false_positive", "reason": "x"})
    assert s == 403
    s, _ = api(None, "GET", {"cloud_account_id": a, "view": "overview"})
    assert s == 401


def test_link_between_tenants_is_refused(api, accounts, conn):
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": accounts["a"], "action": "link_assets", "rel_type": "USES_MODEL",
                                             "source_asset_id": _aid(conn, accounts["a"], "github:acme/app"),
                                             "target_asset_id": _aid(conn, accounts["b"], "provider:groq")})
    assert s == 403


def test_governance_update_validation_and_verification(api, accounts, conn):
    a = accounts["a"]
    aid = _aid(conn, a, "provider:groq")
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "update_asset", "asset_id": aid, "approval_status": "exception"})
    assert s == 400 and "reason" in b["error"]
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "update_asset", "asset_id": aid, "approval_status": "exception",
                                             "approval_reason": "pilot", "approval_until": (date.today() + timedelta(days=400)).isoformat()})
    assert s == 400 and "366" in b["error"]
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "update_asset", "asset_id": aid, "lifecycle_status": "stale"})
    assert s == 400
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "update_asset", "asset_id": aid, "owner": "ai-team",
                                             "environment": "production", "approval_status": "approved"})
    assert s == 200 and set(b["changed"]) >= {"owner", "environment", "approval_status"}
    x = _asset(conn, a, "provider:groq")
    assert x["verification"] == "verified" and x["owner"] == "ai-team"
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "update_asset", "asset_id": aid, "approval_status": "unreviewed"})
    assert _asset(conn, a, "provider:groq")["verification"] == "declared"   # back to what the evidence shows
    s, ch = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "changes"})
    assert any(c["type"] == "approval_changed" and c["actor"] == "owner@a.test" for c in ch["changes"])


def test_register_import_delete(api, accounts, conn):
    a = accounts["a"]
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "register_asset", "name": "Copilot", "asset_type": "application",
                                             "provider": "GitHub", "owner": "it", "criticality": "medium"})
    assert s == 200
    rid = b["asset_id"]
    s, d = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "asset", "asset_id": rid})
    assert d["origin"] == "manual" and d["verification"] == "declared" and d["criticality"] == "medium"
    rows = [{"name": "Chat A", "asset_type": "application"}, {"name": "Bad", "asset_type": "spaceship"}]
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "import_assets", "rows": rows})
    assert s == 400 and "Row 2" in b["error"]
    s, _ = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "assets", "q": "Chat A"})
    assert _ == {"assets": [], "truncated": False, "types": _["types"]}      # atomic: nothing imported
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "import_assets", "rows": rows[:1]})
    assert s == 200 and b["imported"] == 1
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "delete_asset", "asset_id": _aid(conn, a, "provider:groq")})
    assert s == 409
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "delete_asset", "asset_id": rid})
    assert s == 200


def test_manual_links_only_manual_unlink(api, accounts, conn):
    a = accounts["a"]
    src, dst = _aid(conn, a, "github:acme/app"), _aid(conn, a, f"aws:{ROLE}")
    body = {"cloud_account_id": a, "action": "link_assets", "source_asset_id": src, "target_asset_id": dst, "rel_type": "AUTHENTICATES_AS"}
    s, b = api("owner@a.test", "POST", body=body)
    assert s == 200
    s, _ = api("owner@a.test", "POST", body=body)
    assert s == 409
    s, d = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "asset", "asset_id": src})
    discovered = next(r for r in d["relationships"] if r["origin"] == "discovered")
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "unlink_assets", "relationship_id": discovered["id"]})
    assert s == 409
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "unlink_assets", "relationship_id": b["relationship_id"]})
    assert s == 200


def test_finding_status_rules(api, accounts, conn):
    a = accounts["a"]
    fid = str(_finding(conn, a, "secret_in_code")[0])
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "set_finding_status", "finding_id": fid, "status": "accepted", "reason": "rotating"})
    assert s == 400 and "end date" in b["error"]
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "set_finding_status", "finding_id": fid, "status": "resolved"})
    assert s == 400                                                     # only a re-scan can resolve
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "set_finding_status", "finding_id": fid, "status": "accepted",
                                             "reason": "rotating this week", "accepted_until": (date.today() + timedelta(days=7)).isoformat()})
    assert s == 200 and _finding(conn, a, "secret_in_code")[1] == "accepted"


def test_settings_validation_and_export_is_audited_and_formula_safe(api, accounts, conn):
    a = accounts["a"]
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "save_settings", "approved_providers": ["skynet"]})
    assert s == 400
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "save_settings", "github_repos": ["../etc"]})
    assert s == 400
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "save_settings", "approved_providers": ["openai"],
                                             "github_repos": ["app"], "inactive_after_days": 14})
    assert s == 200
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "register_asset", "name": "=HYPERLINK(\"x\")", "asset_type": "tool"})
    s, csv_text = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "export", "what": "assets", "format": "csv"})
    assert s == 200 and "'=HYPERLINK" in csv_text and "\n=HYPERLINK" not in csv_text
    s, au = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "audit"})
    assert any(x["action"] == "export" for x in au["audit"]) and any(x["action"] == "settings" for x in au["audit"])


def test_manual_scan_is_rate_limited(api, accounts):
    a = accounts["a"]
    lam = MagicMock()
    with patch("collectors.aws.scanner.ai_inventory_handler.boto3.client", return_value=lam):
        s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "run_scan"})
        assert s == 200
        assert json.loads(lam.invoke.call_args.kwargs["Payload"]) == {"cloud_account_id": a, "trigger": "manual", "_async": True}
        s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "run_scan"})
        assert s == 429 and lam.invoke.call_count == 1


def test_manual_link_keeps_its_note_when_a_scan_also_finds_it(api, accounts, conn):
    a = accounts["a"]
    src, dst = _aid(conn, a, "github:acme/app"), _aid(conn, a, "provider:groq")
    with conn.cursor() as cur:
        cur.execute("DELETE FROM ai_asset_relationships WHERE source_asset_id = %s AND target_asset_id = %s AND rel_type = 'CALLS_PROVIDER'", (src, dst))
    conn.commit()
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "link_assets", "source_asset_id": src, "target_asset_id": dst,
                                             "rel_type": "CALLS_PROVIDER", "note": "contract #42"})
    assert s == 200
    _run(conn, a, _aws(), [_repo()])
    with conn.cursor() as cur:
        cur.execute("""SELECT origin, note, sources FROM ai_asset_relationships WHERE source_asset_id = %s AND target_asset_id = %s
                       AND rel_type = 'CALLS_PROVIDER'""", (src, dst))
        origin, note, sources = cur.fetchone()
    conn.rollback()
    assert origin == "manual" and note == "contract #42"
    assert any(x.startswith("manual:") for x in sources) and any(x.startswith("github:acme/app@") for x in sources)


def test_same_decision_saved_again_renews_a_lapsed_review(api, accounts, conn):
    a = accounts["a"]
    aid = _aid(conn, a, "provider:groq")
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "update_asset", "asset_id": aid, "approval_status": "approved"})
    with conn.cursor() as cur:
        cur.execute("UPDATE ai_assets SET verification = 'declared' WHERE id = %s", (aid,))   # what a high-impact change does
    conn.commit()
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "update_asset", "asset_id": aid, "approval_status": "approved"})
    assert s == 200 and _asset(conn, a, "provider:groq")["verification"] == "verified"
    s, d = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "asset", "asset_id": aid})
    assert d["changes"][0]["type"] == "review_confirmed"


def test_manual_run_uses_the_account_region(conn, accounts):
    from collectors.aws.scanner import ai_inventory_scanner_handler as h
    with conn.cursor() as cur:
        cur.execute("ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS region VARCHAR(30)")
        cur.execute("UPDATE cloud_accounts SET region = 'us-east-1' WHERE id = %s", (accounts["b"],))
    conn.commit()
    class KeepOpen:                       # the handler closes its connection; the module's must stay open
        def __getattr__(self, name):
            return getattr(conn, name)

        def close(self):
            pass
    with patch.object(h, "_get_connection", return_value=KeepOpen()), patch.object(h, "_assume", return_value=MagicMock()), \
         patch.object(h, "run", return_value={"status": "succeeded"}) as run:
        h.handler({"cloud_account_id": accounts["b"], "_async": True, "trigger": "manual"}, None)
    assert run.call_args[0][4] == "us-east-1"


def test_unreadable_lambda_environment_never_resolves_its_key_finding(conn, accounts):
    a = accounts["a"]
    _run(conn, a, _aws(), [_repo()])
    assert _finding(conn, a, "ai_key_in_lambda_env")[1] in ("open", "in_progress")
    from collectors.aws.scanner import ai_inventory_engine as E, ai_inventory_scanner_handler as h
    aws = _aws()
    aws["functions"][0]["ai_env_names"], aws["functions"][0]["ai_env_plaintext_secrets"] = [], []
    with conn.cursor() as cur:
        cur.execute("INSERT INTO ai_inventory_scans (cloud_account_id, status) VALUES (%s, 'succeeded') RETURNING id", (a,))
        sid = cur.fetchone()[0]
    conn.commit()
    assets, rels, findings, _ = E.build(ACCT, aws, [_repo()], {}, {})
    read = {"aws_parts": set(ALL_PARTS), "aws_parts_by_region": {"eu-west-1": set(ALL_PARTS)}, "repos": {"acme/app"}, "github_complete": True,
            "ciem": False, "lambda_env_unreadable": {FN_ARN}}
    h.store(conn, a, sid, assets, rels, findings, read, 30)
    assert _finding(conn, a, "ai_key_in_lambda_env")[1] in ("open", "in_progress")


def test_lambda_found_only_through_code_is_kept_while_github_is_unread(conn, accounts):
    a = accounts["a"]
    aws = _aws()
    aws["functions"][0]["ai_env_names"], aws["functions"][0]["ai_env_plaintext_secrets"] = [], []
    _run(conn, a, aws, [_repo()])                                      # matched through svc/agent.py only
    _run(conn, a, aws, [], read_repos=(), complete=False)             # GitHub unavailable: Lambda not rebuilt
    assert _asset(conn, a, f"aws:{FN_ARN}")["lifecycle"] == "active"
    _run(conn, a, _aws(), [_repo()])


def test_deleting_a_registered_asset_keeps_its_history(api, accounts, conn):
    a = accounts["a"]
    s, b = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "register_asset", "name": "Temp bot", "asset_type": "agent"})
    s, _ = api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "delete_asset", "asset_id": b["asset_id"]})
    assert s == 200
    s, ch = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "changes"})
    kept = [c for c in ch["changes"] if c["asset"]["name"] == "Temp bot"]
    assert kept and kept[0]["type"] == "registered" and kept[0]["asset"]["id"] is None


def test_api_rejects_unauthenticated_calls_before_touching_the_database():
    from collectors.aws.scanner import ai_inventory_handler as h
    with patch.object(h, "authenticate", return_value=None), patch.object(h, "_get_connection") as gc:
        r = h.handler({"httpMethod": "GET", "queryStringParameters": {"cloud_account_id": str(uuid.uuid4())}, "headers": {}}, None)
    assert r["statusCode"] == 401 and not gc.called


def test_production_asset_without_owner_becomes_a_finding_and_resolves_when_owned(api, conn, accounts):
    a = accounts["a"]
    aid = _aid(conn, a, "provider:groq")
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "update_asset", "asset_id": aid, "owner": None, "environment": "production",
                                      "criticality": "high"})
    with conn.cursor() as cur:
        cur.execute("UPDATE ai_assets SET owner = NULL WHERE id = %s", (aid,))
    conn.commit()
    _run(conn, a, _aws(), [_repo()])
    f = _finding(conn, a, "production_asset_without_owner")
    assert f and f[1] == "open"
    api("owner@a.test", "POST", body={"cloud_account_id": a, "action": "update_asset", "asset_id": aid, "owner": "ai-team"})
    _run(conn, a, _aws(), [_repo()], read_repos=(), complete=False)     # resolves even when sources are partial: it is our own data
    assert _finding(conn, a, "production_asset_without_owner")[1] == "resolved"


def test_risk_score_lists_its_factors(api, conn, accounts):
    a = accounts["a"]
    s, d = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "assets"})
    app = next(x for x in d["assets"] if x["asset_key"] == f"aws:{FN_ARN}")
    assert app["risk_score"] > 0 and app["risk_factors"] and all("points" in f and "factor" in f for f in app["risk_factors"])
    s, one = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "asset", "asset_id": app["id"]})
    assert one["risk_score"] == app["risk_score"]


def test_evidence_package_has_scope_sources_and_limitations(api, accounts):
    a = accounts["a"]
    s, csv_body = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "export", "what": "evidence", "format": "csv"})
    assert s == 400
    s, ev = api("owner@a.test", "GET", {"cloud_account_id": a, "view": "export", "what": "evidence", "format": "json"})
    assert s == 200 and ev["assets"] and all("observations" in x for x in ev["assets"])
    assert "limitations" in ev and "scope" in ev and "not proof" in ev["note"]


def test_vulnerable_dependency_only_resolves_when_dependabot_was_read(conn, accounts):
    a = accounts["a"]
    r = _repo(extra="")
    r["files"].append({"path": "requirements.txt", "text": "langchain==0.0.200\n"})
    r["dependabot"] = {"status": "ok", "alerts": [{"package": "langchain", "ecosystem": "pip", "manifest": "requirements.txt", "ghsa": "GHSA-1",
                                                   "cve": None, "summary": "RCE", "severity": "critical", "fixed_in": "0.0.236", "url": "u"}]}
    from collectors.aws.scanner import ai_inventory_engine as E, ai_inventory_scanner_handler as h

    def run(repo, dependabot_ok):
        with conn.cursor() as cur:
            cur.execute("INSERT INTO ai_inventory_scans (cloud_account_id, status) VALUES (%s, 'succeeded') RETURNING id", (a,))
            sid = cur.fetchone()[0]
        conn.commit()
        assets, rels, findings, _ = E.build(ACCT, _aws(), [repo], {}, {})
        read = {"aws_parts": set(ALL_PARTS), "aws_parts_by_region": {"eu-west-1": set(ALL_PARTS)}, "repos": {"acme/app"}, "github_complete": True, "ciem": False,
                "dependabot_repos": {"acme/app"} if dependabot_ok else set()}
        h.store(conn, a, sid, assets, rels, findings, read, 30)
    run(r, True)
    assert _finding(conn, a, "vulnerable_ai_dependency")[1] == "open"
    fixed = dict(r, dependabot={"status": "no permission to read alerts", "alerts": []})
    run(fixed, False)
    assert _finding(conn, a, "vulnerable_ai_dependency")[1] == "open"            # alerts not readable: no conclusion
    run(dict(r, dependabot={"status": "ok", "alerts": []}), True)
    assert _finding(conn, a, "vulnerable_ai_dependency")[1] == "resolved"
