"""AI Inventory engine (issue #236): discovery signals, verification levels, relationships, findings, and the
guarantee that no secret value or prompt text ends up in the output. Offline: inputs are shaped like the
collector's output (AWS API responses reduced to the fields kept, repository files as path + text)."""
import json

import pytest

from collectors.aws.scanner import ai_inventory_engine as E
from collectors.aws.scanner.ai_inventory_collector import _looks_like_literal_key

pytestmark = [pytest.mark.flow("E2E-AIINV-001"), pytest.mark.severity("P1")]

ACCT = "111122223333"
GROQ_KEY = "gsk_" + "A1b2C3d4E5f6G7h8J9k0L1m2N3p4"          # shaped like a real key, not a real one
ROLE = f"arn:aws:iam::{ACCT}:role/ai-agent-role"

AGENT_PY = '''
import requests
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "openai/gpt-oss-120b"
def handler(event, context):
    return requests.post(GROQ_URL, json={"model": MODEL})
'''


def repo(files, name="acme/app"):
    return {"full_name": name, "url": f"https://github.com/{name}", "default_branch": "main", "commit": "abc123def4567890",
            "files": [{"path": p, "text": t} for p, t in files.items()]}


def aws(**kw):
    base = {"region": "eu-west-1", "coverage": {"bedrock_invocation_logging": {"ok": True}}, "limitations": [], "guardrails": [], "custom_models": [], "provisioned": [],
            "knowledge_bases": [], "agents": [], "vector_collections": [], "sagemaker_endpoints": [], "sagemaker_notebooks": [],
            "functions": [], "bedrock_usage": {}, "invocation_logging": None}
    base.update(kw)
    return base


def by_key(assets):
    return {a["asset_key"]: a for a in assets}


def rels_of(rels, rtype):
    return {(r["source_key"], r["target_key"]) for r in rels if r["type"] == rtype}


# ── source-code signals ─────────────────────────────────────────────────────

def test_provider_comes_from_the_endpoint_not_from_the_model_name():
    assets, rels, _, _ = E.build(ACCT, None, [repo({"svc/agent.py": AGENT_PY})], {})
    a = by_key(assets)
    assert "provider:groq" in a and "provider:openai" not in a      # gpt-oss is an OpenAI model served by Groq
    m = a["model:openai/gpt-oss-120b"]
    assert m["metadata"]["creator"] == "OpenAI" and m["verification"] == "declared"
    assert ("model:openai/gpt-oss-120b", "provider:groq") in rels_of(rels, "SERVED_BY")
    assert ("github:acme/app", "provider:groq") in rels_of(rels, "CALLS_PROVIDER")
    assert ("github:acme/app", "model:openai/gpt-oss-120b") in rels_of(rels, "USES_MODEL")


def test_model_name_without_any_endpoint_has_no_provider():
    assets, rels, _, _ = E.build(ACCT, None, [repo({"cfg.py": 'MODEL = "gpt-4o-mini"'})], {})
    assert "model:gpt-4o-mini" in by_key(assets)
    assert not rels_of(rels, "SERVED_BY")


def test_markdown_mentions_are_not_model_usage():
    assets, _, _, _ = E.build(ACCT, None, [repo({"README.md": "We compared gpt-4o and claude-sonnet-4."})], {})
    assert not assets


def test_bedrock_ids_need_a_version_suffix():
    hits = [s["value"] for s in E.scan_text("a.py", 'x = "anthropic.claude-3-5-sonnet-20240620-v1:0"; y = "amazon.com"') if s["kind"] == "model_ref"]
    assert "anthropic.claude-3-5-sonnet-20240620-v1:0" in hits and not any("amazon.com" in h for h in hits)


def test_secret_value_is_never_kept():
    assets, _, findings, summary = E.build(ACCT, None, [repo({"svc/agent.py": AGENT_PY + f'\nKEY = "{GROQ_KEY}"\n'})], {})
    f = next(x for x in findings if x["rule"] == "secret_in_code")
    assert f["severity"] == "critical" and f["details"]["line"] == 8 and f["details"]["secret_type"] == "groq_api_key"
    dump = json.dumps([assets, findings, summary], default=str)
    assert GROQ_KEY not in dump and GROQ_KEY[4:] not in dump
    assert f["details"]["redacted"].startswith("gsk_") and "chars" in f["details"]["redacted"]


@pytest.mark.parametrize("placeholder", ["sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxx", "sk-your-key-goes-here-123456789", "sk-example-0123456789abcdefghij"])
def test_placeholders_are_not_reported_as_secrets(placeholder):
    assert not [s for s in E.scan_text("a.py", f'KEY = "{placeholder}"') if s["kind"] == "secret"]


# ── MCP ─────────────────────────────────────────────────────────────────────

MCP = {"mcpServers": {
    "remote": {"url": "http://mcp.example.net/sse"},
    "local-fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]},
    "gh": {"command": "npx", "args": ["server-github"], "env": {"GITHUB_TOKEN": "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8"}},
    "safe": {"url": "https://mcp.internal.net", "headers": {"Authorization": "${MCP_TOKEN}"}},
}}


def test_mcp_servers_and_their_risks():
    assets, rels, findings, _ = E.build(ACCT, None, [repo({".cursor/mcp.json": json.dumps(MCP)})], {})
    a = by_key(assets)
    servers = {v["name"]: v for v in a.values() if v["asset_type"] == "mcp_server"}
    assert set(servers) == {"remote", "local-fs", "gh", "safe"}
    rules = {(f["rule"], f["asset_key"].rsplit(":", 1)[-1]) for f in findings}
    assert ("mcp_insecure_transport", "remote") in rules and ("mcp_no_client_auth", "remote") in rules
    assert ("mcp_broad_filesystem", "local-fs") in rules and ("mcp_secret_in_config", "gh") in rules
    assert not any(n == "safe" for _, n in rules)                   # https + ${VAR} reference: nothing to report
    assert len(rels_of(rels, "CONNECTS_TO_MCP_SERVER")) == 4
    assert "ghp_" not in json.dumps([assets, findings])             # env values are not kept, only names
    assert servers["gh"]["metadata"]["env_names"] == ["GITHUB_TOKEN"]


def test_localhost_http_is_not_insecure_transport():
    cfg = {"mcpServers": {"dev": {"url": "http://localhost:3000/mcp", "headers": {"X-Key": "${K}"}}}}
    _, _, findings, _ = E.build(ACCT, None, [repo({"mcp.json": json.dumps(cfg)})], {})
    assert not [f for f in findings if f["rule"] == "mcp_insecure_transport"]


# ── manifests ───────────────────────────────────────────────────────────────

def test_frameworks_guardrails_and_vector_libraries_from_manifests():
    files = {"requirements.txt": "langchain==0.2.1\nguardrails-ai>=0.5\nqdrant-client\n# openai\n",
             "web/package.json": json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}})}
    assets, rels, _, _ = E.build(ACCT, None, [repo(files)], {})
    types = {a["asset_type"] for a in assets}
    assert {"framework", "guardrail", "vector_database", "application"} <= types
    assert not any(a["asset_key"] == "framework:openai_agents" for a in assets)   # commented-out line ignored
    assert rels_of(rels, "PROTECTED_BY_GUARDRAIL") and rels_of(rels, "RETRIEVES_FROM")


def test_repository_without_ai_is_not_an_ai_application():
    assets, _, _, _ = E.build(ACCT, None, [repo({"app.py": "print('hello')", "requirements.txt": "flask\n"})], {})
    assert not assets


# ── AWS ─────────────────────────────────────────────────────────────────────

def test_lambda_is_linked_to_the_repository_file_it_runs_and_to_its_identity():
    fn = {"arn": f"arn:aws:lambda:eu-west-1:{ACCT}:function:agent", "name": "agent", "handler": "svc.agent.handler",
          "runtime": "python3.12", "role_arn": ROLE, "ai_env_names": [], "ai_env_plaintext_secrets": []}
    ciem = {ROLE: {"risk_score": 80, "risk_severity": "critical", "admin": "admin", "risk_reasons": ["Full administrator access"]}}
    assets, rels, findings, _ = E.build(ACCT, aws(functions=[fn]), [repo({"svc/agent.py": AGENT_PY})], ciem)
    fk = f"aws:{fn['arn']}"
    assert ("github:acme/app", fk) in rels_of(rels, "DEPLOYED_ON")
    assert (fk, "provider:groq") in rels_of(rels, "CALLS_PROVIDER")
    assert (fk, f"aws:{ROLE}") in rels_of(rels, "AUTHENTICATES_AS")
    f = next(x for x in findings if x["rule"] == "ai_workload_overprivileged")
    assert f["severity"] == "high" and f["details"]["ciem_reasons"] == ["Full administrator access"]


def test_lambda_without_ai_signals_is_not_inventoried():
    fn = {"arn": f"arn:aws:lambda:eu-west-1:{ACCT}:function:billing", "name": "billing", "handler": "billing.handler",
          "role_arn": ROLE, "ai_env_names": [], "ai_env_plaintext_secrets": []}
    assets, _, _, _ = E.build(ACCT, aws(functions=[fn]), [], {})
    assert not assets


def test_plaintext_ai_key_in_lambda_env_reports_the_name_only():
    fn = {"arn": f"arn:aws:lambda:eu-west-1:{ACCT}:function:bot", "name": "bot", "handler": "bot.handler", "role_arn": None,
          "ai_env_names": ["OPENAI_API_KEY"], "ai_env_plaintext_secrets": ["OPENAI_API_KEY"]}
    _, _, findings, _ = E.build(ACCT, aws(functions=[fn]), [], {})
    f = next(x for x in findings if x["rule"] == "ai_key_in_lambda_env")
    assert f["details"]["variable"] == "OPENAI_API_KEY" and set(f["details"]) == {"basis", "source", "variable", "note"}


@pytest.mark.parametrize("value,expected", [("sk-proj-Ab12Cd34Ef56Gh78Ij90", True), ("arn:aws:secretsmanager:eu-west-1:1:secret:x", False),
                                            ("my-secret-name", False), ("${OPENAI_KEY}", False), ("", False)])
def test_literal_key_detection(value, expected):
    assert _looks_like_literal_key(value) is expected


def test_bedrock_agent_without_guardrail_and_logging_off():
    agent = {"arn": f"arn:aws:bedrock:eu-west-1:{ACCT}:agent/AG1", "name": "support", "status": "PREPARED",
             "model": "anthropic.claude-3-5-sonnet-20240620-v1:0", "role_arn": ROLE, "guardrail": None,
             "instruction_sha256": "ab" * 32, "instruction_length": 420, "knowledge_bases": [],
             "action_groups": [{"id": "AG", "name": "refunds", "executor": "lambda", "state": "ENABLED", "side_effect": "write"}]}
    assets, rels, findings, _ = E.build(ACCT, aws(agents=[agent]), [], {})
    a = by_key(assets)
    ak = f"aws:{agent['arn']}"
    assert a[ak]["verification"] == "discovered"
    assert (ak, "model:anthropic.claude-3-5-sonnet-20240620-v1:0") in rels_of(rels, "USES_MODEL")
    assert ("model:anthropic.claude-3-5-sonnet-20240620-v1:0", "provider:aws_bedrock") in rels_of(rels, "SERVED_BY")
    assert rels_of(rels, "EXPOSES_TOOL") and rels_of(rels, "USES_PROMPT")
    prompt = a[f"prompt:{agent['arn']}"]
    assert prompt["metadata"]["content_sha256"] == "ab" * 32
    assert set(prompt["metadata"]) <= {"content_sha256", "length", "note"}      # a hash, never the instruction text
    rules = {f["rule"] for f in findings}
    assert {"agent_without_guardrail", "bedrock_invocation_logging_off"} <= rules


def test_invocation_metrics_make_a_model_observed():
    assets, _, _, _ = E.build(ACCT, aws(bedrock_usage={"amazon.titan-embed-text-v2:0": 1200}, invocation_logging={"cloudWatchConfig": {}}), [], {})
    m = by_key(assets)["model:amazon.titan-embed-text-v2:0"]
    assert m["verification"] == "observed" and m["metadata"]["invocations_14d"] == 1200


def test_same_model_from_code_and_aws_is_one_asset_with_the_strongest_level():
    code = repo({"x.py": 'import boto3\nc = boto3.client("bedrock-runtime")\nM = "amazon.titan-embed-text-v2:0"'})
    assets, _, _, _ = E.build(ACCT, aws(bedrock_usage={"amazon.titan-embed-text-v2:0": 5}, invocation_logging={"s3Config": {}}), [code], {})
    models = [a for a in assets if a["asset_type"] == "model"]
    assert len(models) == 1 and models[0]["verification"] == "observed"
    assert {o["verification"] for o in models[0]["observations"]} == {"declared", "observed"}


# ── governance ──────────────────────────────────────────────────────────────

def test_unapproved_provider_only_when_a_list_is_set():
    r = [repo({"svc/agent.py": AGENT_PY})]
    assert not [f for f in E.build(ACCT, None, r, {})[2] if f["rule"] == "unapproved_provider"]
    assert [f for f in E.build(ACCT, None, r, {}, {"approved_providers": ["openai"]})[2] if f["rule"] == "unapproved_provider"]
    assert not [f for f in E.build(ACCT, None, r, {}, {"approved_providers": ["groq"]})[2] if f["rule"] == "unapproved_provider"]


def test_keys_and_fingerprints_are_stable_between_runs():
    r = [repo({"svc/agent.py": AGENT_PY + f'\nKEY = "{GROQ_KEY}"\n', "mcp.json": json.dumps(MCP)})]
    a1, _, f1, _ = E.build(ACCT, None, r, {})
    a2, _, f2, _ = E.build(ACCT, None, r, {})
    assert [a["asset_key"] for a in a1] == [a["asset_key"] for a in a2]
    assert sorted(f["fingerprint"] for f in f1) == sorted(f["fingerprint"] for f in f2)


def test_every_finding_has_evidence_recommendation_and_versioned_compliance():
    fn = {"arn": f"arn:aws:lambda:eu-west-1:{ACCT}:function:bot", "name": "bot", "handler": "bot.handler", "role_arn": ROLE,
          "ai_env_names": ["GROQ_API_KEY"], "ai_env_plaintext_secrets": ["GROQ_API_KEY"]}
    r = [repo({"svc/agent.py": AGENT_PY + f'\nKEY = "{GROQ_KEY}"\n', "mcp.json": json.dumps(MCP)})]
    _, _, findings, _ = E.build(ACCT, aws(functions=[fn]), r, {ROLE: {"risk_score": 60, "risk_severity": "high", "admin": None, "risk_reasons": []}},
                                {"approved_providers": ["openai"]})
    assert len({f["rule"] for f in findings}) >= 7
    for f in findings:
        assert f["details"] and f["details"].get("basis") in ("declared", "discovered", "observed", "calculated", "verified")
        assert all(f["recommendation"].get(k) for k in ("current", "proposed", "reason", "rollback"))
        assert f["compliance"] and all(c["mapping_version"] == E.MAPPING_VERSION for c in f["compliance"])
        assert f["severity"] in ("critical", "high", "medium", "low")



# ── review fixes ────────────────────────────────────────────────────────────

def test_credentials_in_mcp_urls_and_arguments_are_redacted():
    tok = "ghp_" + "K8j7H6g5F4d3S2a1Q0w9E8r7"
    cfg = {"mcpServers": {
        "q": {"url": f"https://user:pa55word@mcp.example.net/sse?api_key=abc123secretvalue&region=eu"},
        "a": {"command": "npx", "args": ["server", "--token", tok, f"--api-key={tok}", "--token", "${TOKEN}", GROQ_KEY]}}}
    assets, _, findings, _ = E.build(ACCT, None, [repo({"mcp.json": json.dumps(cfg)})], {})
    dump = json.dumps([assets, findings])
    for secret in (tok, "pa55word", "abc123secretvalue", GROQ_KEY):
        assert secret not in dump
    servers = {a["name"]: a["metadata"] for a in assets if a["asset_type"] == "mcp_server"}
    assert servers["q"]["endpoint"].startswith("https://mcp.example.net/sse?api_key=REDACTED")
    assert servers["a"]["args"] == ["server", "--token", "REDACTED", "--api-key=REDACTED", "--token", "${TOKEN}", "REDACTED"]
    assert {f["asset_key"].rsplit(":", 1)[-1] for f in findings if f["rule"] == "mcp_secret_in_config"} == {"q", "a"}


@pytest.mark.parametrize("text", ["[]", "null", '{"mcpServers": []}', '{"mcp": "x"}', '{"mcpServers": {"x": {"args": "notalist", "env": []}}}'])
def test_odd_but_valid_mcp_json_never_breaks_the_inventory(text):
    assets, _, _, summary = E.build(ACCT, None, [repo({"mcp.json": text, "package.json": "[1, 2]", "svc/agent.py": AGENT_PY})], {})
    assert "provider:groq" in by_key(assets)


def test_bedrock_id_does_not_also_produce_a_shorter_model():
    vals = [s["value"] for s in E.scan_text("a.py", 'M = "anthropic.claude-3-5-sonnet-20240620-v1:0"') if s["kind"] == "model_ref"]
    assert vals == ["anthropic.claude-3-5-sonnet-20240620-v1:0"]


def test_provider_sdk_dependency_is_declared_evidence():
    assets, rels, _, _ = E.build(ACCT, None, [repo({"requirements.txt": "anthropic==0.40\n"})], {})
    assert "provider:anthropic" in by_key(assets)
    r = next(x for x in rels if x["type"] == "CALLS_PROVIDER")
    assert r["confidence"] == "low" and r["verification"] == "declared"


def test_openai_sdk_pointed_at_another_provider_is_not_openai():
    files = {"requirements.txt": "openai==1.50\n", "svc/agent.py": AGENT_PY}
    assets, _, _, _ = E.build(ACCT, None, [repo(files)], {})
    assert "provider:groq" in by_key(assets) and "provider:openai" not in by_key(assets)


def test_logging_off_is_not_concluded_when_its_configuration_could_not_be_read():
    usage = {"amazon.titan-embed-text-v2:0": 3}
    _, _, f1, _ = E.build(ACCT, aws(bedrock_usage=usage, coverage={"bedrock_invocation_logging": {"ok": False}}), [], {})
    _, _, f2, _ = E.build(ACCT, aws(bedrock_usage=usage), [], {})
    assert not [f for f in f1 if f["rule"] == "bedrock_invocation_logging_off"]
    assert [f for f in f2 if f["rule"] == "bedrock_invocation_logging_off"]


def test_agent_guardrail_given_by_id_is_linked():
    g_arn = f"arn:aws:bedrock:eu-west-1:{ACCT}:guardrail/gr123"
    agent = {"arn": f"arn:aws:bedrock:eu-west-1:{ACCT}:agent/AG2", "name": "a2", "role_arn": None, "knowledge_bases": [], "action_groups": [],
             "guardrail": {"id": "gr123", "version": "1", "arn": None}}
    assets, rels, findings, _ = E.build(ACCT, aws(agents=[agent], guardrails=[{"arn": g_arn, "name": "g"}]), [], {})
    assert (f"aws:{agent['arn']}", f"aws:{g_arn}") in rels_of(rels, "PROTECTED_BY_GUARDRAIL")
    assert by_key(assets)[f"aws:{g_arn}"]["metadata"]["guardrail_state"] == "deployed"
    assert not [f for f in findings if f["rule"] == "agent_without_guardrail"]


def test_failed_file_download_marks_the_repository_as_not_read_in_full(monkeypatch):
    import urllib.error
    from collectors.aws.scanner import ai_inventory_collector as C
    monkeypatch.setattr(C, "_gh", lambda url, token, **kw: {"tree": [{"type": "blob", "path": "a.py", "size": 10},
                                                                       {"type": "blob", "path": "b.py", "size": 10}], "truncated": False})

    class Resp:
        def __init__(self, data): self.data = data
        def read(self, n): return self.data
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def urlopen(req, timeout):
        if req.full_url.split("/contents/")[1].startswith("b.py"):
            raise urllib.error.URLError("reset")
        return Resp(b"x = 1")
    monkeypatch.setattr(C.urllib.request, "urlopen", urlopen)
    files, scanned, cands, truncated = C._collect_via_tree("acme/app", "t", "c0ffee")
    assert [f["path"] for f in files] == ["a.py"] and scanned == 1 and cands == 2 and truncated is True


def test_selected_repositories_are_fetched_directly_and_missing_ones_make_it_incomplete(monkeypatch):
    from collectors.aws.scanner import ai_inventory_collector as C
    calls = []

    def gh(url, token, **kw):
        calls.append(url)
        if url.endswith("/repos/acme/gone"):
            raise RuntimeError("404")
        return {"full_name": "acme/app", "archived": False}
    monkeypatch.setattr(C, "_gh", gh)
    monkeypatch.setattr(C, "collect_repo", lambda full, tok: {"files": [], "truncated": False, "commit": "c"})
    out = C.collect_github("acme", "t", ["app", "gone"])
    assert not any("/orgs/" in u for u in calls)
    assert out["complete"] is False and any("gone" in l for l in out["limitations"])


def test_urls_passed_as_mcp_arguments_are_sanitized():
    cfg = {"mcpServers": {"r": {"command": "npx", "args": ["mcp-remote", "https://bob:hunter22@host.example/sse?api_key=s3cr3tvalue99"]}}}
    assets, _, findings, _ = E.build(ACCT, None, [repo({"mcp.json": json.dumps(cfg)})], {})
    dump = json.dumps([assets, findings])
    assert "s3cr3tvalue99" not in dump and "hunter22" not in dump
    assert [f for f in findings if f["rule"] == "mcp_secret_in_config"]


def test_oversized_code_file_makes_the_repository_not_read_in_full():
    from collectors.aws.scanner.ai_inventory_collector import _relevant_large
    assert _relevant_large("svc/agent.py") and _relevant_large("config/mcp.json")
    assert not _relevant_large("package-lock.json") and not _relevant_large("web/dist/app.min.js")


def test_header_arguments_with_credentials_are_redacted():
    cfg = {"mcpServers": {"r": {"command": "npx", "args": ["mcp-remote", "https://h.example/sse", "--header", "Authorization: Bearer Zq81opaqueTOKENx"]}}}
    assets, _, findings, _ = E.build(ACCT, None, [repo({"mcp.json": json.dumps(cfg)})], {})
    assert "Zq81opaqueTOKENx" not in json.dumps([assets, findings])
    assert [f for f in findings if f["rule"] == "mcp_secret_in_config"]


def test_jsonc_mcp_config_is_read_and_broken_config_is_reported():
    jsonc = '{\n // servers\n "servers": {"docs": {"url": "https://docs.example/mcp",},},\n}'
    assets, _, _, summary = E.build(ACCT, None, [repo({".vscode/mcp.json": jsonc})], {})
    assert any(a["asset_type"] == "mcp_server" for a in assets) and not summary["files_not_parsed"]
    _, _, _, summary = E.build(ACCT, None, [repo({"mcp.json": '{"mcpServers": {'})], {})
    assert summary["files_not_parsed"] == [{"repo": "acme/app", "path": "mcp.json", "error": "JSONDecodeError"}]


# ── completeness: regions, guardrail health, tools, delegation, Dependabot ───

def test_several_regions_are_inventoried_side_by_side():
    eu = aws(bedrock_usage={"amazon.titan-embed-text-v2:0": 3})
    us = aws(bedrock_usage={"anthropic.claude-3-5-sonnet-20240620-v1:0": 7})
    us["region"] = "us-east-1"
    assets, _, findings, _ = E.build(ACCT, [eu, us], [], {})
    keys = by_key(assets)
    assert "model:amazon.titan-embed-text-v2:0" in keys and "model:anthropic.claude-3-5-sonnet-20240620-v1:0" in keys
    logging = [f for f in findings if f["rule"] == "bedrock_invocation_logging_off"]
    assert len(logging) == 2 and len({f["fingerprint"] for f in logging}) == 2     # one per region


def test_guardrail_health_follows_its_status():
    g_ok = {"arn": f"arn:aws:bedrock:eu-west-1:{ACCT}:guardrail/a", "name": "ok", "status": "READY"}
    g_bad = {"arn": f"arn:aws:bedrock:eu-west-1:{ACCT}:guardrail/b", "name": "bad", "status": "FAILED"}
    g_unk = {"arn": f"arn:aws:bedrock:eu-west-1:{ACCT}:guardrail/c", "name": "unk"}
    a = by_key(E.build(ACCT, aws(guardrails=[g_ok, g_bad, g_unk]), [], {})[0])
    assert [a[f"aws:{g['arn']}"]["metadata"]["guardrail_state"] for g in (g_ok, g_bad, g_unk)] == ["configured", "degraded", "unknown"]


def test_tool_side_effects_come_from_the_executor_role_not_the_name():
    fn_arn = f"arn:aws:lambda:eu-west-1:{ACCT}:function:refunds"
    fn = {"arn": fn_arn, "name": "refunds", "handler": "x.handler", "role_arn": ROLE, "ai_env_names": [], "ai_env_plaintext_secrets": []}
    agent = {"arn": f"arn:aws:bedrock:eu-west-1:{ACCT}:agent/AG9", "name": "support", "role_arn": None, "guardrail": {"id": "g", "arn": None},
             "knowledge_bases": [], "action_groups": [{"id": "AG", "name": "lookup_order", "executor": fn_arn + ":$LATEST", "state": "ENABLED"}]}
    ciem = {ROLE: {"risk_score": 50, "admin": None, "capabilities": [{"id": "destructive", "label": "Delete infrastructure or data", "result": "allowed"},
                                                                     {"id": "data_read", "label": "Read stored data (S3, DynamoDB)", "result": "scoped"},
                                                                     {"id": "iam_write", "label": "Change IAM identities or permissions", "result": "denied"}]}}
    assets, rels, findings, _ = E.build(ACCT, aws(agents=[agent], functions=[fn]), [], ciem)
    tool = next(a for a in assets if a["asset_type"] == "tool")
    assert tool["metadata"]["side_effect"].startswith("can change or delete resources: Delete infrastructure")
    assert (tool["asset_key"], f"aws:{fn_arn}") in rels_of(rels, "EXECUTED_BY")
    f = next(x for x in findings if x["rule"] == "privileged_ai_tool")
    assert "lookup_order" in f["title"] and f["details"]["capabilities"] == ["Delete infrastructure or data"]
    assets, _, findings, _ = E.build(ACCT, aws(agents=[agent], functions=[fn]), [], {})
    assert next(a for a in assets if a["asset_type"] == "tool")["metadata"]["side_effect"].startswith("unknown")
    assert not [x for x in findings if x["rule"] == "privileged_ai_tool"]


def test_supervisor_agents_delegate_to_collaborators():
    sup = {"arn": f"arn:aws:bedrock:eu-west-1:{ACCT}:agent/SUP", "name": "router", "role_arn": None, "guardrail": {"id": "g"}, "knowledge_bases": [],
           "action_groups": [], "collaboration": "SUPERVISOR",
           "collaborators": [{"name": "billing", "alias_arn": f"arn:aws:bedrock:eu-west-1:{ACCT}:agent-alias/BIL/TSTALIAS", "relay_history": "TO_COLLABORATOR"}]}
    bil = {"arn": f"arn:aws:bedrock:eu-west-1:{ACCT}:agent/BIL", "name": "billing", "role_arn": None, "guardrail": {"id": "g"}, "knowledge_bases": [], "action_groups": []}
    assets, rels, _, _ = E.build(ACCT, aws(agents=[sup, bil]), [], {})
    assert (f"aws:{sup['arn']}", f"aws:{bil['arn']}") in rels_of(rels, "DELEGATES_TO")
    assert len([a for a in assets if a["asset_type"] == "agent"]) == 2          # distinct identities, not merged


def test_dependabot_alerts_on_ai_packages_become_findings_with_impact():
    r = repo({"requirements.txt": "langchain==0.0.200\nflask\n"})
    r["dependabot"] = {"status": "ok", "alerts": [
        {"package": "langchain", "ecosystem": "pip", "manifest": "requirements.txt", "ghsa": "GHSA-xxxx", "cve": "CVE-2023-1", "summary": "RCE",
         "severity": "critical", "fixed_in": "0.0.236", "url": "https://github.com/x"},
        {"package": "flask", "ecosystem": "pip", "manifest": "requirements.txt", "ghsa": "GHSA-yyyy", "cve": None, "summary": "x",
         "severity": "high", "fixed_in": "2.3.2", "url": "https://github.com/y"}]}
    _, _, findings, _ = E.build(ACCT, None, [r], {})
    vul = [f for f in findings if f["rule"] == "vulnerable_ai_dependency"]
    assert len(vul) == 1 and vul[0]["severity"] == "critical" and vul[0]["recommendation"]["proposed"] == "Upgrade to 0.0.236 or later"
    assert vul[0]["asset_key"] == "github:acme/app"


def test_tool_risk_uses_the_role_of_the_invoked_alias_not_latest():
    fn_arn = f"arn:aws:lambda:eu-west-1:{ACCT}:function:refunds"
    admin_role = f"arn:aws:iam::{ACCT}:role/old-admin"
    fn = {"arn": fn_arn, "name": "refunds", "handler": "x.handler", "role_arn": ROLE, "ai_env_names": [], "ai_env_plaintext_secrets": []}
    agent = {"arn": f"arn:aws:bedrock:eu-west-1:{ACCT}:agent/AGX", "name": "support", "role_arn": None, "guardrail": {"id": "g"}, "knowledge_bases": [],
             "action_groups": [{"id": "AG", "name": "refund", "executor": fn_arn + ":prod", "executor_role": admin_role, "state": "ENABLED"}]}
    ciem = {ROLE: {"admin": None, "capabilities": []}, admin_role: {"admin": "admin", "capabilities": []}}
    _, _, findings, _ = E.build(ACCT, aws(agents=[agent], functions=[fn]), [], ciem)
    f = next(x for x in findings if x["rule"] == "privileged_ai_tool")
    assert f["details"]["role_arn"] == admin_role


def test_unknown_operation_means_not_offered_but_other_errors_stay_errors():
    from botocore.exceptions import ClientError
    from collectors.aws.scanner.ai_inventory_collector import _unknown_operation
    err = lambda code, msg: ClientError({"Error": {"Code": code, "Message": msg}}, "ListCustomModels")
    assert _unknown_operation(err("ValidationException", "Unknown operation"))
    assert _unknown_operation(err("UnknownOperationException", "Unknown Operation"))
    assert not _unknown_operation(err("AccessDeniedException", "not authorized"))
    assert not _unknown_operation(err("ValidationException", "bad parameter"))
