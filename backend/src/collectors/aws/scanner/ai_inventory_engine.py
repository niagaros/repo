"""
ai_inventory_engine.py — Niagaros AI Inventory (issue #236). Pure functions: no AWS, GitHub or database calls.

Input: what ai_inventory_collector gathered (AWS AI services read with the customer's read-only scanner role,
repository files read with the customer's GitHub integration), the latest CIEM identities, and manually
registered assets. Output: assets with a stable key, relationships, findings and a summary.

Principles from the issue that this module enforces:
  - Every asset and relationship keeps its source and the moment it was observed.
  - Four verification levels are never mixed up:
      declared    found in source code or configuration (it may not be deployed)
      discovered  listed by a cloud/provider API (it exists / is configured)
      observed    usage evidence (e.g. CloudWatch invocation metrics)
      verified    an authorised person reviewed and approved it
  - Assets are only merged on matching identifiers, never on a display name alone.
  - Secret VALUES are never stored: only where a secret was found and what kind it looks like.
  - Findings need evidence; "custom-built" or "local" is not a finding by itself.
"""
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ENGINE_VERSION = "ai-inventory-1.0"
MAPPING_VERSION = "ai-inventory-compliance-2026.10"

# Extensible taxonomy (issue §2). New types can be added without changing stored data.
ASSET_TYPES = {
    "application": "AI application", "agent": "AI agent", "model": "AI model", "model_provider": "Model provider",
    "model_deployment": "Model deployment", "guardrail": "Guardrail", "mcp_server": "MCP server", "tool": "Tool",
    "prompt": "Prompt / system instruction", "rag_pipeline": "RAG pipeline / knowledge base",
    "vector_database": "Vector database", "dataset": "Dataset", "framework": "AI framework / SDK",
    "ai_endpoint": "AI endpoint", "ai_identity": "AI identity", "ai_infrastructure": "AI infrastructure",
    "workflow": "AI workflow", "evaluation": "Evaluation system", "memory": "AI memory", "artifact": "Model artifact",
}
VERIFICATION_ORDER = {"unknown": 0, "declared": 1, "discovered": 2, "observed": 3, "verified": 4}

# ── provider and library signatures ─────────────────────────────────────────

PROVIDERS = {
    "openai": {"name": "OpenAI", "hosts": [r"api\.openai\.com"], "packages": ["openai"]},
    "azure_openai": {"name": "Azure OpenAI", "hosts": [r"[a-z0-9-]+\.openai\.azure\.com"], "packages": []},
    "anthropic": {"name": "Anthropic", "hosts": [r"api\.anthropic\.com"], "packages": ["anthropic", "@anthropic-ai/sdk"]},
    "groq": {"name": "Groq", "hosts": [r"api\.groq\.com"], "packages": ["groq", "groq-sdk"]},
    "google": {"name": "Google Gemini", "hosts": [r"generativelanguage\.googleapis\.com", r"aiplatform\.googleapis\.com"],
               "packages": ["google-generativeai", "google-genai", "@google/generative-ai", "@google/genai"]},
    "mistral": {"name": "Mistral AI", "hosts": [r"api\.mistral\.ai"], "packages": ["mistralai", "@mistralai/mistralai"]},
    "cohere": {"name": "Cohere", "hosts": [r"api\.cohere\.(?:ai|com)"], "packages": ["cohere", "cohere-ai"]},
    "huggingface": {"name": "Hugging Face", "hosts": [r"api-inference\.huggingface\.co", r"router\.huggingface\.co"],
                    "packages": ["huggingface_hub", "@huggingface/inference"]},
    "openrouter": {"name": "OpenRouter", "hosts": [r"openrouter\.ai/api"], "packages": []},
    "together": {"name": "Together AI", "hosts": [r"api\.together\.(?:xyz|ai)"], "packages": ["together"]},
    "deepseek": {"name": "DeepSeek", "hosts": [r"api\.deepseek\.com"], "packages": []},
    "aws_bedrock": {"name": "Amazon Bedrock", "hosts": [r"bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com"], "packages": []},
}
_BEDROCK_CLIENT = re.compile(r"""client\(\s*["']bedrock-(?:agent-)?runtime["']""")

FRAMEWORKS = {
    "langchain": ["langchain", "langchain-core", "langchain-community", "@langchain/core", "langchain-openai", "langchain-anthropic"],
    "llamaindex": ["llama-index", "llama_index", "llamaindex"],
    "crewai": ["crewai"], "autogen": ["pyautogen", "autogen-agentchat", "autogen"],
    "openai_agents": ["openai-agents", "@openai/agents"], "semantic_kernel": ["semantic-kernel"],
    "haystack": ["haystack-ai", "farm-haystack"], "transformers": ["transformers"], "vercel_ai": ["ai"],
    "mcp_sdk": ["mcp", "@modelcontextprotocol/sdk", "fastmcp"],
}
AGENT_FRAMEWORKS = {"langchain", "llamaindex", "crewai", "autogen", "openai_agents", "semantic_kernel"}
GUARDRAIL_LIBS = {"guardrails-ai": "Guardrails AI", "nemoguardrails": "NVIDIA NeMo Guardrails", "llm-guard": "LLM Guard",
                  "presidio-analyzer": "Microsoft Presidio", "rebuff": "Rebuff", "lakera-guard": "Lakera Guard"}
VECTOR_LIBS = {"pinecone": "Pinecone", "pinecone-client": "Pinecone", "@pinecone-database/pinecone": "Pinecone",
               "weaviate-client": "Weaviate", "qdrant-client": "Qdrant", "chromadb": "Chroma", "pgvector": "pgvector",
               "faiss-cpu": "FAISS", "pymilvus": "Milvus", "opensearch-py": "OpenSearch"}

# Model identifiers. Deliberately conservative: a match must look like a real model id.
MODEL_PATTERNS = [
    ("openai", r"\b(gpt-(?:4o|4\.1|4|3\.5|5)(?:-[a-z0-9.]+)*|text-embedding-3-(?:small|large))\b"),
    ("openai", r"\b(openai/gpt-oss-\d+b)\b"),
    ("anthropic", r"\b(claude-(?:opus|sonnet|haiku|fable|3|3-5|3-7|instant|2)[a-z0-9.-]*)\b"),
    # Bedrock ids always carry a version suffix (anthropic.claude-3-5-sonnet-20240620-v1:0, amazon.titan-embed-text-v2:0)
    ("aws_bedrock", r"\b((?:[a-z]{2}\.)?(?:anthropic|amazon|meta|mistral|cohere|ai21)\.[a-z0-9.-]+-v\d+(?::\d+)?)"),
    ("google", r"\b(gemini-(?:[0-9.]+|pro|flash|ultra)[a-z0-9.-]*)\b"),
    ("mistral", r"\b((?:mistral|mixtral|codestral|ministral)-[a-z0-9.-]+)\b"),
    ("meta", r"\b((?:meta-)?llama-?[0-9][a-z0-9.-]*)\b"),
]

# Secrets: only the KIND and location are kept. Patterns are provider key formats.
SECRET_PATTERNS = [
    ("openai_api_key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    ("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    ("groq_api_key", r"\bgsk_[A-Za-z0-9]{20,}\b"),
    ("huggingface_token", r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
]
_PLACEHOLDER = re.compile(r"(x{6,}|\.\.\.|<|your[_-]|example|placeholder|dummy|test|fake)", re.I)

TEXT_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml", ".txt", ".cfg",
            ".ini", ".env.example", ".java", ".go", ".rb", ".cs", ".tf", ".md")
MCP_CONFIG_NAMES = ("mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json")


def stable_key(*parts):
    return ":".join(str(p) for p in parts)


def fingerprint(*parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:40]


# ── source-code analysis ─────────────────────────────────────────────────────

def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def scan_text(path, text):
    """Signals in one file: provider endpoints, model ids, Bedrock clients, possible secrets."""
    out = []
    for pid, p in PROVIDERS.items():
        for h in p["hosts"]:
            for m in re.finditer(h, text):
                out.append({"kind": "provider_endpoint", "provider": pid, "value": m.group(0), "path": path, "line": _line_of(text, m.start())})
    for m in _BEDROCK_CLIENT.finditer(text):
        out.append({"kind": "provider_endpoint", "provider": "aws_bedrock", "value": m.group(0), "path": path, "line": _line_of(text, m.start())})
    if not path.endswith(".md"):
        found = []
        for pid, rx in MODEL_PATTERNS:
            for m in re.finditer(rx, text, re.I):
                found.append((m.start(1), m.end(1), pid, m.group(1)))
        # a match inside a longer one (claude-3-5-sonnet inside anthropic.claude-3-5-sonnet-...-v1:0) is the same model
        for st, en, pid, val in found:
            if any(o_st <= st and en <= o_en and (o_en - o_st) > (en - st) for o_st, o_en, _, _ in found):
                continue
            out.append({"kind": "model_ref", "provider": pid, "value": val, "path": path, "line": _line_of(text, st)})
    for kind, rx in SECRET_PATTERNS:
        for m in re.finditer(rx, text):
            if _PLACEHOLDER.search(m.group(0)):
                continue
            out.append({"kind": "secret", "secret_type": kind, "path": path, "line": _line_of(text, m.start()),
                        "redacted": m.group(0)[:4] + "…" + f"({len(m.group(0))} chars)"})
    return out


def parse_manifest(path, text):
    """Package names from requirements*.txt, pyproject.toml and package.json (name -> version spec or '')."""
    pkgs = {}
    base = path.rsplit("/", 1)[-1].lower()
    if base == "package.json":
        try:
            d = json.loads(text)
        except ValueError:
            return pkgs
        if not isinstance(d, dict):
            return pkgs
        for sec in ("dependencies", "devDependencies", "peerDependencies"):
            deps = d.get(sec)
            if isinstance(deps, dict):
                for k, v in deps.items():
                    pkgs[str(k).lower()] = str(v)
    elif base.startswith("requirements") and base.endswith(".txt"):
        for line in text.splitlines():
            line = line.split("#")[0].strip()
            m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([<>=!~].*)?$", line)
            if m and not line.startswith("-"):
                pkgs[re.sub(r"\[.*\]", "", m.group(1)).lower().replace("_", "-")] = (m.group(2) or "").strip()
    elif base == "pyproject.toml":
        for m in re.finditer(r'["\']([A-Za-z0-9_.\-]+)\s*([<>=!~][^"\']*)?["\']', text):
            pkgs.setdefault(m.group(1).lower().replace("_", "-"), (m.group(2) or "").strip())
    return pkgs


def parse_mcp_config(path, text):
    """MCP client configuration -> servers. Env/header VALUES are not kept: only names and whether they look like
    literal secrets or ${VARIABLE} references."""
    d = json.loads(_strip_jsonc(text))   # ValueError propagates: _safe records it and the repo is not "read in full"
    if not isinstance(d, dict):
        return []
    mcp = d.get("mcp") if isinstance(d.get("mcp"), dict) else {}
    servers = d.get("mcpServers") or d.get("servers") or mcp.get("servers") or {}
    out = []
    if not isinstance(servers, dict):
        return out
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        url = cfg.get("url") or cfg.get("serverUrl")
        url = url if isinstance(url, str) else None
        command = cfg.get("command") if isinstance(cfg.get("command"), str) else None
        raw_args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
        literal_secrets = [str(k) for k, v in {**env, **headers}.items()
                           if isinstance(v, str) and v and not _is_reference(v)
                           and re.search(r"(key|token|secret|password|auth)", str(k), re.I) and len(v) >= 12]
        url, url_secrets = _sanitize_url(url)
        args, arg_secrets = _sanitize_args([str(a) for a in raw_args])
        out.append({
            "name": str(name), "path": path,
            "transport": "http" if url else ("stdio" if command else "unknown"),
            "url": url, "command": command, "args": args[:20],
            "env_names": sorted(env.keys()), "header_names": sorted(headers.keys()),
            "auth_configured": bool(headers) or bool(url_secrets) or bool(arg_secrets)
                               or any(re.search(r"(key|token|auth|secret)", str(k), re.I) for k in env),
            "literal_secret_names": literal_secrets + url_secrets + arg_secrets,
        })
    return out


_SECRETISH = re.compile(r"(key|token|secret|password|passwd|auth|credential|sig|signature)", re.I)


def _strip_jsonc(text):
    """Remove // and /* */ comments and trailing commas outside strings."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 2; continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True; out.append(c); i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c); i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _is_reference(v):
    """${VAR}, $VAR, {{template}} or <placeholder>: a pointer to a secret, not the secret."""
    return bool(re.search(r"\$\{|\$[A-Z_]|^<|^\{\{", v))


def _literal_secret(v):
    return any(re.search(rx, v) and not _PLACEHOLDER.search(v) for _, rx in SECRET_PATTERNS)


def _sanitize_url(url):
    """Drop user:password@ and every query-parameter value. Returns (safe url, what was removed)."""
    if not url:
        return url, []
    try:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return "[unparseable URL removed]", ["url"]
    removed = []
    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
        removed.append("url credentials")
    for k, v in query:
        if v and not _is_reference(v) and (_SECRETISH.search(k) or _literal_secret(v)):
            removed.append(f"url parameter {k}")
    safe_query = urlencode([(k, "REDACTED" if v else "") for k, v in query])
    return urlunsplit((parts.scheme, netloc, parts.path, safe_query, "")), removed


def _sanitize_args(args):
    """Replace values that follow a secret-like flag (--token x, --api-key=x) or look like a key on their own."""
    out, removed, redact_next = [], [], None
    for a in args:
        h = re.match(r"^\s*([A-Za-z0-9_-]+)\s*:\s*(\S.*)$", a)
        if h and not re.match(r"^[a-z][a-z0-9+.-]*://", a, re.I) and \
                (_SECRETISH.search(h.group(1)) or re.search(r"(cookie|bearer|basic)", a, re.I)) and not _is_reference(h.group(2)):
            out.append(f"{h.group(1)}: REDACTED")
            removed.append(f"header argument {h.group(1)}")
            redact_next = None
            continue
        if re.search(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", a, re.I) and not _is_reference(a):
            out.append("REDACTED")
            removed.append("argument with a bearer/basic credential")
            redact_next = None
            continue
        if redact_next:
            flag, redact_next = redact_next, None
            if not _is_reference(a):
                out.append("REDACTED")
                removed.append(f"argument after {flag}")
                continue
        m = re.match(r"^(--?[A-Za-z0-9_-]+)=(.*)$", a)
        if m and _SECRETISH.search(m.group(1)) and m.group(2) and not _is_reference(m.group(2)):
            out.append(m.group(1) + "=REDACTED")
            removed.append(f"argument {m.group(1)}")
            continue
        if re.match(r"^--?[A-Za-z0-9_-]+$", a) and _SECRETISH.search(a):
            redact_next = a
            out.append(a)
            continue
        if re.match(r"^[a-z][a-z0-9+.-]*://", a, re.I):
            safe, url_removed = _sanitize_url(a)
            out.append(safe)
            removed += [f"argument {r}" for r in url_removed]
            continue
        if _literal_secret(a):
            out.append("REDACTED")
            removed.append("argument that looks like a key")
            continue
        out.append(a)
    return out, removed


# ── inventory assembly ──────────────────────────────────────────────────────

class Inventory:
    def __init__(self):
        self.assets, self.rels, self.findings = {}, {}, []

    def asset(self, key, atype, name, source, verification, ref=None, observed_at=None, provider=None, **meta):
        a = self.assets.get(key)
        if a is None:
            a = self.assets[key] = {"asset_key": key, "asset_type": atype, "name": name, "provider": provider,
                                    "verification": verification, "metadata": {}, "observations": []}
        if VERIFICATION_ORDER[verification] > VERIFICATION_ORDER[a["verification"]]:
            a["verification"] = verification
        a["metadata"].update({k: v for k, v in meta.items() if v is not None})
        obs = {"source": source, "ref": ref, "observed_at": observed_at, "verification": verification}
        if obs not in a["observations"]:
            a["observations"].append(obs)
        return a

    def rel(self, src, dst, rtype, source, verification, confidence="high", note=None):
        if src == dst or src not in self.assets or dst not in self.assets:
            return
        k = (src, dst, rtype)
        r = self.rels.get(k)
        if r is None:
            self.rels[k] = {"source_key": src, "target_key": dst, "type": rtype, "sources": [source],
                            "verification": verification, "confidence": confidence, "note": note}
        else:
            if source not in r["sources"]:
                r["sources"].append(source)
            if VERIFICATION_ORDER[verification] > VERIFICATION_ORDER[r["verification"]]:
                r["verification"] = verification


def _finding(inv, rule, severity, title, asset_key, evidence, recommendation, compliance_theme, key=""):
    inv.findings.append({
        "fingerprint": fingerprint(rule, asset_key, key), "rule": rule, "severity": severity, "title": title,
        "asset_key": asset_key, "details": evidence, "recommendation": recommendation,
        "compliance": compliance_for(compliance_theme),
    })


COMPLIANCE = {
    "inventory": [("ISO 42001", "A.4.2", "Resource documentation (AI system resources)"), ("NIST AI RMF", "MAP 1.1", "Intended purpose and context documented"),
                  ("ISO 27001:2022", "A.5.9", "Inventory of information and other associated assets"), ("EU AI Act", "Art. 11", "Technical documentation")],
    "secrets": [("ISO 27001:2022", "A.5.17", "Authentication information"), ("ISO 27001:2022", "A.8.4", "Access to source code"),
                ("SOC2", "CC6.1", "Logical access security"), ("NIST CSF v2.0", "PR.AA-01", "Identities and credentials managed")],
    "access": [("ISO 27001:2022", "A.8.2", "Privileged access rights"), ("NIST AI RMF", "MANAGE 2.2", "Mechanisms to sustain AI system value and manage risk"),
               ("SOC2", "CC6.3", "Role-based access, least privilege"), ("NIST CSF v2.0", "PR.AA-05", "Access permissions managed with least privilege")],
    "monitoring": [("ISO 42001", "A.6.2.6", "AI system operation and monitoring"), ("ISO 27001:2022", "A.8.15", "Logging"),
                   ("NIST AI RMF", "MEASURE 2.4", "AI system functionality and behavior monitored"), ("EU AI Act", "Art. 12", "Record-keeping")],
    "controls": [("ISO 42001", "A.6.2.4", "AI system verification and validation"), ("NIST AI RMF", "MANAGE 2.4", "Mechanisms to supersede, disengage or deactivate AI systems"),
                 ("EU AI Act", "Art. 15", "Accuracy, robustness and cybersecurity")],
    "transport": [("ISO 27001:2022", "A.8.24", "Use of cryptography"), ("SOC2", "CC6.7", "Transmission of data restricted and protected"),
                  ("NIST CSF v2.0", "PR.DS-02", "Data-in-transit protected")],
    "governance": [("ISO 42001", "A.3.2", "AI roles and responsibilities"), ("NIST AI RMF", "GOVERN 2.1", "Roles and responsibilities documented"),
                   ("ISO 27001:2022", "A.5.9", "Inventory of information and other associated assets")],
}


def compliance_for(theme):
    return [{"framework": f, "control": c, "title": t, "mapping_version": MAPPING_VERSION} for f, c, t in COMPLIANCE.get(theme, [])]


def _handler_module(handler):
    """'collectors.aws.scanner.ai_agent_handler.handler' -> 'collectors/aws/scanner/ai_agent_handler.py'"""
    if not handler or "." not in handler:
        return None
    return handler.rsplit(".", 1)[0].replace(".", "/") + ".py"


def build(account, aws, repos, ciem_by_role, settings=None, now=None):
    """aws: collector output (or None), repos: list of repository scan results, ciem_by_role: role ARN -> CIEM
    identity summary, settings: {"approved_providers": [...]}. Returns (assets, relationships, findings, summary)."""
    settings = settings or {}
    inv = Inventory()
    now_s = now
    approved = {p.lower() for p in settings.get("approved_providers") or []}

    def provider_asset(pid, source, verification, ref=None):
        p = PROVIDERS.get(pid, {"name": pid})
        return inv.asset(stable_key("provider", pid), "model_provider", p["name"], source, verification, ref, now_s, provider=pid)

    def model_asset(creator, model_id, source, verification, ref=None, served_by=None):
        """A model is identified by its id alone. `creator` (who made it) is metadata; `served_by` (whose API
        or service runs it) is a relationship and only set when the evidence shows it."""
        key = stable_key("model", model_id.lower())
        inv.asset(key, "model", model_id, source, verification, ref, now_s, provider=None, model_identifier=model_id,
                  creator=PROVIDERS.get(creator, {}).get("name", creator))
        for pid in served_by or []:
            provider_asset(pid, source, verification, ref)
            inv.rel(key, stable_key("provider", pid), "SERVED_BY", source, verification,
                    confidence="high" if verification in ("discovered", "observed") else "medium")
        return key

    # ── repositories ────────────────────────────────────────────────────────
    file_to_app = {}
    parse_errors = []
    for repo in repos or []:
        app_key = stable_key("github", repo["full_name"])
        src = f"github:{repo['full_name']}@{(repo.get('commit') or '')[:12]}"
        ai_used = False
        for f in repo.get("files", []):
            sigs = scan_text(f["path"], f["text"])
            providers = {s["provider"] for s in sigs if s["kind"] == "provider_endpoint"}
            if providers or any(s["kind"] == "model_ref" for s in sigs):
                file_to_app[(repo["full_name"], f["path"])] = (app_key, providers, [s for s in sigs if s["kind"] == "model_ref"])
            for s in sigs:
                if s["kind"] == "secret":
                    ai_used = True
                    inv.asset(app_key, "application", repo["full_name"], src, "declared", repo.get("url"), now_s,
                              repository=repo["full_name"], default_branch=repo.get("default_branch"))
                    _finding(inv, "secret_in_code", "critical", f"Possible {s['secret_type'].replace('_', ' ')} in {repo['full_name']}:{s['path']}",
                             app_key, {"path": s["path"], "line": s["line"], "secret_type": s["secret_type"], "redacted": s["redacted"],
                                       "basis": "declared", "source": src,
                                       "note": "The value is not stored by Niagaros. Treat the key as exposed until rotated."},
                             {"current": "API key committed to the repository", "proposed": "Rotate the key at the provider, remove it from the code and its history, and load it from a secrets manager",
                              "reason": "Anyone with read access to the repository (or a clone of it) can use the key.", "impact": "Callers using the old key stop working after rotation.",
                              "confidence": "medium", "approvals": "Application owner", "rollback": "Not applicable (a leaked key must be rotated)."},
                             "secrets", key=f"{s['path']}:{s['line']}")
            if f["path"].rsplit("/", 1)[-1].lower() in MCP_CONFIG_NAMES or f["path"].lower().endswith((".cursor/mcp.json", ".vscode/mcp.json")):
                for srv in _safe(parse_mcp_config, f, parse_errors, [], repo["full_name"]):
                    ai_used = True
                    key = stable_key("mcp", repo["full_name"], f["path"], srv["name"])
                    inv.asset(key, "mcp_server", srv["name"], src, "declared", f"{f['path']}", now_s,
                              transport=srv["transport"], endpoint=srv["url"], command=srv["command"], args=srv["args"],
                              env_names=srv["env_names"], header_names=srv["header_names"], auth_configured=srv["auth_configured"],
                              config_path=f["path"], repository=repo["full_name"])
                    inv.asset(app_key, "application", repo["full_name"], src, "declared", repo.get("url"), now_s,
                              repository=repo["full_name"], default_branch=repo.get("default_branch"))
                    inv.rel(app_key, key, "CONNECTS_TO_MCP_SERVER", src, "declared")
                    _mcp_findings(inv, key, srv, src)
        manifests = {}
        for f in repo.get("files", []):
            name = f["path"].rsplit("/", 1)[-1].lower()
            if name == "package.json" or name == "pyproject.toml" or (name.startswith("requirements") and name.endswith(".txt")):
                for pkg, ver in _safe(parse_manifest, f, parse_errors, {}, repo["full_name"]).items():
                    manifests.setdefault(pkg, (ver, f["path"]))
        for fw, names in FRAMEWORKS.items():
            hit = next((n for n in names if n in manifests), None)
            if hit:
                ai_used = True
                key = stable_key("framework", fw)
                inv.asset(key, "framework", hit, src, "declared", manifests[hit][1], now_s, package=hit)
                inv.asset(app_key, "application", repo["full_name"], src, "declared", repo.get("url"), now_s,
                          repository=repo["full_name"], default_branch=repo.get("default_branch"))
                inv.rel(app_key, key, "DEPENDS_ON", src, "declared", note=f"{hit} {manifests[hit][0]} in {manifests[hit][1]}".strip())
        for pkg, label in {**GUARDRAIL_LIBS, **VECTOR_LIBS}.items():
            if pkg in manifests:
                ai_used = True
                is_guard = pkg in GUARDRAIL_LIBS
                key = stable_key("guardrail" if is_guard else "vectordb", "lib", pkg, repo["full_name"])
                inv.asset(key, "guardrail" if is_guard else "vector_database", label, src, "declared", manifests[pkg][1], now_s,
                          package=pkg, guardrail_state="declared" if is_guard else None, repository=repo["full_name"])
                inv.asset(app_key, "application", repo["full_name"], src, "declared", repo.get("url"), now_s,
                          repository=repo["full_name"], default_branch=repo.get("default_branch"))
                inv.rel(app_key, key, "PROTECTED_BY_GUARDRAIL" if is_guard else "RETRIEVES_FROM", src, "declared")
        # provider SDKs in a manifest are declared evidence too. The OpenAI SDK is also used against other
        # providers' OpenAI-compatible endpoints, so it only counts for OpenAI when no other endpoint was found.
        repo_endpoints = {pid for (rn, _), (_, prov, _) in file_to_app.items() if rn == repo["full_name"] for pid in prov}
        for pid, p in PROVIDERS.items():
            pkg = next((n for n in p.get("packages", []) if n in manifests), None)
            if not pkg or pid in repo_endpoints or (pid == "openai" and repo_endpoints):
                continue
            ai_used = True
            provider_asset(pid, src, "declared", manifests[pkg][1])
            inv.asset(app_key, "application", repo["full_name"], src, "declared", repo.get("url"), now_s,
                      repository=repo["full_name"], default_branch=repo.get("default_branch"))
            inv.rel(app_key, stable_key("provider", pid), "CALLS_PROVIDER", src, "declared", confidence="low",
                    note=f"SDK dependency {pkg} in {manifests[pkg][1]} (no endpoint found in the scanned code)")
        for (rname, path), (akey, providers, models) in file_to_app.items():
            if rname != repo["full_name"]:
                continue
            ai_used = True
            inv.asset(app_key, "application", repo["full_name"], src, "declared", repo.get("url"), now_s,
                      repository=repo["full_name"], default_branch=repo.get("default_branch"))
            for pid in providers:
                provider_asset(pid, src, "declared", path)
                inv.rel(app_key, stable_key("provider", pid), "CALLS_PROVIDER", src, "declared", note=path)
            for m in models:
                mk = model_asset(m["provider"], m["value"], src, "declared", f"{path}:{m['line']}", served_by=sorted(providers))
                inv.rel(app_key, mk, "USES_MODEL", src, "declared", note=f"{path}:{m['line']}")
        if not ai_used:
            inv.assets.pop(app_key, None)

    # ── AWS ─────────────────────────────────────────────────────────────────
    if aws:
        region = aws.get("region")
        asrc = f"aws:{account}:{region}"
        usage = aws.get("bedrock_usage") or {}
        for model_id, n in usage.items():
            mk = model_asset("aws_bedrock", model_id, asrc + ":cloudwatch", "observed", f"AWS/Bedrock Invocations ModelId={model_id}",
                             served_by=["aws_bedrock"])
            inv.assets[mk]["metadata"]["invocations_14d"] = n
        for m in aws.get("custom_models", []):
            inv.asset(stable_key("aws", m["arn"]), "model_deployment", m["name"], asrc, "discovered", m["arn"], now_s,
                      provider="aws_bedrock", base_model=m.get("base_model"), kind="custom model")
        for p in aws.get("provisioned", []):
            k = stable_key("aws", p["arn"])
            inv.asset(k, "model_deployment", p["name"], asrc, "discovered", p["arn"], now_s, provider="aws_bedrock",
                      model_arn=p.get("model_arn"), status=p.get("status"), kind="provisioned throughput")
        for g in aws.get("guardrails", []):
            inv.asset(stable_key("aws", g["arn"]), "guardrail", g["name"], asrc, "discovered", g["arn"], now_s, provider="aws_bedrock",
                      guardrail_state="configured", version=g.get("version"), filters=g.get("filters"), status=g.get("status"))
        for kb in aws.get("knowledge_bases", []):
            k = stable_key("aws", kb["arn"])
            inv.asset(k, "rag_pipeline", kb["name"], asrc, "discovered", kb["arn"], now_s, provider="aws_bedrock",
                      status=kb.get("status"), storage_type=kb.get("storage_type"), embedding_model=kb.get("embedding_model"))
            if kb.get("embedding_model"):
                mk = model_asset("aws_bedrock", kb["embedding_model"].split("/")[-1], asrc, "discovered", kb["arn"], served_by=["aws_bedrock"])
                inv.rel(k, mk, "USES_MODEL", asrc, "discovered")
            if kb.get("vector_store_arn"):
                vk = stable_key("aws", kb["vector_store_arn"])
                inv.asset(vk, "vector_database", kb["vector_store_arn"].split("/")[-1], asrc, "discovered", kb["vector_store_arn"], now_s,
                          provider="aws", storage_type=kb.get("storage_type"))
                inv.rel(k, vk, "RETRIEVES_FROM", asrc, "discovered")
        for c in aws.get("vector_collections", []):
            inv.asset(stable_key("aws", c["arn"]), "vector_database", c["name"], asrc, "discovered", c["arn"], now_s,
                      provider="aws", kind="OpenSearch Serverless VECTORSEARCH", status=c.get("status"))
        logging_on = bool(aws.get("invocation_logging"))
        # "off" is only concluded when the logging configuration was actually read
        logging_known = ((aws.get("coverage") or {}).get("bedrock_invocation_logging") or {}).get("ok", False)
        for ag in aws.get("agents", []):
            k = stable_key("aws", ag["arn"])
            inv.asset(k, "agent", ag["name"], asrc, "discovered", ag["arn"], now_s, provider="aws_bedrock",
                      status=ag.get("status"), foundation_model=ag.get("model"), role_arn=ag.get("role_arn"),
                      guardrail=ag.get("guardrail"), memory=ag.get("memory"), idle_session_ttl=ag.get("idle_ttl"),
                      instruction_sha256=ag.get("instruction_sha256"), autonomy_level=ag.get("autonomy"))
            if ag.get("model"):
                mk = model_asset("aws_bedrock", ag["model"].split("/")[-1], asrc, "discovered", ag["arn"], served_by=["aws_bedrock"])
                inv.rel(k, mk, "USES_MODEL", asrc, "discovered")
            if ag.get("instruction_sha256"):
                pk = stable_key("prompt", ag["arn"])
                inv.asset(pk, "prompt", f"{ag['name']} instruction", asrc, "discovered", ag["arn"], now_s,
                          content_sha256=ag["instruction_sha256"], length=ag.get("instruction_length"),
                          note="Only a hash is stored; the instruction text stays in AWS.")
                inv.rel(k, pk, "USES_PROMPT", asrc, "discovered")
            if ag.get("guardrail"):
                gid = ag["guardrail"].get("arn") or ag["guardrail"].get("id")
                g_arn = gid if str(gid).startswith("arn:") else next(
                    (g["arn"] for g in aws.get("guardrails", []) if g["arn"].endswith(f"/{gid}")), None)
                gk = stable_key("aws", g_arn) if g_arn else None
                if gk and gk in inv.assets:
                    inv.rel(k, gk, "PROTECTED_BY_GUARDRAIL", asrc, "discovered")
                    inv.assets[gk]["metadata"]["guardrail_state"] = "deployed"
            else:
                _finding(inv, "agent_without_guardrail", "medium", f"Bedrock agent {ag['name']} has no guardrail", k,
                         {"basis": "discovered", "source": asrc, "agent_arn": ag["arn"]},
                         {"current": "No guardrailConfiguration on the agent", "proposed": "Attach a Bedrock guardrail (content filters, denied topics, sensitive-information filters)",
                          "reason": "Without a guardrail the agent has no platform-level input/output control.", "impact": "Some requests may be blocked after the change; test first.",
                          "confidence": "high", "approvals": "Agent owner", "rollback": "Remove the guardrail from the agent and prepare it again."}, "controls")
            for kbid in ag.get("knowledge_bases", []):
                kbk = next((a for a in inv.assets if a.endswith(f":knowledge-base/{kbid}")), None)
                if kbk:
                    inv.rel(k, kbk, "RETRIEVES_FROM", asrc, "discovered")
            for t in ag.get("action_groups", []):
                tk = stable_key("tool", ag["arn"], t["id"])
                inv.asset(tk, "tool", t["name"], asrc, "discovered", ag["arn"], now_s, provider="aws_bedrock",
                          executor=t.get("executor"), state=t.get("state"), functions=t.get("functions"),
                          side_effect=t.get("side_effect", "unknown"))
                inv.rel(k, tk, "EXPOSES_TOOL", asrc, "discovered")
            _identity_link(inv, k, ag.get("role_arn"), ciem_by_role, asrc)
        if (aws.get("agents") or aws.get("knowledge_bases") or usage or aws.get("custom_models") or aws.get("provisioned")) and logging_known and not logging_on:
            k = stable_key("provider", "aws_bedrock")
            provider_asset("aws_bedrock", asrc, "discovered")
            _finding(inv, "bedrock_invocation_logging_off", "medium", f"Bedrock model invocation logging is off in {region}", k,
                     {"basis": "discovered", "source": asrc, "region": region},
                     {"current": "Model invocation logging disabled", "proposed": "Enable invocation logging to CloudWatch Logs or S3 (with appropriate retention and access control)",
                      "reason": "Without it there is no record of prompts/responses for investigations or audits.", "impact": "Log storage costs; logs may contain sensitive data, so restrict access.",
                      "confidence": "high", "approvals": "Security owner", "rollback": "Disable invocation logging again."}, "monitoring")
        for e in aws.get("sagemaker_endpoints", []):
            k = stable_key("aws", e["arn"])
            inv.asset(k, "ai_endpoint", e["name"], asrc, "discovered", e["arn"], now_s, provider="aws_sagemaker",
                      status=e.get("status"), models=e.get("models"), instance_types=e.get("instance_types"),
                      data_capture=e.get("data_capture"))
        for nb in aws.get("sagemaker_notebooks", []):
            k = stable_key("aws", nb["arn"])
            inv.asset(k, "ai_infrastructure", nb["name"], asrc, "discovered", nb["arn"], now_s, provider="aws_sagemaker",
                      kind="notebook instance", status=nb.get("status"), direct_internet=nb.get("direct_internet"),
                      root_access=nb.get("root_access"), role_arn=nb.get("role_arn"))
            if nb.get("direct_internet") == "Enabled" and nb.get("root_access") == "Enabled":
                _finding(inv, "notebook_internet_and_root", "medium", f"SageMaker notebook {nb['name']} has direct internet and root access", k,
                         {"basis": "discovered", "source": asrc},
                         {"current": "DirectInternetAccess=Enabled, RootAccess=Enabled", "proposed": "Disable direct internet access (use a VPC) and root access unless required",
                          "reason": "A compromised notebook with root and internet access can install tools and exfiltrate data freely.",
                          "impact": "Package installs need a VPC route or proxy.", "confidence": "high", "approvals": "Notebook owner",
                          "rollback": "Re-enable the settings on the notebook instance."}, "access")
            _identity_link(inv, k, nb.get("role_arn"), ciem_by_role, asrc)
        for fn in aws.get("functions", []):
            module = _handler_module(fn.get("handler"))
            matched = [(rp[1], v) for rp, v in file_to_app.items() if module and rp[1].endswith(module)]
            ai_env = fn.get("ai_env_names") or []
            if not matched and not ai_env:
                continue
            k = stable_key("aws", fn["arn"])
            inv.asset(k, "ai_infrastructure", fn["name"], asrc, "discovered", fn["arn"], now_s, provider="aws_lambda",
                      kind="Lambda function", runtime=fn.get("runtime"), handler=fn.get("handler"), role_arn=fn.get("role_arn"),
                      ai_env_names=ai_env, last_modified=fn.get("last_modified"))
            for path, (app_key, providers, models) in matched:
                inv.rel(app_key, k, "DEPLOYED_ON", asrc, "discovered", confidence="medium",
                        note=f"handler {fn['handler']} matches {path}")
                for pid in providers:
                    inv.rel(k, stable_key("provider", pid), "CALLS_PROVIDER", f"{asrc} + {path}", "declared", confidence="medium")
                for m in models:
                    inv.rel(k, stable_key("model", m["value"].lower()), "USES_MODEL", f"{asrc} + {path}", "declared", confidence="medium")
            for name in fn.get("ai_env_plaintext_secrets") or []:
                _finding(inv, "ai_key_in_lambda_env", "high", f"AI provider key stored as a plain environment variable on {fn['name']}", k,
                         {"basis": "discovered", "source": asrc, "variable": name,
                          "note": "Only the variable name is stored; its value is not read into Niagaros."},
                         {"current": f"{name} holds the key in the function configuration", "proposed": "Store the key in Secrets Manager and read it at runtime",
                          "reason": "Environment variables are visible to anyone with lambda:GetFunctionConfiguration.", "impact": "Small code change in the function.",
                          "confidence": "medium", "approvals": "Function owner", "rollback": "Restore the environment variable."}, "secrets", key=name)
            _identity_link(inv, k, fn.get("role_arn"), ciem_by_role, asrc)

    # ── governance-driven findings ──────────────────────────────────────────
    if approved:
        for a in list(inv.assets.values()):
            if a["asset_type"] == "model_provider" and a["provider"] and a["provider"].lower() not in approved:
                _finding(inv, "unapproved_provider", "medium", f"{a['name']} is used but not on the approved provider list", a["asset_key"],
                         {"basis": a["verification"], "sources": [o["source"] for o in a["observations"]][:10]},
                         {"current": f"{a['name']} in use", "proposed": "Review and add it to the approved list, or move the integration to an approved provider",
                          "reason": "Data sent to an unreviewed provider falls outside the agreed data-processing terms.",
                          "impact": "Depends on the integration.", "confidence": "high" if a["verification"] in ("discovered", "observed") else "medium",
                          "approvals": "AI governance owner", "rollback": "Not applicable."}, "governance")

    assets = list(inv.assets.values())
    rels = list(inv.rels.values())
    summary = {
        "assets": len(assets), "by_type": {t: sum(1 for a in assets if a["asset_type"] == t) for t in ASSET_TYPES if any(a["asset_type"] == t for a in assets)},
        "by_verification": {v: sum(1 for a in assets if a["verification"] == v) for v in VERIFICATION_ORDER if any(a["verification"] == v for a in assets)},
        "relationships": len(rels), "providers": sorted({a["name"] for a in assets if a["asset_type"] == "model_provider"}),
        "findings_by_severity": {s: sum(1 for f in inv.findings if f["severity"] == s) for s in ("critical", "high", "medium", "low")},
        "repositories_scanned": len(repos or []), "engine_version": ENGINE_VERSION, "mapping_version": MAPPING_VERSION,
        "files_not_parsed": parse_errors[:50],
    }
    return assets, rels, inv.findings, summary


def _safe(parser, f, errors, empty, repo_name=None):
    """One malformed file must not stop the whole inventory: it is skipped and listed in the summary, and its
    repository then counts as not read in full (nothing it reported before is marked gone)."""
    try:
        return parser(f["path"], f["text"])
    except Exception as e:  # noqa: BLE001 - any parser failure is reported, never fatal
        errors.append({"repo": repo_name, "path": f["path"], "error": type(e).__name__})
        return empty


def _identity_link(inv, asset_key, role_arn, ciem_by_role, source):
    if not role_arn:
        return
    ik = stable_key("aws", role_arn)
    c = ciem_by_role.get(role_arn) or {}
    inv.asset(ik, "ai_identity", role_arn.split("/")[-1], source, "discovered", role_arn, None, provider="aws_iam",
              ciem_risk_score=c.get("risk_score"), ciem_admin=c.get("admin"), ciem_reasons=c.get("risk_reasons"))
    inv.rel(asset_key, ik, "AUTHENTICATES_AS", source, "discovered")
    if c.get("admin") or (c.get("risk_score") or 0) >= 45:
        _finding(inv, "ai_workload_overprivileged", "high" if c.get("admin") == "admin" else "medium",
                 f"{inv.assets[asset_key]['name']} runs as {role_arn.split('/')[-1]}, which CIEM rates {c.get('risk_severity') or 'high'} risk",
                 asset_key, {"basis": "calculated", "source": "CIEM", "role_arn": role_arn, "ciem_admin": c.get("admin"),
                             "ciem_risk_score": c.get("risk_score"), "ciem_reasons": c.get("risk_reasons")},
                 {"current": "AI workload identity with broad permissions", "proposed": "Scope the role to what the AI workload needs (see its CIEM findings)",
                  "reason": "A prompt-injected or compromised AI workload can use every permission its identity has.",
                  "impact": "Actions outside the new scope fail.", "confidence": "medium", "approvals": "Workload owner",
                  "rollback": "Re-attach the previous policy."}, "access", key=role_arn)


def _mcp_findings(inv, key, srv, src):
    url = srv.get("url") or ""
    if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", url):
        _finding(inv, "mcp_insecure_transport", "high", f"MCP server {srv['name']} is reached over plain HTTP", key,
                 {"basis": "declared", "source": src, "config_path": srv["path"], "url": url},
                 {"current": url, "proposed": "Use HTTPS for remote MCP servers", "reason": "Tool calls, results and credentials travel unencrypted.",
                  "impact": "The server must offer TLS.", "confidence": "high", "approvals": "Owner of the client configuration", "rollback": "Restore the previous URL."},
                 "transport")
    if url and not srv.get("auth_configured"):
        _finding(inv, "mcp_no_client_auth", "medium", f"Remote MCP server {srv['name']} has no credentials configured in the client", key,
                 {"basis": "declared", "source": src, "config_path": srv["path"],
                  "note": "Only the client configuration was checked; the server may still require authentication (e.g. OAuth)."},
                 {"current": "No headers or credential environment variables for this server", "proposed": "Confirm the server requires authentication; configure it via a secret reference",
                  "reason": "An unauthenticated remote MCP server exposes its tools to anyone who can reach it.", "impact": "None for the client if the server already uses OAuth.",
                  "confidence": "low", "approvals": "Server owner", "rollback": "Not applicable."}, "access")
    if srv.get("literal_secret_names"):
        _finding(inv, "mcp_secret_in_config", "high", f"Credential written literally in MCP config for {srv['name']}", key,
                 {"basis": "declared", "source": src, "config_path": srv["path"], "variables": srv["literal_secret_names"],
                  "note": "Values are not stored by Niagaros."},
                 {"current": "Credential value in the configuration file", "proposed": "Reference an environment variable or secret store instead (e.g. \"${TOKEN}\") and rotate the credential",
                  "reason": "Configuration files are copied, committed and shared.", "impact": "Clients must provide the variable.",
                  "confidence": "medium", "approvals": "Configuration owner", "rollback": "Not applicable (rotate the credential)."}, "secrets",
                 key=",".join(srv["literal_secret_names"]))
    joined = " ".join([srv.get("command") or ""] + (srv.get("args") or []))
    if re.search(r"server-filesystem|filesystem", joined) and any(a in ("/", "~", "C:\\", "C:/", "%USERPROFILE%", "$HOME") for a in srv.get("args") or []):
        _finding(inv, "mcp_broad_filesystem", "medium", f"Filesystem MCP server {srv['name']} can reach the whole disk or home directory", key,
                 {"basis": "declared", "source": src, "config_path": srv["path"], "args": srv["args"]},
                 {"current": "Allowed directory is a root or home directory", "proposed": "Limit the allowed directories to the project folder",
                  "reason": "A prompt-injected agent could read keys, credentials and other projects.", "impact": "The agent can no longer read outside the folder.",
                  "confidence": "high", "approvals": "Configuration owner", "rollback": "Restore the previous arguments."}, "access")
