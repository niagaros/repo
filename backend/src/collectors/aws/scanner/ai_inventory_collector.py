"""
ai_inventory_collector.py — read-only discovery for the AI Inventory (issue #236).

AWS (customer's CSPMScannerRole, SecurityAudit + ReadOnlyAccess):
  Bedrock agents (+ action groups, knowledge bases, guardrail link), knowledge bases, guardrails, custom models,
  provisioned throughput, model invocation logging; CloudWatch AWS/Bedrock Invocations per model (usage = observed);
  SageMaker endpoints and notebook instances; OpenSearch Serverless VECTORSEARCH collections; Lambda functions
  (handler, role, and the NAMES of AI-related environment variables).
GitHub (customer's existing GitHub integration token): repository files, fetched as one tarball per repository.

Secret VALUES never leave this module: Lambda environment values are only tested for "is this a literal key?"
and discarded; repository files are scanned in memory and only signals with locations are returned.
Every part that fails is recorded in `coverage` and `limitations`.
"""
import gzip
import hashlib
import io
import json
import logging
import re
import tarfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from botocore.config import Config

logger = logging.getLogger(__name__)
RETRY = Config(retries={"max_attempts": 6, "mode": "adaptive"})

AI_ENV_NAME = re.compile(r"(OPENAI|ANTHROPIC|CLAUDE|GROQ|GEMINI|GOOGLE_AI|GENAI|MISTRAL|COHERE|HUGGING|HF_|OPENROUTER|TOGETHER|"
                         r"DEEPSEEK|PERPLEXITY|XAI|BEDROCK|LLM|MODEL_ID|EMBEDDING)", re.I)
AI_SECRET_NAME = re.compile(r"(OPENAI|ANTHROPIC|CLAUDE|GROQ|GEMINI|GOOGLE_AI|GENAI|MISTRAL|COHERE|HUGGING|HF|OPENROUTER|TOGETHER|"
                            r"DEEPSEEK|PERPLEXITY|XAI)[A-Z_]*(KEY|TOKEN|SECRET)", re.I)
SKIP_DIRS = ("node_modules/", "/vendor/", "/dist/", "/build/", "/.git/", "site-packages/", "/__pycache__/", "/.venv/",
             "/venv/", "psycopg2", "/.next/", "/coverage/")
MAX_REPOS, MAX_TARBALL, MAX_FILES, MAX_FILE = 40, 60 * 1024 * 1024, 4000, 400 * 1024


def _err(e):
    code = getattr(e, "response", {}).get("Error", {}).get("Code") if hasattr(e, "response") else None
    return code or type(e).__name__


def _looks_like_literal_key(value):
    """True for a literal credential; False for references (secret ARNs/names, SSM paths, ${VAR})."""
    if not isinstance(value, str) or len(value) < 16:
        return False
    if value.startswith(("arn:", "/", "${", "{{", "ssm:", "secretsmanager:")) or "/" in value:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_\-.]{16,}", value)) and bool(re.search(r"\d", value)) and bool(re.search(r"[A-Za-z]", value))


PART_SERVICE = {"bedrock_guardrails": "bedrock", "bedrock_models": "bedrock", "bedrock_invocation_logging": "bedrock",
                "bedrock_knowledge_bases": "bedrock-agent", "bedrock_agents": "bedrock-agent", "sagemaker": "sagemaker",
                "opensearch_vector_collections": "opensearchserverless", "lambda_functions": "lambda"}
_REGIONS_CACHE = {}


def _available_regions(session, service):
    """Regions where AWS offers the service, from the SDK's endpoint data; None when unknown (then every region is
    tried, and a failed call is a coverage gap)."""
    if service not in _REGIONS_CACHE:
        try:
            # the SDK has no endpoint list for bedrock-agent; it is offered where Bedrock is
            _REGIONS_CACHE[service] = set(session.get_available_regions(service)) or                 (set(session.get_available_regions("bedrock")) if service == "bedrock-agent" else set()) or None
        except Exception:  # noqa: BLE001
            _REGIONS_CACHE[service] = None
    return _REGIONS_CACHE[service]


def _unknown_operation(e):
    err = getattr(e, "response", {}).get("Error", {})
    return err.get("Code") == "UnknownOperationException" or "unknown operation" in str(err.get("Message", "")).lower()


def collect_aws(session, account, region):
    out = {"region": region, "coverage": {}, "limitations": []}

    def part(name, fn):
        service = PART_SERVICE.get(name)
        # a service that AWS does not offer in this region has nothing to inventory there: a complete read. This comes
        # from the SDK's endpoint data, never from a failed call (a network error is a failed read).
        avail = _available_regions(session, service) if service else None
        if avail and region not in avail:
            out["coverage"][name] = {"ok": True, "not_available": True}
            return
        try:
            fn()
            out["coverage"][name] = {"ok": True}
        except Exception as e:
            out["coverage"][name] = {"ok": False, "error": _err(e)}
            out["limitations"].append(f"{name} could not be read in {region} ({_err(e)}).")

    br = session.client("bedrock", region_name=region, config=RETRY)
    ag = session.client("bedrock-agent", region_name=region, config=RETRY)

    def guardrails():
        out["guardrails"] = []
        for page in br.get_paginator("list_guardrails").paginate():
            for g in page.get("guardrails", []):
                d = br.get_guardrail(guardrailIdentifier=g["id"])
                filters = {
                    "content_filters": [f.get("type") for f in (d.get("contentPolicy") or {}).get("filters", [])],
                    "denied_topics": len((d.get("topicPolicy") or {}).get("topics", [])),
                    "sensitive_information": len((d.get("sensitiveInformationPolicy") or {}).get("piiEntities", [])),
                    "word_filters": bool(d.get("wordPolicy")),
                    "contextual_grounding": bool(d.get("contextualGroundingPolicy")),
                }
                out["guardrails"].append({"arn": g["arn"], "name": g["name"], "version": g.get("version"), "status": g.get("status"), "filters": filters})
    part("bedrock_guardrails", guardrails)

    def models():
        try:
            out["custom_models"] = [{"arn": m["modelArn"], "name": m["modelName"], "base_model": m.get("baseModelArn")}
                                    for page in br.get_paginator("list_custom_models").paginate() for m in page.get("modelSummaries", [])]
        except Exception as e:  # noqa: BLE001
            # custom models are not offered in every Bedrock region: AWS answers "Unknown operation" there. That is a
            # complete answer (there are none); any other error is still a failed read.
            if not _unknown_operation(e):
                raise
            out["custom_models"] = []
        out["provisioned"] = [{"arn": p["provisionedModelArn"], "name": p["provisionedModelName"], "model_arn": p.get("modelArn"), "status": p.get("status")}
                              for page in br.get_paginator("list_provisioned_model_throughputs").paginate()
                              for p in page.get("provisionedModelSummaries", [])]
    part("bedrock_models", models)

    def logging_cfg():
        out["invocation_logging"] = br.get_model_invocation_logging_configuration().get("loggingConfig")
    part("bedrock_invocation_logging", logging_cfg)

    def kbs():
        out["knowledge_bases"] = []
        for page in ag.get_paginator("list_knowledge_bases").paginate():
            for k in page.get("knowledgeBaseSummaries", []):
                d = ag.get_knowledge_base(knowledgeBaseId=k["knowledgeBaseId"])["knowledgeBase"]
                vec = ((d.get("knowledgeBaseConfiguration") or {}).get("vectorKnowledgeBaseConfiguration") or {})
                st = d.get("storageConfiguration") or {}
                store_arn = (st.get("opensearchServerlessConfiguration") or {}).get("collectionArn") or \
                    (st.get("rdsConfiguration") or {}).get("resourceArn")
                out["knowledge_bases"].append({"arn": d["knowledgeBaseArn"], "id": d["knowledgeBaseId"], "name": d["name"],
                                               "status": d.get("status"), "storage_type": st.get("type"),
                                               "embedding_model": vec.get("embeddingModelArn"), "vector_store_arn": store_arn})
    part("bedrock_knowledge_bases", kbs)

    def agents():
        out["agents"] = []
        for page in ag.get_paginator("list_agents").paginate():
            for a in page.get("agentSummaries", []):
                d = ag.get_agent(agentId=a["agentId"])["agent"]
                instr = d.get("instruction") or ""
                groups = []
                lam = session.client("lambda", region_name=region, config=RETRY)
                for gp in ag.get_paginator("list_agent_action_groups").paginate(agentId=a["agentId"], agentVersion="DRAFT"):
                    for g in gp.get("actionGroupSummaries", []):
                        gd = ag.get_agent_action_group(agentId=a["agentId"], agentVersion="DRAFT", actionGroupId=g["actionGroupId"])["agentActionGroup"]
                        ex = gd.get("actionGroupExecutor") or {}
                        executor_role = None
                        if str(ex.get("lambda") or "").startswith("arn:aws:lambda"):
                            # the executor may be a version or alias with its own execution role: read that exact configuration
                            executor_role = lam.get_function_configuration(FunctionName=ex["lambda"]).get("Role")
                        groups.append({"id": g["actionGroupId"], "name": g["actionGroupName"], "state": gd.get("actionGroupState"),
                                       "executor_role": executor_role,
                                       "executor": ex.get("lambda") or ex.get("customControl"),
                                       "functions": [f.get("name") for f in (gd.get("functionSchema") or {}).get("functions", [])],
                                       "side_effect": "returns control to the application" if ex.get("customControl") else
                                                      "unknown (executes a Lambda; not inferred from names)"})
                kb_ids = [k["knowledgeBaseId"] for kp in ag.get_paginator("list_agent_knowledge_bases").paginate(agentId=a["agentId"], agentVersion="DRAFT")
                          for k in kp.get("agentKnowledgeBaseSummaries", [])]
                collaborators = []
                if d.get("agentCollaboration") in ("SUPERVISOR", "SUPERVISOR_ROUTER"):
                    tok = None
                    while True:
                        r = ag.list_agent_collaborators(agentId=a["agentId"], agentVersion="DRAFT", **({"nextToken": tok} if tok else {}))
                        collaborators += [{"name": c.get("collaboratorName"), "alias_arn": (c.get("agentDescriptor") or {}).get("aliasArn"),
                                           "relay_history": c.get("relayConversationHistory")} for c in r.get("agentCollaboratorSummaries", [])]
                        tok = r.get("nextToken")
                        if not tok:
                            break
                gr = d.get("guardrailConfiguration") or {}
                lam_groups = [g for g in groups if g["executor"] and str(g["executor"]).startswith("arn:aws:lambda")]
                autonomy = ("A3 — Conditional autonomy" if lam_groups else
                            "A1 — Human-initiated (returns control)" if groups else "A0 — Advisory")
                out["agents"].append({
                    "arn": d["agentArn"], "name": d["agentName"], "status": d.get("agentStatus"), "model": d.get("foundationModel"),
                    "role_arn": d.get("agentResourceRoleArn"),
                    "guardrail": ({"id": gr.get("guardrailIdentifier"), "version": gr.get("guardrailVersion"),
                                   "arn": gr.get("guardrailIdentifier") if str(gr.get("guardrailIdentifier", "")).startswith("arn:") else None}
                                  if gr.get("guardrailIdentifier") else None),
                    "memory": (d.get("memoryConfiguration") or {}).get("enabledMemoryTypes"), "idle_ttl": d.get("idleSessionTTLInSeconds"),
                    "instruction_sha256": hashlib.sha256(instr.encode()).hexdigest() if instr else None, "instruction_length": len(instr),
                    "action_groups": groups, "knowledge_bases": kb_ids,
                    "collaboration": d.get("agentCollaboration"), "collaborators": collaborators,
                    "autonomy": {"level": autonomy, "basis": "inferred from action-group executors"}})
    part("bedrock_agents", agents)

    def usage():
        cw = session.client("cloudwatch", region_name=region, config=RETRY)
        model_ids = sorted({d["Value"] for page in cw.get_paginator("list_metrics").paginate(Namespace="AWS/Bedrock", MetricName="Invocations")
                            for m in page["Metrics"] for d in m["Dimensions"] if d["Name"] == "ModelId"})
        out["bedrock_usage"] = {}
        end = datetime.now(timezone.utc)
        for i in range(0, len(model_ids), 400):
            chunk = model_ids[i:i + 400]
            r = cw.get_metric_data(StartTime=end - timedelta(days=14), EndTime=end, MetricDataQueries=[
                {"Id": f"m{n}", "MetricStat": {"Metric": {"Namespace": "AWS/Bedrock", "MetricName": "Invocations",
                                                          "Dimensions": [{"Name": "ModelId", "Value": mid}]},
                                               "Period": 1209600, "Stat": "Sum"}} for n, mid in enumerate(chunk)])
            for res in r["MetricDataResults"]:
                total = sum(res.get("Values") or [])
                if total > 0:
                    out["bedrock_usage"][chunk[int(res["Id"][1:])]] = int(total)
    part("bedrock_usage_metrics", usage)

    def sagemaker():
        sm = session.client("sagemaker", region_name=region, config=RETRY)
        out["sagemaker_endpoints"], out["sagemaker_notebooks"] = [], []
        for page in sm.get_paginator("list_endpoints").paginate():
            for e in page["Endpoints"]:
                d = sm.describe_endpoint(EndpointName=e["EndpointName"])
                cfg = sm.describe_endpoint_config(EndpointConfigName=d["EndpointConfigName"])
                out["sagemaker_endpoints"].append({"arn": d["EndpointArn"], "name": d["EndpointName"], "status": d.get("EndpointStatus"),
                                                   "models": [v.get("ModelName") for v in cfg.get("ProductionVariants", [])],
                                                   "instance_types": [v.get("InstanceType") for v in cfg.get("ProductionVariants", [])],
                                                   "data_capture": bool((d.get("DataCaptureConfig") or {}).get("EnableCapture"))})
        for page in sm.get_paginator("list_notebook_instances").paginate():
            for nb in page["NotebookInstances"]:
                d = sm.describe_notebook_instance(NotebookInstanceName=nb["NotebookInstanceName"])
                out["sagemaker_notebooks"].append({"arn": d["NotebookInstanceArn"], "name": d["NotebookInstanceName"],
                                                   "status": d.get("NotebookInstanceStatus"), "direct_internet": d.get("DirectInternetAccess"),
                                                   "root_access": d.get("RootAccess"), "role_arn": d.get("RoleArn")})
    part("sagemaker", sagemaker)

    def vectors():
        aoss = session.client("opensearchserverless", region_name=region, config=RETRY)
        ids, token = [], None
        while True:
            r = aoss.list_collections(**({"nextToken": token} if token else {}))
            ids += [c["id"] for c in r.get("collectionSummaries", [])]
            token = r.get("nextToken")
            if not token:
                break
        out["vector_collections"] = []
        for i in range(0, len(ids), 100):
            for c in aoss.batch_get_collection(ids=ids[i:i + 100]).get("collectionDetails", []):
                if c.get("type") == "VECTORSEARCH":
                    out["vector_collections"].append({"arn": c["arn"], "name": c["name"], "status": c.get("status")})
    part("opensearch_vector_collections", vectors)

    def functions():
        lam = session.client("lambda", region_name=region, config=RETRY)
        out["functions"] = []
        for page in lam.get_paginator("list_functions").paginate():
            for f in page["Functions"]:
                env_cfg = f.get("Environment") or {}
                if env_cfg.get("Error"):
                    # e.g. KMS access denied: the variables are unknown, not absent
                    out.setdefault("lambda_env_unreadable", []).append(f["FunctionArn"])
                env = env_cfg.get("Variables") or {}
                ai_names = sorted(k for k in env if AI_ENV_NAME.search(k))
                plaintext = sorted(k for k in env if AI_SECRET_NAME.search(k) and _looks_like_literal_key(env[k]))
                env = None  # values are not kept
                out["functions"].append({"arn": f["FunctionArn"], "name": f["FunctionName"], "handler": f.get("Handler"),
                                         "runtime": f.get("Runtime"), "role_arn": f.get("Role"), "last_modified": f.get("LastModified"),
                                         "ai_env_names": ai_names, "ai_env_plaintext_secrets": plaintext})
    part("lambda_functions", functions)
    if out.get("lambda_env_unreadable"):
        out["limitations"].append(f"The environment variables of {len(out['lambda_env_unreadable'])} Lambda function(s) could not be "
                                  "read (encrypted with a key the scanner role may not use); AI keys in them are not checked.")
    return out


def collect_aws_regions(session, account, home_region):
    """Every region enabled for the account, in parallel. Returns one collector result per region plus the list of
    regions that could not be listed (then only the home region is read and that is said)."""
    from concurrent.futures import ThreadPoolExecutor
    limitations = []
    try:
        regions = sorted(r["RegionName"] for r in session.client("ec2", region_name=home_region, config=RETRY)
                         .describe_regions(AllRegions=False)["Regions"])
    except Exception as e:  # noqa: BLE001
        regions = [home_region]
        limitations.append(f"The enabled regions could not be listed ({_err(e)}); only {home_region} was inventoried.")
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda r: collect_aws(session, account, r), regions))
    return results, regions, limitations


# ── GitHub ──────────────────────────────────────────────────────────────────

def _gh(url, token, raw=False, max_bytes=None, attempts=3):
    """GitHub GET with at most `attempts` tries on rate limiting (403/429 with retry headers) and 5xx errors."""
    for attempt in range(attempts):
        try:
            return _gh_once(url, token, raw, max_bytes)
        except urllib.error.HTTPError as e:
            retryable = e.code >= 500 or e.code == 429 or (e.code == 403 and e.headers.get("Retry-After"))
            if not retryable or attempt == attempts - 1:
                raise
            wait = min(int(e.headers.get("Retry-After") or 2 ** attempt), 20)
            time.sleep(wait)


def _gh_once(url, token, raw, max_bytes):
    req = urllib.request.Request(url, headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json",
                                               "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "niagaros-ai-inventory"})
    with urllib.request.urlopen(req, timeout=60) as r:
        if raw:
            data = r.read((max_bytes or MAX_TARBALL) + 1)
            if max_bytes and len(data) > max_bytes:
                raise ValueError("tarball larger than the limit")
            return data
        return json.loads(r.read().decode())


def _text_member(name):
    from collectors.aws.scanner.ai_inventory_engine import MCP_CONFIG_NAMES, TEXT_EXT
    low = name.lower()
    if any(d in "/" + low for d in SKIP_DIRS):
        return False
    base = low.rsplit("/", 1)[-1]
    return base in MCP_CONFIG_NAMES or low.endswith(TEXT_EXT) or base.startswith("requirements")


MAX_TREE_FILES = 700


def _priority(path):
    from collectors.aws.scanner.ai_inventory_engine import MCP_CONFIG_NAMES
    base = path.lower().rsplit("/", 1)[-1]
    if base in MCP_CONFIG_NAMES or base in ("package.json", "pyproject.toml") or base.startswith("requirements"):
        return 0
    if base.endswith((".py", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".cs")):
        return 1
    if base.endswith((".yaml", ".yml", ".toml", ".tf", ".json", ".cfg", ".ini")):
        return 2
    return 3


def _relevant_large(path):
    """Large files that could hold AI usage or a secret. Lock files and minified bundles are generated and
    skipped on purpose; anything else that is too large to read makes the repository 'not read in full'."""
    base = path.lower().rsplit("/", 1)[-1]
    if base in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock", "composer.lock", "cargo.lock"):
        return False
    if base.endswith((".min.js", ".min.css", ".map", ".bundle.js")):
        return False
    return _priority(path) <= 2


def _collect_via_tree(full_name, token, commit):
    """For repositories too large for one tarball: list the tree, fetch only candidate files (configs and code
    first), up to MAX_TREE_FILES. Returns (files, scanned, candidates)."""
    tree = _gh(f"https://api.github.com/repos/{full_name}/git/trees/{commit}?recursive=1", token)
    blobs = [t for t in tree.get("tree", []) if t.get("type") == "blob" and _text_member(t["path"])]
    cands = [t for t in blobs if (t.get("size") or 0) <= MAX_FILE]
    too_big = [t["path"] for t in blobs if (t.get("size") or 0) > MAX_FILE and _relevant_large(t["path"])]
    cands.sort(key=lambda t: (_priority(t["path"]), t.get("size") or 0))
    def fetch(t):
        req = urllib.request.Request(f"https://api.github.com/repos/{full_name}/contents/{urllib.request.quote(t['path'])}?ref={commit}",
                                     headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.raw",
                                              "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "niagaros-ai-inventory"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read(MAX_FILE)
        except (urllib.error.URLError, TimeoutError, OSError):
            return "failed"
        try:
            return {"path": t["path"], "text": data.decode("utf-8")}
        except UnicodeDecodeError:
            return None  # binary content: nothing to scan, not a failure

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(fetch, cands[:MAX_TREE_FILES]))
    files = [f for f in results if isinstance(f, dict)]
    failed = sum(1 for f in results if f == "failed")
    # a file that could not be downloaded was not read: the repository then counts as not read in full
    return (files, min(len(cands), MAX_TREE_FILES) - failed, len(cands) + len(too_big),
            bool(tree.get("truncated")) or failed > 0 or bool(too_big))


def collect_repo(full_name, token, default_branch=None):
    meta = _gh(f"https://api.github.com/repos/{full_name}", token)
    branch = default_branch or meta.get("default_branch", "main")
    commit = _gh(f"https://api.github.com/repos/{full_name}/commits/{branch}", token).get("sha")
    if (meta.get("size") or 0) * 1024 > MAX_TARBALL:
        files, scanned, cands, tree_trunc = _collect_via_tree(full_name, token, commit)
        return {"full_name": full_name, "url": meta.get("html_url"), "default_branch": branch, "commit": commit,
                "files": files, "truncated": scanned < cands or tree_trunc, "candidates": cands, "scanned": scanned,
                "method": "tree", "private": meta.get("private")}
    data = _gh(f"https://api.github.com/repos/{full_name}/tarball/{commit}", token, raw=True, max_bytes=MAX_TARBALL)
    files, truncated = [], False
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar:
            if not m.isfile():
                continue
            path = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if not _text_member(path):
                continue
            if m.size > MAX_FILE:
                # an oversized code or configuration file was not read: the repository is then not read in full
                truncated = truncated or _relevant_large(path)
                continue
            if len(files) >= MAX_FILES:
                truncated = True
                break
            fh = tar.extractfile(m)
            if fh is None:
                continue
            try:
                files.append({"path": path, "text": fh.read().decode("utf-8")})
            except UnicodeDecodeError:
                continue
    return {"full_name": full_name, "url": meta.get("html_url"), "default_branch": branch, "commit": commit,
            "files": files, "truncated": truncated, "method": "tarball", "private": meta.get("private")}


def _dependabot(full_name, token):
    alerts, page = [], 1
    try:
        while page <= 5:
            batch = _gh(f"https://api.github.com/repos/{full_name}/dependabot/alerts?state=open&per_page=100&page={page}", token)
            if not batch:
                break
            for a in batch:
                dep = (a.get("dependency") or {}).get("package") or {}
                adv = a.get("security_advisory") or {}
                vuln = a.get("security_vulnerability") or {}
                alerts.append({"package": (dep.get("name") or "").lower(), "ecosystem": dep.get("ecosystem"),
                               "manifest": (a.get("dependency") or {}).get("manifest_path"), "ghsa": adv.get("ghsa_id"),
                               "cve": adv.get("cve_id"), "summary": adv.get("summary"), "severity": (vuln.get("severity") or adv.get("severity") or "").lower(),
                               "fixed_in": (vuln.get("first_patched_version") or {}).get("identifier"), "url": a.get("html_url")})
            if len(batch) < 100:
                break
            page += 1
        else:
            return {"status": "more than 500 open alerts (truncated)", "alerts": alerts}
        return {"status": "ok", "alerts": alerts}
    except urllib.error.HTTPError as e:
        return {"status": {403: "no permission to read alerts", 404: "Dependabot alerts disabled"}.get(e.code, f"HTTP {e.code}"), "alerts": []}
    except Exception as e:  # noqa: BLE001
        return {"status": _err(e), "alerts": []}


def collect_github(org, token, include=None):
    """Repositories of the connected organisation (most recently pushed first, up to MAX_REPOS)."""
    out = {"org": org, "repos": [], "coverage": {}, "limitations": []}
    enumeration_complete = True
    if include:
        # selected repositories are looked up directly, so a long organisation listing can never hide one
        names = []
        for item in include:
            full = item if "/" in item else f"{org}/{item}"
            try:
                meta = _gh(f"https://api.github.com/repos/{full}", token)
                if not meta.get("archived"):
                    names.append(meta["full_name"])
            except Exception as e:
                out["coverage"][full] = {"ok": False, "error": _err(e)}
                out["limitations"].append(f"Selected repository {full} could not be found or read ({_err(e)}).")
    else:
        repos, page = [], 1
        while True:
            batch = _gh(f"https://api.github.com/orgs/{org}/repos?per_page=100&page={page}&sort=pushed", token)
            if not batch:
                break
            repos += batch
            page += 1
            if len(repos) >= 300:
                enumeration_complete = len(batch) < 100
                break
        names = [r["full_name"] for r in sorted(repos, key=lambda r: r.get("pushed_at") or "", reverse=True) if not r.get("archived")]
        if not enumeration_complete:
            out["limitations"].append("The organisation has more than 300 repositories; only the 300 most recently pushed were listed.")
    if len(names) > MAX_REPOS:
        out["limitations"].append(f"{len(names)} repositories found; the {MAX_REPOS} most recently pushed were scanned.")
    for full_name in names[:MAX_REPOS]:
        try:
            r = collect_repo(full_name, token)
            r["dependabot"] = _dependabot(full_name, token)
            if r["dependabot"]["status"] != "ok":
                out["limitations"].append(f"{full_name}: Dependabot alerts not available ({r['dependabot']['status']}); "
                                          "known vulnerabilities in AI packages are not checked.")
            out["repos"].append(r)
            out["coverage"][full_name] = {"ok": True, "files": len(r["files"]), "truncated": r["truncated"], "commit": r["commit"]}
            if r["truncated"]:
                out["limitations"].append(f"{full_name}: {r.get('scanned', MAX_FILES)} of {r.get('candidates', 'more')} candidate files were scanned"
                                          " (configuration and code files first).")
        except Exception as e:
            out["coverage"][full_name] = {"ok": False, "error": _err(e)}
            out["limitations"].append(f"{full_name} could not be scanned ({_err(e)}).")
    out["limitations"].append("Repository discovery reads the default branch; other branches and runtime behaviour are not covered.")
    # every repository in scope was read in full: only then may "not seen any more" be concluded for org-wide assets
    out["complete"] = (enumeration_complete and len(names) <= MAX_REPOS and bool(out["coverage"])
                       and all(v.get("ok") and not v.get("truncated") for v in out["coverage"].values()))
    return out
