"""
security_agents_engine.py — Niagaros Security Agents: Red (offensive analysis), Blue (detection), Green
(resolution) (issue #239). Pure functions: no AWS, GitHub or database calls.

The agents are deterministic analysers over data Niagaros already collects with read-only access: CIEM
entitlements, scanner findings, the AI Inventory and CloudTrail management events. No language model decides
anything here; the registry says so ("model: none — deterministic rules").

What the agents deliberately do NOT do, and say so:
  - Red never attacks. It is fixed to Observe & Assess: it derives potential attack paths and exposures from
    configuration. Nothing is called "exploitable" or "validated"; active techniques are refused by the policy
    engine because Niagaros has no authorised way to run them.
  - Blue reads CloudTrail management events in one region. Missing or unreadable telemetry is reported as a
    coverage gap, never as "no threat". Containment is prepared and approved here but executed by the customer:
    Niagaros has no write access to customer accounts.
  - Green plans, creates tickets and requests re-scans. A work item is only Resolved when the source that
    reported it (a fresh scan) no longer shows the problem after the remediation was recorded.
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone

ENGINE_VERSION = "security-agents-1.0"
POLICY_VERSION = "security-agents-policy-2026.10"

# ── autonomy (issue §7) ─────────────────────────────────────────────────────
LEVELS = {
    "L0": "Observe — read approved inventory and telemetry",
    "L1": "Analyze — correlate evidence, create findings and recommendations",
    "L2": "Prepare — create tickets, plans or proposals without applying them",
    "L3": "Approved execution — a specific action after human approval",
    "L4": "Policy-bounded execution — predefined low-risk actions within policy",
    "L5": "Emergency execution — preauthorised emergency actions only",
}
LEVEL_ORDER = {k: i for i, k in enumerate(LEVELS)}
ENVIRONMENTS = ("production", "staging", "development", "test")

# Every action an agent can request. `level` is the autonomy it needs; `executable` is False when Niagaros has no
# authorised way to perform it (the action can be prepared and approved, the customer executes it).
ACTIONS = {
    "read_inventory": {"level": "L0", "label": "Read inventory, findings and entitlements", "executable": True, "risk": "none"},
    "read_telemetry": {"level": "L0", "label": "Read CloudTrail management events", "executable": True, "risk": "none"},
    "analyze": {"level": "L1", "label": "Correlate evidence and derive findings", "executable": True, "risk": "none"},
    "publish_work_item": {"level": "L1", "label": "Publish a work item to the shared queue", "executable": True, "risk": "none"},
    "notify": {"level": "L1", "label": "Notify responders", "executable": True, "risk": "low"},
    "propose_remediation": {"level": "L2", "label": "Prepare a remediation plan", "executable": True, "risk": "none"},
    "create_ticket": {"level": "L2", "label": "Create a ticket in Jira or Monday", "executable": True, "risk": "low"},
    "request_rescan": {"level": "L4", "label": "Start a read-only re-scan to verify a fix", "executable": True, "risk": "low"},
    "verify": {"level": "L1", "label": "Compare the latest scan with the remediation", "executable": True, "risk": "none"},
    "containment": {"level": "L3", "label": "Contain a threat (disable key, detach policy, isolate)", "executable": False, "risk": "high"},
    "apply_change": {"level": "L3", "label": "Apply a configuration or code change", "executable": False, "risk": "high"},
}
# Offensive techniques that are never run: Niagaros has no test environment or written authorisation flow for them.
PROHIBITED_TECHNIQUES = {
    "active_exploitation": "Running exploits against customer systems",
    "credential_attack": "Password spraying, brute force or credential stuffing",
    "destructive_test": "Tests that change, delete or overload resources",
    "persistence_simulation": "Creating backdoors or persistence",
    "network_scan": "Port or vulnerability scanning of customer networks",
    "prompt_injection_live": "Prompt-injection tests against production AI systems",
    "data_extraction": "Reading customer data to prove access",
}

# ── built-in agents (issue §2.2, §3.2, §4.2 — the subset with a real data source) ───────────────
AGENTS = {
    "red-identity-attack-path": {
        "category": "red", "name": "Identity Attack-Path Agent",
        "specialization": "Potential privilege escalation, administrator access and external trust",
        "sources": ["CIEM identities and findings"], "actions": ["read_inventory", "analyze", "publish_work_item", "notify"],
        "mode": "Observe & Assess (analysis only)"},
    "red-vulnerability-assessment": {
        "category": "red", "name": "Vulnerability Assessment Agent",
        "specialization": "Critical and high misconfigurations from the cloud scanners, correlated per resource",
        "sources": ["Scanner findings (CIS AWS, AWS FSBP)"], "actions": ["read_inventory", "analyze", "publish_work_item", "notify"],
        "mode": "Observe & Assess (analysis only)"},
    "red-ai-security": {
        "category": "red", "name": "AI Security Testing Agent",
        "specialization": "AI agents, MCP servers, tool boundaries, leaked AI keys and over-privileged AI workloads",
        "sources": ["AI Inventory findings and relationships"], "actions": ["read_inventory", "analyze", "publish_work_item", "notify"],
        "mode": "Observe & Assess (analysis only; no prompt-injection tests against live systems)"},
    "blue-identity-defense": {
        "category": "blue", "name": "Identity Defense Agent",
        "specialization": "Root use, failed console logins, new access keys, MFA removal, admin policy grants",
        "sources": ["CloudTrail management events"], "actions": ["read_telemetry", "analyze", "publish_work_item", "notify", "containment"],
        "mode": "Observe and recommend; containment needs approval and is executed by you"},
    "blue-cloud-threat": {
        "category": "blue", "name": "Cloud Threat Agent",
        "specialization": "Logging tampering, public exposure changes, network opening, detector removal",
        "sources": ["CloudTrail management events"], "actions": ["read_telemetry", "analyze", "publish_work_item", "notify", "containment"],
        "mode": "Observe and recommend; containment needs approval and is executed by you"},
    "blue-ai-threat-defense": {
        "category": "blue", "name": "AI Threat Defense Agent",
        "specialization": "Guardrail removal, invocation-logging changes and agent changes in Amazon Bedrock",
        "sources": ["CloudTrail management events (bedrock)"], "actions": ["read_telemetry", "analyze", "publish_work_item", "notify"],
        "mode": "Observe and recommend"},
    "red-attack-surface": {
        "category": "red", "name": "Attack Surface Agent",
        "specialization": "What is reachable from the internet (open security groups, public instances and databases, unauthenticated "
                          "function URLs) and what the identity behind it can do",
        "sources": ["EC2, security groups, RDS and Lambda function URLs in every enabled region (read-only)", "CIEM"],
        "actions": ["read_inventory", "analyze", "publish_work_item", "notify"],
        "mode": "Observe & Assess (configuration only; nothing is scanned or connected to)"},
    "blue-aws-detections": {
        "category": "blue", "name": "AWS Detection Integration Agent",
        "specialization": "Active threat findings from Amazon GuardDuty and AWS Security Hub, in every enabled region",
        "sources": ["Amazon GuardDuty", "AWS Security Hub"],
        "actions": ["read_telemetry", "analyze", "publish_work_item", "notify", "containment"],
        "mode": "Observe and recommend; reports where these services are switched off"},
    "blue-incident-triage": {
        "category": "blue", "name": "Incident Triage Agent",
        "specialization": "Groups detections into incidents and correlates them with known weaknesses",
        "sources": ["Blue detections", "Red work items"], "actions": ["read_inventory", "analyze", "publish_work_item", "notify"],
        "mode": "Analysis only"},
    "green-remediation-planner": {
        "category": "green", "name": "Remediation Planning Agent",
        "specialization": "Remediation plan per work item: current state, change, impact, approvals, rollback",
        "sources": ["Work items", "Source recommendations"], "actions": ["read_inventory", "propose_remediation", "create_ticket"],
        "mode": "Recommend and prepare (tickets); changes are applied by your team"},
    "green-verification": {
        "category": "green", "name": "Verification Agent",
        "specialization": "Independently checks the latest scan after a remediation; closes or re-opens the work item",
        "sources": ["Latest CIEM, AI Inventory and scanner results"], "actions": ["read_inventory", "verify", "request_rescan", "notify"],
        "mode": "Verify by re-collection"},
}
CATEGORY_LABEL = {"red": "Red — Offensive", "blue": "Blue — Defensive", "green": "Green — Resolution"}
AGENT_LIFECYCLE = ("registered", "configured", "tested", "approved", "active", "paused", "restricted", "deprecated", "retired")

# ── work-item states (issue §11) ────────────────────────────────────────────
STATES = ("new", "triaged", "assigned", "in_progress", "awaiting_approval", "remediated", "verification", "resolved",
          "blocked", "accepted_risk", "false_positive", "reopened")
OPEN_STATES = ("new", "triaged", "assigned", "in_progress", "awaiting_approval", "remediated", "verification", "blocked", "reopened")
HUMAN_TRANSITIONS = {
    "new": {"triaged", "assigned", "false_positive", "accepted_risk", "blocked"},
    "reopened": {"triaged", "assigned", "in_progress", "false_positive", "accepted_risk", "blocked"},
    "triaged": {"assigned", "in_progress", "false_positive", "accepted_risk", "blocked"},
    "assigned": {"in_progress", "blocked", "accepted_risk", "false_positive"},
    "in_progress": {"remediated", "blocked", "accepted_risk", "awaiting_approval"},
    "blocked": {"triaged", "assigned", "in_progress"},
    "awaiting_approval": {"in_progress"},
    "remediated": {"in_progress"},
    "verification": {"in_progress"},
    "accepted_risk": {"triaged"},
    "false_positive": {"triaged"},
}


def can_transition(current, new, by):
    """by: 'human' or 'verification'. Only the Verification Agent moves an item to resolved (the source re-checked it
    and no longer reports it) or reopened (it came back, or a remediation failed verification)."""
    if new in ("resolved", "reopened", "verification"):
        if by != "verification":
            return False
        if new == "resolved":
            return current in OPEN_STATES
        if new == "reopened":
            return current in ("resolved", "remediated", "verification", "accepted_risk")
        return current == "remediated"
    if by != "human":
        return False
    return new in HUMAN_TRANSITIONS.get(current, set())


def fingerprint(*parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:40]


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


# ── policy & authorisation (issue §8) ───────────────────────────────────────

def default_policy(agent_id, action, environment):
    """Autonomy granted when an organisation has not set one. Conservative: L3 actions always need approval and
    rescans in production need approval."""
    need = ACTIONS[action]["level"]
    if need == "L4" and environment == "production":
        return {"level": "L3", "requires_approval": True}
    if need == "L3":
        return {"level": "L3", "requires_approval": True}
    return {"level": need, "requires_approval": False}


def authorize(agent_id, agent_state, action, account_id, environment, authorizations, policies, now=None, technique=None):
    """Execution-time decision. authorizations: rows {agent_id, scope_type ('account'), scope_reference (account id),
    environments, allowed_actions, prohibited_actions, valid_from, valid_until, revoked_at}; policies: {(agent, action,
    env): {level, requires_approval}}. Returns {decision: allow|approval_required|block, reason, level}."""
    now = now or datetime.now(timezone.utc)
    if technique:
        return {"decision": "block", "reason": f"Technique '{technique}' is not supported: Niagaros only performs passive analysis "
                f"({PROHIBITED_TECHNIQUES.get(technique, 'not an allowed technique')}).", "level": None}
    agent = AGENTS.get(agent_id)
    if not agent:
        return {"decision": "block", "reason": "Unknown agent.", "level": None}
    if action not in ACTIONS:
        return {"decision": "block", "reason": f"Unknown action '{action}'.", "level": None}
    if action not in agent["actions"]:
        return {"decision": "block", "reason": f"{agent['name']} is not allowed to '{ACTIONS[action]['label']}'.", "level": None}
    if agent_state != "active":
        return {"decision": "block", "reason": f"The agent is {agent_state}, not active.", "level": None}
    valid = [a for a in authorizations if a["agent_id"] == agent_id and a.get("revoked_at") is None
             and a["scope_type"] == "account" and str(a["scope_reference"]) == str(account_id)
             and environment in (a.get("environments") or [])]
    if not valid:
        return {"decision": "block", "reason": "No authorisation covers this account and environment.", "level": None}
    in_time = [a for a in valid if _as_dt(a["valid_from"]) <= now < _as_dt(a["valid_until"])]
    if not in_time:
        return {"decision": "block", "reason": "The authorisation for this account has expired or has not started yet.", "level": None}
    # several grants can be valid at once: a prohibition in any of them wins; otherwise one grant allowing it is enough
    if any(action in (a.get("prohibited_actions") or []) for a in in_time):
        return {"decision": "block", "reason": f"'{ACTIONS[action]['label']}' is prohibited by an authorisation.", "level": None}
    if not any(not a.get("allowed_actions") or action in a["allowed_actions"] for a in in_time):
        return {"decision": "block", "reason": f"'{ACTIONS[action]['label']}' is not in the authorised actions.", "level": None}
    pol = policies.get((agent_id, action, environment)) or default_policy(agent_id, action, environment)
    need = ACTIONS[action]["level"]
    if LEVEL_ORDER[pol["level"]] < LEVEL_ORDER[need] and not pol.get("requires_approval"):
        return {"decision": "block", "reason": f"The policy allows up to {pol['level']}; this action needs {need}.", "level": pol["level"]}
    if pol.get("requires_approval") or LEVEL_ORDER[pol["level"]] < LEVEL_ORDER[need] or need == "L3":
        return {"decision": "approval_required", "reason": "Needs approval by an authorised person.", "level": pol["level"]}
    return {"decision": "allow", "reason": "Within authorisation and policy.", "level": pol["level"]}


def _as_dt(v):
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v).replace("Z", "+00:00"))


# ── priority (issue §11, "exploitability, exposure, criticality, confidence") ───────────────────
SEV_POINTS = {"critical": 40, "high": 30, "medium": 18, "low": 8, "info": 2}
CONF_FACTOR = {"high": 1.0, "medium": 0.8, "low": 0.6}


def priority(severity, confidence, exposure=None, criticality=None, active_threat=False, path_to_admin=False):
    """0-100 with its reasons; a prioritisation aid, never shown without the reasons."""
    reasons = [(SEV_POINTS.get(severity, 8), f"severity {severity}")]
    if exposure == "external":
        reasons.append((15, "reachable from outside the account"))
    if criticality in ("high", "critical"):
        reasons.append((10, f"asset criticality {criticality}"))
    if path_to_admin:
        reasons.append((15, "leads to administrator access"))
    if active_threat:
        reasons.append((20, "related suspicious activity detected"))
    raw = sum(p for p, _ in reasons) * CONF_FACTOR.get(confidence, 0.8)
    score = int(min(100, round(raw)))
    return score, [{"points": p, "reason": r} for p, r in reasons] + [{"factor": CONF_FACTOR.get(confidence, 0.8), "reason": f"confidence {confidence}"}]


# ── Red analysers ───────────────────────────────────────────────────────────

def _item(agent_id, source_type, source_id, title, severity, confidence, basis, evidence, assets, recommendation,
          exposure=None, path_to_admin=False, attack_path=None):
    score, why = priority(severity, confidence, exposure, None, False, path_to_admin)
    return {
        "fingerprint": fingerprint(source_type, source_id), "agent_id": agent_id, "category": AGENTS[agent_id]["category"],
        "source_type": source_type, "source_id": str(source_id), "title": title, "severity": severity,
        "confidence": confidence, "basis": basis, "evidence": evidence, "assets": assets,
        "recommendation": recommendation or {}, "priority": score, "priority_reasons": why,
        "exposure": exposure, "path_to_admin": path_to_admin, "attack_path": attack_path,
        "validation": {"status": "not_validated",
                       "note": "Derived from configuration. Active validation (exploitation) is not permitted, so this is a "
                               "potential weakness, not a confirmed exploit."},
    }


def red_identity(identities, ciem_findings):
    """identities: latest CIEM identities (dicts with arn, name, kind, admin, risk_score, escalation, trust);
    ciem_findings: open CIEM findings (id, rule, category, severity, title, identity_arn, details, recommendation)."""
    out = []
    by_arn = {i["arn"]: i for i in identities}
    for f in ciem_findings:
        if f.get("status") not in (None, "open", "in_progress"):
            continue
        if f.get("severity") not in ("critical", "high", "medium"):
            continue  # low items (ownership, hygiene) stay in CIEM; they are not attack paths
        ident = by_arn.get(f.get("identity_arn")) or {}
        cat = f.get("category") or ""
        path = None
        if cat == "privilege_escalation":
            p = (f.get("details") or {}).get("path") or {}
            gained = p.get("gains") or []
            path = {"from": ident.get("name") or f.get("identity_arn"),
                    "steps": [s for s in [p.get("how")] + [f"needs {x}" for x in p.get("required_permissions") or []] if s],
                    "targets": (p.get("targets") or [])[:5],
                    "to": "administrator access" if "full administrator access" in gained else ", ".join(gained[:3]) or "more permissions",
                    "prerequisites": p.get("prerequisites") or []}
        exposure = "external" if cat in ("external_access", "external_resource_access") else "internal"
        out.append(_item("red-identity-attack-path", "ciem_finding", f["id"], f["title"], f["severity"],
                         "high" if cat in ("excessive_permissions", "external_access") else "medium",
                         "calculated from IAM policies (CIEM)",
                         {"rule": f.get("rule"), "category": cat, "identity": f.get("identity_arn"),
                          "identity_risk_score": ident.get("risk_score"), "details": f.get("details")},
                         [{"type": "aws_identity", "ref": f.get("identity_arn"), "name": ident.get("name")}],
                         f.get("recommendation"), exposure=exposure,
                         path_to_admin=cat == "privilege_escalation" and bool(path and path["to"] == "administrator access"),
                         attack_path=path))
    return out


SCANNER_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
EXTERNAL_HINTS = ("public", "0.0.0.0/0", "internet", "anonymous", "world")


def red_vulnerabilities(findings, min_severity="high"):
    """findings: open native scanner findings (id, check_id, title, severity, resource_type, resource_arn, remediation,
    details, framework). Only native frameworks (not mapped duplicates) must be passed in."""
    keep = ("critical", "high") if min_severity == "high" else ("critical", "high", "medium")
    out = []
    for f in findings:
        sev = SCANNER_SEVERITY.get(str(f.get("severity")).upper(), "medium")
        if sev not in keep:
            continue
        text = f"{f.get('title', '')} {json.dumps(f.get('details') or {})}".lower()
        out.append(_item("red-vulnerability-assessment", "scanner_finding", f["id"], f"{f['title']} ({f.get('resource_arn')})", sev, "high",
                         f"configuration check {f.get('check_id')} ({f.get('framework')})",
                         {"check_id": f.get("check_id"), "framework": f.get("framework"), "details": f.get("details")},
                         [{"type": f.get("resource_type"), "ref": f.get("resource_arn")}],
                         {"current": f.get("title"), "proposed": f.get("remediation") or "See the check's remediation guidance.",
                          "reason": "Fails a configuration control of the scanner baseline.",
                          "rollback": "Revert the configuration change."},
                         exposure="external" if any(h in text for h in EXTERNAL_HINTS) else "internal"))
    return out


AI_EXPOSED_RULES = {"mcp_insecure_transport", "mcp_no_client_auth", "secret_in_code"}


def red_ai(ai_findings, relationships=None):
    """ai_findings: open AI Inventory findings (id, rule, severity, title, details, recommendation, asset_key, asset_name);
    relationships: AUTHENTICATES_AS links let an over-privileged AI workload become an attack path to its role."""
    out = []
    for f in ai_findings:
        if f.get("status") not in (None, "open", "in_progress"):
            continue
        path = None
        if f["rule"] == "ai_workload_overprivileged":
            path = {"from": f"input to {f.get('asset_name')} (e.g. a prompt or tool result)", "steps": ["prompt injection or compromise of the AI workload",
                    "uses the permissions of its role"], "to": (f.get("details") or {}).get("role_arn")}
        out.append(_item("red-ai-security", "ai_inventory_finding", f["id"], f["title"], f["severity"],
                         "medium" if f["rule"] in ("mcp_no_client_auth", "ai_workload_overprivileged") else "high",
                         (f.get("details") or {}).get("basis") or "AI Inventory",
                         {"rule": f["rule"], "details": f.get("details")},
                         [{"type": "ai_asset", "ref": f.get("asset_key"), "name": f.get("asset_name")}],
                         f.get("recommendation"),
                         exposure="external" if f["rule"] in AI_EXPOSED_RULES else "internal",
                         path_to_admin=f["rule"] == "ai_workload_overprivileged" and (f.get("details") or {}).get("ciem_admin") == "admin",
                         attack_path=path))
    return out


# ── Blue detection rules over CloudTrail (issue §3) ─────────────────────────
# Each rule: event names it needs from LookupEvents, a predicate on the parsed event, severity, MITRE ATT&CK id.

def _ct(e):
    raw = e.get("CloudTrailEvent")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return {}
    return raw or {}


def _params(e):
    return _ct(e).get("requestParameters") or {}


def _principal(e):
    ui = _ct(e).get("userIdentity") or {}
    return ui.get("arn") or ui.get("principalId") or e.get("Username") or "unknown"


def _is_root(e):
    return (_ct(e).get("userIdentity") or {}).get("type") == "Root"


def _failed(e):
    ct = _ct(e)
    return bool(ct.get("errorCode")) or (ct.get("responseElements") or {}).get("ConsoleLogin") == "Failure"


def _admin_policy(e):
    p = _params(e)
    if str(p.get("policyArn", "")).endswith(":policy/AdministratorAccess"):
        return True
    doc = p.get("policyDocument")
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return False
    statements = (doc or {}).get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    as_list = lambda v: v if isinstance(v, list) else [v]
    for st in statements:
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or "NotAction" in st or "NotResource" in st:
            continue
        if any(a in ("*", "*:*") for a in as_list(st.get("Action"))) and "*" in as_list(st.get("Resource")):
            return True
    return False


def _public_bucket(e):
    p = _params(e)
    if e.get("EventName") == "PutBucketAcl":
        return "acs.amazonaws.com/groups/global/AllUsers" in json.dumps(p) or "acs.amazonaws.com/groups/global/AuthenticatedUsers" in json.dumps(p) \
            or str(p.get("x-amz-acl", "")).startswith("public-")
    policy = p.get("bucketPolicy") or p.get("policy")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return False
    statements = (policy or {}).get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        pr = st.get("Principal")
        if pr == "*" or (isinstance(pr, dict) and (pr.get("AWS") == "*" or pr.get("AWS") == ["*"])):
            return True
    return False


def _open_ingress(e):
    return "0.0.0.0/0" in json.dumps(_params(e)) or "::/0" in json.dumps(_params(e))


def _public_access_block_removed(e):
    if e.get("EventName") == "DeletePublicAccessBlock":
        return True
    if e.get("EventName") != "PutPublicAccessBlock":
        return False
    cfg = _params(e).get("PublicAccessBlockConfiguration") or {}
    return any(cfg.get(k) is False or str(cfg.get(k)).lower() == "false"
               for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))


def _trail_reduced(e):
    """UpdateTrail only counts when it narrows logging (multi-region or global events switched off)."""
    p = _params(e)
    off = lambda k: p.get(k) is False or str(p.get(k)).lower() == "false"
    return off("isMultiRegionTrail") or off("includeGlobalServiceEvents") or off("enableLogFileValidation")


def _no_guardrail(e):
    p = _params(e)
    return not p.get("guardrailConfiguration")


DETECTIONS = [
    {"id": "root_activity", "agent": "blue-identity-defense", "severity": "high", "mitre": "T1078.004",
     "title": "The root user was used", "events": ["ConsoleLogin", "GetSessionToken", "CreateAccessKey"],
     "match": lambda e: _is_root(e) and not _failed(e),
     "why": "Root has unrestricted access and should only be used for a few account tasks.",
     "respond": "Confirm who used root and why; enable hardware MFA on root and remove root access keys."},
    {"id": "console_login_failures", "agent": "blue-identity-defense", "severity": "medium", "mitre": "T1110",
     "title": "Repeated failed console sign-ins", "events": ["ConsoleLogin"], "match": lambda e: _failed(e),
     "threshold": 5, "group_by": "source_ip",
     "why": "Several failures from one address can mean password guessing.",
     "respond": "Check whether the user recognises the attempts; block the address or require MFA."},
    {"id": "access_key_created", "agent": "blue-identity-defense", "severity": "low", "mitre": "T1098.001",
     "title": "A new IAM access key was created", "events": ["CreateAccessKey"], "match": lambda e: not _failed(e),
     "why": "Long-lived keys created outside normal provisioning are a common persistence step.",
     "respond": "Confirm the key was expected; otherwise deactivate it."},
    {"id": "mfa_removed", "agent": "blue-identity-defense", "severity": "high", "mitre": "T1556.006",
     "title": "MFA was removed from a user", "events": ["DeactivateMFADevice", "DeleteVirtualMFADevice"], "match": lambda e: not _failed(e),
     "why": "Removing MFA weakens sign-in protection and often precedes account takeover.",
     "respond": "Confirm with the user; re-enable MFA."},
    {"id": "admin_policy_granted", "agent": "blue-identity-defense", "severity": "high", "mitre": "T1098",
     "title": "Administrator permissions were granted",
     "events": ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"],
     "match": lambda e: not _failed(e) and _admin_policy(e),
     "why": "Granting full administrator access is a privilege-escalation step if not approved.",
     "respond": "Check the change ticket; detach the policy if it was not approved."},
    {"id": "logging_tampered", "agent": "blue-cloud-threat", "severity": "critical", "mitre": "T1562.008",
     "title": "Audit logging was stopped or deleted", "events": ["StopLogging", "DeleteTrail", "UpdateTrail", "DeleteFlowLogs"],
     "match": lambda e: not _failed(e) and (e.get("EventName") != "UpdateTrail" or _trail_reduced(e)),
     "why": "Attackers disable logging to hide what they do next.",
     "respond": "Re-enable the trail immediately and review activity by the same principal."},
    {"id": "detector_removed", "agent": "blue-cloud-threat", "severity": "high", "mitre": "T1562.001",
     "title": "A threat-detection service was switched off", "events": ["DeleteDetector", "DisableSecurityHub", "DeleteConfigurationRecorder", "StopConfigurationRecorder"],
     "match": lambda e: not _failed(e),
     "why": "Removing GuardDuty, Security Hub or AWS Config lowers detection coverage.",
     "respond": "Re-enable the service and confirm the change was approved."},
    {"id": "bucket_made_public", "agent": "blue-cloud-threat", "severity": "high", "mitre": "T1530",
     "title": "An S3 bucket was opened to the public",
     "events": ["PutBucketPolicy", "PutBucketAcl", "DeletePublicAccessBlock", "PutPublicAccessBlock"],
     "match": lambda e: not _failed(e) and (_public_bucket(e) or _public_access_block_removed(e)),
     "why": "Public buckets are a frequent cause of data leaks.",
     "respond": "Restore the public-access block and review the bucket policy."},
    {"id": "ingress_opened", "agent": "blue-cloud-threat", "severity": "medium", "mitre": "T1562.007",
     "title": "A security group was opened to the internet", "events": ["AuthorizeSecurityGroupIngress"],
     "match": lambda e: not _failed(e) and _open_ingress(e),
     "why": "Open inbound rules expose services to scanning and attack.",
     "respond": "Restrict the rule to known addresses."},
    {"id": "bedrock_guardrail_deleted", "agent": "blue-ai-threat-defense", "severity": "high", "mitre": "T1562",
     "title": "A Bedrock guardrail was deleted", "events": ["DeleteGuardrail"], "match": lambda e: not _failed(e),
     "why": "Removing a guardrail switches off input/output protection for the AI systems that used it.",
     "respond": "Confirm the change; restore the guardrail on affected agents."},
    {"id": "bedrock_logging_removed", "agent": "blue-ai-threat-defense", "severity": "high", "mitre": "T1562.008",
     "title": "Bedrock invocation logging was removed", "events": ["DeleteModelInvocationLoggingConfiguration"],
     "match": lambda e: not _failed(e),
     "why": "Without invocation logs, misuse of models cannot be investigated.",
     "respond": "Re-enable model invocation logging."},
    {"id": "bedrock_agent_unguarded", "agent": "blue-ai-threat-defense", "severity": "medium", "mitre": "T1562",
     "title": "A Bedrock agent was changed without a guardrail", "events": ["UpdateAgent", "CreateAgent"],
     "match": lambda e: not _failed(e) and _no_guardrail(e),
     "why": "An agent without a guardrail has no platform-level control over what it receives and returns.",
     "respond": "Attach a guardrail and prepare the agent again."},
]
DETECTION_EVENTS = sorted({n for d in DETECTIONS for n in d["events"]})
# Threshold rules count per UTC day, so every poll re-reads the whole day for their event names.
THRESHOLD_EVENTS = sorted({n for d in DETECTIONS if d.get("threshold") for n in d["events"]})


def detect(events, region):
    """events: LookupEvents results. Returns detections with the matching events' ids as evidence."""
    out = []
    for d in DETECTIONS:
        hits = [e for e in events if e.get("EventName") in d["events"] and _safe_match(d, e)]
        if not hits:
            continue
        if d.get("threshold"):
            groups = {}
            for e in hits:
                groups.setdefault(_ct(e).get("sourceIPAddress") or "unknown", []).append(e)
            batches = []
            for ip, evs in groups.items():
                by_day = {}
                for e in evs:   # an episode = one address on one (UTC) day, so a later attack is a new detection
                    by_day.setdefault(_as_dt(e["EventTime"]).date().isoformat(), []).append(e)
                batches += [(f"{region}|{ip}|{day}", v) for day, v in by_day.items() if len(v) >= d["threshold"]]
        else:
            batches = [(_principal(e) + "|" + str(e.get("EventId")), [e]) for e in hits]
        for key, evs in batches:
            first = min(_as_dt(e["EventTime"]) for e in evs)
            last = max(_as_dt(e["EventTime"]) for e in evs)
            principal = _principal(evs[0])
            resources = sorted({r.get("ResourceName") for e in evs for r in (e.get("Resources") or []) if r.get("ResourceName")})
            out.append({
                "fingerprint": fingerprint(d["id"], key), "rule": d["id"], "agent_id": d["agent"], "severity": d["severity"],
                "title": d["title"], "mitre": d["mitre"], "principal": principal, "resources": resources[:20],
                "source_ip": _ct(evs[0]).get("sourceIPAddress"), "region": region,
                "first_event_at": first.isoformat(), "last_event_at": last.isoformat(), "event_count": len(evs),
                "event_ids": [e.get("EventId") for e in evs][:50], "event_names": sorted({e.get("EventName") for e in evs}),
                "why": d["why"], "respond": d["respond"], "basis": "observed (CloudTrail management events)",
            })
    return out


def _safe_match(d, e):
    try:
        return bool(d["match"](e))
    except Exception:  # noqa: BLE001 - an odd event must not break detection of the others
        return False


# ── Red: attack surface ───────────────────────────────────────────────────
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 6379: "Redis",
                   27017: "MongoDB", 9200: "Elasticsearch", 5601: "Kibana", 2375: "Docker API", 11211: "Memcached"}
DB_PORTS = {"postgres": 5432, "aurora-postgresql": 5432, "mysql": 3306, "aurora-mysql": 3306, "mariadb": 3306, "aurora": 3306,
            "sqlserver-ex": 1433, "sqlserver-se": 1433, "sqlserver-ee": 1433, "sqlserver-web": 1433, "oracle-ee": 1521, "oracle-se2": 1521}


PROTOCOLS = {"-1": "all", "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}


def open_to_internet(rules, families=("ipv4", "ipv6")):
    """Security group ingress rules (IpPermissions) that admit the whole internet over the given address families.
    Returns [(from, to, protocol)] with protocol normalised (tcp, udp, icmp, all)."""
    out = []
    for p in rules or []:
        v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", []))
        v6 = any(r.get("CidrIpv6") == "::/0" for r in p.get("Ipv6Ranges", []))
        if not ((v4 and "ipv4" in families) or (v6 and "ipv6" in families)):
            continue
        proto = PROTOCOLS.get(str(p.get("IpProtocol")), str(p.get("IpProtocol")))
        lo, hi = (0, 65535) if proto == "all" else (p.get("FromPort", 0), p.get("ToPort", 65535))
        out.append((lo, hi, proto))
    return out


def _covers(ranges, port, proto="tcp"):
    return any(lo <= port <= hi and p in ("all", proto) for lo, hi, p in ranges)


def _ports_text(ranges):
    return ", ".join("all ports" if (lo, hi) == (0, 65535) else (str(lo) if lo == hi else f"{lo}-{hi}") + f"/{pr}" for lo, hi, pr in ranges)


def red_attack_surface(surface, ciem_by_role=None):
    """surface: {region: {"security_groups": {id: {"name", "rules"}}, "instances": [...], "databases": [...], "function_urls": [...]}}.
    Items describe reachability from configuration only; nothing was connected to."""
    ciem_by_role = ciem_by_role or {}
    items = []
    for region, s in sorted(surface.items()):
        sgs = s.get("security_groups") or {}
        for inst in s.get("instances") or []:
            fams = (("ipv4",) if inst.get("public_ip") else ()) + (("ipv6",) if inst.get("ipv6") else ())
            if not fams or inst.get("state") != "running":
                continue
            ranges = [r for g in inst.get("security_groups") or [] for r in open_to_internet((sgs.get(g) or {}).get("rules"), fams)]
            if not ranges:
                continue
            sensitive = sorted({f"{n} ({p})" for p, n in SENSITIVE_PORTS.items() if _covers(ranges, p)})
            role = inst.get("role_arn")
            c = ciem_by_role.get(role) or {}
            admin = c.get("admin") == "admin"
            caps = [x["label"] for x in c.get("capabilities") or [] if x.get("result") in ("allowed", "scoped")]
            sev = "critical" if sensitive and admin else "high" if sensitive or admin else "medium"
            to = "full administrator access" if admin else (", ".join(caps[:3]) if caps else ("its instance role" if role else "the instance"))
            items.append(_surface_item(
                "ec2_instance", f"{region}:{inst['id']}", f"EC2 {inst.get('name') or inst['id']} is reachable from the internet on {_ports_text(ranges)}",
                sev, {"instance": inst["id"], "region": region, "public_ip": inst.get("public_ip"), "ipv6": inst.get("ipv6"), "open": _ports_text(ranges),
                      "sensitive_services": sensitive, "role_arn": role, "role_capabilities": caps, "role_admin": admin,
                      "security_groups": inst.get("security_groups")},
                [{"type": "ec2_instance", "ref": inst.get("arn") or inst["id"]}] + ([{"type": "aws_identity", "ref": role}] if role else []),
                {"from": "the internet", "steps": [f"{_ports_text(ranges)} via {', '.join(inst.get('security_groups') or [])}", f"instance {inst['id']}"]
                 + ([f"instance role {role.split('/')[-1]}"] if role else []), "to": to, "prerequisites": ["a vulnerable or misconfigured service on an open port"]},
                admin, "Restrict the security group to known addresses or put the instance behind a load balancer/VPN; scope the instance role."))
        for db in s.get("databases") or []:
            if not db.get("public"):
                continue
            port = db.get("port") or DB_PORTS.get(db.get("engine"))
            ranges = [r for g in db.get("security_groups") or [] for r in open_to_internet((sgs.get(g) or {}).get("rules"))]
            reachable = port is not None and _covers(ranges, port)
            items.append(_surface_item(
                "rds_instance", f"{region}:{db['id']}",
                f"Database {db['id']} is publicly accessible" + (f" and port {port} is open to the internet" if reachable else ""),
                "high" if reachable else "medium",
                {"database": db["id"], "region": region, "engine": db.get("engine"), "port": port, "publicly_accessible": True,
                 "open_to_internet": reachable, "open": _ports_text(ranges) if ranges else "no 0.0.0.0/0 rule",
                 "encrypted": db.get("encrypted"), "security_groups": db.get("security_groups")},
                [{"type": "rds_instance", "ref": db.get("arn") or db["id"]}],
                {"from": "the internet", "steps": [f"port {port} via {', '.join(db.get('security_groups') or [])}" if reachable else "public endpoint (blocked by security group)",
                                                   f"database {db['id']}"], "to": "database login (password or IAM authentication)",
                 "prerequisites": ["valid or guessable database credentials"]},
                False, "Turn off public accessibility, or restrict the security group to the addresses that need it; require TLS."))
        for fu in s.get("function_urls") or []:
            if fu.get("auth_type") != "NONE":
                continue
            role = fu.get("role_arn")
            c = ciem_by_role.get(role) or {}
            admin = c.get("admin") == "admin"
            caps = [x["label"] for x in c.get("capabilities") or [] if x.get("result") in ("allowed", "scoped")]
            items.append(_surface_item(
                "lambda_url", f"{region}:{fu['function']}", f"Lambda {fu['function']} has a public URL without authentication",
                "critical" if admin else "high" if caps else "medium",
                {"function": fu["function"], "region": region, "url": fu.get("url"), "role_arn": role, "role_capabilities": caps, "role_admin": admin},
                [{"type": "lambda_function", "ref": fu.get("arn") or fu["function"]}] + ([{"type": "aws_identity", "ref": role}] if role else []),
                {"from": "the internet", "steps": ["unauthenticated function URL", f"function {fu['function']}"] + ([f"role {role.split('/')[-1]}"] if role else []),
                 "to": "full administrator access" if admin else (", ".join(caps[:3]) if caps else "the function's own logic"),
                 "prerequisites": ["input the function handles unsafely"]},
                admin, "Set the function URL auth type to AWS_IAM or put an authorizer in front; scope the execution role."))
    return items


def _surface_item(kind, ident, title, severity, evidence, assets, path, to_admin, fix):
    it = _item("red-attack-surface", "attack_surface", f"{kind}:{ident}", title, severity, "high", "observed configuration (read-only API calls)",
               evidence, assets, {"current": title, "proposed": fix, "reason": "Anything reachable from the internet is probed continuously.",
                                  "impact": "Legitimate clients outside the allowed range lose access; check who connects first.",
                                  "rollback": "Restore the previous rule or setting.", "approvals": "Resource owner"},
               exposure="external", path_to_admin=to_admin, attack_path=path)
    it["validation"]["note"] = "Derived from configuration. Nothing was scanned or connected to, so reachability of the service itself is not tested."
    return it


# ── Blue: AWS-native detections ────────────────────────────────────────────

def _gd_severity(v):
    v = float(v or 0)
    return "critical" if v >= 8.5 else "high" if v >= 7 else "medium" if v >= 4 else "low"


def blue_aws_native(guardduty, securityhub):
    """guardduty: GetFindings results; securityhub: GetFindings results. A Security Hub copy of a GuardDuty finding is
    skipped only when that GuardDuty finding was imported directly. Returns detections in the same shape as detect()."""
    out = []
    imported_gd = {f["Id"] for f in guardduty or []}
    for f in guardduty or []:
        res = f.get("Resource") or {}
        role = ((res.get("AccessKeyDetails") or {}).get("UserName")) or ((res.get("InstanceDetails") or {}).get("InstanceId"))
        svc = f.get("Service") or {}
        out.append({
            "fingerprint": fingerprint("guardduty", f["Id"]), "rule": "guardduty:" + f.get("Type", "unknown"), "agent_id": "blue-aws-detections",
            "severity": _gd_severity(f.get("Severity")), "title": f.get("Title") or f.get("Type"), "mitre": None,
            "principal": role or res.get("ResourceType") or "unknown", "resources": [x for x in [role, res.get("ResourceType")] if x],
            "source_ip": (((svc.get("Action") or {}).get("NetworkConnectionAction") or {}).get("RemoteIpDetails") or {}).get("IpAddressV4"),
            "region": f.get("Region"), "first_event_at": svc.get("EventFirstSeen") or f.get("CreatedAt"),
            "last_event_at": svc.get("EventLastSeen") or f.get("UpdatedAt"), "event_count": int(svc.get("Count") or 1),
            "event_ids": [f["Id"]], "event_names": [f.get("Type")], "why": f.get("Description"),
            "respond": "Follow the GuardDuty remediation guidance for this finding type; confirm whether the activity was expected.",
            "basis": "observed (Amazon GuardDuty)"})
    for f in securityhub or []:
        if "guardduty" in str(f.get("ProductArn", "")).lower() and str(f.get("Id", "")).rsplit("/", 1)[-1] in imported_gd:
            continue
        if (f.get("Workflow") or {}).get("Status") in ("SUPPRESSED", "RESOLVED") or f.get("RecordState") == "ARCHIVED":
            continue
        label = ((f.get("Severity") or {}).get("Label") or "LOW").lower()
        if label == "informational":
            continue
        resources = [r.get("Id") for r in f.get("Resources") or [] if r.get("Id")]
        out.append({
            "fingerprint": fingerprint("securityhub", f["Id"]), "rule": "securityhub:" + ((f.get("ProductFields") or {}).get("aws/securityhub/ProductName") or "finding"),
            "agent_id": "blue-aws-detections", "severity": label if label in SEV_POINTS else "low", "title": f.get("Title"), "mitre": None,
            "principal": resources[0] if resources else "unknown", "resources": resources[:20], "source_ip": None, "region": f.get("Region"),
            "first_event_at": f.get("FirstObservedAt") or f.get("CreatedAt"), "last_event_at": f.get("LastObservedAt") or f.get("UpdatedAt"),
            "event_count": 1, "event_ids": [f["Id"]], "event_names": (f.get("Types") or [])[:3], "why": f.get("Description"),
            "respond": ((f.get("Remediation") or {}).get("Recommendation") or {}).get("Text") or "See the Security Hub finding.",
            "basis": "observed (AWS Security Hub)"})
    return out


def triage(detections, work_items, window_minutes=60):
    """Incident Triage Agent: groups detections by principal within a time window and correlates them with open
    Red work items on the same identity or resource. Returns incidents."""
    incidents = []
    for det in sorted(detections, key=lambda d: d["first_event_at"]):
        start = _as_dt(det["first_event_at"])
        inc = next((i for i in incidents if i["principal"] == det["principal"]
                    and start - _as_dt(i["last_event_at"]) <= timedelta(minutes=window_minutes)), None)
        if inc is None:
            inc = {"principal": det["principal"], "detections": [], "first_event_at": det["first_event_at"],
                   "last_event_at": det["last_event_at"], "severity": det["severity"], "resources": set()}
            incidents.append(inc)
        inc["detections"].append(det["fingerprint"])
        inc["last_event_at"] = max(inc["last_event_at"], det["last_event_at"])
        inc["resources"] |= set(det["resources"])
        if SEV_POINTS[det["severity"]] > SEV_POINTS[inc["severity"]]:
            inc["severity"] = det["severity"]
    for inc in incidents:
        refs = {inc["principal"]} | inc["resources"]
        related = [w["fingerprint"] for w in work_items if any(a.get("ref") in refs or (a.get("ref") and any(
            str(a["ref"]).endswith("/" + r.split("/")[-1]) for r in refs if r)) for a in w.get("assets") or [])]
        inc["related_work_items"] = related
        inc["resources"] = sorted(inc["resources"])[:20]
        inc["fingerprint"] = fingerprint("incident", inc["principal"], inc["first_event_at"])
        multi = len(inc["detections"]) > 1
        if related and SEV_POINTS[inc["severity"]] < SEV_POINTS["high"]:
            inc["severity"] = "high"
        inc["summary"] = (f"{len(inc['detections'])} detection(s) by {inc['principal'].split('/')[-1]}"
                          + (f", linked to {len(related)} known weakness(es)" if related else "")
                          + ("; activity spans several rules" if multi else ""))
        inc["hypothesis"] = ("Possible misuse of this identity" if related or multi else "Single event; may be legitimate administration")
        inc["basis"] = "correlated (detections + work items); the hypothesis is not a conclusion"
    return incidents


# ── Green ───────────────────────────────────────────────────────────────────

def remediation_plan(item):
    """Plan from the source recommendation. Never claims a change was made."""
    rec = item.get("recommendation") or {}
    steps = []
    if rec.get("current"):
        steps.append(f"Confirm the current state: {rec['current']}")
    steps.append(f"Change: {rec.get('proposed') or 'see the source recommendation'}")
    steps.append("Apply it through your normal change process (pull request or change request); Niagaros does not change your systems.")
    steps.append("Record the change reference (PR, ticket or change ID) on this work item and mark it remediated.")
    steps.append("Verification: the next scan must no longer report the problem; until then the item stays open.")
    return {"steps": steps, "reason": rec.get("reason"), "impact": rec.get("impact"), "approvals": rec.get("approvals") or "Asset owner",
            "rollback": rec.get("rollback"), "confidence": rec.get("confidence") or item.get("confidence"),
            "acceptance_criteria": f"The source ({item['source_type'].replace('_', ' ')}) no longer reports this after a scan that ran after the remediation.",
            "rescan": RESCAN_FOR.get(item["source_type"]), "generated_by": "green-remediation-planner", "engine_version": ENGINE_VERSION}


RESCAN_FOR = {"ciem_finding": "ciem-scanner", "ai_inventory_finding": "ai-inventory-scanner", "scanner_finding": "orchestrator (full scan)"}


def verify(item, source_state, remediated_at):
    """source_state: {"status": source status, "checked_at": when the source last re-collected it (or None),
    "present": whether the latest scan still reports it}. Returns {"result": passed|failed|pending, "reason"}."""
    checked = source_state.get("checked_at")
    if not remediated_at:
        if source_state.get("present") is False and checked is not None:
            return {"result": "passed", "reason": f"Fixed outside this workflow: the scan of {_iso(checked)} no longer reports the problem "
                                                   f"({source_state.get('status')})."}
        return {"result": "pending", "reason": "No remediation recorded yet."}
    if checked is None or _as_dt(checked) <= _as_dt(remediated_at):
        return {"result": "pending", "reason": "No scan has re-checked this since the remediation was recorded."}
    if source_state.get("present"):
        return {"result": "failed", "reason": f"The scan of {_iso(checked)} still reports the problem."}
    return {"result": "passed", "reason": f"The scan of {_iso(checked)} no longer reports the problem ({source_state.get('status')})."}


# ── evaluation (issue §12): fixed synthetic scenarios with known answers ───────────────────────
NOW_EVAL = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _ev(name, root=False, failed=False, params=None, ip="203.0.113.7", minute=0, arn="arn:aws:iam::111122223333:user/alice"):
    ct = {"userIdentity": {"type": "Root" if root else "IAMUser", "arn": "arn:aws:iam::111122223333:root" if root else arn},
          "sourceIPAddress": ip, "requestParameters": params or {}}
    if failed:
        ct["errorCode"] = "AccessDenied"
        if name == "ConsoleLogin":
            ct["responseElements"] = {"ConsoleLogin": "Failure"}
            ct.pop("errorCode")
    return {"EventId": fingerprint(name, minute, ip, root), "EventName": name, "EventTime": (NOW_EVAL + timedelta(minutes=minute)).isoformat(),
            "CloudTrailEvent": json.dumps(ct), "Resources": []}


def evaluation_scenarios():
    """Per agent: (input, expected keys). Expected outputs are fixed so the evaluation measures the agent's logic."""
    pub = {"bucketName": "b", "bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}}
    private = {"bucketName": "b", "bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/x"}}]}}
    blue_events = [
        _ev("ConsoleLogin", root=True), _ev("ConsoleLogin", minute=1),
        *[_ev("ConsoleLogin", failed=True, minute=2 + i, ip="198.51.100.9") for i in range(6)],
        *[_ev("ConsoleLogin", failed=True, minute=2 + i, ip="198.51.100.10") for i in range(2)],
        _ev("StopLogging", minute=10), _ev("StopLogging", failed=True, minute=11),
        _ev("PutBucketPolicy", params=pub, minute=12), _ev("PutBucketPolicy", params=private, minute=13),
        _ev("AttachRolePolicy", params={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, minute=14),
        _ev("AttachRolePolicy", params={"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}, minute=15),
        _ev("AuthorizeSecurityGroupIngress", params={"ipPermissions": {"items": [{"ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}, minute=16),
        _ev("AuthorizeSecurityGroupIngress", params={"ipPermissions": {"items": [{"ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}}]}}, minute=17),
        _ev("DeleteGuardrail", minute=18), _ev("UpdateAgent", params={"agentName": "a"}, minute=19),
        _ev("UpdateAgent", params={"agentName": "b", "guardrailConfiguration": {"guardrailIdentifier": "g"}}, minute=20),
    ]
    blue_expected = {"root_activity": 1, "console_login_failures": 1, "logging_tampered": 1, "bucket_made_public": 1,
                     "admin_policy_granted": 1, "ingress_opened": 1, "bedrock_guardrail_deleted": 1, "bedrock_agent_unguarded": 1}
    ciem = [{"id": "c1", "status": "open", "rule": "no_permanent_admin", "category": "excessive_permissions", "severity": "high",
             "title": "admin user", "identity_arn": "arn:aws:iam::1:user/a"},
            {"id": "c2", "status": "resolved", "rule": "x", "category": "excessive_permissions", "severity": "high", "title": "fixed",
             "identity_arn": "arn:aws:iam::1:user/b"},
            {"id": "c3", "status": "open", "rule": "escalation_paths", "category": "privilege_escalation", "severity": "critical", "title": "path",
             "identity_arn": "arn:aws:iam::1:role/r",
             "details": {"path": {"how": "Create a Lambda with an admin role", "required_permissions": ["iam:PassRole", "lambda:CreateFunction"],
                                  "gains": ["full administrator access"], "targets": ["arn:aws:iam::1:role/admin"]}}}]
    scanner = [{"id": "s1", "check_id": "S3.1", "title": "Bucket is public", "severity": "CRITICAL", "resource_arn": "arn:aws:s3:::x",
                "details": {"public": True}, "framework": "CIS"},
               {"id": "s2", "check_id": "S3.4", "title": "MFA delete off", "severity": "MEDIUM", "resource_arn": "arn:aws:s3:::y", "framework": "CIS"}]
    ai = [{"id": "a1", "status": "open", "rule": "mcp_insecure_transport", "severity": "high", "title": "http mcp", "asset_key": "mcp:x"},
          {"id": "a2", "status": "false_positive", "rule": "secret_in_code", "severity": "critical", "title": "fp", "asset_key": "github:x"}]
    return {
        "red-identity-attack-path": (lambda: red_identity([], ciem), {"c1", "c3"}),
        "red-vulnerability-assessment": (lambda: red_vulnerabilities(scanner), {"s1"}),
        "red-ai-security": (lambda: red_ai(ai), {"a1"}),
        "blue-identity-defense": (lambda: detect(blue_events, "eu-west-1"), blue_expected),
        "blue-cloud-threat": (lambda: detect(blue_events, "eu-west-1"), blue_expected),
        "blue-ai-threat-defense": (lambda: detect(blue_events, "eu-west-1"), blue_expected),
        "red-attack-surface": (lambda: red_attack_surface(_surface_fixture(), {"arn:aws:iam::1:role/web": {"admin": "admin", "capabilities": []}}),
                               {"ec2_instance:eu-west-1:i-web", "rds_instance:eu-west-1:db-pub", "lambda_url:eu-west-1:open-fn"}),
        "blue-aws-detections": (lambda: blue_aws_native(*_native_fixture()), {"gd-1", "sh-2"}),
        "blue-incident-triage": (lambda: triage(detect(blue_events, "eu-west-1"), []), None),
        "green-remediation-planner": (lambda: [remediation_plan({"source_type": "ciem_finding", "confidence": "high",
                                                                 "recommendation": {"current": "a", "proposed": "b", "rollback": "c"}})], None),
        "green-verification": (lambda: [verify({}, {"present": False, "checked_at": NOW_EVAL}, NOW_EVAL - timedelta(hours=1)),
                                        verify({}, {"present": True, "checked_at": NOW_EVAL}, NOW_EVAL - timedelta(hours=1)),
                                        verify({}, {"present": False, "checked_at": NOW_EVAL - timedelta(hours=2)}, NOW_EVAL - timedelta(hours=1))], None),
    }


def _surface_fixture():
    sg_open = {"rules": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                         {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
    sg_closed = {"rules": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}
    return {"eu-west-1": {
        "security_groups": {"sg-open": sg_open, "sg-closed": sg_closed},
        "instances": [{"id": "i-web", "state": "running", "public_ip": "198.51.100.4", "security_groups": ["sg-open"], "role_arn": "arn:aws:iam::1:role/web"},
                      {"id": "i-private", "state": "running", "public_ip": None, "security_groups": ["sg-open"]},
                      {"id": "i-closed", "state": "running", "public_ip": "198.51.100.5", "security_groups": ["sg-closed"]},
                      {"id": "i-stopped", "state": "stopped", "public_ip": "198.51.100.6", "security_groups": ["sg-open"]}],
        "databases": [{"id": "db-pub", "public": True, "engine": "postgres", "port": 5432, "security_groups": ["sg-open"]},
                      {"id": "db-private", "public": False, "engine": "postgres", "port": 5432, "security_groups": ["sg-open"]}],
        "function_urls": [{"function": "open-fn", "auth_type": "NONE"}, {"function": "iam-fn", "auth_type": "AWS_IAM"}]}}


def _native_fixture():
    gd = [{"Id": "gd-1", "Type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller", "Severity": 8.0, "Title": "API called from a known malicious IP",
           "Region": "eu-west-1", "CreatedAt": "2026-10-01T10:00:00Z", "UpdatedAt": "2026-10-01T11:00:00Z",
           "Resource": {"ResourceType": "AccessKey", "AccessKeyDetails": {"UserName": "dev"}}, "Service": {"Count": 3}}]
    sh = [{"Id": "arn:aws:guardduty:eu-west-1:1:detector/d/finding/gd-1", "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/guardduty",
           "Severity": {"Label": "HIGH"}, "Title": "dup"},
          {"Id": "sh-2", "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/inspector", "Severity": {"Label": "CRITICAL"}, "Title": "CVE in image",
           "Resources": [{"Id": "arn:aws:ecr:eu-west-1:1:repository/app"}], "Region": "eu-west-1", "CreatedAt": "2026-10-01T10:00:00Z"},
          {"Id": "sh-3", "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/inspector", "Severity": {"Label": "HIGH"}, "Title": "suppressed",
           "Workflow": {"Status": "SUPPRESSED"}},
          {"Id": "sh-4", "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/config", "Severity": {"Label": "INFORMATIONAL"}, "Title": "info"}]
    return gd, sh


def evaluate(agent_id):
    """Runs the agent's fixed scenarios. Red/Blue: precision and recall against the expected set. Triage, planning
    and verification: property checks with a pass/fail per check."""
    fn, expected = evaluation_scenarios()[agent_id]
    out = fn()
    checks = []
    if agent_id.startswith("red-"):
        got = {w["source_id"] for w in out}
        tp = len(got & expected)
        checks.append(("finds every expected weakness", tp == len(expected)))
        checks.append(("ignores resolved, false-positive and low-severity input", not (got - expected)))
        checks.append(("never claims validated exploitation", all(w["validation"]["status"] == "not_validated" for w in out)))
        precision = tp / len(got) if got else 1.0
        recall = tp / len(expected) if expected else 1.0
    elif agent_id == "blue-aws-detections":
        got = {d["event_ids"][0] for d in out}
        tp = len(got & expected)
        precision = tp / len(got) if got else 1.0
        recall = tp / len(expected)
        checks.append(("imports every active GuardDuty and Security Hub finding", recall == 1.0))
        checks.append(("skips duplicates, suppressed and informational findings", not (got - expected)))
    elif agent_id in ("blue-identity-defense", "blue-cloud-threat", "blue-ai-threat-defense"):
        mine = {d["id"] for d in DETECTIONS if d["agent"] == agent_id}
        got = {}
        for d in out:
            if d["rule"] in mine:
                got[d["rule"]] = got.get(d["rule"], 0) + 1
        exp = {k: v for k, v in expected.items() if k in mine}
        tp = sum(min(got.get(k, 0), v) for k, v in exp.items())
        fp = sum(max(0, got.get(k, 0) - exp.get(k, 0)) for k in got)
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / sum(exp.values()) if exp else 1.0
        checks.append(("detects every expected event pattern", recall == 1.0))
        checks.append(("no detections on failed calls or benign changes", fp == 0))
        checks.append(("every detection links its CloudTrail event ids", all(d["event_ids"] for d in out)))
    elif agent_id == "blue-incident-triage":
        precision = recall = None
        checks.append(("groups activity of one principal into one incident", len({i["principal"] for i in out}) == len(out)))
        checks.append(("labels its conclusion as a hypothesis", all("hypothesis" in i for i in out)))
    elif agent_id == "green-remediation-planner":
        precision = recall = None
        p = out[0]
        checks.append(("plan has acceptance criteria and rollback", bool(p["acceptance_criteria"] and p["rollback"])))
        checks.append(("plan does not claim the change was applied", all("applied" not in s.lower() or "does not" in s.lower() for s in p["steps"])))
    else:
        precision = recall = None
        checks.append(("passes when a later scan no longer reports it", out[0]["result"] == "passed"))
        checks.append(("fails when the later scan still reports it", out[1]["result"] == "failed"))
        checks.append(("waits when no scan ran after the remediation", out[2]["result"] == "pending"))
    passed = all(ok for _, ok in checks)
    return {"agent_id": agent_id, "passed": passed, "precision": precision, "recall": recall,
            "checks": [{"check": c, "passed": ok} for c, ok in checks], "scenario_set": "built-in synthetic scenarios",
            "engine_version": ENGINE_VERSION}
