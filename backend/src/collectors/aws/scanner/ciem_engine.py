"""
ciem_engine.py — Cloud Infrastructure Entitlement Management analysis (issue #17), AWS.

Pure functions: no AWS or database calls, so every rule is unit-testable. Input is what ciem_collector
gathers with the read-only scanner role (GetAccountAuthorizationDetails, the credential report, IAM Access
Advisor, IAM Access Analyzer). Output is an identity inventory plus findings, each with evidence that points
back to the exact policy statement or trust relationship it comes from.

Honesty rules this module follows (they are in the issue too):
  - Observed facts, inferences and calculations are labelled as such (`basis`).
  - Effective access is evaluated from identity policies, group policies, explicit denies and permission
    boundaries. Things we cannot see (service control policies from a management account we cannot read,
    session policies, resource policies on individual resources) are reported as limitations, never ignored
    silently. A conditional statement makes a result "conditional", not "allowed".
  - "Unused" needs telemetry: without Access Advisor data, or for an identity younger than the observation
    window, the status is "unknown", never "unused".
  - Privilege-escalation paths are potential paths with prerequisites and a confidence level, not
    confirmed exploits.
  - A risk score is always accompanied by the reasons that produced it.
"""
import fnmatch
import hashlib
import json
import re
from datetime import datetime, timezone

MAPPING_VERSION = "ciem-compliance-2026.10"
ENGINE_VERSION = "ciem-engine-1.0"

# ── policy evaluation ────────────────────────────────────────────────────────


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def normalize_statements(document, source):
    """Policy document (dict or JSON string) -> list of statement dicts tagged with their source."""
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            return []
    out = []
    for i, st in enumerate(_as_list((document or {}).get("Statement"))):
        if not isinstance(st, dict):
            continue
        out.append({
            "effect": st.get("Effect", "Allow"),
            "actions": [a.lower() for a in _as_list(st.get("Action"))],
            "not_actions": [a.lower() for a in _as_list(st.get("NotAction"))],
            "resources": _as_list(st.get("Resource")),
            "not_resources": _as_list(st.get("NotResource")),
            "conditional": bool(st.get("Condition")),
            "condition": st.get("Condition"),
            "source": {**source, "statement": st.get("Sid") or f"#{i + 1}"},
        })
    return out


_GLOB_CACHE = {}


def _glob(pattern):
    """IAM wildcards: '*' any run of characters, '?' one character. Nothing else is special."""
    rx = _GLOB_CACHE.get(pattern)
    if rx is None:
        rx = re.compile("".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern) + r"\Z", re.S)
        _GLOB_CACHE[pattern] = rx
    return rx


def _match_action(pattern, action):
    # Action names are case-insensitive in IAM.
    return bool(_glob(pattern.lower()).match(action.lower()))


def _match_resource(pattern, resource):
    # Resource ARNs are case-sensitive (S3 keys, for example).
    return bool(_glob(pattern).match(resource))


def _covers_action(st, action):
    if st["actions"]:
        return any(_match_action(p, action) for p in st["actions"])
    if st["not_actions"]:
        return not any(_match_action(p, action) for p in st["not_actions"])
    return False


_ARN_SERVICE = re.compile(r"^arn:[^:]*:([^:]*):")
# Actions whose resources live in another service's ARN namespace.
_RESOURCE_SERVICES = {"sts": {"iam", "sts"}}


def _fits_action(pattern, action):
    """A statement can only grant an action on resources of that action's service: 'Allow NotAction X on an S3
    ARN' does not grant IAM actions. Non-ARN or wildcard-service patterns are kept (we do not guess)."""
    if pattern == "*":
        return True
    m = _ARN_SERVICE.match(pattern)
    if not m or "*" in m.group(1) or "?" in m.group(1):
        return True
    svc = action.split(":")[0].lower()
    return m.group(1) == svc or m.group(1) in _RESOURCE_SERVICES.get(svc, set())


def _patterns(st, action):
    """(resource patterns the statement applies to for `action`, NotResource exclusions)."""
    if st["resources"]:
        return [r for r in st["resources"] if _fits_action(r, action)], []
    if st["not_resources"]:
        return ["*"], list(st["not_resources"])
    return [], []


def _applies_to(st, action, resource):
    """Does the statement apply to this concrete resource ARN?"""
    if not _covers_action(st, action):
        return False
    if st["resources"]:
        return any(_fits_action(r, action) and _match_resource(r, resource) for r in st["resources"])
    if st["not_resources"]:
        return not any(_match_resource(r, resource) for r in st["not_resources"])
    return False


def _has_wild(p):
    return "*" in p or "?" in p


def _contains(a, b):
    """Does pattern `a` match every string pattern `b` matches? Exact for '*', literals and plain prefix
    patterns ('x*'); otherwise False (unknown is never treated as 'contained')."""
    if a == "*" or a == b:
        return True
    if not _has_wild(b):
        return _match_resource(a, b)
    if a.endswith("*") and not _has_wild(a[:-1]):
        prefix = a[:-1]
        return b.startswith(prefix) and not _has_wild(b[:len(prefix)])
    return False


def _disjoint(a, b):
    """True only when no string can match both patterns (literal parts before the first / after the last
    wildcard contradict each other)."""
    def pre(p):
        i = min([p.find(c) for c in "*?" if c in p] or [len(p)])
        return p[:i]

    def suf(p):
        i = max(p.rfind("*"), p.rfind("?"))
        return p[i + 1:] if i >= 0 else p
    if not _has_wild(a) and not _has_wild(b):
        return a != b
    pa, pb = pre(a), pre(b)
    if not (pa.startswith(pb) or pb.startswith(pa)):
        return True
    sa, sb = suf(a), suf(b)
    return not (sa.endswith(sb) or sb.endswith(sa))


def _intersect(a, b):
    """Intersection of two resource patterns. Exact when one contains the other; None when provably
    disjoint; otherwise a combined 'a ∩ b' pattern that is shown as such (overlap, not a guess)."""
    if _contains(a, b):
        return b
    if _contains(b, a):
        return a
    if _disjoint(a, b):
        return None
    return f"{a} ∩ {b}"


def _evaluate_concrete(statements, action, resource, guards):
    notes = []
    for d in statements:
        if d["effect"] == "Deny" and _applies_to(d, action, resource):
            if not d["conditional"]:
                return {"result": "denied", "evidence": [d["source"]], "notes": ["explicit deny"], "scope": [resource], "blocked_by": None}
            notes.append("a conditional deny may apply")
    best, evidence = "not_allowed", []
    for a in statements:
        if a["effect"] == "Allow" and _applies_to(a, action, resource):
            r = "conditional" if a["conditional"] else "allowed"
            if best == "not_allowed" or (best == "conditional" and r == "allowed"):
                best, evidence = r, [a["source"]]
            elif r == best:
                evidence.append(a["source"])
    for gname, gst in guards or []:
        g = _evaluate_concrete(gst, action, resource, None)
        if g["result"] in ("denied", "not_allowed"):
            return {"result": "not_allowed", "evidence": evidence, "notes": notes + [f"blocked by {gname}"],
                    "scope": [], "blocked_by": gname}
        if g["result"] == "conditional":
            notes.append(f"{gname} allows it only under a condition")
    if best == "allowed" and notes:
        best = "conditional"
    return {"result": best, "evidence": evidence, "notes": notes, "scope": [resource] if best != "not_allowed" else [],
            "blocked_by": None}


def _evaluate_any(statements, action, guards):
    """Is `action` granted on at least one resource? Resource patterns are intersected across the identity
    policies, the permissions boundary and every SCP level; denies remove what they cover."""
    grants_, notes = [], []
    for a in statements:
        if a["effect"] == "Allow" and _covers_action(a, action):
            pats, exc = _patterns(a, action)
            grants_ += [{"p": p, "exc": list(exc), "cond": a["conditional"], "src": a["source"], "partial": False} for p in pats]
    if not grants_:
        return {"result": "not_allowed", "evidence": [], "notes": [], "scope": [], "blocked_by": None}
    denies = [d for d in statements if d["effect"] == "Deny" and _covers_action(d, action)]
    for gname, gst in guards or []:
        g_grants = []
        for a in gst:
            if a["effect"] == "Allow" and _covers_action(a, action):
                pats, exc = _patterns(a, action)
                g_grants += [{"p": p, "exc": exc, "cond": a["conditional"]} for p in pats]
        merged = []
        for x in grants_:
            for y in g_grants:
                r = _intersect(x["p"], y["p"])
                if r is not None:
                    merged.append({**x, "p": r, "exc": x["exc"] + y["exc"], "cond": x["cond"] or y["cond"]})
        if not merged:
            return {"result": "not_allowed", "evidence": [g["src"] for g in grants_][:5], "notes": [f"blocked by {gname}"],
                    "scope": [], "blocked_by": gname}
        if any(y["cond"] for y in g_grants):
            notes.append(f"{gname} has conditions")
        grants_ = merged
        denies += [d for d in gst if d["effect"] == "Deny" and _covers_action(d, action)]
    grants_ = [x for x in grants_ if not any(_contains(e, x["p"]) for e in x["exc"])]
    if not grants_:
        return {"result": "not_allowed", "evidence": [], "notes": ["excluded by NotResource"], "scope": [], "blocked_by": None}
    removed_by = []
    for x in grants_:
        for d in denies:
            dp, dexc = _patterns(d, action)
            if dp == ["*"] and dexc:      # Deny with NotResource: denies everything except dexc
                full = all(_disjoint(x["p"], e) for e in dexc)
                part = not full
            else:
                full = any(_contains(r, x["p"]) for r in dp)
                part = not full and any(not _disjoint(x["p"], r) for r in dp)
            if full:
                if d["conditional"]:
                    x["cond"] = True
                    notes.append("a conditional deny may apply")
                else:
                    x["removed"] = True
                    removed_by.append(d["source"])
            elif part:
                x["partial"] = True
                notes.append("denied on part of the resources")
    left = [x for x in grants_ if not x.get("removed")]
    if not left:
        return {"result": "denied", "evidence": removed_by[:5], "notes": ["explicit deny"], "scope": [], "blocked_by": None}
    unconditional = [x for x in left if not x["cond"]]
    if any(x["p"] == "*" and not x["exc"] and not x["partial"] for x in unconditional):
        result = "allowed"
    elif unconditional:
        result = "scoped"
    else:
        result = "conditional"
    use = unconditional or left
    scope = sorted({x["p"] + (" (except " + ", ".join(x["exc"][:3]) + ")" if x["exc"] else "") for x in use})
    return {"result": result, "evidence": [x["src"] for x in use][:10], "notes": sorted(set(notes)), "scope": scope[:10],
            "blocked_by": None}


def evaluate(statements, action, resource="*", guards=None):
    """
    What `statements` (identity + group policies) grant for `action`.
    `resource` '*' asks "on any resource?"; a concrete ARN asks about exactly that resource.
    `guards` is a list of (name, statements) that must ALSO allow it: the permissions boundary and each
    service-control-policy level (AWS requires every level to allow it); their resource scopes are intersected.
    Returns {"result": allowed|scoped|conditional|denied|not_allowed, "evidence", "notes", "scope", "blocked_by"}.
      allowed      unconditional on every resource (or on the concrete resource asked about)
      scoped       unconditional, but only on some resources ("scope" lists them)
      conditional  only when a policy Condition holds, or a conditional Deny may block it
    """
    if resource != "*":
        return _evaluate_concrete(statements, action, resource, guards)
    return _evaluate_any(statements, action, guards)


def grants(ev):
    return ev["result"] in ("allowed", "scoped", "conditional")


# ── capabilities that matter for risk ────────────────────────────────────────

SENSITIVE_CAPABILITIES = [
    # (id, label, actions — any of them, category)
    ("iam_write", "Change IAM identities or permissions",
     ["iam:CreateUser", "iam:CreateRole", "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy",
      "iam:PutRolePolicy", "iam:CreatePolicyVersion", "iam:UpdateAssumeRolePolicy", "iam:CreateAccessKey"], "identity"),
    ("pass_role", "Pass IAM roles to AWS services", ["iam:PassRole"], "identity"),
    ("secrets_read", "Read secrets and secure parameters",
     ["secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"], "data"),
    ("kms_decrypt", "Decrypt with KMS keys", ["kms:Decrypt"], "data"),
    ("data_read", "Read stored data (S3, DynamoDB)", ["s3:GetObject", "dynamodb:Scan", "dynamodb:GetItem", "dynamodb:Query"], "data"),
    ("destructive", "Delete infrastructure or data",
     ["s3:DeleteBucket", "s3:DeleteObject", "ec2:TerminateInstances", "rds:DeleteDBInstance", "dynamodb:DeleteTable",
      "lambda:DeleteFunction", "kms:ScheduleKeyDeletion"], "infrastructure"),
    ("defense_evasion", "Turn off logging or threat detection",
     ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "guardduty:DeleteDetector", "config:StopConfigurationRecorder"], "detection"),
    ("network_admin", "Change network access", ["ec2:AuthorizeSecurityGroupIngress", "ec2:CreateVpcPeeringConnection", "ec2:ModifyInstanceAttribute"], "infrastructure"),
    ("org_admin", "Manage the AWS Organization or account", ["organizations:LeaveOrganization", "organizations:CreateAccount", "account:CloseAccount"], "identity"),
    ("assume_any_role", "Assume other roles", ["sts:AssumeRole"], "identity"),
]

SENSITIVE_SERVICES = {"iam", "sts", "kms", "secretsmanager", "s3", "ec2", "lambda", "organizations", "dynamodb",
                      "rds", "cloudtrail", "ssm", "*"}


ADMIN_PROBE = ["iam:CreateUser", "iam:PassRole", "iam:AttachRolePolicy", "sts:AssumeRole", "s3:GetObject", "s3:DeleteBucket",
               "ec2:RunInstances", "ec2:TerminateInstances", "kms:Decrypt", "secretsmanager:GetSecretValue",
               "lambda:CreateFunction", "rds:DeleteDBInstance", "cloudtrail:StopLogging", "organizations:LeaveOrganization"]


def admin_status(statements, guards=None):
    """'admin' only when an unconditional Allow of every action on every resource exists and nothing narrows it
    (no Deny anywhere, every guard allows everything). 'near_admin' when such an allow (or a broad NotAction
    allow) is narrowed but still grants at least 3/4 of a broad probe of sensitive actions on all resources."""
    def full_allow(sts):
        return [s for s in sts if s["effect"] == "Allow" and not s["conditional"] and "*" in s["actions"]
                and "*" in s["resources"]]
    full = full_allow(statements)
    broad_not = [s for s in statements if s["effect"] == "Allow" and not s["conditional"] and s["not_actions"]
                 and "*" in s["resources"]]
    if not full and not broad_not:
        return None, []
    evidence = [s["source"] for s in full or broad_not]
    narrowed = any(s["effect"] == "Deny" for s in statements) or any(
        not full_allow(g) or any(s["effect"] == "Deny" for s in g) for _, g in (guards or []))
    if full and not narrowed:
        return "admin", evidence
    allowed = sum(1 for a in ADMIN_PROBE if evaluate(statements, a, "*", guards)["result"] == "allowed")
    return ("near_admin", evidence) if allowed >= 0.75 * len(ADMIN_PROBE) else (None, [])


def service_wildcards(statements):
    """Unconditional 'service:*' allows on all resources, per sensitive service."""
    out = []
    for s in statements:
        if s["effect"] != "Allow" or s["conditional"] or "*" not in s["resources"]:
            continue
        for a in s["actions"]:
            m = re.fullmatch(r"([a-z0-9-]+):\*", a)
            if m and m.group(1) in SENSITIVE_SERVICES:
                out.append({"service": m.group(1), "source": s["source"]})
    return out


def capabilities(statements, guards=None):
    caps = []
    for cid, label, actions, category in SENSITIVE_CAPABILITIES:
        best = None
        for a in actions:
            ev = evaluate(statements, a, "*", guards)
            if grants(ev) and (best is None or {"allowed": 3, "scoped": 2, "conditional": 1}[ev["result"]] >
                               {"allowed": 3, "scoped": 2, "conditional": 1}[best["result"]]):
                best = {**ev, "action": a}
        if best:
            caps.append({"id": cid, "label": label, "category": category, "result": best["result"],
                         "via_action": best["action"], "evidence": best["evidence"], "notes": best["notes"],
                         "scope": best.get("scope", [])})
    return caps


# ── privilege escalation ─────────────────────────────────────────────────────

# Well-documented AWS IAM privilege-escalation methods (Rhino Security Labs research, also used by tools such
# as Pacu and PMapper). `needs` must all be granted; `pass_to` names the service a passed role must trust.
ESCALATION_METHODS = [
    ("create_policy_version", "Rewrite a managed policy it is attached to", ["iam:CreatePolicyVersion"], None,
     "Create a new default version of a customer-managed policy attached to itself with administrator rights."),
    ("set_default_policy_version", "Switch a managed policy to an older, broader version", ["iam:SetDefaultPolicyVersion"], None,
     "Make a previously created, more permissive policy version the default. Only works if such a version exists."),
    ("attach_user_policy", "Attach any policy to a user", ["iam:AttachUserPolicy"], None,
     "Attach AdministratorAccess to itself (or another user it controls)."),
    ("attach_group_policy", "Attach any policy to a group", ["iam:AttachGroupPolicy"], None,
     "Attach AdministratorAccess to a group it belongs to."),
    ("attach_role_policy", "Attach any policy to a role it can assume", ["iam:AttachRolePolicy", "sts:AssumeRole"], None,
     "Attach AdministratorAccess to a role and then assume that role."),
    ("put_user_policy", "Write an inline policy on a user", ["iam:PutUserPolicy"], None,
     "Add an inline administrator policy to itself."),
    ("put_group_policy", "Write an inline policy on a group", ["iam:PutGroupPolicy"], None,
     "Add an inline administrator policy to a group it belongs to."),
    ("put_role_policy", "Write an inline policy on a role it can assume", ["iam:PutRolePolicy", "sts:AssumeRole"], None,
     "Add an inline administrator policy to a role and assume it."),
    ("add_user_to_group", "Join a more privileged group", ["iam:AddUserToGroup"], None,
     "Add itself to an existing group with more permissions."),
    ("create_access_key", "Create access keys for other users", ["iam:CreateAccessKey"], None,
     "Create an access key for a more privileged user and act as that user."),
    ("create_login_profile", "Set a console password for other users", ["iam:CreateLoginProfile"], None,
     "Give a more privileged user (without a password) a console password and sign in as them."),
    ("update_login_profile", "Reset other users' console passwords", ["iam:UpdateLoginProfile"], None,
     "Reset the console password of a more privileged user."),
    ("update_assume_role_policy", "Change a role's trust policy", ["iam:UpdateAssumeRolePolicy"], None,
     "Edit the trust policy of a more privileged role to name itself, then assume it (a role naming a principal in "
     "its trust policy needs no further permission in the same account)."),
    ("passrole_ec2", "Run an EC2 instance with a privileged role", ["iam:PassRole", "ec2:RunInstances"], "ec2.amazonaws.com",
     "Launch an instance with a privileged instance profile and use its credentials."),
    ("passrole_lambda_invoke", "Create and invoke a Lambda with a privileged role",
     ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "lambda.amazonaws.com",
     "Create a function that runs as a privileged role and invoke it."),
    ("passrole_lambda_esm", "Create a Lambda with a privileged role triggered by an event source",
     ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"], "lambda.amazonaws.com",
     "Create a function that runs as a privileged role and have an event source trigger it."),
    ("update_lambda_code", "Replace the code of an existing Lambda", ["lambda:UpdateFunctionCode"], None,
     "Change the code of a function whose role is more privileged. Depends on such a function existing."),
    ("passrole_cloudformation", "Create a CloudFormation stack with a privileged role",
     ["iam:PassRole", "cloudformation:CreateStack"], "cloudformation.amazonaws.com",
     "Deploy a stack that runs as a privileged role and creates resources (e.g. an admin user)."),
    ("passrole_glue", "Create a Glue dev endpoint with a privileged role",
     ["iam:PassRole", "glue:CreateDevEndpoint"], "glue.amazonaws.com",
     "Create a dev endpoint that runs as a privileged role and connect to it."),
    ("passrole_sagemaker", "Create a SageMaker notebook with a privileged role",
     ["iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"], "sagemaker.amazonaws.com",
     "Create a notebook that runs as a privileged role and open it."),
    ("ssm_send_command", "Run commands on EC2 instances", ["ssm:SendCommand"], None,
     "Run commands on an instance whose instance profile is more privileged. Depends on such an instance existing."),
]


SENSITIVE_CAP_IDS = {c[0] for c in SENSITIVE_CAPABILITIES}


def _cap_scope(c):
    return ["*"] if c["result"] == "allowed" else [p.split(" (except")[0] for p in c.get("scope", [])] or ["*"]


def gains(caller, target):
    """What `caller` would gain by acting as `target`: capabilities it lacks, or has only on fewer resources."""
    if caller.get("admin") == "admin":
        return []
    if target.get("admin") == "admin":
        return ["full administrator access"]
    mine = {c["id"]: _cap_scope(c) for c in caller.get("capabilities", []) if c["result"] in ("allowed", "scoped")}
    out = []
    for c in target.get("capabilities", []):
        if c["result"] not in ("allowed", "scoped"):
            continue
        if c["id"] not in mine:
            out.append(c["label"])
            continue
        extra = [p for p in _cap_scope(c) if not any(_contains(m, p) for m in mine[c["id"]])]
        if extra:
            out.append(f"{c['label']} on {', '.join(extra[:3])}")
    return out


def _self_gains(identity, guards):
    """What granting itself new policies would really give, given its permissions boundary and SCPs."""
    if not guards:
        return ["any permission, by granting it to itself"]
    caps = capabilities([{"effect": "Allow", "actions": ["*"], "not_actions": [], "resources": ["*"], "not_resources": [],
                          "conditional": False, "condition": None, "source": {"policy": "(new policy)"}}], guards)
    return [f"up to what its permissions boundary / SCPs allow: {g}" for g in gains(identity, {"capabilities": caps, "admin": None})]


# which resource each method's actions apply to: "target" = the target's ARN, "*" = any resource
_TARGET_ACTIONS = {
    "create_policy_version": ["iam:CreatePolicyVersion"], "set_default_policy_version": ["iam:SetDefaultPolicyVersion"],
    "attach_user_policy": ["iam:AttachUserPolicy"], "put_user_policy": ["iam:PutUserPolicy"],
    "attach_group_policy": ["iam:AttachGroupPolicy"], "put_group_policy": ["iam:PutGroupPolicy"],
    "attach_role_policy": ["iam:AttachRolePolicy", "sts:AssumeRole"], "put_role_policy": ["iam:PutRolePolicy", "sts:AssumeRole"],
    "add_user_to_group": ["iam:AddUserToGroup"], "create_access_key": ["iam:CreateAccessKey"],
    "create_login_profile": ["iam:CreateLoginProfile"], "update_login_profile": ["iam:UpdateLoginProfile"],
    "update_assume_role_policy": ["iam:UpdateAssumeRolePolicy"], "passrole_ec2": ["iam:PassRole"],
    "passrole_lambda_invoke": ["iam:PassRole"], "passrole_lambda_esm": ["iam:PassRole"],
    "passrole_cloudformation": ["iam:PassRole"], "passrole_glue": ["iam:PassRole"], "passrole_sagemaker": ["iam:PassRole"],
}


def _candidate_targets(mid, identity, identities, roles_by_service, pass_to, policies_by_arn):
    """(target dict with arn/name, gained capabilities) candidates for a method, before permission checks."""
    by_arn = {i["arn"]: i for i in identities}
    out = []
    if mid in ("create_policy_version", "set_default_policy_version"):
        for arn in sorted({src.get("policy_arn") for src in (st["source"] for st in identity["_statements"])
                           if src.get("type") == "managed" and src.get("policy_arn") and ":aws:policy/" not in src.get("policy_arn", "")}):
            out.append(({"arn": arn, "name": arn.split("/")[-1]}, ["administrator access through a rewritten policy"]))
    elif mid in ("attach_user_policy", "put_user_policy"):
        g = _self_gains(identity, identity.get("_guards"))
        if identity["kind"] == "user" and g:
            out.append(({"arn": identity["arn"], "name": identity["name"]}, g))
    elif mid in ("attach_group_policy", "put_group_policy"):
        g = _self_gains(identity, identity.get("_guards"))
        for gname in identity.get("groups", []):
            grp = next((i for i in identities if i["kind"] == "group" and i["name"] == gname), None)
            if grp and g:
                out.append(({"arn": grp["arn"], "name": gname}, g))
    elif mid in ("attach_role_policy", "put_role_policy"):
        for c in identity.get("can_assume", []):
            role = by_arn.get(c["arn"])
            g = _self_gains(identity, role.get("_guards")) if role else []
            if g:
                out.append(({"arn": c["arn"], "name": c["name"]}, [x.replace("by granting it to itself", "through a role it can assume") for x in g]))
    elif mid == "update_assume_role_policy":
        for r in identities:
            if r["kind"] == "role" and r["arn"] != identity["arn"] and not r.get("path", "").startswith("/aws-service-role/"):
                g = gains(identity, r)
                if g:
                    out.append(({"arn": r["arn"], "name": r["name"]}, g))
    elif mid == "add_user_to_group":
        if identity["kind"] == "user":
            for grp in identities:
                if grp["kind"] == "group" and grp["name"] not in identity.get("groups", []):
                    g = gains(identity, grp)
                    if g:
                        out.append(({"arn": grp["arn"], "name": grp["name"]}, g))
    elif mid in ("create_access_key", "create_login_profile", "update_login_profile"):
        for u in identities:
            if u["kind"] != "user" or u["arn"] == identity["arn"]:
                continue
            pw = (u.get("credentials") or {}).get("password_enabled")
            if (mid == "create_login_profile" and pw) or (mid == "update_login_profile" and not pw):
                continue
            g = gains(identity, u)
            if g:
                out.append(({"arn": u["arn"], "name": u["name"]}, g))
    elif pass_to:
        for r in roles_by_service.get(pass_to, []):
            if r["arn"] != identity["arn"]:
                g = gains(identity, r)
                if g:
                    out.append(({"arn": r["arn"], "name": r["name"]}, g))
    return out


_SAME_RESOURCE = {"passrole_lambda_invoke": ("lambda:CreateFunction", "lambda:InvokeFunction"),
                  "passrole_lambda_esm": ("lambda:CreateFunction", "lambda:CreateEventSourceMapping"),
                  "passrole_sagemaker": ("sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl")}


def _same_resource_possible(mid, evs):
    pair = _SAME_RESOURCE.get(mid)
    if not pair or any(a not in evs for a in pair):
        return True
    sa, sb = evs[pair[0]].get("scope") or ["*"], evs[pair[1]].get("scope") or ["*"]
    if evs[pair[0]]["result"] == "allowed":
        sa = ["*"]
    if evs[pair[1]]["result"] == "allowed":
        sb = ["*"]
    if pair[0].startswith("lambda:") and pair[1] == "lambda:CreateEventSourceMapping":
        return True  # the event-source mapping is its own resource type
    return any(_intersect(a.split(" (except")[0], b.split(" (except")[0]) is not None for a in sa for b in sb)


def escalation_paths(identity, identities, roles_by_service, policies_by_arn=None):
    """Potential escalation methods available to `identity`. Every required permission is evaluated against the
    concrete target it would be used on (honouring denies, the boundary and SCPs); a method only counts when a
    target exists that gives the identity something it does not already have."""
    if identity.get("admin") == "admin":
        return []  # already has full access; escalation adds nothing
    stmts, guards = identity["_statements"], identity.get("_guards")
    out = []
    for mid, title, needs, pass_to, how in ESCALATION_METHODS:
        any_evs = {a: evaluate(stmts, a, "*", guards) for a in needs if a not in _TARGET_ACTIONS.get(mid, [])}
        if not all(grants(e) for e in any_evs.values()):
            continue
        prereq = []
        if mid in ("set_default_policy_version", "update_lambda_code", "ssm_send_command"):
            prereq.append("Depends on resources Niagaros does not inventory yet (older policy versions, Lambda "
                          "functions or EC2 instances with privileged roles)")
        if mid in ("update_lambda_code", "ssm_send_command"):
            if not all(e["result"] in ("allowed", "scoped", "conditional") for e in any_evs.values()):
                continue
            results = {e["result"] for e in any_evs.values()}
            out.append({"method": mid, "title": title, "how": how, "required_permissions": needs,
                        "evidence": [x for e in any_evs.values() for x in e["evidence"]][:10], "targets": [],
                        "gains": ["whatever the function's or instance's role can do"], "prerequisites": prereq,
                        "confidence": "low", "result_per_action": {a: e["result"] for a, e in any_evs.items()}})
            continue
        if not _same_resource_possible(mid, any_evs):
            continue  # e.g. CreateFunction and InvokeFunction allowed only on different functions
        hits = []
        for target, gained in _candidate_targets(mid, identity, identities, roles_by_service, pass_to, policies_by_arn):
            tevs = {a: evaluate(stmts, a, target["arn"], guards) for a in _TARGET_ACTIONS.get(mid, [])}
            if not all(grants(e) for e in tevs.values()):
                continue
            if mid == "update_assume_role_policy":
                ok, _, _ = assumable_by([{"class": "same_account", "principal": identity["arn"], "conditional": False}],
                                        identity["arn"], "", evaluate(stmts, "sts:AssumeRole", target["arn"], guards))
                if not ok:
                    continue  # its own deny / an SCP would still stop it assuming the role
            hits.append((target, gained, tevs))
        if not hits:
            continue
        results = {e["result"] for e in any_evs.values()} | {e["result"] for _, _, t in hits for e in t.values()}
        if "conditional" in results:
            confidence = "low"
        elif prereq or results - {"allowed"}:
            confidence = "medium"
        else:
            confidence = "high"
        first = hits[0][2]
        out.append({
            "method": mid, "title": title, "how": how, "required_permissions": needs,
            "evidence": ([x for e in any_evs.values() for x in e["evidence"]] + [x for e in first.values() for x in e["evidence"]])[:10],
            "targets": [t["arn"] for t, _, _ in hits][:20],
            "gains": sorted({g for _, gl, _ in hits for g in gl})[:10],
            "prerequisites": prereq, "confidence": confidence,
            "result_per_action": {**{a: e["result"] for a, e in any_evs.items()}, **{a: e["result"] for a, e in first.items()}},
        })
    return out


# ── trust relationships ──────────────────────────────────────────────────────

# Positive operators that require the key to be present. ForAllValues:* is deliberately missing: it is also
# true when the key is absent, so on its own it restricts nothing.
_STRICT_OPS = {"stringequals", "stringequalsignorecase", "stringlike", "arnequals", "arnlike",
               "foranyvalue:stringequals", "foranyvalue:stringlike"}
_RESTRICTING_KEYS = {"aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:sourceaccount",
                     "aws:principalarn", "aws:sourcearn", "sts:externalid", "aws:sourceorgid"}


def _conditions(cond):
    out = []
    for op, kv in (cond or {}).items():
        if not isinstance(kv, dict):
            continue
        for k, v in kv.items():
            out.append({"op": op, "key": k.lower(), "values": _as_list(v)})
    return out


def _requires(conds, key, specific=None):
    """True when a condition with a positive string/ARN operator pins `key` to values that are not just
    wildcards (and, if given, pass `specific`). 'Null', negated operators and '*' values do not count."""
    for c in conds:
        if c["key"] != key or c["op"].lower() not in _STRICT_OPS or not c["values"]:
            continue
        vals = [v for v in c["values"] if isinstance(v, str)]
        if vals and all(v.strip("*?") for v in vals) and (specific is None or all(specific(v) for v in vals)):
            return True
    return False


def _github_sub_specific(v):
    # repo:<org>/<repo...> or repo:<org>/* — the organisation must be fixed. "repo:*" is not a restriction.
    return bool(re.match(r"^repo:[^*?/]+/", v))


def analyze_trust(role, own_account):
    """Who can assume this role, from its trust policy, with conditions judged on operator AND value."""
    out = []
    doc = role.get("AssumeRolePolicyDocument") or {}
    if isinstance(doc, str):
        doc = json.loads(doc)
    for st in _as_list(doc.get("Statement")):
        conds = _conditions(st.get("Condition"))
        display = [f"{c['op']} {c['key']} = {', '.join(map(str, c['values']))}" for c in conds]
        principal = st.get("Principal")
        items = []
        if principal == "*":
            items.append(("AWS", "*"))
        elif isinstance(principal, dict):
            for kind, vals in principal.items():
                for v in _as_list(vals):
                    items.append((kind, v))
        for kind, value in items:
            entry = {"kind": kind, "principal": value, "conditions": display, "statement": st.get("Sid"),
                     "effect": st.get("Effect", "Allow"), "conditional": bool(conds)}
            if entry["effect"] == "Deny":
                entry["class"] = "deny"
                out.append(entry)
                continue
            if kind == "Service":
                entry["class"] = "aws_service"
            elif kind == "Federated":
                if "saml-provider" in value:
                    entry["class"] = "saml_federation"
                elif value.startswith("cognito-identity"):
                    entry["class"] = "cognito_federation"
                else:
                    entry["class"] = "oidc_federation"
                    host = value.split("oidc-provider/")[-1]
                    entry["oidc_host"] = host
                    spec = _github_sub_specific if host == "token.actions.githubusercontent.com" else None
                    entry["subject_restricted"] = _requires(conds, f"{host.lower()}:sub", spec)
            elif value == "*":
                restricting = sorted({c["key"] for c in conds if c["key"] in _RESTRICTING_KEYS and _requires(conds, c["key"])})
                entry["class"] = "public_restricted" if restricting else "public"
                entry["restricted_by"] = restricting
            else:
                acct = _account_of(value)
                entry["account"] = acct
                entry["class"] = "same_account" if acct == own_account else "external_account"
                entry["external_id_required"] = _requires(conds, "sts:externalid")
                entry["org_restricted"] = _requires(conds, "aws:principalorgid") or _requires(conds, "aws:principalorgpaths")
                entry["mfa_required"] = any(c["key"] == "aws:multifactorauthpresent" and c["op"].lower() == "bool"
                                            and [str(v).lower() for v in c["values"]] == ["true"] for c in conds)
            entry["conditional"] = bool(conds)
            out.append(entry)
    return out


def _account_of(value):
    if re.fullmatch(r"\d{12}", value):
        return value
    m = re.match(r"arn:aws[a-z-]*:(?:iam|sts)::(\d{12}):", value)
    return m.group(1) if m else None


def assumable_by(role_trust, principal_arn, own_account, identity_eval):
    """Can `principal_arn` (same account) assume a role with trust `role_trust`? `identity_eval` is the
    evaluation of sts:AssumeRole on THIS role for the caller. A trust policy that names the principal is
    enough on its own unless the caller's own policies or an SCP block it; trusting the account root also
    needs an identity-policy allow. A Deny in the trust policy wins."""
    for t in role_trust:
        if t["class"] == "deny" and t["principal"] in ("*", principal_arn, own_account, f"arn:aws:iam::{own_account}:root") \
                and not t.get("conditional"):
            return False, None, False
    by = identity_eval.get("blocked_by") or ""
    # A trust policy naming an IAM *user* ARN is not limited by that user's permissions boundary (implicit
    # deny); SCPs and explicit denies still apply. For roles the boundary does apply.
    is_user = ":user/" in principal_arn
    blocked = identity_eval["result"] == "denied" or by.startswith("service control policy") or (by and not is_user)
    for t in role_trust:
        if t["class"] != "same_account":
            continue
        p = t["principal"]
        cond = t.get("conditional", False) or identity_eval["result"] == "conditional"
        if p == principal_arn and not blocked:
            return True, "named in the role's trust policy", cond
        if p in (own_account, f"arn:aws:iam::{own_account}:root") and grants(identity_eval):
            return True, "account trusted and its own policy allows sts:AssumeRole on this role", cond
    return False, None, False


# ── classification ───────────────────────────────────────────────────────────

OWNER_TAG_KEYS = ("owner", "team", "contact", "owner_email", "ownedby", "maintainer")


def owner_from_tags(tags):
    for t in tags or []:
        if t.get("Key", "").lower().replace("-", "_") in OWNER_TAG_KEYS and t.get("Value"):
            return t["Value"]
    return None


def classify(identity):
    """(classification, basis, reason). basis: observed | inferred."""
    kind = identity["kind"]
    if kind == "group":
        return "group", "observed", "IAM group"
    if kind == "user":
        cred = identity.get("credentials") or {}
        if cred.get("password_enabled"):
            return "human", "observed", "has a console password"
        if cred.get("access_keys_active"):
            return "machine", "inferred", "no console password, uses access keys"
        return "unknown", "inferred", "no console password and no active access keys"
    path = identity.get("path", "")
    if path.startswith("/aws-service-role/"):
        return "service_linked", "observed", "AWS service-linked role (managed by AWS)"
    if path.startswith("/aws-reserved/sso.amazonaws.com/"):
        return "human", "observed", "IAM Identity Center (SSO) permission set role"
    trust = identity.get("trust", [])
    if any(t["class"] == "saml_federation" for t in trust):
        return "human", "observed", "assumed through SAML federation"
    if trust and all(t["class"] in ("aws_service", "oidc_federation") for t in trust):
        return "machine", "observed", "assumed by an AWS service or workload identity"
    if any(t["class"] in ("external_account", "public", "public_restricted") for t in trust):
        return "external", "observed", "assumable from outside this account"
    return "unknown", "inferred", "assumable by other principals in this account"


# ── unused entitlements ──────────────────────────────────────────────────────

def unused_services(identity, observation_days, now=None):
    """From IAM Access Advisor (service-level). Returns dict with status + per-service detail."""
    now = now or datetime.now(timezone.utc)
    aa = identity.get("access_advisor")
    created = identity.get("created")
    if aa is None:
        return {"status": "unknown", "reason": "Access Advisor data was not collected for this identity", "services": []}
    if aa.get("error"):
        return {"status": "unknown", "reason": f"Access Advisor job did not complete ({aa['error']})", "services": []}
    if created and (now - created).days < observation_days:
        return {"status": "unknown", "reason": f"identity is younger than the {observation_days}-day observation window", "services": []}
    services = []
    for s in aa.get("services", []):
        last = s.get("last_authenticated")
        if last is None:
            state = "never_observed"
        elif (now - last).days > observation_days:
            state = "not_used_in_window"
        else:
            state = "used"
        services.append({"service": s["namespace"], "name": s.get("name"), "state": state,
                         "last_authenticated": last.isoformat() if last else None})
    granted = len(services)
    unused = [s for s in services if s["state"] != "used"]
    return {"status": "evaluated", "observation_days": observation_days, "granted_services": granted,
            "unused": unused, "used": [s for s in services if s["state"] == "used"],
            "tracking_note": "AWS tracks service access for up to 400 days; 'never observed' means no access in that period."}


# ── compliance mapping ───────────────────────────────────────────────────────

# Versioned. A finding indicates a control is at risk; it is not proof of non-compliance on its own.
COMPLIANCE = {
    "least_privilege": [("ISO 27001:2022", "A.8.2", "Privileged access rights"), ("ISO 27001:2022", "A.5.15", "Access control"),
                        ("SOC2", "CC6.3", "Role-based access, least privilege"), ("NIST CSF v2.0", "PR.AA-05", "Access permissions managed with least privilege"),
                        ("CIS Controls v8.1", "6.8", "Define and maintain role-based access control"), ("PCI DSS v4.0", "7.2.2", "Access assigned on least privilege")],
    "privileged_access": [("ISO 27001:2022", "A.8.2", "Privileged access rights"), ("SOC2", "CC6.1", "Logical access security"),
                          ("NIST CSF v2.0", "PR.AA-05", "Access permissions managed with least privilege"), ("CIS Controls v8.1", "5.4", "Restrict administrator privileges"),
                          ("PCI DSS v4.0", "7.2.2", "Access assigned on least privilege")],
    "dormant_access": [("ISO 27001:2022", "A.5.18", "Access rights (review and removal)"), ("SOC2", "CC6.2", "User registration and removal"),
                       ("NIST CSF v2.0", "PR.AA-01", "Identities and credentials managed"), ("CIS Controls v8.1", "5.3", "Disable dormant accounts"),
                       ("PCI DSS v4.0", "8.2.6", "Inactive accounts removed or disabled within 90 days")],
    "credentials": [("ISO 27001:2022", "A.5.17", "Authentication information"), ("SOC2", "CC6.1", "Logical access security"),
                    ("NIST CSF v2.0", "PR.AA-01", "Identities and credentials managed"), ("CIS Controls v8.1", "6.5", "Require MFA for administrative access"),
                    ("PCI DSS v4.0", "8.6.3", "Passwords/passphrases for application and system accounts protected")],
    "external_access": [("ISO 27001:2022", "A.5.19", "Information security in supplier relationships"), ("ISO 27001:2022", "A.5.15", "Access control"),
                        ("SOC2", "CC6.1", "Logical access security"), ("NIST CSF v2.0", "PR.AA-05", "Access permissions managed with least privilege"),
                        ("CIS Controls v8.1", "6.8", "Define and maintain role-based access control")],
    "ownership": [("ISO 27001:2022", "A.5.16", "Identity management"), ("SOC2", "CC6.2", "User registration and removal"),
                  ("NIST CSF v2.0", "PR.AA-01", "Identities and credentials managed"), ("PCI DSS v4.0", "8.6.1", "System and application accounts managed")],
    "escalation": [("ISO 27001:2022", "A.8.2", "Privileged access rights"), ("SOC2", "CC6.3", "Role-based access, least privilege"),
                   ("NIST CSF v2.0", "PR.AA-05", "Access permissions managed with least privilege"), ("CIS Controls v8.1", "5.4", "Restrict administrator privileges")],
}


def compliance_for(theme):
    return [{"framework": f, "control": c, "title": t, "mapping_version": MAPPING_VERSION} for f, c, t in COMPLIANCE.get(theme, [])]


# ── findings ─────────────────────────────────────────────────────────────────

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Built-in entitlement policies (issue #17 §14). Each can be switched off or re-rated per account.
POLICY_RULES = {
    "no_permanent_admin": ("No standing administrator access for users or non-SSO roles", "high"),
    "no_wildcard_sensitive": ("No full-service wildcards on sensitive services", "medium"),
    "machine_identity_owner": ("Machine identities must have an owner tag", "low"),
    "external_trust_controls": ("External trust requires an ExternalId or organisation condition", "high"),
    "no_public_trust": ("No role may be assumable by anyone", "critical"),
    "oidc_subject_restricted": ("Workload federation (OIDC) must restrict the subject", "critical"),
    "unused_access_review": ("Access unused during the observation window must be reviewed", "low"),
    "key_rotation": ("Active access keys are rotated within 90 days", "medium"),
    "human_mfa": ("Users with a console password have MFA", "high"),
    "no_root_keys": ("The root user has no access keys", "critical"),
    "root_usage": ("The root user is not used for routine sign-in", "medium"),
    "escalation_paths": ("No identity has a privilege-escalation path", "high"),
}


def fingerprint(account, category, arn, key=""):
    return hashlib.sha256(f"{account}|{category}|{arn}|{key}".encode()).hexdigest()[:40]


def _finding(account, rule, category, severity, title, identity, detail, recommendation, theme, key=""):
    return {
        "fingerprint": fingerprint(account, category, identity["arn"] if identity else "-", key),
        "rule": rule, "category": category, "severity": severity, "title": title,
        "identity_arn": identity["arn"] if identity else None,
        "identity_name": identity.get("name") if identity else None,
        "details": detail, "recommendation": recommendation, "compliance": compliance_for(theme),
    }


def _apply_rule(settings, rule, default_sev):
    cfg = (settings or {}).get(rule) or {}
    if cfg.get("enabled") is False:
        return None
    return cfg.get("severity") or default_sev


def disabled_rules(settings):
    return sorted(r for r, cfg in (settings or {}).items() if isinstance(cfg, dict) and cfg.get("enabled") is False)


def build_findings(account, identities, root, external_findings, settings, observation_days):
    f = []
    for i in identities:
        cls = i["classification"]
        if cls == "service_linked":
            continue  # managed by AWS; the customer cannot change these permissions
        if i.get("admin") and i["kind"] in ("user", "role") and not (cls == "human" and i.get("path", "").startswith("/aws-reserved/")):
            sev = _apply_rule(settings, "no_permanent_admin", "high" if i["admin"] == "admin" else "medium")
            if sev:
                f.append(_finding(account, "no_permanent_admin", "excessive_permissions", sev,
                                  f"{'Full' if i['admin'] == 'admin' else 'Near-full'} administrator access on {i['kind']} {i['name']}",
                                  i, {"evidence": i["admin_evidence"][:10], "basis": "calculated",
                                      "limitations": i.get("limitations", [])},
                                  _rec_admin(i, observation_days), "privileged_access"))
        for w in i.get("wildcards", []):
            if i.get("admin") == "admin":
                break
            sev = _apply_rule(settings, "no_wildcard_sensitive", "high" if w["service"] in ("iam", "sts", "kms", "organizations") else "medium")
            if sev:
                f.append(_finding(account, "no_wildcard_sensitive", "wildcard_permission", sev,
                                  f"{w['service']}:* on all resources for {i['name']}", i,
                                  {"evidence": [w["source"]], "service": w["service"], "basis": "observed"},
                                  {"current": f"Allow {w['service']}:* on Resource *",
                                   "proposed": f"Allow only the {w['service']} actions this identity needs, on the specific resources it uses",
                                   "reason": "A full-service wildcard also grants future and destructive actions.",
                                   "impact": "Calls to actions that are no longer granted will fail; check with the identity's owner first.",
                                   "confidence": "medium", "approvals": "Identity owner", "rollback": "Re-attach the previous policy version."},
                                  "least_privilege", key=w["service"]))
        for p in i.get("escalation", []):
            sev = _apply_rule(settings, "escalation_paths", {"high": "high", "medium": "medium", "low": "low"}[p["confidence"]])
            if sev:
                f.append(_finding(account, "escalation_paths", "privilege_escalation", sev,
                                  f"Potential privilege escalation: {p['title']} ({i['name']})", i,
                                  {"path": p, "basis": "calculated", "note": "Potential path; not a confirmed exploit."},
                                  {"current": "Grants " + ", ".join(p["required_permissions"]),
                                   "proposed": "Remove one of these permissions, or scope it to resources that cannot lead to more privilege",
                                   "reason": p["how"], "impact": "Workflows that legitimately use these permissions must be identified first.",
                                   "confidence": p["confidence"], "approvals": "Security owner",
                                   "rollback": "Restore the removed permission from the previous policy version."},
                                  "escalation", key=p["method"]))
        for t in i.get("trust", []):
            if t["class"] == "public":
                sev = _apply_rule(settings, "no_public_trust", "critical")
                if sev:
                    f.append(_finding(account, "no_public_trust", "external_access", sev, f"Role {i['name']} can be assumed by any AWS principal", i,
                                      {"trust": t, "basis": "observed"},
                                      _rec_trust(t, "Replace Principal \"*\" with the specific accounts or roles that need access."),
                                      "external_access", key="public"))
            elif t["class"] == "public_restricted":
                sev = _apply_rule(settings, "no_public_trust", "medium")
                if sev:
                    f.append(_finding(account, "no_public_trust", "external_access", sev,
                                      f"Role {i['name']} trusts any AWS principal that meets its conditions", i,
                                      {"trust": t, "basis": "observed",
                                       "why": "The trust policy uses Principal \"*\" and relies on conditions ("
                                              + ", ".join(t.get("restricted_by", [])) + ") to limit who can assume it. Check that they do."},
                                      _rec_trust(t, "Prefer naming the accounts or roles explicitly instead of Principal \"*\" with conditions."),
                                      "external_access", key="public_restricted"))
            elif t["class"] == "external_account" and not (t.get("external_id_required") or t.get("org_restricted")):
                sev = _apply_rule(settings, "external_trust_controls", "high")
                if sev:
                    f.append(_finding(account, "external_trust_controls", "external_access", sev,
                                      f"Role {i['name']} trusts account {t['account']} without an ExternalId or organisation condition", i,
                                      {"trust": t, "basis": "observed"},
                                      _rec_trust(t, "Add a Condition requiring sts:ExternalId (for vendors) or aws:PrincipalOrgID (for your own accounts)."),
                                      "external_access", key=t["principal"]))
            elif t["class"] == "oidc_federation" and not t.get("subject_restricted"):
                sev = _apply_rule(settings, "oidc_subject_restricted", "critical")
                if sev:
                    f.append(_finding(account, "oidc_subject_restricted", "external_access", sev,
                                      f"Role {i['name']} trusts {t.get('oidc_host')} without restricting the subject", i,
                                      {"trust": t, "basis": "observed",
                                       "why": "Without a ':sub' condition any workload of that identity provider (for GitHub: any repository) can assume the role."},
                                      _rec_trust(t, f"Add a StringLike condition on {t.get('oidc_host')}:sub limited to your repositories/workloads."),
                                      "external_access", key=t["principal"]))
        if cls == "machine" and not i.get("owner") and i["kind"] in ("user", "role"):
            sev = _apply_rule(settings, "machine_identity_owner", "low")
            if sev:
                f.append(_finding(account, "machine_identity_owner", "ownership", sev, f"Machine identity {i['name']} has no owner", i,
                                  {"basis": "observed", "checked_tags": list(OWNER_TAG_KEYS)},
                                  {"current": "No owner/team tag", "proposed": "Tag the identity with Owner=<team or person>",
                                   "reason": "Nobody is accountable for reviewing this identity's access.", "impact": "None (tags only).",
                                   "confidence": "high", "approvals": "None", "rollback": "Remove the tag."}, "ownership"))
        un = i.get("unused") or {}
        if un.get("status") == "evaluated" and un.get("unused") and (i.get("admin") or i.get("capabilities")):
            sev = _apply_rule(settings, "unused_access_review", "medium" if i.get("admin") else "low")
            if sev:
                names = sorted({u["service"] for u in un["unused"]})
                f.append(_finding(account, "unused_access_review", "unused_entitlement", sev,
                                  f"{i['name']} has access to {len(names)} service(s) not used in {observation_days} days", i,
                                  {"unused": un["unused"][:60], "observation_days": observation_days, "basis": "observed",
                                   "caution": "Infrequent but legitimate work (disaster recovery, yearly jobs, break-glass) may not show up in this window."},
                                  {"current": f"Access to {un['granted_services']} services",
                                   "proposed": "Remove access to: " + ", ".join(names[:25]) + (" …" if len(names) > 25 else ""),
                                   "reason": f"No access recorded by AWS in the last {observation_days} days.",
                                   "impact": "Anything that only runs rarely and uses these services would fail.",
                                   "confidence": "medium", "approvals": "Identity owner",
                                   "rollback": "Re-attach the previous policy version."}, "dormant_access"))
        cred = i.get("credentials") or {}
        if i["kind"] == "user":
            for k in cred.get("keys", []):
                if k["active"] and k.get("age_days") is not None and k["age_days"] > 90:
                    sev = _apply_rule(settings, "key_rotation", "medium")
                    if sev:
                        f.append(_finding(account, "key_rotation", "stale_credential", sev,
                                          f"Access key {k['slot']} of {i['name']} is {k['age_days']} days old", i,
                                          {"key": k, "basis": "observed"},
                                          {"current": f"Active key, last rotated {k.get('last_rotated')}",
                                           "proposed": "Rotate the key, or replace it with an IAM role / short-lived credentials",
                                           "reason": "Long-lived keys are the most common way AWS accounts are compromised.",
                                           "impact": "Applications using the old key must switch to the new one.",
                                           "confidence": "high", "approvals": "Identity owner",
                                           "rollback": f"aws iam update-access-key --user-name {i['name']} --access-key-id <old key> --status Active"},
                                          "credentials", key=k["slot"]))
                if k["active"] and not k.get("last_used"):
                    sev = _apply_rule(settings, "unused_access_review", "low")
                    if sev:
                        f.append(_finding(account, "unused_access_review", "unused_entitlement", sev,
                                          f"Active access key {k['slot']} of {i['name']} has no recorded use", i,
                                          {"key": k, "basis": "observed",
                                           "note": "AWS reports no last-used date. That means the key was never used, or not since AWS started tracking key use (April 2015)."},
                                          {"current": "Active, no recorded use", "proposed": "Deactivate the key (it can be re-activated)",
                                           "reason": "An unused credential is risk without benefit.", "impact": "None if it is truly unused.",
                                           "confidence": "medium", "approvals": "Identity owner",
                                           "rollback": f"aws iam update-access-key --user-name {i['name']} --access-key-id <key> --status Active"},
                                          "credentials", key="unused-" + k["slot"]))
            if cred.get("password_enabled") and not cred.get("mfa_active"):
                sev = _apply_rule(settings, "human_mfa", "high")
                if sev:
                    f.append(_finding(account, "human_mfa", "weak_authentication", sev, f"{i['name']} signs in with a password but has no MFA", i,
                                      {"basis": "observed"},
                                      {"current": "Console password without MFA", "proposed": "Enable MFA, or move this person to IAM Identity Center",
                                       "reason": "A leaked password alone gives console access.", "impact": "The user must enrol an MFA device.",
                                       "confidence": "high", "approvals": "None", "rollback": "Deactivate the MFA device."}, "credentials"))
            if cls == "human" and cred.get("password_last_used_days") is not None and cred["password_last_used_days"] > observation_days:
                sev = _apply_rule(settings, "unused_access_review", "medium")
                if sev:
                    f.append(_finding(account, "unused_access_review", "dormant_identity", sev,
                                      f"{i['name']} has not signed in for {cred['password_last_used_days']} days", i,
                                      {"basis": "observed", "password_last_used": cred.get("password_last_used")},
                                      {"current": "Console access kept", "proposed": "Disable the console password or remove the user",
                                       "reason": "Dormant accounts are easy targets and nobody notices their misuse.",
                                       "impact": "The person can no longer sign in.", "confidence": "high", "approvals": "Identity owner",
                                       "rollback": "Re-create the login profile."}, "dormant_access"))
    if root and root.get("access_keys_active"):
        sev = _apply_rule(settings, "no_root_keys", "critical")
        if sev:
            f.append(_finding(account, "no_root_keys", "stale_credential", sev, "The root user has active access keys", {"arn": f"arn:aws:iam::{account}:root", "name": "root"},
                              {"basis": "observed"},
                              {"current": "Root access keys active", "proposed": "Delete the root access keys",
                               "reason": "Root keys have unrestricted access that no policy can limit.",
                               "impact": "Anything still using them breaks; find it via CloudTrail first.",
                               "confidence": "high", "approvals": "Account owner", "rollback": "Not reversible; create new keys only if unavoidable."},
                              "credentials"))
    if root and root.get("password_last_used_days") is not None and root["password_last_used_days"] <= observation_days:
        sev = _apply_rule(settings, "root_usage", "medium")
        if sev:
            f.append(_finding(account, "root_usage", "privileged_use", sev,
                              f"The root user signed in {root['password_last_used_days']} day(s) ago",
                              {"arn": f"arn:aws:iam::{account}:root", "name": "root"},
                              {"basis": "observed", "password_last_used": root.get("password_last_used"), "mfa_active": root.get("mfa_active")},
                              {"current": "Root user used for day-to-day sign-in",
                               "proposed": "Use the root user only for the few tasks that require it; use named admin identities otherwise",
                               "reason": "Root activity cannot be limited by any policy and is hard to attribute to a person.",
                               "impact": "None for existing workloads.", "confidence": "high", "approvals": "Account owner",
                               "rollback": "Not applicable."}, "privileged_access"))
    for x in external_findings or []:
        if x.get("resource_type") == "AWS::IAM::Role":
            continue  # role trust is analysed above from the trust policy itself (incl. SSO/SAML); avoid duplicates
        sev = _apply_rule(settings, "external_trust_controls", "high" if x.get("is_public") else "medium")
        if not sev:
            continue
        f.append(_finding(account, "external_trust_controls", "external_resource_access", sev,
                          f"{x['resource_type']} {x['resource']} is accessible {'publicly' if x.get('is_public') else 'from outside the account'}",
                          {"arn": x["resource"], "name": x["resource"]},
                          {"basis": "observed", "source": "IAM Access Analyzer", "region": x.get("region"), "principal": x.get("principal"),
                           "actions": x.get("actions"), "condition": x.get("condition"), "analyzed_at": x.get("analyzed_at")},
                          {"current": "Resource policy grants access outside the zone of trust",
                           "proposed": "Remove the external principal from the resource policy, or archive the finding in Access Analyzer if it is intended",
                           "reason": "External access is a data-exposure path.", "impact": "The external party loses access.",
                           "confidence": "high", "approvals": "Resource owner", "rollback": "Restore the previous resource policy."},
                          "external_access", key=x.get("id", "")))
    return f


def _rec_admin(i, days):
    un = i.get("unused") or {}
    used = sorted({u["service"] for u in un.get("used", [])}) if un.get("status") == "evaluated" else []
    if used:
        proposed = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [f"{s}:*" for s in used], "Resource": "*"}]}
        return {"current": "AdministratorAccess-level permissions", "proposed_policy": proposed,
                "proposed": f"Replace with access to the {len(used)} services used in the last {days} days, then narrow to actions with IAM Access Analyzer policy generation",
                "reason": "Standing administrator access gives an attacker everything if this identity is compromised.",
                "impact": "Anything that needs a service not used in the window (DR, yearly jobs) will fail.",
                "confidence": "medium", "approvals": "Security owner and identity owner",
                "rollback": "Re-attach the previous policy; keep the old policy ARN in the change ticket."}
    if un.get("status") == "evaluated":
        return {"current": "AdministratorAccess-level permissions",
                "proposed": f"No AWS service use was recorded in {days} days: remove the administrator access, and remove the identity if nobody needs it",
                "reason": "Standing administrator access that is not used is pure risk.",
                "impact": "Rare tasks (break-glass, yearly jobs) would need another route; for people use time-limited admin roles (IAM Identity Center).",
                "confidence": "medium", "approvals": "Security owner and identity owner",
                "rollback": "Re-attach the previous policy; keep the old policy ARN in the change ticket."}
    return {"current": "AdministratorAccess-level permissions",
            "proposed": "Replace with a scoped policy; for people use time-limited admin roles (e.g. IAM Identity Center) instead of standing admin",
            "reason": "Standing administrator access gives an attacker everything if this identity is compromised.",
            "impact": "Not enough activity data to propose a scoped policy safely.", "confidence": "low",
            "approvals": "Security owner and identity owner", "rollback": "Re-attach the previous policy."}


def _rec_trust(t, proposed):
    return {"current": f"Trust: {t['kind']} {t['principal']}" + (f" with conditions {', '.join(t['conditions'])}" if t["conditions"] else " without conditions"),
            "proposed": proposed, "reason": "The trust policy decides who outside the account can act as this role.",
            "impact": "Principals not matching the new condition can no longer assume the role.",
            "confidence": "high", "approvals": "Role owner", "rollback": "Restore the previous trust policy (iam:UpdateAssumeRolePolicy)."}


# ── risk score ───────────────────────────────────────────────────────────────

def risk(identity, findings):
    """0-100 prioritisation aid with the reasons that make it up. Never shown without its reasons."""
    reasons = []
    def add(points, text):
        reasons.append({"points": points, "reason": text})
    if identity.get("admin") == "admin":
        add(40, "full administrator access")
    elif identity.get("admin") == "near_admin":
        add(30, "near-full administrator access")
    caps = {c["id"] for c in identity.get("capabilities", [])}
    if "iam_write" in caps:
        add(15, "can change IAM permissions")
    if caps & {"secrets_read", "kms_decrypt", "data_read"}:
        add(10, "can read sensitive data or secrets")
    if "defense_evasion" in caps:
        add(10, "can turn off logging or threat detection")
    mine = [f for f in findings if f["identity_arn"] == identity["arn"]]
    cats = {f["category"] for f in mine}
    if "privilege_escalation" in cats:
        add(20, "has a potential privilege-escalation path")
    if any(f["category"] == "external_access" and f["severity"] == "critical" for f in mine):
        add(40, "can be assumed from outside without restriction")
    elif "external_access" in cats:
        add(20, "trusted by another account without controls")
    if "weak_authentication" in cats:
        add(15, "password without MFA")
    if cats & {"unused_entitlement", "dormant_identity"}:
        add(5, "holds access it does not use")
    if "stale_credential" in cats:
        add(10, "long-lived or unused access keys")
    if identity["classification"] == "service_linked":
        reasons = [{"points": 0, "reason": "service-linked role managed by AWS"}]
    score = min(100, sum(r["points"] for r in reasons))
    sev = "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"
    return score, sev, reasons


# ── orchestration ────────────────────────────────────────────────────────────

def analyze(raw, account, observation_days=90, settings=None, now=None):
    """raw = ciem_collector output. Returns (identities, findings, summary)."""
    now = now or datetime.now(timezone.utc)
    policies = {p["Arn"]: p for p in raw.get("policies", [])}

    def managed_statements(arns, via):
        out = []
        for arn in arns:
            p = policies.get(arn)
            if p is None:
                continue
            out += normalize_statements(p["document"], {"policy": p["name"], "policy_arn": arn, "type": "managed", "via": via})
        return out

    groups = {}
    for g in raw.get("groups", []):
        st = managed_statements([a["PolicyArn"] for a in g.get("AttachedManagedPolicies", [])], f"group {g['GroupName']}")
        for ip in g.get("GroupPolicyList", []):
            st += normalize_statements(ip["PolicyDocument"], {"policy": ip["PolicyName"], "type": "inline", "via": f"group {g['GroupName']}"})
        groups[g["GroupName"]] = {"arn": g["Arn"], "name": g["GroupName"], "statements": st,
                                  "policies": [a["PolicyName"] for a in g.get("AttachedManagedPolicies", [])] + [p["PolicyName"] for p in g.get("GroupPolicyList", [])]}

    creds = raw.get("credential_report", {})
    aa = raw.get("access_advisor", {})
    identities = []

    for u in raw.get("users", []):
        st = managed_statements([a["PolicyArn"] for a in u.get("AttachedManagedPolicies", [])], "direct")
        for ip in u.get("UserPolicyList", []):
            st += normalize_statements(ip["PolicyDocument"], {"policy": ip["PolicyName"], "type": "inline", "via": "direct"})
        member_of = u.get("GroupList", [])
        for gname in member_of:
            st += groups.get(gname, {}).get("statements", [])
        boundary = None
        if u.get("PermissionsBoundary"):
            boundary = managed_statements([u["PermissionsBoundary"]["PermissionsBoundaryArn"]], "permissions boundary")
        identities.append({
            "kind": "user", "arn": u["Arn"], "name": u["UserName"], "path": u.get("Path", "/"), "created": u.get("CreateDate"),
            "tags": u.get("Tags", []), "groups": member_of,
            "policies": [a["PolicyName"] for a in u.get("AttachedManagedPolicies", [])] + [p["PolicyName"] for p in u.get("UserPolicyList", [])],
            "boundary_arn": (u.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
            "credentials": creds.get(u["UserName"], {}), "access_advisor": aa.get(u["Arn"]),
            "_statements": st, "_boundary": boundary,
        })
    for r in raw.get("roles", []):
        st = managed_statements([a["PolicyArn"] for a in r.get("AttachedManagedPolicies", [])], "direct")
        for ip in r.get("RolePolicyList", []):
            st += normalize_statements(ip["PolicyDocument"], {"policy": ip["PolicyName"], "type": "inline", "via": "direct"})
        boundary = None
        if r.get("PermissionsBoundary"):
            boundary = managed_statements([r["PermissionsBoundary"]["PermissionsBoundaryArn"]], "permissions boundary")
        last = (r.get("RoleLastUsed") or {}).get("LastUsedDate")
        identities.append({
            "kind": "role", "arn": r["Arn"], "name": r["RoleName"], "path": r.get("Path", "/"), "created": r.get("CreateDate"),
            "tags": r.get("Tags", []), "policies": [a["PolicyName"] for a in r.get("AttachedManagedPolicies", [])] + [p["PolicyName"] for p in r.get("RolePolicyList", [])],
            "boundary_arn": (r.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
            "trust": analyze_trust(r, account), "last_used": last, "last_used_region": (r.get("RoleLastUsed") or {}).get("Region"),
            "access_advisor": aa.get(r["Arn"]), "_statements": st, "_boundary": boundary,
        })
    for gname, g in groups.items():
        identities.append({"kind": "group", "arn": g["arn"], "name": gname, "path": "/", "policies": g["policies"],
                           "members": [u["name"] for u in identities if u["kind"] == "user" and gname in u.get("groups", [])],
                           "_statements": g["statements"], "_boundary": None})

    scp_guards = []
    for lvl in raw.get("scp_levels") or []:
        lst = []
        for pdoc in lvl.get("policies", []):
            lst += normalize_statements(pdoc["document"], {"policy": pdoc["name"], "type": "scp", "via": f"SCP on {lvl['target']}"})
        scp_guards.append((f"service control policy ({lvl['target']})", lst))
    for i in identities:
        g = list(scp_guards) if i["kind"] != "group" and not i.get("path", "").startswith("/aws-service-role/") else []
        if i.get("_boundary") is not None:
            g.insert(0, ("permissions boundary", i["_boundary"]))
        i["_guards"] = g or None

    global_limits = list(raw.get("limitations", []))
    for i in identities:
        i["admin"], i["admin_evidence"] = admin_status(i["_statements"], i["_guards"])
        i["wildcards"] = service_wildcards(i["_statements"])
        i["capabilities"] = capabilities(i["_statements"], i["_guards"])
        i["owner"] = owner_from_tags(i.get("tags"))
        i["classification"], i["classification_basis"], i["classification_reason"] = classify(i)
        i["limitations"] = list(global_limits)
        if any(s["conditional"] for s in i["_statements"]):
            i["limitations"].append("Some statements have conditions; results that depend on them are marked 'conditional'.")
        if i["kind"] != "group":
            i["unused"] = unused_services(i, observation_days, now)

    roles = [i for i in identities if i["kind"] == "role"]
    roles_by_service = {}
    for r in roles:
        for t in r.get("trust", []):
            if t["class"] == "aws_service":
                roles_by_service.setdefault(t["principal"], []).append(r)
    for i in identities:
        if i["kind"] == "group":
            continue
        i["can_assume"] = []
        for r in roles:
            if r["arn"] == i["arn"] or r.get("path", "").startswith("/aws-service-role/"):
                continue
            ev = evaluate(i["_statements"], "sts:AssumeRole", r["arn"], i["_guards"])
            ok, how, cond = assumable_by(r.get("trust", []), i["arn"], account, ev)
            if ok:
                i["can_assume"].append({"arn": r["arn"], "name": r["name"], "how": how, "conditional": cond,
                                        "target_admin": r.get("admin")})
        admin_targets = [c for c in i["can_assume"] if c["target_admin"] == "admin"]
        if admin_targets and i.get("admin") != "admin":
            i.setdefault("_extra_paths", []).append({
                "method": "assume_admin_role", "title": "Assume an administrator role",
                "how": "Assume a role in this account that has full administrator access.",
                "required_permissions": ["sts:AssumeRole"], "evidence": [], "gains": ["full administrator access"],
                "targets": [c["arn"] for c in admin_targets],
                "prerequisites": [], "confidence": "low" if all(c["conditional"] for c in admin_targets) else "high",
                "result_per_action": {}})
    for i in identities:
        if i["kind"] == "group" or i["classification"] == "service_linked":
            i["escalation"] = []   # groups act through members; service-linked roles are managed by AWS
            i.pop("_extra_paths", None)
            continue
        i["escalation"] = escalation_paths(i, identities, roles_by_service) + i.pop("_extra_paths", [])

    findings = build_findings(account, identities, raw.get("root"), raw.get("external_access"), settings, observation_days)
    for i in identities:
        i["risk_score"], i["risk_severity"], i["risk_reasons"] = risk(i, findings)

    summary = {
        "identities": sum(1 for i in identities if i["kind"] != "group"),
        "human": sum(1 for i in identities if i["classification"] == "human"),
        "machine": sum(1 for i in identities if i["classification"] == "machine"),
        "service_linked": sum(1 for i in identities if i["classification"] == "service_linked"),
        "external_roles": sum(1 for i in identities if i["classification"] == "external"),
        "unknown": sum(1 for i in identities if i["classification"] == "unknown"),
        "groups": sum(1 for i in identities if i["kind"] == "group"),
        "policies": len(policies),
        "admins": sum(1 for i in identities if i.get("admin") == "admin" and i["kind"] != "group"),
        "privileged": sum(1 for i in identities if i["kind"] != "group" and (i.get("admin") or any(c["category"] == "identity" for c in i["capabilities"]))),
        "escalation_paths": sum(len(i["escalation"]) for i in identities),
        "external_trusts": sum(1 for i in identities for t in i.get("trust", []) if t["class"] in ("external_account", "public", "public_restricted", "oidc_federation")),
        "unused_evaluated": sum(1 for i in identities if (i.get("unused") or {}).get("status") == "evaluated"),
        "unused_unknown": sum(1 for i in identities if (i.get("unused") or {}).get("status") == "unknown"),
        "machine_without_owner": sum(1 for i in identities if i["classification"] == "machine" and not i.get("owner")),
        "findings_by_severity": {s: sum(1 for f in findings if f["severity"] == s) for s in ("critical", "high", "medium", "low")},
        "external_resource_findings": sum(1 for x in raw.get("external_access") or [] if x.get("resource_type") != "AWS::IAM::Role"),
        "observation_days": observation_days, "engine_version": ENGINE_VERSION, "mapping_version": MAPPING_VERSION,
    }
    return identities, findings, summary


def least_privilege_score(identities, findings):
    """Share of non-AWS-managed identities without an open excessive-permission, escalation or external-trust
    finding. Explained by its definition, shown as a ratio, not a grade."""
    scope = [i for i in identities if i["kind"] != "group" and i["classification"] != "service_linked"]
    bad = {f["identity_arn"] for f in findings if f["category"] in ("excessive_permissions", "wildcard_permission", "privilege_escalation", "external_access")}
    ok = sum(1 for i in scope if i["arn"] not in bad)
    return {"compliant": ok, "total": len(scope), "pct": round(100 * ok / len(scope)) if scope else None,
            "definition": "Identities (excluding AWS service-linked roles) without excessive-permission, wildcard, escalation or unrestricted external-trust findings."}


def public_view(identity):
    """Identity as stored/returned: internal fields stripped, datetimes as ISO strings."""
    out = {k: v for k, v in identity.items() if not k.startswith("_")}
    for k in ("created", "last_used"):
        if isinstance(out.get(k), datetime):
            out[k] = out[k].isoformat()
    return out
