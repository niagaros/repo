"""CIEM engine (issue #17): policy evaluation, escalation paths, trust analysis, unused access and findings.
Offline: input is shaped exactly like GetAccountAuthorizationDetails / credential report / Access Advisor output."""
from datetime import datetime, timedelta, timezone

import pytest

from collectors.aws.scanner import ciem_engine as E

pytestmark = [pytest.mark.flow("E2E-CIEM-001"), pytest.mark.severity("P1")]

ACCT = "111122223333"
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)
ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def st(doc, name="p"):
    return E.normalize_statements(doc, {"policy": name})


def stmt(effect, action, resource="*", condition=None, not_action=None):
    s = {"Effect": effect, "Resource": resource}
    if not_action:
        s["NotAction"] = not_action
    else:
        s["Action"] = action
    if condition:
        s["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [s]}


# ── evaluate ────────────────────────────────────────────────────────────────

def test_unconditional_allow_on_all_resources_is_allowed():
    assert E.evaluate(st(stmt("Allow", "s3:*")), "s3:GetObject")["result"] == "allowed"


def test_explicit_deny_wins_over_allow():
    s = st(ADMIN_DOC) + st(stmt("Deny", "iam:*"), "deny")
    r = E.evaluate(s, "iam:CreateUser")
    assert r["result"] == "denied" and r["evidence"][0]["policy"] == "deny"


def test_conditional_allow_is_not_reported_as_allowed():
    s = st(stmt("Allow", "s3:GetObject", condition={"Bool": {"aws:SecureTransport": "true"}}))
    assert E.evaluate(s, "s3:GetObject")["result"] == "conditional"


def test_allow_on_specific_resources_is_scoped():
    s = st(stmt("Allow", "s3:GetObject", "arn:aws:s3:::bucket/*"))
    assert E.evaluate(s, "s3:GetObject")["result"] == "scoped"
    assert E.evaluate(s, "s3:GetObject", "arn:aws:s3:::bucket/key")["result"] == "allowed"
    assert E.evaluate(s, "s3:GetObject", "arn:aws:s3:::other/key")["result"] == "not_allowed"


def test_not_action_allow_covers_everything_except_the_listed_actions():
    s = st(stmt("Allow", None, not_action=["iam:*"]))
    assert E.evaluate(s, "s3:DeleteBucket")["result"] == "allowed"
    assert E.evaluate(s, "iam:CreateUser")["result"] == "not_allowed"


def test_permissions_boundary_and_scp_can_only_remove_access():
    s = st(ADMIN_DOC)
    boundary = ("permissions boundary", st(stmt("Allow", "s3:*")))
    assert E.evaluate(s, "s3:GetObject", "*", [boundary])["result"] == "allowed"
    assert E.evaluate(s, "iam:CreateUser", "*", [boundary])["result"] == "not_allowed"
    scp = ("service control policy (r-1)", st(ADMIN_DOC) + st(stmt("Deny", "organizations:LeaveOrganization")))
    r = E.evaluate(s, "organizations:LeaveOrganization", "*", [scp])
    assert r["result"] == "denied"
    narrow_scp = ("service control policy (ou-1)", st(stmt("Allow", "ec2:*")))
    r = E.evaluate(s, "s3:GetObject", "*", [narrow_scp])
    assert r["result"] == "not_allowed" and r["blocked_by"].startswith("service control policy")


def test_admin_detection_requires_full_access_to_survive_denies():
    assert E.admin_status(st(ADMIN_DOC))[0] == "admin"
    assert E.admin_status(st(ADMIN_DOC) + st(stmt("Deny", "iam:*")))[0] == "near_admin"
    assert E.admin_status(st(stmt("Allow", None, not_action=["iam:*"])))[0] == "near_admin"
    assert E.admin_status(st(stmt("Allow", "s3:*")))[0] is None


def test_service_wildcards_only_for_unconditional_all_resource_statements():
    w = E.service_wildcards(st(stmt("Allow", ["kms:*", "logs:*"])))
    assert [x["service"] for x in w] == ["kms"]  # logs is not a sensitive service
    assert E.service_wildcards(st(stmt("Allow", "kms:*", "arn:aws:kms:eu-west-1:1:key/x"))) == []


# ── trust ───────────────────────────────────────────────────────────────────

def role(name, trust_principal, condition=None, path="/", policies=None, inline=None, tags=None):
    s = {"Effect": "Allow", "Principal": trust_principal, "Action": "sts:AssumeRole"}
    if condition:
        s["Condition"] = condition
    return {"RoleName": name, "Arn": f"arn:aws:iam::{ACCT}:role{path}{name}", "Path": path,
            "CreateDate": NOW - timedelta(days=400), "AssumeRolePolicyDocument": {"Statement": [s]},
            "AttachedManagedPolicies": policies or [], "RolePolicyList": inline or [], "Tags": tags or []}


def test_trust_classification():
    t = E.analyze_trust(role("x", "*"), ACCT)
    assert t[0]["class"] == "public"
    t = E.analyze_trust(role("x", {"AWS": "arn:aws:iam::999988887777:root"}), ACCT)[0]
    assert t["class"] == "external_account" and not t["external_id_required"]
    t = E.analyze_trust(role("x", {"AWS": "999988887777"}, {"StringEquals": {"sts:ExternalId": "abc"}}), ACCT)[0]
    assert t["external_id_required"]
    t = E.analyze_trust(role("x", {"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
                             {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}), ACCT)[0]
    assert t["class"] == "oidc_federation" and not t["subject_restricted"]
    t = E.analyze_trust(role("x", {"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
                             {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:org/app:*"}}), ACCT)[0]
    assert t["subject_restricted"]


NO = {"result": "not_allowed", "blocked_by": None}
YES = {"result": "allowed", "blocked_by": None}


def test_named_principal_can_assume_without_identity_policy_but_root_trust_needs_one():
    trust = E.analyze_trust(role("x", {"AWS": f"arn:aws:iam::{ACCT}:user/alice"}), ACCT)
    assert E.assumable_by(trust, f"arn:aws:iam::{ACCT}:user/alice", ACCT, NO)[0]
    assert not E.assumable_by(trust, f"arn:aws:iam::{ACCT}:user/alice", ACCT, {"result": "denied"})[0]  # own explicit deny wins
    assert not E.assumable_by(trust, f"arn:aws:iam::{ACCT}:user/alice", ACCT, {"result": "not_allowed", "blocked_by": "service control policy (r)"})[0]
    root_trust = E.analyze_trust(role("x", {"AWS": f"arn:aws:iam::{ACCT}:root"}), ACCT)
    assert not E.assumable_by(root_trust, f"arn:aws:iam::{ACCT}:user/bob", ACCT, NO)[0]
    assert E.assumable_by(root_trust, f"arn:aws:iam::{ACCT}:user/bob", ACCT, YES)[0]


def test_trust_policy_deny_wins():
    r = role("x", {"AWS": f"arn:aws:iam::{ACCT}:user/alice"})
    r["AssumeRolePolicyDocument"]["Statement"].append({"Effect": "Deny", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:user/alice"}, "Action": "sts:AssumeRole"})
    assert not E.assumable_by(E.analyze_trust(r, ACCT), f"arn:aws:iam::{ACCT}:user/alice", ACCT, YES)[0]


# ── review round 1: semantics that must not over- or understate access ─────

def test_not_resource_is_really_evaluated():
    s = st({"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "NotResource": f"arn:aws:iam::{ACCT}:role/admin"}]})
    assert E.evaluate(s, "iam:PassRole", f"arn:aws:iam::{ACCT}:role/admin")["result"] == "not_allowed"
    assert E.evaluate(s, "iam:PassRole", f"arn:aws:iam::{ACCT}:role/app")["result"] == "allowed"
    assert E.evaluate(s, "iam:PassRole")["result"] == "scoped"
    d = st(ADMIN_DOC) + st({"Statement": [{"Effect": "Deny", "Action": "iam:PassRole", "NotResource": f"arn:aws:iam::{ACCT}:role/safe"}]})
    assert E.evaluate(d, "iam:PassRole", f"arn:aws:iam::{ACCT}:role/admin")["result"] == "denied"


def test_resource_limited_not_action_does_not_grant_other_services():
    s = st({"Statement": [{"Effect": "Allow", "NotAction": "s3:DeleteObject", "Resource": "arn:aws:s3:::a/*"}]})
    assert E.evaluate(s, "iam:CreateAccessKey")["result"] == "not_allowed"
    assert E.evaluate(s, "s3:GetObject")["result"] == "scoped"


def test_resource_scopes_are_intersected_with_the_boundary_and_deny():
    s = st(stmt("Allow", "s3:GetObject", "arn:aws:s3:::a/*"))
    boundary = ("permissions boundary", st(stmt("Allow", "s3:GetObject", "arn:aws:s3:::b/*")))
    assert E.evaluate(s, "s3:GetObject", "*", [boundary])["result"] == "not_allowed"
    both = st(stmt("Allow", "s3:GetObject", "arn:aws:s3:::a/*")) + st(stmt("Deny", "s3:GetObject", "arn:aws:s3:::a/*"))
    assert E.evaluate(both, "s3:GetObject")["result"] == "denied"
    wide = ("permissions boundary", st(stmt("Allow", "s3:*")))
    r = E.evaluate(s, "s3:GetObject", "*", [wide])
    assert r["result"] == "scoped" and r["scope"] == ["arn:aws:s3:::a/*"]


def test_resources_are_case_sensitive_actions_are_not():
    s = st(stmt("Allow", "S3:GetObject", "arn:aws:s3:::bucket/Key"))
    assert E.evaluate(s, "s3:getobject", "arn:aws:s3:::bucket/Key")["result"] == "allowed"
    assert E.evaluate(s, "s3:GetObject", "arn:aws:s3:::bucket/key")["result"] == "not_allowed"


def test_admin_is_not_claimed_when_anything_narrows_it():
    assert E.admin_status(st(ADMIN_DOC) + st(stmt("Deny", "*")))[0] is None
    assert E.admin_status(st(ADMIN_DOC), [("permissions boundary", st(stmt("Allow", "s3:GetObject")))])[0] is None
    assert E.admin_status(st(ADMIN_DOC) + st(stmt("Deny", "iam:PassRole")))[0] == "near_admin"


def test_trust_conditions_are_judged_on_their_values():
    gh = f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"
    t = E.analyze_trust(role("x", {"Federated": gh}, {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:*"}}), ACCT)[0]
    assert not t["subject_restricted"]
    t = E.analyze_trust(role("x", {"Federated": gh}, {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*"}}), ACCT)[0]
    assert t["subject_restricted"]
    t = E.analyze_trust(role("x", {"AWS": "999988887777"}, {"Null": {"sts:ExternalId": "false"}}), ACCT)[0]
    assert not t["external_id_required"]
    t = E.analyze_trust(role("x", {"AWS": "999988887777"}, {"StringEquals": {"sts:ExternalId": "*"}}), ACCT)[0]
    assert not t["external_id_required"]
    t = E.analyze_trust(role("x", "*", {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}), ACCT)[0]
    assert t["class"] == "public_restricted" and t["restricted_by"] == ["aws:principalorgid"]


# ── full analysis on a small account ────────────────────────────────────────

def managed(name, doc, aws=False):
    arn = f"arn:aws:iam::aws:policy/{name}" if aws else f"arn:aws:iam::{ACCT}:policy/{name}"
    return {"Arn": arn, "name": name, "document": doc, "aws_managed": aws}


def user(name, policies=None, inline=None, groups=None, tags=None):
    return {"UserName": name, "Arn": f"arn:aws:iam::{ACCT}:user/{name}", "Path": "/", "CreateDate": NOW - timedelta(days=500),
            "AttachedManagedPolicies": [{"PolicyName": p["name"], "PolicyArn": p["Arn"]} for p in policies or []],
            "UserPolicyList": inline or [], "GroupList": groups or [], "Tags": tags or []}


def advisor(*services_last):
    return {"services": [{"namespace": ns, "name": ns, "last_authenticated": last} for ns, last in services_last]}


@pytest.fixture
def account():
    admin_p = managed("AdministratorAccess", ADMIN_DOC, aws=True)
    keys_p = managed("KeyMaker", stmt("Allow", "iam:CreateAccessKey"))
    pass_p = managed("Deployer", {"Statement": [
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{ACCT}:role/lambda-admin"},
        {"Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}]})
    scoped_pass = managed("SafeDeployer", {"Statement": [
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{ACCT}:role/lambda-small"},
        {"Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}]})
    secrets_p = managed("SecretsAll", stmt("Allow", "secretsmanager:*"))
    empty_pass = managed("EmptyDeployer", {"Statement": [
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{ACCT}:role/lambda-empty"},
        {"Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}]})
    self_keys = managed("SelfKeys", stmt("Allow", "iam:CreateAccessKey", f"arn:aws:iam::{ACCT}:user/self-keys"))
    raw = {
        "policies": [admin_p, keys_p, pass_p, scoped_pass, secrets_p, empty_pass, self_keys],
        "users": [
            user("alice-admin", [admin_p]),
            user("bob", [keys_p]),
            user("ci-deployer", [pass_p]),
            user("safe-deployer", [scoped_pass]),
            user("empty-deployer", [empty_pass]),
            user("self-keys", [self_keys]),
        ],
        "groups": [],
        "roles": [
            role("lambda-admin", {"Service": "lambda.amazonaws.com"}, policies=[{"PolicyName": "AdministratorAccess", "PolicyArn": admin_p["Arn"]}]),
            role("lambda-small", {"Service": "lambda.amazonaws.com"}, policies=[{"PolicyName": "SecretsAll", "PolicyArn": secrets_p["Arn"]}],
                 tags=[{"Key": "Owner", "Value": "platform"}]),
            role("lambda-empty", {"Service": "lambda.amazonaws.com"}),
            role("vendor", {"AWS": "arn:aws:iam::999988887777:root"}),
            role("vendor-ok", {"AWS": "arn:aws:iam::999988887777:root"}, {"StringEquals": {"sts:ExternalId": "x"}}),
            role("gha", {"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"}),
            role("AWSServiceRoleForSupport", {"Service": "support.amazonaws.com"}, path="/aws-service-role/support.amazonaws.com/",
                 policies=[{"PolicyName": "AdministratorAccess", "PolicyArn": admin_p["Arn"]}]),
            role("AWSReservedSSO_Admin_123", {"Federated": f"arn:aws:iam::{ACCT}:saml-provider/AWSSSO_x"},
                 path="/aws-reserved/sso.amazonaws.com/", policies=[{"PolicyName": "AdministratorAccess", "PolicyArn": admin_p["Arn"]}]),
        ],
        "credential_report": {
            "alice-admin": {"password_enabled": True, "mfa_active": False, "password_last_used_days": 200, "keys": [], "access_keys_active": False},
            "bob": {"password_enabled": False, "mfa_active": False, "keys": [
                {"slot": "1", "active": True, "age_days": 400, "last_rotated": "2025-09-14", "last_used": "2026-10-01"},
                {"slot": "2", "active": True, "age_days": 10, "last_rotated": "2026-10-09", "last_used": None}],
                "access_keys_active": True},
            "ci-deployer": {"password_enabled": False, "keys": [], "access_keys_active": False},
            "safe-deployer": {"password_enabled": False, "keys": [], "access_keys_active": False},
        },
        "root": {"access_keys_active": True, "password_last_used_days": 2},
        "access_advisor": {
            f"arn:aws:iam::{ACCT}:user/alice-admin": advisor(("s3", NOW - timedelta(days=3)), ("ec2", NOW - timedelta(days=200)), ("iam", None)),
            f"arn:aws:iam::{ACCT}:role/lambda-small": {"error": "timeout"},
        },
        "external_access": [
            {"id": "aa1", "resource": "arn:aws:s3:::public-bucket", "resource_type": "AWS::S3::Bucket", "principal": {"AWS": "*"}, "is_public": True},
            {"id": "aa2", "resource": f"arn:aws:iam::{ACCT}:role/AWSReservedSSO_Admin_123", "resource_type": "AWS::IAM::Role", "is_public": False},
        ],
        "limitations": ["example limitation"],
    }
    return E.analyze(raw, ACCT, 90, {}, now=NOW)


def by_name(ids, name):
    return next(i for i in ids if i["name"] == name)


def test_classification(account):
    ids, _, _ = account
    assert by_name(ids, "alice-admin")["classification"] == "human"
    bob = by_name(ids, "bob")
    assert (bob["classification"], bob["classification_basis"]) == ("machine", "inferred")
    assert by_name(ids, "AWSServiceRoleForSupport")["classification"] == "service_linked"
    assert by_name(ids, "AWSReservedSSO_Admin_123")["classification"] == "human"
    assert by_name(ids, "lambda-admin")["classification"] == "machine"
    assert by_name(ids, "vendor")["classification"] == "external"


def test_unused_needs_real_telemetry(account):
    ids, _, _ = account
    alice = by_name(ids, "alice-admin")["unused"]
    states = {s["service"]: s["state"] for s in alice["unused"] + alice["used"]}
    assert states == {"s3": "used", "ec2": "not_used_in_window", "iam": "never_observed"}
    assert by_name(ids, "lambda-small")["unused"]["status"] == "unknown"   # Access Advisor job failed
    assert by_name(ids, "bob")["unused"]["status"] == "unknown"            # no data collected


def test_escalation_paths(account):
    ids, findings, _ = account
    bob = by_name(ids, "bob")
    ck = next(p for p in bob["escalation"] if p["method"] == "create_access_key")
    assert f"arn:aws:iam::{ACCT}:user/alice-admin" in ck["targets"]
    ci = by_name(ids, "ci-deployer")
    pl = next(p for p in ci["escalation"] if p["method"] == "passrole_lambda_invoke")
    assert pl["targets"] == [f"arn:aws:iam::{ACCT}:role/lambda-admin"] and pl["confidence"] == "high"
    # PassRole to a role that can read secrets the deployer cannot: still a real gain, so a path (review round 1)
    sp = next(p for p in by_name(ids, "safe-deployer")["escalation"] if p["method"] == "passrole_lambda_invoke")
    assert sp["targets"] == [f"arn:aws:iam::{ACCT}:role/lambda-small"] and "Read secrets and secure parameters" in sp["gains"]
    # a role that gives nothing new is not a path
    assert not any(p["method"].startswith("passrole") for p in by_name(ids, "empty-deployer")["escalation"])
    # CreateAccessKey only on itself: no path to other users
    assert not [p for p in by_name(ids, "self-keys")["escalation"] if p["method"] == "create_access_key"]
    # an administrator gains nothing from escalation
    assert by_name(ids, "alice-admin")["escalation"] == []
    assert any(f["category"] == "privilege_escalation" and f["identity_name"] == "ci-deployer" for f in findings)


def test_findings_cover_the_issue_scenarios(account):
    _, findings, summary = account
    titles = {f["rule"]: f for f in findings}
    by = lambda rule, name: [f for f in findings if f["rule"] == rule and f["identity_name"] == name]
    assert by("no_permanent_admin", "alice-admin")[0]["severity"] == "high"
    assert not by("no_permanent_admin", "AWSReservedSSO_Admin_123")   # SSO sessions are time-limited by design
    assert not [f for f in findings if f["identity_name"] == "AWSServiceRoleForSupport"]  # AWS-managed
    assert by("external_trust_controls", "vendor") and not by("external_trust_controls", "vendor-ok")
    assert by("oidc_subject_restricted", "gha")[0]["severity"] == "critical"
    assert by("human_mfa", "alice-admin")
    assert [f for f in by("key_rotation", "bob") if "400 days" in f["title"]]
    assert [f for f in by("unused_access_review", "bob") if "no recorded use" in f["title"]]
    assert by("machine_identity_owner", "lambda-admin") and not by("machine_identity_owner", "lambda-small")
    assert titles["no_root_keys"]["severity"] == "critical"
    assert titles["root_usage"]
    ext = [f for f in findings if f["category"] == "external_resource_access"]
    assert len(ext) == 1 and ext[0]["severity"] == "high"   # the IAM role finding is covered by trust analysis instead
    for f in findings:
        assert f["recommendation"]["proposed"] and f["recommendation"]["rollback"]
        assert all(c["mapping_version"] == E.MAPPING_VERSION for c in f["compliance"])
    assert summary["findings_by_severity"]["critical"] >= 2


def test_admin_recommendation_follows_the_activity_data():
    i = {"unused": {"status": "evaluated", "used": [{"service": "s3"}], "unused": []}}
    assert E._rec_admin(i, 90)["proposed_policy"]["Statement"][0]["Action"] == ["s3:*"]
    i = {"unused": {"status": "evaluated", "used": [], "unused": [{"service": "ec2"}]}}
    assert "No AWS service use was recorded" in E._rec_admin(i, 90)["proposed"]
    i = {"unused": {"status": "unknown"}}
    assert E._rec_admin(i, 90)["confidence"] == "low"


def test_risk_scores_always_carry_their_reasons(account):
    ids, _, _ = account
    alice = by_name(ids, "alice-admin")
    assert alice["risk_score"] == min(100, sum(r["points"] for r in alice["risk_reasons"]))
    assert alice["risk_severity"] == "critical" and any("administrator" in r["reason"] for r in alice["risk_reasons"])
    sl = by_name(ids, "AWSServiceRoleForSupport")
    assert sl["risk_score"] == 0 and sl["risk_reasons"]


def test_rules_can_be_switched_off_or_re_rated():
    raw = {"policies": [], "users": [], "groups": [], "roles": [role("gha", {"Federated": "arn:aws:iam::1:oidc-provider/x"})]}
    _, f, _ = E.analyze(raw, ACCT, 90, {"oidc_subject_restricted": {"enabled": False}}, now=NOW)
    assert not [x for x in f if x["rule"] == "oidc_subject_restricted"]
    _, f, _ = E.analyze(raw, ACCT, 90, {"oidc_subject_restricted": {"severity": "medium"}}, now=NOW)
    assert [x for x in f if x["rule"] == "oidc_subject_restricted"][0]["severity"] == "medium"


def test_fingerprints_are_stable_across_scans(account):
    _, f1, _ = account
    assert len({f["fingerprint"] for f in f1}) == len(f1)
    assert E.fingerprint(ACCT, "c", "arn", "k") == E.fingerprint(ACCT, "c", "arn", "k")


def test_least_privilege_score_excludes_aws_managed_roles(account):
    ids, findings, _ = account
    lp = E.least_privilege_score(ids, findings)
    assert lp["total"] == sum(1 for i in ids if i["kind"] != "group" and i["classification"] != "service_linked")
    assert 0 <= lp["pct"] <= 100 and lp["definition"]


def test_public_view_strips_internal_fields(account):
    ids, _, _ = account
    v = E.public_view(by_name(ids, "bob"))
    assert not [k for k in v if k.startswith("_")]


# ── tenant_auth: tokens must come from our own Cognito pool when configured ──

def _tok(iss, use="access"):
    import base64, json
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'none'})}.{seg({'iss': iss, 'token_use': use})}.sig"


def test_tenant_auth_rejects_tokens_from_other_user_pools(monkeypatch):
    from collectors.aws.scanner import tenant_auth as T
    ours = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Ours1"
    monkeypatch.setenv("COGNITO_USER_POOL_ID", "eu-west-1_Ours1")
    assert T._issued_by_our_pool(_tok(ours))
    assert not T._issued_by_our_pool(_tok("https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Attacker"))
    assert not T._issued_by_our_pool(_tok(ours, use="id"))
    assert not T._issued_by_our_pool("garbage")
    monkeypatch.delenv("COGNITO_USER_POOL_ID")
    assert T._issued_by_our_pool("anything")  # unchanged behaviour when not configured



# ── review round 2 ──────────────────────────────────────────────────────────

def _ident(name, docs, kind="user", guards=None, groups=None):
    stmts = []
    for d in docs:
        stmts += st(d, name)
    i = {"kind": kind, "arn": f"arn:aws:iam::{ACCT}:{kind}/{name}", "name": name, "path": "/", "groups": groups or [],
         "_statements": stmts, "_guards": guards, "credentials": {}}
    i["admin"], _ = E.admin_status(stmts, guards)
    i["capabilities"] = E.capabilities(stmts, guards)
    i["can_assume"] = []
    return i


def test_conditional_trust_deny_does_not_block_everyone():
    r = role("x", {"AWS": f"arn:aws:iam::{ACCT}:user/alice"})
    r["AssumeRolePolicyDocument"]["Statement"].append({"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole",
                                                       "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-1"}}})
    assert E.assumable_by(E.analyze_trust(r, ACCT), f"arn:aws:iam::{ACCT}:user/alice", ACCT, NO)[0]


def test_gains_compare_resource_scope_not_just_category():
    caller = _ident("dev", [stmt("Allow", "s3:GetObject", "arn:aws:s3:::data/dev/*")])
    target = _ident("prod", [stmt("Allow", "s3:GetObject", "arn:aws:s3:::data/prod/*")], kind="role")
    assert E.gains(caller, target) == ["Read stored data (S3, DynamoDB) on arn:aws:s3:::data/prod/*"]
    same = _ident("dev2", [stmt("Allow", "s3:GetObject", "arn:aws:s3:::data/dev/x*")], kind="role")
    assert E.gains(caller, same) == []


def test_wildcard_containment_is_real_not_literal():
    s = st(stmt("Allow", "s3:GetObject", "arn:aws:s3:::b/*")) + st(stmt("Deny", "s3:GetObject", "arn:aws:s3:::b/?"))
    assert E.evaluate(s, "s3:GetObject")["result"] == "scoped"          # only 1-char keys are denied
    s = st(stmt("Allow", "s3:GetObject", "arn:aws:s3:::team-*"))
    r = E.evaluate(s, "s3:GetObject", "*", [("permissions boundary", st(stmt("Allow", "s3:GetObject", "arn:aws:s3:::*-prod")))])
    assert r["result"] == "scoped" and "∩" in r["scope"][0]               # overlap shown, not hidden
    r = E.evaluate(s, "s3:GetObject", "*", [("permissions boundary", st(stmt("Allow", "s3:GetObject", "arn:aws:s3:::other-*")))])
    assert r["result"] == "not_allowed"                                  # provably disjoint


def test_named_user_bypasses_boundary_implicit_deny_but_role_does_not():
    blocked_by_boundary = {"result": "not_allowed", "blocked_by": "permissions boundary"}
    user_trust = E.analyze_trust(role("x", {"AWS": f"arn:aws:iam::{ACCT}:user/alice"}), ACCT)
    assert E.assumable_by(user_trust, f"arn:aws:iam::{ACCT}:user/alice", ACCT, blocked_by_boundary)[0]
    role_trust = E.analyze_trust(role("x", {"AWS": f"arn:aws:iam::{ACCT}:role/app"}), ACCT)
    assert not E.assumable_by(role_trust, f"arn:aws:iam::{ACCT}:role/app", ACCT, blocked_by_boundary)[0]


def test_for_all_values_is_not_a_restriction():
    t = E.analyze_trust(role("x", "*", {"ForAllValues:StringLike": {"aws:PrincipalOrgPaths": "o-ours/*"}}), ACCT)[0]
    assert t["class"] == "public"


def test_not_resource_exclusion_can_remove_the_whole_grant():
    s = st({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::b/private/*"}]})
    r = E.evaluate(s, "s3:GetObject", "*", [("permissions boundary", st(stmt("Allow", "s3:GetObject", "arn:aws:s3:::b/private/*")))])
    assert r["result"] == "not_allowed"


def test_trust_rewrite_respects_an_explicit_assume_deny():
    caller = _ident("c", [stmt("Allow", "iam:UpdateAssumeRolePolicy"), stmt("Deny", "sts:AssumeRole")])
    admin_role = _ident("adm", [ADMIN_DOC], kind="role")
    assert not [p for p in E.escalation_paths(caller, [caller, admin_role], {}) if p["method"] == "update_assume_role_policy"]
    caller2 = _ident("c2", [stmt("Allow", "iam:UpdateAssumeRolePolicy")])
    assert [p for p in E.escalation_paths(caller2, [caller2, admin_role], {}) if p["method"] == "update_assume_role_policy"]


def test_create_and_invoke_on_different_functions_is_no_path():
    lam = _ident("lam-admin", [ADMIN_DOC], kind="role")
    doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": lam["arn"]},
                         {"Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": "arn:aws:lambda:eu-west-1:1:function:new-*"},
                         {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "arn:aws:lambda:eu-west-1:1:function:old-*"}]}
    c = _ident("c", [doc])
    assert not [p for p in E.escalation_paths(c, [c, lam], {"lambda.amazonaws.com": [lam]}) if p["method"] == "passrole_lambda_invoke"]


def test_self_attach_cannot_exceed_the_permissions_boundary():
    boundary = [("permissions boundary", st(stmt("Allow", ["iam:AttachUserPolicy", "s3:GetObject"])))]
    c = _ident("c", [stmt("Allow", ["iam:AttachUserPolicy", "s3:GetObject"])], guards=boundary)
    assert not [p for p in E.escalation_paths(c, [c], {}) if p["method"] == "attach_user_policy"]
    wider = [("permissions boundary", st(stmt("Allow", ["iam:AttachUserPolicy", "secretsmanager:GetSecretValue"])))]
    c2 = _ident("c2", [stmt("Allow", "iam:AttachUserPolicy")], guards=wider)
    p = [p for p in E.escalation_paths(c2, [c2], {}) if p["method"] == "attach_user_policy"][0]
    assert any("Read secrets" in g for g in p["gains"])


def test_external_resource_findings_follow_the_rule_switch():
    raw = {"policies": [], "users": [], "groups": [], "roles": [],
           "external_access": [{"id": "x", "resource": "arn:aws:s3:::b", "resource_type": "AWS::S3::Bucket", "is_public": True}]}
    _, f, _ = E.analyze(raw, ACCT, 90, {"external_trust_controls": {"enabled": False}}, now=NOW)
    assert not f
    _, f, _ = E.analyze(raw, ACCT, 90, {"external_trust_controls": {"severity": "critical"}}, now=NOW)
    assert f[0]["severity"] == "critical"
