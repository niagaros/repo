"""Security Agents engine (issue #239): execution-time authorisation, autonomy per action and environment, Red
analysis (never 'validated'), Blue CloudTrail detections, triage, work-item state machine, verification and the
built-in evaluations. Offline: CloudTrail input is shaped like LookupEvents output."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from collectors.aws.scanner import security_agents_engine as E

pytestmark = [pytest.mark.flow("E2E-SECAGENTS-001"), pytest.mark.severity("P1")]

ACCT = "2d89a822-75a3-448d-a0c2-90dfe63bdfa7"
NOW = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)


def auth(agent="red-identity-attack-path", envs=("production",), days=30, start=-1, allowed=(), prohibited=(), account=ACCT):
    return {"agent_id": agent, "scope_type": "account", "scope_reference": account, "environments": list(envs),
            "allowed_actions": list(allowed), "prohibited_actions": list(prohibited),
            "valid_from": NOW + timedelta(days=start), "valid_until": NOW + timedelta(days=start + days), "revoked_at": None}


# ── authorisation ───────────────────────────────────────────────────────────

def test_allowed_within_scope_and_policy():
    d = E.authorize("red-identity-attack-path", "active", "analyze", ACCT, "production", [auth()], {}, NOW)
    assert d["decision"] == "allow"


@pytest.mark.parametrize("kw,state,reason", [
    ({}, "configured", "not active"),
    ({"account": "other-account"}, "active", "No authorisation"),
    ({"envs": ("staging",)}, "active", "No authorisation"),
    ({"start": -40}, "active", "expired"),
    ({"start": 2}, "active", "expired or has not started"),
    ({"prohibited": ("publish_work_item",)}, "active", "prohibited"),
    ({"allowed": ("analyze",)}, "active", "not in the authorised actions"),
])
def test_blocked_without_valid_scope(kw, state, reason):
    d = E.authorize("red-identity-attack-path", state, "publish_work_item", ACCT, "production", [auth(**kw)], {}, NOW)
    assert d["decision"] == "block" and reason in d["reason"]


def test_revoked_authorisation_blocks():
    a = auth()
    a["revoked_at"] = NOW
    assert E.authorize("red-identity-attack-path", "active", "analyze", ACCT, "production", [a], {}, NOW)["decision"] == "block"


def test_agent_cannot_use_actions_outside_its_role():
    d = E.authorize("red-identity-attack-path", "active", "containment", ACCT, "production", [auth()], {}, NOW)
    assert d["decision"] == "block" and "not allowed" in d["reason"]


@pytest.mark.parametrize("technique", sorted(E.PROHIBITED_TECHNIQUES))
def test_offensive_techniques_are_always_refused(technique):
    d = E.authorize("red-identity-attack-path", "active", "analyze", ACCT, "production", [auth()], {}, NOW, technique=technique)
    assert d["decision"] == "block" and "passive analysis" in d["reason"]


def test_changing_systems_always_needs_approval_and_rescans_in_production_too():
    a = auth("blue-identity-defense")
    assert E.authorize("blue-identity-defense", "active", "containment", ACCT, "production", [a], {}, NOW)["decision"] == "approval_required"
    v = auth("green-verification", envs=("production", "test"))
    assert E.authorize("green-verification", "active", "request_rescan", ACCT, "production", [v], {}, NOW)["decision"] == "approval_required"
    assert E.authorize("green-verification", "active", "request_rescan", ACCT, "test", [v], {}, NOW)["decision"] == "allow"


def test_autonomy_is_per_action_and_environment():
    a = auth("green-remediation-planner", envs=("production", "staging"))
    pol = {("green-remediation-planner", "create_ticket", "production"): {"level": "L1", "requires_approval": False},
           ("green-remediation-planner", "create_ticket", "staging"): {"level": "L2", "requires_approval": True}}
    assert E.authorize("green-remediation-planner", "active", "create_ticket", ACCT, "production", [a], pol, NOW)["decision"] == "block"
    assert E.authorize("green-remediation-planner", "active", "create_ticket", ACCT, "staging", [a], pol, NOW)["decision"] == "approval_required"
    assert E.authorize("green-remediation-planner", "active", "propose_remediation", ACCT, "production", [a], pol, NOW)["decision"] == "allow"


# ── Red ─────────────────────────────────────────────────────────────────────

def test_red_identity_builds_attack_path_and_never_claims_exploitation():
    ciem = [{"id": "f1", "status": "open", "rule": "escalation_paths", "category": "privilege_escalation", "severity": "high",
             "title": "Potential privilege escalation: PassRole + Lambda (dev)", "identity_arn": "arn:aws:iam::1:user/dev",
             "details": {"path": {"how": "Create a function with an admin role", "required_permissions": ["iam:PassRole", "lambda:CreateFunction"],
                                  "gains": ["full administrator access"], "targets": ["arn:aws:iam::1:role/admin"], "prerequisites": []}},
             "recommendation": {"current": "x", "proposed": "y"}}]
    items = E.red_identity([{"arn": "arn:aws:iam::1:user/dev", "name": "dev", "risk_score": 70}], ciem)
    assert len(items) == 1
    i = items[0]
    assert i["attack_path"]["to"] == "administrator access" and "needs iam:PassRole" in i["attack_path"]["steps"]
    assert i["path_to_admin"] and i["validation"]["status"] == "not_validated"
    assert any(r.get("reason") == "leads to administrator access" for r in i["priority_reasons"])


def test_red_vulnerabilities_keep_only_serious_native_findings_and_mark_exposure():
    f = [{"id": "s1", "check_id": "S3.1", "title": "Bucket allows public read", "severity": "CRITICAL", "resource_arn": "arn:aws:s3:::x",
          "details": {"public": True}, "framework": "CIS"},
         {"id": "s2", "check_id": "IAM.6", "title": "Root without hardware MFA", "severity": "HIGH", "resource_arn": "arn:aws:iam::1:root",
          "details": {}, "framework": "FSBP"},
         {"id": "s3", "check_id": "S3.4", "title": "MFA delete off", "severity": "MEDIUM", "resource_arn": "arn:aws:s3:::y", "framework": "CIS"}]
    items = {i["source_id"]: i for i in E.red_vulnerabilities(f)}
    assert set(items) == {"s1", "s2"}
    assert items["s1"]["exposure"] == "external" and items["s2"]["exposure"] == "internal"
    assert items["s1"]["priority"] > items["s2"]["priority"]


def test_red_ai_turns_an_overprivileged_ai_workload_into_a_path():
    items = E.red_ai([{"id": "a1", "status": "open", "rule": "ai_workload_overprivileged", "severity": "high", "title": "bot runs as admin",
                       "details": {"role_arn": "arn:aws:iam::1:role/bot", "ciem_admin": "admin"}, "asset_key": "aws:fn", "asset_name": "bot"}])
    assert items[0]["attack_path"]["to"] == "arn:aws:iam::1:role/bot" and items[0]["path_to_admin"]


def test_fingerprints_are_stable_so_duplicates_correlate():
    f = [{"id": "s1", "check_id": "S3.1", "title": "t", "severity": "HIGH", "resource_arn": "a", "framework": "CIS"}]
    assert E.red_vulnerabilities(f)[0]["fingerprint"] == E.red_vulnerabilities(f)[0]["fingerprint"]


# ── Blue ────────────────────────────────────────────────────────────────────

def ev(name, minute=0, root=False, failed=False, params=None, ip="203.0.113.5", arn="arn:aws:iam::1:user/alice", eid=None):
    ct = {"userIdentity": {"type": "Root" if root else "IAMUser", "arn": "arn:aws:iam::1:root" if root else arn},
          "sourceIPAddress": ip, "requestParameters": params}
    if failed:
        ct["errorCode"] = "AccessDenied"
    return {"EventId": eid or f"{name}-{minute}-{ip}", "EventName": name, "EventTime": NOW + timedelta(minutes=minute),
            "CloudTrailEvent": json.dumps(ct), "Resources": [{"ResourceName": "trail-1"}] if name == "StopLogging" else []}


def test_detections_link_their_cloudtrail_events():
    out = E.detect([ev("StopLogging"), ev("StopLogging", 1, failed=True)], "eu-west-1")
    assert len(out) == 1 and out[0]["rule"] == "logging_tampered" and out[0]["severity"] == "critical"
    assert out[0]["event_ids"] == ["StopLogging-0-203.0.113.5"] and out[0]["resources"] == ["trail-1"]


def test_failed_logins_need_the_threshold_per_source_address():
    fails = [ev("ConsoleLogin", i, failed=True, ip="198.51.100.1") for i in range(5)] + [ev("ConsoleLogin", i, failed=True, ip="198.51.100.2") for i in range(4)]
    out = [d for d in E.detect(fails, "eu-west-1") if d["rule"] == "console_login_failures"]
    assert len(out) == 1 and out[0]["event_count"] == 5 and out[0]["source_ip"] == "198.51.100.1"


def test_benign_changes_are_not_detections():
    benign = [ev("AttachRolePolicy", params={"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
              ev("AuthorizeSecurityGroupIngress", params={"cidrIp": "10.0.0.0/8"}),
              ev("PutBucketPolicy", params={"bucketPolicy": {"Statement": [{"Principal": {"AWS": "arn:aws:iam::1:role/x"}}]}}),
              ev("UpdateAgent", params={"guardrailConfiguration": {"guardrailIdentifier": "g"}}),
              ev("ConsoleLogin")]
    assert E.detect(benign, "eu-west-1") == []


def test_odd_events_do_not_break_detection():
    broken = {"EventId": "x", "EventName": "PutBucketPolicy", "EventTime": NOW, "CloudTrailEvent": "{not json"}
    assert E.detect([broken, ev("DeleteGuardrail")], "eu-west-1")[0]["rule"] == "bedrock_guardrail_deleted"


def test_triage_groups_by_principal_and_correlates_known_weaknesses():
    dets = E.detect([ev("CreateAccessKey", 0), ev("AttachUserPolicy", 5, params={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
                     ev("CreateAccessKey", 200, arn="arn:aws:iam::1:user/bob")], "eu-west-1")
    items = [{"fingerprint": "w1", "assets": [{"ref": "arn:aws:iam::1:user/alice"}]}]
    inc = E.triage(dets, items)
    alice = next(i for i in inc if i["principal"].endswith("alice"))
    assert len(alice["detections"]) == 2 and alice["related_work_items"] == ["w1"] and alice["severity"] == "high"
    assert "hypothesis" in alice and "not a conclusion" in alice["basis"]
    assert len(inc) == 2


# ── Green & state machine ───────────────────────────────────────────────────

def test_only_verification_resolves_or_reopens():
    assert not E.can_transition("remediated", "resolved", "human")
    assert E.can_transition("remediated", "resolved", "verification")
    assert E.can_transition("resolved", "reopened", "verification")
    assert not E.can_transition("resolved", "reopened", "human")
    assert E.can_transition("in_progress", "remediated", "human")
    assert not E.can_transition("new", "remediated", "human")


def test_verification_needs_a_scan_after_the_remediation():
    rem = NOW - timedelta(hours=2)
    assert E.verify({}, {"present": False, "checked_at": NOW}, rem)["result"] == "passed"
    assert E.verify({}, {"present": True, "checked_at": NOW}, rem)["result"] == "failed"
    assert E.verify({}, {"present": False, "checked_at": rem - timedelta(minutes=1)}, rem)["result"] == "pending"
    assert E.verify({}, {"present": None, "checked_at": None}, rem)["result"] == "pending"
    fixed_elsewhere = E.verify({}, {"present": False, "checked_at": NOW, "status": "resolved"}, None)
    assert fixed_elsewhere["result"] == "passed" and "outside this workflow" in fixed_elsewhere["reason"]


def test_plan_never_claims_the_change_was_made():
    p = E.remediation_plan({"source_type": "ciem_finding", "confidence": "high", "recommendation": {"current": "a", "proposed": "b", "rollback": "c"}})
    assert p["rescan"] == "ciem-scanner" and "does not change your systems" in " ".join(p["steps"])
    assert "no longer reports" in p["acceptance_criteria"]


@pytest.mark.parametrize("agent_id", sorted(E.AGENTS))
def test_every_agent_passes_its_built_in_evaluation(agent_id):
    r = E.evaluate(agent_id)
    assert r["passed"], [c for c in r["checks"] if not c["passed"]]
    if r["precision"] is not None:
        assert r["precision"] == 1.0 and r["recall"] == 1.0


def test_priority_explains_itself():
    score, why = E.priority("high", "medium", exposure="external", active_threat=True)
    assert 0 < score <= 100 and {w["reason"] for w in why} >= {"severity high", "reachable from outside the account", "related suspicious activity detected"}


# ── review fixes ────────────────────────────────────────────────────────────

def test_deny_statements_and_conditional_grants_are_not_public_buckets():
    deny = {"bucketPolicy": {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}
    cond = {"bucketPolicy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                                       "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}]})}
    public = {"bucketPolicy": json.dumps({"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject"}})}
    out = E.detect([ev("PutBucketPolicy", 0, params=deny), ev("PutBucketPolicy", 1, params=cond), ev("PutBucketPolicy", 2, params=public)], "eu-west-1")
    assert [d["event_ids"] for d in out] == [["PutBucketPolicy-2-203.0.113.5"]]


def test_public_access_block_only_counts_when_switched_off():
    on = {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
    off = {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": True}}
    out = E.detect([ev("PutPublicAccessBlock", 0, params=on), ev("PutPublicAccessBlock", 1, params=off), ev("DeletePublicAccessBlock", 2)], "eu-west-1")
    assert sorted(d["event_ids"][0] for d in out) == ["DeletePublicAccessBlock-2-203.0.113.5", "PutPublicAccessBlock-1-203.0.113.5"]


def test_update_trail_only_counts_when_logging_is_narrowed():
    out = E.detect([ev("UpdateTrail", 0, params={"name": "t", "isMultiRegionTrail": True}),
                    ev("UpdateTrail", 1, params={"name": "t", "isMultiRegionTrail": False})], "eu-west-1")
    assert [d["event_ids"] for d in out] == [["UpdateTrail-1-203.0.113.5"]]


def test_failed_login_episodes_on_different_days_are_separate_detections():
    day1 = [ev("ConsoleLogin", i, failed=True, ip="198.51.100.1") for i in range(5)]
    day2 = [{**e, "EventId": e["EventId"] + "-d2", "EventTime": e["EventTime"] + timedelta(days=1)} for e in day1]
    out = [d for d in E.detect(day1 + day2, "eu-west-1") if d["rule"] == "console_login_failures"]
    assert len(out) == 2 and len({d["fingerprint"] for d in out}) == 2


def test_overlapping_grants_combine_independent_of_order():
    a1, a2 = auth(allowed=("analyze",)), auth(allowed=("read_inventory",))
    for grants in ([a1, a2], [a2, a1]):
        assert E.authorize("red-identity-attack-path", "active", "read_inventory", ACCT, "production", grants, {}, NOW)["decision"] == "allow"
    p = auth(prohibited=("analyze",))
    for grants in ([auth(), p], [p, auth()]):
        assert E.authorize("red-identity-attack-path", "active", "analyze", ACCT, "production", grants, {}, NOW)["decision"] == "block"


def test_admin_grant_needs_an_allow_statement_for_everything():
    deny = {"policyDocument": json.dumps({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})}
    split = {"policyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"},
                                                         {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})}
    admin = {"policyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}]})}
    out = E.detect([ev("PutUserPolicy", 0, params=deny), ev("PutUserPolicy", 1, params=split), ev("PutRolePolicy", 2, params=admin)], "eu-west-1")
    assert [d["event_ids"] for d in out] == [["PutRolePolicy-2-203.0.113.5"]]


def test_threshold_events_are_read_for_the_whole_day():
    from unittest.mock import MagicMock
    from collectors.aws.scanner.security_agents_runner_handler import collect_cloudtrail
    s = MagicMock()
    s.client.return_value.lookup_events.return_value = {"Events": []}
    since = datetime(2026, 10, 22, 14, 30, tzinfo=timezone.utc)
    collect_cloudtrail(s, "eu-west-1", since)
    starts = {c.kwargs["LookupAttributes"][0]["AttributeValue"]: c.kwargs["StartTime"] for c in s.client.return_value.lookup_events.call_args_list}
    assert starts["ConsoleLogin"] == datetime(2026, 10, 22, tzinfo=timezone.utc) and starts["StopLogging"] == since


def test_low_ciem_hygiene_items_are_not_published_as_weaknesses():
    low = [{"id": "l1", "status": "open", "rule": "machine_owner", "category": "ownership", "severity": "low", "title": "no owner",
            "identity_arn": "arn:aws:iam::1:role/x"}]
    assert E.red_identity([], low) == []


# ── attack surface and AWS-native detections ──────────────────────────────

def test_attack_surface_builds_a_path_from_the_internet_to_the_role():
    items = {i["source_id"]: i for i in E.red_attack_surface(E._surface_fixture(), {"arn:aws:iam::1:role/web": {"admin": "admin", "capabilities": []}})}
    web = items["ec2_instance:eu-west-1:i-web"]
    assert web["severity"] == "critical" and web["path_to_admin"] and web["attack_path"]["to"] == "full administrator access"
    assert "SSH (22)" in web["evidence"]["sensitive_services"] and web["exposure"] == "external"
    assert "Nothing was scanned" in web["validation"]["note"]
    assert set(items) == {"ec2_instance:eu-west-1:i-web", "rds_instance:eu-west-1:db-pub", "lambda_url:eu-west-1:open-fn"}


def test_public_database_behind_a_closed_group_is_medium_not_high():
    s = {"eu-west-1": {"security_groups": {"sg": {"rules": []}}, "databases": [{"id": "d", "public": True, "engine": "postgres", "port": 5432,
                                                                              "security_groups": ["sg"]}]}}
    item = E.red_attack_surface(s)[0]
    assert item["severity"] == "medium" and item["evidence"]["open_to_internet"] is False


def test_all_traffic_rule_covers_every_port():
    assert E.open_to_internet([{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]) == [(0, 65535, "all")]
    assert E.open_to_internet([{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]) == [(443, 443, "tcp")]


def test_aws_native_findings_keep_their_ids_and_skip_duplicates():
    out = E.blue_aws_native(*E._native_fixture())
    assert sorted(d["event_ids"][0] for d in out) == ["gd-1", "sh-2"]
    gd = next(d for d in out if d["event_ids"] == ["gd-1"])
    assert gd["severity"] == "high" and gd["principal"] == "dev" and gd["basis"] == "observed (Amazon GuardDuty)"


def test_ipv6_only_instances_and_protocols_are_judged_correctly():
    s = {"eu-west-1": {"security_groups": {"sg6": {"rules": [{"IpProtocol": "6", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]},
                                           "sgudp": {"rules": [{"IpProtocol": "udp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}},
                       "instances": [{"id": "i-v6", "state": "running", "public_ip": None, "ipv6": ["2001:db8::1"], "security_groups": ["sg6"]}],
                       "databases": [{"id": "db-udp", "public": True, "engine": "postgres", "port": 5432, "security_groups": ["sgudp"]}]}}
    items = {i["source_id"]: i for i in E.red_attack_surface(s)}
    assert "SSH (22)" in items["ec2_instance:eu-west-1:i-v6"]["evidence"]["sensitive_services"]
    assert items["rds_instance:eu-west-1:db-udp"]["evidence"]["open_to_internet"] is False      # UDP does not reach PostgreSQL


def test_security_hub_guardduty_copies_are_kept_when_guardduty_was_not_read():
    gd, sh = E._native_fixture()
    assert sorted(d["event_ids"][0] for d in E.blue_aws_native([], sh)) == ["arn:aws:guardduty:eu-west-1:1:detector/d/finding/gd-1", "sh-2"]


def test_same_address_in_two_regions_gives_two_detections():
    fails = [ev("ConsoleLogin", i, failed=True, ip="198.51.100.1") for i in range(5)]
    a = E.detect(fails, "eu-west-1")[0]
    b = E.detect(fails, "us-east-1")[0]
    assert a["fingerprint"] != b["fingerprint"]
