"""
ciem_collector.py — read-only collection for CIEM (issue #17), AWS.

Every call here is a read that the customer's CSPMScannerRole (SecurityAudit + ReadOnlyAccess) already allows:
  iam:GetAccountAuthorizationDetails      users, groups, roles, trust policies, attached/inline policies
  iam:GenerateCredentialReport / Get...   console passwords, MFA, access-key age and last use, root keys
  iam:GenerateServiceLastAccessedDetails  IAM Access Advisor: which services each identity actually used
  access-analyzer:ListAnalyzers/Findings  resources shared outside the account (if an analyzer is enabled)
  organizations:Describe/List...          service control policies, when this account can read them

Nothing is written to the customer's account. Every part that fails is recorded in `coverage` and
`limitations` instead of being skipped silently, so the UI can say what was not analysed.
"""
import csv
import io
import logging
import time
from datetime import datetime, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

RETRY = Config(retries={"max_attempts": 8, "mode": "adaptive"})
MAX_ADVISOR_PRINCIPALS = 300
ADVISOR_TIMEOUT_S = 120


def _err(e):
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "ClientError")
    return type(e).__name__


def collect_authorization(iam):
    out = {"users": [], "groups": [], "roles": [], "policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate():
        out["users"] += page.get("UserDetailList", [])
        out["groups"] += page.get("GroupDetailList", [])
        out["roles"] += page.get("RoleDetailList", [])
        for p in page.get("Policies", []):
            default = next((v for v in p.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
            if default is None:
                continue
            out["policies"].append({"Arn": p["Arn"], "name": p["PolicyName"], "document": default["Document"],
                                    "version": default.get("VersionId"), "aws_managed": p["Arn"].startswith("arn:aws:iam::aws:"),
                                    "attachments": p.get("AttachmentCount"), "updated": p.get("UpdateDate")})
    return out


def _parse_dt(v):
    if not v or v in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def collect_credential_report(iam, now=None):
    now = now or datetime.now(timezone.utc)
    for _ in range(20):
        state = iam.generate_credential_report().get("State")
        if state == "COMPLETE":
            break
        time.sleep(1)
    content = iam.get_credential_report()["Content"].decode("utf-8")
    users, root = {}, None

    def days(dt):
        return (now - dt).days if dt else None

    for row in csv.DictReader(io.StringIO(content)):
        keys = []
        for slot in ("1", "2"):
            active = row.get(f"access_key_{slot}_active") == "true"
            rotated = _parse_dt(row.get(f"access_key_{slot}_last_rotated"))
            used = _parse_dt(row.get(f"access_key_{slot}_last_used_date"))
            if active or rotated:
                keys.append({"slot": slot, "active": active, "last_rotated": rotated.isoformat() if rotated else None,
                             "age_days": days(rotated), "last_used": used.isoformat() if used else None,
                             "last_used_service": row.get(f"access_key_{slot}_last_used_service")})
        pw_used = _parse_dt(row.get("password_last_used"))
        entry = {
            "password_enabled": row.get("password_enabled") == "true",
            "password_last_used": pw_used.isoformat() if pw_used else None,
            "password_last_used_days": days(pw_used),
            "mfa_active": row.get("mfa_active") == "true",
            "keys": keys, "access_keys_active": any(k["active"] for k in keys),
        }
        if row["user"] == "<root_account>":
            root = entry
        else:
            users[row["user"]] = entry
    return users, root


def collect_access_advisor(iam, arns):
    """IAM Access Advisor per principal: start every job, then poll them together."""
    jobs, results = {}, {}
    for arn in arns[:MAX_ADVISOR_PRINCIPALS]:
        try:
            jobs[arn] = iam.generate_service_last_accessed_details(Arn=arn, Granularity="SERVICE_LEVEL")["JobId"]
        except Exception as e:
            results[arn] = {"error": _err(e)}
    deadline = time.time() + ADVISOR_TIMEOUT_S
    while jobs and time.time() < deadline:
        for arn, job in list(jobs.items()):
            try:
                r = iam.get_service_last_accessed_details(JobId=job)
            except Exception as e:
                results[arn] = {"error": _err(e)}
                del jobs[arn]
                continue
            if r["JobStatus"] == "IN_PROGRESS":
                continue
            if r["JobStatus"] == "FAILED":
                results[arn] = {"error": (r.get("Error") or {}).get("Code", "FAILED")}
            else:
                services, marker = list(r.get("ServicesLastAccessed", [])), r.get("Marker")
                while r.get("IsTruncated") and marker:
                    r = iam.get_service_last_accessed_details(JobId=job, Marker=marker)
                    services += r.get("ServicesLastAccessed", [])
                    marker = r.get("Marker")
                results[arn] = {"services": [{"namespace": s["ServiceNamespace"], "name": s.get("ServiceName"),
                                              "last_authenticated": s.get("LastAuthenticated")} for s in services]}
            del jobs[arn]
        if jobs:
            time.sleep(1)
    for arn in jobs:
        results[arn] = {"error": "timeout"}
    for arn in arns[MAX_ADVISOR_PRINCIPALS:]:
        results[arn] = {"error": "not collected (principal limit reached)"}
    return results


def collect_external_access(session, region, account):
    """IAM Access Analyzer findings for resources OWNED BY THIS ACCOUNT. An organization analyzer also reports
    other member accounts' resources; those belong to other tenants and are never taken over.
    Returns (active, archived) or None when no analyzer is active."""
    aa = session.client("accessanalyzer", region_name=region, config=RETRY)
    analyzers = [a for a in aa.list_analyzers().get("analyzers", []) if a.get("status") == "ACTIVE"
                 and a.get("type") in ("ACCOUNT", "ORGANIZATION")]
    if not analyzers:
        return None
    out, archived = [], []
    for page in aa.get_paginator("list_findings").paginate(analyzerArn=analyzers[0]["arn"],
                                                            filter={"status": {"eq": ["ACTIVE", "ARCHIVED"]},
                                                                    "resourceOwnerAccount": {"eq": [account]}}):
        for f in page.get("findings", []):
            if f.get("resourceOwnerAccount") != account:
                continue   # defence in depth: never store another account's resource
            if f.get("status") == "ARCHIVED":
                archived.append({"id": f["id"], "resource": f.get("resource"), "resource_type": f.get("resourceType")})
                continue
            out.append({"id": f["id"], "resource": f.get("resource"), "resource_type": f.get("resourceType"),
                        "principal": f.get("principal"), "actions": f.get("action"), "condition": f.get("condition"),
                        "is_public": bool(f.get("isPublic")), "region": region,
                        "analyzed_at": f.get("analyzedAt").isoformat() if f.get("analyzedAt") else None})
    return out, archived


def collect_scps(session, account):
    """Service control policies that apply to this account, as levels [root, OUs..., account].
    Returns (levels or None, note)."""
    org = session.client("organizations", config=RETRY)
    try:
        info = org.describe_organization()["Organization"]
    except ClientError as e:
        if _err(e) == "AWSOrganizationsNotInUseException":
            return [], "Account is not in an AWS Organization: no service control policies apply."
        return None, f"Could not determine AWS Organization membership ({_err(e)})."
    if info.get("MasterAccountId") == account:
        return [], "This is the organization's management account: service control policies do not apply to it."
    if "SERVICE_CONTROL_POLICY" not in [t["Type"] for t in info.get("AvailablePolicyTypes", [])] and info.get("FeatureSet") != "ALL":
        return [], "Service control policies are not enabled in this organization."
    try:
        chain, target = [], account
        while True:
            chain.append(target)
            parents = org.list_parents(ChildId=target)["Parents"]
            if not parents:
                break
            target = parents[0]["Id"]
            if parents[0]["Type"] == "ROOT":
                chain.append(target)
                break
        levels = []
        for t in reversed(chain):
            docs = []
            for page in org.get_paginator("list_policies_for_target").paginate(TargetId=t, Filter="SERVICE_CONTROL_POLICY"):
                for p in page["Policies"]:
                    docs.append({"name": p["Name"], "id": p["Id"],
                                 "document": org.describe_policy(PolicyId=p["Id"])["Policy"]["Content"]})
            levels.append({"target": t, "policies": docs})
        return levels, f"Service control policies read for {len(levels)} level(s) of organization {info['Id']}."
    except ClientError as e:
        return None, (f"This account is a member of AWS Organization {info['Id']}. Its service control policies are managed "
                      f"in the management account and could not be read ({_err(e)}). They can only remove access, so "
                      "effective access shown here may be broader than in reality.")


def collect(session, account, region="eu-west-1"):
    iam = session.client("iam", config=RETRY)
    raw = {"limitations": [], "coverage": {}}
    started = datetime.now(timezone.utc)

    auth = collect_authorization(iam)  # without this nothing can be analysed: let it raise
    raw.update(auth)
    raw["coverage"]["authorization"] = {"ok": True, "users": len(auth["users"]), "roles": len(auth["roles"]),
                                        "groups": len(auth["groups"]), "policies": len(auth["policies"])}
    try:
        raw["credential_report"], raw["root"] = collect_credential_report(iam)
        raw["coverage"]["credential_report"] = {"ok": True}
    except Exception as e:
        raw["credential_report"], raw["root"] = {}, None
        raw["coverage"]["credential_report"] = {"ok": False, "error": _err(e)}
        raw["limitations"].append(f"IAM credential report unavailable ({_err(e)}): password, MFA and access-key findings are missing.")

    principals = [u["Arn"] for u in auth["users"]] + [r["Arn"] for r in auth["roles"]
                                                      if not r.get("Path", "").startswith("/aws-service-role/")]
    try:
        raw["access_advisor"] = collect_access_advisor(iam, principals)
        failed = sum(1 for v in raw["access_advisor"].values() if v.get("error"))
        raw["coverage"]["access_advisor"] = {"ok": failed == 0, "principals": len(principals), "failed": failed}
        if failed:
            raw["limitations"].append(f"IAM Access Advisor data missing for {failed} identit{'y' if failed == 1 else 'ies'}: their unused access is 'unknown'.")
    except Exception as e:
        raw["access_advisor"] = {}
        raw["coverage"]["access_advisor"] = {"ok": False, "error": _err(e)}
        raw["limitations"].append(f"IAM Access Advisor unavailable ({_err(e)}): unused access cannot be determined.")

    try:
        ext = collect_external_access(session, region, account)
        if ext is None:
            raw["external_access"] = []
            raw["coverage"]["access_analyzer"] = {"ok": False, "error": "no active analyzer"}
            raw["limitations"].append(f"IAM Access Analyzer is not enabled in {region}: resources shared outside the account "
                                      "(S3 buckets, KMS keys, ...) are not analysed. Enabling it is free for external access findings.")
        else:
            raw["external_access"], raw["external_archived"] = ext
            raw["coverage"]["access_analyzer"] = {"ok": True, "findings": len(ext[0]), "archived": len(ext[1]), "region": region}
            raw["limitations"].append(f"IAM Access Analyzer findings are from region {region} only.")
    except Exception as e:
        raw["external_access"] = []
        raw["coverage"]["access_analyzer"] = {"ok": False, "error": _err(e)}
        raw["limitations"].append(f"IAM Access Analyzer could not be read ({_err(e)}).")

    try:
        levels, note = collect_scps(session, account)
    except Exception as e:
        levels, note = None, f"Service control policies could not be read ({_err(e)})."
    raw["scp_levels"] = levels
    raw["coverage"]["scp"] = {"ok": levels is not None, "note": note}
    if levels is None:
        raw["limitations"].append(note)
    raw["limitations"].append("Not evaluated: session policies, resource policies on individual resources other than "
                              "what IAM Access Analyzer reports, and VPC endpoint policies.")
    raw["coverage"]["duration_s"] = round((datetime.now(timezone.utc) - started).total_seconds(), 1)
    return raw
