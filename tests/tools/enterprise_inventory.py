"""
Enterprise readiness (#294), phase 1: build the infrastructure inventory from the LIVE AWS account, read-only.

    python tests/tools/enterprise_inventory.py --profile niagaros-admin      (writes docs/enterprise-readiness/inventory/)

Every table says when it was read and from which API, so it is evidence (E4: production records) rather than a
description. No secret values are read: secrets are listed by name only, and Lambda environment variables by key.
"""
import argparse
import datetime as dt
import json
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "enterprise-readiness" / "inventory"
REGION = "eu-west-1"
API_ID = "hzf92ft6j7"


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") if c not in (None, "") else "—" for c in r) + " |")
    return "\n".join(out)


def page(title, read_at, source, intro, body):
    return f"# {title}\n\nRead from AWS on **{read_at}** via {source}. {intro}\n\n{body}\n"


def lambdas(s):
    lam = s.client("lambda")
    fns = [f for p in lam.get_paginator("list_functions").paginate() for f in p["Functions"]]
    rows = []
    for f in sorted(fns, key=lambda x: x["FunctionName"]):
        env = sorted((f.get("Environment") or {}).get("Variables", {}).keys())
        rows.append([f["FunctionName"], f["Runtime"] if "Runtime" in f else f.get("PackageType"), f["Role"].split("/")[-1],
                     f.get("Timeout"), f.get("MemorySize"), "yes" if f.get("VpcConfig", {}).get("VpcId") else "no",
                     ", ".join(env), f["LastModified"][:10]])
    return fns, md_table(["Function", "Runtime", "Role", "Timeout s", "Memory MB", "In VPC", "Env keys (no values)", "Last modified"], rows)


def routes(s):
    api = s.client("apigatewayv2")
    integ, token = {}, None
    while True:
        r = api.get_integrations(ApiId=API_ID, MaxResults="500", **({"NextToken": token} if token else {}))
        integ.update({i["IntegrationId"]: i.get("IntegrationUri", "") for i in r["Items"]})
        token = r.get("NextToken")
        if not token:
            break
    rs, token = [], None
    while True:
        r = api.get_routes(ApiId=API_ID, MaxResults="500", **({"NextToken": token} if token else {}))
        rs += r["Items"]
        token = r.get("NextToken")
        if not token:
            break
    rows = []
    for r in sorted(rs, key=lambda x: (x["RouteKey"].split(" ", 1)[-1], x["RouteKey"])):
        uri = integ.get((r.get("Target") or "").replace("integrations/", ""), "")
        fn = uri.split(":function:")[-1].split("/")[0] if ":function:" in uri else uri
        rows.append([r["RouteKey"], fn, r.get("AuthorizationType")])
    return rs, md_table(["Route", "Lambda", "Gateway authorizer"], rows)


def schedules(s):
    ev = s.client("events")
    rules = ev.list_rules()["Rules"]
    rows = []
    for r in sorted(rules, key=lambda x: x["Name"]):
        targets = ev.list_targets_by_rule(Rule=r["Name"])["Targets"]
        rows.append([r["Name"], r.get("ScheduleExpression") or (r.get("EventPattern") and "event pattern"), r.get("State"),
                     ", ".join(t["Arn"].split(":")[-1] for t in targets)])
    return md_table(["Rule", "Schedule", "State", "Targets"], rows)


def databases(s):
    rds = s.client("rds")
    rows = []
    for d in rds.describe_db_instances()["DBInstances"]:
        rows.append([d["DBInstanceIdentifier"], f'{d["Engine"]} {d["EngineVersion"]}', d["DBInstanceClass"], d.get("MultiAZ"),
                     d.get("StorageEncrypted"), d.get("PubliclyAccessible"), d.get("BackupRetentionPeriod"), d.get("DeletionProtection"),
                     d.get("AutoMinorVersionUpgrade")])
    return md_table(["Instance", "Engine", "Class", "Multi-AZ", "Encrypted", "Publicly accessible", "Backup days", "Deletion protection",
                     "Auto minor upgrades"], rows)


def buckets(s):
    s3 = s.client("s3")
    rows = []
    for b in s3.list_buckets()["Buckets"]:
        n = b["Name"]

        def get(fn, default="unknown"):
            try:
                return fn()
            except Exception as e:  # noqa: BLE001
                code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
                return "none" if code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchPublicAccessBlockConfiguration",
                                          "NoSuchBucketPolicy") else default
        enc = get(lambda: s3.get_bucket_encryption(Bucket=n)["ServerSideEncryptionConfiguration"]["Rules"][0]
                  ["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"])
        pab = get(lambda: "all on" if all(s3.get_public_access_block(Bucket=n)["PublicAccessBlockConfiguration"].values()) else "partial")
        ver = get(lambda: s3.get_bucket_versioning(Bucket=n).get("Status") or "off")
        rows.append([n, enc, pab, ver])
    return md_table(["Bucket", "Default encryption", "Block public access", "Versioning"], rows)


def identity(s):
    c = s.client("cognito-idp")
    rows = []
    for p in c.list_user_pools(MaxResults=20)["UserPools"]:
        d = c.describe_user_pool(UserPoolId=p["Id"])["UserPool"]
        mfa = c.get_user_pool_mfa_config(UserPoolId=p["Id"])
        rows.append([d["Name"], d.get("UserPoolTier"), d.get("MfaConfiguration"),
                     "on" if (mfa.get("SoftwareTokenMfaConfiguration") or {}).get("Enabled") else "off",
                     (mfa.get("WebAuthnConfiguration") or {}).get("RelyingPartyId") or "not configured",
                     ", ".join(d.get("Policies", {}).get("SignInPolicy", {}).get("AllowedFirstAuthFactors") or []),
                     d.get("Policies", {}).get("PasswordPolicy", {}).get("MinimumLength"), d.get("DeletionProtection"),
                     d.get("EstimatedNumberOfUsers")])
    return md_table(["User pool", "Tier", "MFA", "TOTP", "Passkey relying party", "First factors", "Min password length",
                     "Deletion protection", "Users (estimate)"], rows)


def secrets(s):
    sm = s.client("secretsmanager")
    rows = []
    for x in [x for p in sm.get_paginator("list_secrets").paginate() for x in p["SecretList"]]:
        rows.append([x["Name"], "yes" if x.get("RotationEnabled") else "no", (x.get("LastChangedDate") or "")and str(x["LastChangedDate"])[:10],
                     "customer KMS key" if x.get("KmsKeyId") else "AWS managed key"])
    return md_table(["Secret (name only)", "Rotation", "Last changed", "Encryption"], rows)


def monitoring(s):
    cw = s.client("cloudwatch")
    alarms = [a for p in cw.get_paginator("describe_alarms").paginate() for a in p["MetricAlarms"]]
    rows = [[a["AlarmName"], a.get("MetricName"), a.get("StateValue"), ", ".join(x.split(":")[-1] for x in a.get("AlarmActions") or [])]
            for a in alarms]
    return md_table(["Alarm", "Metric", "State", "Actions"], rows) if rows else "_No CloudWatch alarms are configured._"


def frontend(s):
    a = s.client("amplify")
    rows = []
    for app in a.list_apps()["apps"]:
        branches = [b["branchName"] for b in a.list_branches(appId=app["appId"])["branches"]]
        domains = [f'{sd["subDomainSetting"]["prefix"]}.{d["domainName"]} → {sd["subDomainSetting"]["branchName"]}'
                   for d in a.list_domain_associations(appId=app["appId"])["domainAssociations"] for sd in d["subDomains"]]
        rows.append([app["name"], ", ".join(branches), "; ".join(domains)])
    return md_table(["Amplify app", "Branches", "Custom domains"], rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default=None)
    args = ap.parse_args()
    s = boto3.Session(profile_name=args.profile, region_name=REGION)
    account = s.client("sts").get_caller_identity()["Account"]
    read_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    OUT.mkdir(parents=True, exist_ok=True)
    fns, fn_md = lambdas(s)
    rs, rt_md = routes(s)
    docs = {
        "lambda-inventory.md": page("Lambda inventory", read_at, "`lambda:ListFunctions`", f"{len(fns)} functions in account {account}, {REGION}.", fn_md),
        "api-inventory.md": page("API inventory", read_at, f"`apigatewayv2:GetRoutes` on API `{API_ID}`",
                                 f"{len(rs)} routes. Authorisation happens inside each Lambda (`tenant_auth.guard`), not at the gateway; "
                                 "`NONE` below is the gateway setting, not the absence of a check.", rt_md),
        "schedules.md": page("Schedules", read_at, "`events:ListRules`", "Every scheduled job in the account.", schedules(s)),
        "data-stores.md": page("Databases and storage", read_at, "`rds:DescribeDBInstances`, `s3:*` read calls", "",
                               "## PostgreSQL (RDS)\n\n" + databases(s) + "\n\n## S3 buckets\n\n" + buckets(s)),
        "identity.md": page("Identity", read_at, "`cognito-idp:DescribeUserPool`, `GetUserPoolMfaConfig`", "", identity(s)),
        "secrets.md": page("Secrets", read_at, "`secretsmanager:ListSecrets` (names and metadata only, never values)", "", secrets(s)),
        "monitoring.md": page("Monitoring", read_at, "`cloudwatch:DescribeAlarms`", "", monitoring(s)),
        "frontend.md": page("Frontend hosting", read_at, "`amplify:ListApps`, `ListBranches`, `ListDomainAssociations`", "", frontend(s)),
    }
    for name, text in docs.items():
        (OUT / name).write_text(text, encoding="utf-8")
    (OUT / "README.md").write_text(page("Infrastructure inventory", read_at, "the read-only script `tests/tools/enterprise_inventory.py`",
                                        "Regenerate it after every infrastructure change; the date above is the evidence date.",
                                        "\n".join(f"- [{n[:-3].replace('-', ' ').capitalize()}]({n})" for n in docs)), encoding="utf-8")
    print(json.dumps({"written": sorted(docs), "read_at": read_at, "lambdas": len(fns), "routes": len(rs)}))


if __name__ == "__main__":
    main()
