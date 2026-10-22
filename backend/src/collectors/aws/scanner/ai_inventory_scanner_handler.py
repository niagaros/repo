"""
ai_inventory_scanner_handler.py — AI Inventory scanner Lambda (issue #236). Invoked by the orchestrator in wave 1
like every scanner ({"cloud_account_id", "role_arn", "external_id", "region"}); hands itself off to an async
invocation so the orchestrator is not held up.

  AWS discovery (customer's read-only role) + GitHub discovery (customer's GitHub integration, if connected)
  -> ai_inventory_engine.build (also links AI workloads to their CIEM identity)
  -> upsert assets by stable key (governance fields are never touched by a scan), observations, relationships,
     change history, findings.

Freshness: an asset not seen again only becomes 'stale' (and after the configured number of days 'inactive')
when the source that normally reports it WAS read successfully this time. A failing integration never turns
stale information into "current", and never into "gone". Findings resolve on the same rule.
"""
import hashlib
import json
import logging
import os
from datetime import datetime, timezone

import boto3
import psycopg2
from psycopg2.extras import Json

from collectors.aws.scanner import ai_inventory_engine as E
from collectors.aws.scanner.ai_inventory_collector import collect_aws_regions, collect_github

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
REGION = os.environ.get("SECRET_REGION", "eu-west-1")
J = lambda o: Json(o, dumps=lambda x: json.dumps(x, default=str))

GITHUB_RULES = {"secret_in_code", "mcp_insecure_transport", "mcp_no_client_auth", "mcp_secret_in_config", "mcp_broad_filesystem"}
AWS_PARTS = ("bedrock_guardrails", "bedrock_models", "bedrock_invocation_logging", "bedrock_knowledge_bases", "bedrock_agents",
             "bedrock_usage_metrics", "sagemaker", "opensearch_vector_collections", "lambda_functions")
RULE_PARTS = {"agent_without_guardrail": {"bedrock_agents"}, "notebook_internet_and_root": {"sagemaker"},
              "ai_key_in_lambda_env": {"lambda_functions"},
              "bedrock_invocation_logging_off": {"bedrock_invocation_logging", "bedrock_agents", "bedrock_knowledge_bases",
                                                 "bedrock_usage_metrics", "bedrock_models"},
              "privileged_ai_tool": {"bedrock_agents", "lambda_functions"}}
GOVERNANCE_RULE = "production_asset_without_owner"   # from your own governance data: always re-evaluated


def _get_connection():
    s = json.loads(boto3.client("secretsmanager", region_name=REGION).get_secret_value(
        SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"],
                            password=s["password"], sslmode="require", connect_timeout=10)


def _assume(role_arn, external_id):
    c = boto3.client("sts", region_name=REGION).assume_role(
        RoleArn=role_arn, ExternalId=external_id, RoleSessionName="niagaros-ai-inventory", DurationSeconds=3600)["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                         aws_session_token=c["SessionToken"], region_name=REGION)


def _github_token(secret_name):
    raw = boto3.client("secretsmanager", region_name=REGION).get_secret_value(SecretId=secret_name)["SecretString"]
    try:
        return json.loads(raw)["github_token"]
    except (ValueError, KeyError, TypeError):
        return raw.strip()


def _repo_of(key):
    """Repository a code-derived asset key belongs to (None for org-wide keys such as frameworks)."""
    parts = key.split(":")
    if parts[0] == "github":
        return key[len("github:"):]
    if parts[0] == "mcp" and len(parts) > 1:
        return parts[1]
    if parts[0] in ("guardrail", "vectordb") and len(parts) > 3 and parts[1] == "lib":
        return parts[-1]
    return None


def _aws_parts(key):
    """Collector parts that list this AWS-derived asset; the asset is only judged 'not seen' when all were read."""
    if key.startswith(("prompt:", "tool:")):
        return {"bedrock_agents"}
    arn = key[len("aws:"):]
    if ":guardrail/" in arn:
        return {"bedrock_guardrails"}
    if ":custom-model/" in arn or ":provisioned-model/" in arn:
        return {"bedrock_models"}
    if ":knowledge-base/" in arn:
        return {"bedrock_knowledge_bases"}
    if ":agent/" in arn:
        return {"bedrock_agents"}
    if arn.startswith("arn:aws:sagemaker:"):
        return {"sagemaker"}
    if arn.startswith("arn:aws:lambda:"):
        return {"lambda_functions"}
    if arn.startswith("arn:aws:aoss:"):
        return {"opensearch_vector_collections", "bedrock_knowledge_bases"}
    if arn.startswith("arn:aws:iam:"):
        return {"bedrock_agents", "sagemaker", "lambda_functions"}
    return set(AWS_PARTS)


def _source_read(key, from_github, read, rule=None, code_dependent=False):
    """Was every source that normally reports this asset (or finding) read completely in this scan?
    read = {"aws_parts": set of collector parts read OK, "repos": repositories read in full, "github_complete": bool,
            "lambda_env_unreadable": Lambda ARNs whose environment could not be read}
    code_dependent: a Lambda that is only inventoried because its handler matched AI code in a repository."""
    if key.startswith("aws:") and key[len("aws:"):] in read.get("lambda_env_unreadable", set()):
        return False
    if code_dependent and not read["github_complete"]:
        return False
    if key.startswith(("aws:", "prompt:", "tool:")):
        arn = key.split(":", 1)[1]
        parts = arn.split(":")
        region = parts[3] if len(parts) > 4 and parts[0] == "arn" else ""
        by_region = read.get("aws_parts_by_region") or {}
        if region:
            if region not in by_region:
                return False             # that region was not read in this run: nothing can be concluded about it
            have = by_region[region]
        else:
            have = read["aws_parts"]
        return (RULE_PARTS.get(rule) or _aws_parts(key)) <= have
    if rule in RULE_PARTS:
        return RULE_PARTS[rule] <= read["aws_parts"]
    repo = _repo_of(key)
    if repo:
        return repo in read["repos"]
    if key.startswith(("framework:", "guardrail:lib:", "vectordb:lib:")):
        return read["github_complete"]
    # providers and models: seen in AWS and/or in code
    return set(AWS_PARTS) <= read["aws_parts"] and (read["github_complete"] or not from_github)


def _rel_sources_read(sources, read):
    """Sources look like 'github:org/repo@commit', 'aws:account:region[:cloudwatch]' or 'aws:... + path/in/repo'."""
    if not sources:
        return False
    for src in sources:
        head, _, code_path = str(src).partition(" + ")
        if head.startswith("github:"):
            if head[len("github:"):].split("@", 1)[0] not in read["repos"]:
                return False
        elif head.startswith("aws:"):
            if not set(AWS_PARTS) <= read["aws_parts"]:
                return False
        else:
            return False
        if code_path and not read["github_complete"]:
            return False
    return True


def _hash(meta):
    return hashlib.sha256(json.dumps(meta, sort_keys=True, default=str).encode()).hexdigest()


RISKY_CHANGE_KEYS = {"guardrail": "high", "role_arn": "medium", "foundation_model": "medium", "endpoint": "medium",
                     "transport": "medium", "auth_configured": "high", "instruction_sha256": "medium", "args": "low",
                     "ai_env_names": "low", "status": "low"}


def _changes(old, new):
    keys = sorted(set(old) | set(new))
    diff = {k: (old.get(k), new.get(k)) for k in keys if old.get(k) != new.get(k) and k != "invocations_14d"}
    if not diff:
        return None, None
    order = {"high": 3, "medium": 2, "low": 1}
    impact = max((RISKY_CHANGE_KEYS.get(k, "low") for k in diff), key=lambda x: order[x])
    return diff, impact


def store(conn, account_id, scan_id, assets, rels, findings, read, inactive_after_days):
    now = datetime.now(timezone.utc)
    ids, new_assets, new_high = {}, [], []
    with conn.cursor() as cur:
        for a in assets:
            meta = a["metadata"]
            h = _hash(meta)
            cur.execute("SELECT id, metadata, metadata_hash, verification, lifecycle_status FROM ai_assets WHERE cloud_account_id = %s AND asset_key = %s FOR UPDATE",
                        (account_id, a["asset_key"]))
            row = cur.fetchone()
            if row is None:
                cur.execute("""INSERT INTO ai_assets (cloud_account_id, asset_key, asset_type, name, provider, verification,
                                                      metadata, metadata_hash, last_synced)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW()) RETURNING id""",
                            (account_id, a["asset_key"], a["asset_type"], a["name"], a.get("provider"), a["verification"], J(meta), h))
                aid = cur.fetchone()[0]
                cur.execute("""INSERT INTO ai_asset_changes (cloud_account_id, asset_id, change_type, new, source, risk_impact)
                               VALUES (%s, %s, 'discovered', %s, %s, NULL)""",
                            (account_id, aid, J({"type": a["asset_type"], "verification": a["verification"]}),
                             ", ".join(sorted({o["source"] for o in a["observations"]}))[:500]))
                new_assets.append(a)
            else:
                aid, old_meta, old_hash, old_ver, life = row
                verification = "verified" if old_ver == "verified" else a["verification"]
                if old_hash != h:
                    diff, impact = _changes(old_meta or {}, meta)
                    if diff:
                        cur.execute("""INSERT INTO ai_asset_changes (cloud_account_id, asset_id, change_type, previous, new, source, risk_impact)
                                       VALUES (%s, %s, 'configuration_changed', %s, %s, 'scan', %s)""",
                                    (account_id, aid, J({k: v[0] for k, v in diff.items()}), J({k: v[1] for k, v in diff.items()}), impact))
                        if impact == "high" and old_ver == "verified":
                            # a reviewed asset changed in a risk-relevant way: the review no longer covers it
                            verification = a["verification"]
                            cur.execute("UPDATE ai_assets SET next_review_at = CURRENT_DATE WHERE id = %s", (aid,))
                            cur.execute("""INSERT INTO ai_asset_changes (cloud_account_id, asset_id, change_type, previous, new, source, risk_impact)
                                           VALUES (%s, %s, 'review_required', %s, %s, 'scan', 'high')""",
                                        (account_id, aid, J({"verification": "verified"}),
                                         J({"verification": verification, "reason": "High-impact configuration change: " + ", ".join(sorted(diff))})))
                cur.execute("""UPDATE ai_assets SET name = %s, asset_type = %s, provider = %s, verification = %s, metadata = %s,
                                      metadata_hash = %s, last_seen = NOW(), last_synced = NOW(),
                                      lifecycle_status = CASE WHEN lifecycle_status IN ('stale', 'inactive') THEN 'active' ELSE lifecycle_status END
                               WHERE id = %s""",
                            (a["name"], a["asset_type"], a.get("provider"), verification, J(meta), h, aid))
            ids[a["asset_key"]] = aid
            for o in a["observations"]:
                cur.execute("INSERT INTO ai_asset_observations (asset_id, scan_id, source, ref, verification) VALUES (%s, %s, %s, %s, %s)",
                            (aid, scan_id, o["source"], o.get("ref"), o["verification"]))
        # freshness of assets this scan did not see, only where the responsible source was read
        cur.execute("""SELECT a.id, a.asset_key, a.last_seen, a.lifecycle_status,
                              EXISTS (SELECT 1 FROM ai_asset_observations o WHERE o.asset_id = a.id AND o.source LIKE 'github:%%'),
                              a.asset_key LIKE 'aws:arn:aws:lambda:%%' AND jsonb_array_length(COALESCE(a.metadata->'ai_env_names', '[]'::jsonb)) = 0
                       FROM ai_assets a
                       WHERE a.cloud_account_id = %s AND a.origin = 'discovered' AND NOT (a.asset_key = ANY(%s))
                         AND a.lifecycle_status IN ('active', 'stale', 'inactive')""", (account_id, list(ids)))
        for aid, key, last_seen, life, from_github, code_dep in cur.fetchall():
            if not _source_read(key, from_github, read, code_dependent=code_dep):
                continue
            age = (now - last_seen).days
            new_state = "inactive" if age >= inactive_after_days else "stale"
            if new_state != life:
                cur.execute("UPDATE ai_assets SET lifecycle_status = %s WHERE id = %s", (new_state, aid))
                cur.execute("""INSERT INTO ai_asset_changes (cloud_account_id, asset_id, change_type, previous, new, source)
                               VALUES (%s, %s, 'lifecycle', %s, %s, 'scan')""",
                            (account_id, aid, J({"lifecycle_status": life}), J({"lifecycle_status": new_state, "not_seen_for_days": age})))
        for r in rels:
            s_id, t_id = ids.get(r["source_key"]), ids.get(r["target_key"])
            if not s_id or not t_id:
                continue
            cur.execute("""INSERT INTO ai_asset_relationships (cloud_account_id, source_asset_id, target_asset_id, rel_type, sources,
                                                               verification, confidence, note)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT (source_asset_id, target_asset_id, rel_type) DO UPDATE SET
                               -- a link someone added by hand keeps its note and author; scan evidence is added to it
                               sources = CASE WHEN ai_asset_relationships.origin = 'manual'
                                              THEN (SELECT jsonb_agg(DISTINCT x) FROM jsonb_array_elements(ai_asset_relationships.sources || EXCLUDED.sources) x)
                                              ELSE EXCLUDED.sources END,
                               verification = EXCLUDED.verification, confidence = EXCLUDED.confidence,
                               note = CASE WHEN ai_asset_relationships.origin = 'manual' THEN ai_asset_relationships.note ELSE EXCLUDED.note END,
                               last_seen = NOW()""",
                        (account_id, s_id, t_id, r["type"], J(r["sources"]), r["verification"], r["confidence"], r.get("note")))
        # discovered relationships that are gone: removed only when every source that reported them was re-read
        current = {(ids.get(r["source_key"]), ids.get(r["target_key"]), r["type"]) for r in rels}
        cur.execute("""SELECT r.id, r.source_asset_id, r.target_asset_id, r.rel_type, r.sources, t.name
                       FROM ai_asset_relationships r JOIN ai_assets t ON t.id = r.target_asset_id
                       WHERE r.cloud_account_id = %s AND r.origin = 'discovered'""", (account_id,))
        for rid, s_id, t_id, rtype, sources, t_name in cur.fetchall():
            if (s_id, t_id, rtype) in current or not _rel_sources_read(sources, read):
                continue
            cur.execute("DELETE FROM ai_asset_relationships WHERE id = %s", (rid,))
            cur.execute("""INSERT INTO ai_asset_changes (cloud_account_id, asset_id, change_type, previous, new, source, risk_impact)
                           VALUES (%s, %s, 'relationship_removed', %s, NULL, 'scan', %s)""",
                        (account_id, s_id, J({"relationship": rtype, "target": t_name}),
                         "high" if rtype == "PROTECTED_BY_GUARDRAIL" else "low"))
        cur.execute("""SELECT asset_key, name, asset_type, criticality FROM ai_assets WHERE cloud_account_id = %s AND environment = 'production'
                       AND owner IS NULL AND asset_type <> 'ai_identity' AND lifecycle_status IN ('active', 'stale')""", (account_id,))
        for key, name, atype, crit in cur.fetchall():
            ids.setdefault(key, None)
            findings = findings + [{
                "fingerprint": E.fingerprint(GOVERNANCE_RULE, key), "rule": GOVERNANCE_RULE, "asset_key": key,
                "severity": "high" if crit in ("high", "critical") else "medium",
                "title": f"Production {E.ASSET_TYPES.get(atype, atype).lower()} {name} has no owner",
                "details": {"basis": "governance (your inventory data)", "environment": "production", "criticality": crit,
                            "note": "Ownership is required for production AI assets."},
                "recommendation": {"current": "No owner recorded", "proposed": "Record the accountable owner on the asset",
                                   "reason": "Without an owner nobody reviews changes, incidents or risk acceptances for this AI system.",
                                   "impact": "None", "confidence": "high", "approvals": "AI governance owner", "rollback": "Not applicable."},
                "compliance": E.compliance_for("governance")}]
        if None in ids.values():
            cur.execute("SELECT asset_key, id FROM ai_assets WHERE cloud_account_id = %s AND asset_key = ANY(%s)",
                        (account_id, [k for k, v in ids.items() if v is None]))
            ids.update(dict(cur.fetchall()))
        seen = set()
        for f in findings:
            seen.add(f["fingerprint"])
            cur.execute("""
                INSERT INTO ai_inventory_findings (cloud_account_id, fingerprint, asset_id, rule, severity, title, details, recommendation, compliance)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cloud_account_id, fingerprint) DO UPDATE SET
                    asset_id = EXCLUDED.asset_id, severity = EXCLUDED.severity, title = EXCLUDED.title, details = EXCLUDED.details,
                    recommendation = EXCLUDED.recommendation, compliance = EXCLUDED.compliance, last_seen = NOW(),
                    status = CASE WHEN ai_inventory_findings.status = 'resolved' THEN 'open'
                                  WHEN ai_inventory_findings.status = 'accepted' AND ai_inventory_findings.accepted_until < CURRENT_DATE THEN 'open'
                                  ELSE ai_inventory_findings.status END,
                    status_reason = CASE WHEN ai_inventory_findings.status = 'resolved' THEN 'Re-opened: present again in the latest scan'
                                         WHEN ai_inventory_findings.status = 'accepted' AND ai_inventory_findings.accepted_until < CURRENT_DATE THEN 'Re-opened: risk acceptance expired'
                                         ELSE ai_inventory_findings.status_reason END,
                    resolved_at = CASE WHEN ai_inventory_findings.status = 'resolved' THEN NULL ELSE ai_inventory_findings.resolved_at END
                RETURNING (xmax = 0)""",
                        (account_id, f["fingerprint"], ids.get(f["asset_key"]), f["rule"], f["severity"], f["title"],
                         J(f["details"]), J(f["recommendation"]), J(f["compliance"])))
            if cur.fetchone()[0] and f["severity"] in ("critical", "high"):
                new_high.append(f)
        cur.execute("""UPDATE ai_inventory_findings SET status = 'open', status_reason = 'Re-opened: risk acceptance expired'
                       WHERE cloud_account_id = %s AND status = 'accepted' AND accepted_until < CURRENT_DATE""", (account_id,))
        # resolve only what the responsible source re-read and no longer reported
        cur.execute("""SELECT f.id, f.rule, a.asset_key,
                              EXISTS (SELECT 1 FROM ai_asset_observations o WHERE o.asset_id = f.asset_id AND o.source LIKE 'github:%%'),
                              a.asset_key LIKE 'aws:arn:aws:lambda:%%' AND jsonb_array_length(COALESCE(a.metadata->'ai_env_names', '[]'::jsonb)) = 0
                       FROM ai_inventory_findings f LEFT JOIN ai_assets a ON a.id = f.asset_id
                       WHERE f.cloud_account_id = %s AND f.status IN ('open', 'in_progress') AND NOT (f.fingerprint = ANY(%s))""",
                    (account_id, list(seen)))
        to_resolve = []
        for fid, rule, key, from_github, code_dep in cur.fetchall():
            if key is None:
                continue  # the asset was removed by hand; nothing to re-check against
            if rule in ("ai_workload_overprivileged", "privileged_ai_tool") and not read.get("ciem"):
                continue
            if rule == GOVERNANCE_RULE:
                to_resolve.append(fid)
                continue
            if rule == "vulnerable_ai_dependency" and _repo_of(key) not in read.get("dependabot_repos", set()):
                continue
            if _source_read(key, from_github, read, rule, code_dependent=bool(code_dep) and rule != "ai_key_in_lambda_env"):
                to_resolve.append(fid)
        if to_resolve:
            cur.execute("""UPDATE ai_inventory_findings SET status = 'resolved', resolved_at = NOW(),
                               status_reason = 'Not present in the latest scan (verified by re-collection)'
                           WHERE id = ANY(%s::uuid[])""", ([str(i) for i in to_resolve],))
        resolved = len(to_resolve)
        # provenance older than 180 days is pruned, except each asset's most recent observation
        cur.execute("""DELETE FROM ai_asset_observations o USING ai_assets a
                       WHERE o.asset_id = a.id AND a.cloud_account_id = %s AND o.observed_at < NOW() - INTERVAL '180 days'
                         AND o.id <> (SELECT o2.id FROM ai_asset_observations o2 WHERE o2.asset_id = o.asset_id
                                      ORDER BY o2.observed_at DESC LIMIT 1)""", (account_id,))
    conn.commit()
    return new_assets, new_high, resolved


def _notify(conn, account_id, new_assets, new_high):
    try:
        from collectors.aws.scanner.notification_lib import create_notification
    except Exception:
        return
    try:
        if new_high:
            crit = any(f["severity"] == "critical" for f in new_high)
            create_notification(conn, account_id, "ai", "critical_security_finding" if crit else "ai_inventory_high_risk",
                                "P1" if crit else "P2", f"{len(new_high)} new high-risk AI inventory finding(s)",
                                description="; ".join(f["title"] for f in new_high[:5]),
                                resource_link=f"ai_inventory.html?account_id={account_id}#findings",
                                actor="ai-inventory-scanner")
        meaningful = [a for a in new_assets if a["asset_type"] not in ("ai_identity",)]
        if meaningful:
            create_notification(conn, account_id, "ai", "ai_asset_discovered", "P4", f"{len(meaningful)} new AI asset(s) discovered",
                                description=", ".join(sorted({E.ASSET_TYPES.get(a['asset_type'], a['asset_type']) for a in meaningful})),
                                resource_link=f"ai_inventory.html?account_id={account_id}#shadow", actor="ai-inventory-scanner")
    except Exception:
        logger.exception("AI inventory notification failed")


def run(conn, account_id, session, trigger="schedule", region=None):
    region = region or REGION
    with conn.cursor() as cur:
        # a run that never finished (Lambda timeout) must not look like it is still going
        cur.execute("""UPDATE ai_inventory_scans SET status = 'failed', finished_at = NOW(), error = 'Did not finish (timed out)'
                       WHERE cloud_account_id = %s AND status = 'running' AND started_at < NOW() - INTERVAL '20 minutes'""", (account_id,))
        cur.execute("INSERT INTO ai_inventory_scans (cloud_account_id, trigger) VALUES (%s, %s) RETURNING id", (account_id, trigger))
        scan_id = cur.fetchone()[0]
        cur.execute("SELECT approved_providers, github_repos, inactive_after_days FROM ai_inventory_settings WHERE cloud_account_id = %s", (account_id,))
        srow = cur.fetchone()
        approved, include, inactive_days = (srow[0], srow[1], srow[2]) if srow else ([], [], 30)
        cur.execute("SELECT org_name, github_token_secret FROM github_integrations WHERE cloud_account_id = %s", (account_id,))
        gh = cur.fetchone()
        cur.execute("""SELECT i.arn, i.risk_score, i.risk_severity, i.admin, i.data->'risk_reasons', i.data->'capabilities' FROM ciem_identities i
                       WHERE i.scan_id = (SELECT id FROM ciem_scans WHERE cloud_account_id = %s AND status IN ('succeeded', 'partial')
                                          ORDER BY started_at DESC LIMIT 1) AND i.kind = 'role'""", (account_id,))
        ciem = {arn: {"risk_score": sc, "risk_severity": sv, "admin": adm, "risk_reasons": [r.get("reason") for r in (rr or [])],
                      "capabilities": [{"id": c.get("id"), "label": c.get("label"), "result": c.get("result")} for c in (caps or [])]}
                for arn, sc, sv, adm, rr, caps in cur.fetchall()}
    conn.commit()
    coverage, limitations = {}, []
    read = {"aws_parts": set(), "repos": set(), "github_complete": False, "ciem": bool(ciem)}
    try:
        aws_account = session.client("sts").get_caller_identity()["Account"]
        aws_list, regions, region_limits = collect_aws_regions(session, aws_account, region)
        coverage["aws"] = {a["region"]: a["coverage"] for a in aws_list}
        limitations += region_limits
        for a in aws_list:
            limitations += a["limitations"]
        # per region which collector parts were read; region-less assets need the part in every region
        read["aws_parts_by_region"] = {a["region"]: {k for k, v in a["coverage"].items() if v.get("ok")} for a in aws_list}
        read["aws_parts"] = set.intersection(*read["aws_parts_by_region"].values()) if aws_list else set()
        if region_limits:
            read["aws_parts"] = set()    # the region list is unknown: region-less assets may live elsewhere
        summary_regions = regions
        repos = []
        if gh:
            try:
                g = collect_github(gh[0], _github_token(gh[1]), include or None)
                repos = g["repos"]
                coverage["github"] = g["coverage"]
                limitations += g["limitations"]
                read["repos"] = {n for n, v in g["coverage"].items() if v.get("ok") and not v.get("truncated")}
                read["dependabot_repos"] = {r["full_name"] for r in repos if (r.get("dependabot") or {}).get("status") == "ok"}
                read["github_complete"] = bool(g.get("complete"))
            except Exception as e:
                coverage["github"] = {"error": type(e).__name__}
                limitations.append(f"GitHub organisation {gh[0]} could not be read ({type(e).__name__}).")
        else:
            limitations.append("No GitHub organisation is connected: AI usage in source code (providers, models, MCP servers, "
                               "leaked keys) is not inventoried. Connect GitHub under Settings.")
        if not ciem:
            limitations.append("No CIEM scan yet: the permissions of AI workload identities are not assessed.")
        read["lambda_env_unreadable"] = {arn for a in aws_list for arn in a.get("lambda_env_unreadable") or []}
        assets, rels, findings, summary = E.build(aws_account, aws_list, repos, ciem, {"approved_providers": approved})
        summary["regions"] = summary_regions
        unparsed = {e.get("repo") for e in summary.get("files_not_parsed") or []}
        if unparsed:
            # a configuration file that could not be parsed was not read: its repository is not read in full
            read["repos"] -= unparsed
            read["github_complete"] = False
            limitations.append(f"{len(summary['files_not_parsed'])} configuration file(s) could not be parsed; "
                               "what they declare is kept from earlier runs until they can be read.")
        new_assets, new_high, resolved = store(conn, account_id, scan_id, assets, rels, findings, read, inactive_days)
        with conn.cursor() as cur:   # governance findings are added in store(): count them in this run's totals too
            cur.execute("""SELECT severity, count(*) FROM ai_inventory_findings WHERE cloud_account_id = %s AND rule = %s
                           AND status IN ('open', 'in_progress') GROUP BY 1""", (account_id, GOVERNANCE_RULE))
            for sev, n in cur.fetchall():
                summary["findings_by_severity"][sev] = summary["findings_by_severity"].get(sev, 0) + n
        conn.commit()
        complete = set(AWS_PARTS) <= read["aws_parts"] and (not gh or read["github_complete"])
        summary.update({"new_assets": len(new_assets), "resolved_this_scan": resolved,
                        "sources_read": {"aws_parts": sorted(read["aws_parts"]), "repositories": sorted(read["repos"]),
                                         "github_complete": read["github_complete"], "github_connected": bool(gh)}})
        status = "succeeded" if complete else "partial"
        with conn.cursor() as cur:
            cur.execute("""UPDATE ai_inventory_scans SET status = %s, finished_at = NOW(), coverage = %s, limitations = %s, summary = %s
                           WHERE id = %s""", (status, J(coverage), J(limitations), J(summary), scan_id))
        conn.commit()
        _notify(conn, account_id, new_assets, new_high)
        return {"scan_id": str(scan_id), "status": status, "summary": summary}
    except Exception as e:
        conn.rollback()
        logger.exception("AI inventory scan failed")
        with conn.cursor() as cur:
            # details stay in the server log; the customer sees a plain message
            cur.execute("UPDATE ai_inventory_scans SET status = 'failed', finished_at = NOW(), error = %s WHERE id = %s",
                        ("The inventory run stopped because of a problem on our side. It runs again with the next scan.", scan_id))
        conn.commit()
        return {"scan_id": str(scan_id), "status": "failed", "error": type(e).__name__}


def handler(event, context):
    account_id = (event or {}).get("cloud_account_id")
    if not account_id:
        return {"statusCode": 400, "body": json.dumps({"error": "cloud_account_id is required"})}
    if not event.get("_async") and context is not None and os.environ.get("AI_INVENTORY_ASYNC", "1") == "1":
        boto3.client("lambda", region_name=REGION).invoke(FunctionName=context.invoked_function_arn, InvocationType="Event",
                                                          Payload=json.dumps({**event, "_async": True}).encode())
        return {"statusCode": 202, "body": json.dumps({"status": "queued"})}
    conn = _get_connection()
    try:
        role_arn, external_id, region = event.get("role_arn"), event.get("external_id"), event.get("region")
        if not role_arn or not region:
            # a manual run only carries the account id: everything else comes from the account record
            with conn.cursor() as cur:
                cur.execute("SELECT role_arn, external_id, COALESCE(region, %s) FROM cloud_accounts WHERE id = %s", (REGION, account_id))
                row = cur.fetchone()
            conn.commit()
            if not row:
                return {"statusCode": 404, "body": json.dumps({"error": "unknown cloud account"})}
            if not role_arn:
                role_arn, external_id = row[0], row[1]
            region = region or row[2]
        try:
            session = _assume(role_arn, external_id)
        except Exception as e:
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO ai_inventory_scans (cloud_account_id, status, finished_at, error, trigger)
                               VALUES (%s, 'failed', NOW(), %s, %s)""", (account_id, "Niagaros could not sign in to this AWS account with the "
                                                                           "scanner role. Check the role and its external ID.",
                                                                           event.get("trigger", "schedule")))
            conn.commit()
            return {"statusCode": 200, "body": json.dumps({"status": "failed", "error": "assume_role"})}
        return {"statusCode": 200, "body": json.dumps(run(conn, account_id, session, event.get("trigger", "schedule"), region), default=str)}
    finally:
        conn.close()


lambda_handler = handler
