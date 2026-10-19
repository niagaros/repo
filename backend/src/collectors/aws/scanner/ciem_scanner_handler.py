"""
ciem_scanner_handler.py — CIEM scanner Lambda (issue #17). Invoked by the orchestrator in wave 1 like every
other scanner: {"cloud_account_id", "role_arn", "external_id", "region"}.

  assume the customer's read-only CSPMScannerRole -> ciem_collector.collect -> ciem_engine.analyze
  -> store the identity inventory and upsert findings by fingerprint.

Finding lifecycle across scans:
  - new fingerprint                        -> open (first_seen now)
  - seen again                             -> details refreshed, last_seen now; a 'resolved' finding re-opens
  - accepted risk past its end date        -> re-opens
  - open finding absent from the scan       -> resolved, "verified by re-collection", but ONLY when the data
    source that produces that kind of finding was read successfully this time (absence could be missing data)
  - finding of a rule switched off          -> suppressed (not "resolved": nothing was fixed); re-opens when the
    rule is on again and the finding is still there
  - accepted risk past its end date         -> re-opens on every scan, whether or not it was seen again
"""
import json
import logging
import os
from datetime import date, datetime, timezone

import boto3
import psycopg2
from psycopg2.extras import Json

from collectors.aws.scanner import ciem_engine
from collectors.aws.scanner.ciem_collector import collect

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
KEEP_SCANS_WITH_INVENTORY = 10

# Which collection a finding category depends on besides the IAM authorization details (always required).
CATEGORY_SOURCES = {
    "external_resource_access": ["access_analyzer"],
    "stale_credential": ["credential_report"], "weak_authentication": ["credential_report"],
    "dormant_identity": ["credential_report"], "privileged_use": ["credential_report"],
    "unused_entitlement": ["credential_report", "access_advisor"],
    "ownership": ["credential_report"],   # user classification (machine vs unknown) comes from the credential report
}
ALL_CATEGORIES = ["excessive_permissions", "wildcard_permission", "privilege_escalation", "external_access", "ownership",
                  "external_resource_access", "stale_credential", "weak_authentication", "dormant_identity",
                  "privileged_use", "unused_entitlement"]


def resolvable_categories(coverage):
    ok = lambda k: bool((coverage.get(k) or {}).get("ok"))
    if not ok("authorization"):
        return []
    return [c for c in ALL_CATEGORIES if all(ok(src) for src in CATEGORY_SOURCES.get(c, []))]


def _get_connection():
    s = json.loads(boto3.client("secretsmanager", region_name=REGION).get_secret_value(
        SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"],
                            password=s["password"], sslmode="require", connect_timeout=10)


def _assume(role_arn, external_id):
    c = boto3.client("sts", region_name=REGION).assume_role(
        RoleArn=role_arn, ExternalId=external_id, RoleSessionName="niagaros-ciem", DurationSeconds=3600)["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                         aws_session_token=c["SessionToken"], region_name=REGION)


def _account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


def _settings(cur, account_id):
    cur.execute("SELECT observation_days, rules FROM ciem_settings WHERE cloud_account_id = %s", (account_id,))
    row = cur.fetchone()
    return (row[0], row[1] or {}) if row else (90, {})


def _policy_documents(raw):
    """Readable documents for customer-managed and inline policies (AWS-managed ones are public and large)."""
    docs = {}
    for p in raw.get("policies", []):
        if not p["aws_managed"]:
            docs[p["name"]] = {"arn": p["Arn"], "document": p["document"], "version": p.get("version")}
    return docs


def _identity_row(i, raw_inline, docs):
    data = ciem_engine.public_view(i)
    attached = {}
    for name in i.get("policies", []):
        if name in docs:
            attached[name] = docs[name]
        elif (i["arn"], name) in raw_inline:
            attached[name] = {"inline": True, "document": raw_inline[(i["arn"], name)]}
    data["policy_documents"] = attached
    return data


def _inline_index(raw):
    idx = {}
    for u in raw.get("users", []):
        for p in u.get("UserPolicyList", []):
            idx[(u["Arn"], p["PolicyName"])] = p["PolicyDocument"]
    for r in raw.get("roles", []):
        for p in r.get("RolePolicyList", []):
            idx[(r["Arn"], p["PolicyName"])] = p["PolicyDocument"]
    for g in raw.get("groups", []):
        for p in g.get("GroupPolicyList", []):
            idx[(g["Arn"], p["PolicyName"])] = p["PolicyDocument"]
    return idx


def store(conn, account_id, scan_id, identities, findings, summary, raw, resolvable, disabled, region=None):
    now = datetime.now(timezone.utc)
    docs, inline = _policy_documents(raw), _inline_index(raw)
    new_high = []
    with conn.cursor() as cur:
        for i in identities:
            cur.execute("""INSERT INTO ciem_identities (scan_id, cloud_account_id, arn, name, kind, classification,
                                                        risk_score, risk_severity, admin, owner, data)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (scan_id, account_id, i["arn"], i["name"], i["kind"], i["classification"], i["risk_score"],
                         i["risk_severity"], i.get("admin"), i.get("owner"), Json(_identity_row(i, inline, docs), dumps=lambda o: json.dumps(o, default=str))))
        seen = set()
        for f in findings:
            seen.add(f["fingerprint"])
            cur.execute("""
                INSERT INTO ciem_findings (cloud_account_id, fingerprint, rule, category, severity, title, identity_arn,
                                           identity_name, details, recommendation, compliance, last_scan_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cloud_account_id, fingerprint) DO UPDATE SET
                    rule = EXCLUDED.rule, category = EXCLUDED.category, severity = EXCLUDED.severity, title = EXCLUDED.title,
                    identity_name = EXCLUDED.identity_name, details = EXCLUDED.details,
                    recommendation = EXCLUDED.recommendation, compliance = EXCLUDED.compliance,
                    last_seen = NOW(), last_scan_id = EXCLUDED.last_scan_id,
                    status = CASE
                        WHEN ciem_findings.status IN ('resolved', 'suppressed') THEN 'open'
                        WHEN ciem_findings.status = 'accepted' AND ciem_findings.accepted_until < CURRENT_DATE THEN 'open'
                        ELSE ciem_findings.status END,
                    status_reason = CASE
                        WHEN ciem_findings.status = 'resolved' THEN 'Re-opened: present again in the latest scan'
                        WHEN ciem_findings.status = 'suppressed' THEN 'Re-opened: the rule is switched on again'
                        WHEN ciem_findings.status = 'accepted' AND ciem_findings.accepted_until < CURRENT_DATE THEN 'Re-opened: risk acceptance expired'
                        ELSE ciem_findings.status_reason END,
                    resolved_at = CASE WHEN ciem_findings.status IN ('resolved', 'suppressed') THEN NULL ELSE ciem_findings.resolved_at END
                RETURNING (xmax = 0) AS inserted
            """, (account_id, f["fingerprint"], f["rule"], f["category"], f["severity"], f["title"], f["identity_arn"],
                  f["identity_name"], Json(f["details"], dumps=lambda o: json.dumps(o, default=str)),
                  Json(f["recommendation"], dumps=lambda o: json.dumps(o, default=str)), Json(f["compliance"]), scan_id))
            if cur.fetchone()[0] and f["severity"] in ("critical", "high"):
                new_high.append(f)
        cur.execute("""UPDATE ciem_findings SET status = 'open', status_reason = 'Re-opened: risk acceptance expired'
                       WHERE cloud_account_id = %s AND status = 'accepted' AND accepted_until < CURRENT_DATE""", (account_id,))
        if disabled:
            cur.execute("""UPDATE ciem_findings SET status = 'suppressed', status_reason = 'Rule switched off in CIEM settings'
                           WHERE cloud_account_id = %s AND status IN ('open', 'in_progress') AND rule = ANY(%s)""",
                        (account_id, list(disabled)))
        # Absent from a scan whose data source was read: resolved. Access Analyzer is regional, so its findings
        # are only resolved by a scan of the same region. A suppressed finding that is gone once its rule is
        # back on is resolved too (it was fixed meanwhile).
        cur.execute("""UPDATE ciem_findings SET status = 'resolved', resolved_at = NOW(),
                           status_reason = 'Not present in the latest scan (verified by re-collection)'
                       WHERE cloud_account_id = %s AND status IN ('open', 'in_progress', 'suppressed')
                         AND NOT (fingerprint = ANY(%s)) AND category = ANY(%s) AND NOT (rule = ANY(%s))
                         AND (category <> 'external_resource_access' OR details->>'region' = %s)""",
                    (account_id, list(seen), list(resolvable), list(disabled), region or REGION))
        resolved = cur.rowcount
        cur.execute("""DELETE FROM ciem_identities WHERE scan_id IN (
                           SELECT id FROM ciem_scans WHERE cloud_account_id = %s ORDER BY started_at DESC OFFSET %s)""",
                    (account_id, KEEP_SCANS_WITH_INVENTORY))
    conn.commit()
    return new_high, resolved


def _notify(conn, account_id, new_high):
    if not new_high:
        return
    try:
        from collectors.aws.scanner.notification_lib import create_notification
    except Exception:
        logger.exception("notification_lib not available")
        return
    crit = [f for f in new_high if f["severity"] == "critical"]
    try:
        create_notification(
            conn, account_id, "security",
            "critical_security_finding" if crit else "ciem_high_risk_entitlement",
            "P1" if crit else "P2",
            f"{len(new_high)} new high-risk cloud entitlement finding(s)",
            description="; ".join(f["title"] for f in new_high[:5]) + (" …" if len(new_high) > 5 else ""),
            resource_link="ciem.html", actor="ciem-scanner")
    except Exception:
        logger.exception("could not create the CIEM notification")


def _overdue_reviews(conn, account_id):
    try:
        from collectors.aws.scanner.notification_lib import create_notification
    except Exception:
        return
    with conn.cursor() as cur:
        cur.execute("""SELECT id, name, reviewer_email, due_date FROM ciem_access_reviews
                       WHERE cloud_account_id = %s AND status = 'open' AND due_date < CURRENT_DATE AND NOT overdue_notified""",
                    (account_id,))
        rows = cur.fetchall()
    for rid, name, reviewer, due in rows:
        try:
            create_notification(conn, account_id, "security", "ciem_access_review_overdue", "P3",
                                f"Access review '{name}' is overdue", description=f"Due {due}; reviewer {reviewer}.",
                                resource_link="ciem.html#reviews", actor="ciem-scanner")
            with conn.cursor() as cur:
                cur.execute("UPDATE ciem_access_reviews SET overdue_notified = true WHERE id = %s", (rid,))
            conn.commit()
        except Exception:
            logger.exception("could not notify an overdue access review")
            conn.rollback()


def run(conn, account_id, session, trigger="schedule", region=None):
    with conn.cursor() as cur:
        days, rules = _settings(cur, account_id)
        cur.execute("INSERT INTO ciem_scans (cloud_account_id, trigger, observation_days) VALUES (%s, %s, %s) RETURNING id",
                    (account_id, trigger, days))
        scan_id = cur.fetchone()[0]
    conn.commit()
    try:
        aws_account = _account_id(session)
        raw = collect(session, aws_account, region or REGION)
        identities, findings, summary = ciem_engine.analyze(raw, aws_account, days, rules)
        summary["least_privilege"] = ciem_engine.least_privilege_score(identities, findings)
        complete = all(v.get("ok") for k, v in raw["coverage"].items() if isinstance(v, dict) and k not in ("access_analyzer", "scp"))
        resolvable = resolvable_categories(raw["coverage"])
        disabled = ciem_engine.disabled_rules(rules)
        new_high, resolved = store(conn, account_id, scan_id, identities, findings, summary, raw, resolvable, disabled,
                                   region or REGION)
        summary["resolvable_categories"] = resolvable
        summary["new_high_or_critical"] = len(new_high)
        summary["resolved_this_scan"] = resolved
        with conn.cursor() as cur:
            cur.execute("""UPDATE ciem_scans SET status = %s, finished_at = NOW(), coverage = %s, limitations = %s,
                                  summary = %s, engine_version = %s, mapping_version = %s WHERE id = %s""",
                        ("succeeded" if complete else "partial", Json(raw["coverage"], dumps=lambda o: json.dumps(o, default=str)),
                         Json(raw["limitations"]), Json(summary, dumps=lambda o: json.dumps(o, default=str)),
                         ciem_engine.ENGINE_VERSION, ciem_engine.MAPPING_VERSION, scan_id))
        conn.commit()
        _notify(conn, account_id, new_high)
        _overdue_reviews(conn, account_id)
        return {"scan_id": str(scan_id), "status": "succeeded" if complete else "partial", "summary": summary}
    except Exception as e:
        conn.rollback()
        msg = f"{type(e).__name__}: {str(e)[:300]}"
        logger.exception("CIEM scan failed")
        with conn.cursor() as cur:
            cur.execute("UPDATE ciem_scans SET status = 'failed', finished_at = NOW(), error = %s WHERE id = %s", (msg, scan_id))
        conn.commit()
        return {"scan_id": str(scan_id), "status": "failed", "error": msg}


def handler(event, context):
    account_id = (event or {}).get("cloud_account_id")
    if not account_id:
        return {"statusCode": 400, "body": json.dumps({"error": "cloud_account_id is required"})}
    # The orchestrator calls scanners synchronously, one after another, within its own 10-minute limit.
    # CIEM takes about a minute per account (IAM Access Advisor jobs), and nothing downstream depends on it,
    # so hand the work to an asynchronous invocation of this same function and answer straight away.
    if not event.get("_async") and context is not None and os.environ.get("CIEM_ASYNC", "1") == "1":
        boto3.client("lambda", region_name=REGION).invoke(
            FunctionName=context.invoked_function_arn, InvocationType="Event",
            Payload=json.dumps({**event, "_async": True}).encode())
        return {"statusCode": 202, "body": json.dumps({"status": "queued"})}
    conn = _get_connection()
    try:
        role_arn, external_id = event.get("role_arn"), event.get("external_id")
        if not role_arn:
            with conn.cursor() as cur:
                cur.execute("SELECT role_arn, external_id FROM cloud_accounts WHERE id = %s", (account_id,))
                row = cur.fetchone()
            if not row:
                return {"statusCode": 404, "body": json.dumps({"error": "unknown cloud account"})}
            role_arn, external_id = row
        try:
            session = _assume(role_arn, external_id)
        except Exception as e:
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO ciem_scans (cloud_account_id, status, finished_at, error, trigger)
                               VALUES (%s, 'failed', NOW(), %s, %s)""",
                            (account_id, f"Could not assume the scanner role: {type(e).__name__}", event.get("trigger", "schedule")))
            conn.commit()
            return {"statusCode": 200, "body": json.dumps({"status": "failed", "error": "assume_role"})}
        result = run(conn, account_id, session, event.get("trigger", "schedule"), event.get("region"))
        return {"statusCode": 200, "body": json.dumps(result, default=str)}
    finally:
        conn.close()


lambda_handler = handler
