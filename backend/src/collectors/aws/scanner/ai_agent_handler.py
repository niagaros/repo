"""
ai_agent_handler.py

Niagaros AI Agent (GitHub issue #262), v1.

Scope decision: issue #262 describes a full multi-cloud, multi-tool
autonomous security agent — live integrations with Azure, GCP,
Kubernetes, GitHub, GitLab, Jira, ServiceNow, Entra ID, Okta,
CrowdStrike, Defender, Wiz, Prisma Cloud, plus "Agentic Actions" that
autonomously rotate secrets, disable identities, and apply security
policies. None of those integrations exist in this codebase, and this
platform's own scanner role is SecurityAudit + ReadOnlyAccess — it has
no write access to a customer's AWS account at all. Building any of
that would mean either faking an integration this codebase has no real
connection to, or giving an LLM autonomous infrastructure-write power
this product's own IAM model doesn't grant anyone.

What's built here instead, for real:
  - Natural-language Q&A over this account's own real data (findings,
    resources, cloud_accounts, TPRM vendors, Audit Management). The LLM
    classifies the question into one of a fixed set of real, pre-built
    queries (never free-form SQL generation) and phrases the real
    result — it never invents the numbers. This covers the issue's
    "AI-Powered Search" examples almost verbatim: highest risks,
    account/framework compliance, internet-facing criticals, failing
    framework controls, expiring vendor certificates, audit evidence.
  - One real, human-confirmed action: create a remediation task in
    Audit Management from a finding already surfaced in that audit's
    real findings register. The agent proposes the exact task; nothing
    is created until a human confirms — no autonomous execution.
  - A full audit trail: every question, the real data used to answer
    it, the generated answer, and whether an action was taken.

Declined, explicitly, rather than silently invented:
  - Azure/GCP/Kubernetes/GitHub/GitLab/Jira/ServiceNow/Entra
    ID/Okta/CrowdStrike/Defender/Wiz/Prisma Cloud — no real connection
    to any of these exists in this AWS-only product.
  - Autonomous "Agentic Actions" (rotate secrets, disable identities,
    apply policies) — no write-access role exists for this, and
    granting one silently would be a far heavier security decision
    than anything else already built here.
  - "Internet exposure" only covers the one real, narrow signal this
    scanner actually has — S3 public-access checks — not a general
    external-attack-surface claim (same honesty line already drawn for
    TPRM's website-TLS check).

FRAMEWORK_CASE_SQL / FRAMEWORK_LABELS / FRAMEWORK_DB_VALUES below are
copied verbatim from trust_center_handler.py / calculator_handler.py so
this agent's framework answers use the exact same real framework set
and counting method as the rest of the product (see the 2026-09-08
dashboard/Trust Center/framework-page counting-consistency fixes).
"""

import json
import logging
import os
import re
import urllib.request
from datetime import date, datetime, timezone

import boto3
import psycopg2

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _is_uuid(value):
    return bool(value) and bool(_UUID_RE.match(value))


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}

GROQ_MODEL_ID = os.environ.get("GROQ_MODEL_ID", "openai/gpt-oss-120b")
GROQ_SECRET_NAME = os.environ.get("GROQ_SECRET_NAME", "cspm/questionnaire/groq-api-key")

FRAMEWORK_CASE_SQL = """
    CASE
        WHEN f.framework = 'ISO 27001:2022' THEN 'ISO27001'
        WHEN f.framework = 'NIST CSF v2.0'  THEN 'NIST'
        WHEN f.framework = 'GDPR'            THEN 'GDPR'
        WHEN f.framework = 'SOC2'            THEN 'SOC2'
        WHEN f.framework = 'PCI DSS v4.0'   THEN 'PCIDSS'
        WHEN f.framework = 'NIS2'            THEN 'NIS2'
        WHEN f.framework = 'HIPAA'           THEN 'HIPAA'
        WHEN f.framework = 'NIST 800-53 Rev 5' THEN 'NIST80053'
        WHEN f.framework = 'BSI-C5'          THEN 'BSIC5'
        WHEN f.framework = 'CSA CCM 4.0'     THEN 'CSACCM'
        WHEN f.framework = 'FedRAMP Moderate Rev 4' THEN 'FEDRAMP'
        WHEN f.framework = 'ISO 42001'       THEN 'ISO42001'
        WHEN f.framework = 'ISO 27017'       THEN 'ISO27017'
        WHEN f.framework = 'AWS FTR'         THEN 'AWSFTR'
        WHEN f.framework = 'MVSP'            THEN 'MVSP'
        WHEN f.framework = 'TISAX'           THEN 'TISAX'
        WHEN f.framework = 'HITRUST CSF'     THEN 'HITRUST'
        WHEN f.framework = 'DORA'            THEN 'DORA'
        WHEN f.framework = 'CRI Profile'     THEN 'CRIPROFILE'
        WHEN f.framework = 'EU AI Act'       THEN 'EUAIACT'
        WHEN f.framework = 'NIST AI RMF'     THEN 'NISTAIRMF'
        WHEN f.framework = 'ISO 27701'       THEN 'ISO27701'
        WHEN f.framework = 'ISO 27018'       THEN 'ISO27018'
        WHEN f.framework = 'Microsoft SSPA'  THEN 'SSPA'
        WHEN f.framework = 'CIS Controls v8.1' THEN 'CISCTRL'
        WHEN f.framework = '23 NYCRR 500 (NYDFS)' THEN 'NYDFS'
        WHEN f.framework = 'NIST Privacy Framework' THEN 'NISTPRIV'
        WHEN f.framework = 'CIS AWS Foundations Benchmark v5.0.0' THEN 'CISAWS'
        WHEN f.framework = 'AWS Foundational Security Best Practices' THEN 'FSBP'
        ELSE NULL
    END
"""

FRAMEWORK_LABELS = {
    "ISO27001": "ISO/IEC 27001:2022", "NIST": "NIST CSF v2.0", "GDPR": "GDPR", "SOC2": "SOC 2",
    "PCIDSS": "PCI DSS v4.0", "NIS2": "NIS2", "HIPAA": "HIPAA", "NIST80053": "NIST SP 800-53 Rev 5",
    "BSIC5": "BSI C5", "CSACCM": "CSA CCM 4.0", "FEDRAMP": "FedRAMP Moderate", "ISO42001": "ISO 42001:2023",
    "ISO27017": "ISO 27017:2015", "AWSFTR": "AWS FTR", "MVSP": "MVSP", "TISAX": "TISAX",
    "HITRUST": "HITRUST CSF", "DORA": "DORA", "CRIPROFILE": "CRI Profile", "EUAIACT": "EU AI Act",
    "NISTAIRMF": "NIST AI RMF", "ISO27701": "ISO 27701", "ISO27018": "ISO 27018", "SSPA": "Microsoft SSPA",
    "CISCTRL": "CIS Controls v8.1", "NYDFS": "23 NYCRR 500 (NYDFS)", "NISTPRIV": "NIST Privacy Framework",
    "CISAWS": "CIS AWS Foundations Benchmark", "FSBP": "AWS Foundational Security Best Practices",
}
FRAMEWORK_DB_VALUES = {
    "ISO27001": ["ISO 27001:2022"], "NIST": ["NIST CSF v2.0"], "GDPR": ["GDPR"], "SOC2": ["SOC2"],
    "PCIDSS": ["PCI DSS v4.0"], "NIS2": ["NIS2"], "HIPAA": ["HIPAA"], "NIST80053": ["NIST 800-53 Rev 5"],
    "BSIC5": ["BSI-C5"], "CSACCM": ["CSA CCM 4.0"], "FEDRAMP": ["FedRAMP Moderate Rev 4"], "ISO42001": ["ISO 42001"],
    "ISO27017": ["ISO 27017"], "AWSFTR": ["AWS FTR"], "MVSP": ["MVSP"], "TISAX": ["TISAX"],
    "HITRUST": ["HITRUST CSF"], "DORA": ["DORA"], "CRIPROFILE": ["CRI Profile"], "EUAIACT": ["EU AI Act"],
    "NISTAIRMF": ["NIST AI RMF"], "ISO27701": ["ISO 27701"], "ISO27018": ["ISO 27018"], "SSPA": ["Microsoft SSPA"],
    "CISCTRL": ["CIS Controls v8.1"], "NYDFS": ["23 NYCRR 500 (NYDFS)"], "NISTPRIV": ["NIST Privacy Framework"],
    "CISAWS": ["CIS AWS Foundations Benchmark v5.0.0", "AWS Foundational Security Best Practices"],
}

# Only real check IDs this scanner can honestly call "internet exposure" —
# S3 public-access checks. No security-group/VPC/RDS-public checks exist
# in this scanner, so this list is deliberately narrow, not a general
# external-attack-surface claim.
INTERNET_FACING_CHECK_PREFIXES = ("S3.2.", "S3.3.")

INTENTS = (
    "highest_risks", "account_compliance", "internet_facing_critical",
    "framework_status", "vendor_certs_expiring", "audit_evidence_needed",
    "unsupported",
)

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS ai_agent_queries (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    question          TEXT         NOT NULL,
    intent            VARCHAR(50)  NOT NULL,
    evidence          JSONB        NOT NULL,
    answer            TEXT         NOT NULL,
    action_taken      VARCHAR(50),
    action_details    JSONB,
    asked_by          VARCHAR(255),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ai_agent_queries_account_idx ON ai_agent_queries(cloud_account_id, created_at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON ai_agent_queries TO cspm_lambda;
"""


def _get_connection():
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    client = boto3.client("secretsmanager", region_name=region)
    secret = json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return psycopg2.connect(
        host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
        user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
    )


def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body, default=str)}


# ── Groq (same pattern as questionnaire_handler.py) ─────────────────────

_groq_key_cache = None


def _get_groq_key():
    global _groq_key_cache
    if _groq_key_cache is None:
        region = os.environ.get("SECRET_REGION", "eu-west-1")
        client = boto3.client("secretsmanager", region_name=region)
        secret = client.get_secret_value(SecretId=GROQ_SECRET_NAME)["SecretString"]
        try:
            _groq_key_cache = json.loads(secret)["api_key"]
        except (json.JSONDecodeError, KeyError):
            _groq_key_cache = secret.strip()
    return _groq_key_cache


def _call_groq(prompt, max_tokens=400):
    api_key = _get_groq_key()
    req_body = json.dumps({
        "model": GROQ_MODEL_ID,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.1,
        "reasoning_effort": "low",
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=req_body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Mozilla/5.0 (compatible; niagaros-ai-agent/1.0)",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=25) as resp:
        payload = json.loads(resp.read())
    return payload["choices"][0]["message"]["content"].strip()


def _classify_intent(question):
    fw_codes = "\n".join(f"  {code}: {label}" for code, label in sorted(FRAMEWORK_LABELS.items()))
    prompt = (
        "Classify this security/compliance question into exactly one intent from "
        f"this fixed list: {', '.join(INTENTS)}.\n\n"
        "- highest_risks: asking about top/highest/worst risks or vulnerabilities in general.\n"
        "- account_compliance: asking about overall or per-framework compliance score/posture.\n"
        "- internet_facing_critical: asking specifically about internet-exposed or "
        "publicly-accessible critical issues.\n"
        "- framework_status: asking which controls are failing/passing for one named "
        "compliance framework.\n"
        "- vendor_certs_expiring: asking about vendor/third-party certificates expiring or expired.\n"
        "- audit_evidence_needed: asking what evidence is needed for an audit of one named framework.\n"
        "- unsupported: anything about a cloud provider other than AWS, a tool this platform "
        "doesn't integrate with (Jira, ServiceNow, Okta, CrowdStrike, Wiz, etc.), or asking the "
        "agent to autonomously change/remediate infrastructure itself.\n\n"
        f"If the question names a specific framework, match it to exactly one of these short "
        f"codes (use the code, not the full name) — or null if none is named or none matches:\n"
        f"{fw_codes}\n\n"
        f'Question: "{question}"\n\n'
        'Respond with ONLY a JSON object, no other text: {"intent": "...", "framework_code": "..." or null}'
    )
    raw = _call_groq(prompt, max_tokens=300)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`").replace("json", "", 1).strip()
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        raw = match.group(0)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("intent classification returned unparseable output: %r", raw)
        return "unsupported", None
    intent = parsed.get("intent") if isinstance(parsed, dict) else None
    if intent not in INTENTS:
        intent = "unsupported"
    framework_code = parsed.get("framework_code") if isinstance(parsed, dict) else None
    if framework_code not in FRAMEWORK_LABELS:
        framework_code = None
    return intent, framework_code


# ── Real, pre-built queries — never free-form SQL from the LLM ─────────

def _q_highest_risks(cur, account_id):
    cur.execute("""
        SELECT f.check_id, f.title, f.severity, r.resource_name, f.remediation
        FROM findings f JOIN resources r ON f.resource_id = r.id
        WHERE r.cloud_account_id = %s AND f.result = 'FAIL'
        ORDER BY CASE UPPER(f.severity) WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                 WHEN 'MEDIUM' THEN 3 ELSE 4 END, f.check_id
        LIMIT 10
    """, (account_id,))
    return [{"check_id": r[0], "title": r[1], "severity": r[2], "resource_name": r[3], "remediation": r[4]}
            for r in cur.fetchall()]


def _q_account_compliance(cur, account_id):
    cur.execute(f"""
        SELECT service, COUNT(*) AS total, COUNT(*) FILTER (WHERE result = 'PASS') AS passed
        FROM (SELECT {FRAMEWORK_CASE_SQL} AS service, f.result
              FROM findings f JOIN resources r ON f.resource_id = r.id
              WHERE r.cloud_account_id = %s) sub
        WHERE service IS NOT NULL
        GROUP BY service
        ORDER BY COUNT(*) FILTER (WHERE result = 'PASS') * 100.0 / NULLIF(COUNT(*), 0) ASC
    """, (account_id,))
    return [{"framework": FRAMEWORK_LABELS.get(row[0], row[0]), "score": round(row[2] * 100.0 / row[1], 1)}
            for row in cur.fetchall() if row[1]]


def _q_internet_facing_critical(cur, account_id):
    like_clauses = " OR ".join(["f.check_id LIKE %s"] * len(INTERNET_FACING_CHECK_PREFIXES))
    params = [account_id] + [f"{p}%" for p in INTERNET_FACING_CHECK_PREFIXES]
    cur.execute(f"""
        SELECT f.check_id, f.title, r.resource_name
        FROM findings f JOIN resources r ON f.resource_id = r.id
        WHERE r.cloud_account_id = %s AND f.result = 'FAIL' AND UPPER(f.severity) = 'CRITICAL'
          AND ({like_clauses})
        ORDER BY f.check_id
        LIMIT 20
    """, params)
    return {
        "scope_note": "Only covers S3 public-access checks — the one real internet-exposure "
                       "signal this scanner has. Not a full external attack-surface scan.",
        "findings": [{"check_id": r[0], "title": r[1], "resource_name": r[2]} for r in cur.fetchall()],
    }


def _q_framework_status(cur, account_id, framework_code):
    if not framework_code or framework_code not in FRAMEWORK_DB_VALUES:
        return {"error": "I couldn't match that to one of this account's tracked frameworks."}
    db_values = FRAMEWORK_DB_VALUES[framework_code]
    cur.execute("""
        SELECT f.check_id, f.title, r.resource_name
        FROM findings f JOIN resources r ON f.resource_id = r.id
        WHERE r.cloud_account_id = %s AND f.result = 'FAIL' AND f.framework = ANY(%s)
        ORDER BY f.check_id
        LIMIT 20
    """, (account_id, db_values))
    failing = [{"check_id": r[0], "title": r[1], "resource_name": r[2]} for r in cur.fetchall()]
    return {"framework": FRAMEWORK_LABELS.get(framework_code, framework_code), "failing_controls": failing}


def _q_vendor_certs_expiring(cur, account_id):
    cur.execute("""
        SELECT v.name, c.certification_type, c.expiry_date
        FROM tprm_certifications c JOIN tprm_vendors v ON c.vendor_id = v.id
        WHERE v.cloud_account_id = %s AND c.expiry_date IS NOT NULL
          AND c.expiry_date <= CURRENT_DATE + INTERVAL '30 days'
        ORDER BY c.expiry_date
    """, (account_id,))
    return [{"vendor": r[0], "certification_type": r[1], "expiry_date": r[2].isoformat()} for r in cur.fetchall()]


def _q_audit_evidence_needed(cur, account_id, framework_code):
    if not framework_code:
        return {"error": "I couldn't match that to one of this account's tracked frameworks."}
    fw_label = FRAMEWORK_LABELS.get(framework_code, framework_code)
    cur.execute("""
        SELECT a.id, a.title, a.status FROM audits a
        WHERE a.cloud_account_id = %s AND a.framework = %s
        ORDER BY a.created_at DESC LIMIT 1
    """, (account_id, framework_code))
    audit = cur.fetchone()
    if not audit:
        return {"framework": fw_label, "audit_exists": False,
                "note": f"No audit has been created yet for {fw_label} in Audit Management."}
    audit_id, audit_title, audit_status = audit
    cur.execute("""
        SELECT id, title, status, root_cause FROM audit_findings WHERE audit_id = %s
        ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END
    """, (audit_id,))
    findings = [{"id": str(r[0]), "title": r[1], "status": r[2], "has_root_cause": bool(r[3])}
                for r in cur.fetchall()]
    return {"framework": fw_label, "audit_exists": True, "audit_id": str(audit_id),
            "audit_title": audit_title, "audit_status": audit_status, "findings": findings}


def _run_intent(cur, account_id, intent, framework_code):
    if intent == "highest_risks":
        return {"findings": _q_highest_risks(cur, account_id)}
    if intent == "account_compliance":
        return {"frameworks": _q_account_compliance(cur, account_id)}
    if intent == "internet_facing_critical":
        return _q_internet_facing_critical(cur, account_id)
    if intent == "framework_status":
        return _q_framework_status(cur, account_id, framework_code)
    if intent == "vendor_certs_expiring":
        return {"certificates": _q_vendor_certs_expiring(cur, account_id)}
    if intent == "audit_evidence_needed":
        return _q_audit_evidence_needed(cur, account_id, framework_code)
    return None


UNSUPPORTED_MESSAGE = (
    "I can only answer questions about this AWS account's own real, scanned data right now — "
    "I'm not connected to Azure, GCP, Kubernetes, GitHub, GitLab, Jira, ServiceNow, Okta, "
    "CrowdStrike, Wiz, or any other tool, and I can't autonomously change your infrastructure. "
    "I can tell you about: your highest risks, compliance scores per framework, internet-facing "
    "S3 exposure, which controls are failing for a named framework, vendor certificates expiring, "
    "and what evidence exists for a framework's audit."
)


def _phrase_answer(question, intent, evidence):
    if intent == "unsupported":
        return UNSUPPORTED_MESSAGE
    prompt = (
        "Answer this security/compliance question using ONLY the real data below, which comes "
        "directly from this account's own live compliance scans and stored records. Do not invent "
        "any numbers, names, or facts that are not present in the data — this includes not listing "
        "example or typical evidence/document types for a framework unless they literally appear in "
        "the data. If the data is empty, or shows no audit/no issues/no records, say that plainly in "
        "one sentence instead of describing what such an audit or evidence set would generally "
        "contain. Be concise: 2-5 sentences, professional tone, as if written by a security "
        "analyst.\n\n"
        f"Question: {question}\n\n"
        f"Real data:\n{json.dumps(evidence, default=str)}\n\n"
        "Answer:"
    )
    try:
        return _call_groq(prompt, max_tokens=350)
    except Exception as e:
        logger.exception("groq phrasing failed")
        return (f"I found real data for this ({json.dumps(evidence, default=str)[:300]}...), "
                f"but couldn't reach the AI service to phrase it in words ({e}).")


def handler(event, context):
    if not event or "httpMethod" not in event:
        return {"statusCode": 400, "body": json.dumps({"error": "not an API Gateway event"})}

    method = event["httpMethod"]
    if method == "OPTIONS":
        return _resp(200, {})

    qs = event.get("queryStringParameters") or {}
    body = json.loads(event["body"]) if event.get("body") else {}

    conn = _get_connection()
    try:
        if method == "GET":
            account_id = qs.get("cloud_account_id")
            if not _is_uuid(account_id):
                return _resp(200, {"history": []})
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, question, intent, answer, action_taken, created_at
                    FROM ai_agent_queries WHERE cloud_account_id = %s
                    ORDER BY created_at DESC LIMIT 50
                """, (account_id,))
                history = [{
                    "id": str(r[0]), "question": r[1], "intent": r[2], "answer": r[3],
                    "action_taken": r[4], "created_at": r[5].isoformat(),
                } for r in cur.fetchall()]
            return _resp(200, {"history": history})

        if method == "POST":
            action = body.get("action")

            if action == "migrate":
                with conn:
                    with conn.cursor() as cur:
                        cur.execute(BOOTSTRAP_SQL)
                return _resp(200, {"migrated": True})

            if action == "ask":
                account_id = body.get("cloud_account_id")
                question = (body.get("question") or "").strip()
                if not _is_uuid(account_id):
                    return _resp(400, {"error": "cloud_account_id is required"})
                if not question:
                    return _resp(400, {"error": "question is required"})

                try:
                    intent, framework_code = _classify_intent(question)
                except Exception as e:
                    logger.exception("intent classification failed")
                    return _resp(200, {"intent": "unsupported", "answer": UNSUPPORTED_MESSAGE,
                                        "evidence": {}, "_debug": str(e)})

                with conn.cursor() as cur:
                    evidence = _run_intent(cur, account_id, intent, framework_code) if intent != "unsupported" else {}
                answer = _phrase_answer(question, intent, evidence)

                with conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO ai_agent_queries (cloud_account_id, question, intent, evidence, answer, asked_by)
                            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
                        """, (account_id, question, intent, json.dumps(evidence, default=str), answer,
                              body.get("asked_by", "Admin")))
                        query_id = str(cur.fetchone()[0])

                return _resp(200, {"id": query_id, "intent": intent, "evidence": evidence, "answer": answer})

            if action == "create_remediation_task":
                query_id = body.get("query_id")
                finding_id = body.get("finding_id")
                title = body.get("title")
                owner_email = body.get("owner_email")
                due_date = body.get("due_date")
                if not (_is_uuid(query_id) and _is_uuid(finding_id) and title):
                    return _resp(400, {"error": "query_id, finding_id and title are required"})
                with conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM audit_findings WHERE id = %s", (finding_id,))
                        if not cur.fetchone():
                            return _resp(404, {"error": "That finding no longer exists in Audit Management."})
                        cur.execute("""
                            INSERT INTO audit_remediation_tasks (audit_finding_id, title, owner_email, due_date)
                            VALUES (%s, %s, %s, %s) RETURNING id
                        """, (finding_id, title, owner_email, due_date))
                        task_id = str(cur.fetchone()[0])
                        cur.execute("UPDATE audit_findings SET status = 'in_remediation' WHERE id = %s AND status = 'open'",
                                    (finding_id,))
                        cur.execute("""
                            UPDATE ai_agent_queries SET action_taken = 'create_remediation_task',
                                   action_details = %s WHERE id = %s
                        """, (json.dumps({"task_id": task_id, "finding_id": finding_id, "title": title}), query_id))
                return _resp(200, {"task_id": task_id})

            return _resp(400, {"error": f"unknown action: {action}"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.exception("ai_agent_handler error")
        return _resp(500, {"error": str(e)})
    finally:
        conn.close()
