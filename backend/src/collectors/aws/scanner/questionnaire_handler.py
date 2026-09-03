"""
questionnaire_handler.py

Questionnaire Automation for Security Reviews (GitHub issue #259), v1.

Two responsibilities in one Lambda, dispatched by event shape, same pattern
as custom_framework_handler.py:
  - API Gateway proxy events (event["httpMethod"] present): CRUD + AI-draft
    generation, served to frontend/public/questionnaire_automation.html.
  - {"migrate": true} / {"seed_evidence_docs": [...]}: one-time admin setup,
    run manually, not part of the orchestrator's scan cycle.

Honesty constraints this file is deliberately built around (see issue
discussion and the rest of this codebase's "no fabricated checks" rule):
  - Only CSV upload is implemented. XLSX/DOCX/PDF are not parsed in v1;
    callers get a clear "not supported yet" error instead of silent
    mis-parsing.
  - An answer is only drafted from evidence this account actually has:
    its own live compliance findings (findings/resources tables) and
    Niagaros' own published security docs (evidence_documents, seeded
    from docs/public/security/**/*.md). Retrieval is plain keyword
    overlap — no vector index, no invented semantic matching.
  - Confidence is computed from how much real evidence was found, not
    self-reported by the model.
  - If the Groq API key isn't configured yet, or no evidence was found
    for a question, no AI draft is produced — the item is left for a
    human to answer, with whatever real evidence was found still attached
    so a reviewer isn't starting from nothing.
"""

import csv
import io
import json
import logging
import os
import re
import urllib.request

import boto3
import psycopg2
from psycopg2.extras import Json

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}

GROQ_MODEL_ID = os.environ.get("GROQ_MODEL_ID", "openai/gpt-oss-120b")
GROQ_SECRET_NAME = os.environ.get("GROQ_SECRET_NAME", "cspm/questionnaire/groq-api-key")

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS questionnaires (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    name             VARCHAR(255) NOT NULL,
    source_filename  VARCHAR(255),
    status           VARCHAR(20)  NOT NULL DEFAULT 'draft',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS questionnaire_items (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    questionnaire_id  UUID         NOT NULL REFERENCES questionnaires(id) ON DELETE CASCADE,
    row_number        INT          NOT NULL,
    question_text     TEXT         NOT NULL,
    answer_text       TEXT,
    answer_status     VARCHAR(20)  NOT NULL DEFAULT 'unanswered',
    confidence        VARCHAR(10),
    evidence          JSONB        NOT NULL DEFAULT '[]',
    ai_generated      BOOLEAN      NOT NULL DEFAULT FALSE,
    reviewed_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS evidence_documents (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    source_path   VARCHAR(500) NOT NULL,
    category      VARCHAR(100),
    section_title VARCHAR(255),
    content       TEXT         NOT NULL,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (source_path, section_title)
);
CREATE INDEX IF NOT EXISTS questionnaires_account_idx ON questionnaires(cloud_account_id);
CREATE INDEX IF NOT EXISTS questionnaire_items_questionnaire_idx ON questionnaire_items(questionnaire_id);
"""

ADMIN_MIGRATION_SQL = BOOTSTRAP_SQL + """
GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaires TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaire_items TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON evidence_documents TO cspm_lambda;
"""

STOPWORDS = set("""
a an the is are was were be been being do does did will would should could
can may might must shall of to in on at for with without by from as and or
but if then than that this these those it its your you we our their they
he she his her him please provide describe explain does your company have
has do you what how when where which who all any not no yes
""".split())


def _tokenize(text: str) -> set:
    words = re.findall(r"[a-zA-Z][a-zA-Z0-9\-]{2,}", (text or "").lower())
    return {w for w in words if w not in STOPWORDS}


def _get_connection():
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    client = boto3.client("secretsmanager", region_name=region)
    secret = json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return psycopg2.connect(
        host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
        user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
    )


# ── evidence retrieval (real data only) ──────────────────────────────

def _find_control_evidence(cur, cloud_account_id, q_tokens, limit=5):
    cur.execute("""
        SELECT f.check_id, MAX(f.title) AS title, MAX(f.description) AS description,
               MAX(f.framework) AS framework, BOOL_OR(f.result = 'FAIL') AS any_fail,
               COUNT(*) FILTER (WHERE f.result = 'PASS') AS n_pass,
               COUNT(*) FILTER (WHERE f.result = 'FAIL') AS n_fail
        FROM findings f
        JOIN resources r ON r.id = f.resource_id
        WHERE r.cloud_account_id = %s
        GROUP BY f.check_id
    """, (cloud_account_id,))
    scored = []
    for check_id, title, description, framework, any_fail, n_pass, n_fail in cur.fetchall():
        tokens = _tokenize(title) | _tokenize(description)
        overlap = q_tokens & tokens
        if len(overlap) >= 2:
            scored.append({
                "score": len(overlap),
                "type": "control",
                "check_id": check_id,
                "title": title,
                "description": description,
                "framework": framework,
                "status": "FAIL" if any_fail else "PASS",
                "passed": n_pass,
                "failed": n_fail,
            })
    scored.sort(key=lambda x: -x["score"])
    return scored[:limit]


def _find_doc_evidence(cur, q_tokens, limit=5):
    cur.execute("SELECT source_path, category, section_title, content FROM evidence_documents")
    scored = []
    for source_path, category, section_title, content in cur.fetchall():
        tokens = _tokenize(section_title) | _tokenize(content)
        overlap = q_tokens & tokens
        if len(overlap) >= 2:
            excerpt = content.strip()
            if len(excerpt) > 500:
                excerpt = excerpt[:500].rsplit(" ", 1)[0] + "…"
            scored.append({
                "score": len(overlap),
                "type": "doc",
                "source_path": source_path,
                "category": category,
                "section_title": section_title,
                "excerpt": excerpt,
            })
    scored.sort(key=lambda x: -x["score"])
    return scored[:limit]


def _confidence(control_ev, doc_ev):
    if control_ev and doc_ev:
        return "high"
    if control_ev or doc_ev:
        return "medium"
    return "low"


# ── AI drafting (Bedrock, grounded strictly in retrieved evidence) ──────

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


def _draft_answer(question_text, control_ev, doc_ev):
    """Returns (answer_text, error). error is a short string if the
    drafting API isn't usable; answer_text is None in that case."""
    if not control_ev and not doc_ev:
        return None, None  # no evidence — caller skips drafting, that's expected

    lines = []
    for e in control_ev:
        lines.append(
            f"- Compliance control {e['check_id']} ({e['framework']}): {e['title']}. "
            f"Current status in this account: {e['status']} "
            f"({e['passed']} resources passing, {e['failed']} failing)."
        )
    for e in doc_ev:
        lines.append(f"- Published security documentation — {e['section_title']}: {e['excerpt']}")
    evidence_block = "\n".join(lines)

    prompt = (
        "You are drafting a candidate answer to one question from a customer's "
        "security/vendor-assessment questionnaire (e.g. CAIQ, SIG). Use ONLY the "
        "evidence listed below, which comes from this vendor's own live compliance "
        "scan results and published security documentation. Do not invent facts, "
        "certifications, dates, or numbers that are not present in the evidence. "
        "If the evidence only partially answers the question, say what is covered "
        "and explicitly note what is not. Write 2-5 sentences, professional tone, "
        "as if written by the vendor's security team.\n\n"
        f"Question: {question_text}\n\n"
        f"Evidence:\n{evidence_block}\n\n"
        "Draft answer:"
    )

    try:
        api_key = _get_groq_key()
        req_body = json.dumps({
            "model": GROQ_MODEL_ID,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 400,
            "temperature": 0.2,
            "reasoning_effort": "low",
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=req_body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "Mozilla/5.0 (compatible; niagaros-questionnaire-handler/1.0)",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read())
        answer = payload["choices"][0]["message"]["content"].strip()
        return (answer or None), None
    except Exception as e:
        logger.warning("AI draft generation unavailable: %s", e)
        return None, str(e)


def _generate_item(conn, item_id):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT qi.question_text, q.cloud_account_id
            FROM questionnaire_items qi
            JOIN questionnaires q ON q.id = qi.questionnaire_id
            WHERE qi.id = %s
        """, (item_id,))
        row = cur.fetchone()
        if not row:
            return {"error": "item not found"}
        question_text, cloud_account_id = row

        q_tokens = _tokenize(question_text)
        control_ev = _find_control_evidence(cur, cloud_account_id, q_tokens)
        doc_ev = _find_doc_evidence(cur, q_tokens)
        confidence = _confidence(control_ev, doc_ev)
        evidence = control_ev + doc_ev

    answer, bedrock_error = _draft_answer(question_text, control_ev, doc_ev)

    with conn:
        with conn.cursor() as cur:
            if answer:
                cur.execute("""
                    UPDATE questionnaire_items
                    SET answer_text = %s, confidence = %s, evidence = %s,
                        ai_generated = TRUE, answer_status = 'draft', updated_at = NOW()
                    WHERE id = %s
                """, (answer, confidence, Json(evidence), item_id))
            else:
                cur.execute("""
                    UPDATE questionnaire_items
                    SET confidence = %s, evidence = %s, ai_generated = FALSE,
                        answer_status = 'needs_review', updated_at = NOW()
                    WHERE id = %s
                """, (confidence, Json(evidence), item_id))

    if answer:
        return {"generated": True, "answer": answer, "confidence": confidence, "evidence": evidence}
    if not control_ev and not doc_ev:
        return {"generated": False, "reason": "no_evidence", "confidence": confidence, "evidence": evidence}
    return {"generated": False, "reason": "bedrock_unavailable", "detail": bedrock_error,
            "confidence": confidence, "evidence": evidence}


# ── CRUD ──────────────────────────────────────────────────────────────

def _parse_csv(csv_text):
    reader = csv.reader(io.StringIO(csv_text))
    rows = [r for r in reader if any(c.strip() for c in r)]
    if not rows:
        return []
    header = [c.strip().lower() for c in rows[0]]
    q_idx, a_idx = 0, None
    if "question" in header:
        q_idx = header.index("question")
        data_rows = rows[1:]
        for cand in ("answer", "existing answer", "current answer"):
            if cand in header:
                a_idx = header.index(cand)
        if "answer" not in header and a_idx is None:
            pass
    else:
        data_rows = rows

    questions = []
    for r in data_rows:
        if q_idx >= len(r) or not r[q_idx].strip():
            continue
        existing_answer = r[a_idx].strip() if (a_idx is not None and a_idx < len(r) and r[a_idx].strip()) else None
        questions.append((r[q_idx].strip(), existing_answer))
    return questions


def _upload_questionnaire(conn, cloud_account_id, name, filename, csv_text):
    questions = _parse_csv(csv_text)
    if not questions:
        raise ValueError("No questions found in the uploaded CSV — expected one question per row, optionally with a header row containing a 'Question' column.")
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO questionnaires (cloud_account_id, name, source_filename)
                VALUES (%s, %s, %s) RETURNING id
            """, (cloud_account_id, name, filename))
            questionnaire_id = cur.fetchone()[0]
            for i, (question_text, existing_answer) in enumerate(questions, start=1):
                status = "unanswered" if not existing_answer else "needs_review"
                cur.execute("""
                    INSERT INTO questionnaire_items (questionnaire_id, row_number, question_text, answer_text, answer_status)
                    VALUES (%s, %s, %s, %s, %s)
                """, (questionnaire_id, i, question_text, existing_answer, status))
    return str(questionnaire_id), len(questions)


def _list_questionnaires(cur, cloud_account_id):
    cur.execute("""
        SELECT q.id, q.name, q.source_filename, q.status, q.created_at,
               COUNT(qi.id) AS total,
               COUNT(qi.id) FILTER (WHERE qi.answer_status = 'approved') AS approved,
               COUNT(qi.id) FILTER (WHERE qi.answer_text IS NOT NULL) AS answered
        FROM questionnaires q
        LEFT JOIN questionnaire_items qi ON qi.questionnaire_id = q.id
        WHERE q.cloud_account_id = %s
        GROUP BY q.id ORDER BY q.created_at DESC
    """, (cloud_account_id,))
    return [{
        "id": str(r[0]), "name": r[1], "source_filename": r[2], "status": r[3],
        "created_at": r[4].isoformat(), "total": r[5], "approved": r[6], "answered": r[7],
    } for r in cur.fetchall()]


def _get_questionnaire(cur, questionnaire_id):
    cur.execute("SELECT id, name, source_filename, status, created_at FROM questionnaires WHERE id = %s", (questionnaire_id,))
    row = cur.fetchone()
    if not row:
        return None
    q = {"id": str(row[0]), "name": row[1], "source_filename": row[2], "status": row[3], "created_at": row[4].isoformat()}
    cur.execute("""
        SELECT id, row_number, question_text, answer_text, answer_status, confidence, evidence, ai_generated
        FROM questionnaire_items WHERE questionnaire_id = %s ORDER BY row_number
    """, (questionnaire_id,))
    q["items"] = [{
        "id": str(r[0]), "row_number": r[1], "question_text": r[2], "answer_text": r[3],
        "answer_status": r[4], "confidence": r[5], "evidence": r[6], "ai_generated": r[7],
    } for r in cur.fetchall()]
    return q


def _update_item(conn, item_id, answer_text=None, answer_status=None):
    sets, params = [], []
    if answer_text is not None:
        sets.append("answer_text = %s")
        params.append(answer_text)
        sets.append("ai_generated = FALSE")
    if answer_status is not None:
        sets.append("answer_status = %s")
        params.append(answer_status)
        if answer_status == "approved":
            sets.append("reviewed_at = NOW()")
    if not sets:
        return
    sets.append("updated_at = NOW()")
    params.append(item_id)
    with conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE questionnaire_items SET {', '.join(sets)} WHERE id = %s", params)


def _delete_questionnaire(conn, questionnaire_id):
    with conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM questionnaires WHERE id = %s", (questionnaire_id,))


# ── entrypoint ────────────────────────────────────────────────────────

def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body)}


def handler(event, context):
    if event and event.get("migrate"):
        secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
        region = os.environ.get("SECRET_REGION", "eu-west-1")
        secret = json.loads(boto3.client("secretsmanager", region_name=region).get_secret_value(SecretId=secret_name)["SecretString"])
        conn = psycopg2.connect(
            host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
            user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
        )
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(ADMIN_MIGRATION_SQL)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()

    if event and "seed_evidence_docs" in event:
        conn = _get_connection()
        try:
            n = 0
            with conn:
                with conn.cursor() as cur:
                    for d in event["seed_evidence_docs"]:
                        cur.execute("""
                            INSERT INTO evidence_documents (source_path, category, section_title, content)
                            VALUES (%s, %s, %s, %s)
                            ON CONFLICT (source_path, section_title) DO UPDATE
                                SET content = EXCLUDED.content, category = EXCLUDED.category, updated_at = NOW()
                        """, (d["source_path"], d.get("category"), d.get("section_title") or "", d["content"]))
                        n += 1
            return {"statusCode": 200, "body": json.dumps({"seeded": n})}
        finally:
            conn.close()

    if not event or "httpMethod" not in event:
        return {"statusCode": 400, "body": json.dumps({"error": "no orchestrator mapping — this is not a compliance framework mapper"})}

    method = event["httpMethod"]
    if method == "OPTIONS":
        return _resp(200, {})

    qs = event.get("queryStringParameters") or {}
    body = json.loads(event["body"]) if event.get("body") else {}

    conn = _get_connection()
    try:
        if method == "GET":
            if qs.get("questionnaire_id"):
                q = _get_questionnaire(conn.cursor(), qs["questionnaire_id"])
                if not q:
                    return _resp(404, {"error": "not found"})
                return _resp(200, q)
            account_id = qs.get("cloud_account_id")
            if not account_id:
                return _resp(400, {"error": "cloud_account_id required"})
            with conn.cursor() as cur:
                return _resp(200, {"questionnaires": _list_questionnaires(cur, account_id)})

        if method == "POST":
            action = body.get("action")
            if action == "upload":
                try:
                    qid, n = _upload_questionnaire(conn, body["cloud_account_id"], body["name"], body.get("filename", ""), body["csv_text"])
                except ValueError as ve:
                    return _resp(400, {"error": str(ve)})
                return _resp(200, {"id": qid, "questions_imported": n})
            if action == "generate_item":
                return _resp(200, _generate_item(conn, body["item_id"]))
            if action == "generate_all":
                with conn.cursor() as cur:
                    cur.execute("SELECT id FROM questionnaire_items WHERE questionnaire_id = %s ORDER BY row_number", (body["questionnaire_id"],))
                    item_ids = [str(r[0]) for r in cur.fetchall()]
                results = {"generated": 0, "no_evidence": 0, "bedrock_unavailable": 0}
                for iid in item_ids:
                    r = _generate_item(conn, iid)
                    if r.get("generated"):
                        results["generated"] += 1
                    elif r.get("reason") == "no_evidence":
                        results["no_evidence"] += 1
                    elif r.get("reason") == "bedrock_unavailable":
                        results["bedrock_unavailable"] += 1
                return _resp(200, results)
            if action == "update_item":
                _update_item(conn, body["item_id"], body.get("answer_text"), body.get("answer_status"))
                return _resp(200, {"updated": True})
            return _resp(400, {"error": f"unknown action: {action}"})

        if method == "DELETE":
            if qs.get("questionnaire_id"):
                _delete_questionnaire(conn, qs["questionnaire_id"])
                return _resp(200, {"deleted": "questionnaire"})
            return _resp(400, {"error": "questionnaire_id required"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.error("questionnaire_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": str(e)})
    finally:
        conn.close()
