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
  - CSV, XLSX, and DOCX upload are implemented (XLSX parsed per-worksheet,
    only reading sheets with a recognizable "Question" header — real
    multi-tab questionnaires like CAIQ have 17 CCM-domain sheets; DOCX
    read directly from its OOXML via stdlib zipfile+ElementTree, no lxml
    dependency). PDF forms are not parsed — extracting reliable Q&A pairs
    from arbitrary PDF layouts needs real, dedicated work, and a rushed
    heuristic risks silently mis-reading questions, which is worse than
    refusing the upload with a clear error.
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

import base64
import csv
import io
import json
import logging
import os
import re
import secrets
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone

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
CREATE TABLE IF NOT EXISTS questionnaire_item_comments (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id       UUID         NOT NULL REFERENCES questionnaire_items(id) ON DELETE CASCADE,
    author_name   VARCHAR(120) NOT NULL,
    comment_text  TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS questionnaire_item_history (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id       UUID         NOT NULL REFERENCES questionnaire_items(id) ON DELETE CASCADE,
    from_status   VARCHAR(20),
    to_status     VARCHAR(20)  NOT NULL,
    actor_name    VARCHAR(120),
    changed_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS questionnaire_share_links (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    questionnaire_id UUID         NOT NULL REFERENCES questionnaires(id) ON DELETE CASCADE,
    token            VARCHAR(64)  NOT NULL UNIQUE,
    expires_at       TIMESTAMPTZ  NOT NULL,
    revoked          BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS questionnaires_account_idx ON questionnaires(cloud_account_id);
CREATE INDEX IF NOT EXISTS questionnaire_items_questionnaire_idx ON questionnaire_items(questionnaire_id);
CREATE INDEX IF NOT EXISTS questionnaire_item_comments_item_idx ON questionnaire_item_comments(item_id);
CREATE INDEX IF NOT EXISTS questionnaire_item_history_item_idx ON questionnaire_item_history(item_id);
CREATE INDEX IF NOT EXISTS questionnaire_share_links_token_idx ON questionnaire_share_links(token);
CREATE INDEX IF NOT EXISTS questionnaire_share_links_questionnaire_idx ON questionnaire_share_links(questionnaire_id);
"""

ADMIN_MIGRATION_SQL = BOOTSTRAP_SQL + """
GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaires TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaire_items TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON evidence_documents TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaire_item_comments TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaire_item_history TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaire_share_links TO cspm_lambda;
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


def _parse_xlsx(file_bytes):
    """Parses every worksheet independently — real multi-tab questionnaires
    (e.g. CAIQ's 17 CCM-domain sheets) put questions in different sheets with
    their own header row. A sheet is only read if one of its header cells
    contains "question" (case-insensitive); sheets without a recognizable
    question column (e.g. a cover/instructions tab) are silently skipped
    rather than guessing a column."""
    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=True)
    questions = []
    for ws in wb.worksheets:
        q_idx = a_idx = None
        header_found = False
        for row in ws.iter_rows(values_only=True):
            if not any(c not in (None, "") for c in row):
                continue
            if not header_found:
                header = [str(c).strip().lower() if c is not None else "" for c in row]
                q_idx = next((i for i, h in enumerate(header) if re.search(r"\bquestions?\b", h)), None)
                a_idx = next((i for i, h in enumerate(header) if re.search(r"\b(answer|response)s?\b", h)), None)
                header_found = True
                continue
            if q_idx is None or q_idx >= len(row):
                continue
            qtext = row[q_idx]
            if not qtext or not str(qtext).strip():
                continue
            existing = None
            if a_idx is not None and a_idx < len(row) and row[a_idx] not in (None, ""):
                existing = str(row[a_idx]).strip()
            questions.append((str(qtext).strip(), existing))
    return questions


DOCX_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _docx_text(elem):
    return "".join(t.text or "" for t in elem.iter(DOCX_W_NS + "t"))


def _parse_docx(file_bytes):
    """Reads word/document.xml directly via the stdlib zipfile + ElementTree
    (a .docx is just a zip of OOXML) instead of pulling in python-docx,
    which depends on lxml — a compiled C extension that would need a
    manylinux wheel vendored the same way psycopg2 is, for a format this
    simple to read directly. Two extraction strategies, in order:
      1. Any table with a header cell matching "question" as a whole word
         (the common case: a two/three-column Question/Answer table).
      2. If no such table exists, every paragraph ending in "?" is treated
         as a question — covers plainly-numbered-list questionnaires with
         no table structure at all."""
    with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
        xml_bytes = z.read("word/document.xml")
    body = ET.fromstring(xml_bytes).find(DOCX_W_NS + "body")

    questions = []
    for tbl in body.iter(DOCX_W_NS + "tbl"):
        rows = tbl.findall(DOCX_W_NS + "tr")
        if not rows:
            continue
        header_cells = [_docx_text(tc).strip().lower() for tc in rows[0].findall(DOCX_W_NS + "tc")]
        q_idx = next((i for i, h in enumerate(header_cells) if re.search(r"\bquestions?\b", h)), None)
        a_idx = next((i for i, h in enumerate(header_cells) if re.search(r"\b(answer|response)s?\b", h)), None)
        if q_idx is None:
            continue
        for tr in rows[1:]:
            cells = tr.findall(DOCX_W_NS + "tc")
            if q_idx >= len(cells):
                continue
            qtext = _docx_text(cells[q_idx]).strip()
            if not qtext:
                continue
            existing = _docx_text(cells[a_idx]).strip() if (a_idx is not None and a_idx < len(cells) and _docx_text(cells[a_idx]).strip()) else None
            questions.append((qtext, existing))

    if questions:
        return questions

    for p in body.findall(DOCX_W_NS + "p"):
        text = _docx_text(p).strip()
        if text.endswith("?"):
            questions.append((text, None))
    return questions


def _parse_uploaded_file(filename, file_base64):
    ext = (filename or "").rsplit(".", 1)[-1].lower()
    raw = base64.b64decode(file_base64)
    if ext in ("xlsx", "xlsm"):
        return _parse_xlsx(raw)
    if ext == "xls":
        raise ValueError("Legacy .xls files aren't supported — please re-save as .xlsx or .csv and re-upload.")
    if ext == "docx":
        return _parse_docx(raw)
    if ext == "doc":
        raise ValueError("Legacy .doc files aren't supported — please re-save as .docx or .csv and re-upload.")
    if ext == "pdf":
        raise ValueError("PDF questionnaires aren't supported yet — please export/retype the questions as .csv, .xlsx, or .docx and re-upload.")
    return _parse_csv(raw.decode("utf-8-sig", errors="replace"))


REUSE_SIMILARITY_THRESHOLD = 0.7


def _find_reused_answer(cur, cloud_account_id, question_text, exclude_questionnaire_id):
    """Acceptance criterion from issue #259: previously-approved answers to
    the same or a near-identical question, from any other questionnaire on
    this account, are surfaced automatically instead of re-answering from
    scratch every time. Similarity is plain Jaccard overlap on tokens — the
    same inspectable method used for evidence retrieval, not an embedding
    index. Deliberately conservative (0.7 default): a wrong reused answer
    on a security questionnaire is worse than missing a reuse opportunity,
    so this only fires on a strong match, and even then leaves the item at
    'needs_review' rather than auto-approving it."""
    q_tokens = _tokenize(question_text)
    if not q_tokens:
        return None
    cur.execute("""
        SELECT qi.question_text, qi.answer_text, q.name, q.id, qi.reviewed_at
        FROM questionnaire_items qi
        JOIN questionnaires q ON q.id = qi.questionnaire_id
        WHERE q.cloud_account_id = %s
          AND q.id != %s
          AND qi.answer_status = 'approved'
          AND qi.answer_text IS NOT NULL
    """, (cloud_account_id, exclude_questionnaire_id))

    best = None
    for candidate_q, candidate_a, source_name, source_qid, reviewed_at in cur.fetchall():
        c_tokens = _tokenize(candidate_q)
        if not c_tokens:
            continue
        union = q_tokens | c_tokens
        similarity = len(q_tokens & c_tokens) / len(union) if union else 0
        if similarity >= REUSE_SIMILARITY_THRESHOLD and (best is None or similarity > best["similarity"]):
            best = {
                "type": "reused",
                "answer_text": candidate_a,
                "source_questionnaire": source_name,
                "source_questionnaire_id": str(source_qid),
                "matched_question": candidate_q,
                "similarity": round(similarity, 2),
                "approved_at": reviewed_at.isoformat() if reviewed_at else None,
            }
    return best


def _upload_questionnaire(conn, cloud_account_id, name, filename, file_base64):
    questions = _parse_uploaded_file(filename, file_base64)
    if not questions:
        raise ValueError("No questions found in the uploaded file — expected one question per row/sheet-row, optionally under a header cell containing 'Question'.")
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO questionnaires (cloud_account_id, name, source_filename)
                VALUES (%s, %s, %s) RETURNING id
            """, (cloud_account_id, name, filename))
            questionnaire_id = cur.fetchone()[0]
            reused_count = 0
            for i, (question_text, existing_answer) in enumerate(questions, start=1):
                answer_text, status, confidence, evidence = existing_answer, ("needs_review" if existing_answer else "unanswered"), None, []
                if not existing_answer:
                    reuse = _find_reused_answer(cur, cloud_account_id, question_text, questionnaire_id)
                    if reuse:
                        answer_text = reuse["answer_text"]
                        status = "needs_review"
                        confidence = "high"
                        evidence = [reuse]
                        reused_count += 1
                cur.execute("""
                    INSERT INTO questionnaire_items
                        (questionnaire_id, row_number, question_text, answer_text, answer_status, confidence, evidence)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (questionnaire_id, i, question_text, answer_text, status, confidence, Json(evidence)))
    return str(questionnaire_id), len(questions), reused_count


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


def _evidence_tags(evidence):
    """Real tags derived from what an answer actually cites — a control's
    framework, or a doc's category — never an invented taxonomy."""
    tags = set()
    for e in evidence or []:
        if e.get("type") == "control" and e.get("framework"):
            tags.add(e["framework"])
        elif e.get("type") == "doc" and e.get("category"):
            tags.add(e["category"])
    return sorted(tags)


def _get_answer_library(cur, cloud_account_id, search=None):
    """Knowledge Base section from issue #259: a centralized, searchable,
    tagged library of approved answers, with version history. Grouped by
    exact question text — a real repeat of the same question across
    questionnaires — rather than fuzzy-matching, so "version history" only
    ever shows genuinely-the-same question answered more than once, not a
    guess at similarity."""
    cur.execute("""
        SELECT qi.question_text, qi.answer_text, qi.evidence, qi.reviewed_at, q.name
        FROM questionnaire_items qi
        JOIN questionnaires q ON q.id = qi.questionnaire_id
        WHERE q.cloud_account_id = %s AND qi.answer_status = 'approved' AND qi.answer_text IS NOT NULL
        ORDER BY qi.reviewed_at DESC NULLS LAST
    """, (cloud_account_id,))

    grouped = {}
    for question_text, answer_text, evidence, reviewed_at, questionnaire_name in cur.fetchall():
        entry = grouped.setdefault(question_text, {"question_text": question_text, "tags": set(), "versions": []})
        entry["tags"].update(_evidence_tags(evidence))
        entry["versions"].append({
            "answer_text": answer_text,
            "questionnaire_name": questionnaire_name,
            "approved_at": reviewed_at.isoformat() if reviewed_at else None,
        })

    results = []
    needle = (search or "").strip().lower()
    for entry in grouped.values():
        entry["tags"] = sorted(entry["tags"])
        if needle and needle not in entry["question_text"].lower() and needle not in entry["versions"][0]["answer_text"].lower() and not any(needle in t.lower() for t in entry["tags"]):
            continue
        results.append(entry)

    results.sort(key=lambda e: e["versions"][0]["approved_at"] or "", reverse=True)
    return results


def _get_analytics(cur, cloud_account_id):
    """Acceptance criterion from issue #259: "automation rates, review
    times, and completion metrics are displayed." Every number here is a
    direct aggregate over real stored rows — deliberately no "time saved"
    metric, since that would require inventing an assumed minutes-per-
    question constant with no real basis, which is exactly the kind of
    fabricated number this codebase avoids."""
    cur.execute("""
        SELECT qi.answer_status, qi.confidence, qi.ai_generated, qi.evidence,
               qi.created_at, qi.reviewed_at
        FROM questionnaire_items qi
        JOIN questionnaires q ON q.id = qi.questionnaire_id
        WHERE q.cloud_account_id = %s
    """, (cloud_account_id,))
    rows = cur.fetchall()

    total = len(rows)
    approved = sum(1 for r in rows if r[0] == "approved")
    answered = 0
    automation = {"ai_generated": 0, "reused": 0, "manual": 0, "unanswered": 0}
    confidence_counts = {"high": 0, "medium": 0, "low": 0, "none": 0}
    review_hours = []

    for status, confidence, ai_generated, evidence, created_at, reviewed_at in rows:
        confidence_counts[confidence or "none"] += 1
        was_reused = isinstance(evidence, list) and any(e.get("type") == "reused" for e in evidence)
        if ai_generated:
            automation["ai_generated"] += 1
            answered += 1
        elif was_reused:
            automation["reused"] += 1
            answered += 1
        elif status != "unanswered":
            automation["manual"] += 1
            answered += 1
        else:
            automation["unanswered"] += 1
        if reviewed_at:
            review_hours.append((reviewed_at - created_at).total_seconds() / 3600)

    cur.execute("""
        SELECT qi.question_text, COUNT(*) AS n
        FROM questionnaire_items qi
        JOIN questionnaires q ON q.id = qi.questionnaire_id
        WHERE q.cloud_account_id = %s AND qi.evidence = '[]'::jsonb AND qi.answer_text IS NULL
        GROUP BY qi.question_text
        HAVING COUNT(*) > 1
        ORDER BY n DESC
        LIMIT 10
    """, (cloud_account_id,))
    recurring_gaps = [{"question": r[0], "times_asked": r[1]} for r in cur.fetchall()]

    return {
        "total_questions": total,
        "answered_questions": answered,
        "approved_questions": approved,
        "completion_rate": round(approved / total, 3) if total else None,
        "automation_rate": round((automation["ai_generated"] + automation["reused"]) / answered, 3) if answered else None,
        "automation_breakdown": automation,
        "confidence_breakdown": confidence_counts,
        "avg_review_time_hours": round(sum(review_hours) / len(review_hours), 2) if review_hours else None,
        "reviewed_count": len(review_hours),
        "recurring_evidence_gaps": recurring_gaps,
    }


def _current_control_status(cur, cloud_account_id):
    cur.execute("""
        SELECT f.check_id, BOOL_OR(f.result = 'FAIL') AS any_fail,
               COUNT(*) FILTER (WHERE f.result = 'PASS') AS n_pass,
               COUNT(*) FILTER (WHERE f.result = 'FAIL') AS n_fail
        FROM findings f
        JOIN resources r ON r.id = f.resource_id
        WHERE r.cloud_account_id = %s
        GROUP BY f.check_id
    """, (cloud_account_id,))
    return {
        check_id: {"status": "FAIL" if any_fail else "PASS", "passed": n_pass, "failed": n_fail}
        for check_id, any_fail, n_pass, n_fail in cur.fetchall()
    }


def _is_stale(evidence, current_status):
    """Acceptance criterion from issue #259: "Given compliance evidence
    changes, when a related questionnaire is reopened, then outdated
    responses are identified and recommended for review." Compares the
    control status/counts an answer was drafted from against the current
    live scan state — the same worst-case-PASS/FAIL computation every
    mapper and _find_control_evidence already use, so this is comparing
    like with like, not a different metric."""
    for e in evidence or []:
        if e.get("type") != "control":
            continue
        current = current_status.get(e.get("check_id"))
        if current is None:
            continue  # check no longer produces findings — ambiguous, don't flag
        if (current["status"] != e.get("status")
                or current["passed"] != e.get("passed")
                or current["failed"] != e.get("failed")):
            return True
    return False


def _get_questionnaire(cur, questionnaire_id):
    cur.execute("SELECT id, name, source_filename, status, created_at, cloud_account_id FROM questionnaires WHERE id = %s", (questionnaire_id,))
    row = cur.fetchone()
    if not row:
        return None
    q = {"id": str(row[0]), "name": row[1], "source_filename": row[2], "status": row[3], "created_at": row[4].isoformat()}
    cloud_account_id = row[5]
    cur.execute("""
        SELECT id, row_number, question_text, answer_text, answer_status, confidence, evidence, ai_generated
        FROM questionnaire_items WHERE questionnaire_id = %s ORDER BY row_number
    """, (questionnaire_id,))
    items = [{
        "id": str(r[0]), "row_number": r[1], "question_text": r[2], "answer_text": r[3],
        "answer_status": r[4], "confidence": r[5], "evidence": r[6], "ai_generated": r[7],
    } for r in cur.fetchall()]

    current_status = _current_control_status(cur, cloud_account_id)

    item_ids = [item["id"] for item in items]
    comments_by_item, history_by_item = {}, {}
    if item_ids:
        cur.execute("""
            SELECT item_id, id, author_name, comment_text, created_at
            FROM questionnaire_item_comments WHERE item_id = ANY(%s::uuid[]) ORDER BY created_at
        """, (item_ids,))
        for item_id, cid, author_name, comment_text, created_at in cur.fetchall():
            comments_by_item.setdefault(str(item_id), []).append({
                "id": str(cid), "author_name": author_name, "comment_text": comment_text,
                "created_at": created_at.isoformat(),
            })
        cur.execute("""
            SELECT item_id, from_status, to_status, actor_name, changed_at
            FROM questionnaire_item_history WHERE item_id = ANY(%s::uuid[]) ORDER BY changed_at
        """, (item_ids,))
        for item_id, from_status, to_status, actor_name, changed_at in cur.fetchall():
            history_by_item.setdefault(str(item_id), []).append({
                "from_status": from_status, "to_status": to_status, "actor_name": actor_name,
                "changed_at": changed_at.isoformat(),
            })

    for item in items:
        item["is_stale"] = bool(item["answer_text"]) and _is_stale(item["evidence"], current_status)
        item["comments"] = comments_by_item.get(item["id"], [])
        item["history"] = history_by_item.get(item["id"], [])

    q["items"] = items
    q["outstanding_count"] = sum(1 for i in items if i["answer_status"] != "approved")
    return q


def _update_item(conn, item_id, answer_text=None, answer_status=None, actor_name=None):
    sets, params = [], []
    if answer_text is not None:
        sets.append("answer_text = %s")
        params.append(answer_text)
        sets.append("ai_generated = FALSE")
    prior_status = None
    if answer_status is not None:
        with conn.cursor() as cur:
            cur.execute("SELECT answer_status FROM questionnaire_items WHERE id = %s", (item_id,))
            row = cur.fetchone()
            prior_status = row[0] if row else None
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
            if answer_status is not None and answer_status != prior_status:
                cur.execute("""
                    INSERT INTO questionnaire_item_history (item_id, from_status, to_status, actor_name)
                    VALUES (%s, %s, %s, %s)
                """, (item_id, prior_status, answer_status, actor_name))


def _add_comment(conn, item_id, author_name, comment_text):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO questionnaire_item_comments (item_id, author_name, comment_text)
                VALUES (%s, %s, %s) RETURNING id, created_at
            """, (item_id, author_name, comment_text))
            cid, created_at = cur.fetchone()
    return {"id": str(cid), "author_name": author_name, "comment_text": comment_text, "created_at": created_at.isoformat()}


def _delete_questionnaire(conn, questionnaire_id):
    with conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM questionnaires WHERE id = %s", (questionnaire_id,))


# ── secure sharing ───────────────────────────────────────────────────

SHARE_LINK_DEFAULT_DAYS = 7


def _create_share_link(conn, questionnaire_id, days=SHARE_LINK_DEFAULT_DAYS):
    token = secrets.token_urlsafe(32)
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO questionnaire_share_links (questionnaire_id, token, expires_at)
                VALUES (%s, %s, NOW() + (%s || ' days')::interval)
                RETURNING token, expires_at
            """, (questionnaire_id, token, days))
            token, expires_at = cur.fetchone()
    return {"token": token, "expires_at": expires_at.isoformat()}


def _list_share_links(cur, questionnaire_id):
    cur.execute("""
        SELECT token, expires_at, revoked, created_at FROM questionnaire_share_links
        WHERE questionnaire_id = %s ORDER BY created_at DESC
    """, (questionnaire_id,))
    return [{
        "token": r[0], "expires_at": r[1].isoformat(), "revoked": r[2], "created_at": r[3].isoformat(),
        "active": (not r[2]) and r[1] > datetime.now(timezone.utc),
    } for r in cur.fetchall()]


def _revoke_share_link(conn, token):
    with conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE questionnaire_share_links SET revoked = TRUE WHERE token = %s", (token,))


def _get_shared_questionnaire(cur, token):
    """Public, unauthenticated read path for a share link. Only APPROVED
    items are ever returned — an unreviewed AI draft or in-progress manual
    note never leaves the building through a share link, regardless of how
    much real evidence backs it. Unapproved items still appear, with the
    answer withheld, so an external viewer sees the full question list and
    an honest "pending internal review" status rather than silently
    missing rows."""
    cur.execute("""
        SELECT q.id, q.name, q.created_at
        FROM questionnaire_share_links sl
        JOIN questionnaires q ON q.id = sl.questionnaire_id
        WHERE sl.token = %s AND sl.revoked = FALSE AND sl.expires_at > NOW()
    """, (token,))
    row = cur.fetchone()
    if not row:
        return None
    questionnaire_id, name, created_at = row
    cur.execute("""
        SELECT row_number, question_text, answer_text, answer_status
        FROM questionnaire_items WHERE questionnaire_id = %s ORDER BY row_number
    """, (questionnaire_id,))
    items = []
    for row_number, question_text, answer_text, answer_status in cur.fetchall():
        is_approved = answer_status == "approved"
        items.append({
            "row_number": row_number,
            "question_text": question_text,
            "answer_text": answer_text if is_approved else None,
            "status": "answered" if is_approved else "pending_internal_review",
        })
    return {"name": name, "created_at": created_at.isoformat(), "items": items}


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
            if qs.get("share_token"):
                with conn.cursor() as cur:
                    shared = _get_shared_questionnaire(cur, qs["share_token"])
                if not shared:
                    return _resp(404, {"error": "This share link is invalid, expired, or has been revoked."})
                return _resp(200, shared)
            if qs.get("questionnaire_id"):
                with conn.cursor() as cur:
                    q = _get_questionnaire(cur, qs["questionnaire_id"])
                    if not q:
                        return _resp(404, {"error": "not found"})
                    q["share_links"] = _list_share_links(cur, qs["questionnaire_id"])
                return _resp(200, q)
            account_id = qs.get("cloud_account_id")
            if not account_id:
                return _resp(400, {"error": "cloud_account_id required"})
            if qs.get("analytics"):
                with conn.cursor() as cur:
                    return _resp(200, _get_analytics(cur, account_id))
            if qs.get("library"):
                with conn.cursor() as cur:
                    return _resp(200, {"entries": _get_answer_library(cur, account_id, qs.get("q"))})
            with conn.cursor() as cur:
                return _resp(200, {"questionnaires": _list_questionnaires(cur, account_id)})

        if method == "POST":
            action = body.get("action")
            if action == "upload":
                try:
                    filename = body.get("filename", "")
                    if "file_base64" in body:
                        file_b64 = body["file_base64"]
                    else:
                        # Back-compat: plain CSV text sent directly (no file picker).
                        file_b64 = base64.b64encode(body["csv_text"].encode("utf-8")).decode("ascii")
                        filename = filename or "upload.csv"
                    qid, n, reused = _upload_questionnaire(conn, body["cloud_account_id"], body["name"], filename, file_b64)
                except ValueError as ve:
                    return _resp(400, {"error": str(ve)})
                return _resp(200, {"id": qid, "questions_imported": n, "reused_from_prior_approvals": reused})
            if action == "generate_item":
                return _resp(200, _generate_item(conn, body["item_id"]))
            if action == "generate_all":
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT id FROM questionnaire_items
                        WHERE questionnaire_id = %s AND answer_text IS NULL
                        ORDER BY row_number
                    """, (body["questionnaire_id"],))
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
                _update_item(conn, body["item_id"], body.get("answer_text"), body.get("answer_status"), body.get("actor_name"))
                return _resp(200, {"updated": True})
            if action == "add_comment":
                comment = _add_comment(conn, body["item_id"], body.get("author_name", "Anonymous"), body["comment_text"])
                return _resp(200, comment)
            if action == "create_share_link":
                link = _create_share_link(conn, body["questionnaire_id"], body.get("days", SHARE_LINK_DEFAULT_DAYS))
                return _resp(200, link)
            if action == "revoke_share_link":
                _revoke_share_link(conn, body["token"])
                return _resp(200, {"revoked": True})
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
