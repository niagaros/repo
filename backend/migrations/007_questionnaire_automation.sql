-- Migration: questionnaires / questionnaire_items / evidence_documents
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Backs Questionnaire Automation for Security Reviews (GitHub issue #259).
-- v1 scope, built end-to-end and real rather than a stub for every bullet
-- in the issue:
--   - Upload a questionnaire as CSV (one question per row); XLSX/DOCX/PDF
--     parsing is not implemented yet and the UI says so rather than
--     pretending to support it.
--   - Each question is matched against this account's real, already-scanned
--     compliance findings AND a knowledge base of Niagaros' own published
--     security documentation (evidence_documents, seeded from
--     docs/public/security/**/*.md) using keyword overlap — no vector
--     index in v1, this is deliberately simple and inspectable.
--   - An AI draft answer is only generated from the evidence actually
--     retrieved (via Amazon Bedrock); if Bedrock access isn't provisioned
--     on the account yet, or no evidence was found, the item is left for
--     manual entry instead of fabricating an answer.
--   - Confidence is a programmatic function of how much real evidence was
--     found (0 matches -> low/manual, weak match -> medium, a live control
--     result plus a doc section -> high) — never the model's own
--     self-reported confidence.
--   - Review workflow (draft -> needs_review -> approved) and CSV export
--     are implemented. Collaboration (mentions/comments), analytics, and
--     reuse of a per-account "approved answer library" across
--     questionnaires are not built in v1.

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

GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaires TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaire_items TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON evidence_documents TO cspm_lambda;
