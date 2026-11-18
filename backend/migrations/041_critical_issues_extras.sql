-- Zero Critical Issues (#296), second pass: engineering tickets, AI explanations kept with their inputs, and a
-- remediation deadline per source (identity findings often need a different deadline than storage settings).

ALTER TABLE critical_issues
    ADD COLUMN IF NOT EXISTS ticket          JSONB,
    ADD COLUMN IF NOT EXISTS ai_explanation  JSONB;

ALTER TABLE critical_issue_settings
    ADD COLUMN IF NOT EXISTS sla_by_source   JSONB NOT NULL DEFAULT '{}'::jsonb;
