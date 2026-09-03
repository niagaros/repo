-- Migration: questionnaire_item_comments / questionnaire_item_history
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Adds the Collaboration section from issue #259 (comments, approval
-- history) to Questionnaire Automation. There's no multi-user auth system
-- wired into this Lambda (the dashboard token is opaque, validated
-- elsewhere) — author_name is a free-text display name the browser asks
-- for once and remembers in localStorage, not a fabricated identity/role
-- system. "Assigned reviewers" and "@mentions" from the issue are not
-- built here: without real user accounts to assign/notify, faking that
-- would mean storing names with no actual routing/notification behind
-- them, which is the kind of feature-shaped placeholder this codebase
-- avoids.

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

CREATE INDEX IF NOT EXISTS questionnaire_item_comments_item_idx ON questionnaire_item_comments(item_id);
CREATE INDEX IF NOT EXISTS questionnaire_item_history_item_idx ON questionnaire_item_history(item_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaire_item_comments TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaire_item_history TO cspm_lambda;
