-- Migration: questionnaire_share_links
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- "Secure sharing" from issue #259's Export & Delivery section: a real,
-- expiring, unguessable read-only link a customer/partner can open without
-- a Niagaros login. Only APPROVED items are ever visible through a share
-- link — an unreviewed AI draft or manual note is never exposed externally,
-- even if the questionnaire has one; the point of the review step is human
-- sign-off before anything leaves the building.

CREATE TABLE IF NOT EXISTS questionnaire_share_links (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    questionnaire_id UUID         NOT NULL REFERENCES questionnaires(id) ON DELETE CASCADE,
    token            VARCHAR(64)  NOT NULL UNIQUE,
    expires_at       TIMESTAMPTZ  NOT NULL,
    revoked          BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS questionnaire_share_links_token_idx ON questionnaire_share_links(token);
CREATE INDEX IF NOT EXISTS questionnaire_share_links_questionnaire_idx ON questionnaire_share_links(questionnaire_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON questionnaire_share_links TO cspm_lambda;
