-- Migration: questionnaire_items.edited_after_ai
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Backs the last two Analytics bullets from issue #259: "manual edits
-- required" and "most common questions". Set in _update_item whenever an
-- AI-generated answer's text is changed before approval — a real signal
-- of how much a draft actually needed correcting, not an estimate.

ALTER TABLE questionnaire_items ADD COLUMN IF NOT EXISTS edited_after_ai BOOLEAN NOT NULL DEFAULT FALSE;
