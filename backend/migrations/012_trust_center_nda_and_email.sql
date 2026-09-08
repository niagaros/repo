-- Migration: Trust Center NDA click-through + real approval email tracking
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Closes two gaps found by re-checking the built Trust Center against
-- issue #258 and against how Vanta/Drata Trust Centers actually work:
--   1. Restricted documents had no confidentiality acknowledgement step
--      before a request could be submitted.
--   2. Approval only ever produced a link for the admin to copy-paste;
--      there was no attempt at a real automatic notification.
-- See docs/internal/architecture/aws/trust_center.md for the honest
-- account of what "real automatic email" required (an AWS SES production
-- access request, submitted and denied — case 178854954000928 — because
-- the account has no verified sending domain yet) and why the NDA
-- click-through has no such external blocker and is built for real here.

ALTER TABLE trust_document_access_requests
    ADD COLUMN IF NOT EXISTS nda_accepted_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS nda_accepted_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS email_status      VARCHAR(20),
    ADD COLUMN IF NOT EXISTS email_error       TEXT;

GRANT SELECT, INSERT, UPDATE, DELETE ON trust_document_access_requests TO cspm_lambda;
