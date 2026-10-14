-- Allow an audit engagement to be ended before its agreed end date.
--
-- Issue #266, acceptance criterion 3 covers the other direction: access
-- expires once end_date passes, which works because access is computed on
-- every request rather than stored. What was missing is the ability to end
-- one early. An engagement could be created but never closed, shortened or
-- amended, so adding the wrong auditor — or an audit that stops ahead of
-- schedule — could not be undone without going into the database by hand.
--
-- Why a column and not simply moving end_date backwards: migration 007
-- carries CHECK (end_date >= start_date), and start_date defaults to the
-- day the engagement was created. Setting end_date to yesterday on an
-- engagement created today is therefore rejected by the database. Moving
-- start_date along with it would falsify when the audit actually began,
-- which is the kind of record an auditor may later need to cite.
--
-- Closing early and expiring on schedule are also genuinely different
-- events, and an audit trail is worth more when it can tell them apart.
ALTER TABLE audit_engagements ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ;

-- Nothing to backfill: an engagement that has not been closed has no closing
-- moment, and NULL says exactly that. Existing rows keep expiring on their
-- end date as before.

COMMENT ON COLUMN audit_engagements.closed_at IS
    'Set when an admin ends the engagement before its end_date. NULL means it was never closed early; access then expires on end_date as usual.';
