-- Migration: findings.first_detected_at
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- findings.detected_at is overwritten to NOW() on every scan run for every
-- finding, whether it's brand new or has existed for months (see
-- db_writer.py's and every framework mapper handler's ON CONFLICT DO
-- UPDATE, which always sets detected_at = NOW()). So it really means
-- "last verified at", not "first appeared at" — there was no real column
-- to answer "which issue was most recently added" from.
--
-- first_detected_at is set once on INSERT and is never listed in any
-- ON CONFLICT DO UPDATE SET clause anywhere in the codebase, so it stays
-- truthful across every future rescan without needing any other code
-- changes. Existing rows are backfilled to their current detected_at as
-- an honest floor — their true original detection time predates this
-- column and isn't recoverable, so this is the earliest truthful value
-- available, not a guess at history.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS first_detected_at TIMESTAMPTZ;
UPDATE findings SET first_detected_at = detected_at WHERE first_detected_at IS NULL;
ALTER TABLE findings ALTER COLUMN first_detected_at SET DEFAULT NOW();

GRANT SELECT, INSERT, UPDATE ON findings TO cspm_lambda;
