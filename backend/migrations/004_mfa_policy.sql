-- Migration: organization-level MFA policy (issue #265, acceptance
-- criterion #3)
-- Run as cspm_admin
--
-- "Given MFA is required by policy, when a user signs in without MFA
--  configured, then access is blocked until enrollment is completed."
--
-- This only stores the POLICY (does this organization require MFA for
-- all its members?). Actually enforcing it — checking a user's real
-- Cognito MFA status and blocking access — happens client-side via
-- Amplify Auth (fetchMFAPreference) in useRequireAuth.ts, since that's
-- genuinely a Cognito concern, not something this Postgres database
-- tracks or could enforce on its own.

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN NOT NULL DEFAULT false;
