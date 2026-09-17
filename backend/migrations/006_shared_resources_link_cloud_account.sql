-- Migration: link shared dashboards to a real connected cloud account
-- Run as cspm_admin
--
-- 005_shared_resources.sql let an admin "share a dashboard" that was just
-- a free-text name with no connection to anything real — clicking it in
-- the UI opened nothing. Niagaros already has exactly one real dashboard
-- (niagaros-dashboard.html?account_id=<cloud_accounts.id>), scoped to a
-- specific connected cloud account. This migration makes "sharing a
-- dashboard" mean sharing access to that real, existing dashboard for one
-- of the organization's own connected accounts, instead of an arbitrary
-- label.
--
-- Nullable + ON DELETE CASCADE: if the referenced cloud account is later
-- actually deleted (not just disconnected — disconnection only flips
-- status), the share stops making sense and should disappear with it.

ALTER TABLE shared_resources
    ADD COLUMN IF NOT EXISTS cloud_account_id UUID REFERENCES cloud_accounts(id) ON DELETE CASCADE;
