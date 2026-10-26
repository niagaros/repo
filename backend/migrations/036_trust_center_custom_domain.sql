-- Custom Trust Center domain (#272), e.g. trust.domits.com.
-- A domain only serves an account's Trust Center once custom_domain_verified_at is set, which happens after the
-- account proved DNS control with a TXT record holding custom_domain_token. Only verified domains must be unique,
-- so an unverified claim can never block the real owner.
-- Run as admin (the table is admin-owned). Same statements as trust_center_handler.ADMIN_MIGRATION_SQL.
SET lock_timeout = '5s';
ALTER TABLE trust_center_settings
    ADD COLUMN IF NOT EXISTS custom_domain             VARCHAR(253),
    ADD COLUMN IF NOT EXISTS custom_domain_token       VARCHAR(64),
    ADD COLUMN IF NOT EXISTS custom_domain_verified_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS trust_center_settings_verified_domain_uq
    ON trust_center_settings (custom_domain) WHERE custom_domain_verified_at IS NOT NULL;
