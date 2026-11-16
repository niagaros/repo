-- Trust Center (issue #258), second pass: what the first pass left out.
--   * certificates and reports carry their own validity; the status (valid / expiring / expired) is calculated at
--     every read, so an expired certificate is never shown as current
--   * status & availability: a link to the company's own status page and the incident / maintenance notices the
--     company publishes itself (Niagaros does not monitor the customer's uptime and does not invent a history)
--   * branding: accent colour and logo; responsible disclosure: security contact and policy text
--   * analytics: page loads per day (counts only, no visitor data) next to the existing document audit log
--   * an account-level audit trail for settings, branding and notices

ALTER TABLE trust_documents
    ADD COLUMN IF NOT EXISTS valid_from   DATE,
    ADD COLUMN IF NOT EXISTS valid_until  DATE,
    ADD COLUMN IF NOT EXISTS issuer       VARCHAR(255);
DO $$ BEGIN
    ALTER TABLE trust_documents ADD CONSTRAINT trust_documents_validity_order
        CHECK (valid_from IS NULL OR valid_until IS NULL OR valid_from <= valid_until);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE trust_center_settings
    ADD COLUMN IF NOT EXISTS brand_color        VARCHAR(7),
    ADD COLUMN IF NOT EXISTS logo_s3_key        VARCHAR(500),
    ADD COLUMN IF NOT EXISTS status_page_url    VARCHAR(500),
    ADD COLUMN IF NOT EXISTS security_contact   VARCHAR(255),
    ADD COLUMN IF NOT EXISTS disclosure_policy  TEXT;
DO $$ BEGIN
    ALTER TABLE trust_center_settings ADD CONSTRAINT trust_center_brand_color_hex
        CHECK (brand_color IS NULL OR brand_color ~ '^#[0-9a-fA-F]{6}$');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS trust_center_updates (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    kind             VARCHAR(12)  NOT NULL CHECK (kind IN ('incident', 'maintenance', 'notice')),
    title            VARCHAR(200) NOT NULL,
    body             TEXT,
    starts_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at      TIMESTAMPTZ,
    published_by     VARCHAR(255) NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS trust_center_updates_account_idx ON trust_center_updates (cloud_account_id, starts_at DESC);

CREATE TABLE IF NOT EXISTS trust_center_page_views (
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    day              DATE         NOT NULL,
    views            INTEGER      NOT NULL DEFAULT 0,
    PRIMARY KEY (cloud_account_id, day)
);

CREATE TABLE IF NOT EXISTS trust_center_events (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    actor            VARCHAR(255) NOT NULL,
    action           VARCHAR(40)  NOT NULL,
    detail           JSONB        NOT NULL DEFAULT '{}'::jsonb,
    at               TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS trust_center_events_account_idx ON trust_center_events (cloud_account_id, at DESC);

GRANT SELECT, INSERT, UPDATE ON trust_center_updates, trust_center_page_views TO cspm_lambda;
GRANT SELECT, INSERT ON trust_center_events TO cspm_lambda;
REVOKE UPDATE, DELETE, TRUNCATE ON trust_center_events FROM cspm_lambda;
REVOKE DELETE, TRUNCATE ON trust_center_updates, trust_center_page_views FROM cspm_lambda;
