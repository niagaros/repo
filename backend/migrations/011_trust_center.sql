-- Migration: Trust Center (GitHub issue #258)
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- A per-account public/authenticated portal showing real, continuously
-- updated compliance status plus a real document vault the account can
-- upload its own real trust documents into (security policies, DPAs,
-- whitepapers it actually has). Deliberately does NOT fabricate SOC
-- reports, uptime history, or incident history — this codebase has no
-- real data source for any of those, and inventing one would violate the
-- "no fabricated evidence" rule the rest of the platform is built around.
-- See docs/internal/architecture/aws/trust_center.md for full scope notes.

CREATE TABLE IF NOT EXISTS trust_center_settings (
    cloud_account_id UUID         PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    is_public        BOOLEAN      NOT NULL DEFAULT FALSE,
    public_slug      VARCHAR(64)  NOT NULL UNIQUE,
    company_name     VARCHAR(255),
    intro_text       TEXT,
    contact_email    VARCHAR(255),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_documents (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    title            VARCHAR(255) NOT NULL,
    category         VARCHAR(50)  NOT NULL DEFAULT 'other',
    visibility       VARCHAR(20)  NOT NULL DEFAULT 'restricted',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_document_versions (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id    UUID         NOT NULL REFERENCES trust_documents(id) ON DELETE CASCADE,
    version_number INT          NOT NULL,
    s3_key         VARCHAR(500) NOT NULL,
    filename       VARCHAR(255) NOT NULL,
    changelog      TEXT,
    uploaded_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_document_access_requests (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id      UUID         NOT NULL REFERENCES trust_documents(id) ON DELETE CASCADE,
    requester_name   VARCHAR(255) NOT NULL,
    requester_email  VARCHAR(255) NOT NULL,
    reason           TEXT,
    status           VARCHAR(20)  NOT NULL DEFAULT 'pending',
    access_token     VARCHAR(64),
    token_expires_at TIMESTAMPTZ,
    requested_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    decided_at       TIMESTAMPTZ,
    decided_by       VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS trust_document_audit_log (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID         NOT NULL REFERENCES trust_documents(id) ON DELETE CASCADE,
    actor       VARCHAR(255),
    action      VARCHAR(30)  NOT NULL,
    at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS trust_documents_account_idx ON trust_documents(cloud_account_id);
CREATE INDEX IF NOT EXISTS trust_document_versions_doc_idx ON trust_document_versions(document_id);
CREATE INDEX IF NOT EXISTS trust_document_access_requests_doc_idx ON trust_document_access_requests(document_id);
CREATE INDEX IF NOT EXISTS trust_document_access_requests_token_idx ON trust_document_access_requests(access_token);
CREATE INDEX IF NOT EXISTS trust_document_audit_log_doc_idx ON trust_document_audit_log(document_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON trust_center_settings TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_documents TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_document_versions TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_document_access_requests TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON trust_document_audit_log TO cspm_lambda;
