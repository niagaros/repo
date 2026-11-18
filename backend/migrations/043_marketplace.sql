-- Niagaros Marketplace (issue #90). Run as cspm_admin. Re-runnable.
--
-- The catalog itself is a file shipped with the Lambda (marketplace_catalog.csv), not a table: it changes with the
-- code that makes an entry connectable, and keeping it in git means an "Available" entry can never point at a
-- connector that does not exist (marketplace_lib checks that when it loads).
--
-- What customers do in the marketplace is stored here: requests for integrations that are not built yet, ratings,
-- reviews and problem reports, and an audit trail of every marketplace action.

CREATE TABLE IF NOT EXISTS integration_requests (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    slug             TEXT NOT NULL,          -- catalog slug, or 'new:<name>' for something not in the catalog
    name             TEXT NOT NULL,
    note             TEXT,
    requested_by     TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cloud_account_id, slug)
);
CREATE INDEX IF NOT EXISTS integration_requests_slug_idx ON integration_requests (slug);

CREATE TABLE IF NOT EXISTS marketplace_feedback (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    slug             TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN ('review', 'issue')),
    rating           SMALLINT CHECK (rating BETWEEN 1 AND 5),
    message          TEXT,
    author           TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (kind <> 'review' OR rating IS NOT NULL)
);
-- One review per account and integration (a new one replaces the old); problem reports can be repeated.
CREATE UNIQUE INDEX IF NOT EXISTS marketplace_feedback_review_uq ON marketplace_feedback (cloud_account_id, slug) WHERE kind = 'review';
CREATE INDEX IF NOT EXISTS marketplace_feedback_slug_idx ON marketplace_feedback (slug, kind);

-- integration_audit_log (028/integrations_handler) already records Jira/Monday changes; marketplace actions go there
-- too so there is one integration trail per account. Created here as well in case 028's bootstrap has not run.
CREATE TABLE IF NOT EXISTS integration_audit_log (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    integration_id   UUID,
    provider         TEXT,
    actor_email      TEXT,
    action           TEXT NOT NULL,
    details          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS integration_audit_log_account_idx ON integration_audit_log (cloud_account_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON integration_requests, marketplace_feedback TO cspm_lambda;
GRANT SELECT, INSERT ON integration_audit_log TO cspm_lambda;
