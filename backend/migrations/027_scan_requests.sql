-- Per-account scan requests / throttle (issue #279). Applied via scan-handler {"action":"migrate"}.
CREATE TABLE IF NOT EXISTS scan_requests (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    requested_by     TEXT,
    requested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_requests_account ON scan_requests (cloud_account_id, requested_at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_requests TO cspm_lambda;
