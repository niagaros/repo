-- resources/findings as the cloud scanners write them (only the columns the security agents read), for the
-- Security Agents PostgreSQL tests.
CREATE TABLE IF NOT EXISTS resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    resource_type TEXT, resource_id TEXT, resource_name TEXT, region TEXT, config JSONB, last_scanned_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id UUID REFERENCES resources(id) ON DELETE CASCADE,
    check_id VARCHAR(100), title VARCHAR(500), description TEXT, severity VARCHAR(20), status VARCHAR(20),
    detected_at TIMESTAMP DEFAULT NOW(), result VARCHAR(20), framework VARCHAR(100), remediation TEXT, details JSONB,
    first_detected_at TIMESTAMPTZ DEFAULT NOW()
);
