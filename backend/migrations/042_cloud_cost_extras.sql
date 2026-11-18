-- Cloud Cost (#295), second pass: commitment inventory with end dates and expiry alerts, AWS purchase
-- recommendations, AI spend per usage type (model / token direction), EKS cluster cost through the AWS cluster tag.

ALTER TABLE cost_commitment_snapshots DROP CONSTRAINT IF EXISTS cost_commitment_snapshots_kind_check;
ALTER TABLE cost_commitment_snapshots ADD CONSTRAINT cost_commitment_snapshots_kind_check
    CHECK (kind IN ('reservations', 'savings_plans', 'inventory', 'recommendations', 'eks_clusters'));

ALTER TABLE cost_alerts DROP CONSTRAINT IF EXISTS cost_alerts_kind_check;
ALTER TABLE cost_alerts ADD CONSTRAINT cost_alerts_kind_check
    CHECK (kind IN ('budget_threshold', 'budget_forecast', 'anomaly', 'aws_anomaly', 'commitment_expiry'));

-- Monthly cost and quantity per usage type, only for services where the usage type carries meaning Niagaros shows
-- (AI services: model and input/output tokens). Same history rule as cost_daily: current value per key.
CREATE TABLE IF NOT EXISTS cost_usage_type_monthly (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    month              DATE        NOT NULL,
    service            TEXT        NOT NULL,
    usage_type         TEXT        NOT NULL,
    amount             NUMERIC(18,6) NOT NULL,
    usage_quantity     NUMERIC(24,6),
    unit               TEXT,
    currency           VARCHAR(8)  NOT NULL,
    estimated          BOOLEAN     NOT NULL,
    ingestion_id       UUID        REFERENCES cost_ingestions(id) ON DELETE SET NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cloud_account_id, month, service, usage_type)
);

GRANT SELECT, INSERT, UPDATE ON cost_usage_type_monthly TO cspm_lambda;
REVOKE DELETE, TRUNCATE ON cost_usage_type_monthly FROM cspm_lambda;
