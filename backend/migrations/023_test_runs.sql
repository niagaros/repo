-- Automated test runs and per-test results (issue #279). Applied via test-results-handler {"action":"migrate"}.
CREATE TABLE IF NOT EXISTS test_runs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_at      TIMESTAMPTZ NOT NULL,
    commit_sha  TEXT,
    branch      TEXT,
    trigger     TEXT,
    totals      JSONB NOT NULL,
    summary     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_at, commit_sha, trigger)
);
CREATE TABLE IF NOT EXISTS test_results (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id      UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
    test_id     TEXT NOT NULL,
    flow        TEXT,
    severity    TEXT,
    layer       TEXT,
    status      TEXT NOT NULL,
    duration_s  NUMERIC,
    failed_step TEXT,
    message     TEXT,
    flaky       BOOLEAN NOT NULL DEFAULT false
);
-- The first version used a BIGSERIAL id; the app's database user cannot use sequences created by the admin user,
-- so convert it (idempotent, and the table is empty when this runs).
DO $$ BEGIN
  IF (SELECT data_type FROM information_schema.columns WHERE table_name = 'test_results' AND column_name = 'id') <> 'uuid' THEN
    ALTER TABLE test_results ALTER COLUMN id DROP DEFAULT;
    ALTER TABLE test_results ALTER COLUMN id TYPE uuid USING gen_random_uuid();
    ALTER TABLE test_results ALTER COLUMN id SET DEFAULT gen_random_uuid();
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_test_results_flow ON test_results(flow, status);
CREATE INDEX IF NOT EXISTS idx_test_results_run  ON test_results(run_id);
CREATE INDEX IF NOT EXISTS idx_test_runs_run_at  ON test_runs(run_at DESC);
