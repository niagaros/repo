-- Migration: Niagaros Calculators, v1 (GitHub issue #263)
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Scope decision: issue #263 proposes ~40 calculators (cyber risk exposure,
-- FAIR-based risk estimation, cost-of-a-data-breach, AI risk scores, cloud
-- cost/TCO, executive KPIs). Almost all of them require either a real
-- actuarial/industry benchmark dataset this platform has no access to
-- (breach-cost averages, FAIR probability distributions), or an AI model
-- asserting a risk judgement well beyond what this platform's existing AI
-- integration is used for (drafting answers strictly from real evidence).
-- Building those would mean presenting invented numbers as if they were
-- measured or verified — this codebase's standing "no fabricated evidence"
-- rule.
--
-- The issue itself gives an explicit priority order, though:
--   1st: Compliance Effort Calculator
--   2nd: Compliance Cost Calculator
--   3rd: [Framework] Cost Calculator
-- All three are built here, for real: the GAP INPUT (how many findings are
-- currently open for a chosen framework, broken down by severity) is real,
-- live data from the same findings/resources tables the dashboard, Trust
-- Center, monthly report, and Audit Management all already read from. The
-- EFFORT/COST side is the user's own, clearly-editable assumption (hours
-- per finding by severity, hourly rate) — never presented as a verified
-- external benchmark. "[Framework] Cost Calculator" is the same tool,
-- framework-scoped, rather than a separate build, since every framework
-- already has its own real gap count.
--
-- Declined, explicitly: Cyber Risk Exposure / FAIR-based Risk Estimator /
-- Cost of a Data Breach Estimator (no real breach-cost dataset), AI Risk
-- Calculator / AI-generated scenario forecasting (would require an AI
-- judgement of risk, not a drafted answer from real evidence), Kubernetes
-- Security Score (this platform has no Kubernetes collector), cloud-cost/
-- TCO calculators (no billing-data integration exists). See
-- docs/internal/architecture/aws/calculators.md for the full scope table.

CREATE TABLE IF NOT EXISTS calculator_scenarios (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    calculator_type   VARCHAR(30)  NOT NULL DEFAULT 'compliance_cost', -- 'compliance_effort' | 'compliance_cost'
    title             VARCHAR(255) NOT NULL,
    framework         VARCHAR(100),
    gap_snapshot      JSONB        NOT NULL, -- real findings-by-severity counts at save time
    assumptions       JSONB        NOT NULL, -- user-entered hours-per-severity / hourly rate
    results           JSONB        NOT NULL, -- computed totals at save time
    created_by        VARCHAR(255),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS calculator_scenarios_account_idx ON calculator_scenarios(cloud_account_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON calculator_scenarios TO cspm_lambda;
