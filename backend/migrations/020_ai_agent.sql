-- Niagaros AI Agent (GitHub issue #262), v1.
--
-- Scope decision: issue #262 describes a full multi-cloud, multi-tool
-- autonomous security agent — live integrations with Azure, GCP,
-- Kubernetes, GitHub, GitLab, Jira, ServiceNow, Entra ID, Okta,
-- CrowdStrike, Defender, Wiz, Prisma Cloud, plus "Agentic Actions" that
-- autonomously rotate secrets, disable identities, and apply security
-- policies. None of those integrations exist in this codebase, and this
-- platform's own scanner role is SecurityAudit + ReadOnlyAccess — it has
-- no write access to a customer's AWS account at all. Building any of
-- that would mean either faking an integration this codebase has no real
-- connection to, or giving an LLM autonomous infrastructure-write power
-- this product's own IAM model doesn't grant anyone — both violate the
-- standing "no fabricated capability" rule.
--
-- What's built here instead, for real:
--   - Natural-language Q&A, but only over this account's own real data
--     (findings, resources, cloud_accounts, TPRM vendors, Audit
--     Management) already verified elsewhere in this product. The LLM
--     classifies the question into one of a fixed set of real, pre-built
--     queries and phrases the real result — it never invents the numbers
--     itself. This directly covers the "AI-Powered Search" examples in
--     the issue almost verbatim (highest risks, account compliance,
--     internet-facing criticals, failing SOC 2 controls, expiring vendor
--     certificates).
--   - One real, human-confirmed action ("Workflow Automation" /
--     "Agentic Actions", scoped honestly): create a remediation task in
--     Audit Management from a finding the agent surfaced. The agent
--     proposes the exact task; nothing is created until a human clicks
--     confirm — there is no autonomous execution.
--   - A full audit trail of every question asked, what real data backed
--     the answer, and whether an action was taken — this satisfies the
--     literal "records a complete audit trail" acceptance criterion.
--
-- Declined, explicitly, rather than silently invented:
--   - Azure/GCP/Kubernetes/GitHub/GitLab/Jira/ServiceNow/Entra
--     ID/Okta/CrowdStrike/Defender/Wiz/Prisma Cloud integrations — no
--     real connection to any of these exists in this AWS-only product.
--   - Autonomous "Agentic Actions" (rotate secrets, disable identities,
--     apply policies) — no write-access role exists, and granting one
--     silently would be a materially heavier security decision than
--     anything else in this codebase.

CREATE TABLE IF NOT EXISTS ai_agent_queries (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    question          TEXT         NOT NULL,
    intent            VARCHAR(50)  NOT NULL,
    evidence          JSONB        NOT NULL,
    answer            TEXT         NOT NULL,
    action_taken      VARCHAR(50),
    action_details    JSONB,
    asked_by          VARCHAR(255),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ai_agent_queries_account_idx ON ai_agent_queries(cloud_account_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON ai_agent_queries TO cspm_lambda;
