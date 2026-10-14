-- When each onboarding step was first completed, per organization.
--
-- The wizard works out what is done by asking the backend on every page
-- load, and stores nothing. That is enough to draw a progress bar, but it
-- means the platform knows that a step is missing without knowing since
-- when — and two of this project's research questions need exactly that.
--
-- DV4, the intelligence layer, cannot run any rule that begins with "after
-- seven days": there is no anchor to count from. DV5, the analytics
-- dashboard, cannot measure drop-off per step, because drop-off is about
-- how long someone has been stuck and that is a duration. Both are blocked
-- on this one table rather than on anything in their own design.
--
-- Deliberately only the first completion. A step that is undone and redone
-- — a cloud account disconnected and reconnected — keeps its original
-- moment, because the question these two layers ask is "how long did it
-- take this customer to get here", not "when was it last true".
CREATE TABLE IF NOT EXISTS onboarding_step_completions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    step            VARCHAR(32) NOT NULL
        CHECK (step IN ('infrastructure', 'team', 'auditor',
                        'workspace', 'compliance', 'governance', 'training')),
    completed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One row per step per organization: the write is an upsert that does
    -- nothing when the step is already recorded, so the wizard can report
    -- the same state on every page load without this table growing.
    UNIQUE (organization_id, step)
);

CREATE INDEX IF NOT EXISTS idx_step_completions_organization
    ON onboarding_step_completions(organization_id);

GRANT SELECT, INSERT ON onboarding_step_completions TO cspm_lambda;
