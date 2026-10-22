-- CIEM (issue #17): access reviews that repeat on a schedule. The CIEM scanner starts the next review when the
-- interval has passed; each review keeps a link to the one it continues.
ALTER TABLE ciem_access_reviews ADD COLUMN IF NOT EXISTS repeat_every_days INTEGER
    CHECK (repeat_every_days IS NULL OR repeat_every_days IN (30, 90, 180, 365));
ALTER TABLE ciem_access_reviews ADD COLUMN IF NOT EXISTS previous_review_id UUID REFERENCES ciem_access_reviews(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_ciem_review_previous ON ciem_access_reviews (previous_review_id) WHERE previous_review_id IS NOT NULL;
