# Third-Party Risk Management (GitHub issue #261)

## What it does

A vendor registry that tracks the security posture of an account's own
third parties (SaaS vendors, processors, suppliers) — vendor details,
uploaded compliance certifications with real expiry-driven status, and
security assessment tracking (sent → received → approved) — with a risk
score computed from real, verifiable inputs only.

- **Lambda**: `tprm-handler` (python3.12, role `CSPMScannerLambdaRole`)
- **API**: HTTP API `hzf92ft6j7`, route `/tprm` (GET/POST/OPTIONS)
- **S3**: `niagaros-tprm-documents` (private, encrypted, public access
  blocked) — real uploaded certification and assessment evidence files
- **DB**: `tprm_vendors`, `tprm_certifications`, `tprm_assessments`,
  `tprm_audit_log` (migration `014_tprm.sql`)
- **Frontend**: `frontend/public/tprm.html`

## Scope decision — a fraction of issue #261, built honestly

The issue's Proposed Solution describes a full standalone TPRM product:
procurement/ticketing/CMDB/identity-provider integrations, AI-assisted
questionnaire review, breach and dark-web monitoring, financial-stability
scoring, geographic/fourth-party risk, executive reporting, automated
reminders and escalation workflows. Building all of that in one pass would
mean either faking integrations this codebase has no real connection to,
or inventing risk signals (breach data, financial health, dark-web
exposure) with no real data source — both violate this codebase's
standing rule against fabricated evidence (see the FSBP/koppelingsaudit
work this same session — the whole point of that audit was catching
exactly this kind of "looks right, isn't" mismatch).

**Built, for real:**
- Vendor registry: name, category, criticality, business owner, contact,
  status. Real CRUD, real audit log on every change.
- Certification tracking with a real uploaded document (S3, presigned
  download) and a status computed from the certificate's own expiry date
  (`valid` / `expiring_soon` within 30 days / `expired`) — never guessed.
- Assessment tracking (sent → in_progress → received → approved) with a
  real uploaded completed-questionnaire document.
- Risk scoring (`_compute_risk()` in `tprm_handler.py`) from exactly three
  real, verifiable factors:
  - Vendor-declared criticality (10/20/30/40 risk points for low/medium/
    high/critical)
  - +20 points if no currently-valid certification exists; +15 if the
    soonest-expiring valid certification expires within 30 days
  - +15 points if no assessment has reached `approved` status
  - Score capped at 100; bucketed low (0-25) / medium (26-50) / high
    (51-75) / critical (76-100)

  Verified live end-to-end against a real test vendor (deleted after):
  criticality-only baseline (critical, no cert, no assessment) → 75
  ("high"); after adding a valid certification → 55; after also approving
  an assessment → 40 ("medium"); re-tested with a certification expiring
  within 30 days → 55 again (expiring-soon penalty), confirming the
  formula reacts correctly to each factor independently.

**Why not reuse Questionnaire Automation (issue #259) for assessments:**
That feature answers questionnaires sent TO this account by ITS
customers, drafting answers from this account's own findings/evidence —
the opposite direction from TPRM, which tracks questionnaires this
account sends OUT to its vendors, whose answers are the vendor's own,
not this account's evidence. Reusing that table would have misrepresented
whose evidence a vendor's answers actually are, so TPRM has its own
`tprm_assessments` table that only tracks send/receive/approve status and
a real uploaded document, with no drafting logic pretending to answer for
the vendor.

## v1.1 — pushed further after direct feedback ("build everything, find legit ways")

The user explicitly asked to build as much of the real userstory as
honestly possible rather than stopping at the v1 slice above. Re-examined
every "deliberately not built" item from v1 and built the ones with a real,
non-fabricated way to do them:

- **Vendor onboarding workflow** (issue: "risk-based onboarding
  workflows... security/privacy/compliance reviews... legal/business
  approvals") — `tprm_vendors.onboarding_stage`, a real 8-stage state
  machine (`registered → risk_assessment → security_review →
  privacy_review → compliance_review → legal_approval → business_approval
  → active`), advanced explicitly via `advance_onboarding` and logged to
  the audit trail. No auto-decisioning — a human still approves each
  stage; this is a real workflow, not a fabricated automated approval.
- **Risk assessments per domain** — `tprm_assessments.domain`
  (cybersecurity / privacy / compliance / operational_resilience /
  business_continuity / data_residency), so a vendor can have multiple,
  independently tracked assessments instead of one generic record.
- **Real CAIQ questionnaire content** — CAIQ (Consensus Assessments
  Initiative Questionnaire) is the Cloud Security Alliance's own
  self-assessment version of its Cloud Controls Matrix (CCM): the same
  control domains, phrased as questions. `CAIQ_DOMAINS` reuses the exact
  8 CCM v4 domain titles/descriptions already verified in
  `csa_ccm_mapper_handler.py` earlier this session (the
  AWS-technically-verifiable subset of the full 17-domain matrix), turned
  into real yes/no self-assessment questions — not invented text.
  Creating a `caiq`-type assessment auto-populates
  `tprm_assessment_items` with these 8 real questions; each is answerable
  (yes/no/na/unknown) and tracked with a real answered-count.
- **Geographic / data-residency risk** — `tprm_vendors.country` plus
  `_is_adequate_country()`, checked against the European Commission's
  real, published list of GDPR adequacy decisions (EU/EEA members plus
  the specific third countries the Commission has recognized). Unknown
  countries and the US (which depends on individual company-level Data
  Privacy Framework certification, not a blanket decision) are correctly
  left unflagged rather than guessed. Adds 10 real risk points when a
  vendor is in a non-adequate jurisdiction — verified live: a vendor in
  India scored correctly flagged `is_adequate_country: false` and the
  10-point addition showed up in the total.
- **Sub-processor and financial-notes fields** — honest, vendor-
  self-declared free text (`subprocessors`, `financial_notes`), explicitly
  never scored or verified by this platform, because no real automated
  source exists for either. Storing what the vendor told you is legitimate;
  computing a financial-health number ourselves would not be.
- **Real continuous monitoring with real email alerts** —
  `_check_and_notify()` (new EventBridge rule `tprm-daily-monitoring`,
  daily) checks every vendor for certifications expiring within 30 days
  or already expired, and vendors whose risk score has crossed into
  `critical`, and sends one real summary email via SES (same pattern and
  same sandbox caveat as Trust Center and the monthly report). This
  directly satisfies 2 of the issue's 6 acceptance criteria (certificate-
  expiry notification; risk-score-threshold alerting). Verified live: a
  test vendor with an expiring cert and critical risk triggered
  `email: {"sent": true}`; a vendor with nothing wrong correctly returned
  `"reason": "nothing_to_report"` instead of sending an empty alert.

**Still deliberately not built — no real data source exists, and
fabricating one would violate this codebase's core rule:**
- AI-assisted questionnaire *review*/scoring of a vendor's actual answers
  (answering is now real and structured; automatically judging whether an
  answer is "good enough" would require either a real LLM call against
  real evidence — out of scope for this pass — or guessing)
- Breach notifications, dark-web monitoring, external attack-surface
  scanning of vendors
- Financial-stability *scoring* (the raw field for vendor-provided
  information is real; computing our own number is not, with no data
  source)
- Fourth-party dependency *verification* (sub-processors are recorded as
  self-declared; nothing here independently verifies them)
- Procurement / contract-management / ticketing / CMDB / identity-provider
  integrations — none of these systems exist in this codebase
- Executive reporting / vendor risk heatmap dashboard beyond the vendor
  grid, summary counts, and onboarding stepper already in `tprm.html`

## Manual test / re-run

```
# Migrate (temporarily point DB_SECRET_NAME at cspm/database/admin-credentials first)
aws lambda invoke --function-name tprm-handler --payload '{"migrate":true}' \
  --cli-binary-format raw-in-base64-out out.json

# List vendors
aws lambda invoke --function-name tprm-handler \
  --payload '{"httpMethod":"GET","queryStringParameters":{"cloud_account_id":"<id>"}}' \
  --cli-binary-format raw-in-base64-out out.json
```
