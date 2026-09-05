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

## v1.3 — literal userstory completion pass ("look carefully at what's actually in it")

Re-read the literal issue #261 text line by line against everything built
so far and found real, concrete, missed items — not new invented scope:

- **Compliance & Certifications named 7 more frameworks explicitly**
  (NIS2, DORA, ISO 42001, HITRUST CSF, CIS Benchmarks, NIST CSF, EU AI Act)
  that weren't in `CERTIFICATION_TYPES`, plus **Evidence Management's**
  distinct categories (audit reports, pentests, policies, insurance
  certificates, BCPs, security documentation) — all added as real,
  uploadable evidence types.
- **Contract tracking** (`contract_start_date`/`contract_end_date`/real
  uploaded contract document) — issue #261 names "Contract renewals"
  under Continuous Monitoring and "contracts" explicitly in acceptance
  criterion 5's evidence list; neither existed before.
- **"Data sensitivity"** (Risk Scoring) — `handles_sensitive_data`, real
  self-declared boolean, +10 risk points when true.
- **"Internet exposure" / "External attack surface"** (Risk Scoring /
  Continuous Monitoring) — `_check_website_tls()`, a real, narrow,
  honestly-named technical signal: does the vendor's own declared website
  present a valid, currently-trusted TLS certificate? A genuine live
  network check (stdlib `ssl`/`socket`, no paid attack-surface-scanning
  service configured in this account), explicitly not a stand-in for real
  port scanning or subdomain enumeration. Verified live against
  `https://www.google.com` → `website_tls_valid: true`.
- **"Service inventory" / "asset relationships"** (Vendor Inventory) —
  `services_provided` / `internal_systems_accessed`, real self-declared
  text fields.
- **Findings & Remediation** (risk acceptance, exception management,
  corrective action tracking, escalation workflows) — new
  `tprm_remediation_tasks` table: real tasks with a due date, assignee,
  and a required written reason when a risk is explicitly accepted
  instead of resolved (never silently dropped). Overdue open tasks are
  surfaced as an escalation in the daily monitoring email.
- **Acceptance criterion 1** ("onboarding workflow begins... a risk
  assessment... automatically assigned") — `_create_vendor` now also
  auto-creates a real CAIQ assessment (the same real 8-question set) the
  moment a vendor is registered. Verified live: a newly created vendor
  immediately had an 8-item CAIQ assessment attached.
- **Acceptance criterion 3** ("notifications are sent to the vendor
  owner") — added `business_owner_email`; `_check_and_notify` now
  includes each critical vendor's real owner email as an actual
  recipient, not just the internal distribution list.
- **Acceptance criterion 4** ("risk score increases... alerts and
  remediation workflows are triggered") — `_check_and_notify` now
  auto-opens a real remediation task the moment a vendor first crosses
  into `critical` (never duplicated while one is already open). Verified
  live: a test vendor pushed to critical had a task titled "Vendor
  reached critical risk — review required" appear automatically.
- **CSV/evidence-package exports now include the new fields** (contract
  status, registration number) for a complete real hand-off to an
  auditor or a procurement/contract-management system.

Full live verification chain for this pass: created a real vendor with
country/sensitive-data/website/owner-email set → confirmed risk score
correctly included the sensitivity and non-adequate-country factors →
confirmed the auto-created CAIQ assessment existed → ran a real website
TLS check against google.com → uploaded real contract dates → ran
`check_and_notify` and confirmed a real remediation task was auto-created
and a real email was sent → cleaned up the test vendor.

## v1.2 — "just build it and see how far you can get legitimately"

Pushed once more on the remaining gaps. Found real, honest paths for four
more:

- **Honest incident log** (`tprm_incidents`) — not automated breach/
  dark-web monitoring (no such API is set up or paid for in this AWS
  account), but a real, manually-curated record of a specific, publicly-
  reported incident someone actually read about, with a source URL so it's
  checkable. This is what "breach notifications" becomes when there's no
  automated feed: a real log, not a fabricated one.
- **Real company-registry reference** (`tprm_vendors.registration_number`)
  — a free-text field for a vendor's real KVK/Companies House/equivalent
  number, so a human can look it up in a real public registry. Not a
  computed financial score (still not built — no real source), just an
  honest pointer to where a human could verify one.
- **Deterministic "no"-answer flagging on CAIQ assessments** — issue
  #261's "automated response validation" done without any AI or guessing:
  counting real "no" answers to real CCM/CAIQ controls and surfacing the
  count as a concern flag. A real, defensible rule, not an invented
  judgment about whether an answer is "good enough."
- **Evidence package export** (`?evidence_package=<vendor_id>`) — issue
  #261 AC #5 verbatim ("auditor requests evidence... all associated
  assessments, certifications... available"): one real, aggregated JSON
  per vendor with presigned download links for every uploaded document,
  generated on demand. Verified live: returned the vendor's real profile,
  risk score, certifications, assessments, and the incident just logged,
  all in one response.
- **CSV export** (`?export_csv=1`) — real data portability standing in
  for "integrations" with procurement/contract-management systems this
  codebase doesn't have: a real file the account can actually import into
  one, rather than a fabricated live connection to a system that isn't
  there.
- **Risk-level filtering on the vendor grid** (`tprm.html`) — click a
  summary card (Critical / High / Low+Medium) to filter to just that
  risk band; the closest honest version of a "risk heatmap" without
  inventing a second dimension of data that doesn't exist.

**What's still genuinely not built, and why no further legitimate path
was found:**
- **Automated breach/dark-web monitoring** — real services for this
  (e.g. paid breach-database APIs) exist, but none is configured or paid
  for in this AWS account; calling one would require the user to set up
  and pay for that subscription first. The honest incident log above is
  the real substitute available today.
- **Financial-stability *scoring*** — real public company-registry APIs
  exist (e.g. UK Companies House has a free API), but none is registered/
  keyed in this environment either; `registration_number` is the honest
  placeholder for a human to check manually until one is wired up.
- **AI-scoring of whether a vendor's answer is actually adequate** — real
  and buildable (this codebase already has a working Groq LLM integration
  for Questionnaire Automation), but scoring answer *quality* rather than
  just counting "no" answers would mean the AI is forming a judgment
  about a vendor's real security posture — a materially different, higher-
  stakes claim than Questionnaire Automation's drafting-from-evidence use
  case, and out of scope for this pass without deliberately deciding to
  take that on.
- **Procurement / ticketing / CMDB / identity-provider integrations** —
  none of these systems exist in this codebase to integrate with; CSV
  export is the honest substitute.

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
