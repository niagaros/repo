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

**Deliberately not built — no real data source exists, and fabricating
one would violate this codebase's core rule:**
- AI-assisted questionnaire *review* (the issue's own wording — CAIQ/SIG
  Lite/SIG Core are supported as questionnaire *types* to track, but
  nothing here reads or scores a vendor's actual answers)
- Breach notifications, dark-web monitoring, external attack-surface
  scanning of vendors
- Financial-stability scoring, geographic-risk scoring, fourth-party
  dependency mapping
- Procurement / contract-management / ticketing / CMDB / identity-provider
  integrations — none of these systems exist in this codebase
- Automated reminders and escalation workflows (a real, honestly buildable
  next step — reuse the SES pattern already proven in Trust Center's
  approval emails and the monthly report — but not built in this pass)
- Executive reporting / vendor risk heatmap dashboard beyond the vendor
  grid and summary counts already in `tprm.html`

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
