# Trust Center (GitHub issue #258)

## What it does

A per-account public/authenticated portal that shows real, continuously
updated compliance status plus a real document vault the account uploads
its own real documents into. Directly addresses the issue's problem
statement: "demonstrating continuous compliance instead of point-in-time
certifications" — every score shown is live scan data with a genuine
"last verified" timestamp, not a cached badge.

- **Lambda**: `trust-center-handler` (python3.12, role `CSPMScannerLambdaRole`)
- **API**: HTTP API `hzf92ft6j7`, route `/trust-center` (GET/POST/OPTIONS)
- **S3**: `niagaros-trust-center-documents` (private, `BucketOwnerEnforced`,
  AES256 default encryption) — real uploaded files, one S3 key per version
- **DB**: `trust_center_settings`, `trust_documents`, `trust_document_versions`,
  `trust_document_access_requests`, `trust_document_audit_log` (migration `011_trust_center.sql`)
- **Frontend**: `frontend/public/trust_center.html` (admin config, behind the
  dashboard sidebar) and `frontend/public/trust_center_public.html`
  (the actual public page, no login/sidebar, reached via `?slug=...`)

## Compliance status: reused verbatim, not reimplemented

`_get_compliance_status()` copies the exact CASE-mapping and
credit-based `SUM(passed_credit)/SUM(passed_credit+failed_credit)` query
`get-dashboard-data`'s per-service stats section already uses — same
`FRAMEWORK_CASE_SQL` constant, same finding→framework label mapping. This
is deliberate: an independently-written second query computing "the same"
per-framework score is exactly how this session's earlier dashboard
double-counting and "1 check, 0%" bugs happened. Copying the proven query
means a Trust Center score can never silently disagree with the
dashboard's own number for the same account.

Each framework also carries `last_verified` (`MAX(f.detected_at)` across
its findings) — the honest analogue of "this certificate hasn't expired."

**Real bug found and fixed during build**: `ORDER BY passed * 100.0 / NULLIF(total, 0)`
referencing the SELECT list's own aliases (`passed`, `total`) failed with
`column "passed" does not exist` — fixed by repeating the full
`SUM(...)` expressions in the ORDER BY clause instead of the aliases.

## Documents: real files, real access control, real audit trail

Verified end-to-end via live Lambda invokes: uploaded a real public
document and a real restricted document, turned the Trust Center public,
confirmed the public view returns a working presigned download URL for
the public document and only the title (no link) for the restricted one,
submitted a real access request, approved it as admin (generating a
`secrets.token_urlsafe(24)` token, 30-day expiry), downloaded successfully
with that token, confirmed an invalid token is rejected with 403, and
confirmed every step (upload, view, request, approval, download) appears
in `trust_document_audit_log` with a real actor and timestamp.

Approval doesn't email the link (no reliable production email sending is
wired into this codebase — SES is still in sandbox mode per the monthly
report doc). The admin UI surfaces the generated link via a copyable
prompt for the admin to send manually, the same honest pattern
Questionnaire Automation's share links already use.

## Scope decision — what's built vs. explicitly not built

The issue's Proposed Solution lists far more than one pass can honestly
deliver. Built for real, matching real acceptance criteria:

| AC | Status |
|---|---|
| Public info accessible without auth | ✅ `?slug=` route, no auth |
| Restricted docs need authorization | ✅ approval + token-gated download |
| Compliance status reflects changes automatically | ✅ inherent — it's a live query, not a cached cert |
| Admin-approved access request with audit logging | ✅ `trust_document_access_requests` + `trust_document_audit_log` |
| Questionnaire responses reused automatically | ✅ `_get_public_qa_highlights()` surfaces the account's approved Questionnaire Automation answers directly on the public page — genuinely queries the same data, not a link out to a separate page (an earlier version of this doc claimed this was "linked" when it hadn't actually been wired in yet; fixed) |
| Document versions archived, audit retained | ✅ every upload is a new `trust_document_versions` row, never overwritten |

## Security Posture and document categories (added after gap review)

Two gaps found by comparing the built version against the issue line by
line and against how Vanta/Drata Trust Centers actually work:

- **Document categories were incomplete.** The issue's Trust Documents
  list names SOC reports, ISO certificates, subprocessor lists, and BC/DR
  documentation explicitly; the first pass only had policy/privacy/dpa/
  whitepaper/pentest/other. `DOCUMENT_CATEGORIES` now matches the issue's
  list.
- **No "Security Posture" section existed at all.** `_get_security_posture()`
  pulls real content for encryption, IAM, infrastructure security, and
  vulnerability management from `evidence_documents` — the same table
  Questionnaire Automation seeds from `docs/public/security/**/*.md`. A
  topic with no matching real document shows "not yet published" rather
  than guessing at content; "Secure SDLC overview" and "Responsible
  disclosure policy" from the issue have no corresponding published doc
  yet, so they are not included as topics rather than faked.

## NDA click-through and real approval email (closed for real, not documented around)

The user pushed back on both items below being left as "deliberate
differences" — correctly: neither is actually blocked by anything, so
both are now built for real (migration `012_trust_center_nda_and_email.sql`).

- **NDA click-through**: `trust_document_access_requests` now has
  `nda_accepted_name` + `nda_accepted_at`. The public request modal
  requires a checked confidentiality box and a typed full legal name
  before `request_access` is accepted at all — the backend rejects the
  request with 400 if either is missing (verified live). Every acceptance
  is also written to `trust_document_audit_log` as `nda_accepted`, with
  the requester's email as actor and a real timestamp.
- **Real approval email**: `_send_approval_email()` calls `ses:SendEmail`
  (IAM permission `TrustCenterApprovalEmail` added to
  `CSPMScannerLambdaRole`) with the actual download link on approval.
  This is not simulated — verified live against two real cases:
  - Approving a request from the one SES-verified address
    (`bottomclipzz@gmail.com`) → `email_status: "sent"`, real email
    delivered, audit log shows `approved_email_sent`.
  - Approving a request from an arbitrary external address
    (`someexternalauditor@example.com`) → SES genuinely rejects it
    (`"Email address is not verified..."` — the account is still in
    SES sandbox mode), and the handler records `email_status: "failed"`
    with AWS's own error text rather than pretending to have sent it.
    The admin UI (`trust_center.html`) shows this honestly and falls
    back to the manual copy-link prompt only in that case.

**Why not every external recipient can be emailed automatically yet —
a real, currently-open blocker, not a design choice:**
SES production access was actually requested via `aws sesv2
put-account-details` (case `178854954000928`) and was **denied
instantly**, almost certainly because the only verified sending identity
is a personal Gmail address rather than a company domain. Domain
verification for `niagaros.com` was started (`create-email-identity`,
DKIM tokens generated) — DNS for that domain is hosted at SiteGround
(`ns1/ns2.siteground.net`, confirmed via NS lookup), and adding the 3 DKIM
CNAME records there is a prerequisite for resubmitting production access
credibly. This is tracked as open follow-up work, not silently accepted:
until it lands, automatic email only reaches SES-verified test addresses,
and the manual copy-link fallback (already built, now clearly labeled
in the UI) remains the real path for everyone else.

**Still true, and still a deliberate simplification rather than a gap:**
"Authenticates" (AC #2) is approval + a time-limited token, not a real
login/SSO flow — there is no identity provider wired into this codebase.
Combined with the NDA acknowledgement and audit trail above, this is a
reasonable approximation of the acceptance criterion's intent (controlled,
auditable, non-anonymous access), not a corner cut for convenience.

**Deliberately not built — no real data source exists for these, and
fabricating one would violate this codebase's core rule:**
- SOC reports, penetration-test summaries, security whitepapers as
  *generated* content — these are real files the account uploads itself;
  nothing here writes one on their behalf.
- Uptime history, incident history, status page integration — this
  codebase has no uptime-monitoring or incident-management system to pull
  real data from.
- Compliance "certifications" as a distinct concept — deliberately
  replaced with live scan scores, which is a stronger, more honest signal
  than a point-in-time cert this platform doesn't actually issue.

**Not built, out of scope for this pass (no missing-data problem, just
scope):**
- Branding/white-label/custom domain.
- Analytics (visitor analytics, engagement metrics, document-download
  counts beyond the audit log itself).
- Identity-provider/ticketing/CRM/status-page integrations.
- NDA click-through gating before a restricted download (currently:
  admin manually reviews the stated reason before approving).

## Manual test / re-run

```
# Migrate
aws lambda invoke --function-name trust-center-handler --payload '{"migrate":true}' \
  --cli-binary-format raw-in-base64-out out.json

# Public view
aws lambda invoke --function-name trust-center-handler \
  --payload '{"httpMethod":"GET","queryStringParameters":{"slug":"<slug>"}}' \
  --cli-binary-format raw-in-base64-out out.json
```
