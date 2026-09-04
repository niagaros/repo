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
| Questionnaire responses reused automatically | ✅ links to the existing Answer Library (Questionnaire Automation) rather than duplicating it |
| Document versions archived, audit retained | ✅ every upload is a new `trust_document_versions` row, never overwritten |

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
