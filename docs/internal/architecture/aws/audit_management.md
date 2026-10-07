# Audit Management (GitHub issue #260)

## What issue #260 asked for

A full standalone audit-GRC platform: annual audit calendar with
calendar-app integration, every audit type (internal/external/
certification/surveillance/regulatory/supplier/customer/third-party),
automated evidence collection, formal sampling/interview/testing-procedure
tooling, real-time multi-user collaboration, a findings register with
CAPA workflows, remediation tracking with escalation, support for 15 named
frameworks (including "OFDSS", which is not a real, recognized standard),
and executive reporting/dashboards.

## Scope decision

Building the full proposal in one pass would mean either faking
integrations this codebase has no real connection to (a calendar system,
real-time collaboration infrastructure, formal sampling tooling), or
inventing a framework this platform cannot verify anything against
("OFDSS"). Both violate this codebase's standing "no fabricated evidence"
rule.

**What's built instead, for real:**

- **Audit records** — title, type, framework, scope, dates, lead auditor,
  stakeholders. Plain user-entered data, no invention.
- **A findings register auto-seeded from real scan data.** At audit
  creation, if a framework is chosen, every currently-FAILing finding this
  account already has for that framework (same `findings`/`resources`
  tables the main dashboard, Trust Center, and monthly report all already
  read from) is copied into `audit_findings` with its real title,
  description, remediation guidance, and severity. This is a new lens on
  data already verified elsewhere in this product, not a new measurement.
- **Manual findings** for non-technical auditor observations (e.g. a
  physical walkthrough finding) — free-text, honestly labelled `source =
  'manual'` so it's never confused with a scanner-verified finding.
- **Remediation tracking**, mirroring the already-built, already-tested
  TPRM remediation-task pattern (`tprm_handler.py`): owner, due date,
  status, and a *required* verification note before a task can be marked
  verified — marking a task verified automatically closes its finding.
- **Evidence**: a real uploaded file (S3, `niagaros-audit-documents`,
  encrypted, private) or a real link to a document that already exists in
  the Trust Center vault (`trust_documents`) — never a second,
  disconnected copy of the same file.
- **Daily monitoring** (upcoming audits starting within 7 days, overdue
  remediation tasks) with a real email alert via SES, reusing the exact
  pattern already live-tested in `tprm_handler.py`'s `_check_and_notify`.

**Declined, explicitly, rather than silently invented:**

- Calendar-app integration, real-time multi-user collaboration, formal
  sampling/interview/testing-procedure tooling, automated escalation
  chains — no real system in this codebase to integrate with, and no
  fabricated stand-in was built in their place.
- "OFDSS" — not a recognized framework. Left out of the framework
  picklist (`FRAMEWORK_LABELS`) rather than guessed at or invented.
- AI judgement of finding severity/sufficiency — same line drawn in TPRM:
  a materially heavier claim than what the existing AI integration in this
  platform is used for.

## Architecture

- **Lambda**: `audit-management-handler` (python3.12, role
  `CSPMScannerLambdaRole`, same bundled-psycopg2 package layout as
  `tprm-handler`/`trust-center-handler`).
- **DB**: migration `018_audit_management.sql` — `audits`,
  `audit_findings`, `audit_remediation_tasks`, `audit_evidence`,
  `audit_finding_comments` (v2). FKs to `cloud_accounts` and
  `trust_documents` (evidence reuse), same UUID/`gen_random_uuid()`
  convention as every other table in this schema.
- **S3**: `niagaros-audit-documents`, private, SSE-AES256, full Block
  Public Access.
- **API**: `GET/POST/OPTIONS /audit-management` on the shared HTTP API
  (`hzf92ft6j7`).
- **EventBridge**: `audit-management-daily-monitoring`
  (`cron(0 8 * * ? *)`) → `{"check_and_notify": "<niagaros_account_id>"}`.
- **Frontend**: `frontend/public/audit_management.html` — audit list with
  live progress rollups, a detail view with an expandable findings
  register, inline remediation-task management, and evidence upload/
  download. Linked from the sidebar of the dashboard, TPRM, Trust Center,
  and Questionnaire Automation pages.
- `FRAMEWORK_CASE_SQL` / `FRAMEWORK_LABELS` are copied verbatim from
  `trust_center_handler.py` (same reuse pattern already used in
  `monthly_report_handler.py`) so the audit framework picklist matches the
  exact real framework set the rest of the product tracks. A reverse
  mapping, `FRAMEWORK_DB_VALUES`, translates a picklist choice back to the
  real `findings.framework` string(s) used to seed the register.

## Live verification (2026-09-07, against the real Niagaros account)

- Created a real audit for ISO 27001 → 8 real findings auto-seeded
  (`A.5.15`, `A.8.5`, `A.5.18`, `A.8.2`, `A.8.24`, `A.5.17`, `A.8.3`,
  `A.8.11`), each with its real title/description/remediation text.
- Created a remediation task; verifying without notes was correctly
  rejected (`verification_notes is required...`); verifying with notes
  succeeded and the parent finding auto-flipped to `verified` with a real
  `resolved_at` timestamp.
- List rollup after that: 8 total / 1 closed / 7 open / 12% progress —
  arithmetically consistent with the detail view.
- Uploaded a real evidence file to S3 and downloaded it back via a
  presigned URL — byte-identical content confirmed.
- Ran `check_and_notify` against the real account: correctly detected the
  test audit's upcoming start date and sent a real SES email
  (`email.sent: true`).
- Full UI walkthrough via a headless-browser test (Playwright): create →
  list shows real seeded-findings toast → detail view renders real
  ISO 27001 control text → delete → confirmed empty again.
- All test data (the audit, its findings/tasks, and the S3 object) was
  deleted after verification — nothing fabricated was left in the account.

## v2 (2026-09-08): closing the gaps against the literal userstory

After v1 shipped, the 6 Acceptance Criteria in issue #260 were re-checked
one by one against the actual code (not memory of what was intended). One
was genuinely half-built; the rest were already satisfied but hadn't been
re-verified against the literal wording:

1. Scope/framework/timeline/stakeholders at creation — already satisfied.
2. Evidence can be uploaded or linked — already satisfied.
3. **Owner receives a notification at assignment** — was previously only
   covered by the *daily* digest (`_check_and_notify`), which only catches
   already-overdue/upcoming items, not "you were just assigned this."
   Fixed: `_create_remediation_task` now sends a real, immediate SES email
   (`_notify_task_assigned`) with the task, finding, audit, and due date,
   whenever an `owner_email` is given. Honestly reports
   `{"sent": false, "reason": "no_owner_email"}` / `"not_configured"` when
   it can't send, rather than silently claiming success.
4. **Finding auto-closed on verification approval** — the AC says
   "closed"; v1's cascade actually set the finding to `verified`.
   Functionally the progress rollup already counted `verified` as closed,
   but the literal status word was wrong. Fixed: `_update_remediation_task`
   now sets the finding to `closed` (not `verified`) when its task is
   verified. `verified` remains a valid, separate value for manual status
   changes via `update_finding_status`.
5. Evidence reuse across audits via `trust_documents` — already satisfied.
6. Dashboard shows progress/open findings/remediation live on every load —
   already satisfied.

Also closed, from the issue's "Proposed Solution" list (not strict ACs,
but explicit line items):

- **Audit Readiness Score**, surfaced by that exact name in both the audit
  list cards and the detail header (`audit_readiness_score` — same
  computation as the pre-existing `progress_pct`, which is kept for
  backward compatibility).
- **Evidence completeness**: % of an audit's findings with >=1 linked
  evidence item (`evidence_completeness_pct`), shown in the detail header.
- **Notes and comments** on findings: new `audit_finding_comments` table
  (author, body, timestamp) and a plain comment thread per finding. This
  is a running log, not real-time multi-user collaboration — no
  presence/live-sync infrastructure exists in this codebase to back that
  claim honestly, so it wasn't built.
- **Root cause analysis** is now editable on *any* finding at any point
  (`update_finding_root_cause`), not only settable once at manual-finding
  creation time as in v1.

Still explicitly declined, for the same reason as v1: calendar
integration, real-time collaboration, formal sampling/interview/testing-
procedure tooling, automated escalation chains.

### Live verification (2026-09-08, against the real Niagaros test account)

- Deployed the updated Lambda, then hit a real, blocking permissions wall:
  `audit_finding_comments` references `audit_findings`, which is owned by
  `cspm_admin`, not the app's `cspm_lambda` runtime user — `cspm_lambda`
  cannot grant itself `REFERENCES` on a table it doesn't own. Fixed by
  temporarily pointing the Lambda's `DB_SECRET_NAME` at the existing
  `cspm/database/admin-credentials` secret, running the migration once as
  the table owner, then reverting the env var back — confirmed reverted
  and confirmed `cspm_lambda` could read/write the new table afterward.
- Created a real, temporary audit (CIS AWS Foundations, 21 real seeded
  findings) against the "Niagaros (intern testaccount)" account.
- `create_remediation_task` with a real owner email
  (`sofyanberbach73@gmail.com`) returned `{"notification": {"sent":
  true}}`; with no owner email, correctly returned `{"sent": false,
  "reason": "no_owner_email"}` instead of silently pretending to send.
- Set a real root cause on a real finding, added a real comment, then
  created and verified a remediation task on that same finding — the
  finding's status came back `closed` (not `verified`), confirming the
  AC4 fix; `audit_readiness_score` correctly read `5` (1 of 21 findings
  closed) on the next detail fetch.
- Evidence completeness read `0%` correctly (no evidence existed on this
  test account to link) — not exercised further, since linking a fake
  document just to force a non-zero number would itself be fabricated
  data.
- All test data (the audit, its 21 seeded findings, the remediation task,
  and the comment) was deleted afterward and confirmed gone from the
  database — nothing left behind.
