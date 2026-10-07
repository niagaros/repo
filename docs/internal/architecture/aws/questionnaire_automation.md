# Questionnaire Automation for Security Reviews (GitHub issue #259)

## What it does

Lets a user upload a customer security questionnaire as CSV, matches every
question against this cloud account's own real, already-scanned compliance
findings and Niagaros' published security documentation, and drafts a
candidate answer from whatever real evidence was actually found. Nothing is
answered from thin air: if no evidence matches a question, no draft is
produced and the item is left for a human to fill in.

- **Lambda**: `questionnaire-handler` (python3.12, role `CSPMScannerLambdaRole`,
  handler `collectors.aws.scanner.questionnaire_handler.handler`)
- **API**: HTTP API `hzf92ft6j7` (`get-dashboard-data-API`), route
  `/questionnaires` (GET/POST/DELETE/OPTIONS), same API the dashboard and
  Custom Frameworks already use.
- **Frontend**: `frontend/public/questionnaire_automation.html`, same sidebar
  shell as every other framework page, reachable via the new "Questionnaires"
  sidebar item added to the dashboard and all framework pages.
- **DB**: `questionnaires`, `questionnaire_items`, `evidence_documents`
  (migration `007_questionnaire_automation.sql`); `questionnaire_item_comments`,
  `questionnaire_item_history` (migration `008_questionnaire_collaboration.sql`).

## How evidence retrieval works

No vector index, no embeddings — deliberately simple keyword overlap so the
matching is fully inspectable:

1. Tokenize the question (lowercase words ≥3 chars, small stopword list).
2. Score every distinct `check_id` this account has findings for, by token
   overlap between the question and that check's `title`+`description`
   (worst-case PASS/FAIL across all resources, same logic every other mapper
   uses). Keep the top 5 with overlap ≥2 tokens.
3. Score every row in `evidence_documents` the same way. This table is
   seeded from `docs/public/security/**/*.md`, chunked by markdown heading
   (192 chunks from 57 files as of the initial seed) via a one-off
   `{"seed_evidence_docs": [...]}` invoke — there's no live sync back to the
   docs folder, so re-run the seed after meaningfully editing those docs.
4. Confidence is computed from *how much real evidence was found*
   (control + doc match → `high`, either alone → `medium`, neither → `low`,
   and `low` never gets an AI draft) — never self-reported by the model.

## The AI-drafting backend: three providers, two dead ends, documented so the
## next person doesn't repeat the same debugging

This is worth writing down in detail because all three attempts happened in
one session and each failure looked different enough to be worth knowing in
advance.

**1. Amazon Bedrock (first choice — same account as everything else, no new
vendor).** Failed for two independent reasons, found via live `invoke-model`
calls, not assumed from docs:
- Every current-generation Claude model on Bedrock requires a cross-region
  *inference profile* (e.g. `eu.anthropic.claude-sonnet-4-20250514-v1:0`),
  not a plain model ID — using a plain model ID fails with "on-demand
  throughput isn't supported." Older/legacy IDs (`claude-3-haiku-20240307`)
  are separately blocked with "marked by provider as Legacy... not actively
  used in the last 30 days."
- After the account owner enabled a current model (Claude Sonnet 4.6) via
  the Bedrock model catalog, invoking it *still* failed with
  `AccessDeniedException: INVALID_PAYMENT_INSTRUMENT` — Bedrock's Anthropic
  models are billed through an AWS Marketplace subscription, which is a
  separate payment check from whatever lets the rest of the AWS account
  (Lambda, RDS, S3, etc.) run. Fixing this needs a valid payment method
  attached to the AWS **root** account specifically (billing pages are
  root-only by default, even for IAM users with AdministratorAccess) — not
  something fixable from Lambda/CLI, and not something to push on someone
  who doesn't own the account's billing.

**2. Google Gemini (considered as a free-tier fallback).** Never actually
got as far as a code change — the AI Studio API-key console
(`aistudio.google.com/apikey`) was unreachable in testing (page loaded for
about a second and then failed with no usable error, most likely a browser
extension interfering with the page, though this was never confirmed).
Abandoned in favor of Groq rather than spending more time debugging a
third-party console.

**3. Groq (what's actually deployed).** Free tier, no payment method
required, OpenAI-compatible REST API. Two real bugs found via live testing
against the actual API before this worked:
- **Cloudflare 403 (error code 1010) on Python's default User-Agent.**
  `urllib.request` without an explicit `User-Agent` header identifies
  itself as `Python-urllib/3.x`, which Groq's Cloudflare front blocks as a
  bot signature — confirmed by reproducing the identical 403 locally with
  the same bare request, then fixing it by sending a normal
  browser-style User-Agent string.
- **`openai/gpt-oss-120b` is a reasoning model** — by default it spends the
  `max_tokens` budget on a hidden `reasoning` field before writing the
  actual answer, so a low `max_tokens` (e.g. 10, used while debugging)
  returns an empty `content` with `finish_reason: length` and looks like a
  broken integration when it isn't. Fixed with `reasoning_effort: "low"` in
  the request body, which leaves the token budget for the actual answer.
- Also note: Groq's hosted-model catalog changes over time — `llama-3.3-70b-versatile`
  (the obvious first guess) returned `model_not_found` by the time this was
  built; check `GET /openai/v1/models` against the live key rather than
  assuming a model name from memory or documentation.

**Current config**: `GROQ_MODEL_ID` env var, default `openai/gpt-oss-120b`.
API key in Secrets Manager as `cspm/questionnaire/groq-api-key`
(`{"api_key": "gsk_..."}`), covered by the Lambda role's existing
`secretsmanager:GetSecretValue` on `cspm/*` — no IAM change was needed to
add this secret.

Verified end-to-end: draft answers correctly cite real `check_id`s and
pass/fail counts, and explicitly surface real compliance gaps (e.g. "the MFA
control is currently failing") instead of glossing over them when the
evidence is mixed — which is the point of grounding the prompt strictly in
retrieved evidence rather than letting the model free-associate.

## Acceptance criteria from issue #259 — status

1. ✅ **Previously-approved answers auto-matched.** On upload, every question
   without a file-provided answer is checked (Jaccard token overlap, ≥0.7
   similarity) against every approved answer from this account's other
   questionnaires. Deliberately conservative and never auto-approves — lands
   at `needs_review` with an evidence entry recording the source.
2. ✅ **Relevant evidence suggested/attached automatically.** The evidence
   chips described above.
3. ✅ **Low-confidence answers flagged for review.** `confidence: "low"`
   (no real evidence found) never gets an AI draft; item stays `needs_review`.
4. ⚠️ **"Original formatting preserved" on export.** Not applicable as
   specified — export is CSV-only in both directions, so there's no
   "original formatting" to preserve. Would need format-matching export
   (e.g. re-filling the original XLSX/DOCX) to actually satisfy this.
5. ✅ **Outdated responses flagged when evidence changes.** Every fetch of a
   questionnaire recomputes each cited control's *current* live status/counts
   and compares against what was stored at drafting time; a mismatch sets
   `is_stale: true` on the item.
6. ✅ **Analytics: automation rate, review time, completion rate.**
   `GET ?cloud_account_id=..&analytics=1` — real aggregates only, no assumed
   "time saved per question" constant.

## Collaboration (comments, approval history)

`questionnaire_item_comments` (a flat discussion thread per item) and
`questionnaire_item_history` (every `answer_status` transition — from, to,
who, when, logged inside `_update_item`). No multi-user auth is wired into
this Lambda (the dashboard's bearer token is opaque, validated elsewhere),
so `author_name`/`actor_name` is a display name the browser asks for once
and remembers in `localStorage` — a real name people type in, not a
fabricated identity/role system. **Not built**: assigned reviewers and
@mentions from the issue — without real user accounts to assign or notify,
faking that would just be names with no routing/notification behind them.

The detail view also surfaces an `outstanding_count` (items not yet
`approved`) as a header pill.

## Supported upload formats

| Format | Status | How |
|---|---|---|
| CSV | ✅ | stdlib `csv`, header row with a "Question" column recognized automatically |
| XLSX/XLSM | ✅ | `openpyxl` (vendored, pure-Python — no compiled extension needed). Every worksheet is checked independently for a header cell matching `\bquestions?\b`; sheets without one (cover pages, instructions) are skipped. Handles CAIQ's 17 CCM-domain-tab layout. |
| DOCX | ✅ | Reads `word/document.xml` directly via stdlib `zipfile`+`ElementTree` — deliberately avoids `python-docx`/`lxml` (a compiled C extension needing its own manylinux wheel) for a format this simple to read directly. Prefers a Question/Answer table; falls back to every paragraph ending in "?". |
| XLS / DOC (legacy binary) | ❌ | Clear upload error asking for `.xlsx`/`.docx`/`.csv` instead. |
| PDF | ❌ | Not attempted — reliable Q&A extraction from arbitrary PDF layouts needs real, dedicated work (AcroForm fields vs. free text vary wildly); a rushed heuristic risks silently mis-reading questions, which is worse than refusing the upload. |

## Secure sharing and Print/PDF export

`questionnaire_share_links` (migration 009) — a cryptographically random
token (`secrets.token_urlsafe`), a default 7-day expiry, and a `revoked`
flag. A new public, unauthenticated GET path (`?share_token=...`) serves a
read-only view with none of the normal `cloud_account_id` scoping. **Only
`approved` items are ever exposed** — an unapproved item still appears in
the question list (so the external viewer sees the real shape of the
questionnaire) but with the answer withheld and status
`pending_internal_review`; an unreviewed AI draft never leaves the
building through a share link, regardless of how much real evidence backs
it. `frontend/public/questionnaire_share_view.html` renders it standalone,
no sidebar/login chrome. Revoking immediately invalidates the token.

PDF export is the browser's native "Print / Save as PDF" (`@media print`
rules hiding app chrome), both on the internal detail view (full content)
and the external share view — deliberately no server-side PDF library
vendored, since that would mean either a heavy native dependency
(weasyprint) or a fragile compiled one (reportlab's optional accelerator),
for something the browser already does reliably.

## Answer Library (Knowledge Base)

`GET ?cloud_account_id=..&library=1[&q=search]` groups every approved
answer across all of an account's questionnaires by exact question text,
returning: **tags** (the real frameworks/doc-categories that answer's
evidence actually cited — never an invented taxonomy), and **version
history** (every historical approved answer to that exact question,
newest first — genuine version history derived from real approvals, not a
separate versioning system). The `q` param filters on question text,
answer text, or tags. Frontend: "📚 Answer Library" view with a live
search box.

## Analytics — full list of what's tracked

Beyond completion/automation rate and confidence distribution (see
acceptance criteria above): **most common questions** (asked more than
once across all questionnaires) and **manual edit rate** — the fraction of
AI-generated answers whose text was changed before approval, tracked via
an `edited_after_ai` column (migration 010) set in `_update_item` only
when the submitted text actually differs from what's stored, not just
resubmitted unchanged.

**Real bug found and fixed while wiring this up**: `_update_item`
previously set `ai_generated = FALSE` on *every* save that included
`answer_text`, even when the "Save" button resubmitted identical,
unedited text — silently discarding accurate AI-generated provenance and
miscounting untouched drafts as "manually entered" everywhere (UI,
automation-rate analytics). Fixed by comparing against the previously
stored `answer_text` and only touching provenance fields when it actually
changed. Verified: resaving an AI draft unchanged now correctly leaves
`ai_generated: true`; a genuine edit correctly flips `edited_after_ai`.

## Issue #259 — final coverage summary

Everything explicitly asked for is built except: **PDF upload** (see table
below — a deliberate refusal, not an oversight), **preserving original
file formatting on export** (not applicable — export is plain text/CSV in
both directions, there's no original layout to preserve), **assigned
reviewers / @mentions** (no real user-account system exists to assign or
notify — faking it would be names with no routing behind them), a
**"suggested improvements before submission" AI pass** (the review/edit
step already lets a human correct a draft before approving; a distinct
"AI critiques its own draft" feature was not built), and specific evidence
sub-types the codebase has no real data source for at all — **certificates,
penetration-test summaries, and architecture diagrams** are not modeled as
evidence because nothing in this codebase ingests them; treating that as a
gap to fake would violate the same "no fabricated evidence" rule the rest
of this feature is built around.

## Known limitations / not yet built

- **PDF upload** (see format table above).
- **`evidence_documents` is a point-in-time seed**, not synced live from the
  docs folder — re-run the seed after editing `docs/public/security/**/*.md`
  in any way that should show up in future drafts.
- **No role-based review routing** (legal/security/compliance as distinct
  review stages) — approval is a single `needs_review` → `approved` step,
  not a multi-stage pipeline.

## Manual re-seed / test commands

```
# Re-seed evidence_documents after editing docs/public/security/**/*.md
aws lambda invoke --function-name questionnaire-handler \
  --payload file://evidence_docs.json \
  --cli-binary-format raw-in-base64-out out.json

# Manually trigger drafting for one questionnaire
aws lambda invoke --function-name questionnaire-handler \
  --payload '{"httpMethod":"POST","body":"{\"action\":\"generate_all\",\"questionnaire_id\":\"<uuid>\"}"}' \
  --cli-binary-format raw-in-base64-out out.json
```
