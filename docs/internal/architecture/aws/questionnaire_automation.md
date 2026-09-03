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
  (migration `007_questionnaire_automation.sql`).

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

## Known limitations / not yet built

- **CSV only.** XLSX/DOCX/PDF questionnaires aren't parsed; the upload UI
  says so rather than silently mishandling them.
- **No collaboration** (comments, mentions, assigned reviewers) and **no
  analytics dashboard** — issue #259 asked for both, out of scope for this
  pass.
- **No cross-questionnaire answer library** — every questionnaire's
  evidence retrieval runs independently; a previously-approved answer to
  the same question on a different questionnaire isn't reused or suggested.
- **`evidence_documents` is a point-in-time seed**, not synced live from the
  docs folder — re-run the seed after editing `docs/public/security/**/*.md`
  in any way that should show up in future drafts.

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
