# Monthly Compliance Report (GitHub issue #234)

## What it does

`monthly-report-generator` (Lambda, `collectors/aws/scanner/monthly_report_handler.py`)
builds a presentation-ready HTML summary for one cloud account: current
compliance score, score delta vs. last month, findings newly introduced,
findings resolved, the top 5 unresolved findings by severity, and a
recommended-next-steps list. It is triggered monthly by the EventBridge rule
`monthly-domits-security-review` (`cron(0 7 ? * 2#1 *)` — first Monday of the
month, 08:00 CET/07:00 UTC), with a fixed payload targeting Domits'
`cloud_account_id`.

## How trend data works

The `findings` table only ever holds the *current* state per
`(resource_id, check_id)` — every scan upserts over the previous result, so
there is no built-in history to diff against. This feature adds
`compliance_snapshots` (migration `004_compliance_snapshots.sql`, extended by
`005_compliance_snapshot_type.sql`): each run stores the full list of
currently-failing `(check_id, resource_id)` pairs (`failing_keys`, JSONB)
alongside the aggregate counts.

**Two kinds of rows, tagged by `snapshot_type`:**
- `'scan'` — written by `Database.record_compliance_snapshot()`, called from
  `orchestrator/lambda_handler.py` after every completed scan+mapper cycle
  for an account (whichever triggers a full scan: the dashboard's "Scan Now"
  button, or any future scheduled run). Potentially many per month.
- `'monthly_report'` — written once per report by `monthly_report_handler.py`
  itself, marking the end of a reporting period.

**Why this matters**: comparing only "now" against "the single point a month
ago" hides everything in between — e.g. a finding that regressed mid-month
and was already fixed again before the report ran would never show up.
Instead, `_period_data()` finds the last `'monthly_report'` snapshot (the
start of the current period; 30 days back if there isn't one yet), pulls
every `'scan'` row recorded since then, and:
- uses the **oldest** scan in the window as the diff baseline (state at the
  start of the period) for the new/resolved findings list — not just "the
  last thing that happened,"
- reports the **min and max score** actually reached during the period, so a
  temporary regression is visible even if things were fixed again by the
  time the report runs.

The very first run for an account has no prior monthly-report snapshot: the
window falls back to the last 30 days, every current failure not yet seen in
that window is reported as "new," and the score delta is shown as "no prior
snapshot" instead of a number if there's nothing to compare against at all.
That's expected, not a bug.

## Infrastructure

- **Lambda**: `monthly-report-generator` (python3.12, role `MonthlyReportLambdaRole`)
- **Role permissions**: `secretsmanager:GetSecretValue` on `cspm/database/credentials`, `s3:PutObject` on `niagaros-compliance-reports/*`, plus the standard Lambda basic-execution managed policy. Deliberately does **not** reuse `CSPMScannerLambdaRole` — this Lambda writes to S3, which the scanner role never needed and shouldn't have.
- **S3 bucket**: `niagaros-compliance-reports` (private, Block Public Access on all 4 settings, AES256 default encryption). Report key format: `{cloud_account_id}/{YYYY-MM}.html`.
- **EventBridge rule**: `monthly-domits-security-review`, targets the Lambda with `{"cloud_account_id": "<domits-uuid>"}`.
- **DB**: `compliance_snapshots` table, granted to `cspm_lambda`.
- **Orchestrator dependency**: `cspm_orchestrator` (`backend/src/orchestrator/lambda_handler.py`) calls `Database.record_compliance_snapshot()` (`backend/src/config/database.py`) once per account after each completed scan cycle. If the orchestrator's DB access or this call is ever removed, the monthly report silently degrades to comparing only two single points a month apart again (min/max/period scan-count will just show the current value with 0 or 1 scans) — it won't error, so watch for that regression specifically, not just for exceptions.

## Email delivery

SES is in **sandbox mode** in this account (`ProductionAccessEnabled: false`),
which means both the sender and every recipient must be a verified identity —
there's no "send to anyone" yet. `bottomclipzz@gmail.com` is verified and
used as both `REPORT_SENDER_EMAIL` and `REPORT_RECIPIENT_EMAILS` (comma-
separated list) for now, since no sending domain (e.g. `reports@niagaros.io`)
is verified. `_send_email()` sends the full HTML report inline via
`sesv2.send_email`, with a short plain-text fallback for non-HTML clients.

**Known caveat**: because SES doesn't own gmail.com's SPF/DKIM records,
sending "as" a personal Gmail address through a third party can land in
spam or get flagged — this works for now but isn't how you'd want it in
production. Before wider rollout: verify a real sending domain
(`reports@niagaros.io`) with proper DKIM/SPF/DMARC records, and request SES
production access (an AWS support case) so recipients don't need to be
individually verified.

## Known limitations / not yet built

- **Single account, hardcoded in the EventBridge target.** To cover more
  accounts, either add one target per account or change the Lambda to accept
  no payload and iterate all `cloud_accounts` with `status = 'active'`.
- **No slide-deck template** — only the HTML report exists; a slide-deck
  version was out of scope for this pass.

## Manual re-run

```
aws lambda invoke --function-name monthly-report-generator \
  --payload '{"cloud_account_id": "<uuid>"}' \
  --cli-binary-format raw-in-base64-out out.json
```
