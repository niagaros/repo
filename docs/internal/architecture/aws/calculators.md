# Niagaros Calculators (GitHub issue #263)

## What issue #263 asked for

A library of ~40 calculators across risk (cyber risk exposure, FAIR-based
estimation, third-party/supply-chain/AI risk), compliance (readiness
score, gap %, control coverage, audit readiness), cloud security
(posture/attack-surface/IAM risk/Kubernetes score), financial
(cybersecurity ROI, cost-of-a-data-breach, TCO, annual budget planner),
executive (maturity score, MTTR/MTTD impact), sales/marketing (ROI for
Niagaros, TCO comparison), and "AI-assisted" (AI-generated
recommendations, scenario forecasting, "what-if" analysis, investment
optimization) — with export to PDF/CSV/Excel and shareable links.

## Scope decision

Almost all of these require either a real actuarial/industry-benchmark
dataset this platform has no access to (breach-cost averages, FAIR
probability distributions, cyber-insurance actuarial tables), or an AI
model asserting a risk judgement well beyond what this platform's existing
AI integration is used for (Questionnaire Automation drafts answers
strictly from the account's own real evidence — it never judges risk or
generates a number that looks like a fact). Building the Cost-of-a-Data-
Breach Estimator, the FAIR-based Risk Estimator, or an "AI Risk
Calculator" would mean presenting an invented number as if it were
measured — this codebase's standing "no fabricated evidence" rule.

The issue itself gives an explicit priority order, though:

1. Compliance Effort Calculator
2. Compliance Cost Calculator
3. [Framework] Cost Calculator

**All three are built here, for real**, as one tool with two modes
(Effort / Cost) plus a framework picker:

- **The gap input is real, live data.** For the chosen framework, the
  calculator queries the exact same `findings`/`resources` tables the
  dashboard, Trust Center, monthly report, and Audit Management already
  read from, and shows the real count of currently-FAILing findings,
  broken down by severity. No new measurement — the same real gap that
  already drives the framework's compliance % everywhere else in the
  product.
- **The effort/cost side is the user's own, editable assumption** — hours
  to fix one finding per severity, and (in Cost mode) a blended hourly
  rate. **These fields start at 0, not a pre-filled default.** An earlier
  version of this tool shipped with pre-filled "sensible" defaults
  (8h/4h/2h/1h, €75/hour) — the user correctly rejected that: even with a
  disclaimer, a specific-looking dollar figure appearing before anyone
  typed a real number is exactly the kind of thing that reads as
  fabricated. The result now stays at 0 until the user enters their own
  number, so no figure can ever appear that nobody actually chose.
- **"[Framework] Cost Calculator"** is the same tool, framework-scoped,
  rather than a separate build — every framework already has its own real
  gap count via the same picker.
- **Scenarios can be saved** (title, framework, the gap snapshot at save
  time, the assumptions used, and the computed result) for later
  reference — a lightweight, honest version of "export and share," backed
  by a real `calculator_scenarios` table rather than a generated PDF
  service. A print/export button uses the browser's native print-to-PDF
  (same pattern as the existing dashboard "Print Report" feature).

**Declined, explicitly, rather than silently invented:**

- Cyber Risk Exposure Calculator, FAIR-based Risk Estimator, Cost of a
  Data Breach Estimator — no real breach-cost or actuarial dataset exists
  in this codebase.
- AI Risk Calculator, AI-generated scenario forecasting/"what-if"
  analysis, investment optimization — would require an AI judgement of
  risk, not a drafted answer from real evidence (the line already drawn
  for TPRM's declined items).
- Kubernetes Security Score — no Kubernetes collector exists in this
  platform.
- Cloud cost/TCO calculators, "Cost Savings from Automation" as an
  absolute claim — no billing-data integration exists; presenting a
  specific dollar figure without one would be fabricated.
- The full compliance/cloud-security calculator family (Control Coverage,
  Cross-Compliance Coverage, Audit Readiness Score, Cloud Security
  Posture Score, Attack Surface Score, IAM Risk Score, etc.) — these
  *could* legitimately be built from real data already in this platform
  (they're largely re-expressions of numbers the dashboard, Audit
  Management, and IAM Analysis already compute), but weren't in this
  pass since the issue itself only prioritized the three above. A natural
  v2.

## Architecture

- **Lambda**: `calculator-handler` (python3.12, role
  `CSPMScannerLambdaRole`, same bundled-psycopg2 package layout as the
  other scanner handlers).
- **DB**: migration `019_calculators.sql` — single table
  `calculator_scenarios` (framework, real gap snapshot, user assumptions,
  computed results, all as JSONB).
- **API**: `GET/POST/OPTIONS /calculators` on the shared HTTP API
  (`hzf92ft6j7`).
- **Frontend**: `frontend/public/calculators.html` — framework picker with
  a live real-gap display, an Effort/Cost tab toggle, an assumptions form,
  a live-recalculating result card, and a saved-scenarios list. Linked
  from the sidebar of the dashboard, TPRM, Trust Center, Audit Management,
  and Questionnaire Automation pages.
- `FRAMEWORK_LABELS` / `FRAMEWORK_DB_VALUES` are copied verbatim from
  `trust_center_handler.py` / `audit_management_handler.py` (same reuse
  pattern already established across this codebase).

## Live verification (2026-09-07, against the real Niagaros account)

- `gap_data` for ISO 27001 returned 8 real open findings (all HIGH),
  matching the count already confirmed in Audit Management's own live
  test the same day.
- `gap_data` for GDPR returned 5 real open findings (4 HIGH, 1 MEDIUM).
- Effort calculator: 8 HIGH × 4h = 32h, correct.
- Cost calculator: 32h × €75 = €2,400 for ISO 27001; for GDPR,
  (4×4h + 1×2h) × €75 = €1,350 — both verified by hand against the UI
  output.
- Saved a real scenario via the API, confirmed it listed correctly, then
  deleted it — full lifecycle tested.
- Full UI walkthrough via a headless-browser test (Playwright): load →
  real ISO 27001 gap displayed → switch to Cost tab → switch framework to
  GDPR (gap and result both update live) → save a scenario through the
  real UI → confirmed it appears in Saved Scenarios with the right
  numbers → deleted via the API afterward. No console errors.
- Found and fixed one real bug during the build itself (not this
  session's data, a coding mistake in the new file): the HTML-escaping
  helper's `&` case was miscopied to map to `&lt;` instead of `&amp;` —
  caught by re-reading the function before deploying, fixed before any
  live test ran against it.
- **Post-ship correction #1**: the user pushed back immediately after
  seeing the first live numbers ("waarvoor zijn die kosten en ik wil niks
  neps hebben") — right to. The pre-filled default assumptions (8h/4h/2h/1h,
  €75/hour) were removed; every assumption field now starts at 0 and the
  result stays at 0 until the user types a real number. Reverified: 8 real
  HIGH findings × a typed "3" hours = 24h, live-recalculated, no
  pre-existing figure involved.
- **Post-ship correction #2**: the user then asked for the opposite fix —
  base the calculator on real external benchmarks instead of leaving
  everything blank ("maak de niagaros calculator gebaseerd op benchmarks
  van andere ... kom met iets echts, geen gesjoemel"). The distinction
  from correction #1: an *invented* default (no source, presented as if
  it were reasonable) is fabrication; a *cited* default (a named, dated,
  publicly-published external report, linked in the UI) is not — it's the
  same practice every comparable vendor (Vanta, Drata) uses. Three real
  external benchmarks were researched (via live web search, not recalled
  from memory) and added, each exposed by the API with its source name,
  URL, and an honest note about its limitations:
    - **Average days to remediate a vulnerability, by severity** — Edgescan
      2025 Vulnerability Statistics Report (10th edition): Critical 61
      days (host/cloud; internet-facing criticals average 35), High 30
      days, Medium 75 days (midpoint of the report's 60-90 day window).
      Low has no widely-published figure — shown as 90 days with an
      explicit note that this is the conservative edge of the Medium
      band, not a distinct measured statistic. Displayed as a read-only
      reference table next to the account's real open-finding count per
      severity — never multiplied into a fabricated "total days" figure,
      since remediation can be parallelized and a simple multiplication
      would imply something the source data doesn't support.
    - **Average hourly rate for a cybersecurity/compliance consultant** —
      Glassdoor (pulled 2026): $76/hour, median of a $58-$100 typical
      range. This one **is** used as a live, editable default in the Cost
      Calculator's rate field, with the source cited and linked directly
      next to the input.
    - **Average cost of a data breach** — IBM Cost of a Data Breach
      Report 2025: global average $4.44M, US average $10.22M, mean 241
      days to identify and contain. Shown in a new "Cost of a Data Breach
      — industry context" panel alongside the account's own real
      critical/high open-finding count — deliberately *not* multiplied
      together, since Niagaros has no real breach-probability or
      exposed-record data that would make a personalized dollar
      prediction a true statement rather than an invented one.
  Where no real benchmark could be found — hours of actual engineering
  work to fix one finding, which nobody publishes reliably by severity —
  the field honestly stays at 0 with a note saying no benchmark exists,
  rather than being filled with a guess to avoid looking incomplete.
  Currency was also corrected from € to $ throughout the cost results,
  since the only sourced rate benchmark (Glassdoor) is in USD.
  Reverified live: 8 real HIGH findings × a typed "4" hours × the real
  cited $76/hour rate = $2,432, correct.
- **Post-ship comparison #3**: the user asked what Vanta itself does here.
  Researched Vanta's own real, public "Automation Value Calculator"
  (vanta.com/automation-value-calculator): almost all of its inputs are
  user-entered (headcount, hours spent, questionnaire volume) — no
  external benchmark at all for most fields. The one place it adds
  outside context is explicitly anecdotal, not a cited report: "Our
  customers tell us that without automation, the average questionnaire
  can take 2-4 hours" — labelled as customer feedback, not data. It also
  carries an explicit disclaimer: "Time savings estimates are provided
  for illustration purposes only and depend on a variety of factors
  unique to each organization." This is now mirrored in this calculator's
  own disclaimer text. What is deliberately NOT copied: Vanta's "our
  customers tell us" line is legitimate for them because they have real
  aggregate customer usage data to draw it from — Niagaros doesn't yet,
  since this calculator has no real users. Adding an invented version of
  that line now would be exactly the kind of fabrication this whole
  feature was built to avoid. Once Niagaros has real usage/feedback data
  from actual customers using this calculator, an honestly-labelled
  "our customers tell us" note becomes legitimate to add — not before.
- **Post-ship correction #4**: the user pushed back a second time, sharper
  ("kijk goed of dit klopt nog qua cijfers en is dit het meest actueel"),
  after seeing the live numbers, on three specific points:
    1. Why does Critical show a *cheaper* total than High? Because there
       was only 1 real open Critical finding vs 17 High — the arithmetic
       was correct but opaque. Fixed by adding an explicit "N findings ×
       Hh" line under every result-breakdown number, and a note in the
       disclaimer explaining that a lower total means fewer real findings,
       not a lower per-finding cost.
    2. The remediation-days table showed nothing distinct for High beyond
       what Critical already showed — on inspection this was a citation
       gap, not a data gap: the note explained Critical/Medium/Low but
       never explicitly justified the High figure's provenance.
    3. On checking sourcing more carefully, two real, more serious
       problems surfaced:
       - The Critical/High "days to remediate" table was presenting four
         clean per-severity numbers as if Edgescan published each one —
         it doesn't. It reports Critical alone but High only combined
         with Critical, and Medium/Low not at all. Fixed by only showing
         what's actually published, and adding a separate,
         explicitly-labelled "SLA target, not measured" row for
         Medium/Low sourced from vulnerability-management SLA guidance
         (HostedScan) — a genuinely different kind of number, never
         presented as equivalent to Edgescan's measured data.
       - **Both cited reports were a year stale.** Edgescan has an 11th
         (2026) edition and IBM has a 2026 edition, both newer than what
         was first cited. Re-verified live via web search and a direct
         fetch of edgescan.com/stats-report (not a third-party PDF
         mirror, which was intentionally avoided): the Edgescan
         High+Critical-combined figure (54.81/39 days) is confirmed
         still current in the 2026 edition; the Critical-only breakdown
         (74.3/61/35 days) is only confirmed attributed to the 2025
         edition in every source checked, so it's cited to that specific
         edition rather than assumed to carry over. IBM's 2026 report
         (published Jul 2026, breaches Mar 2025-Feb 2026, 602
         organizations) gives real, higher figures — global $4.99M
         (up from $4.44M), US $11.5M (up from $10.22M), 247 days mean
         to identify/contain (up from 241) — now shown instead of the
         year-old numbers, with the prior year's figures kept visible in
         the citation note for transparency about what changed.
    4. Also asked, separately, whether citing all of this raises
       copyright concerns. Answered directly: facts/statistics are not
       copyrightable, only a source's specific expression of them is:
       citing a number with a name+link (as done throughout) is standard,
       industry-wide practice (this is literally how every competitor
       cites the same IBM/Edgescan/Glassdoor reports), and none of the
       source text, charts, or images are reproduced — only individual
       factual data points, in this project's own words and formatting.
