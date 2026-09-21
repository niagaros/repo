# Niagaros automated testing framework (issue #279)

Continuously proves that Niagaros' critical business flows work — measured by **flows covered**, not lines of code.

```
python -m pip install pytest requests playwright pypdf boto3 && python -m playwright install chromium
python tests/tools/run_suite.py            # everything: unit + live API + UI, flaky re-run, coverage summary
python -m pytest tests/unit                # fast, offline
python -m pytest tests/ui                  # real Chromium against the real frontend files (APIs mocked)
python -m pytest tests/api                 # live, against the deployed API (self-cleaning [E2E] data)
node tests/tools/deploy_gate.mjs           # the P0 deployment gate
```

| Layer | Folder | What it proves |
|---|---|---|
| Unit | `tests/unit` | Notification routing, AI-intent hardening, questionnaire parsing, every compliance mapper's invariants, the framework's own maths |
| API / security | `tests/api` | Auth gate, tenant isolation, validation, CORS, full create→read→update→delete business flows, no leaked test data |
| UI | `tests/ui` | Notification Settings wizard, XSS regressions, every page loads without script errors, the status page, this dashboard |
| Gate | `tests/tools/deploy_gate.mjs` | P0 checks that block a build (runs in `amplify.yml` preBuild and CI) |

## Classification
Every test carries `@pytest.mark.flow("E2E-…")` and `@pytest.mark.severity("P0..P4")`. Flow metadata (domain, owner, environment, frequency, dependencies) lives in `tests/registry/critical_flows.json`. To register a new critical flow, add it there and tag its tests — coverage recalculates automatically. Flows for features that do not exist yet stay in the inventory as honest gaps with a `gap_reason`.

## Statuses (never hidden)
`passed` · `failed` (blocks) · `known_failure` (a real, tracked defect — strict-xfail, so it turns red the moment it is fixed and the marker must be removed) · `blocked` (needs `E2E_TOKEN`) · `skipped` (not applicable) · `flaky` (failed, then passed on immediate re-run).

## Diagnostics
`tests/reports/latest.json` / `summary.json` (git-ignored, also the CI artifact) hold, per failure: test id, flow, severity, failed step, request/response, stack trace, commit, environment. The public dashboard (`frontend/public/test_dashboard.html`) only receives the sanitized `test_results.json` (numbers + a one-line diagnosis — no bodies, URLs or account ids).

## Test data & production safety
- All writes go to one dedicated test tenant (`E2E_ACCOUNT_ID`); the HTTP client refuses writes to any other account.
- Everything created is prefixed `[E2E]`, removed in finalizers even if a test fails, and `test_zz_no_test_data_left_behind` verifies nothing leaked.
- No production customer data is read into or modified by tests.

## Authenticated tests
Set `E2E_TOKEN` (a Cognito access token of a **dedicated test user**; in CI: repository secret `E2E_TOKEN`). Without it those tests are reported as *blocked*, not passed.

## CI
`.github/workflows/tests.yml` runs on every PR/push; `production-smoke.yml` runs read-only checks every 30 minutes. To make a red run **block merging**, mark `deploy-gate (P0)` and `critical-flows (unit + API + UI)` as *required status checks* in the repository's branch protection settings (an admin-only GitHub setting).
