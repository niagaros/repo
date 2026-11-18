# Product capability register — 16 November 2026

Status uses the implementation scale from the maturity model. "Tested" means automated tests exist and pass (E-002 /
E-003); "Live-verified" means the deployed API was exercised on 16 November 2026. Nothing has been independently assessed.

| Capability | Status | Evidence |
|---|---|---|
| AWS posture scanning (S3, IAM, KMS, CloudWatch/CloudTrail, Cognito) | Operational (weekly schedule), tested | Scanners + `cspm-weekly-orchestrator` (E-001), unit tests |
| GitHub posture scanning | Operational, tested | `github-cis-scanner` |
| Compliance mapping (≈28 frameworks + custom frameworks) | Operational, tested | E-015 |
| Dashboard, monthly report, compliance snapshots | Operational, tested | UI tests, live smoke |
| CIEM (entitlements, escalation paths, access reviews) | Operational, tested | `backend/tests/test_ciem_store_and_api.py` |
| AI Inventory, Security Agents | Deployed, tested | backend tests |
| Zero Critical Issues (#296) | Deployed, tested, live-verified | 12 DB tests, 5 UI tests, live 401/403 probes |
| Cloud Cost (#295) | Deployed, tested, live-verified (ingestion run against the real AWS bill into a test database) | 17 engine tests, 13 DB tests, 5 UI tests |
| Privacy & Security settings, passkeys, recovery (#291) | Deployed, tested, live-verified | 10 DB tests; live PIN, recovery, sign-out, TOTP run (E-007) |
| Trust Center incl. validity, notices, branding, analytics (#258) | Deployed, tested | 6 DB tests, 7 UI tests, live public view |
| Questionnaires, TPRM, Audit Management | Operational, tested | UI and API tests |
| Notifications (in-app, webhooks, email, SMS) | Operational; email and SMS limited by sandbox | E-018 |
| Teams, organizations, business units, roles | Operational, tested | backend tests |
| Tenant isolation | Operational, tested, live-verified | E-005 |
| Jira / Monday integrations | Implemented; tested against mocks only | — |
| SSO / SCIM | Not started | — |
| Runtime / workload protection, Kubernetes, DSPM | Not started | — |
| Multi-cloud (Azure / GCP / OCI) | Not started in production | — |
