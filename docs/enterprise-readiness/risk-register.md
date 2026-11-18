# Risk and technical-debt register

| ID | Risk | Likelihood / impact | What limits it today | Owner | Decision | Review |
|---|---|---|---|---|---|---|
| R-01 | Organization MFA policy enforced by the web app only; a valid token can call the API without MFA | Medium / High | Tenant guard still limits data to the user's own accounts; MFA status changes are recorded | Unassigned | Fix (P0-01) | 2027-01 |
| R-02 | Stolen access token can change MFA or passkeys directly at Cognito for up to an hour | Low / High | Access tokens expire after one hour; global sign-out revokes them immediately; Niagaros records such changes as "observed" | Unassigned | Accept, monitor | 2027-01 |
| R-03 | Database endpoint reachable from the internet (Lambdas run outside a VPC) | Medium / High | SSL enforced, strong credentials, connection monitoring, deletion protection, backups (E-017) | Unassigned | Accepted until VPC move (P0-07) | 2027-01 |
| R-04 | No infrastructure as code: drift and non-reproducible deploys | High / Medium | Every scripted deploy downloads the live package afterwards and compares it with the build | Unassigned | Fix (P0-04) | 2027-01 |
| R-05 | One function on Python 3.9 (no longer supported by AWS) | Medium / Medium | Function is read-only (S3 scanner) | Unassigned | Fix (P0-05) | 2026-12 |
| R-06 | Secrets never rotated | Medium / High | Secrets Manager with AWS-managed encryption; least-privilege read per Lambda role for the newer functions | Unassigned | Fix (P0-06) | 2027-01 |
| R-07 | Email in SES sandbox, SMS in SNS sandbox: notifications and approval links do not reach every recipient | High / Medium | Manual copy-link fallback; delivery failures are recorded honestly | Unassigned | Fix (P0-10, DKIM records at the DNS host) | When DNS is changed |
| R-08 | One shared database and backend for every environment; tests of branches hit production APIs | High / Medium | Test writes only on dedicated test tenants, prefixed and cleaned up; the real customer account is never written | Unassigned | Fix (P0-04) | 2027-01 |
| R-09 | No dynamic security testing or penetration test | Medium / High | Static analysis, tenant isolation tests, code reviews | Unassigned | Fix (P0-08) | 2027-01 |
| R-10 | Cost ingestion makes paid AWS requests in customer accounts | Low / Low | Opt-in per account with explicit consent, one refresh per hour at most, counted per run | Unassigned | Accept | — |
| R-11 | Single region (eu-west-1) | Low / High | Multi-AZ database, backups; restore tested | Unassigned | Accept for now | 2027-06 |
| R-12 | Cognito user pool could be deleted by one API call | — | **Closed 2026-11-16**: deletion protection ACTIVE (E-006) | — | Done | — |
