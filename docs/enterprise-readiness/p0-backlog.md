# P0 remediation backlog

Ordered by what unblocks the most gates for the least work. Each item should become its own GitHub issue (the issue
asks for separate implementation issues per P0 workstream); the ID here is the reference until then.

| ID | Item | Gate(s) | Size | Status |
|---|---|---|---|---|
| P0-01 | Enforce an organization's MFA requirement in the API (`tenant_auth`: Cognito `GetUser` already returns the user's MFA settings) | 2 | S | Open |
| P0-02 | Independent review of `tenant_auth.guard` and every handler's REFS; decide on database row-level security | 3 | M | Open |
| P0-03 | Platform health alarms | 7 | S | **Done 2026-11-16** — 5 alarms on the existing alert topic (E-010) |
| P0-03b | Runbooks for the five alarms and for "scan failed for an account" | 7 | S | Open |
| P0-04 | Infrastructure as code for Lambdas, routes, IAM, schedules; a separate staging backend | 1, 6 | L | Open |
| P0-05 | Move `cis_s3_scanner` from Python 3.9 to 3.12 | 4 | S | Open |
| P0-06 | Rotation for the database credentials (Secrets Manager rotation Lambda) | 5 | M | Open |
| P0-07 | Lambdas into a VPC and close the public database endpoint | 5 | M | Open (accepted risk R-03 until then) |
| P0-08 | Dynamic application testing in CI and an external penetration test | 4 | M | Open |
| P0-09 | Central administrative audit view and a retention policy for all audit trails | 8, 9 | M | Open |
| P0-10 | SLOs, incident response procedure and one exercise; SES production access (DKIM) | 6, 7, 10 | M | Open |
| P0-11 | Enterprise SSO (SAML/OIDC) and SCIM provisioning | 2 | L | Open |
| P0-12 | Validate end-to-end that offboarding a customer deletes their data | 5 | S | Open |
| P0-13 | Name an owner for every domain in the scorecard | all | S | Open |
| P0-14 | Re-enable the branch-protection workflow; run the backend database tests in CI | 4 | S | Open |
| — | Cognito deletion protection | 2, 5 | S | **Done 2026-11-16** (R-12) |
