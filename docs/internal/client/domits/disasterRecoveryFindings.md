# Domits — Disaster Recovery: findings and changes made (2026-09-01)

Real findings from running the new RDS/DynamoDB disaster-recovery checks (see `docs/internal/architecture/aws/disaster_recovery_scanning.md`) against Domits' AWS account (`115462458880`), plus the production changes made as a direct result. All changes below were read-only checks except where explicitly marked as a production change.

## Account inventory (as found)

- **RDS**: none, in any region checked (eu-west-1, eu-north-1, us-east-1, us-east-2, us-west-2, eu-central-1, eu-west-2).
- **Aurora / Aurora DSQL**: none found, despite internal onboarding docs describing "Aurora DSQL (PostgreSQL)" as a datastore. Either it lives in an AWS account we don't have access to, or it was never actually built. **Unresolved — worth confirming with the team.**
- **DynamoDB**: exactly one table, `General-Messaging-Production-WebSocketConnections` (region `eu-north-1`) — tracks active chat WebSocket connections (`connectionId`, `userId`). Empty at rest by design (only holds rows for currently-open connections).
- **S3**: 24 buckets, several holding real customer data (`accommodation` — 1000+ objects, listing photos; `accommodationphotos`; `domits-host-payout-invoices`; `domits-task-attachments`; `general-messaging-production-attachments`; `cognitodata`; `ical-storage`; `icalender`). All checked buckets have versioning **enabled** (real, positive finding — this is their working backup mechanism for object data). Note: objects predate versioning being turned on, so there is no multi-version history yet to point to as proof; only future overwrites will actually exercise it.
- **Cognito**: production user pool `domits7b73f586_userpool_7b73f586-production` (`eu-north-1_HjL3yKPeV`), 33 real users.

## Findings and fixes

| Resource | Finding | Action taken |
|---|---|---|
| DynamoDB table | Point-in-time recovery was **disabled** (`DynamoDB.DR.1` FAIL) | **Production change**: enabled PITR, 35-day retention (`aws dynamodb update-continuous-backups`) |
| DynamoDB table | Deletion protection was **disabled** (`DynamoDB.DR.2` FAIL) | **Production change**: enabled (`aws dynamodb update-table --deletion-protection-enabled`) |
| Cognito user pool | **No deletion protection**, 33 real users, and Cognito has no native backup/restore mechanism at all (unlike RDS/DynamoDB, there is no point-in-time-recovery API for user pools) | **Production change**: enabled deletion protection (`aws cognito-idp update-user-pool`). This is the only available safeguard — there is still no way to recover this pool's data if it is ever deleted; deletion protection only prevents the accidental `delete-user-pool` call itself. |
| S3 (all data buckets) | Versioning already enabled | No action — already correct |

**Caution encountered:** the first Cognito `update-user-pool` call (deletion protection only) silently reset `LambdaConfig.PreSignUp` and `VerificationMessageTemplate` to empty, because Cognito's update API treats unspecified fields as "clear this" for some fields rather than "leave unchanged". Both were restored to their original values in a follow-up call using `--cli-input-json` (curly-brace placeholders like `{####}` in the verification message break the CLI's shorthand parameter parser — use `--cli-input-json` for any future Cognito user-pool update, not the shorthand flags).

## Two real restore tests performed on the DynamoDB table

Both restored to a brand-new, isolated table (never touched the live table), torn down immediately after verification.

| Date (UTC) | Live items at test time | RPO | RTO | Data integrity |
|---|---|---|---|---|
| 2026-09-01 09:30:07 | 0 (no one connected at the time) | 4m58s | 3m12s | 0/0 match (trivial — table was empty) |
| 2026-09-01 11:09:14 | 3 (live, changing) | 4m57s | 3m27s | Restored table had 4 structurally-valid connection records (real `connectionId`/`userId` pairs). Count did not match the live table (4 vs 3) — expected, not a bug: this table is transient and the live count kept changing during/after the test. |

Both rows are recorded in `dr_test_results` (`cloud_account_id = cbb94e43-4e42-4fac-997e-8f931131bde7`).

## Housekeeping

Four duplicate `cloud_accounts` rows existed for this AWS account (repeated onboarding-wizard attempts, no dedup logic in `/onboard`). Reduced to one (`cbb94e43-4e42-4fac-997e-8f931131bde7`), reassigned to the actual logged-in tester's email (`bottomclipzz@gmail.com`) after discovering `owner_email` ownership checks were silently blocking the dashboard from showing data for the wrong session. **The `/onboard` endpoint should probably dedupe on `(user, account_id)` going forward** — not fixed here, only worked around by manual cleanup.

## Open question for the team

Where does Domits' actual structured application data live (listings, bookings, host/guest profile data beyond auth)? Not found in this AWS account across every database service checked (RDS, Aurora, Aurora DSQL, DynamoDB, DocumentDB, Neptune, Redshift, OpenSearch). Either a separate AWS account exists that we don't have access to, or the "Aurora DSQL" datastore mentioned in onboarding docs was never actually built.
