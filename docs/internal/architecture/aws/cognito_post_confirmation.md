# Cognito PostConfirmation trigger (`post-confirmation-handler`)

## Why

Every organization-scoped endpoint (team, auditors, onboarding steps 5–7)
looks the caller up in the `users` table. Migration 002 assumed a Cognito
post-confirmation trigger filled that table, but it was never built: the
user pool `niagaros-users` (`eu-west-1_mHQf9RNTc`) had no triggers at all,
and on 14 Oct 2026 only 2 of 12 Cognito users had a row. Everyone else got
"unauthorized" on those pages.

## What it does

`backend/src/auth/post_confirmation.py`, on `PostConfirmation_ConfirmSignUp`
with a verified email: inserts `users (cognito_sub, email, full_name)`. The
`users_default_organization` DB trigger (002) then creates the person's own
organization with them as admin. Pending team invites are accepted later by
`/team/accept-invite`.

- Never blocks a sign-up: errors are logged and swallowed, every call has a
  short timeout without retries, and a step is skipped if it could not finish
  before the Lambda's 4 s timeout (Cognito allows 5 s).
- Identity is the Cognito `sub`; an email owned by another `sub` is never
  adopted.
- `governance-handler` provisions the same way on a first request, as a
  fallback.

## Deployed (14 Oct 2026)

- Role `PostConfirmationLambdaRole`: logs + `secretsmanager:GetSecretValue` on
  `cspm/database/credentials*`.
- Function `post-confirmation-handler`, handler
  `auth.post_confirmation.lambda_handler`, Python 3.12 x86_64, 4 s, 256 MB,
  package = `auth/` + bundled psycopg2.
- Invoke permission for `cognito-idp.amazonaws.com` on the pool ARN.
- Pool `LambdaConfig.PostConfirmation` set via `UpdateUserPool`.
  **UpdateUserPool resets every setting you leave out**, so the request was
  built from `DescribeUserPool` (pruned to the UpdateUserPool input shape,
  plus `PoolName`), the pool was re-read right before the update, and
  compared afterwards: only `LambdaConfig` changed.
- Backfill: the 8 confirmed, verified users without a row were added.

## Rollback

`UpdateUserPool` with the saved pool description and an empty
`LambdaConfig` (same full-request rule as above), then delete the function
and the role. Rows already created stay; they are what migration 002 expects.
