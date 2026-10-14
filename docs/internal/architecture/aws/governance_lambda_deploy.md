# Rollout: governance Lambda (onboarding steps 5–7, #270 / #281 / #282)

Steps 5 (Configure Compliance), 6 (Configure Governance) and 7 (Security
Training) are served by one Lambda, `governance-handler`. It is built the same
way as `team-handler` and `auditor-handler` (see
`onboarding_lambda_deploy.md`): hand-made, no Infrastructure-as-Code.

## 1. Database migration

`backend/migrations/031_compliance_governance_training.sql`, run **as the
admin role** (it creates tables and grants them to `cspm_lambda`). It is
re-runnable (`IF NOT EXISTS` everywhere). It depends on 002 (organizations,
users.organization_id) and 003 (team_audit_log), which are already live.

Rollback: the tables are new and nothing else reads them, so
`DROP TABLE policy_acknowledgements, governance_exceptions,
governance_policy_versions, governance_policies, compliance_certifications,
compliance_frameworks;` undoes it.

## 2. Package

The same package as team/auditor: `api/`, `config/`, `auth/` from
`backend/src/`, plus the bundled `psycopg2` from `backend/src/psycopg2_lambda/`.
`governance_handler` imports `_get_caller`, `_response` and `_route_path` from
`team_handler`, so the files must ship together.

## 3. Function

| Setting | Value |
|---|---|
| Name | `governance-handler` |
| Handler | `api.governance_handler.lambda_handler` |
| Runtime | Python 3.12, x86_64 (the bundled psycopg2 requires it) |
| Timeout / memory | 30 s / 256 MB |
| `DB_SECRET_NAME` | `cspm/database/credentials` |
| `COGNITO_USER_POOL_ID` | `eu-west-1_mHQf9RNTc` — **required**: without it every request is refused (fail closed) |

Own role `GovernanceHandlerLambdaRole` with only:

- `AWSLambdaBasicExecutionRole` (logs)
- `secretsmanager:GetSecretValue` on `cspm/database/credentials*`

No Cognito permission: GetUser authorizes itself with the caller's token.
Unlike team-handler it needs no `AdminUserGlobalSignOut`, so it does not
reuse that role.

## 4. API Gateway routes (API `hzf92ft6j7`, payload 2.0)

    GET /compliance      POST /compliance/{proxy+}   DELETE /compliance/{proxy+}
    GET /governance      POST /governance/{proxy+}
    GET /training        POST /training/{proxy+}

All seven point to `governance-handler`. The handler reads ids from the path
itself, so greedy routes are fine here (unlike team-handler).

**Never use `ANY`.** An `ANY` route also matches the browser's CORS preflight
(`OPTIONS`), so API Gateway forwards it to the Lambda instead of answering it,
and the browser blocks the real request ("Could not reach Niagaros"). This
happened on the first deploy (14 Oct 2026). Also only GET/POST/DELETE/PATCH are
in the API's CORS config, so the handler uses POST, not PUT. CORS is set at
API level. Add a `lambda:InvokeFunction` permission for
`apigateway.amazonaws.com` scoped to `arn:aws:execute-api:eu-west-1:225989360315:hzf92ft6j7/*`.

## 5. Check after deploying

- `GET /compliance` without a token → 401.
- Signed in: `/settings/compliance`, `/settings/governance`,
  `/settings/training` load, and `/onboarding` shows steps 5–7 as clickable.

## Security notes

- Every query is scoped to the caller's `organization_id`; ids from the
  request are only used together with it.
- The token's `iss` must be our user pool before the email from GetUser is
  trusted (GetUser accepts tokens from *any* pool). team-handler and
  get-dashboard-data do not have this check yet.
- Separation of duties is enforced twice: in the handler and by CHECK
  constraints (`decided_by <> author_id`, `decided_by <> requested_by`).
- A change and its audit row are committed in one transaction.

## Tests

`backend/tests/test_governance_handler.py` runs the real SQL against a
throwaway PostgreSQL (see the module docstring). CI does not run it yet,
because CI has no PostgreSQL service.
