# Niagaros — Phase 2: AWS Cognito (User Pool / Auth)

## Purpose

Provide authentication for frontend and backend via JWT tokens.

## 2.1 Create Cognito User Pool (Console Summary)

- Cognito → User Pools → Create Pool  
- Required attributes: email  
- Password policy: strong  
- App client:
  - Name: `niagaros-web-client`
  - No client secret
  - OAuth flows: Authorization code + PKCE
  - Scopes: `openid`, `email`, `profile`
  - Callback URL: `https://example.com/callback` (placeholder)
  - Hosted domain: `niagaros-auth-<suffix>`

## 2.2 Create Cognito Groups

- `tenant_admin`
- `tenant_user`

## 2.3 CLI Examples

### Create user pool

```bash
aws cognito-idp create-user-pool \
  --pool-name NiagarosUserPool \
  --policies PasswordPolicy="{MinimumLength=12,RequireUppercase=true,RequireLowercase=true,RequireNumbers=true,RequireSymbols=true}"
```

### Create app client

```bash
aws cognito-idp create-user-pool-client \
  --user-pool-id <POOL_ID> \
  --client-name niagaros-web-client \
  --no-client-secret \
  --allowed-o-auth-flows "code" \
  --allowed-o-auth-scopes "openid" "email" \
  --callback-urls "https://example.com/callback"
```

## Verification

- Sign in via Hosted UI
- Validate JWT contains correct claims
- Groups appear in `cognito:groups` field

